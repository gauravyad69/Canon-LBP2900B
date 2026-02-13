#!/usr/bin/env python3
"""
CAPT Protocol Analyzer v2 - Correctly handles wire byte order.
The CAPT protocol on wire: first 2 bytes are command code, next 2 bytes are size (LE).
On wire we see e.g. a1a1 0400 = IDENT command, size 4.
The user's notation 0xA0A1 means wire bytes a1 a0 (swapped), so let's use WIRE order.
"""

import subprocess
import sys
import os
import struct
from collections import OrderedDict, defaultdict

# CAPT commands keyed by WIRE bytes (as they appear in hex dump)
# Wire hex -> (canonical_name, user_notation)
CAPT_COMMANDS = {
    # Wire bytes    Name                 User notation
    "a1a0": ("CHKJOBSTAT",             "0xA0A1"),
    "a8a0": ("CHKXSTATUS",             "0xA0A8"),
    "a1a1": ("IDENT",                  "0xA1A1"),
    "a0a2": ("JOB_BEGIN",              "0xA2A0"),
    "a0d0": ("SET_PARM_PAGE",          "0xD0A0"),
    "a4d0": ("SET_PARM_HISCOA",        "0xD0A4"),
    "a9d0": ("SET_PARMS",              "0xD0A9"),
    "a0c0": ("PRINT_DATA",             "0xC0A0"),
    "a4c0": ("PRINT_DATA_END",         "0xC0A4"),
    "a7e0": ("FIRE",                   "0xE0A7"),
    "a9e0": ("JOB_END",                "0xE0A9"),
    "a1e1": ("JOB_SETUP",              "0xE1A1"),
    "a2e1": ("GPIO",                   "0xE1A2"),
    # Additional commands found during analysis:
    "a0a1": ("IDENT_REPLY?",           "0xA1A0"),  # this might be query vs reply
    "a0e0": ("CHKJOBSTAT_ALT?",        "0xE0A0"),
    "a2e0": ("JOB_BEGIN_ALT?",         "0xE0A2"),
    "a3e0": ("UNKNOWN_E0A3",           "0xE0A3"),
    "a4e0": ("UNKNOWN_E0A4",           "0xE0A4"),
    "a5e0": ("UNKNOWN_E0A5",           "0xE0A5"),
}

PAPER_SIZES = {
    0x00: "Unknown/Default",
    0x01: "A4",
    0x02: "Letter",
    0x03: "Legal",
    0x04: "Executive",
    0x05: "B5(JIS)",
    0x06: "A5",
    0x07: "Envelope_Monarch",
    0x08: "Envelope_COM10",
    0x09: "Envelope_DL",
    0x0A: "Envelope_C5",
    0x0B: "Envelope_B5",
    0x0C: "16K",
    0x0D: "Index_Card",
    0x80: "Custom",
}

PAPER_TYPES = {
    0x00: "Plain",
    0x01: "Plain_L",
    0x02: "Heavy",
    0x03: "Heavy_H",
    0x04: "Transparency",
    0x05: "Envelope",
    0x06: "Label",
}


def run_tshark(pcap_file):
    """Extract USB bulk transfer data from pcapng file."""
    cmd = [
        'tshark', '-r', pcap_file,
        '-Y', 'usb.transfer_type==0x03',
        '-T', 'fields',
        '-e', 'frame.number',
        '-e', 'usb.src',
        '-e', 'usb.dst',
        '-e', 'usb.data_len',
        '-e', 'usb.capdata',
    ]
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                text=True, timeout=60)
        return result.stdout
    except Exception as e:
        return ""


def parse_capt_commands_from_hex(hex_data):
    """Parse CAPT commands from a hex string. Returns list of (wire_cmd, size, payload_hex, full_raw)."""
    commands = []
    offset = 0
    hex_data = hex_data.strip()

    while offset + 8 <= len(hex_data):
        wire_cmd = hex_data[offset:offset+4]
        try:
            size_bytes = bytes.fromhex(hex_data[offset+4:offset+8])
        except ValueError:
            break

        size = struct.unpack('<H', size_bytes)[0]

        if size < 4 or size > 65535:
            break

        end = offset + size * 2
        if end > len(hex_data):
            # Truncated - take what we can
            payload_hex = hex_data[offset+8:]
            full_raw = hex_data[offset:]
            commands.append((wire_cmd, size, payload_hex, full_raw))
            break

        payload_hex = hex_data[offset+8:end]
        full_raw = hex_data[offset:end]
        commands.append((wire_cmd, size, payload_hex, full_raw))
        offset = end

    return commands


def get_cmd_name(wire_cmd):
    """Get command name from wire bytes."""
    info = CAPT_COMMANDS.get(wire_cmd)
    if info:
        return info[0]
    return f"UNKNOWN({wire_cmd})"


def decode_page_params(payload_hex, indent="    "):
    """Decode SET_PARM_PAGE (a0d0 / D0A0) payload."""
    lines = []

    try:
        data = bytes.fromhex(payload_hex)
    except ValueError:
        return [f"{indent}(invalid hex: {payload_hex})"]

    lines.append(f"{indent}Raw ({len(data)} bytes): {payload_hex}")

    if len(data) < 4:
        return lines

    # Based on the user's structure description for D0A0:
    # But first - the payload starts AFTER the 4-byte header (cmd+size)
    # So byte 0 of payload = byte 0 of the structure

    if len(data) >= 2:
        lines.append(f"{indent}Bytes 0-1 (header?):        0x{data[0]:02x} 0x{data[1]:02x}")
    if len(data) >= 4:
        # Check if bytes 2-3 are a sub-command header (like "312a" = "2a31" swapped)
        lines.append(f"{indent}Bytes 2-3 (header?):        0x{data[2]:02x} 0x{data[3]:02x}")
    if len(data) >= 6:
        paper_code = struct.unpack('<H', data[4:6])[0]
        paper_name = PAPER_SIZES.get(paper_code & 0xFF, f"UNKNOWN(0x{paper_code:04x})")
        lines.append(f"{indent}Bytes 4-5 (paper size):     0x{paper_code:04x} -> {paper_name}")
    if len(data) >= 8:
        lines.append(f"{indent}Bytes 6-7:                  0x{data[6]:02x} 0x{data[7]:02x}")
    if len(data) >= 9:
        toner = data[8]
        toner_names = {0x1F: "Normal", 0x0F: "Lightest", 0x3F: "Darkest",
                       0x17: "Light", 0x27: "Slightly_Dark", 0x2F: "Dark"}
        toner_s = toner_names.get(toner, f"Custom(0x{toner:02x})")
        lines.append(f"{indent}Byte  8   (toner density):  0x{toner:02x} = {toner_s}")
    if len(data) >= 10:
        lines.append(f"{indent}Byte  9:                    0x{data[9]:02x}")
    if len(data) >= 11:
        lines.append(f"{indent}Byte  10:                   0x{data[10]:02x}")
    if len(data) >= 12:
        lines.append(f"{indent}Byte  11:                   0x{data[11]:02x}")
    if len(data) >= 13:
        ptype = data[12]
        ptype_name = PAPER_TYPES.get(ptype, f"UNKNOWN(0x{ptype:02x})")
        lines.append(f"{indent}Byte  12  (paper type):     0x{ptype:02x} = {ptype_name}")
    if len(data) >= 20:
        lines.append(f"{indent}Bytes 13-18:                {' '.join(f'{b:02x}' for b in data[13:19])}")
        toner_save = data[19]
        lines.append(f"{indent}Byte  19  (toner save):     0x{toner_save:02x} = {'ON' if toner_save else 'OFF'}")
    if len(data) >= 26:
        lines.append(f"{indent}Bytes 20-25:                {' '.join(f'{b:02x}' for b in data[20:26])}")
    if len(data) >= 28:
        line_size = struct.unpack('<H', data[26:28])[0]
        lines.append(f"{indent}Bytes 26-27 (line size):    {line_size} bytes")
    if len(data) >= 30:
        num_lines = struct.unpack('<H', data[28:30])[0]
        lines.append(f"{indent}Bytes 28-29 (num lines):    {num_lines}")
    if len(data) >= 32:
        paper_w = struct.unpack('<H', data[30:32])[0]
        lines.append(f"{indent}Bytes 30-31 (paper width):  {paper_w} px")
    if len(data) >= 34:
        paper_h = struct.unpack('<H', data[32:34])[0]
        lines.append(f"{indent}Bytes 32-33 (paper height): {paper_h} px")
    if len(data) > 34:
        lines.append(f"{indent}Remaining ({len(data)-34}b):          {' '.join(f'{b:02x}' for b in data[34:])}")

    return lines


def decode_job_setup(payload_hex, indent="    "):
    """Decode JOB_SETUP (a1e1 / E1A1) payload."""
    lines = []
    try:
        data = bytes.fromhex(payload_hex)
    except ValueError:
        return [f"{indent}(invalid hex)"]

    lines.append(f"{indent}Raw ({len(data)} bytes): {payload_hex}")

    # The JOB_SETUP typically has some header bytes then null-terminated strings
    # Let's display the structure and extract printable strings
    if len(data) >= 8:
        lines.append(f"{indent}Header bytes: {' '.join(f'{b:02x}' for b in data[:8])}")

    # Find all null-terminated strings
    strings_found = []
    i = 0
    while i < len(data):
        # Look for a run of printable ASCII
        start = i
        s = ""
        while i < len(data) and data[i] >= 0x20 and data[i] < 0x7f:
            s += chr(data[i])
            i += 1
        if len(s) >= 2:  # only report strings of length >= 2
            strings_found.append((start, s))
        i += 1

    if strings_found:
        lines.append(f"{indent}Embedded strings:")
        labels = ["Hostname", "Username", "Document", "Extra1", "Extra2", "Extra3"]
        for idx, (offset, s) in enumerate(strings_found):
            label = labels[idx] if idx < len(labels) else f"String{idx}"
            lines.append(f"{indent}  [{label}] @offset {offset}: \"{s}\"")

    return lines


def decode_set_parms_wrapper(payload_hex, indent="    "):
    """Decode SET_PARMS (a9d0 / D0A9) wrapper containing sub-commands."""
    lines = []

    sub_cmds = parse_capt_commands_from_hex(payload_hex)
    if sub_cmds:
        lines.append(f"{indent}Contains {len(sub_cmds)} sub-command(s):")
        for i, (wire_cmd, size, sub_payload, raw) in enumerate(sub_cmds):
            name = get_cmd_name(wire_cmd)
            lines.append(f"{indent}  [{i}] {wire_cmd} ({name}) size={size}")

            if wire_cmd == "a0d0":
                lines.extend(decode_page_params(sub_payload, indent + "      "))
            elif wire_cmd == "a4d0":
                lines.append(f"{indent}      HISCOA params ({len(sub_payload)//2}b): {sub_payload[:100]}{'...' if len(sub_payload)>100 else ''}")
            elif wire_cmd == "a2e1":
                lines.append(f"{indent}      GPIO payload: {sub_payload}")
            elif wire_cmd == "a7e0":
                lines.append(f"{indent}      FIRE payload: {sub_payload}")
            else:
                if sub_payload:
                    lines.append(f"{indent}      payload: {sub_payload[:100]}{'...' if len(sub_payload)>100 else ''}")
    else:
        lines.append(f"{indent}Raw payload ({len(payload_hex)//2}b): {payload_hex[:120]}{'...' if len(payload_hex)>120 else ''}")

    return lines


def analyze_capture(pcap_file, filename, output):
    """Analyze a single pcapng capture file."""
    W = lambda s: output.append(s)

    W(f"\n{'='*100}")
    W(f"FILE: {filename}")
    W(f"{'='*100}")

    raw_output = run_tshark(pcap_file)
    if not raw_output.strip():
        W("  No USB bulk transfer data found.")
        return {}

    lines = raw_output.strip().split('\n')

    # Data structures
    command_sequence = []
    d0a0_payloads = []   # SET_PARM_PAGE (standalone)
    d0a9_payloads = []   # SET_PARMS wrapper
    e1a1_payloads = []   # JOB_SETUP
    e1a2_payloads = []   # GPIO
    a0a2_data = []       # JOB_BEGIN
    e0a7_data = []       # FIRE
    unknown_cmds = []
    all_wire_codes = set()

    for line in lines:
        parts = line.split('\t')
        if len(parts) < 4:
            continue

        frame_no = parts[0].strip()
        src = parts[1].strip()
        dst = parts[2].strip()
        data_len_str = parts[3].strip()
        capdata = parts[4].strip() if len(parts) > 4 else ""

        if not capdata:
            continue

        hex_data = capdata.replace(':', '').replace(' ', '').lower()
        is_outgoing = (src == "host")
        direction = "HOST>DEV" if is_outgoing else "DEV>HOST"

        cmds = parse_capt_commands_from_hex(hex_data)

        for wire_cmd, size, payload, raw in cmds:
            all_wire_codes.add(wire_cmd)
            name = get_cmd_name(wire_cmd)
            is_known = wire_cmd in CAPT_COMMANDS

            command_sequence.append({
                'frame': frame_no,
                'direction': direction,
                'wire_cmd': wire_cmd,
                'name': name,
                'size': size,
                'payload': payload,
                'raw': raw,
                'outgoing': is_outgoing,
            })

            if not is_known:
                unknown_cmds.append({
                    'frame': frame_no,
                    'direction': direction,
                    'wire_cmd': wire_cmd,
                    'size': size,
                    'payload': payload,
                    'raw': raw,
                })

            # Collect specific command types
            if wire_cmd == "a0d0":
                d0a0_payloads.append((frame_no, direction, payload))
            elif wire_cmd == "a9d0":
                d0a9_payloads.append((frame_no, direction, payload))
            elif wire_cmd == "a1e1":
                e1a1_payloads.append((frame_no, direction, payload))
            elif wire_cmd == "a2e1":
                e1a2_payloads.append((frame_no, direction, payload))
            elif wire_cmd == "a0a2":
                a0a2_data.append((frame_no, direction, payload, raw))
            elif wire_cmd == "a7e0":
                e0a7_data.append((frame_no, direction, payload, raw))

    # ---- PRINT RESULTS ----

    # Deduplicated command sequence (skip repeated polling)
    W(f"\n--- COMMAND SEQUENCE (unique, non-polling) ---")
    # First show full print-job related sequence (skip repeated CHKXSTATUS/IDENT polling)
    prev_pattern = ""
    repeat_count = 0
    for cmd in command_sequence:
        pattern = f"{cmd['direction']}:{cmd['wire_cmd']}"
        if pattern == prev_pattern and cmd['wire_cmd'] in ('a8a0', 'a0a1', 'a1a0'):
            repeat_count += 1
            continue
        else:
            if repeat_count > 0:
                W(f"    ... ({repeat_count} more repeated {get_cmd_name(prev_pattern.split(':')[1])} polls) ...")
                repeat_count = 0
            trunc_p = cmd['payload'][:50] + "..." if len(cmd['payload']) > 50 else cmd['payload']
            W(f"  Fr{cmd['frame']:>5} {cmd['direction']:>8} {cmd['wire_cmd']} {cmd['name']:<22s} sz={cmd['size']:>6} {'payload=' + trunc_p if trunc_p else ''}")
        prev_pattern = pattern

    if repeat_count > 0:
        W(f"    ... ({repeat_count} more repeated polls) ...")

    # D0A9 wrappers
    if d0a9_payloads:
        W(f"\n--- a9d0 (SET_PARMS / D0A9) WRAPPERS ({len(d0a9_payloads)} found) ---")
        for frame, direction, payload in d0a9_payloads:
            W(f"\n  Frame {frame} {direction}:")
            for line in decode_set_parms_wrapper(payload):
                W(line)

    # Standalone D0A0
    if d0a0_payloads:
        W(f"\n--- a0d0 (SET_PARM_PAGE / D0A0) STANDALONE ({len(d0a0_payloads)} found) ---")
        for frame, direction, payload in d0a0_payloads:
            W(f"\n  Frame {frame} {direction}:")
            for line in decode_page_params(payload):
                W(line)

    # JOB_SETUP
    if e1a1_payloads:
        W(f"\n--- a1e1 (JOB_SETUP / E1A1) ({len(e1a1_payloads)} found) ---")
        for frame, direction, payload in e1a1_payloads:
            W(f"\n  Frame {frame} {direction}:")
            for line in decode_job_setup(payload):
                W(line)

    # GPIO
    if e1a2_payloads:
        W(f"\n--- a2e1 (GPIO / E1A2) ({len(e1a2_payloads)} found) ---")
        for frame, direction, payload in e1a2_payloads:
            W(f"  Frame {frame} {direction}: {payload}")
            try:
                data = bytes.fromhex(payload)
                W(f"    Bytes: {' '.join(f'{b:02x}' for b in data)}")
            except:
                pass

    # JOB_BEGIN
    if a0a2_data:
        W(f"\n--- a0a2 (JOB_BEGIN / A2A0) ({len(a0a2_data)} found) ---")
        for frame, direction, payload, raw in a0a2_data:
            W(f"  Frame {frame} {direction}: raw={raw}")
            if payload:
                try:
                    data = bytes.fromhex(payload)
                    W(f"    Bytes: {' '.join(f'{b:02x}' for b in data)}")
                    if len(data) >= 4:
                        job_id = struct.unpack('<I', data[:4])[0]
                        W(f"    Possible job_id (LE32): {job_id} (0x{job_id:08x})")
                except:
                    pass

    # FIRE
    if e0a7_data:
        W(f"\n--- a7e0 (FIRE / E0A7) ({len(e0a7_data)} found) ---")
        for frame, direction, payload, raw in e0a7_data:
            W(f"  Frame {frame} {direction}: raw={raw}")
            if payload:
                try:
                    data = bytes.fromhex(payload)
                    W(f"    Bytes: {' '.join(f'{b:02x}' for b in data)}")
                except:
                    pass

    # Unknown commands (filter out continuation data like 0x0000, 0x0001, etc.)
    truly_unknown = [u for u in unknown_cmds
                     if u['wire_cmd'] not in ('0000', '0001', '0002', '0003', '0004')]
    if truly_unknown:
        # Deduplicate by wire_cmd
        unknown_by_code = defaultdict(list)
        for u in truly_unknown:
            unknown_by_code[u['wire_cmd']].append(u)

        W(f"\n--- UNKNOWN COMMANDS ({len(unknown_by_code)} unique codes, {len(truly_unknown)} occurrences) ---")
        for code, instances in sorted(unknown_by_code.items()):
            W(f"\n  Wire code: {code} ({len(instances)} occurrences)")
            # Show first 3
            for u in instances[:3]:
                trunc_raw = u['raw'][:100] + "..." if len(u['raw']) > 100 else u['raw']
                W(f"    Frame {u['frame']} {u['direction']} sz={u['size']} raw={trunc_raw}")
            if len(instances) > 3:
                W(f"    ... and {len(instances)-3} more")

    # Continuation/response data (0000, 0001, etc.) - these are likely multi-part responses
    continuation_cmds = [u for u in unknown_cmds
                         if u['wire_cmd'] in ('0000', '0001', '0002', '0003')]
    if continuation_cmds:
        cont_by_code = defaultdict(int)
        for u in continuation_cmds:
            cont_by_code[u['wire_cmd']] += 1
        W(f"\n--- CONTINUATION/MULTI-PART RESPONSES ---")
        for code, count in sorted(cont_by_code.items()):
            W(f"  Wire code {code}: {count} occurrences (likely continuation of previous response)")

    return {
        'command_sequence': command_sequence,
        'wire_codes': all_wire_codes,
        'd0a0': d0a0_payloads,
        'd0a9': d0a9_payloads,
        'e1a1': e1a1_payloads,
        'e1a2': e1a2_payloads,
        'a0a2': a0a2_data,
        'e0a7': e0a7_data,
        'unknown': unknown_cmds,
    }


def main():
    base_dir = "/home/mrhell/Projects/misc/Canon-LBP2900B"
    dirs = [
        os.path.join(base_dir, "canonlbp"),
        os.path.join(base_dir, "canonlbp2"),
    ]

    output = []
    all_results = {}

    for d in dirs:
        if not os.path.isdir(d):
            continue
        for fn in sorted(os.listdir(d)):
            if fn.endswith('.pcapng'):
                full_path = os.path.join(d, fn)
                results = analyze_capture(full_path, fn, output)
                all_results[fn] = results

    # ---- CROSS-FILE SUMMARY ----
    output.append(f"\n{'='*100}")
    output.append("CROSS-FILE SUMMARY")
    output.append(f"{'='*100}")

    # All unique wire codes
    all_codes = set()
    for fn, res in all_results.items():
        all_codes.update(res.get('wire_codes', set()))

    output.append(f"\nAll unique CAPT wire codes seen across all captures:")
    for code in sorted(all_codes):
        name = get_cmd_name(code)
        notation = CAPT_COMMANDS.get(code, ("", ""))[1] if code in CAPT_COMMANDS else "N/A"
        output.append(f"  wire={code}  name={name:<25s}  user_notation={notation}")

    # Unknown codes only
    known_codes = set(CAPT_COMMANDS.keys())
    # Also exclude continuation data codes
    really_unknown = all_codes - known_codes - {'0000', '0001', '0002', '0003', '0004',
                                                  'd000', '312a'}
    if really_unknown:
        output.append(f"\nTruly UNKNOWN wire codes (not in command table):")
        for code in sorted(really_unknown):
            # Find which files contain this code
            files = [fn for fn, res in all_results.items() if code in res.get('wire_codes', set())]
            output.append(f"  {code} - found in: {', '.join(files[:5])}")
    else:
        output.append(f"\nNo truly unknown command codes found (all are accounted for).")

    # Page parameters comparison
    output.append(f"\n{'='*100}")
    output.append("PAGE PARAMETERS (D0A0) COMPARISON ACROSS FILES")
    output.append(f"{'='*100}")
    for fn, res in all_results.items():
        # Check both standalone and wrapped
        all_page_params = list(res.get('d0a0', []))

        # Also extract from D0A9 wrappers
        for frame, direction, wrapper_payload in res.get('d0a9', []):
            sub_cmds = parse_capt_commands_from_hex(wrapper_payload)
            for wire_cmd, size, sub_payload, raw in sub_cmds:
                if wire_cmd == "a0d0":
                    all_page_params.append((frame, direction + "(in D0A9)", sub_payload))

        if all_page_params:
            output.append(f"\n  {fn}:")
            for frame, direction, payload in all_page_params:
                if len(payload) >= 12:
                    try:
                        data = bytes.fromhex(payload)
                        paper_code = data[4] if len(data) > 4 else -1
                        paper_name = PAPER_SIZES.get(paper_code, f"0x{paper_code:02x}")
                        toner = data[8] if len(data) > 8 else -1
                        ptype = data[12] if len(data) > 12 else -1
                        ptype_name = PAPER_TYPES.get(ptype, f"0x{ptype:02x}")
                        toner_save = data[19] if len(data) > 19 else -1
                        w = struct.unpack('<H', data[30:32])[0] if len(data) >= 32 else 0
                        h = struct.unpack('<H', data[32:34])[0] if len(data) >= 34 else 0
                        output.append(f"    Fr{frame} {direction}: paper={paper_name}, toner=0x{toner:02x}, type={ptype_name}, save={'ON' if toner_save else 'OFF'}, {w}x{h}px")
                    except Exception as e:
                        output.append(f"    Fr{frame}: parse error: {e}")

    # JOB_SETUP comparison
    output.append(f"\n{'='*100}")
    output.append("JOB_SETUP (E1A1) COMPARISON ACROSS FILES")
    output.append(f"{'='*100}")
    for fn, res in all_results.items():
        if res.get('e1a1'):
            output.append(f"\n  {fn}:")
            for frame, direction, payload in res['e1a1']:
                try:
                    data = bytes.fromhex(payload)
                    strings_found = []
                    i = 0
                    while i < len(data):
                        start = i
                        s = ""
                        while i < len(data) and data[i] >= 0x20 and data[i] < 0x7f:
                            s += chr(data[i])
                            i += 1
                        if len(s) >= 2:
                            strings_found.append(s)
                        i += 1
                    strings_str = " | ".join(f'"{s}"' for s in strings_found)
                    output.append(f"    Fr{frame} {direction}: {strings_str}")
                except:
                    output.append(f"    Fr{frame}: raw={payload[:60]}")

    # Print all output
    full_text = '\n'.join(output)
    print(full_text)

    # Also save to file
    with open('/tmp/capt_analysis_v2.txt', 'w') as f:
        f.write(full_text)

    print(f"\n\nFull analysis saved to /tmp/capt_analysis_v2.txt")


if __name__ == '__main__':
    main()
