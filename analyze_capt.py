#!/usr/bin/env python3
"""
CAPT Protocol Analyzer - Extracts and decodes CAPT commands from USB pcapng captures.
"""

import subprocess
import sys
import os
import struct
from collections import OrderedDict

# CAPT command definitions
CAPT_COMMANDS = {
    0xA0A1: "CHKJOBSTAT",
    0xA0A8: "CHKXSTATUS",
    0xA1A0: "IDENT_QUERY",       # appears as a1a0
    0xA1A1: "IDENT",
    0xA2A0: "JOB_BEGIN",
    0xC0A0: "PRINT_DATA",
    0xC0A4: "PRINT_DATA_END",
    0xD0A0: "SET_PARM_PAGE",
    0xD0A4: "SET_PARM_HISCOA",
    0xD0A9: "SET_PARMS",
    0xE0A7: "FIRE",
    0xE0A9: "JOB_END",
    0xE1A1: "JOB_SETUP",
    0xE1A2: "GPIO",
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
                                text=True, timeout=30)
        return result.stdout
    except Exception as e:
        print(f"  ERROR running tshark: {e}")
        return ""


def parse_capt_command(hex_data, offset=0):
    """Parse a single CAPT command from hex data at given offset.
    Returns (cmd_code, size, payload_hex, total_bytes_consumed) or None."""
    if len(hex_data) < offset + 8:  # minimum 4 bytes = 8 hex chars
        return None

    try:
        cmd_bytes = bytes.fromhex(hex_data[offset:offset+4])
        size_bytes = bytes.fromhex(hex_data[offset+4:offset+8])
    except ValueError:
        return None

    # Command code: first 2 bytes as big-endian for display (a1a1 -> 0xA1A1)
    cmd_code = (cmd_bytes[0] << 8) | cmd_bytes[1]
    # Size: 2 bytes little-endian
    size = struct.unpack('<H', size_bytes)[0]

    if size < 4:
        return None

    payload_len = size - 4  # size includes the 4-byte header
    payload_hex = hex_data[offset+8:offset+8+payload_len*2]

    return (cmd_code, size, payload_hex, size * 2)


def parse_all_commands(hex_data):
    """Parse all CAPT commands from a hex string (handles chained commands like D0A9)."""
    commands = []
    offset = 0
    while offset < len(hex_data) - 7:
        result = parse_capt_command(hex_data, offset)
        if result is None:
            break
        cmd_code, size, payload_hex, consumed = result
        commands.append((cmd_code, size, payload_hex))
        offset += consumed
    return commands


def decode_page_params(payload_hex):
    """Decode D0A0 SET_PARM_PAGE payload."""
    if len(payload_hex) < 68:  # at least 34 bytes
        return f"  (payload too short: {len(payload_hex)//2} bytes)"

    try:
        data = bytes.fromhex(payload_hex)
    except ValueError:
        return "  (invalid hex)"

    lines = []
    lines.append(f"  Raw hex ({len(data)} bytes): {payload_hex}")

    if len(data) >= 2:
        lines.append(f"  Bytes 0-1 (header?):        {data[0]:02x} {data[1]:02x}")
    if len(data) >= 4:
        lines.append(f"  Bytes 2-3 (header?):        {data[2]:02x} {data[3]:02x}")
    if len(data) >= 6:
        paper_code = struct.unpack('<H', data[4:6])[0]
        paper_name = PAPER_SIZES.get(paper_code, f"UNKNOWN(0x{paper_code:04x})")
        lines.append(f"  Bytes 4-5 (paper size):     0x{paper_code:04x} = {paper_name}")
    if len(data) >= 8:
        lines.append(f"  Bytes 6-7:                  {data[6]:02x} {data[7]:02x}")
    if len(data) >= 9:
        toner = data[8]
        if toner == 0x1F:
            toner_s = "Normal"
        elif toner == 0x0F:
            toner_s = "Lightest"
        elif toner == 0x3F:
            toner_s = "Darkest"
        else:
            toner_s = f"Custom(0x{toner:02x})"
        lines.append(f"  Byte 8 (toner density):     0x{toner:02x} = {toner_s}")
    if len(data) >= 12:
        lines.append(f"  Bytes 9-11:                 {data[9]:02x} {data[10]:02x} {data[11]:02x}")
    if len(data) >= 13:
        ptype = data[12]
        ptype_name = PAPER_TYPES.get(ptype, f"UNKNOWN(0x{ptype:02x})")
        lines.append(f"  Byte 12 (paper type):       0x{ptype:02x} = {ptype_name}")
    if len(data) >= 20:
        lines.append(f"  Bytes 13-18:                {' '.join(f'{b:02x}' for b in data[13:19])}")
        toner_save = data[19]
        lines.append(f"  Byte 19 (toner save):       0x{toner_save:02x} = {'ON' if toner_save else 'OFF'}")
    if len(data) >= 26:
        lines.append(f"  Bytes 20-25:                {' '.join(f'{b:02x}' for b in data[20:26])}")
    if len(data) >= 28:
        line_size = struct.unpack('<H', data[26:28])[0]
        lines.append(f"  Bytes 26-27 (line size):    {line_size} bytes (0x{line_size:04x})")
    if len(data) >= 30:
        num_lines = struct.unpack('<H', data[28:30])[0]
        lines.append(f"  Bytes 28-29 (num lines):    {num_lines} (0x{num_lines:04x})")
    if len(data) >= 32:
        paper_w = struct.unpack('<H', data[30:32])[0]
        lines.append(f"  Bytes 30-31 (paper width):  {paper_w} pixels (0x{paper_w:04x})")
    if len(data) >= 34:
        paper_h = struct.unpack('<H', data[32:34])[0]
        lines.append(f"  Bytes 32-33 (paper height): {paper_h} pixels (0x{paper_h:04x})")
    if len(data) > 34:
        lines.append(f"  Remaining bytes ({len(data)-34}):      {' '.join(f'{b:02x}' for b in data[34:])}")

    return '\n'.join(lines)


def decode_job_setup(payload_hex):
    """Decode E1A1 JOB_SETUP payload - contains hostname, username, docname."""
    try:
        data = bytes.fromhex(payload_hex)
    except ValueError:
        return "  (invalid hex)"

    lines = []
    lines.append(f"  Raw hex ({len(data)} bytes): {payload_hex}")

    # Try to extract null-terminated strings
    strings = []
    current = b""
    for b in data:
        if b == 0:
            if current:
                try:
                    strings.append(current.decode('utf-8', errors='replace'))
                except:
                    strings.append(current.hex())
                current = b""
        elif 0x20 <= b < 0x7f:
            current += bytes([b])
        else:
            if current:
                try:
                    strings.append(current.decode('utf-8', errors='replace'))
                except:
                    pass
                current = b""

    if current:
        try:
            strings.append(current.decode('utf-8', errors='replace'))
        except:
            pass

    if strings:
        labels = ["Hostname", "Username", "Document", "Extra"]
        for i, s in enumerate(strings):
            label = labels[i] if i < len(labels) else f"String{i}"
            lines.append(f"  {label}: \"{s}\"")

    return '\n'.join(lines)


def decode_d0a9_wrapper(payload_hex):
    """Decode D0A9 SET_PARMS wrapper - contains multiple sub-commands."""
    lines = []
    lines.append(f"  Raw wrapper ({len(payload_hex)//2} bytes payload)")

    # Parse sub-commands within the wrapper
    sub_cmds = parse_all_commands(payload_hex)
    if sub_cmds:
        lines.append(f"  Contains {len(sub_cmds)} sub-command(s):")
        for i, (cmd, size, payload) in enumerate(sub_cmds):
            cmd_name = CAPT_COMMANDS.get(cmd, f"UNKNOWN_0x{cmd:04X}")
            lines.append(f"    [{i}] 0x{cmd:04X} ({cmd_name}) size={size}")
            if cmd == 0xD0A0:
                lines.append(decode_page_params(payload))
            elif cmd == 0xE1A2:
                lines.append(f"    GPIO payload: {payload}")
            elif cmd == 0xE0A7:
                lines.append(f"    FIRE payload: {payload}")
            elif cmd == 0xD0A4:
                lines.append(f"    HISCOA payload ({len(payload)//2} bytes): {payload[:80]}{'...' if len(payload)>80 else ''}")
            else:
                if payload:
                    lines.append(f"    Payload: {payload[:120]}{'...' if len(payload)>120 else ''}")
    else:
        lines.append(f"  Raw: {payload_hex[:120]}{'...' if len(payload_hex)>120 else ''}")

    return '\n'.join(lines)


def decode_chkxstatus_reply(payload_hex):
    """Decode A0A8 CHKXSTATUS reply."""
    try:
        data = bytes.fromhex(payload_hex)
    except ValueError:
        return f"  (invalid hex: {payload_hex})"

    lines = []
    lines.append(f"  Raw ({len(data)} bytes): {payload_hex}")
    return '\n'.join(lines)


def analyze_capture(pcap_file, filename):
    """Analyze a single pcapng capture file."""
    print(f"\n{'='*100}")
    print(f"FILE: {filename}")
    print(f"{'='*100}")

    output = run_tshark(pcap_file)
    if not output.strip():
        print("  No USB bulk transfer data found.")
        return {}

    lines = output.strip().split('\n')

    # Collect all transfers
    host_to_printer = []  # OUT (commands sent to printer)
    printer_to_host = []  # IN (responses from printer)
    all_commands = []
    unknown_commands = []
    d0a0_payloads = []
    d0a9_payloads = []
    e1a1_payloads = []
    e1a2_payloads = []
    a2a0_data = []
    e0a7_data = []
    command_sequence = []

    for line in lines:
        parts = line.split('\t')
        if len(parts) < 5:
            continue

        frame_no = parts[0].strip()
        src = parts[1].strip()
        dst = parts[2].strip()
        data_len = parts[3].strip()
        capdata = parts[4].strip() if len(parts) > 4 else ""

        if not capdata:
            continue

        # Clean hex data (remove colons, spaces)
        hex_data = capdata.replace(':', '').replace(' ', '').lower()

        is_outgoing = (src == "host")
        direction = "OUT>>>" if is_outgoing else "<<<IN"

        # Parse commands
        cmds = parse_all_commands(hex_data)

        if cmds:
            for cmd_code, size, payload in cmds:
                cmd_name = CAPT_COMMANDS.get(cmd_code, None)
                if cmd_name is None:
                    cmd_name = f"UNKNOWN_0x{cmd_code:04X}"
                    unknown_commands.append((frame_no, direction, cmd_code, size, payload, hex_data))

                command_sequence.append((frame_no, direction, cmd_code, cmd_name, size, payload))

                if cmd_code == 0xD0A0:
                    d0a0_payloads.append((frame_no, direction, payload, hex_data))
                elif cmd_code == 0xD0A9:
                    d0a9_payloads.append((frame_no, direction, payload, hex_data))
                elif cmd_code == 0xE1A1:
                    e1a1_payloads.append((frame_no, direction, payload, hex_data))
                elif cmd_code == 0xE1A2:
                    e1a2_payloads.append((frame_no, direction, payload, hex_data))
                elif cmd_code == 0xA2A0:
                    a2a0_data.append((frame_no, direction, payload, hex_data))
                elif cmd_code == 0xE0A7:
                    e0a7_data.append((frame_no, direction, payload, hex_data))
        else:
            # Data that doesn't parse as CAPT command (might be print data payload)
            if len(hex_data) > 8:
                # Check first 4 bytes as potential command
                try:
                    first2 = int(hex_data[:4], 16)
                    if first2 not in CAPT_COMMANDS:
                        # Might be raw print data or multi-part response
                        pass
                except:
                    pass

    # Print command sequence
    print(f"\n--- COMMAND SEQUENCE ({len(command_sequence)} commands) ---")
    for frame, direction, code, name, size, payload in command_sequence:
        trunc_payload = payload[:40] + "..." if len(payload) > 40 else payload
        print(f"  Frame {frame:>5} {direction} 0x{code:04X} {name:<20s} size={size:>5}  payload={trunc_payload}")

    # Print D0A9 SET_PARMS wrapper details
    if d0a9_payloads:
        print(f"\n--- D0A9 (SET_PARMS) WRAPPER PAYLOADS ({len(d0a9_payloads)} found) ---")
        for frame, direction, payload, raw in d0a9_payloads:
            print(f"\n  Frame {frame} {direction}:")
            print(decode_d0a9_wrapper(payload))

    # Print D0A0 SET_PARM_PAGE details
    if d0a0_payloads:
        print(f"\n--- D0A0 (SET_PARM_PAGE) PAYLOADS ({len(d0a0_payloads)} found) ---")
        for frame, direction, payload, raw in d0a0_payloads:
            print(f"\n  Frame {frame} {direction}:")
            print(decode_page_params(payload))

    # Print E1A1 JOB_SETUP details
    if e1a1_payloads:
        print(f"\n--- E1A1 (JOB_SETUP) PAYLOADS ({len(e1a1_payloads)} found) ---")
        for frame, direction, payload, raw in e1a1_payloads:
            print(f"\n  Frame {frame} {direction}:")
            print(decode_job_setup(payload))

    # Print E1A2 GPIO details
    if e1a2_payloads:
        print(f"\n--- E1A2 (GPIO) PAYLOADS ({len(e1a2_payloads)} found) ---")
        for frame, direction, payload, raw in e1a2_payloads:
            print(f"  Frame {frame} {direction}: {payload}")

    # Print A2A0 JOB_BEGIN details
    if a2a0_data:
        print(f"\n--- A2A0 (JOB_BEGIN) DATA ({len(a2a0_data)} found) ---")
        for frame, direction, payload, raw in a2a0_data:
            print(f"  Frame {frame} {direction}: raw={raw}  payload={payload}")

    # Print E0A7 FIRE details
    if e0a7_data:
        print(f"\n--- E0A7 (FIRE) DATA ({len(e0a7_data)} found) ---")
        for frame, direction, payload, raw in e0a7_data:
            print(f"  Frame {frame} {direction}: raw={raw}  payload={payload}")

    # Print unknown commands
    if unknown_commands:
        print(f"\n--- UNKNOWN COMMANDS ({len(unknown_commands)} found) ---")
        for frame, direction, code, size, payload, raw in unknown_commands:
            print(f"  Frame {frame} {direction}: cmd=0x{code:04X} size={size} raw={raw[:80]}")
    else:
        print(f"\n--- No unknown commands found ---")

    return {
        'command_sequence': command_sequence,
        'd0a0': d0a0_payloads,
        'd0a9': d0a9_payloads,
        'e1a1': e1a1_payloads,
        'e1a2': e1a2_payloads,
        'a2a0': a2a0_data,
        'e0a7': e0a7_data,
        'unknown': unknown_commands,
    }


def main():
    base_dir = "/home/mrhell/Projects/misc/Canon-LBP2900B"

    dirs = [
        os.path.join(base_dir, "canonlbp"),
        os.path.join(base_dir, "canonlbp2"),
    ]

    all_results = {}

    for d in dirs:
        if not os.path.isdir(d):
            continue
        for fn in sorted(os.listdir(d)):
            if fn.endswith('.pcapng'):
                full_path = os.path.join(d, fn)
                results = analyze_capture(full_path, fn)
                all_results[fn] = results

    # Summary
    print(f"\n{'='*100}")
    print("CROSS-FILE SUMMARY")
    print(f"{'='*100}")

    # Collect all unique command codes
    all_codes = set()
    all_unknowns = set()
    for fn, res in all_results.items():
        for _, _, code, _, _, _ in res.get('command_sequence', []):
            all_codes.add(code)
        for _, _, code, _, _, _ in res.get('unknown', []):
            all_unknowns.add(code)

    print(f"\nAll unique CAPT command codes seen across all captures:")
    for code in sorted(all_codes):
        name = CAPT_COMMANDS.get(code, "UNKNOWN")
        print(f"  0x{code:04X} = {name}")

    if all_unknowns:
        print(f"\nUNKNOWN command codes (not in known list):")
        for code in sorted(all_unknowns):
            print(f"  0x{code:04X}")

    # Compare page parameters across captures
    print(f"\nPage parameter comparison (D0A0 payloads):")
    for fn, res in all_results.items():
        if res.get('d0a0'):
            print(f"\n  {fn}:")
            for frame, direction, payload, raw in res['d0a0']:
                if len(payload) >= 68:
                    try:
                        data = bytes.fromhex(payload)
                        paper_code = struct.unpack('<H', data[4:6])[0]
                        paper_name = PAPER_SIZES.get(paper_code, f"0x{paper_code:04x}")
                        toner = data[8]
                        ptype = data[12] if len(data) > 12 else -1
                        toner_save = data[19] if len(data) > 19 else -1
                        w = struct.unpack('<H', data[30:32])[0] if len(data) >= 32 else 0
                        h = struct.unpack('<H', data[32:34])[0] if len(data) >= 34 else 0
                        print(f"    Frame {frame}: paper={paper_name}, toner=0x{toner:02x}, type=0x{ptype:02x}, save=0x{toner_save:02x}, {w}x{h}px")
                    except Exception as e:
                        print(f"    Frame {frame}: parse error: {e}")


if __name__ == '__main__':
    main()
