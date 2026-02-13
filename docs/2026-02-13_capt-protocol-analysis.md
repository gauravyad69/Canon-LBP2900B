# Canon LBP2900 CAPT Protocol Analysis

**Date:** 2026-02-13  
**Source:** USB capture `print3continuousPages.pcapng` (3-page Windows print job)  
**Windows Driver:** `LBP2900_R150_V330_W64_uk_EN_2.exe` (v3.30, 11MB PE32 installer)  
**Decoder:** `/tmp/decode_capt.py` (custom Python CAPT USB packet decoder)

---

## 1. Driver Extraction

The Windows installer is a self-extracting ZIP containing SZDD-compressed DLLs:

| Binary | Size | Purpose |
|--------|------|---------|
| `cnab4rdd.dll` | 1.2MB | Ultra Fast Rendering module (rasterization/HiSCoA) |
| `cpc10da4.exe` | 998KB | Despooler (spool data processing pipeline) |
| `cnab4m.dll` | 990KB | CAPT printer graphics DDI driver |
| `cnab4lmd.dll` | 57KB | Language monitor (loads CNAB4SMD.DLL) |
| `cnab4pmd.dll` | 265KB | Port/Status Monitor UI |
| `cnab4icd.dll` | 672KB | Installer/Configuration driver |
| `cnab4809.dll` | 1.3MB | CAPT UI DLL (driver settings) |
| `cnab4smd.dll` | 126KB | Status monitor driver |

The actual CAPT USB communication layer is constructed indirectly through dispatch
tables — command IDs are not found as simple immediates in the binaries.

---

## 2. CAPT Command Reference

| Command ID | Name | Direction | Description |
|------------|------|-----------|-------------|
| `0xA1A1` | CAPT_IDENT | Host→Printer | Identify printer model |
| `0xA0A8` | CAPT_CHKXSTATUS | Host→Printer | Extended status query (40-byte response) |
| `0xE0A0` | CAPT_CHKSTATUS | Host→Printer | Basic status query (2-byte response) |
| `0xA0A1` | CAPT_CHKJOBSTAT | Host→Printer | Job status query |
| `0xA2A0` | CAPT_JOB_BEGIN | Host→Printer | Begin job, returns 2-byte job ID |
| `0xE1A1` | CAPT_JOB_SETUP | Host→Printer | Job metadata (fg flag, page count, strings) |
| `0xE0A6` | CAPT_UNKNOWN_E0A6 | Host→Printer | Unknown init command (2 bytes: 00 00) |
| `0xE0A3` | CAPT_START_1 | Host→Printer | Printer init step 1 |
| `0xE0A2` | CAPT_START_2 | Host→Printer | Printer init step 2 |
| `0xE0A4` | CAPT_START_3 | Host→Printer | Printer init step 3 |
| `0xE0A5` | CAPT_UPLOAD_2 | Host→Printer | Upload firmware params (16 bytes) |
| `0xD0A9` | CAPT_SET_PARMS | Host→Printer | Multi-param wrapper (page + HiSCoA params) |
| `0xC0A0` | CAPT_PRINT_DATA | Host→Printer | HiSCoA compressed page data |
| `0xC0A4` | CAPT_PRINT_DATA_END | Host→Printer | End of page data block |
| `0xE0A7` | CAPT_FIRE | Host→Printer | Fire/print page (2-byte page number) |
| `0xE0A9` | CAPT_JOB_END | Host→Printer | End job (2-byte job ID) |
| `0xE1A2` | CAPT_GPIO | Host→Printer | LED control (12 bytes) |

---

## 3. JOB_SETUP (0xE1A1) Payload Structure

Total size: 72 bytes header + variable-length UTF-16LE strings

| Offset | Size | Field | Notes |
|--------|------|-------|-------|
| 0–3 | 4 | Reserved | `00 00 00 00` |
| 4–5 | 2 | Page number | LE16: 0 at job start, total pages in fg=1, last page in fg=6 |
| 6–7 | 2 | Reserved | `00 00` |
| 8–9 | 2 | Hostname length | UTF-16LE byte count |
| 10–11 | 2 | Username length | UTF-16LE byte count |
| 12–13 | 2 | Doc name length | UTF-16LE byte count |
| 14–15 | 2 | Reserved | `00 00` |
| 16 | 1 | **fg value** | `1` = job start, `6` = job end |
| 17 | 1 | Unknown | `0x01` |
| 18–19 | 2 | Job ID | LE16, matches JOB_BEGIN response |
| 20–21 | 2 | Timezone offset 1 | `0xFFC4` = -60 |
| 22–23 | 2 | Timezone offset 2 | `0xFF88` = -120 |
| 24–25 | 2 | Year | LE16 (e.g., 2025) |
| 26 | 1 | Month | 1–12 |
| 27 | 1 | Day | 1–31 |
| 28 | 1 | Hour | 0–23 |
| 29 | 1 | Minute | 0–59 |
| 30 | 1 | Second | 0–59 |
| 31 | 1 | Unknown | `0x01` |
| 32–71 | 40 | Reserved | Zeros |
| 72+ | var | Strings | UTF-16LE: hostname, username, doc name (concatenated) |

### fg Values

| fg | Meaning | When Sent | Page Field |
|----|---------|-----------|------------|
| 1 | Job start | Once, at job prologue | Total page count (or 0) |
| 2 | **NEVER USED** | Windows driver never sends fg=2 | N/A |
| 6 | Job end | Once, immediately after last FIRE | Last fired page number |

---

## 4. Extended Status Response (0xA0A8) Structure

40-byte response from printer:

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0–1 | 2 | status[0] | Flags: READY, UNINIT, BUFFERFULL, NOPAPER, BUSY |
| 8–9 | 2 | status[1] | Flags: NOPAPER2, PRINTING, BUTTON, PROCESSING |
| 10–11 | 2 | status[2] | Flags: nERROR, BUTTON1 |
| 12–13 | 2 | status[3] | Flags: POWERUP1 |
| 14–15 | 2 | page_decoding | Pages decoded by printer firmware |
| 16–17 | 2 | page_printing | Pages currently being printed |
| 18–19 | 2 | page_out | Pages physically ejected from fuser |
| 20–21 | 2 | page_completed | Pages fully completed |
| 34–35 | 2 | page_received | Pages received into printer buffer |

### Key Status Flags (status[0])

| Bit | Flag | Meaning |
|-----|------|---------|
| 15 | READY1 | Printer ready |
| 12 | READY2 | Printer ready (alt) |
| 7 | BUSY | Printer busy processing |
| 5 | UNINIT1 | Needs initialization (START_1/2/3) |
| 4 | UNINIT2 | Needs initialization |
| 2 | BUFFERFULL | Print buffer full, wait before sending more |
| 1 | NOPAPER1 | Paper tray empty |
| 0 | PROCESSING | Processing data |

---

## 5. Windows 3-Page Print Protocol (Complete Trace)

Decoded from `print3continuousPages.pcapng`:

```
=== JOB PROLOGUE ===
[27]  CAPT_IDENT
[33]  CAPT_CHKXSTATUS
[39]  CAPT_CHKJOBSTAT
[45]  CAPT_CHKXSTATUS
[51]  CAPT_CHKJOBSTAT
[57]  CAPT_JOB_BEGIN → job_id=7
[63]  CAPT_JOB_SETUP  fg=1, page=3, job=7  ← TOTAL PAGE COUNT
[66]  RECV JOB_SETUP ACK
[67]  CAPT_CHKSTATUS
[73]  CAPT_CHKXSTATUS
[79]  CAPT_CHKJOBSTAT
[85]  CAPT_UNKNOWN_E0A6 (0x00, 0x00)  ← SENT FOR LBP2900 TOO
[89]  CAPT_CHKSTATUS

=== PRINTER INIT (first page only, when UNINIT flags set) ===
[95]  CAPT_START_1
[99]  CAPT_START_2
[103] CAPT_START_3
[107] CAPT_CHKSTATUS (wait for init)
[113] CAPT_UPLOAD_2 (16 bytes firmware params)
[117] CAPT_CHKSTATUS
[123] CAPT_CHKXSTATUS
[129] CAPT_CHKSTATUS (status polling)
[135] CAPT_CHKSTATUS
[141] CAPT_CHKSTATUS

=== PAGE 1+2 DATA UPLOAD (pre-uploaded together!) ===
[147] CAPT_SET_PARMS (68 bytes: page params + HiSCoA)
[149] CAPT_PRINT_DATA (large frame, ~49KB)
[151] CAPT_PRINT_DATA_END  ← page 1 data complete
[153] CAPT_PRINT_DATA (large frame, ~49KB)
[155] CAPT_PRINT_DATA_END  ← page 2 data complete

=== PAGE 1+2 PARAMS AND FIRE ===
[157-168] Status polling
[169] CAPT_SET_PARMS (68 bytes)  ← page params resent
[171-182] Status polling
[183] CAPT_FIRE page=1  ← FIRE PAGE 1
[187-313] Status polling (~130 frames, ~20 seconds)
[319] CAPT_FIRE page=2  ← FIRE PAGE 2 (no new SET_PARMS needed)
[323-527] Status polling (~200 frames, ~30 seconds)

=== PAGE 3 DATA UPLOAD AND FIRE ===
[533] CAPT_SET_PARMS (68 bytes)
[535] CAPT_PRINT_DATA (large frame)
[537] CAPT_PRINT_DATA_END  ← page 3 data complete
[539-550] Status polling
[551] CAPT_FIRE page=3  ← FIRE PAGE 3

=== JOB EPILOGUE (IMMEDIATELY after last FIRE) ===
[555] CAPT_JOB_SETUP fg=6, page=3  ← SENT ONCE, RIGHT AFTER LAST FIRE
[558] RECV JOB_SETUP ACK
[559] CAPT_JOB_END job=7
[562] RECV JOB_END ACK
[563-629] Post-job status polling (CHKXSTATUS + CHKJOBSTAT pairs)
```

---

## 6. Critical Differences: Windows vs Old Linux Driver

| Aspect | Windows Driver | Old Linux Driver (broken) |
|--------|---------------|--------------------------|
| **fg=1 page count** | `page=3` (total pages) | `page=0` (unknown) |
| **fg=2 JOB_SETUP** | **NEVER sent** | Sent after every page ❌ |
| **fg=6 JOB_SETUP** | Sent **once**, immediately after last FIRE | Sent after **every** page ❌ |
| **page_out wait** | Does **not** wait for page ejection between pages | Waits for `page_out == page_decoding` after every page ❌ |
| **0xE0A6 command** | Sent in job prologue (frame 85) | Missing from LBP2900 prologue ❌ |
| **Data pre-upload** | Uploads multiple pages before firing | Sequential: upload → fire → upload → fire |
| **FIRE timing** | Fires pages in sequence, status-poll between | Same (ok) |
| **Job end sequence** | FIRE(last) → fg=6 → JOB_END | fg=6 was in page_epilogue, wait page_completed before fg=6 ❌ |

---

## 7. Bugs Fixed

### Bug 1: Extra Blank Page (fg=6 per page)
- **Root Cause:** `send_job_start(state, 6, ...)` was called in `page_epilogue` after every page. fg=6 signals "job complete" to the printer firmware, which caused it to attempt paper ejection/finalization after each page, pulling an extra blank sheet.
- **Fix:** Moved fg=6 to `job_epilogue`, sent exactly once immediately after the last FIRE.

### Bug 2: Spurious fg=2 JOB_SETUP
- **Root Cause:** `send_job_start(state, 2, ...)` was called in `page_epilogue` before FIRE. The Windows driver **never** sends fg=2.
- **Fix:** Removed fg=2 entirely.

### Bug 3: page_out Wait Blocking Between Pages
- **Root Cause:** `page_epilogue` waited for `page_out == page_decoding` (physical page ejection) before returning. This blocked the driver from proceeding to the next page, causing timing mismatches with the printer firmware.
- **Fix:** Removed `page_out` wait from `page_epilogue`. Page completion is now only checked at job end via `page_completed == page_decoding`.

### Bug 4: Missing 0xE0A6 Command
- **Root Cause:** The LBP2900 `job_prologue` did not send the `0xE0A6` command, even though the Windows USB capture shows it being sent (frame 85). The LBP3000 code already had it.
- **Fix:** Added `0xE0A6` with payload `{0x00, 0x00}` to `lbp2900_job_prologue`.

### Bug 5: fg=6 Timing (wait before vs after)
- **Root Cause:** `job_epilogue` waited for `page_completed == page_decoding` BEFORE sending fg=6. But the Windows capture shows fg=6 sent IMMEDIATELY after the last FIRE (frame 551→555), with no wait.
- **Fix:** Reordered: send fg=6 first, then wait for page_completed, then JOB_END.

### Bug 6: Date Encoding in JOB_SETUP
- **Root Cause:** `tm_year` was sent raw (years since 1900, e.g., 126 for 2026). `tm_mon` was sent raw (0-based, 0=January).
- **Fix:** `tm_year + 1900` and `tm_mon + 1`.

### Bug 7: String Buffer Overflow in JOB_SETUP
- **Root Cause:** No bounds checking on hostname/username/docname string lengths before UTF-16LE conversion. Long strings could overflow the allocated buffer.
- **Fix:** Added bounds: hostname max 32 chars, username max 32 chars, docname max 64 chars.

---

## 8. Correct Page Lifecycle (After Fix)

```
page_epilogue(state):
    CAPT_PRINT_DATA_END
    wait(page_received == page_decoding)
    CAPT_FIRE(page_decoding)
    state->last_fired_page = page_decoding
    return true  ← NO page_out wait

job_epilogue(state):
    CAPT_JOB_SETUP(fg=6, last_fired_page)  ← FIRST, before any wait
    wait(page_completed == page_decoding)
    CAPT_JOB_END(job_id)
```

---

## 9. SET_PARM_PAGE (0xD0A0) Structure — 40 bytes

| Offset | Size | Field | Example (A4) |
|--------|------|-------|-------------|
| 0–3 | 4 | Header | `00 00 30 2A` |
| 4 | 1 | Paper size code | `0x01` (A4) |
| 5–7 | 3 | Reserved | `00 00 00` |
| 8 | 1 | Toner density | `0x1F` (normal) |
| 9–11 | 3 | Sub-densities | `0x1C 0x1C 0x1C` |
| 12 | 1 | Paper type | `0x00` (Plain) |
| 13 | 1 | Adapt | `0x11` |
| 14 | 1 | Unknown | `0x04` |
| 15 | 1 | Reserved | `0x00` |
| 16 | 1 | Unknown | `0x01` |
| 17 | 1 | Unknown | `0x01` |
| 18 | 1 | Image ref | `0x00` |
| 19 | 1 | Toner save | `0x00` (off), `0x01` (on) |
| 20–21 | 2 | Reserved | `00 00` |
| 22–23 | 2 | Height margin | `0x0076` (118 pixels) |
| 24–25 | 2 | Width margin | `0x004E` (78 pixels) |
| 26–27 | 2 | Line size | LE16 bytes per line (592 for A4) |
| 28–29 | 2 | Num lines | LE16 (6776 for A4) |
| 30–31 | 2 | Paper width | LE16 pixels at 600dpi (4960 for A4) |
| 32–33 | 2 | Paper height | LE16 pixels at 600dpi (7014 for A4) |
| 34–39 | 6 | Tail | `00 00 01 00 00 00` |

### Paper Size Codes

| Code | Paper Size | Width×Height (600dpi) |
|------|-----------|----------------------|
| 0x01 | A4 | 4960 × 7014 |
| 0x02 | Letter | 5100 × 6600 |
| 0x03 | Legal | 5100 × 8400 |
| 0x04 | Executive | 4350 × 6300 |
| 0x05 | A5 | 3496 × 4960 |
| 0x06 | B5 | 4298 × 6070 |
| 0x07 | Com10 Envelope | 2474 × 5700 |
| 0x08 | Monarch Envelope | 2324 × 4500 |
| 0x09 | C5 Envelope | 3826 × 5408 |
| 0x0A | DL Envelope | 2598 × 5196 |
| 0x0B | Index Card 3×5 | 1800 × 2400 |

### Toner Density Map

| Level | Value | Description |
|-------|-------|-------------|
| 1 | 0x0F | Lightest |
| 2 | 0x17 | Light |
| 3 | 0x1F | Normal (default) |
| 4 | 0x2F | Dark |
| 5 | 0x3F | Darkest |

---

## 10. Tools Used

- **tshark**: USB pcapng packet extraction
- **Python 3**: Custom CAPT protocol decoder (`/tmp/decode_capt.py`)
- **radare2**: Binary analysis of extracted DLLs
- **7z**: Installer extraction
- **SZDD decompressor**: Custom Python script for MS Compress archives

## 11. Files Modified

- `src/prn_lbp2900.c` — Page/job lifecycle, JOB_SETUP metadata encoding
- `src/printer.h` — Added `last_fired_page` field to `printer_state_s`
