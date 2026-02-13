# Canon LBP2900B CAPT Protocol Analysis

> Comprehensive reverse-engineering analysis of USB captures from Canon LBP2900B printer.
> 18 pcapng files analyzed using tshark + custom Python parser.
> Updated with implementation verification and corrected findings.

---

## Table of Contents

1. [Wire Format](#1-wire-format)
2. [Command Table](#2-command-table)
3. [Standard Print Sequence](#3-standard-print-sequence)
4. [D0A9 SET_PARMS Wrapper Structure](#4-d0a9-set_parms-wrapper-structure)
5. [D0A0 SET_PARM_PAGE Byte Map](#5-d0a0-set_parm_page-byte-map)
6. [E1A1 JOB_SETUP Structure](#6-e1a1-job_setup-structure)
7. [Per-Capture Analysis](#7-per-capture-analysis)
8. [Page Parameters Comparison](#8-page-parameters-comparison)
9. [JOB_SETUP Comparison](#9-job_setup-comparison)
10. [GPIO (E1A2) Analysis](#10-gpio-e1a2-analysis)
11. [Status/Response Codes](#11-statusresponse-codes)
12. [Unknown Commands](#12-unknown-commands)
13. [Error/Recovery Scenarios](#13-errorrecovery-scenarios)
14. [JOB_BEGIN Retry Format](#14-job_begin-retry-format)
15. [Implementation Status](#15-implementation-status)

---

## 1. Wire Format

Every CAPT command on the USB bulk pipe is framed as:

```
[2 bytes: wire command] [2 bytes: total size (LE)] [N bytes: payload]
```

- **Total size** = 4 (header) + len(payload), little-endian.
- Commands with no payload have size = 4.
- **CRITICAL**: The wire byte order is **SWAPPED** relative to the canonical notation.
  Wire `a8a0` = canonical `0xA0A8` (CHKXSTATUS). First wire byte → low byte of user notation.

### Example

```
Wire bytes: a8 a0 04 00
             │  │  └──── size = 0x0004 = 4 (no payload)
             └──┘ wire cmd = a8a0 → user notation 0xA0A8 (CHKXSTATUS)
```

---

## 2. Command Table

All wire codes observed across 18 captures, with canonical notation:

| Wire Code | User Notation | Name               | Direction | Payload Size | Notes |
|-----------|--------------|---------------------|-----------|-------------|-------|
| `a1a1`    | 0xA1A1       | IDENT              | H↔D       | 0 / 52      | Identity/capabilities query |
| `a8a0`    | 0xA0A8       | CHKXSTATUS         | H↔D       | 0 / 52      | Extended status check |
| `a1a0`    | 0xA0A1       | CHKJOBSTAT         | H↔D       | 0 / 18      | Job status check |
| `a0a2`    | 0xA2A0       | JOB_BEGIN          | H↔D       | 8 / 4       | Start print job |
| `a1e1`    | 0xE1A1       | JOB_SETUP          | H↔D       | var / 2     | Job metadata (hostname/user/doc) |
| `a2e1`    | 0xE1A2       | GPIO               | H↔D       | 12 / 2      | GPIO/hardware control |
| `a9d0`    | 0xD0A9       | SET_PARMS          | H→D       | 64          | Wrapper for page parameters |
| `a0c0`    | 0xC0A0       | PRINT_DATA         | H→D       | var         | HISCOA-compressed page data |
| `a4c0`    | 0xC0A4       | PRINT_DATA_END     | H→D       | 0           | End of page data |
| `a7e0`    | 0xE0A7       | FIRE               | H↔D       | 2 / 2       | Execute/print page N |
| `a9e0`    | 0xE0A9       | JOB_END            | H↔D       | 2 / 2       | End print job |
| `a0e0`    | 0xE0A0       | CHKJOBSTAT_ALT     | H↔D       | 0 / 8       | Alt job status (polling) |
| `a2e0`    | 0xE0A2       | INIT_E0A2          | H↔D       | 0 / 2       | Initialization command |
| `a3e0`    | 0xE0A3       | INIT_E0A3          | H↔D       | 0 / 2       | Initialization command |
| `a4e0`    | 0xE0A4       | INIT_E0A4          | H↔D       | 0 / 2       | Initialization command |
| `a5e0`    | 0xE0A5       | INIT_E0A5          | H↔D       | 16 / 2      | Init with magic `ADEA DBEE` |
| `a6e0`    | 0xE0A6       | UNKNOWN_E0A6       | H↔D       | 2 / 2       | Post-print cleanup? |
| `a7a0`    | 0xA0A7       | UNKNOWN_A0A7       | H↔D       | 0 / 136     | Only in manual-scaling capture |
| `312a`    | —            | IDENT_CAPS         | D→H       | 253         | Printer capabilities data |
| `d000`    | —            | STATUS_BLOCK_D     | D→H       | ~508-3068   | Periodic status (idle/printing) |
| `c000`    | —            | STATUS_BLOCK_C     | D→H       | ~508-3068   | Status during paper jam/errors |
| `8000`    | —            | STATUS_BLOCK_8     | D→H       | ~508-3068   | Status during out-of-paper |
| `6d00`    | —            | UNKNOWN_006D       | D→H       | 28          | Only in manual-scaling capture |
| `0000`    | —            | (continuation)     | D→H       | 11          | Multi-part response continuation |
| `0001`    | —            | (continuation)     | D→H       | 252         | Multi-part response continuation |
| `0002`    | —            | (continuation)     | D→H       | 508         | Multi-part response continuation |
| `0003`    | —            | (continuation)     | D→H       | 508         | Multi-part response continuation |

### Sub-commands inside D0A9 wrapper:

| Wire Code | Name               | Size | Notes |
|-----------|-------------------|------|-------|
| `a0d0`    | SET_PARM_PAGE     | 44   | Page parameters (40 payload bytes) |
| `a4d0`    | SET_PARM_HISCOA   | 12   | HISCOA compression params (8 payload bytes) |
| `a1d0`    | UNKNOWN_D0A1      | 4    | No payload |
| `a2d0`    | UNKNOWN_D0A2      | 4    | No payload |

---

## 3. Standard Print Sequence

Canonical single-page print job (from `alrady_connected_printer_printing_then_idle_for_awhile.pcapng`):

```
Phase 1: IDENTIFICATION
  HOST→DEV  IDENT (a1a1)                    sz=4
  DEV→HOST  IDENT (a1a1)                    sz=56  payload starts: 000b...
  DEV→HOST  312a IDENT_CAPS                 sz=257 payload: f0ff4000040041000100...
  
Phase 2: STATUS CHECK
  HOST→DEV  CHKXSTATUS (a8a0)              sz=4
  DEV→HOST  CHKXSTATUS (a8a0)              sz=56  payload starts: ??88
  DEV→HOST  0000 (continuation)            sz=15  payload: 0000000080000000...
  HOST→DEV  CHKJOBSTAT (a1a0)             sz=4
  DEV→HOST  CHKJOBSTAT (a1a0)             sz=22  payload starts: 0010
  DEV→HOST  d000 STATUS_BLOCK              sz=3072

Phase 3: JOB START
  HOST→DEV  JOB_BEGIN (a0a2)              sz=12  payload: 00 00 1e 00 00 00 00 00
  DEV→HOST  JOB_BEGIN (a0a2)              sz=8   payload: 00 00
  HOST→DEV  JOB_SETUP (a1e1)             sz=var  (hostname, username, docname)
  DEV→HOST  JOB_SETUP (a1e1)             sz=6   payload: 00 00

Phase 4: INITIALIZATION
  HOST→DEV  CHKJOBSTAT_ALT (a0e0)        sz=4
  DEV→HOST  CHKJOBSTAT_ALT (a0e0)        sz=12
  HOST→DEV  GPIO (a2e1)                   sz=16  payload: 000000000000000000000000
  DEV→HOST  GPIO (a2e1)                   sz=6   payload: 0000
  HOST→DEV  INIT_E0A3 (a3e0)             sz=4
  DEV→HOST  INIT_E0A3 (a3e0)             sz=6   payload: 0000
  HOST→DEV  INIT_E0A2 (a2e0)             sz=4
  DEV→HOST  INIT_E0A2 (a2e0)             sz=6   payload: 0000
  HOST→DEV  INIT_E0A4 (a4e0)             sz=4
  DEV→HOST  INIT_E0A4 (a4e0)             sz=6   payload: 0000
  HOST→DEV  INIT_E0A5 (a5e0)             sz=20  payload: eedbeaad000000000000000000000000
  DEV→HOST  INIT_E0A5 (a5e0)             sz=6   payload: 0000

Phase 5: STATUS POLLING (wait for ready)
  [repeat CHKJOBSTAT_ALT + CHKXSTATUS until printer ready]

Phase 6: PAGE DATA
  HOST→DEV  SET_PARMS (a9d0)              sz=68  [D0A0+D0A4+D0A1+D0A2]
  HOST→DEV  PRINT_DATA (a0c0)            sz=var  [HISCOA compressed raster]
  HOST→DEV  PRINT_DATA (a0c0)            sz=var  [continuation if needed]
  HOST→DEV  PRINT_DATA_END (a4c0)        sz=4

Phase 7: FIRE
  [poll status until ready]
  HOST→DEV  FIRE (a7e0)                   sz=6   payload: 01 00  (page 1)
  DEV→HOST  FIRE (a7e0)                   sz=6   payload: 00 00

Phase 8: JOB END
  HOST→DEV  JOB_SETUP (a1e1)             sz=var  (byte 16 changes to 0x06)
  DEV→HOST  JOB_SETUP (a1e1)             sz=6   payload: 00 00
  HOST→DEV  JOB_END (a9e0)               sz=6   payload: 05 00
  DEV→HOST  JOB_END (a9e0)               sz=6   payload: 00 00

Phase 9: POST-JOB POLLING
  [CHKXSTATUS + CHKJOBSTAT + d000 status blocks in loop]
```

### Multi-Page Variant (3 pages)

For each page N (1, 2, 3):
```
  SET_PARMS (a9d0)  — byte[0] increments per page  
  PRINT_DATA (a0c0) × N chunks
  PRINT_DATA_END (a4c0)
  [poll]
  FIRE (a7e0)       — payload = N (01, 02, 03)
```

Then final:
```
  JOB_SETUP (a1e1)  — byte 16 = 0x06 (end marker)
  JOB_END (a9e0)
```

---

## 4. D0A9 SET_PARMS Wrapper Structure

The SET_PARMS command (`a9d0`, wire) wraps exactly 4 sub-commands in every capture:

```
Total payload: 64 bytes

[0] a0d0 SET_PARM_PAGE   size_field=44  payload=40 bytes (page parameters)
[1] a4d0 SET_PARM_HISCOA size_field=12  payload=8 bytes  (compression params)
[2] a1d0 UNKNOWN_D0A1    size_field=4   payload=0 bytes
[3] a2d0 UNKNOWN_D0A2    size_field=4   payload=0 bytes
```

Each sub-command has the same 4-byte header: `[2B wire cmd] [2B size (LE)]`

### HISCOA Parameters (always the same)

```
Raw: 01 04 01 01 00 f9 80 00
```
This is constant across all captures — likely the fixed HISCOA compression configuration.

---

## 5. D0A0 SET_PARM_PAGE Byte Map

The 40-byte payload of SET_PARM_PAGE (`a0d0`):

```
Offset  Size  Field                Values seen
------  ----  -------------------  ----------------------------------------
 0-1    2     Page counter (LE16)  0x0000-0x0006 (increments per page/job)
 2-3    2     Magic                Always 0x312A
 4-5    2     Paper size (LE16)    0x0002=Letter, 0x000C=16K, 0x0013=Manual(?)
 6-7    2     (reserved)           Always 0x0000
 8      1     Toner density        0x00=Lightest, 0x1F=Normal, 0x3F=Darkest
 9      1     (copy of byte 8?)    Usually same as byte 8
10      1     (copy of byte 8?)    Usually same as byte 8
11      1     (copy of byte 8?)    Usually same as byte 8
12      1     Paper type           0x00=Plain, 0x01=Plain_L, 0x05=Envelope
13-18   6     Fixed params         Always: 11 04 00 01 01 02
19      1     Toner save           0x00=OFF, 0x01=ON
20-25   6     Fixed params         Always: 01 00 78 00 60 00
26-27   2     Line size (LE16)     Bytes per raster line (e.g. 592, 608)
28-29   2     Num lines (LE16)     Total raster lines (e.g. 6776, 8162, 8400)
30-31   2     Paper width (LE16)   Pixels (e.g. 4960, 5078, 5100)
32-33   2     Paper height (LE16)  Pixels (e.g. 7014, 8400)
34      1     (reserved)           Always 0x00
35      1     (reserved)           Always 0x00
36      1     Page type extra      0x01 (default), 0x02 (tonerSave/IndexCard), 0x1C (manual)
37-39   3     (reserved)           Always 0x000000
```

### Paper Size Codes

| Code   | Paper Size |
|--------|-----------|
| 0x0002 | Letter (4960×7014 px, line_sz=592) |
| 0x000C | 16K (5100×8400 px, line_sz=592) |
| 0x0013 | Manual/Custom (5078×8400 px, line_sz=608) |

### Paper Type Codes

| Code | Type |
|------|------|
| 0x00 | Plain Paper |
| 0x01 | Plain Paper L |
| 0x05 | Envelope |

### Toner Density Values

| Code | Density |
|------|---------|
| 0x00 | Lightest (all 4 bytes: 00 1f 1f 1f) |
| 0x1F | Normal (all 4 bytes: 1f 1f 1f 1f) |
| 0x3F | Darkest (all 4 bytes: 3f 1f 1f 1f) |

---

## 6. E1A1 JOB_SETUP Structure

JOB_SETUP (`a1e1`) HOST→DEV carries print job metadata with embedded UTF-16LE strings.

### Byte Map (payload after 4-byte command header):

```
Offset  Size  Field                     Notes
------  ----  -----------------------   --------------------------------
 0-3    4     (unknown)                 Always 00 00 00 00
 4      1     Phase flag                0x01=has data (normal), 0x00=cancel, or page count for multi-page
 5-7    3     (padding)                 Always 00 00 00
 8-9    2     Hostname length (LE16)    In bytes (e.g. 20 = 10 UTF-16 chars)
10-11   2     Username length (LE16)    In bytes (e.g. 12 = 6 UTF-16 chars)
12-13   2     Docname length (LE16)     In bytes (e.g. 14 = 7 UTF-16 chars)
14-15   2     (padding)                 Always 00 00
16      1     Job phase (fg)            0x01=start, 0x02=retry after error, 0x04=cancel, 0x06=end
17      1     Source type               0x01=standard print, 0x02=Chrome/app-initiated print
18-19   2     Job ID (LE16)             Assigned by printer in JOB_BEGIN response, reused in JOB_END
20-21   2     X resolution? (LE16)      Always 480 (0x01E0)
22-23   2     Y resolution? (LE16)      Always 420 (0x01A4)
24-25   2     Year (LE16)               e.g. 2025 (0x07E9)
26      1     Month                     1-12
27      1     Day                       1-31
28      1     Hour                      0-23
29      1     Minute                    0-59
30      1     Second                    0-59
31-71   41    Zero padding              All 0x00
72      —     UTF-16LE strings start    Hostname + Username + Docname concatenated
```

### String Decoding

Strings are concatenated at offset 72, using lengths from bytes 8-13:

```
Offset 72 ........................ offset 72+hn_len ................... offset 72+hn_len+un_len ...
[  Hostname (hn_len bytes)  ]  [  Username (un_len bytes)  ]  [  Docname (dn_len bytes)  ]
```

### JOB_SETUP Appears Twice Per Job

1. **First occurrence** (Phase 3): byte 16 = `0x01` (job start)
2. **Second occurrence** (Phase 8): byte 16 = `0x06` (job end)

Both contain identical hostname/username/docname.

---

## 7. Per-Capture Analysis

### 7.1 `alrady_connected_printer_printing_then_idle_for_awhile.pcapng`
- **Scenario**: Normal single-page print, then idle polling
- **JOB_SETUP**: Host=OPREKIN-PC, User=mrhell, Doc=ChatGPT, Time=2025-11-27 21:21:28
- **Page Params**: Letter, toner=Normal(0x1F), type=Plain, save=OFF, 4960×7014px
- **GPIO**: `00 00 00 00 00 00 00 00 00 00 00 00` (all zeros)
- **JOB_BEGIN**: payload `00 00 1e 00 00 00 00 00` (possible job_id=0x001e0000)
- **FIRE**: payload `01 00` (page 1)
- **JOB_END**: payload `05 00`
- **Post-print**: Long CHKXSTATUS+CHKJOBSTAT+d000 polling loop

### 7.2 `alraedy_printeron_then_connectusb.pcapng`
- **No USB bulk transfer data** — only USB enumeration/control transfers

### 7.3 `already_connectedprinter-printing_with_no_printer-then_print_being_paused_then_deleted_response.pcapng`
- **Scenario**: Attempted print when printer disconnected, then paused/deleted
- **JOB_SETUP (×4)**: Host=OPREKIN-PC, User=mrhell, Doc=ChatGPT
  - Fr63: byte16=0x01 (start), Fr159: byte16=0x06 (end)
  - Fr641: byte16=0x02 (retry after error), Fr1661: byte16=0x04 (cancel)
- **Page Params**: Letter, toner=Normal, type=Plain, save=OFF, 4960×7014px
- **Notable**: Multiple JOB_BEGIN/JOB_END cycles, a6e0 command appears
- **GPIO**: `00 00 01 02 01 00 00 00 00 00 01 00` (non-zero — error state)

### 7.4 `change_pagesizeToLegalThenPrintTestPage.pcapng`
- **Scenario**: Changed page size to Legal, printed test page
- **JOB_SETUP**: Host=OPREKIN-PC, User=mrhell, Doc=Test Page, Time=2025-11-27 21:28:44
- **Page Params**: **16K(0x0C)**, toner=Normal(0x1F), type=Plain, save=OFF, **5100×8400px**
- **Note**: Paper code 0x0C corresponds to "16K" in the driver — likely the closest match for Legal in the CAPT driver's paper code table

### 7.5 `increaseTonerDensityThenPrint.pcapng`
- **Scenario**: Increased toner density to max, printed test page
- **JOB_SETUP**: Host=OPREKIN-PC, User=mrhell, Doc=Test Page
- **Page Params**: 16K(0x0C), **toner=0x3F (Darkest)**, type=Plain, save=OFF, 5100×8400px
- **Toner bytes**: `3f 1f 1f 1f` — only byte 8 changes, bytes 9-11 stay 0x1F

### 7.6 `outOfPaper-PressRedButtonAfterFeedingPaper.pcapng`
- **Scenario**: Print attempted with no paper → paper jam state → feed paper → press button → resume
- **JOB_SETUP (×8)**: Host=OPREKIN-PC, User=mrhell, Doc=ChatGPT
  - 4 JOB_BEGIN/JOB_SETUP/JOB_END cycles (2 failed attempts + 2 successful)
- **Page Params**: Letter, toner=Normal, type=Plain, save=OFF, 4960×7014px
- **GPIO (first)**: `00 00 01 02 01 00 00 00 00 00 01 00` (error state GPIO)
- **GPIO (second)**: `00 00 00 00 00 00 00 00 00 00 00 00` (normal after recovery)
- **Error recovery**:
  - First attempt: JOB_SETUP(fg=1, job_id=5) → FIRE → JOB_SETUP(fg=6) → JOB_END(5)
  - Retry: JOB_BEGIN(byte[0]=0x05, prev job_id) → JOB_SETUP(fg=2, job_id=5)
  - Re-init: START_1 → START_2 → START_3 → UPLOAD_2(DEADBEEF)
  - GPIO(no-paper) → RESET(0000) → wait → GPIO(off)
  - Second re-init: START_1 → START_2 → START_3 → UPLOAD_2
  - Resume: SET_PARMS → PRINT_DATA → FIRE → JOB_SETUP(fg=6) → JOB_END(5)
- **a6e0 (RESET)**: Appears during error recovery after GPIO

### 7.7 `print3continuousPages.pcapng`
- **Scenario**: Print 3 consecutive pages in one job
- **JOB_SETUP**: Host=OPREKIN-PC, User=mrhell, Doc=ChatGPT, Time=2025-11-27 23:05:15
- **Page Params (×3)**: Letter, toner=Normal, type=Plain, save=OFF, 4960×7014px
  - SET_PARMS byte[0]: 0x00, 0x01, 0x02 (page counter increments)
- **FIRE (×3)**: payloads `01 00`, `02 00`, `03 00` (page number as LE16)
- **Structure**: SET_PARMS+DATA+FIRE repeated 3 times, then JOB_SETUP(end)+JOB_END

### 7.8 `printNoTonerThenInsertTonerThenPrint.pcapng`
- **Scenario**: Print with no toner → insert toner → print again
- **JOB_SETUP**: Host=OPREKIN-PC, User=mrhell, Doc=ChatGPT
- **Page Params**: Letter, toner=Normal, type=Plain, save=OFF, 4960×7014px
- **Error state**: Long polling loop before successful print at Fr953

### 7.9 `printerpower_on_off.pcapng`
- **No USB bulk transfer data** — power cycle doesn't generate bulk transfers

### 7.10 `replug_usb.pcapng`
- **No USB bulk transfer data** — only USB re-enumeration

### 7.11 `setToPlainPaperLThenOpenStatusWindow.pcapng`
- **Scenario**: Set paper to Plain_L, opened printer status window
- **No SET_PARMS/PRINT_DATA** — just status polling
- **Only commands**: IDENT → CHKXSTATUS → CHKJOBSTAT → loop (monitoring only)

### 7.12 `statuswindowOpenCoverCloseCoverWhichCausesSpooling.pcapng`
- **Scenario**: Opened cover (causes spooling/error), then closed cover
- **JOB_SETUP**: Host=OPREKIN-PC, User=mrhell, Doc=ChatGPT
- **Sequence**: Normal print start → cover open during spooling → long polling → recovery
- **Notable**: 66 `0001` continuation responses during error state

### 7.13 `PageSizeToIndexCard-OutputSizeToA4-...-PageTypeToHeavy-TonerDensityToNormalButUseTonerSave.pcapng`
- **Scenario**: IndexCard→A4, 2 pages/sheet, Heavy paper, Toner Save ON
- **JOB_SETUP**: Host=OPREKIN-PC, User=mrhell, Doc=**Chrome Web Store**
  - byte4=0x00, byte16=0x01, byte17=0x02 (Chrome-initiated print)
- **Page Params (×3 SET_PARMS)**: Letter, toner=Normal, type=**Plain_L(0x01)**, save=**ON**
  - byte[36]=0x02 (instead of normal 0x01)
  - 2 FIRE commands (pages 1, 2)
- **GPIO**: `00 00 01 02 02 00 00 00 00 00 01 00` (non-zero, different pattern)
- **Unknown 8000**: 1 occurrence, payload `b009b30d960000020000 0000`
- **a6e0**: 4 occurrences (2 pairs of HOST→DEV + DEV→HOST)

### 7.14 `PrintUsingChromePrintWindow-PagesCustom(1-16)-PageSizeA4-PagesPerSheetTo16-ScaleFitToPaper-PrinterPaperJamFix.pcapng`
- **Scenario**: Chrome print 16 pages→1 sheet, paper jam, then fix
- **JOB_SETUP**: Host=OPREKIN-PC, User=mrhell, Doc=**Constitution-of-Nepal_2072_Eng_www.moljpa.gov_.npDate-72_11_16.pdf**
  - Time=2025-11-27 23:02:43, byte16=0x01, byte17=0x02
- **Page Params**: Letter, toner=Normal, type=**Plain_L**, save=**ON**, 4960×7014px
- **FIRE**: payload `01 00` (1 page output despite 16 source pages — 16-up layout)
- **c000 status blocks**: 70 occurrences during paper jam + recovery
- **d000 status blocks**: 7 occurrences after jam resolved
- **GPIO (first)**: `00 00 06 00 00 00 00 00 00 00 00 01` (unique pattern)
- **GPIO (second)**: `00 00 00 00 00 00 00 00 00 00 00 00` (after recovery)

### 7.15 `PrinterCancelDocument.pcapng`
- **Scenario**: Cancel a print job in progress
- **Starts with CHKJOBSTAT_ALT** (no IDENT) — printer already in active job
- **JOB_SETUP**: Host=OPREKIN-PC, User=mrhell, Doc=**Chrome Web Store**
  - byte4=0x00 (no data flag), byte16=**0x04** (cancel), byte17=**0x02**
- **Sequence**: Extended CHKJOBSTAT_ALT polling → JOB_SETUP(cancel) → INIT_E0A2 → JOB_END
- **No SET_PARMS, no PRINT_DATA, no FIRE** — clean cancel
- **JOB_END**: payload `02 00`
- **c000 status blocks**: 12 occurrences (sz=512, payload `b009b30d9600fd0200000000`)

### 7.16 `communicationErrorToSolve.pcapng`
- **Scenario**: Repeated communication errors
- **Only IDENT commands** — repeated IDENT→reply loops, never progresses
  - 6 complete IDENT cycles, with `312a` capabilities response each time
  - Eventually establishes connection, enters CHKXSTATUS+CHKJOBSTAT loop
- **CHKXSTATUS response**: `3188` (vs normal `0088`/`0088`) — bit 0x31 set indicates error
- **No print job** — stuck in error polling

### 7.17 `manualPageSize-ManualScalingTo200-OrientationToLandscape-FinishingToCollateOff-TonerDensityToLightest.pcapng`
- **Scenario**: Manual page size, 200% scaling, landscape, lightest toner
- **JOB_SETUP**: Host=OPREKIN-PC, User=mrhell, Doc=**Test Page**, Time=2025-11-27 22:45:38
- **Page Params**: paper=**0x13 (Manual/Custom)**, toner=**0x00 (Lightest)**, type=**Envelope(0x05)**, save=OFF
  - Dimensions: **5078×8400px**, line_size=608 bytes
  - byte[36]=0x1C (unique value)
- **FIRE**: payload `03 00` (page 3? or job-counter related)
- **UNIQUE commands**:
  - `a7a0` HOST→DEV sz=4, DEV→HOST sz=140 (only in this capture, large reply)
  - `6d00` DEV→HOST sz=32 payload starts `4c00` (only in this capture)
- **`0002` continuations**: 71 occurrences (instead of `0001`) — different printer response mode
- **`0003` continuations**: 10 occurrences

### 7.18 `random.pcapng`
- **Scenario**: Miscellaneous/random print capture
- **Contains**: Standard print sequence with IDENT→CHKXSTATUS→JOB_BEGIN→JOB_SETUP→init→SET_PARMS→DATA→FIRE→JOB_END

---

## 8. Page Parameters Comparison

| Capture | Paper | Toner | Type | Save | Width×Height | Line Size | byte[0] | byte[36] |
|---------|-------|-------|------|------|-------------|-----------|---------|----------|
| Default prints (×6) | Letter(0x02) | Normal(0x1F) | Plain(0x00) | OFF | 4960×7014 | 592 | varies | 0x01 |
| Legal (change_pagesize) | 16K(0x0C) | Normal(0x1F) | Plain(0x00) | OFF | 5100×8400 | 592 | 0x00 | 0x01 |
| Toner+ (increaseToner) | 16K(0x0C) | **Dark(0x3F)** | Plain(0x00) | OFF | 5100×8400 | 592 | 0x01 | 0x01 |
| IndexCard/TonerSave | Letter(0x02) | Normal(0x1F) | **Plain_L(0x01)** | **ON** | 4960×7014 | 592 | 0x04 | **0x02** |
| Chrome/PaperJam | Letter(0x02) | Normal(0x1F) | **Plain_L(0x01)** | **ON** | 4960×7014 | 592 | 0x06 | **0x02** |
| Manual/Landscape/Lightest | **Manual(0x13)** | **Light(0x00)** | **Envelope(0x05)** | OFF | **5078×8400** | **608** | 0x02 | **0x1C** |

---

## 9. JOB_SETUP Comparison

| Capture | Hostname | User | Document | Timestamp | byte16 | byte17 | byte18-19 |
|---------|----------|------|----------|-----------|--------|--------|-----------|
| First capture | OPREKIN-PC | mrhell | ChatGPT | 2025-11-27 21:21:28 | 0x01→0x06 | 0x01 | 2 |
| outOfPaper | OPREKIN-PC | mrhell | ChatGPT | 2025-11-27 21:38:31 | 0x01→0x06 | 0x01 | 5 |
| 3pages | OPREKIN-PC | mrhell | ChatGPT | 2025-11-27 23:05:15 | 0x01→0x06 | 0x01 | 2 |
| Legal (change_page) | OPREKIN-PC | mrhell | Test Page | 2025-11-27 21:28:44 | 0x01→0x06 | 0x01 | 3 |
| Toner+ (increase) | OPREKIN-PC | mrhell | Test Page | — | 0x01→0x06 | 0x01 | — |
| Manual/Landscape | OPREKIN-PC | mrhell | Test Page | 2025-11-27 22:45:38 | 0x01→0x06 | 0x01 | 4 |
| IndexCard | OPREKIN-PC | mrhell | Chrome Web Store | 2025-11-27 22:55:58 | 0x01 | **0x02** | 2 |
| ChromePrint | OPREKIN-PC | mrhell | Constitution-of-Nepal_2072_...pdf | 2025-11-27 23:02:43 | 0x01→0x06 | **0x02** | 3 |
| CancelDoc | OPREKIN-PC | mrhell | Chrome Web Store | 2025-11-27 22:55:58 | **0x04** | **0x02** | 2 |

### Key Observations:
- **byte16 (fg)** transitions: `0x01`(start) → `0x06`(end) for normal jobs, `0x02` for retry after error recovery, `0x04` for cancellation. **There is no fg=5** — earlier confusion stemmed from JOB_END payload=5 (which is the job_id, not fg)
- **byte17**: `0x01` for standard prints, `0x02` for Chrome/app-originated prints
- **byte18-19 (job_id)**: Monotonically increasing job counter assigned by the printer. Values 1-8 seen across captures. JOB_END payload always matches this job_id. JOB_BEGIN response returns this value.
- **bytes 20-23**: Always 480×420 — possibly resolution in some unit
- **byte4 (phase_flag)**: Usually 0x01 for has-data, 0x00 for cancel. For multi-page jobs, this is the total page count (e.g., 0x03 for 3-page job)

---

## 10. GPIO (E1A2) Analysis

GPIO command carries 12 bytes of payload:

| Capture Scenario | GPIO Payload (12 bytes) | Notes |
|-----------------|------------------------|-------|
| Normal print (default) | `00 00 00 00 00 00 00 00 00 00 00 00` | All zeros |
| Error recovery (outOfPaper, first) | `00 00 01 02 01 00 00 00 00 00 01 00` | Error state |
| After recovery (outOfPaper, second) | `00 00 00 00 00 00 00 00 00 00 00 00` | Cleared |
| IndexCard/TonerSave | `00 00 01 02 02 00 00 00 00 00 01 00` | Special mode |
| ChromePrint (first, paper jam) | `00 00 06 00 00 00 00 00 00 00 00 01` | Paper jam GPIO |
| ChromePrint (second, recovery) | `00 00 00 00 00 00 00 00 00 00 00 00` | Cleared |

### GPIO Byte Positions:
- **Byte 2**: Error type code (0x01=no-paper/waiting, 0x06=paper jam)
- **Byte 3**: Sub-type (0x02 during no-paper/waiting, 0x00 during jam)
- **Byte 4**: Variant (0x01=no-paper normal, 0x02=IndexCard/special mode, 0x00=jam)
- **Bytes 5-9**: Always 0x00
- **Byte 10**: Set to 0x01 during no-paper errors (not during jam)
- **Byte 11**: Set to 0x01 during paper jam (not during no-paper)

### GPIO Pattern Summary:
| Pattern | Byte[2] | Byte[3] | Byte[4] | Byte[10] | Byte[11] | Meaning |
|---------|---------|---------|---------|----------|----------|----------|
| `000001020100000000000100` | 0x01 | 0x02 | 0x01 | 0x01 | 0x00 | No paper / waiting |
| `000001020200000000000100` | 0x01 | 0x02 | 0x02 | 0x01 | 0x00 | Special mode (IndexCard) |
| `000006000000000000000001` | 0x06 | 0x00 | 0x00 | 0x00 | 0x01 | Paper jam |
| `000001020100000000000101` | 0x01 | 0x02 | 0x01 | 0x01 | 0x01 | Cancel during error |
| `000000000000000000000000` | 0x00 | 0x00 | 0x00 | 0x00 | 0x00 | Normal / LED off |

---

## 11. Status/Response Codes

### CHKXSTATUS Response Analysis

The 52-byte CHKXSTATUS reply starts with a 2-byte status word:

| Status Word | Meaning |
|------------|---------|
| `0088` | Normal/ready |
| `0188` | Post-print (page processing) |
| `0488` | Printing in progress |
| `1088` | Job active, waiting |
| `1188` | Paper error state |
| `1288` | Cancelling |
| `1388` | Post-cancel |
| `168a` | Error + status change |
| `018a` | Recovery in progress |
| `3188` | Communication error |

### d000 / c000 / 8000 Status Blocks

These are periodic status updates from the printer (3072 or 512 bytes):

| Wire Code | When Seen | Payload Start |
|-----------|-----------|---------------|
| `d000` | Normal operation/idle | `f60968109600fd01/0200000000` or `af09b40d9600fd0100000000` |
| `c000` | Paper jam / cancel / error recovery | `f60968109600fd0100000000` or `b009b30d9600fd0200000000` |
| `8000` | Out of paper state | `f60968109600000100000000` |

The first 12 bytes likely encode: page counter, toner status, and error flags.

### 312a Capabilities Response

Identical in every capture:

```
Raw (253 bytes): f0ff 4000 0400 4100 0100 d002 0000 6f08
                 0000 e40d 0000 0000 0000 fa02 0000 f604
                 0000 283c 3232 5802 5802 1503 0200 ...
```

Decoded fields (tentative):
- `f0ff` = marker
- `4000` = 64 (some size?)
- `0400` = 4 (number of something?)
- `4100` = 65 (ASCII 'A'?)
- `d002` = 720 (DPI?)
- `6f08` = 2159 (8.5" × 254?)
- `e40d` = 3556 (14" × 254?)
- `fa02` = 762 (3" × 254?)
- `f604` = 1270 (5" × 254?)

### 0000 Continuation Responses

11-byte responses with embedded status:

```
Byte layout: 00 00 XX XX XX XX XX XX XX XX XX
             ─────  └─────────────────────────── status bytes
```

| Status Bytes | Meaning |
|-------------|---------|
| `000080000000000000` | Normal/idle, no job |
| `000080000000010000` | Job active |
| `000080000000010001` | Job active, paper processing |
| `800080000000010000` | Printing |
| `840080000000010000` | Page being processed |
| `a00080000000010000` | Post-fire processing |
| `a40080000000010000` | Post-job cleanup |
| `040080000000010001` | Error clearing |
| `200000000000000000` | Paper feed error |
| `000080000001010000` | Cancel state |
| `044000000000020001` | Multi-job error state |

---

## 12. Unknown Commands

### Fully Unknown Wire Codes

| Wire | User Notation | Where Seen | Size | Payload | Purpose Guess |
|------|--------------|------------|------|---------|---------------|
| `a6e0` | 0xE0A6 | Most captures (normal + error) | 6→6 | `0000`→`0000` | **RESET** — sent after JOB_SETUP in normal init, and during error recovery before re-init. Now identified as `CAPT_RESET` in driver. |
| `a7a0` | 0xA0A7 | Manual scaling only | 4→140 | (none)→`0001...` | Extended capabilities query? Large 136-byte reply |
| `6d00` | 0x006D | Manual scaling only | — / 32 | DEV→HOST `4c00...` | Extended status? 28-byte payload |
| `8000` | 0x0080 | outOfPaper + IndexCard | 3072/512 | Similar to d000 | Status block during paper errors |
| `c000` | 0x00C0 | outOfPaper, ChromeJam, Cancel | 3072/512 | Similar to d000 | Status block during jam/recovery |

### a5e0 Magic Marker

Always sends `eedbeaad 00000000 00000000 00000000`:
- `eedbeaad` reversed = `0xADEADBEE` — likely a deliberate "DEADBEEF"-like magic constant
- Possibly marks the initialization boundary

---

## 13. Error/Recovery Scenarios

### Out of Paper → Feed → Resume

```
1. Normal job start (IDENT → JOB_BEGIN → JOB_SETUP(fg=1) → RESET → init)
2. CHKJOBSTAT_ALT polling returns 0x1088 (waiting)
3. d000 status blocks have normal payload
4. After paper out detected:
   - 8000 status blocks appear (payload: ...00010000...)
   - 0000 continuation shows error flags
5. Long CHKJOBSTAT_ALT polling (hundreds of frames)
6. JOB_SETUP(fg=6) + JOB_END (end current job)
7. JOB_BEGIN with byte[0]=prev_job_id → JOB_SETUP(fg=2) (retry)
8. Re-initialization: START_1 → START_2 → START_3 → UPLOAD_2(DEADBEEF)
9. GPIO(no-paper pattern: 000001020100000000000100)
10. RESET(0000)
11. Wait for user to feed paper + press button
12. GPIO(off: 000000000000000000000000)
13. Re-initialization again: START_1 → START_2 → START_3 → UPLOAD_2
14. SET_PARMS → PRINT_DATA → FIRE → JOB_SETUP(fg=6) → JOB_END (success)
```

**Driver implementation**: `wait_user()` handles steps 9-13, `job_epilogue()` handles step 6,
`job_prologue()` with `is_retry=true` handles steps 7-8.

### Paper Jam → Fix → Resume (Chrome Print)

```
1. Normal job start through SET_PARMS + PRINT_DATA + FIRE
2. CHKXSTATUS returns varying status (0x0488, 0x0489...)
3. c000 status blocks replace d000 (hundreds of occurrences)
4. Status flags: PAPERJAM (s2 bit14) + JAMERR (s4 bit7) set
5. GPIO(jam pattern: 000006000000000000000001)
6. RESET(0000)
7. Wait for jam cleared → COVEROPEN (s2 bit12) transitional → all clear
8. GPIO(off: 000000000000000000000000)
9. Re-init: START_1 → START_2 → START_3 → UPLOAD_2(DEADBEEF)
10. JOB_SETUP(fg=6) → JOB_END
```

**Driver implementation**: `page_epilogue()` detects PAPERJAM/JAMERR → returns false →
`wait_user()` sends jam GPIO + RESET + waits + GPIO off + re-init.

### Cancel Document

```
1. Already in active CHKJOBSTAT_ALT polling (ongoing job)
2. Host sends JOB_SETUP with byte16=0x04 (cancel flag), byte4=0x00 (no data)
3. Host sends START_2 (INIT_E0A2)
4. Host sends JOB_END with payload = job_id
5. Post-cancel: CHKXSTATUS shows 0x1388, c000 status blocks
```

**Driver implementation**: `cancel_job()` sends JOB_SETUP(fg=4) → START_2 → JOB_END(job_id).
Triggered by SIGTERM/SIGINT signal handler.

### Communication Error

```
1. Repeated IDENT commands (6+ cycles)
2. Each cycle: HOST IDENT → DEV IDENT + 312a caps → HOST IDENT again
3. Eventually establishes connection
4. CHKXSTATUS returns 0x3188 (bit pattern indicates comm error)
5. Enters CHKXSTATUS + CHKJOBSTAT polling loop
6. No print job initiated
```

**Driver implementation**: Not implemented. Low priority — rare scenario.

---

## Appendix: Raw Hex Payloads

### 312a Capabilities (identical in all captures)

```
f0ff4000040041000100d00200006f080000e40d000000000000fa020000
f6040000283c32325802580215030200
```

### SET_PARM_PAGE Examples

**Default Letter:**
```
0100 312a 0200 0000 1f1f1f1f 00 110400010102 00 01007800 6000 5002781a 6013661b 000001000000
```

**Legal (16K):**
```
0000 312a 0c00 0000 1f1f1f1f 00 110400010102 00 01007800 6000 6002e21f d613d020 000001000000
```

**Darkest toner:**
```
0100 312a 0c00 0000 3f1f1f1f 00 110400010102 00 01007800 6000 6002e21f d613d020 000001000000
```

**Plain_L + Toner Save:**
```
0400 312a 0200 0000 1f1f1f1f 01 110400010102 01 01007800 6000 5002781a 6013661b 000002000000
```

**Manual/Landscape/Lightest:**
```
0200 312a 1300 0000 001f1f1f 05 110400010102 00 01007800 6000 6002e21f d613d020 00001c000000
```

### JOB_SETUP Examples

**Normal (ChatGPT, 118 bytes):**
```
00000000 01000000 1400 0c00 0e00 0000 01 01 0200 e001 a401 e907 0b 1b 15 15 1c
[41 zero bytes]
4f005000520045004b0049004e002d00500043  (OPREKIN-PC)
006d007200680065006c006c                (mrhell)
00430068006100740047005000540              (ChatGPT)
```

**Cancel (Chrome Web Store, 136 bytes):**
```
00000000 00000000 1400 0c00 2000 0000 04 02 0200 e001 a401 e907 0b 1b 16 37 3a
[41 zero bytes]
4f005000520045004b0049004e002d00500043  (OPREKIN-PC)
006d007200680065006c006c                (mrhell)
004300680072006f006d006500200057006500  (Chrome Web Store)
62002000530074006f0072006500
```

### INIT_E0A5 Magic

```
eedbeaad 00000000 00000000 00000000
```

---

*Analysis generated from 18 USB pcapng captures using tshark v4.6.3 and custom Python CAPT parser.*
*All captures from host OPREKIN-PC, user mrhell, dated 2025-11-27.*
*Updated 2026-02-13 with implementation verification and corrected findings.*

---

## 14. JOB_BEGIN Retry Format

The JOB_BEGIN command (`a0a2`) payload differs between new jobs and retry-after-error:

```
New job:   00 00 1E 00 00 00 00 00   (byte[0] = 0x00)
Retry:     05 00 1E 00 00 00 00 00   (byte[0] = previous job_id)
```

### Observed JOB_BEGIN Payloads

| Capture | Payload | Context |
|---------|---------|---------|
| All normal prints | `00 00 1E 00 00 00 00 00` | New job |
| outOfPaper (2nd) | `05 00 1E 00 00 00 00 00` | Retry, prev job_id=5 |
| no_printer (2nd) | `01 00 1E 00 00 00 00 00` | Retry, prev job_id=1 |

### JOB_BEGIN Response

The printer responds with 4 bytes. The response contains the assigned job_id at bytes[2-3]:
```
Response: 00 00 XX XX   (XX XX = job_id LE16)
```
Our driver reads this via `job = WORD(buf[2], buf[3])`.

### JOB_END Payload = Job ID

The JOB_END payload always matches the JOB_SETUP byte[18-19] job_id:

| Capture | job_id | JOB_END payload |
|---------|--------|-----------------|
| First capture | 2 | `02 00` |
| outOfPaper | 5 | `05 00` |
| 3 pages | 7 | `07 00` |
| no toner | 8 | `08 00` |
| cancel | 2 | `02 00` |

**Note**: There is no fg=5. The value "5" in earlier analysis was the JOB_END payload (= job_id), not a JOB_SETUP fg value.

---

## 15. Implementation Status

Cross-reference of protocol features vs driver implementation in `src/prn_lbp2900.c`.

### ✅ Fully Implemented

| Feature | Files | Notes |
|---------|-------|-------|
| Wire format (LE command framing) | `capt-command.c` | 4-byte header + payload |
| Full command enum | `capt-command.h` | All observed commands including CAPT_RESET |
| JOB_SETUP with UTF-16LE strings | `prn_lbp2900.c` | Hostname, username, docname from CUPS args |
| JOB_SETUP fg values (1,2,4,6) | `prn_lbp2900.c` | fg=1 start, fg=2 retry, fg=4 cancel, fg=6 end |
| SET_PARM_PAGE (40 bytes) | `prn_lbp2900.c` | Paper code, density, type, toner save, dimensions |
| Paper size codes | `prn_lbp2900.c` | A4, Letter, Legal, A5, B5, Executive, envelopes, Index |
| Toner density (0x00-0x3F) | `prn_lbp2900.c` | 5 levels mapped to capture values |
| Toner save mode | `prn_lbp2900.c` | byte[19]=0x01, byte[36]=0x02 |
| Paper type codes | `rastertocapt.c` | Plain, PlainL, Heavy, HeavyH, OHP, Envelope |
| Multi-page printing | `prn_lbp2900.c` | Page counter in SET_PARMS, FIRE per page |
| GPIO LED: no-paper blink | `prn_lbp2900.c` | `blinkonbuf` = `000001020100000000000100` |
| GPIO LED: paper jam | `prn_lbp2900.c` | `jambuf` = `000006000000000000000001` |
| GPIO LED: off | `prn_lbp2900.c` | `blinkoffbuf` = all zeros |
| Error detection: PAPERJAM | `capt-status.h` | s2 bit 14 (0x4000) |
| Error detection: COVEROPEN | `capt-status.h` | s2 bit 12 (0x1000) |
| Error detection: JAMERR | `capt-status.h` | s4 bit 7 (0x0080) |
| Error recovery wait loop | `prn_lbp2900.c` | Waits for all error flags to clear |
| CAPT_RESET during recovery | `prn_lbp2900.c` | Sent in wait_user and job_prologue |
| Re-init after recovery | `prn_lbp2900.c` | START_1→START_2→START_3→UPLOAD_2 in wait_user |
| Cancel job (fg=4) | `prn_lbp2900.c` | JOB_SETUP(fg=4) → START_2 → JOB_END |
| Job retry with fg=2 | `prn_lbp2900.c` | is_retry flag, JOB_BEGIN carries prev job_id |
| JOB_BEGIN retry format | `prn_lbp2900.c` | byte[0] = previous job_id for retry |
| INIT_E0A5 DEADBEEF magic | `prn_lbp2900.c` | `magicbuf_2` = `eedbeaad...` |
| HISCOA compression params | `hiscoa-common.c` | Fixed `01 04 01 01 00 f9 80 00` |
| Signal-based cancel (SIGTERM) | `rastertocapt.c` | Graceful CUPS cancel handling |

### ⚠️ Partial / Approximated

| Feature | Status | Notes |
|---------|--------|-------|
| phase_flag (byte[4]) | Simplified | Code uses 0/1 (has_data), captures show page count for multi-page. Non-critical — printer accepts both. |
| byte17 (source type) | Hardcoded 0x01 | Chrome prints use 0x02. No functional difference observed. |
| Page counter in SET_PARMS byte[0] | Uses ipage | Captures show 0-based; code uses `ipage-1`. Matches. |
| GPIO IndexCard variant | Not needed | `000001020200000000000100` (byte[4]=2) only seen in special mode. Standard blink works. |

### ❌ Not Implemented (Low Priority)

| Feature | Reason |
|---------|--------|
| 0xA0A7 extended capabilities query | Only seen in manual-scaling capture. Unknown purpose. |
| 0x006D extended status response | Only seen in manual-scaling capture. Unknown purpose. |
| Cancel GPIO pattern (byte[10]+byte[11] both set) | Only seen during cancel-while-in-error. Standard cancel via fg=4 works. |
| d000/c000/8000 status block parsing | Large status blocks (512-3072 bytes) with error/printing info. Current polling-based approach works. |
| Communication error (0x3188) handling | Would need IDENT retry loop. Rare scenario. |

### Status Register Map (Confirmed from captures)

```
status[0] (s0):  [15]=READY1 [12]=READY2 [9]=JOBSTAT_CHNG [8]=XSTATUS_CHNG
                 [7]=BUSY [5]=UNINIT1 [4]=UNINIT2 [2]=BUFFERFULL
                 [1]=NOPAPER1 [0]=PROCESSING

status[1] (s1):  [14]=NOPAPER2 [7]=PROCESSING1 [5]=BUTTON [2]=PRINTING
                 [0]=POWERUP

status[2] (s2):  [14]=PAPERJAM [12]=COVEROPEN [8]=BUTTON1 [7]=nERROR
                 Jam recovery: 0x4100 → 0x1000 → 0x0000

status[3] (s3):  [12]=POWERUP1

status[4] (s4):  [7]=JAMERR
                 During jam: togles with PAPERJAM, both set = active jam

status[5] (s5):  (no known flags)

status[6] (s6):  (no known flags)
```
