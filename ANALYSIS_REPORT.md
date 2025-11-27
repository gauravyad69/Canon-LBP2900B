# Canon LBP2900B Protocol Analysis Report

**Date:** November 27, 2025  
**Based on:** USB captures from Windows Canon CAPT driver  
**Analyzed captures:** 14 pcapng files covering various scenarios

---

## Executive Summary

Analysis of USB traffic between the official Windows Canon driver and the LBP2900B printer reveals several protocol features that are missing or incomplete in the current Linux driver implementation.

---

## 1. Command Protocol Overview

### 1.1 Currently Implemented Commands

| Command | Hex Code | Status | Description |
|---------|----------|--------|-------------|
| CAPT_IDENT | 0xA1A1 | ✅ Working | Get printer identification |
| CAPT_CHKXSTATUS | 0xA0A8 | ✅ Working | Extended status polling |
| CAPT_CHKJOBSTAT | 0xA0A1 | ✅ Working | Job status check |
| CAPT_JOB_BEGIN | 0xA2A0 | ✅ Working | Start print job |
| CAPT_JOB_END | 0xE0A9 | ✅ Working | End print job |
| CAPT_JOB_SETUP | 0xE1A1 | ⚠️ Partial | Job metadata (empty strings) |
| CAPT_SET_PARMS | 0xD0A9 | ✅ Working | Multi-command wrapper |
| CAPT_SET_PARM_PAGE | 0xD0A0 | ⚠️ Partial | Page parameters (hardcoded values) |
| CAPT_SET_PARM_HISCOA | 0xD0A4 | ✅ Working | Hi-SCoA compression params |
| CAPT_PRINT_DATA | 0xC0A0 | ✅ Working | Compressed page data |
| CAPT_PRINT_DATA_END | 0xC0A4 | ✅ Working | End of page data |
| CAPT_FIRE | 0xE0A7 | ✅ Working | Trigger page output |
| CAPT_GPIO | 0xE1A2 | ✅ Working | LED control |

### 1.2 Commands Found in Captures (Not in Driver)

| Command | Hex Code | Context | Notes |
|---------|----------|---------|-------|
| Unknown | 0xA0A2 | Paper out recovery | 12-byte payload, purpose unknown |

---

## 2. Page Parameters Analysis (0xD0A0)

### 2.1 Byte-by-Byte Comparison

Captured from Windows driver for different scenarios:

```
Offset  Field               A4 Normal   A4 High Density   Legal
------  ------------------  ----------  ----------------  ----------
0-3     Command header      a0d02c00    a0d02c00          a0d02c00
4-5     Paper size code     0100        0600              0600
6-7     Unknown             312a        312a              312a
8-9     Paper dim related   0200        0c00              0c00
10-11   Padding             0000        0000              0000
12-15   Margins             1f1f1f1f    3f1f1f1f          1f1f1f1f
                            ^^normal    ^^HIGH DENSITY
16      Paper type A        00          00                00
17-18   Adapt mode          1104        1104              1104
19      Toner saving        00          00                00
20-21   Unknown             0101        0101              0101
22-23   Unknown             0200        0200              0200
24-25   Unknown             0100        0100              0100
26-27   Margin H            7800        7800              7800
28-29   Margin W            6000        6000              6000
30-31   Line size (bytes)   5002        6002              6002
                            (592)       (608)             (608)
32-33   Num lines           781a        e21f              e21f
                            (6776)      (8162)            (8162)
34-35   Paper width (px)    6013        ec13              ec13
                            (4960)      (5100)            (5100)
36-37   Paper height (px)   661b        d020              d020
                            (7014)      (8400)            (8400)
38-43   Tail                000001...   000001...         000001...
```

### 2.2 Key Findings

#### Toner Density Control
- **Location:** Byte 12 (first margin byte)
- **Values:**
  - `0x1F` = Normal density
  - `0x3F` = High density (increased by 0x20)
- **Current driver:** Hardcoded to `0x1F`

#### Toner Saving Mode
- **Location:** Byte 19
- **Values:**
  - `0x00` = Normal mode
  - `0x01` = Toner saving mode
- **Current driver:** Hardcoded to `0x00`

#### Paper Size Codes
- **Location:** Bytes 4-5
- **Known values:**
  - `0x0001` = A4
  - `0x0006` = Legal
  - `0x0002` = Letter (from SPECS)
- **Current driver:** Hardcoded to `0x02`

---

## 3. Job Metadata (0xE1A1)

### 3.1 Windows Driver Sends

```
Offset  Content
------  -------
0-7     Header (00 00 00 00 01 00 00 00)
8-9     Hostname length (14 00 = 20 bytes = 10 UTF-16 chars)
10-11   Username length (0c 00 = 12 bytes = 6 UTF-16 chars)
12-13   Document length (0e 00 = 14 bytes = 7 UTF-16 chars)
14-19   Flags and job info
20-31   Timestamp and padding
32-71   Reserved (zeros)
72+     UTF-16LE strings: hostname, username, document name
```

Example decoded:
- Hostname: `OPREKIN-PC`
- Username: `mrhell`
- Document: `ChatGPT`

### 3.2 Linux Driver Sends

```c
uint8_t ml = 0x00; /* host name length */
uint8_t ul = 0x00; /* user name length */
uint8_t nl = 0x00; /* document name length */
```

All strings are empty - printer status window shows no job info.

---

## 4. Implementation Plan

### Phase 1: Toner Density & Saving (High Priority)
- [ ] Add PPD options for toner density (Normal/High)
- [ ] Add PPD option for toner saving mode
- [ ] Parse CUPS options in driver
- [ ] Modify `pageparms[]` array based on options

### Phase 2: Paper Size Support (Medium Priority)
- [ ] Map more paper sizes to Canon codes
- [ ] Update `page_set_dims()` for additional sizes
- [ ] Test with Legal, Letter, Executive sizes

### Phase 3: Job Metadata (Low Priority)
- [ ] Extract hostname from system
- [ ] Extract username from CUPS job info
- [ ] Extract document name from CUPS job info
- [ ] Encode strings as UTF-16LE
- [ ] Update `send_job_start()` function

---

## 5. Files to Modify

| File | Changes |
|------|---------|
| `Canon-LBP-2900.ppd` | Add TonerDensity, TonerSave options |
| `src/prn_lbp2900.c` | Parse options, modify `pageparms[]` |
| `src/rastertocapt.c` | Pass CUPS options to printer ops |
| `src/printer.h` | Add fields for new options |

---

## 6. Testing Checklist

- [ ] Print test page with normal density
- [ ] Print test page with high density
- [ ] Print test page with toner saving
- [ ] Print on Legal paper
- [ ] Print on Letter paper
- [ ] Verify job name shows in Windows status tool (if available)

---

## Appendix: Raw Capture Data

### A4 Normal Print (D0A9 multi-command)
```
a9d04400a0d02c000100312a020000001f1f1f1f00110400010102000100780060
005002781a6013661b000001000000a4d00c000104010100f98000a1d00400a2d00400
```

### Legal Print (D0A9 multi-command)
```
a9d04400a0d02c000600312a0c0000001f1f1f1f00110400010102000100780060
006002e21fec13d020000001000000a4d00c000104010100f98000a1d00400a2d00400
```

### High Toner Density (D0A9 multi-command)
```
a9d04400a0d02c000600312a0c0000003f1f1f1f00110400010102000100780060
006002e21fec13d020000001000000a4d00c000104010100f98000a1d00400a2d00400
```
