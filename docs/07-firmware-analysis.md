# Firmware Analysis Guide

## Overview

This guide covers reverse engineering the stock Aqara ESP32 firmware using
Ghidra with the MCP plugin for Claude-assisted analysis.

## Prerequisites

### Hardware
- Aqara FP2 with UART wires attached (TP8, TP9, TP28)
- USB-UART adapter (3.3V logic level)

### Software
- **Ghidra 12.0.3** — https://ghidra-sre.org (native Xtensa support)
- **Java 21 LTS** (OpenJDK)
- **ghidra-esp32-flash-loader** (dynacylabs) — **required** for proper import
- **ghidra-mcp** (bethington) — MCP server for Claude-assisted analysis
- **esptool** — `pip install esptool`
- **Xvfb + XFCE** (for headless servers) — Ghidra needs a display

## Step 1: Dump the Firmware

**Important**: Do this BEFORE flashing ESPHome. The stock firmware contains the
light sensor driver, radar OTA code, and all protocol handlers.

```bash
# Hold TP28 (GPIO0) LOW during power-on to enter download mode
esptool.py --baud 230400 --port /dev/ttyUSB0 read_flash 0x0 0x1000000 fp2_stock.bin

# Label with unit's HomeKit digits — flash contains unit-specific calibration
```

## Step 2: Load in Ghidra

### Install the ESP32 Flash Loader (Critical)

**Do not use the raw binary loader** — it does not create cross-references and
makes analysis nearly impossible. The flash loader correctly maps segments,
imports SVD peripherals, and resolves ROM symbols.

```bash
git clone https://github.com/dynacylabs/ghidra-esp32-flash-loader.git
cd ghidra-esp32-flash-loader
git checkout v12.0
GHIDRA_INSTALL_DIR=/path/to/ghidra gradle buildExtension
# Install: File → Install Extensions → select dist/*.zip → restart Ghidra
```

### Import the Firmware

1. `File → Import File` → select the **full flash dump** (not an extracted partition)
2. The flash loader auto-detects the ESP32 format and parses the partition table
3. Language: **Xtensa:LE:32:default**
4. Let auto-analysis run (~60 seconds, produces ~9,200 functions)

### Verify Proper Import

After import, you should see proper segments:
- `app_DROM0_3f400020` — flash-mapped read-only data (strings live here)
- `app_IRAM0_40080000` — fast IRAM code
- `app_IRAM0_400d0020` — flash-mapped code (main application)
- `.text` — ROM code
- Various `.bss_*` segments for BSS data

If you only see a single `ram:` segment, the flash loader didn't work.

## Step 3: Set Up Ghidra MCP

### Install bethington/ghidra-mcp

```bash
git clone https://github.com/bethington/ghidra-mcp.git
cd ghidra-mcp
./ghidra-mcp-setup.sh --deploy --ghidra-path /path/to/ghidra
pip install -r requirements.txt
```

### Enable and Start

1. In Ghidra: `File → Configure → Configure All Plugins → GhidraMCP` (check it)
2. `Tools → GhidraMCP → Start MCP Server`
3. The server binds to a Unix domain socket at
   `/run/user/1000/ghidra-mcp/ghidra-<pid>.sock`

### Configure Claude Code

```bash
claude mcp add ghidra-mcp /path/to/ghidra-mcp/.venv/bin/python /path/to/ghidra-mcp/bridge_mcp_ghidra.py
```

The bridge auto-discovers UDS sockets. All 193 tools become available.

### Headless Server Setup

For servers without a display:

```bash
# Install Xvfb and a desktop
sudo pacman -S xorg-server-xvfb xfce4 x11vnc

# Start virtual display + desktop + VNC
Xvfb :1 -screen 0 1920x1080x24 -nolisten tcp &
DISPLAY=:1 startxfce4 &
x11vnc -display :1 -forever -nopw -listen 0.0.0.0 &

# Launch Ghidra
DISPLAY=:1 /path/to/ghidraRun &
```

Connect via VNC to configure the plugin, then Claude Code connects via MCP.

## Step 4: Analysis Targets

### Completed: Light Sensor Driver

**Status: SOLVED** — TI OPT3001 at I2C address 0x44. Driver implemented.

Key findings from RE:
- Source: `apps/user/hal/acceleration_ambinent_light.c`
- `FUN_400e8d24` — OPT3001 init: writes config to register 1
- `FUN_400e8d5c` — da218B init: `0x0E` to reg `0x11`, `0x40` to reg `0x0F`
- `FUN_400e8f8c` — Calibration init: reads NVS coefficients (lux_low_k/b, etc.)
- `FUN_400e8d84` — Lux getter: reads structure offset +8
- Calibration: linear k/b coefficients per range, stored in NVS
- **OPT3001 config value**: `0xC610` (single-shot mode, 800ms, auto-range).
  Our ESPHome driver uses `0xCE10` (continuous mode). Aqara's single-shot
  approach saves power — sensor only converts when polled.

### Completed: Handler Function Name Table

**Status: SOLVED** — complete `radar_*` / `cloud_*` handler table extracted.

Extracted from DROM `3f409d00 - 3f40a6c0`. Maps every SubID to its local
handler (`radar_*`) and cloud relay handler (`cloud_*`). See
[02-uart-protocol.md](02-uart-protocol.md) for the full table.

Key discoveries:
- `radar_zone_people_number` — SubID **0x0175**, native per-zone counting (implemented)
- Cloud-only attributes found: bed height, overhead height, fall delay,
  blind zone, disturbance suppression
- OpCode dispatch table at `3f40a6cc` with 5 handler function pointers

### Completed: OpCode Dispatch Table

**Status: SOLVED** — all 5 opcode handlers identified.

Found at DROM `3f40a6cc`:
| OpCode | Handler Address |
|--------|----------------|
| 1 (RESPONSE) | `0x400DE904` |
| 2 (WRITE) | `0x400DE8F0` |
| 3 (ACK) | `0x400E1390` |
| 4 (READ) | `0x400DE8DC` |
| 5 (REPORT) | `0x400DE8C8` |

Note: Ghidra's auto-analysis did not create functions at these addresses.
Manual function creation in the GUI is needed before decompilation.

### Completed: Radar Firmware Version Table

Compatibility table at DROM `3f40a6f4`: versions `3.1.85` through `3.23.85+`.
The `.85` suffix is shared between ESP32 app (4.x.85) and radar (3.x.85)
firmware, likely a product variant identifier.

### Completed: Radar OTA (XMODEM-1K)

**Status: FULLY REVERSE ENGINEERED, implementation pending**

Complete OTA sequence decompiled from stock firmware:

**Phase 1 — Trigger bootloader:**
Send `WRITE SubID=0x0127 DataType=0x04(BOOL) Value=0x01` via standard
Aqara UART protocol at 890000 baud.

**Phase 2 — XMODEM-1K handshake:**
Radar enters bootloader and sends `'C'` (0x43) requesting CRC mode.
Wait up to 20 seconds for the handshake character.

**Phase 3 — Transfer loop:**
Send 1029-byte packets: `[STX(0x02)][BlkNum][~BlkNum][1024 data][CRC16-hi][CRC16-lo]`
- Block numbers start at 1, wrap at 256
- CRC: CRC-16/XMODEM (poly 0x1021, init 0x0000) — NOT CRC-16/MODBUS
- On ACK (0x06): next block. On timeout (3s): retry (max 5). On CAN (0x18): abort if >10

**Phase 4 — End transfer:**
Send EOT (0x04), wait for ACK. Retry up to 5 times on timeout.

**Key parameters:**

| Parameter | Value |
|-----------|-------|
| Block size | 1024 bytes (XMODEM-1K) |
| Header byte | STX (0x02) |
| CRC polynomial | 0x1021 (CRC-CCITT) |
| CRC init | 0x0000 |
| Start timeout | 20 seconds |
| Transfer timeout | 3 seconds per block |
| Max retries/block | 5 |
| Max CAN before abort | 11 |
| Packet buffer | 1029 bytes (0x405) |

**Firmware source partition:**
- Label: `mcu_ota`, type: DATA, sub_type: 0xFE
- Size: 4MB at flash offset 0x433000
- Access: `esp_partition_find_first(1, 0xFE, "mcu_ota")`

**Function addresses:**

| Function | Address | Purpose |
|----------|---------|---------|
| `radar_ota_start` | 0x400e6f60 | Init OTA, open partition, send 0x0127 |
| `ota_set_flag_send` | 0x400e6e8c | Sends WRITE 0x0127 BOOL=true |
| `xmodem_new` | 0x400e7440 | Allocate XMODEM context (28 bytes) |
| `xmodem_recv` | 0x400e7218 | 3-state XMODEM receive machine |
| `xmodem_build_packet` | 0x400e702c | Build 1029-byte XMODEM-1K packet |
| `xmodem_send_eot` | 0x400e7084 | Send EOT with retry |
| `xmodem_crc16` | 0x400e6fe4 | CRC-16/CCITT calculation |
| `xmodem_timer` | 0x400e7348 | Timeout handler |
| `radar_ota_result` | 0x400e6db8 | Completion handler |

**Source files** (from embedded strings):
- `apps/user/ota/radar_ota.c`
- `apps/user/ota/xmodem.c`
- `apps/user/hal/radar.c`

### Completed: SubID 0x0203 Zone Configuration Sync

**Status: SOLVED, not required for implementation**

Reverse engineered the full call chain for SubID 0x0203:

```
radar_sw_version()         @ 0x400e4f28  (heartbeat handler)
  └─ heartbeat_config_sync()   @ 0x400decd4  (WRITE 0x0203 UINT8)
       └─ FUN_400e7e20()       @ 0x400e7e20  (frame builder)
```

Key findings:
- **Write-only** — no handler in the 139-entry SubID registration table
- Sent on every heartbeat after zone reconfiguration (flag at `Ram400d1480`)
- The zone reconfig trigger (`FUN_400e5ebc`) increments an NVS counter,
  resets all detection states, and sets the sync flag
- Value comes from state struct offset 599 (0x257) — likely zone config
  version counter
- **Not needed** for static zones (our zones are YAML-defined at compile time)
- Full documentation in [02-uart-protocol.md](02-uart-protocol.md)

### Completed: Three Radar Firmware Images Identified

**Status: VALIDATED** — three MSTR firmware images in `mcu_ota` partition,
all CRC32-verified, structurally validated via Ghidra.

| Image | Offset | Valid Size | CRC32 | Content |
|-------|--------|-----------|-------|---------|
| FW1 MSS | 0x000000 | 65KB | 0x5F97B23D ✓ | SBL boot loader (has `SBL_WORK_MODE_OFFSET`) |
| FW1 DSS | 0x012000 | 683KB | 0xD8B3A3AA ✓ | Zone detection, people counting |
| FW2 MSS | 0x0C0000 | 65KB | 0x8EDF2D7A ✓ | SBL boot loader (no work mode offset) |
| FW2 DSS | 0x0D2000 | 576KB | 0xD83C969D ✓ | Fall detection with DSP scoring |
| FW3 | 0x1A0000 | 678KB | 0xA579DCB8 ✓ | Vital signs (MSS + DSS + BSS; SBL on radar boot ROM) |

**Naming correction:** `fp2_radar_mss.bin` in `/ghidra-binaries/` is actually FW1's
DSS content (offset 0x0120B0 in mcu_ota), not the MSS boot loader. All Ghidra
analysis was on the correct binary. `fp2_radar_dsp.bin` is FW2's DSS content.

**Shared runtime:** All three DSS images contain an identical TI-RTOS segment
(247,416 bytes, same SHA256) — built from the same TI SDK.

**OTA requirements:** Must use raw MSTR images from mcu_ota (NOT extracted .bin
files). CRC32 trailer (4 bytes) must be included. FW3 has no SBL — requires
compatible boot loader already on radar QSPI flash.

### SBL OTA Safety Assessment

**Status: VALIDATED** — SBL decompiled in Ghidra (`fp2_sbl.bin`, ARM:LE:32:v7).

### SBL Boot Logic (Ghidra-decompiled: FUN_000007d8)

**Boot parameter table** (16 bytes at QSPI + 0x030000):

| Byte | Field | Description |
|------|-------|-------------|
| 0 | Magic | 0xAA (valid config marker) |
| 2 | `SBL_WORK_MODE_OFFSET` | Work mode: 3=zone, 8=fall, 9=sleep |
| 4 | `SBL_SLEEP_ENABLE_OFFSET` | Sleep enable flag (0 or 1). **Dead code in practice** — FW3 never writes config+0xb6c to a non-zero value, so this stays 0 permanently. FW3 activation routes exclusively through byte[2]=9. |
| 5 | `SBL_OTA_VERIFY_OFFSET` | OTA pending flag: 1=new firmware waiting |
| 15 | End marker | 0x55 |

**Firmware selection logic** (decompiled from FUN_000007d8 in `fp2_sbl.bin`):

```
1. Read boot params from QSPI + 0x030000
2. If OTA pending (byte[5] == 1):
     Verify OTA image at QSPI + 0x510000 (FUN_0000a6b0)
     If verify fails → load BACKUP from QSPI + 0x040000
     If verify passes → fall through to normal selection
3. Normal selection (FUN_0000a038 reads byte[4]=sleep_enable, FUN_0000a0bc reads byte[2]=work_mode):
     If sleep_enable == 1 OR work_mode == 9:
       → Load from QSPI + 0x460000  (FW3 vital signs)
       → Backup at QSPI + 0x040000
     Elif work_mode == 8:
       → Load from QSPI + 0x392000  (FW2 fall detection)
       → Backup at QSPI + 0x100000
     Else (default):
       → Load from QSPI + 0x2D2000  (FW1 zone detection)
       → Backup at QSPI + 0x040000
4. If load fails → fall back to backup address
```

**Only `work_mode == 9` triggers FW3 in practice.** The `sleep_enable == 1`
branch exists in the SBL but is effectively dead code on this device: scanning
the FW3 MSS binary for stores to `config+0xb6c` (the source of SBL byte[4])
finds only cold-init zeroing and WORK_MODE-handler clearing — no writer ever
sets it to a non-zero value. The stock Aqara app appears to write
`SLEEP_REPORT_ENABLE` (SubID 0x0156) with value 9 for cloud-symmetry, but in
FW3 the dispatcher routes that WRITE to a logger-only handler (FUN_0001fbf8),
so it never reaches any config field.

### Radar QSPI Flash Layout (Ghidra-confirmed)

| QSPI Address | Content | Source |
|---|---|---|
| 0x000000 | SBL boot loader | MSTR type 1 at mcu_ota:0x000000 |
| 0x030000 | Boot parameter table (16 bytes) | FUN_00009fb4, FUN_0000a038, FUN_0000a0bc |
| 0x040000 | Backup factory default image | FUN_000007d8 fallback path |
| 0x100000 | Backup for fall detection mode | FUN_000007d8 mode 8 fallback |
| 0x2D2000 | FW1 Zone Detection application | DAT_00000cc8 = 0x002D2000 |
| 0x392000 | FW2 Fall Detection application | DAT_00000ccc = 0x00392000 |
| 0x460000 | FW3 Sleep/Vital Signs application | Hardcoded in FUN_000007d8 |
| 0x510000 | OTA staging / verify area | FUN_0000a6b0 verify target |

**Critical: QSPI layout differs from ESP32's mcu_ota layout.** The ESP32 stores
firmware contiguously (FW1:0x000000, FW2:0x0C0000, FW3:0x1A0000) but the radar's
QSPI uses completely different addresses. The ESP32 must reformat during OTA.

**Our 2.4MB radar flash backup is INCOMPLETE.** QSPI has data up to 0x510000+
(>5MB). Only 0x000000-0x250000 was captured.

### OTA Safety (Ghidra-confirmed)

**Backup is at SEPARATE addresses from application areas:**
- Zone/sleep backup at 0x040000 — separate from apps at 0x2D2000/0x460000 ✓
- Fall detection backup at 0x100000 — separate from app at 0x392000 ✓
- OTA staging at 0x510000 — separate from everything ✓
- SBL at 0x000000 — not in any application area ✓

**OTA writes to staging area (0x510000), not application partition.**
After XMODEM transfer, SBL verifies (FUN_0000a6b0 with CRC + auth check).
If verify fails → loads backup. Application area is NOT modified during transfer.

**If OTA verify fails, backup loads.** Confirmed in decompiled FUN_000007d8:
verify returns false → `iVar4 = 0x40000` → LAB_00000946 loads backup.

**Recovery assessment (updated with Ghidra evidence):**

| Scenario | Recovery | Risk Level |
|---|---|---|
| XMODEM transfer fails | GPIO13 reset → boots existing app | **Safe** ✓ |
| Transfer OK, verify fails | SBL loads backup image | **Safe** ✓ |
| Transfer OK, verify OK, wrong mode | GPIO13 reset + re-flash | **Safe** ✓ |
| Power loss during XMODEM | Staging corrupted, app untouched | **Safe** ✓ |
| Power loss during staging→app copy | App corrupted, backup loads | **Likely safe** |
| SBL corruption | **Bricked** — SOP pin recovery | **Very unlikely** ✓ |

### Complete OTA Flow (Ghidra-confirmed across both firmwares)

```
1. ESP32 sends SubID 0x0127 (OTA_SET_FLAG=true) to radar app
   → Stock ESP32: ota_set_flag_send at 0x400e6e8c
   → ESPHome: enqueue_command_(WRITE, OTA_SET_FLAG, true)

2. Radar app writes OTA_VERIFY=1 to boot params (QSPI+0x030000 byte[5])
   → Performs soft restart (0xAD to 0xFFFFE11C)

3. SBL boots, reads boot params:
   → FUN_00009fb4 reads byte[5] (OTA_VERIFY) → returns 1
   → SBL enters XMODEM receive mode (FUN_00004224 + FrameStartISR)

4. ESP32 sends firmware via XMODEM-1K:
   → Stock ESP32: xmodem_build_packet at 0x400e702c, reads from mcu_ota partition
   → ESPHome: ota_send_current_block_() reads from MCU_OTA_FLASH_OFFSET
   → 1024-byte blocks, CRC-16/CCITT, STX framing

5. SBL receives and processes:
   → FUN_00004224 state machine: Meta header → RPRC parse → Authentication
   → FUN_00006ae4/FUN_00006c0c process RPRC segments
   → Data written to QSPI flash at target application address
   → "Error: Authentication check failed!!!" if auth fails (state 3)
   → "Error: RPRC Parsing Failure!!!" if format invalid

6. After transfer complete:
   → FUN_0000a6b0 verifies at QSPI+0x510000 (verification record)
   → If verify OK: clears OTA flag, boots normally
   → If verify fails: loads backup from QSPI+0x040000

7. SBL selects application based on boot params:
   → WORK_MODE + SLEEP_ENABLE → address 0x2D2000/0x392000/0x460000
```

**Key finding: OTA writes to the APPLICATION address, not staging.**
The 0x510000 area contains a verification record (hash/CRC), not the full
image. The backup at 0x040000 is at a separate address and is NOT overwritten.

**Stock ESP32 XMODEM functions** (from earlier RE, confirmed present):

| Function | Address | Purpose |
|---|---|---|
| `radar_ota_start` | 0x400e6f60 | Init OTA, open mcu_ota partition |
| `ota_set_flag_send` | 0x400e6e8c | Send WRITE 0x0127 BOOL=true |
| `xmodem_new` | 0x400e7440 | Allocate XMODEM context |
| `xmodem_build_packet` | 0x400e702c | Build 1029-byte XMODEM-1K packet |
| `xmodem_recv` | 0x400e7218 | 3-state receive machine |
| `xmodem_send_eot` | 0x400e7084 | Send EOT with retry |
| `xmodem_crc16` | 0x400e6fe4 | CRC-16/CCITT |

### Authentication Mechanism (Ghidra-confirmed: FUN_00000cd4)

**The "authentication" is CRC integrity verification, NOT cryptographic signing.**

FUN_00000cd4 uses the TI CRC hardware driver to compute a CRC signature over
each RPRC segment, then compares it against pre-computed values stored in the
MSTR header segment descriptors (at offsets +0x8a8 and +0x8ac in the segment
array). Functions involved:
- `FUN_0000b9a0` — get CRC transaction ID
- `FUN_00007908` — compute CRC signature over data
- `FUN_0000bcac` — read computed signature result
- Compare against stored values → `"verify success!"` or `"verify failure!"`

**Stock firmware images from `mcu_ota` will pass** because their MSTR headers
contain the correct pre-computed CRC values. Modified or custom firmware would
fail because the CRC would not match.

### XMODEM-1K Protocol — CONFIRMED

**The stock ESP32 XMODEM state machine has been fully decompiled (FUN_400e7218).**
The protocol between ESP32 and radar SBL is standard XMODEM-1K with CRC-16:

```
ESP32 sends:  WRITE SubID=0x0127 DataType=BOOL Value=1
              (FUN_400e6e8c: exactly matches our ESPHome implementation)

Radar:        Restarts into SBL → sends 'C' (0x43) for CRC mode handshake

ESP32 state machine (FUN_400e7218):
  State 0 (WAITING): wait for 'C' or NAK → State 1
  State 1 (TRANSFER): send 1029-byte blocks, wait for ACK → next block
                       if offset >= total_size → send EOT → State 2
  State 2 (ENDING):   wait for ACK → completion callback
  
  CAN (0x18): cancel counter, abort after 10
  Retries: max 5 per block (FUN_400e7128)

Packet format (FUN_400e702c):
  [STX=0x02] [Block#] [~Block#] [1024 data bytes] [CRC-16 HI] [CRC-16 LO]
  Total: 1029 bytes per packet

Data source: read callback at context+0x24, reads from mcu_ota partition
  Offset tracked at context+0x10, incremented by 0x400 per block
```

**Our ESPHome XMODEM-1K implementation is compatible.** The packet format,
handshake protocol, ACK/NAK handling, retry logic, and EOT sequence all match
the stock ESP32 firmware's implementation. The SBL's XMODEM receive handler
is likely in the Thumb code region of the SBL binary (not fully disassembled)
but responds with standard XMODEM 'C'/ACK/NAK bytes.

### Firmware Selection: All Three Images Sent Together

`xmodem_new` (FUN_400e7440) is called with callbacks including a flash read
function that reads from the `mcu_ota` partition (opened via
`esp_partition_find_first(1, 0xFE, "mcu_ota")` in FUN_400e9d90).

Our ESPHome `ota_detect_firmware_size_()` scans backwards from the end of the
4MB mcu_ota partition to find the last non-0xFF byte (0x250011 = 2,424,849
bytes), then rounds up to 1024-byte XMODEM block boundary.

**The ENTIRE mcu_ota content (all three firmwares) is sent as one transfer:**
- Transfer size: 2,425,856 bytes (2,369 blocks)
- Estimated time: ~47 seconds at 50 blocks/second
- Contents: FW1 MSS+DSS (768KB) + FW2 MSS+DSS (896KB) + FW3 (704KB)

The SBL's RPRC parser (FUN_00004224) processes the incoming stream, extracting
each MSTR image and writing the segments to their designated QSPI addresses
(0x2D2000, 0x392000, 0x460000). The boot parameter table at QSPI+0x030000
then determines which image to boot based on `SBL_WORK_MODE_OFFSET` and
`SBL_SLEEP_ENABLE_OFFSET`.

**What we still don't know:**
- **Whether QSPI is erased before writing:** The erase function could not be
  located in either the SBL or radar application firmware decompilation.
  QSPI flash REQUIRES erasure before programming (writing can only clear bits,
  not set them). Therefore erase MUST happen — the question is whether it's a
  full chip erase, sector-by-sector, or block erase. This affects how long the
  OTA takes and whether partial regions are preserved.
- **Whether the Xtensa code at 0x400e6d90 passes a sub-range of the partition**
  (could not decompile the function that calls xmodem_new).
- **Exact handshake timing:** How long after SubID 0x0127 before the radar
  sends the XMODEM 'C' handshake byte. Our code waits 20 seconds
  (OTA_HANDSHAKE_TIMEOUT_MS).

**Empirical testing would resolve all remaining unknowns.** A no-op test
(flashing FW1 back to itself) would confirm: protocol compatibility, erase
behaviour, timing, and whether stock images pass authentication.

### Completed: SubID Data Formats & Radar Firmware Validation

**Status: SOLVED** — all priority formats decoded. Validated against
decompiled TI IWR6843 radar firmware (`fp2_radar_mss.bin` = FW1 DSS, ARM:LE:32:v7).

| SubID | Name | Radar FW Function | Decoded Format | Validated? |
|-------|------|-------------------|---------------|------------|
| 0x0104 | PRESENCE_DETECT | `FUN_00026a10` | UINT8 strictly 0/1 | **YES** |
| 0x0142 | ZONE_PRESENCE | `FUN_0000f218` | UINT16 [zone_id, 0/1] | **YES** |
| 0x0115 | ZONE_MOTION | `FUN_0000f218` | UINT16 [zone_id, state] even/odd | **YES** |
| 0x0175 | ZONE_PEOPLE_NUMBER | `FUN_0001f360` | UINT16 [zone_id, count] | **YES** |
| 0x0165 | ONTIME_PEOPLE_NUMBER | `FUN_0001f360` | UINT32 (uint16 zero-ext) | **YES** |
| 0x0121 | FALL_DETECTION | **NOT FOUND** | Not sent by radar | **ISSUE** |
| 0x0154 | TARGET_POSTURE | `FUN_000229d0` | UINT16 [zone_id, posture] | **YES** |
| 0x0159 | (unknown) | — | **Not emitted by FUN_00006c84** — prior note was wrong. 0x0159 may be emitted elsewhere in FW3 but hasn't been traced to a specific emit site. Our older SLEEP_DATA float decoder was based on TI reference debug strings and was never confirmed on the wire. | **NO** |
| 0x0117 | HR/BR (FW3 only) | `FUN_00006c84` | 14-byte per-target: `[count=1][track_id][HR×100 u16 BE][BR×100 u16 BE][zeros]` | **YES** (2026-04-21) |
| 0x0161 | SLEEP_STATE | `FUN_00026fcc` | UINT8 (0=awake, 1=light, 2=deep only) | partial |
| 0x0167 | SLEEP_PRESENCE | `FUN_00026a58` | UINT8 strictly 0/1 | partial |
| 0x0171 | SLEEP_IN_OUT | `FUN_0002df1c` (vs) | UINT8 (0=exit, 1=enter) | partial |
| 0x0176 | SLEEP_EVENT | `FUN_0002cf68` (vs) | UINT8 (1=light, 2=deep transition) | partial |

Key findings from validation:
- **0x0121 is ANGLE_SENSOR_REV, not fall detection** — dispatch table confirmed.
  0x0122 is the stock fall handler. Actual fall signal is **SubID 0x0306** (UINT8: 0/1).
- **0x0155 PEOPLE_COUNTING is dwell time, not fall** — 7-byte BLOB2:
  `[ZoneID:1][Count:2 BE][DwellTime:4 BE]`. DwellTime = 0.15 × frame_count.
- **SLEEP_STATE has no REM** — only values 0, 1, 2 produced by radar state machine
- **Sleep sensors (0x0159, 0x0161, 0x0167) only produced by FW3** — the vital signs
  DSP code does not exist in FW1. Scene mode 9 alone is insufficient.
- **0x0142 and 0x0115 sent together** from same function on zone transitions
- **Presence values strictly 0/1** — never other non-zero values

### Completed: Scene Mode and Operating Mode Analysis

**Status: VALIDATED** — complete scene mode state machine traced via Ghidra.

- **FUN_00013d9c**: Scene mode write handler. Writes to flash + restarts.
  Modes 3/5 clear `sleep_report_enable`. Mode 9 does not.
- **FUN_000257d4**: Boot-time override. If `sleep_report_enable=1`, forces mode 9.
- **FUN_00025dfc**: SubID-to-scene mapper. 0x01xx + opcode!=1 → mode 3 (clears sleep).
- **Sleep and presence are mutually exclusive** — different chirp configs, different DSP.
- **Full mode switching requires radar firmware OTA** — not just scene mode changes.
  FW1 for zone detection, FW2 for fall detection, FW3 for vital signs.

### Completed: 0x0155 PEOPLE_COUNTING and Fall Detection Path

**Status: SOLVED** — fall detection uses SubID 0x0306, NOT 0x0155.

- **0x0155** is people counting + dwell time. `ontime_value = 0.15 × frame_count`.
  Non-zero whenever anyone is present. NOT a fall indicator.
- **0x0306** is the actual fall detection result (UINT8: 0=no fall, 1=fall).
  Sent from radar FUN_000244f8, offset +0x589 in config struct.
- **Fall detection algorithm** uses state machine at offset +0x587. Checks targets
  within defined boundary region for 25 frames.
- **FW2 has enhanced fall detection** with DSP scoring, height estimation,
  and a small custom neural network. FW1's fall detection is basic.

### Completed: NVS Lux Calibration

**Status: FULLY REVERSE ENGINEERED**

The stock firmware applies a two-range piecewise linear calibration to
OPT3001 readings: `calibrated_centilux = raw_centilux * k + b`

**Calibration init** decompiled from `FUN_400e8f8c`. NVS keys are in the
`"fctry"` (factory) partition, NOT the regular `"nvs"` partition.

**NVS keys and data types:**

| Key | Stored As | Conversion | Description |
|-----|-----------|------------|-------------|
| `lux_low_k` | int16 blob | ÷ 1000.0 → float | Low range slope |
| `lux_low_b` | int16 blob | ÷ 10.0 → float | Low range intercept |
| `lux_high_k` | int16 blob | ÷ 1000.0 → float | High range slope |
| `lux_high_b` | int16 blob | ÷ 10.0 → float | High range intercept |
| `lux_low_min` | int32 blob | direct (centilux) | Low range min bound |
| `lux_low_max` | int32 blob | direct (centilux) | Low range max / crossover point |
| `lux_high_min` | int32 blob | direct (centilux) | High range min bound |
| `lux_high_max` | int32 blob | direct (centilux) | High range max bound |

**Algorithm:**
```
if raw_centilux > low_max:
    calibrated = raw * high_k + high_b
else:
    calibrated = raw * low_k + low_b
result = clamp(calibrated, 0, 83000)  // centilux
```

**Hardcoded defaults** (when factory NVS has no calibration):
- Low range: k=3.856, b=1.4
- High range: k=3.876, b=2.9
- Crossover at result=160 centilux

**This unit's extracted values** (from `fp2_fctry.bin`):
```
Low range:  k=4.143, b=0.9    (5-150 centilux)
High range: k=4.868, b=-24.9  (160-2000 centilux)
Accelerometer corrections: x=-19, y=2, z=-22
```

**Filtering:** 10-sample circular buffer with trimmed mean (discard
highest and lowest when ≥3 non-zero samples). First 10 readings after
boot are discarded as warmup.

**Implementation notes:**
- Factory partition: `esp_partition_find_first(ESP_PARTITION_TYPE_DATA, 0xFF, "fctry")`
- NVS blob format: 2-byte blobs for int16, 4-byte blobs for int32
- All values in centilux (1/100 lux). Our OPT3001 driver currently
  reports in lux, so divide the calibrated centilux by 100.
- The factory NVS is preserved across ESPHome flashing (different partition)

### Completed: FW3 MSS + DSS — Vital Signs Activation and Row-Noise Trap

**Status: FULLY MAPPED (2026-04-21)** — supersedes earlier notes that
hypothesized FW3 was abandoned or required binary patches.

#### FW3 MSS emit pipeline (Ghidra, `fp2_radar_vitalsigns.bin`)

`FUN_00006c84` is the 0x0117 emitter. It is called from `FUN_0002ad1c` (a task
loop that pends on an IPC semaphore from the DSS). Three gates in series must
all pass:

1. `config+0xb8 == 1` — LOCATION_REPORT_ENABLE gate. Set by the 0x0112 WRITE
   handler at 0x2c9c8. The driver sends this during init.
2. `*(DAT_00006f60 + 0x28) > 15` — rate limiter. This counter increments every
   frame and resets only on successful emit. Not a stabilization window;
   caps emissions at ≈one per 16 frames (≈800ms at 20Hz).
3. `target_count != 0` — the DSS-reported target count, passed as param_9.
   Read from shared-memory byte at `0x0802ba6c - 0x48`. This is the critical
   gate for vital-signs operation.

When all three pass, the emitter writes a 14-byte per-target block to
`*(config+0x500)` at offsets 0..13:

| Offset | Field | Encoding |
|--------|-------|----------|
| 0 | count | 1 (fixed) |
| 1 | track_id | u8 |
| 2-3 | HR × 100 | u16 big-endian |
| 4-5 | BR × 100 | u16 big-endian |
| 6-13 | zero | padding |

Payload is sent as 0x0117 REPORT (opcode 5). Driver must decode 0x0117 as
vitals in FW3 and as X/Y tracking in FW1/FW2 — same SubID, different layout.

#### FW3 WRITE dispatcher map

`FUN_00009e80` routes WRITE SubIDs to per-attribute handlers. Verified 2026-04-21:

| SubID | Handler | Writes | Type | Notes |
|-------|---------|--------|------|-------|
| 0x0112 | `location_report_enable_handler` @ 0x2c9c8 | `+0xb8` | u8 | Opens HR/BR emit gate |
| 0x0116 | `FUN_00016e18` | SBL boot params in flash | — | Triggers flash save + radar restart |
| 0x0122 | `FUN_0002a830` | `+0x510` | u8 | FALL_SENSITIVITY — when 1, activates bed-region geometry via FUN_0002dca8 |
| 0x0143 | `FUN_0002d068` | `+0x5b8` | u8 | Alt activator for bed-region geometry (values 4,7 with +0x510==2) |
| 0x0156 | `FUN_0001fbf8` | — | — | **SLEEP_REPORT_ENABLE — logger only, NO-OP**. Prints current flash params; does not write any config field. |
| 0x0168 | `FUN_0002b228` | `+0xb94` | u8 | SLEEP_MOUNT_POSITION (0-3 clamped) |
| 0x0169 | `FUN_00029f48` | `+0xb98` | u32 | SLEEP_ZONE_SIZE packed `(width_cm<<16)\|length_cm` |
| 0x0170 | `FUN_0002b27c` | `+0xb9c` | u8 | WALL_CORNER_POS (mounting orientation for general tracking; distinct from SLEEP_MOUNT_POSITION) |
| 0x0173 | `FUN_0002ae24` | `+0xba1` | u8 | WALK_DISTANCE_ENABLE (also clears `+0xba4` cached walk-distance accumulator on change) |
| 0x0177 | `FUN_0002bfa0` | `+0xb92` | u16 | SLEEP_BED_HEIGHT |
| 0x0178 | `FUN_0002c4a4` | `+0xbb0` | u16 | OVERHEAD_HEIGHT (range [150,400], default 220) |

**SBL byte[4] is permanently 0 on this device.** Scanning the FW3 binary for
all stores to `config+0xb6c` returns only cold-init zeroing and WORK_MODE
clear-to-zero. No WRITE handler sets it non-zero. So the SBL
`sleep_enable==1` firmware-selection branch is dead code, and `work_mode==9`
is the sole path to FW3 boot.

#### FW3 geometry functions (Ghidra)

Bed-region geometry built by `FUN_00006390` in DSS task. Helpers:

- `FUN_0002e768` — width in meters = `(zone_size>>16) / 100.0`
- `FUN_0002e740` — length in meters = `(zone_size & 0xFFFF) / 100.0`
- `FUN_0002b760` / `FUN_0002b850` — mount_position X/Y offset, returns 0 when
  `FUN_0002dca8()` returns 0 or mount_position ∈ {0,3}
- `FUN_0002b620` — mount_angle in radians = `π × (90 - *(config+0x508)) / 180`

`FUN_0002dca8` is a boolean gate:
```
return (config+0x510 == 1)
    OR (config+0x510 == 2 AND config+0x5b8 ∈ {4, 7})
```
Fresh-init defaults: `+0x510=2`, `+0x5b8=3` → returns 0 (geometry disabled).
Driver's init sends `FALL_SENSITIVITY=1` which writes `+0x510=1`, enabling it.

#### FW3 DSS — C674x DSP code analysis (2026-04-21)

`fp2_radar_vitalsigns.bin` is the MSS (Cortex-R4F) slice only. The complete
FW3 image is packaged as three TI RPRC subimages (RPRC magic = `"RPRC"`):

| File | Type | Size | Contents |
|------|------|------|----------|
| `fw3_rprc0_type4.bin` | 0x04 (MSS R4F) | 210KB | Same code as `fp2_radar_vitalsigns.bin` at offset 0 |
| `fw3_rprc1_typec.bin` | 0x0c (DSS_DATA) | 247KB | Shared TI-RTOS blob, identical SHA256 across FW1/FW2/FW3 |
| `fw3_rprc2_typed.bin` | 0x0d (DSS_APP) | 262KB | **FW3 DSS vital-signs application (C674x DSP code)** |

Strip the 48-byte RPRC header to get the raw C674x code at offset 0x30.
Entry point 0x007f5fe0 (from RPRC header offset 4).

**Aqara's FW3 is built from TI mmWave Industrial Toolbox 4.11.0
`Vital_Signs_With_People_Tracking` lab.** Embedded path strings in both MSS
and DSS binaries confirm:

```
C:/ti/mmwave_industrial_toolbox_4_11_0/labs/Vital_Signs/
  Vital_Signs_With_People_Tracking/src/common/dpc/
    capon3d_vitalsigns/src/objectdetection.c
  Vital_Signs_With_People_Tracking/src/common/dpc/
    objdetrangehwa_vitalsigns/src/objdetrangehwa.c
  Vital_Signs_With_People_Tracking/src/dss/dss_main.c
  Vital_Signs_With_People_Tracking/src/mss/mss_main.c
  Vital_Signs_With_People_Tracking/src/mss/pcount3D_cli.c
```

The pipeline is:

1. ADC buffer + range FFT (HWA)
2. `RADARDEMO_aoaEst2DCaponBF` — 2D Capon angle beamforming (azimuth × elevation)
3. Dynamic CFAR (`RADARDEMO_detectionCFAR_handle` configured via
   `dynamicRACfarCfg`) — detects moving targets
4. Static CFAR (configured via `staticRACfarCfg`) — detects stationary targets
5. Point cloud assembly (range, angle, Doppler, SNR per detection)
6. **TI GTrack group tracker** (`src/gtrack_module.c`) — allocates, associates,
   and maintains tracks via Kalman filtering
7. Vital-signs FFT on the tracked point's phase history (breathing + heart rate)
8. Write results into `VS_Data_MSS2DSS` shared-memory struct
9. MSS's `FUN_0002ad1c` task loop reads the struct and calls `FUN_00006c84`
   to emit 0x0117 frames

#### Aqara's hard-coded DSS defaults

Extracted from MSS binary strings (these are the CLI commands Aqara's
`pcount3D_cli.c` fires at boot to configure the DSS):

```
sensorPosition 2 0 0                 # sensor height 2m, az=0°, el=0°
staticBoundaryBox -1.5 1.5 0 2.5 -3 3    # x∈[-1.5,1.5], y∈[0,2.5], z∈[-3,3]
presenceBoundaryBox -1.5 1.5 0 2.5 -3 3
fovCfg -1 70.0 20.0                  # 70° azimuth, 20° elevation

# CFAR
dynamicRACfarCfg -1 3 4 2 2 8 12 4 12 5.00 8.00 0.40 1 1
staticRACfarCfg  -1 6 2 2 2 8 8 6 4 8.00 15.00 0.30 0 0

# Angle estimation
dynamic2DAngleCfg -1 1.5 0.0300 1 0 1 0.30 0.85 8.00
dynamicRangeAngleCfg -1 0.75 0.0010 1 0

# GTrack allocation
allocationParam 20 100 0.1 10 0.5 20
# snrThre=20 snrThrObscured=100 velocityThre=0.1 pointsThre=10 maxDistThre=0.5 maxVelThre=20

# GTrack state machine
stateParam 2 50 50 900 50 9000
# det2active=2 det2free=50 active2free=50 static2free=900 exit2free=50 sleep2free=9000

# GTrack gating
gatingParam 3 2 2 3 4

# GTrack
trackingCfg 1 2 800 1 46 96 70

# Vital signs
vitalsign 15 300
fineMotionCfg -1 1
```

#### The GTrack velocity allocation gate — actual silent-all-night cause

DSS's `gtrack_moduleAllocate()` (verified in TI SDK source
`/tmp/ti-sdk/sdk/mmwave_sdk_01_02_00_05/packages/ti/alg/gtrack/src/gtrack_module.c`,
line 190-192):

```c
if((allocNum > inst->params.allocationParams.pointsThre) &&    // >10 points
   (allocSNR > inst->params.allocationParams.snrThre) &&        // SNR sum > 20
   (fabs(un[2]) > inst->params.allocationParams.velocityThre) ) // |velocity| > 0.1 m/s
{
    /* Allocate new tracker */
}
```

`un[2]` is the cluster centroid's radial velocity (doppler). To allocate a new
track, the centroid must have |velocity| > 0.1 m/s. A sleeping person has
radial velocity ≈ 0 (chest expansion is sub-mm per frame, 0 at CFAR point
resolution). The cluster velocity fails the gate. **No track is ever created,
numCurrentTargets stays 0 in the VS_Data_MSS2DSS struct, no 0x0117 emit.**

This is why the sensor goes silent for the whole night if Sleep Monitoring is
set while the user is already in bed.

#### The workaround (documented in 04-esphome-component.md Operating Modes)

Once a track is allocated from motion, the state machine keeps it alive via
long static/sleep timers:

```
stateParam 2 50 50 900 50 9000
# static2free=900 frames (~45s)  sleep2free=9000 frames (~7.5 min)
```

So the correct sleep-mode entry is: cycle Operating Mode to Sleep Monitoring
while empty of bed, let FW3 boot, then **walk to the bed and climb in with
motion**. The track allocates within 2-3 seconds of sustained detection, then
persists via the sleep-state timer. Lying still thereafter is fine.

#### MSS → DSS IOCTL surface (embedded MSS error strings)

```
DPC_OBJDET_IOCTL__STATIC_PRE_START_CFG
DPC_OBJDET_IOCTL__STATIC_PRE_START_COMMON_CFG
DPC_OBJDETRANGEHWA_IOCTL__STATIC_PRE_START_CFG
DPC_OBJDETRANGEHWA_IOCTL__STATIC_PRE_START_COMMON_CFG
DPC_OBJDETRANGEHWA_IOCTL__TRACKER_STATIC_CFG
```

The MSS uses these IOCTLs to push the CLI-derived configs into the DSS
Data-Processing Chain (DPC). Any driver-side fix to override `velocityThre=0`
would need to either send a different `allocationParam` command BEFORE start,
or send a post-start tracker reconfig. Whether Aqara exposes any attribute
SubID that wraps such a command is still undetermined.

#### FW3 DSS ancestor sources (cloned locally for reference)

Public TI-ancestor repos in `/tmp/vital_signs_people_tracking/`:

- `multiple-person-vital-signs/firmware/vital_signs_tracking_dss/` — an
  OLDER `oddemo_heatmap` lineage that Aqara does **NOT** use. Has a
  2000.0f peak threshold and row-noise self-calibration — neither of these
  apply to Aqara's capon3d_vitalsigns build.
- `hoangnv31/mmwave_tracking/datapath/dpc/objectdetection/objdetdsp/` —
  capon3d 3D people counting (no vital signs). Same base detection pipeline
  Aqara uses but without the VS overlay.

TI's GTrack library is shipped with mmwave_sdk — at
`/tmp/ti-sdk/sdk/mmwave_sdk_01_02_00_05/packages/ti/alg/gtrack/`. This
is the authoritative source for the allocation gate logic.

The exact `Vital_Signs_With_People_Tracking` source is TI-proprietary (binary-
only distribution), but we now have enough cross-reference to understand the
algorithm fully.

### Priority 4: 0x03xx Attribute Range

Commented-out code references three attributes in the 0x03xx range:
```cpp
// enqueue_read_((AttrId) 0x302); // Read radar flash ID
// enqueue_read_((AttrId) 0x303); // Read radar ID
// enqueue_read_((AttrId) 0x305); // Read radar calibration result
```

These appear to be radar system information attributes.

## Ghidra Analysis Tips

### Finding Functions by String Reference

Strings in the FP2 firmware live in `app_DROM0_3f400020`. To find the function
that uses a string:

1. `search_strings` to find the string address
2. `get_xrefs_to` on that address — returns the referencing function
3. `decompile_function` on the function address

### Byte Pattern Search for Strings

If `search_strings` doesn't find a string (e.g., not defined as a string type),
search for the raw bytes:

```
# "lux_low_k" = 6c 75 78 5f 6c 6f 77 5f 6b
search_byte_patterns pattern="6c 75 78 5f 6c 6f 77"
```

Then find references to that address using literal pool searches.

### Xtensa Literal Pools

Xtensa uses `l32r` instructions to load 32-bit values from a literal pool. The
literal pool entries appear as 4-byte little-endian addresses in memory, usually
just before the function that uses them. Search for the address bytes in
little-endian order:

```
# To find code referencing address 3f40b9d8:
search_byte_patterns pattern="d8 b9 40 3f"
```

## Reference Resources

### ESP32 Reverse Engineering

- [BlackVS/ESP32-reversing](https://github.com/BlackVS/ESP32-reversing) — curated resource list
- [wilco375/ESP-Firmware-Toolbox](https://github.com/wilco375/ESP-Firmware-Toolbox) — complete RE toolkit
- [Tarlogic FIDB guide](https://www.tarlogic.com/blog/esp32-firmware-using-ghidra-fidb/) — function identification

### Ghidra Extensions

| Extension | URL | Purpose |
|-----------|-----|---------|
| ghidra-esp32-flash-loader | [dynacylabs](https://github.com/dynacylabs/ghidra-esp32-flash-loader) | Load ESP32 flash dumps (required) |
| GhidraSVD | [antoniovazquezblanco](https://github.com/antoniovazquezblanco/GhidraSVD) | Import SVD peripheral maps |
| ESP32 SVD files | [espressif/svd](https://github.com/espressif/svd) | Official peripheral definitions |

### FP2-Specific RE

- [hansihe/AqaraPresenceSensorFP2ReverseEngineering](https://github.com/hansihe/AqaraPresenceSensorFP2ReverseEngineering) — UART protocol, board schematic, GPIO map
- [niceboygithub/AqaraPresenceSensorFP2](https://github.com/niceboygithub/AqaraPresenceSensorFP2) — hardware details, esptool commands

### MCP Server

- [bethington/ghidra-mcp](https://github.com/bethington/ghidra-mcp) — 193-tool MCP server for Claude-assisted Ghidra analysis
