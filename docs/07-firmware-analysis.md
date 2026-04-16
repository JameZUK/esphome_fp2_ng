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
| FW3 | 0x1A0000 | 678KB | 0xA579DCB8 ✓ | Vital signs (standalone, no SBL) |

**Naming correction:** `fp2_radar_mss.bin` in `/ghidra-binaries/` is actually FW1's
DSS content (offset 0x0120B0 in mcu_ota), not the MSS boot loader. All Ghidra
analysis was on the correct binary. `fp2_radar_dsp.bin` is FW2's DSS content.

**Shared runtime:** All three DSS images contain an identical TI-RTOS segment
(247,416 bytes, same SHA256) — built from the same TI SDK.

**OTA requirements:** Must use raw MSTR images from mcu_ota (NOT extracted .bin
files). CRC32 trailer (4 bytes) must be included. FW3 has no SBL — requires
compatible boot loader already on radar QSPI flash.

### SBL OTA Safety Assessment

**Status: PARTIALLY ASSESSED** — SBL strings analysed, Ghidra decompilation pending.

The FW1 MSS (SBL boot loader, 65KB) handles radar firmware OTA via XMODEM-1K.
Key safety features confirmed from string analysis:

**Safety features (confirmed via strings):**
- **Backup factory image fallback:** `"Error: Could not download the metaimage
  to RAM. Trying to boot the backup factory default image from Flash address: %x"`
  — if the main application fails to load, the SBL loads a backup.
- **Image loaded to RAM first:** `"Load the input buffer to the RAM Start..."`
  / `"...End..."` — firmware verified in RAM before execution.
- **CRC verification:** `CRC Driver` with `"verify success!"` / `"verify failure!"`
- **Authentication check:** `"Error: Authentication check failed!!!"` — may block
  unsigned/modified firmware images.
- **Boot parameter table** at flash 0x240000 with `SBL_OTA_VERIFY_OFFSET`,
  `SBL_WORK_MODE_OFFSET`, `SBL_SLEEP_ENABLE_OFFSET`.
- **Flash drivers** for Macronix, Winbond, Spansion QSPI chips.

**Risks (not yet verified via Ghidra decompilation):**
- **Unknown: Does OTA overwrite the backup image?** If the OTA target area
  overlaps with the backup, a failed write leaves no recovery path.
- **Unknown: Partial write recovery.** If power is lost mid-flash, the main
  image is corrupted. Does the backup survive?
- **Authentication may block our transfers.** The `"Authentication check failed"`
  string suggests signature verification. Only firmware images from the original
  `mcu_ota` partition (with valid signatures) may be accepted.
- **XMODEM-1K implementation is untested.** Code is structurally correct but
  has never been run against the actual radar SBL.

**Recovery options:**

| Scenario | Recovery |
|---|---|
| XMODEM transfer fails (timeout/CRC) | SBL stays in boot mode → GPIO13 reset → boots existing firmware |
| Transfer OK but image fails verification | SBL falls back to backup factory image |
| Transfer OK, verification OK, wrong firmware | GPIO13 reset → re-flash correct firmware |
| Partial write + power loss | Unknown — depends on whether backup image is preserved |
| SBL itself corrupted | **Bricked** — requires TI IWR6843 SOP pin ROM bootloader recovery |

**Recommended safe test sequence:**
1. Flash FW1 back to itself (no-op test of XMODEM pipeline)
2. If successful, flash FW3 (vital signs) for sleep monitoring
3. Keep GPIO13 reset available for recovery
4. Do NOT flash custom/modified firmware (authentication may reject it)

**Remaining work:**
- Load SBL into Ghidra (ARM Cortex-R4, RPRC content at mcu_ota offset 0x40)
- Decompile the OTA write handler to confirm flash target addresses
- Verify backup image is separate from OTA target area
- Trace the authentication mechanism to confirm stock firmware images pass
- Identify the radar QSPI flash partition layout

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
| 0x0159 | SLEEP_DATA | `FUN_00006c84` (vs) | BLOB2: 3× LE float (12 bytes) | **YES** |
| 0x0161 | SLEEP_STATE | `FUN_00026fcc` | UINT8 (0=awake, 1=light, 2=deep only) | **YES** |
| 0x0167 | SLEEP_PRESENCE | `FUN_00026a58` | UINT8 strictly 0/1 | **YES** |
| 0x0171 | SLEEP_IN_OUT | `FUN_0002df1c` (vs) | UINT8 (0=exit, 1=enter) | **YES** |
| 0x0176 | SLEEP_EVENT | `FUN_0002cf68` (vs) | UINT8 (1=light, 2=deep transition) | **YES** |

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
