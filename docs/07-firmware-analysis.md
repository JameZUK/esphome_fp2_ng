# Firmware Analysis Guide

## Overview

This guide covers reverse engineering the stock Aqara ESP32 firmware to discover
undocumented features — specifically the light sensor driver, radar OTA protocol,
and unknown SubID data formats.

## Prerequisites

### Hardware
- Aqara FP2 with UART wires attached (TP8, TP9, TP28)
- USB-UART adapter (3.3V logic level)

### Software
- **Ghidra 12.0.3** — https://ghidra-sre.org (native Xtensa support)
- **Java 21 LTS** (OpenJDK)
- **Python 3.10+**
- **esptool** — `pip install esptool`
- **ghidra-mcp** (bethington) — MCP server for Claude-assisted analysis
- **ghidra-esp32-flash-loader** (dynacylabs) — Ghidra extension for ESP32 flash
- **GhidraSVD** (optional) — SVD file loader extension

## Step 1: Dump the Firmware

**Important**: Do this BEFORE flashing ESPHome. The stock firmware contains the
light sensor driver, radar OTA code, and all protocol handlers.

```bash
# Hold TP28 (GPIO0) LOW during power-on to enter download mode
# Connect USB-UART adapter: TP8=TX, TP9=RX, GND

# Dump entire 16Mbit flash
esptool.py --baud 230400 --port /dev/ttyUSB0 read_flash 0x0 0x1000000 fp2_stock_firmware.bin

# Label the backup with the unit's HomeKit pairing digits
# Flash may contain unit-specific calibration data
```

## Step 2: Parse the Flash Image

### Option A: Ghidra Flash Loader (Recommended)

Install the **dynacylabs/ghidra-esp32-flash-loader** extension:

1. Download the release ZIP matching your Ghidra version from
   https://github.com/dynacylabs/ghidra-esp32-flash-loader/releases
2. Ghidra → File → Install Extensions → select ZIP → restart
3. Import: File → Import File → select `fp2_stock_firmware.bin`
4. The loader auto-detects ESP32, loads partitions, imports SVD
   peripherals, and maps ROM code

This is the easiest path — it handles everything automatically.

### Option B: Manual ELF Extraction

```bash
# Install esp32_image_parser
pip install esp32_image_parser

# View partition table
python3 -m esp32_image_parser show_partitions fp2_stock_firmware.bin

# Extract application partition as ELF
python3 -m esp32_image_parser create_elf fp2_stock_firmware.bin \
    -partition ota_0 -output fp2_app.elf

# Dump NVS (non-volatile storage — may contain WiFi creds, HomeKit data)
python3 -m esp32_image_parser dump_nvs fp2_stock_firmware.bin \
    -partition nvs -nvs_output_type json
```

Alternative: **esp32knife** (more actively maintained):
```bash
# From https://github.com/niceboygithub/AqaraPresenceSensorFP2
pip install esp32knife
esp32knife --chip esp32 dissect fp2_stock_firmware.bin
```

Then import the ELF into Ghidra manually:
- Architecture: `Xtensa:LE:32:default`
- Load SVD: File → Import SVD (via GhidraSVD extension) using
  `esp32.svd` from https://github.com/espressif/svd
- Import ROM labels from ESP-IDF's `esp32.rom.ld` linker script

## Step 3: Set Up Ghidra MCP Server

### Install bethington/ghidra-mcp

```bash
git clone https://github.com/bethington/ghidra-mcp.git
cd ghidra-mcp

# Linux
./ghidra-mcp-setup.sh --deploy --ghidra-path /path/to/ghidra_12.0.3_PUBLIC

# Install Python dependencies
pip install -r requirements.txt
```

### Enable in Ghidra

1. Launch Ghidra, open your project with the FP2 firmware
2. File → Configure → check GhidraMCP
3. Tools → GhidraMCP → Start MCP Server
4. Verify: `curl http://127.0.0.1:8089/check_connection`

### Configure Claude Code

Add to your MCP settings (project `.mcp.json` or `~/.claude.json`):

```json
{
  "mcpServers": {
    "ghidra-mcp": {
      "command": "python",
      "args": ["/absolute/path/to/ghidra-mcp/bridge_mcp_ghidra.py"]
    }
  }
}
```

The bridge uses stdio transport (Claude Code default) and connects to Ghidra's
HTTP server at `127.0.0.1:8089`.

Optional environment variables (`.env` file in ghidra-mcp directory):
```
GHIDRA_HOST=127.0.0.1
GHIDRA_PORT=8089
MCP_TIMEOUT=30
SCRIPT_TIMEOUT=1800
```

### MCP Capabilities

The bethington/ghidra-mcp server provides **193 tools** including:

- Function listing, searching, decompilation (standard + forced)
- Cross-references (bidirectional + bulk)
- Call graph analysis
- Memory and data segment enumeration
- Data type/struct creation and modification
- Byte pattern search
- Function documentation export/import
- SHA-256 function hashing for cross-version matching
- Completeness scoring for analysis progress

## Step 4: Apply Function Identification (FIDB)

Most of the firmware is ESP-IDF SDK code. FIDB auto-identifies these functions
so you can focus on Aqara's custom code.

### Determine ESP-IDF Version

Check the UART boot log (serial output during stock firmware boot) for a line
like:
```
I (25) boot: ESP-IDF v5.x.x 2nd stage bootloader
```

Or look for version strings in the firmware binary.

### Create FIDB (One-Time)

1. Clone the matching ESP-IDF version:
   ```bash
   git clone -b v5.x.x --recursive https://github.com/espressif/esp-idf.git
   ```
2. Compile multiple example projects with `-Os` and `-O2` optimizations
3. Import all compiled ELFs into a Ghidra project
4. Auto-analyze each
5. Tools → Function ID → Create New Empty FIDB → Populate from Programs
6. Architecture: `Xtensa:LE:32:default`

### Apply FIDB

1. Tools → Function ID → Attach Existing FIDB → select your `.fidb` file
2. Run Auto Analyze with "Function ID" analyzer enabled
3. Thousands of SDK functions will be identified automatically

## Step 5: Analysis Targets

### Priority 1: Light Sensor Driver

The stock firmware reads an ambient light sensor and exposes it via HomeKit.
The sensor is likely an I2C device sharing the bus with the accelerometer
(GPIO32=SCL, GPIO33=SDA).

**Search strategy:**
- Find I2C transactions to addresses other than 0x27 (accelerometer)
- Search for references to `i2c_master_cmd_begin`, `i2c_master_write_byte`,
  or the new `i2c_master_transmit` API
- Look for string references: "lux", "light", "illumin", "ambient"
- Check for ADC reads on channels 4/5/7 (GPIO32/33/35)
- Find the HomeKit characteristic handler for IID 0x0A72
  (Current Ambient Light Level)

**Expected findings:**
- I2C address of the light sensor IC
- Initialization sequence (register writes)
- Read command and data format
- Conversion formula (raw ADC/I2C value → lux)

### Priority 2: Radar OTA / SOP Pin Control

The stock firmware can update the radar's TI IWR6843AOP firmware via the
Aqara app. Understanding this enables radar OTA from ESPHome.

**Search strategy:**
- Find references to SubID 0x0127 (`OTA_SET_FLAG`)
- Search for GPIO configurations beyond the known pin map — unknown GPIOs
  may control the radar's SOP (Sense-On-Power) pins
- Look for TI BSL (Bootstrap Loader) protocol implementation
- Search for strings: "ota", "upgrade", "firmware", "bsl", "sop"
- Find the firmware download handler (likely fetches from Aqara cloud URL)

**Expected findings:**
- Which GPIOs control the radar SOP pins (for bootloader mode)
- The UART bootloader protocol sequence
- Whether the radar firmware is stored in ESP32 flash or downloaded on-demand

### Priority 3: Unknown SubID Data Formats

Several SubIDs have unknown data types (marked `?` in the protocol docs).
The stock firmware contains handlers for all of them.

**Key targets:**

| SubID | Name | What to find |
|-------|------|-------------|
| 0x0121 | FALL_DETECTION | Event structure, severity levels |
| 0x0154 | TARGET_POSTURE | Posture enum values (standing/sitting/lying) |
| 0x0159 | SLEEP_DATA | Sleep tracking data format |
| 0x0161 | SLEEP_STATE | Sleep state enum (awake/light/deep/REM?) |
| 0x0164 | REALTIME_PEOPLE | Difference from ONTIME (0x0165) |
| 0x0174 | WALK_DISTANCE_ALL | Distance data format and units |

**Search strategy:**
- Find the main UART report dispatcher (equivalent to our `handle_report_()`)
- Each case/branch will reveal the payload parsing for that SubID
- Cross-reference with the cloud upload handlers to understand data semantics

### Priority 4: 0x03xx Attribute Range

The code has commented-out reads for SubIDs 0x0302, 0x0303, 0x0305:
```cpp
// enqueue_read_((AttrId) 0x302); // Read radar flash ID attribute
// enqueue_read_((AttrId) 0x303); // Read radar ID attribute
// enqueue_read_((AttrId) 0x305); // Read radar calibration result attribute
```

These may be in a different attribute space (radar system info vs detection
config). The stock firmware likely reads these during initialization.

## Reference Resources

### ESP32 Reverse Engineering

- [BlackVS/ESP32-reversing](https://github.com/BlackVS/ESP32-reversing) —
  curated resource list (architecture docs, tools, exploits)
- [wilco375/ESP-Firmware-Toolbox](https://github.com/wilco375/ESP-Firmware-Toolbox) —
  complete RE toolkit (dump, analyze, patch) from OrangeCon 2025
- [Tarlogic FIDB guide](https://www.tarlogic.com/blog/esp32-firmware-using-ghidra-fidb/) —
  function identification walkthrough
- [Xtensa ISA Reference](https://0x04.net/~mwk/doc/xtensa.pdf) — instruction
  set manual

### Ghidra Extensions

| Extension | URL | Purpose |
|-----------|-----|---------|
| ghidra-esp32-flash-loader | [dynacylabs](https://github.com/dynacylabs/ghidra-esp32-flash-loader) | Load ESP32 flash dumps directly |
| GhidraSVD | [antoniovazquezblanco](https://github.com/antoniovazquezblanco/GhidraSVD) | Import SVD peripheral maps |
| ESP32 SVD files | [espressif/svd](https://github.com/espressif/svd) | Official peripheral definitions |

### FP2-Specific RE

- [hansihe/AqaraPresenceSensorFP2ReverseEngineering](https://github.com/hansihe/AqaraPresenceSensorFP2ReverseEngineering) —
  UART protocol, board schematic, GPIO map
- [niceboygithub/AqaraPresenceSensorFP2](https://github.com/niceboygithub/AqaraPresenceSensorFP2) —
  hardware details, esptool commands, partition layout

### MCP Server

- [bethington/ghidra-mcp](https://github.com/bethington/ghidra-mcp) — 193-tool
  MCP server for Claude-assisted Ghidra analysis
