# ESPHome Component Reference

## Overview

The project provides two ESPHome external components:

- **`aqara_fp2`** — main radar UART communication and entity management
- **`aqara_fp2_accel`** — accelerometer + OPT3001 light sensor driver

## Component Architecture

```
aqara_fp2/
  __init__.py          Python config schema and code generation
  fp2_component.h      C++ header — types, enums, class declaration
  fp2_component.cpp    C++ implementation — protocol, state machine, handlers

aqara_fp2_accel/
  __init__.py          Python config schema
  aqara_fp2_accel.h    C++ header — accel + OPT3001
  aqara_fp2_accel.cpp  C++ implementation — I2C, orientation, lux
```

### Key Classes

- **`FP2Component`** — main component, extends `Component` and `UARTDevice`.
  Manages the UART state machine, command queue, and all sensor entities.
- **`FP2Zone`** — per-zone configuration and sensor holders. Contains the zone's
  grid bitmap, sensitivity, and pointers to presence/motion/count sensors.
- **`FP2LocationSwitch`** — switch entity to enable/disable target location
  reporting.
- **`FP2CalibrateEdgeButton`** — button entity to trigger edge auto-calibration.
- **`FP2CalibrateInterferenceButton`** — button entity to trigger interference
  auto-calibration.
- **`AqaraFP2Accel`** — accelerometer + light sensor component running on a
  dedicated FreeRTOS task for non-blocking I2C reads.

## UART State Machine

The frame decoder in `handle_incoming_byte_()` processes bytes one at a time:

```
SYNC → VER_H → VER_L → SEQ → OPCODE → LEN_H → LEN_L → H_CHECK → PAYLOAD → CRC_L → CRC_H
  │                                                         │                          │
  │ (not 0x55)                                              │ (checksum fail)          │ (CRC fail)
  └─────────────────────────────────────────────────────────┴──────────────────────────┘
                              Reset to SYNC
```

After successful CRC validation, the frame is dispatched to `handle_parsed_frame_()`
which routes by OpCode to:
- `handle_ack_()` — processes ACKs, releases command queue
- `handle_report_()` — processes radar reports (presence, motion, tracking, etc.)
- `handle_response_()` — handles reverse-read requests from the radar, and
  routes data-bearing responses through `handle_report_()` (some SubIDs like
  zone presence may arrive as RESPONSE instead of REPORT)

## Command Queue

Commands are queued in a `std::deque<FP2Command>` and sent sequentially:

1. `send_next_command_()` sends the front command
2. If it's a WRITE, sets `waiting_for_ack_attr_id_` and waits
3. On ACK, pops the command and sends the next
4. On timeout (500ms), retries up to 3 times before dropping
5. ACK frames are high-priority — pushed to the front of the queue

## Exposed Entities

### Global Sensors

| Config Key | Entity Type | Class | Description |
|------------|-------------|-------|-------------|
| `global_zone.presence` | binary_sensor | occupancy | Overall presence (SubID 0x0104: 0=empty, non-zero=occupied) |
| `global_zone.motion` | binary_sensor | motion | Overall motion (SubID 0x0103: even=active, odd=inactive) |
| `people_count` | sensor | measurement | Total person count (from SubID 0x0165) |
| `fall_detection` | binary_sensor | — | Fall event (SubID 0x0121) — see note below |
| `sleep_state` | text_sensor | — | Sleep state: none/awake/light/deep (SubID 0x0161) |
| `sleep_presence` | binary_sensor | occupancy | Sleep zone presence (SubID 0x0167) |
| `heart_rate` | sensor | measurement (bpm) | Heart rate from sleep monitoring (SubID 0x0159)* |
| `respiration_rate` | sensor | measurement (br/min) | Respiration rate from sleep monitoring (SubID 0x0159)* |
| `heart_rate_deviation` | sensor | measurement (bpm) | Heart rate deviation from sleep monitoring (SubID 0x0159) |
| `walking_distance` | sensor | measurement (m) | Cumulative walking distance (SubID 0x0174, confirmed cm÷100) |
| `target_tracking` | text_sensor | diagnostic | Base64-encoded target data (SubID 0x0117) |
| `location_report_switch` | switch | — | Show/hide target tracking data (see below) |
| `calibrate_edge` | button | diagnostic | Trigger edge boundary auto-calibration |
| `calibrate_interference` | button | diagnostic | Trigger interference auto-calibration |
| `clear_edge` | button | diagnostic | Clear/reset room boundary calibration |
| `clear_interference` | button | diagnostic | Clear/reset interference calibration |
| `radar_fw_stage` | button | diagnostic | **EXPERIMENTAL** — Stage radar firmware from URL to flash |
| `radar_ota` | button | diagnostic | **EXPERIMENTAL** — Flash staged firmware to radar via XMODEM |
| `radar_temperature` | sensor | temperature | Radar chip temperature in Celsius |
| `radar_software_version` | text_sensor | diagnostic | Radar firmware build number |
| `mounting_position_sensor` | text_sensor | diagnostic | Current mount position string |

### Per-Zone Sensors

| Config Key | Entity Type | Class | Description |
|------------|-------------|-------|-------------|
| `presence` | binary_sensor | occupancy | Zone presence (inferred from motion and people count) |
| `motion` | binary_sensor | motion | Zone motion (SubID 0x0115: even=active, odd=inactive) |
| `zone_people_count` | sensor | measurement | Native per-zone count (SubID 0x0175) |
| `posture` | text_sensor | — | Per-zone posture: none/standing/sitting/lying (SubID 0x0154) |
| `zone_map_sensor` | text_sensor | diagnostic | Zone grid as hex string |

*Sleep data fields are IEEE 754 floats in LE byte order. Field names and
order confirmed from radar firmware debug strings (TI Vital Signs demo).
Sleep state values 0 (awake), 1 (light), 2 (deep) confirmed — no REM state
exists in the radar firmware. See [02-uart-protocol.md](02-uart-protocol.md)
for full details.*

**Fall detection note:** Radar firmware analysis found that SubID 0x0121 is
**not sent by the radar directly**. Fall detection data goes through SubID
0x0155 (PEOPLE_COUNTING). The stock ESP32 firmware likely extracts fall
events from 0x0155 and rebroadcasts as 0x0121. Our handler for 0x0121 may
not receive data — this needs further investigation.

### Accelerometer / Light Sensor

| Config Key | Entity Type | Class | Description |
|------------|-------------|-------|-------------|
| `light_sensor` | sensor | illuminance | OPT3001 ambient light (lux) |

### Grid Diagnostic Sensors

| Config Key | Entity Type | Description |
|------------|-------------|-------------|
| `edge_label_grid_sensor` | text_sensor | Edge boundary grid hex |
| `entry_exit_grid_sensor` | text_sensor | Entry/exit grid hex |
| `interference_grid_sensor` | text_sensor | Interference source grid hex |

## Per-Zone People Counting

Zone people counting uses the radar's native per-zone count reports
(SubID 0x0175). The radar internally counts people in each configured zone
and sends periodic REPORT frames with `[zone_id, count]`.

### Location Reporting and People Counting

The radar's people counting depends on its internal location tracking being
active. The component always enables `LOCATION_REPORT_ENABLE` (0x0112) during
initialization to ensure counting works.

The **Report Targets** switch controls only whether target tracking data is
published to the `target_tracking` text sensor in HA. It does **not** disable
the radar's internal tracking — people counting, zone presence inference, and
all other features continue working regardless of the switch state.

### Zone Presence Inference

The radar may not send explicit zone presence reports (SubID 0x0142) when a
zone is already occupied at boot — it only fires on state transitions. To
ensure zone presence is always accurate, it is inferred from:

- **Zone motion active** → zone presence ON
- **Zone people count > 0** → zone presence ON
- **Zone people count == 0** → zone presence OFF
- **Global presence OFF** → all zones cleared (cascade)

### State Clearing Cascade

When global presence (SubID 0x0104) reports empty (state 0), the component
clears all zone and global states to ensure consistency:

- All zone presence, motion, people count, and posture → cleared
- Global people count → 0
- Sleep state → "none", sleep presence → off
- Heart rate, respiration rate, heart rate deviation → unknown (NAN)

## Auto-Calibration

Four button entities manage the radar's calibration:

- **`calibrate_edge`** — writes `EDGE_AUTO_ENABLE` (0x0150) = true. The radar
  scans the environment and sends back `EDGE_AUTO_SET` (0x0149) with the detected
  room boundary grid. The component stores the grid, applies it to the radar,
  and updates the card diagnostic sensor.

- **`calibrate_interference`** — writes `INTERFERENCE_AUTO_ENABLE` (0x0139) = true.
  The radar identifies interference sources and sends back
  `INTERFERENCE_AUTO_SET` (0x0125) with the detected interference grid.

- **`clear_edge`** — sends an empty (all-zero) grid to `EDGE_MAP` (0x0107),
  resetting room boundary detection to uncalibrated. Updates the card sensor.

- **`clear_interference`** — sends an empty grid to `INTERFERENCE_MAP` (0x0110),
  clearing all interference source markers. Updates the card sensor.

## Radar Firmware OTA (EXPERIMENTAL)

> **WARNING: This feature is untested and experimental. Incorrect use could
> brick the radar module, requiring physical access to recover. Use at your
> own risk. Do not use unless you understand the implications.**

The component can update the TI IWR6843AOP radar's firmware via XMODEM-1K
over the existing UART connection. This is the same mechanism the stock
Aqara firmware uses to apply radar updates from the cloud.

### Prerequisites

- A valid TI IWR6843 firmware binary (must start with `MSTR` header)
- The firmware file must be extracted from a stock Aqara flash dump
  (offset 0x433000, typically ~2.4MB)
- **There is no way to read the radar's current firmware back** — XMODEM is
  one-way. Back up your stock flash dump before experimenting.

### How It Works

Two-step process for safety:

1. **Stage**: Downloads firmware from a URL to the ESP32's flash storage.
   Validates the MSTR header before writing. Does not touch the radar.
2. **Flash**: Reads staged firmware from ESP32 flash and transfers it to the
   radar via XMODEM-1K. The radar enters bootloader mode, receives the
   firmware, validates it, and restarts.

### Configuration

```yaml
aqara_fp2:
  # URL to a TI IWR6843 firmware binary (MSTR format)
  # Place the file in HA's /config/www/ folder and reference it here:
  radar_firmware_url: "http://homeassistant.local:8123/local/radar_firmware.bin"

  radar_fw_stage:
    name: "Stage Radar Firmware"   # Downloads URL → ESP32 flash
  radar_ota:
    name: "Flash Radar Firmware"   # Transfers flash → radar via XMODEM
```

### Safety Checks

- Firmware must have valid `MSTR` magic header (TI format)
- Minimum size 1KB, maximum 4MB
- Flash is verified after write
- The OTA button refuses to proceed without valid staged firmware
- During XMODEM transfer, do **not** power off the device

### Extracting Firmware from Stock Dump

```python
# Extract radar firmware from a full flash dump
with open('stock_flash.bin', 'rb') as f:
    f.seek(0x433000)
    data = f.read(4 * 1024 * 1024)

# Trim trailing 0xFF (erased flash)
size = len(data)
while size > 0 and data[size-1] == 0xFF:
    size -= 1

with open('radar_firmware.bin', 'wb') as f:
    f.write(data[:size])
```

### Known Limitations

- **Untested** — the XMODEM transfer has been implemented from reverse
  engineering but has not been validated on real hardware
- **No firmware source** — Aqara distributes radar firmware via their cloud
  only. The only known source is extracting from a stock flash dump.
- **No rollback** — if the transfer fails partway, the radar may be in an
  indeterminate state. A power cycle should recover it to the previous
  firmware (the radar validates before applying), but this is unconfirmed.
- **No version check** — the component does not verify whether the firmware
  is newer or compatible with the current radar hardware revision.

## OPT3001 Light Sensor

The OPT3001 ambient light sensor shares the I2C bus with the accelerometer:

- **Address**: 0x44
- **Mode**: Continuous conversion, 800ms, automatic full-scale range
- **Config register**: 0xCE10
- **Read rate**: Every ~1 second (10th cycle of the 100ms accel task)
- **Publish**: From the ESPHome main loop (thread-safe via mutex). Only publishes
  on >5% change to avoid flooding HA.
- **Bus contention**: 5ms yield between accel and OPT3001 reads. Automatic
  `i2c_master_bus_reset()` on timeout/invalid-state errors.

## Configuration Reference

### Minimal Config

```yaml
uart:
  id: uart_bus
  tx_pin: GPIO19
  rx_pin: GPIO18
  baud_rate: 890000

external_components:
  - source: github://JameZUK/esphome_fp2_ng@main
    refresh: 120s
    components: [ aqara_fp2, aqara_fp2_accel ]

aqara_fp2_accel:
  id: fp2_accel
  light_sensor:
    name: "Ambient Light"

aqara_fp2:
  id: fp2
  accel: fp2_accel
  uart_id: uart_bus
  radar_reset_pin: GPIO13
  mounting_position: wall  # wall | left_corner | right_corner

  global_zone:
    presence:
      name: "Presence"
```

### Full Config with All Features

```yaml
aqara_fp2_accel:
  id: fp2_accel
  light_sensor:
    name: "Ambient Light"

aqara_fp2:
  id: fp2
  accel: fp2_accel
  uart_id: uart_bus
  radar_reset_pin: GPIO13
  mounting_position: left_corner
  left_right_reverse: false

  # Global sensors
  people_count:
    name: "Total People"
  radar_temperature:
    name: "Radar Temperature"
  radar_software_version:
    name: "Radar Version"
  fall_detection:
    name: "Fall Detected"

  # Sleep monitoring
  sleep_state:
    name: "Sleep State"
  sleep_presence:
    name: "Sleep Presence"
  heart_rate:
    name: "Heart Rate"
  respiration_rate:
    name: "Respiration Rate"
  heart_rate_deviation:
    name: "Heart Rate Deviation"

  # Target tracking
  target_tracking:
    name: "Targets"
  location_report_switch:
    name: "Report Targets"

  # Auto-calibration buttons
  calibrate_edge:
    name: "Calibrate Room Boundaries"
  calibrate_interference:
    name: "Calibrate Interference"

  # Radar firmware OTA (EXPERIMENTAL — see docs)
  # radar_firmware_url: "http://homeassistant.local:8123/local/radar_firmware.bin"
  # radar_fw_stage:
  #   name: "Stage Radar Firmware"
  # radar_ota:
  #   name: "Flash Radar Firmware"

  # Global presence/motion
  global_zone:
    presence_sensitivity: medium  # low | medium | high
    presence:
      name: "Global Presence"
    motion:
      name: "Global Motion"

  # Detection zones
  zones:
    - id: bed_zone
      grid: |-
        ..............
        ..............
        ..............
        ..XXXXXXXXXX..
        ..XXXXXXXXXX..
        ..XXXXXXXXXX..
        ..XXXXXXXXXX..
        ..............
        ..............
        ..............
        ..............
        ..............
        ..............
        ..............
      presence_sensitivity: high
      presence:
        name: "Bed Presence"
      motion:
        name: "Bed Motion"
      zone_people_count:
        name: "Bed People Count"
      posture:
        name: "Bed Posture"
```

### Required ESP32 Config

The FP2 uses a single-core ESP32 variant. This config block is mandatory:

```yaml
esp32:
  board: esp32-solo1
  framework:
    type: esp-idf
    sdkconfig_options:
      CONFIG_FREERTOS_UNICORE: "y"
      CONFIG_ESP_SYSTEM_SINGLE_CORE_MODE: "y"
    advanced:
      ignore_efuse_mac_crc: true
      ignore_efuse_custom_mac: true
```

### Map Config Service (for Lovelace Card)

To use the custom Lovelace card, add this API action:

```yaml
api:
  encryption:
    key: !secret api_encryption_key
  actions:
    - action: get_map_config
      supports_response: only
      then:
        - api.respond:
            data: !lambda |-
              id(fp2).json_get_map_data(root);
```

## Accelerometer Component

The `aqara_fp2_accel` component runs on a dedicated FreeRTOS task to avoid
blocking the main ESPHome loop with I2C operations.

- **I2C bus**: GPIO32 (SCL), GPIO33 (SDA), 400kHz
- **Accelerometer**: da218B at address 0x27
- **Light sensor**: OPT3001 at address 0x44 (same bus)
- **Sample rate**: 10 samples averaged, configurable interval (default 100ms)
- **Outputs**: Orientation enum (UP, DOWN, SIDE, etc.), tilt angle, vibration
  state, ambient light (lux)
- **Thread safety**: All public accessors use FreeRTOS mutexes. Sensor publish
  happens from the main loop, not the task.

The radar periodically queries the ESP32 for orientation and angle data via
reverse-read requests (SubIDs 0x0143, 0x0120). The accelerometer component
provides these values.
