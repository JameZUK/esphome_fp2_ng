# esphome_fp2_ng

Custom ESPHome firmware and Home Assistant card for the Aqara FP2 Presence Sensor, with per-zone people counting.

Forked from [hansihe/esphome_fp2](https://github.com/hansihe/esphome_fp2) with bug fixes, new features, and comprehensive documentation.

![Card screenshot](images/card_screenshot.png)

## What This Does

Replaces the stock ESP32 firmware on the Aqara FP2 with ESPHome, while keeping the radar firmware intact. This gives you **local-only** access to data that Aqara normally locks behind their cloud:

- **Per-zone people counting** — how many people are in each zone, not just binary presence
- **Global people count** — total detected persons
- **Real-time target tracking** — individual target positions, velocity, classification
- **Zone presence and motion** — per-zone binary sensors
- **Radar diagnostics** — temperature, firmware version

All data stays local. No Aqara cloud dependency.

## Changes from Upstream

See [docs/06-changelog.md](docs/06-changelog.md) for full details.

**Bug fixes:**
- Switch fall-through bug in report handler (malformed packets misinterpreted)
- Null pointer crashes when global zone sensors not configured
- ESP-IDF 5.5+ compilation error (`driver/i2c.h` removed)
- Wall mounting mode broken in Lovelace card
- PI constant typo in accelerometer
- Dead calibration code in accelerometer

**New features:**
- Global people count sensor (`people_count`)
- Per-zone people count sensors (`zone_people_count`)
- Zone motion handler (was commented out)
- I2C bus scan diagnostic (for light sensor discovery)

## Quick Start

### 1. Flash the FP2

See [FLASHING.md](FLASHING.md) for hardware disassembly, wiring, and backup instructions.

### 2. ESPHome Configuration

```yaml
esphome:
  name: fp2-bedroom

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

wifi:
  ssid: !secret wifi_ssid
  password: !secret wifi_password

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

ota:
  - platform: esphome
    password: !secret ota_password

logger:

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

aqara_fp2:
  id: fp2
  accel: fp2_accel
  uart_id: uart_bus
  radar_reset_pin: GPIO13
  mounting_position: left_corner  # wall | left_corner | right_corner

  people_count:
    name: "Total People"

  radar_temperature:
    name: "Radar Temperature"

  radar_software_version:
    name: "Radar Version"

  target_tracking:
    name: "Targets"

  location_report_switch:
    name: "Report Targets"

  global_zone:
    presence_sensitivity: medium
    presence:
      name: "Global Presence"
    motion:
      name: "Global Motion"

  zones:
    - id: bed_zone
      grid: |-
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
        ..............
      presence_sensitivity: high
      presence:
        name: "Bed Presence"
      motion:
        name: "Bed Motion"
      zone_people_count:
        name: "Bed People Count"

binary_sensor:
  - platform: gpio
    pin:
      number: GPIO36
      inverted: true
    name: "Device Button"

light:
  - platform: status_led
    name: "Status LED"
    pin:
      number: GPIO27
      inverted: true
```

### 3. Lovelace Card (Optional)

Install via HACS:
1. HACS → Frontend → Custom repositories
2. Add `https://github.com/JameZUK/esphome_fp2_ng`, category: Dashboard
3. Install and restart HA

Add to a dashboard:
```yaml
type: custom:aqara-fp2-card
entity_prefix: sensor.fp2_bedroom
title: Bedroom FP2
```

## Exposed Entities

### Global

| Config Key | Type | Description |
|------------|------|-------------|
| `people_count` | sensor | Total detected person count |
| `global_zone.presence` | binary_sensor | Overall presence |
| `global_zone.motion` | binary_sensor | Overall motion |
| `target_tracking` | text_sensor | Base64 target data (diagnostic) |
| `location_report_switch` | switch | Toggle location tracking |
| `radar_temperature` | sensor | Radar chip temperature (diagnostic) |
| `radar_software_version` | text_sensor | Radar firmware version (diagnostic) |

### Per Zone

| Config Key | Type | Description |
|------------|------|-------------|
| `presence` | binary_sensor | Zone occupancy |
| `motion` | binary_sensor | Zone motion |
| `zone_people_count` | sensor | Number of people in zone |

Zone people counting requires location tracking data. It is **automatically enabled** when any zone has a `zone_people_count` sensor configured.

## Zone Grid

Zones are defined as 14x14 ASCII grids. Each cell maps to a region of the detection area (~0.5m x 0.5m):

- `.` or space = inactive
- `X` or `x` = active detection cell

```yaml
grid: |-
  ..............
  ..XXXX........
  ..XXXX........
  ..XXXX........
  ..............
  ..............
  ..............
  ..............
  ..............
  ..............
  ..............
  ..............
  ..............
  ..............
```

## Documentation

Comprehensive technical documentation is in the [`docs/`](docs/) directory:

| Document | Contents |
|----------|----------|
| [01-hardware.md](docs/01-hardware.md) | Hardware reference — ESP32, radar, accelerometer, GPIO map |
| [02-uart-protocol.md](docs/02-uart-protocol.md) | Complete UART protocol spec — frames, opcodes, all SubIDs |
| [03-firmware.md](docs/03-firmware.md) | Firmware architecture — stock vs ESPHome, flash layout, data flow |
| [04-esphome-component.md](docs/04-esphome-component.md) | ESPHome component reference — entities, config, examples |
| [05-development.md](docs/05-development.md) | Development guide — building, adding attributes, known limitations |
| [06-changelog.md](docs/06-changelog.md) | All changes from upstream |

## Requirements

- ESPHome 2026.2+ (ESP-IDF framework)
- Home Assistant 2024.x+ (for card)
- HACS (recommended for card installation)

## Hardware

The FP2 contains:
- **ESP32-SOLO1** (single-core) — runs this firmware
- **TI IWR6843AOP** — 60GHz mmWave radar (firmware untouched)
- **MiraMEMS da218B** — accelerometer for orientation
- **Unknown IC** — light sensor (not yet implemented, [investigation in progress](docs/01-hardware.md))

Flashing requires soldering to UART test points. See [FLASHING.md](FLASHING.md).

## Credits

- [hansihe](https://github.com/hansihe) — original [esphome_fp2](https://github.com/hansihe/esphome_fp2) and [protocol reverse engineering](https://github.com/hansihe/AqaraPresenceSensorFP2ReverseEngineering)
- [niceboygithub](https://github.com/niceboygithub) — [hardware documentation](https://github.com/niceboygithub/AqaraPresenceSensorFP2)
- [simmsb](https://github.com/simmsb) — ESP-IDF 5.5+ I2C migration patch

## Disclaimer

This project is not affiliated with or endorsed by Aqara. Use at your own risk. Flashing custom firmware will void your warranty and may brick the device if done incorrectly. Always back up the stock firmware first.
