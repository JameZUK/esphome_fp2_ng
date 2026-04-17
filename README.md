# esphome_fp2_ng

> **TL;DR:** Full-featured ESPHome firmware for the Aqara FP2 presence sensor — unlocks per-zone people counting, sleep monitoring, fall detection, posture tracking, and real-time target visualisation. All local, no cloud.

The Aqara FP2 is a remarkable piece of hardware — an ESP32 paired with a TI IWR6843AOP 60GHz mmWave radar capable of tracking individual people through walls, monitoring heart rate and respiration during sleep, and detecting falls. Unfortunately, Aqara locks most of this behind HomeKit and their cloud.

This project replaces the stock ESP32 firmware with ESPHome, giving you local-only access to everything the radar can do: per-zone presence and motion detection, native people counting, sleep state monitoring with heart rate and respiration, fall detection with configurable overtime alerts, posture tracking (standing/sitting/lying), walking distance, and real-time target position streaming.

Every feature has been validated against both the stock ESP32 firmware and the TI radar firmware through comprehensive Ghidra reverse engineering. The complete UART protocol (50+ SubIDs) is documented, and a custom Lovelace card provides live radar visualisation with zone overlays and posture-aware target tracking.

Forked from [hansihe/esphome_fp2](https://github.com/hansihe/esphome_fp2).

![Radar Map](images/card_radar_map.png)

| | |
|---|---|
| ![Presence & Motion](images/card_presence_motion.png) | ![Sleep & Vitals](images/card_sleep_vitals.png) |
| ![Environment](images/card_environment.png) | ![Controls](images/card_controls.png) |
| ![Diagnostics](images/card_diagnostics.png) | |

## What This Does

Replaces the stock ESP32 firmware on the Aqara FP2 with ESPHome, while keeping the TI IWR6843AOP radar firmware intact. This gives you **local-only** access to data that Aqara normally locks behind HomeKit and their cloud:

- **Per-zone people counting** — native radar counting (SubID 0x0175), not position approximation
- **Global people count** — total detected persons
- **Sleep monitoring** — heart rate, respiration rate, heart rate deviation
- **Fall detection** — binary sensor for fall events
- **Posture tracking** — per-zone standing/sitting/lying detection
- **Walking distance** — cumulative distance sensor
- **Real-time target tracking** — individual target positions with configurable publish rate
- **Zone presence and motion** — per-zone binary sensors with presence inference
- **Factory-calibrated light sensor** — OPT3001 with per-unit NVS calibration
- **Accelerometer corrections** — factory calibration from NVS
- **Radar firmware OTA** — XMODEM-1K, verified (swap between FW1 / FW2 / FW3 wirelessly)
- **Auto-calibration** — room boundary and interference detection buttons

All data stays local. No Aqara cloud dependency.

## Changes from Upstream

See [docs/06-changelog.md](docs/06-changelog.md) for the original changelog.

**Bug fixes:**
- Switch fall-through in report handler (malformed packets misinterpreted)
- Null pointer crashes when global zone sensors not configured
- ESP-IDF 5.5+ compilation error (`driver/i2c.h` removed)
- Wall mounting mode broken in Lovelace card
- PI constant typo in accelerometer
- Presence detection state interpretation (0=empty, non-zero=occupied)
- Zone presence inference from motion/people count (0x0142 may not fire on boot)
- Stale sensor states cleared on presence-off cascade (sleep, people count, posture)
- Location reporting always enabled at radar level (people counting dependency)
- **All three grids (edge, interference, exit) always sent during init** — radar silently suppresses presence/motion reports if any grid is missing
- Double-init at 45 seconds — radar ACKs commands during boot but doesn't apply them

**New features:**
- Global people count sensor
- Per-zone native people counting (SubID 0x0175)
- Per-zone posture tracking (standing/sitting/lying)
- Fall detection via 0x0155 PEOPLE_COUNTING (Ghidra-confirmed source)
- Sleep monitoring: state, presence, heart rate, respiration, heart rate deviation
- Walking distance sensor
- Radar state diagnostic sensor (Booting/Init sent/Re-init/Ready/Presence)
- OPT3001 ambient light with factory NVS calibration
- Accelerometer factory NVS corrections
- Configurable target tracking publish rate (default 500ms)
- Radar firmware OTA via XMODEM-1K (endpoint verified via handshake probe; requires the canonical 16 MB flash layout — see [FLASHING.md](FLASHING.md))
- Data-bearing RESPONSE frame routing (fixes missing zone reports)
- Improved Lovelace card: throttled updates, posture-aware targets, auto-tracking

**Reverse engineering:**
- Complete UART protocol spec with 43+ SubIDs documented
- SubID 0x0203 zone config sync mechanism (fully traced)
- SubID 0x0155 PEOPLE_COUNTING blob structure (7 bytes: zone, count, ontime)
- Fall detection path: radar FUN_00015624 sends 0x0155, not 0x0121
- Radar OTA XMODEM-1K protocol (all parameters, function addresses)
- NVS lux calibration algorithm (two-range piecewise linear)
- Handler registration table (139 entries, 32 bytes each)
- Stock firmware init sequence and radar boot timing

## Quick Start

### 1. Flash the FP2

See [FLASHING.md](FLASHING.md) for hardware disassembly, wiring, and backup instructions.

> **Important:** Back up the full flash before flashing ESPHome. The stock flash
> contains factory calibration data AND the three TI radar firmware images that
> cannot be recovered otherwise. Use [scripts/extract_radar_firmware.py](scripts/)
> to pull the radar firmware out of your backup for later use.

### 2. ESPHome Configuration

```yaml
esphome:
  name: fp2-bedroom
  on_boot:
    priority: 600
    then:
      - delay: 2s

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
  power_save_mode: light

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
  - source: github://JameZUK/esphome_fp2_ng@v1.2.0
    refresh: 0s
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
  mounting_position: left_corner  # wall | left_corner | right_corner

  # Global sensors
  people_count:
    name: "Total People"
  fall_detection:
    name: "Fall Detected"
  fall_overtime:
    name: "Fall Overtime"
  fall_overtime_period: 30000ms     # Optional: prolonged fall timeout
  radar_temperature:
    name: "Radar Temperature"
  radar_software_version:
    name: "Radar Version"
  radar_state:
    name: "Radar State"

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
  # sleep_mount_position: 2         # Optional: sleep-specific mount (0-3)
  # sleep_zone_size: 1000           # Optional: sleep zone dimensions

  # Walking distance
  walking_distance:
    name: "Walking Distance"
  dwell_time_enable: true            # Optional: enable dwell time tracking

  # Target tracking (throttled to 2Hz by default)
  target_tracking:
    name: "Targets"
  target_tracking_interval: 500ms
  location_report_switch:
    name: "Report Targets"

  # Operating mode (all 4 modes, mutually exclusive)
  operating_mode:
    name: "Operating Mode"

  # Auto-calibration / maintenance
  calibrate_edge:
    name: "Calibrate Room Boundaries"
  calibrate_interference:
    name: "Calibrate Interference"
  clear_edge:
    name: "Clear Room Boundaries"
  clear_interference:
    name: "Clear Interference"
  delete_false_targets:
    name: "Delete False Targets"

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
        ..XXXXXXXX....
        ..XXXXXXXX....
        ..XXXXXXXX....
        ..XXXXXXXX....
        ..XXXXXXXX....
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
1. HACS > Frontend > Custom repositories
2. Add `https://github.com/JameZUK/esphome_fp2_ng`, category: Dashboard
3. Install and restart HA

Add to a dashboard:
```yaml
type: custom:aqara-fp2-card
entity_prefix: sensor.fp2_bedroom
title: Bedroom FP2
auto_tracking: true     # Auto-enable target tracking when card loads (default: false)
display_mode: full      # full | zoomed (default: full)
show_grid: true         # Show grid lines (default: true)
show_sensor_position: true  # Show sensor marker (default: true)
show_zone_labels: true  # Show zone labels (default: true)
```

## Exposed Entities

### Global

| Config Key | Type | Description |
|------------|------|-------------|
| `people_count` | sensor | Total detected person count |
| `fall_detection` | binary_sensor | Fall detected (via SubID 0x0306 from radar fall state machine) |
| `fall_overtime` | binary_sensor | Prolonged fall alert (person unable to get up) |
| `fall_overtime_period` | config (ms) | Time before overtime triggers (e.g. `30000ms`) |
| `fall_delay_time` | config (uint16) | Delay before confirming a fall event |
| `falldown_blind_zone` | config (grid) | 14x14 ASCII grid for fall detection exclusion zones |
| `radar_state` | text_sensor | Booting / Init sent / Re-init / Ready / Presence / Sleep |
| `operating_mode` | select | Operating mode: Zone Detection / Fall Detection / Sleep Monitoring / Fall + Positioning |
| `sleep_state` | text_sensor | none / awake / light / deep (requires sleep mode ON) |
| `sleep_presence` | binary_sensor | Sleep zone occupancy (requires sleep mode ON) |
| `heart_rate` | sensor (bpm) | Heart rate (requires sleep mode ON) |
| `respiration_rate` | sensor (br/min) | Respiration rate (requires sleep mode ON) |
| `heart_rate_deviation` | sensor (bpm) | Heart rate deviation (requires sleep mode ON) |
| `walking_distance` | sensor (m) | Cumulative walking distance |
| `dwell_time_enable` | config (bool) | Enable dwell time tracking (default: false) |
| `sleep_mount_position` | config (0-3) | Sleep-specific mounting position (0=ceiling, 1=wall-side, 2=wall-head, 3=wall-foot) |
| `sleep_zone_size` | config (uint32) | Sleep zone dimensions (`width_cm << 16 \| length_cm`) |
| `sleep_bed_height` | config (uint16) | Bed/mattress height in cm |
| `overhead_height` | config (uint16) | Ceiling height in cm |
| `global_zone.presence` | binary_sensor | Overall presence (0=empty, non-zero=occupied) |
| `global_zone.motion` | binary_sensor | Overall motion (even=active, odd=inactive) |
| `target_tracking` | text_sensor | Base64 target data (diagnostic) |
| `target_tracking_interval` | config | Publish rate, default 500ms |
| `location_report_switch` | switch | Show/hide target data in HA |
| `calibrate_edge` | button | Trigger room boundary auto-calibration |
| `calibrate_interference` | button | Trigger interference auto-calibration |
| `clear_edge` | button | Clear/reset room boundary calibration |
| `clear_interference` | button | Clear/reset interference calibration |
| `delete_false_targets` | button | Remove phantom/false targets from radar tracking |
| `radar_temperature` | sensor | Radar chip temperature (diagnostic) |
| `radar_software_version` | text_sensor | Radar firmware build number |

### Per Zone

| Config Key | Type | Description |
|------------|------|-------------|
| `presence` | binary_sensor | Zone occupancy (inferred from motion + people count) |
| `motion` | binary_sensor | Zone motion (even=active, odd=inactive) |
| `zone_people_count` | sensor | Native per-zone people count from radar |
| `posture` | text_sensor | none / standing / sitting / lying |

### Accelerometer / Light Sensor

| Config Key | Type | Description |
|------------|------|-------------|
| `light_sensor` | sensor (lux) | OPT3001 ambient light with factory NVS calibration |

### Radar Firmware OTA (EXPERIMENTAL)

> **WARNING: Untested. Incorrect use could brick the radar module.**
> See [docs/04-esphome-component.md](docs/04-esphome-component.md) for full details.

| Config Key | Type | Description |
|------------|------|-------------|
| `radar_firmware_url` | config | URL to TI IWR6843 firmware binary (MSTR format) |
| `radar_fw_stage` | button | Download firmware from URL to ESP32 flash |
| `radar_ota` | button | Flash staged firmware to radar via XMODEM-1K |

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

## Radar Init Behaviour

The radar requires **all three grids** to be sent during init for presence/motion reports (SubID 0x0103/0x0104) to work:

1. **Edge grid** (0x0107) — Room boundary
2. **Entry/exit grid** (0x0109) — Entry/exit zones
3. **Interference grid** (0x0110) — Interference sources

The component sends empty defaults for any grid not configured in YAML. You only need to configure `edge_grid` explicitly — the others default to empty (no interference, no entry/exit zones).

**Boot timing:** The radar ACKs commands sent during its ~38-second boot sequence but does not apply them. The component handles this with a double-init: commands are sent on first heartbeat, then re-sent at 45 seconds after boot.

**Presence delay after OTA:** After an OTA flash, the radar may take 2-5 minutes before it begins producing presence/motion reports. The `radar_state` sensor tracks progress: Booting → Init sent → Re-init → Ready → Presence. Target tracking (0x0117) starts immediately, but presence reports are delayed. This is normal radar behaviour — a full power cycle may produce faster results.

## Operating Modes

![Aqara App Modes](images/aqara_app_modes.jpeg)

The stock Aqara app presents four operating modes. Each mode uses a **different radar firmware image** stored in the ESP32's `mcu_ota` partition (4MB). The stock app flashes the appropriate firmware to the radar when switching modes via the "Install Now" button.

### Radar Firmware Images

The `mcu_ota` partition contains three TI IWR6843 MSTR firmware images. All images are **CRC32 verified** and structurally validated:

| Firmware | Offset | MSTR Size | Format | Source Path |
|----------|--------|-----------|--------|-------------|
| **FW1** | 0x000000 | MSS: 65KB (type 1) + DSS: 683KB (type 3) | SBL boot loader + people counting application | `../mss/` `../dss/Peoplecount.c` |
| **FW2** | 0x0C0000 | MSS: 65KB (type 1) + DSS: 576KB (type 3) | SBL boot loader + 3D fall detection application | `E:/workspace/update12/3d_people_counting_*/` |
| **FW3** | 0x1A0000 | DSS: 678KB (type 3) only | Standalone vital signs application (no SBL) | `C:/ti/mmwave_industrial_toolbox_4_11_0/Vital_Signs/` |

**Note:** The MSTR type 1 sections are SBL (Secondary Boot Loader) images. FW1's SBL contains `SBL_WORK_MODE_OFFSET` and `SBL_SLEEP_ENABLE_OFFSET` for multi-firmware switching. FW2's SBL does not. FW3 has no SBL — it relies on the SBL already present on the radar's QSPI flash.

All three DSS/application images share an **identical TI-RTOS/SYS-BIOS runtime** (247KB, same SHA256 hash) — confirming they were built against the same TI SDK.

### Capabilities by Firmware (Confirmed via String Analysis)

| Capability | FW1 | FW2 | FW3 |
|---|---|---|---|
| Aqara UART protocol (`communication.c`) | Yes | Yes | Yes |
| Presence detection | Yes | Yes | Yes |
| Zone / edge / interference configuration | Yes | Yes | Yes |
| Bed height / overhead height config | Yes | Yes | Yes |
| Basic people counting (`Peoplecount.c`) | Yes | --- | --- |
| Fall area reporting (`Fall area: %d`) | Yes | --- | --- |
| Background learning | Yes | --- | --- |
| Fall detection with shallow classifier | --- | Yes | --- |
| DSP-based fall scoring (`score: %f`) | --- | Yes | --- |
| Height estimation (`median_height`) | --- | Yes | --- |
| Fall recognition timing (`fallRecognize`) | --- | Yes | --- |
| 3D people counting | --- | Yes | Yes |
| Vital signs chain (`Running Vital Signs Chain`) | --- | --- | Yes |
| Heart rate / breath rate measurement | --- | --- | Yes |
| Sleep stage tracking (`sleep tid:%d`) | --- | --- | Yes |
| Capon3D beamforming + HWA acceleration | --- | --- | Yes |

**Note on FW2's "deep learning":** The string `"Deep learning layer L3 data"` is present and there is evidence of a small custom neural network (~9 layers, `mylayer[].output_data`, `wide`, `high`, `outchannels`). However, no standard ML framework (TensorFlow Lite, etc.) is used. This appears to be a shallow custom classifier for fall/posture recognition, not modern deep learning. The ~27KB of weight-like float data exists in the gap region beyond the MSTR boundary.

### Mode to Firmware Mapping

| App Mode | Firmware | Mounting | Persons | Description |
|----------|----------|----------|---------|-------------|
| **Zone Detection** | FW1 | Wall | Multi | Presence, motion, zones, basic people counting |
| **Fall Detection** | FW2 | Ceiling | Single | Fall detection with DSP scoring and height estimation |
| **Sleep Monitoring** | FW3 | Bedside | Single | Vital signs: heart rate, respiration, sleep state |
| **Fall + Positioning** | FW2 | Ceiling | Single | Fall detection with real-time target streaming |

**Note:** The firmware-to-mode mapping is inferred from capabilities matching the app mode descriptions. No direct mapping table was found in the stock ESP32 firmware. The selection mechanism uses `SBL_WORK_MODE_OFFSET` in the radar's boot loader.

### Current Implementation Status

The `operating_mode` select currently switches the radar's **scene mode** (3, 8, or 9) within the active firmware (FW1). This works correctly for Zone Detection. However:

- **Sleep Monitoring** and **advanced Fall Detection** require **different radar firmware images** (FW3 and FW2 respectively). The scene mode switch alone is insufficient — the vital signs DSP code does not exist in FW1, and FW2's fall detection algorithm is fundamentally different from FW1's.
- **Radar firmware OTA** (XMODEM-1K via SubID 0x0127) — endpoint verified on real hardware via the `radar_ota_probe` safe test. Full mode-switching OTA needs the 16 MB partition layout (see [FLASHING.md](FLASHING.md)).
- All three firmware images share the same Aqara UART protocol, so the ESPHome component's SubID handlers work with any of them.

### Radar OTA Setup (requires 16 MB partition layout)

Radar OTA needs a `mcu_ota` data partition on the ESP32 to stage the firmware
blob before streaming it to the radar over XMODEM-1K. This is only available
with the **16 MB partition layout** — see [FLASHING.md](FLASHING.md) for the
one-time serial flash.

Once on 16 MB, add to YAML:
```yaml
aqara_fp2:
  radar_firmware_url: https://raw.githubusercontent.com/JameZUK/esphome_fp2_ng/main/backup/radar_firmware.bin
  radar_fw_stage:
    name: "Stage Radar Firmware"
  radar_ota:
    name: "Trigger Radar OTA"
  radar_ota_probe:
    name: "Radar OTA Probe (safe test)"
```

Flow:
1. **Radar OTA Probe** — sends SubID 0x0127, waits for XMODEM 'C' handshake, immediately aborts with CAN. No flash writes. Safe to run anytime. Confirms the bootloader endpoint works.
2. **Stage Radar Firmware** — HTTPS downloads `radar_firmware.bin` (2.4 MB) to the `mcu_ota` partition. ~15–60 s.
3. **Trigger Radar OTA** — streams the staged firmware to the radar over XMODEM. ~3 minutes.

### What gets sent during radar OTA

The shipped `backup/radar_firmware.bin` is a byte-identical copy of the stock
Aqara `mcu_ota` partition content. It contains all three TI IWR6843 MSTR
container images, packed contiguously, with **no stripping or transformation**:

| Image | Offset      | Size    | MSTR version | Role |
|-------|-------------|---------|--------------|------|
| FW1   | `0x000000`  | 768 KB  | v1, 55 files | Zone Detection (default) |
| FW2   | `0x0C0000`  | 896 KB  | v1, 55 files | Fall Detection (DSP scoring) |
| FW3   | `0x1A0000`  | 708 KB  | v3, 55 files | Sleep Monitoring (vital signs) |

Total 2,424,849 bytes,
SHA256 `964d1fc24a78b1dcb1b8c18e3b4167ef475bb4b7cb87c68485909407ba31d2c2`.

When you trigger radar OTA, **the full 2.4 MB blob is streamed**, same as the
stock Aqara app. The radar's SBL handles the multi-image container internally
and selects which FW to run based on its boot parameter table.

### OTA Safety Notes

The SBL (Secondary Boot Loader) has a **backup factory image fallback** — if the
main application fails to load after OTA, the SBL attempts to boot a backup image.
This significantly reduces (but does not eliminate) the risk of bricking.

**Safety assessment (Ghidra-confirmed):**
- **OTA writes to staging area (QSPI 0x510000)**, separate from application and
  backup partitions. Application firmware is NOT modified during transfer.
- **Backup images at separate addresses** (0x040000 for zone/sleep, 0x100000 for
  fall). If OTA verification fails, SBL loads backup — confirmed in decompiled code.
- **SBL boot loader at 0x000000** is not in any application area — survives OTA.
- **Power loss during XMODEM** corrupts only the staging area — safe.
- **CAN abort (safe probe)** — the probe sends CAN x3 after receiving the 'C' handshake. No flash writes occur.

**Requirements:**
- Must use raw MSTR images from the `mcu_ota` partition (the shipped
  `backup/radar_firmware.bin` is correct).
- CRC32 trailer after MSTR data is included and verified by the SBL.
- FW3 has no SBL — it requires the SBL already on the radar's QSPI flash.

**Recommended test sequence:** Run `radar_ota_probe` first (zero-risk). If that
succeeds, stage and trigger a FW1-to-FW1 OTA (same firmware) to validate the
full flow before attempting FW2/FW3. See [07-firmware-analysis.md](docs/07-firmware-analysis.md)
for the full SBL decompilation and QSPI flash map.

### AI Learning

The stock app's "AI Learning" feature triggers both edge and interference auto-calibration simultaneously while the room is empty. Use the `calibrate_edge` and `calibrate_interference` buttons together to replicate this — ensure the room is clear first.

## Known Limitations

- **Sleep monitoring requires radar firmware swap** — The vital signs processing
  (heart rate, respiration) runs on FW3, a completely separate radar firmware
  from the default FW1. The vital signs DSP code does not exist in FW1 — scene
  mode 9 alone is insufficient. Radar OTA (XMODEM-1K) is implemented and the
  endpoint is verified; requires the 16 MB partition layout (see [FLASHING.md](FLASHING.md)).

- **Advanced fall detection requires radar firmware swap** — FW2 has a DSP-based
  fall detection algorithm with scoring and height estimation, distinct from FW1's
  basic fall algorithm. FW1's fall detection (SubID 0x0306) may only work from
  ceiling mounting.

- **Sleep state** — Only values 0 (awake), 1 (light sleep), 2 (deep sleep)
  exist in the vital signs firmware. No REM detection.

- **Presence delay after OTA** — The radar may take 2-5 minutes after an OTA
  flash before it starts producing presence reports. Target tracking works
  immediately. Use the `radar_state` sensor to monitor boot progress.

- **Extracted binary naming** — `fp2_radar_mss.bin` is misnamed; it is actually
  FW1's DSS (application) content, not the MSS boot loader. The Ghidra analysis
  was performed on the correct data despite the naming.

## Factory Calibration

The component automatically reads per-unit calibration data from the factory NVS partition (`fctry`) if it was preserved during flashing:

- **Lux calibration**: two-range piecewise linear correction for the OPT3001
- **Accelerometer corrections**: per-axis offset compensation

This data is written during Aqara manufacturing and is unique to each unit. Back up your full flash before flashing ESPHome to preserve it.

## Documentation

Comprehensive technical documentation is in the [`docs/`](docs/) directory:

| Document | Contents |
|----------|----------|
| [01-hardware.md](docs/01-hardware.md) | Hardware reference — ESP32, radar, accelerometer, light sensor, GPIO map |
| [02-uart-protocol.md](docs/02-uart-protocol.md) | Complete UART protocol spec — frames, opcodes, 43+ SubIDs, zone sync |
| [03-firmware.md](docs/03-firmware.md) | Firmware architecture — stock vs ESPHome, flash layout, data flow |
| [04-esphome-component.md](docs/04-esphome-component.md) | ESPHome component reference — all entities, config, radar OTA, examples |
| [05-development.md](docs/05-development.md) | Development guide — building, adding attributes, known limitations |
| [06-changelog.md](docs/06-changelog.md) | All changes from upstream |
| [07-firmware-analysis.md](docs/07-firmware-analysis.md) | Ghidra RE workflow — OTA protocol, NVS calibration, handler tables |

## Requirements

- ESPHome 2024.6+ (ESP-IDF framework)
- Home Assistant 2024.x+ (for card)
- HACS (recommended for card installation)

## Hardware

The FP2 contains:
- **ESP32-SOLO1** (single-core) — runs this firmware
- **TI IWR6843AOP** — 60GHz mmWave radar (firmware untouched by default)
- **MiraMEMS da218B** — accelerometer for orientation (I2C 0x27)
- **TI OPT3001** — ambient light sensor (I2C 0x44), factory-calibrated via NVS

Flashing requires soldering to UART test points. See [FLASHING.md](FLASHING.md).

## Credits

A massive thank you to [Hans Elias J. (hansihe)](https://github.com/hansihe) for the original [esphome_fp2](https://github.com/hansihe/esphome_fp2) component and the extraordinary [protocol reverse engineering](https://github.com/hansihe/AqaraPresenceSensorFP2ReverseEngineering) that made all of this possible. The UART protocol analysis, frame decoding, and initial SubID discovery were well outside my own skill set, and this project simply would not exist without that foundational work.

- [niceboygithub](https://github.com/niceboygithub) — [hardware documentation](https://github.com/niceboygithub/AqaraPresenceSensorFP2)
- [simmsb](https://github.com/simmsb) — ESP-IDF 5.5+ I2C migration patch

## Disclaimer

This project is not affiliated with or endorsed by Aqara, Texas Instruments, or Apple. Use at your own risk. Flashing custom firmware will void your warranty and may brick the device if done incorrectly. Always back up the stock firmware first.
