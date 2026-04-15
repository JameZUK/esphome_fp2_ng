# Changelog (esphome_fp2_ng)

Changes from the upstream [hansihe/esphome_fp2](https://github.com/hansihe/esphome_fp2).

## 2026-04-15 — Fall Detection Fix, Sleep Mode Switch, Scene Mode RE

### Critical Fixes

- **Fall detection uses SubID 0x0306, not 0x0155 ontime** — The ontime field
  in 0x0155 is cumulative dwell time (0.15 * frame_count), non-zero for ANY
  presence. The actual fall signal is SubID 0x0306 (UINT8: 0/1) from the
  radar's fall state machine at offset +0x587/+0x589.

- **SubID 0x0121 is angle sensor revision, not fall detection** — Dispatch
  table confirms 0x0121 → `radar_angle_sensor_rev`. Fall handler is 0x0122
  (stock ESP32), actual signal is 0x0306 (radar).

### New Features

- **Sleep mode switch** — Toggle between presence detection (scene mode 3)
  and vital signs monitoring (scene mode 9). Uses WORK_MODE (0x0116) WRITE
  to trigger flash save + radar self-restart. Init skipped in sleep mode
  to prevent 0x01xx WRITEs from triggering mode 3.

### RE Discoveries

- **Scene mode state machine** (FUN_00013d9c): Mode 3/5 entry clears
  sleep_report_enable. Mode changes write to flash and self-restart.
- **FUN_000257d4** (scene mode reporter): Checks sleep_report_enable on boot,
  overrides scene_mode from 3 to 9 if set.
- **FUN_00025dfc** (SubID-to-scene mapper): 0x01xx + opcode!=1 → mode 3.
  Our ACKs (opcode 3) for 0x0117 were resetting to mode 3 and clearing sleep.
- **SLEEP_REPORT_ENABLE writes to RAM only** — flash write requires
  FUN_00013d9c (triggered by WORK_MODE SubID 0x0116).
- **Sleep zone params (0x0168/0x0169/0x0177/0x0178) are RAM-only** in the
  radar, lost on every reboot. Sent during normal init.
- **Vital signs (0x0159) come from DSS** (C674x DSP), not MSS. Only
  forwarded when radar is in scene mode 9.
- **Complete SubID sender enumeration**: All 30 callers of FUN_00019590
  mapped, including 0x0305 and 0x0306 in the 0x03xx range.

## 2026-04-14 — Presence Detection Fix, Fall Detection, Complete Feature Audit

### Critical Fixes

- **All three grids sent during init**: The radar requires edge (0x0107),
  interference (0x0110), and exit (0x0109) grids ALL sent during init or it
  silently suppresses presence/motion reports. The component now sends empty
  defaults when grids are not configured in YAML.

- **Double-init at 45 seconds**: The radar ACKs commands during its ~38-second
  boot sequence but does not apply them. Init is now sent twice: on first
  heartbeat (~3s) and again at 45 seconds. Both inits are identical.

- **Presence delay after OTA**: After OTA flash, the radar takes 2-5 minutes
  before producing presence/motion reports (0x0103/0x0104). Target tracking
  (0x0117) starts immediately. This is normal radar behaviour.

### New Features

- **Fall detection via 0x0155 PEOPLE_COUNTING**: Confirmed via Ghidra RE of
  both radar firmware (`FUN_00015624` sends 0x0155 with "Fall area: %d, %d"
  debug string) and stock ESP32 firmware (`radar_people_counting` at
  `0x400e04c4`). BLOB2 payload is 7 bytes:
  `[ZoneID:1] [PeopleCount:2 BE] [OntimeValue:4 BE]`.
  Non-zero ontime indicates a fall event. SubID 0x0121 is NOT sent by the radar.

- **Fall overtime detection (0x0135)**: Binary sensor for prolonged falls
  (person unable to get up). Triggers when fall persists beyond configured timeout.

- **Fall overtime period (0x0134)**: Configurable timeout in milliseconds.

- **Fall delay time (0x0179)**: Delay before confirming a fall event. Discovered
  via Ghidra handler table RE — `"fall_delay_time:%d"` debug string in radar firmware.

- **Falldown blind zone (0x0180)**: 40-byte grid (same 14x14 ASCII format) for
  fall detection exclusion zones. Extensively referenced in radar firmware with
  flash storage, validation, and deletion functions.

- **Sleep bed height (0x0177)**: Bed/mattress height config for sleep monitoring.
  Discovered via Ghidra — `"sleep_bed_height:%d"` in radar firmware.

- **Overhead/ceiling height (0x0178)**: Ceiling height config for spatial
  calibration. Handler `FUN_000265f4` stores at offset +0xbb0 in radar config.

- **Delete false targets (0x0160)**: Button to remove phantom/false targets
  from radar tracking.

- **Dwell time enable (0x0172)**: Now configurable (was hardcoded off).

- **Sleep mount position (0x0168)** and **sleep zone size (0x0169)**: Optional
  sleep monitoring configuration parameters.

- **Radar state diagnostic sensor**: Text sensor tracking boot sequence:
  Booting → Init sent → Re-init → Ready → Presence.

- **HW version capture (0x0101)**: Reads radar hardware version and appends
  to software version string. Note: radar does not respond to READ requests
  for this SubID in practice.

- **Radar debug log (0x0201)**: Captures debug strings from radar MCU when
  `debug_mode: true`. Radar's internal debug flag appears off by default;
  no known SubID to enable it.

### Card Improvements

- **Update throttling**: 250ms throttle on hass updates (was unthrottled)
- **Posture-aware targets**: S=standing, s=sitting, L=lying with glow effects
- **Auto-tracking**: `auto_tracking: true` enables target reporting when card loads,
  disables when navigating away
- **Info overlay**: Status bar overlaid on canvas bottom instead of below it
- **Removed console.log spam**: ~30 debug logs per update cycle removed

### RE Discoveries

- **0x0155 PEOPLE_COUNTING blob structure**: 7 bytes decoded via Ghidra analysis
  of both radar (`FUN_00015624`) and stock ESP32 (`0x400e04c4`) firmware
- **Fall detection path**: Radar's fall algorithm sends 0x0155, NOT 0x0121.
  Stock firmware derived 0x0121 from 0x0155 data.
- **Handler table SubIDs 0x0177-0x0180**: All four confirmed in both firmwares
  via Ghidra. Handler functions, debug strings, and cloud relay functions found.
- **Radar debug flag**: 0x0201 send function gated by flag at offset +0x587 in
  radar config struct. Flag is zero (off) by default.
- **HW_VERSION behaviour**: Radar has send function `FUN_00026a94` with
  `"Hardware_version:%d"` string but does not respond to READ requests.

## 2026-04-12 — OPT3001 Light Sensor, Auto-Calibration, I2C Fixes

### New Features

- **OPT3001 ambient light sensor**: Identified as TI OPT3001 at I2C address
  0x44 via I2C bus scan diagnostic. Driver reads lux every ~1s in continuous
  mode (800ms conversion, auto-range). Publishes on >5% change.
  Config: `light_sensor: name: "Ambient Light"` under `aqara_fp2_accel`.

- **Auto-calibration buttons**: Added `calibrate_edge` and
  `calibrate_interference` button entities. Pressing triggers
  `EDGE_AUTO_ENABLE` / `INTERFERENCE_AUTO_ENABLE` on the radar. Handlers
  receive the auto-detected grids, store them, apply to radar, and update
  card diagnostic sensors.

- **Complete SubID enum**: Added all 22 previously missing SubIDs from the
  protocol RE (43 total). Organized by category: system, detection, config,
  grids, auto-calibration, tracking, counting, posture, fall detection,
  sleep monitoring, temperature.

- **I2C bus scan diagnostic**: Scans all I2C addresses during `dump_config()`
  and logs found devices with candidate identifications. Runs after API
  connects so results appear in ESPHome logs (not just serial).

### Bug Fixes

- **I2C bus contention**: Added 5ms yield between accelerometer and OPT3001
  reads. Added `i2c_master_bus_reset()` on `INVALID_STATE`/`TIMEOUT` errors
  to recover the bus. Suppressed noisy warning logs for recoverable errors.

- **I2C bus scan timing**: Moved scan from `setup()` to `dump_config()` so
  results appear in API logs. Accel FreeRTOS task is suspended during scan
  to prevent contention.

### Documentation

- **Firmware analysis guide** (07-firmware-analysis.md): Complete RE workflow
  using Ghidra + bethington/ghidra-mcp + dynacylabs ESP32 flash loader.

- **Full protocol reference**: Updated 02-uart-protocol.md with all 43 known
  SubIDs and implementation status (Y/P/N).

### RE Discoveries (from stock firmware analysis)

- **Light sensor IC**: TI OPT3001 at I2C 0x44. Stock firmware source file:
  `apps/user/hal/acceleration_ambinent_light.c`. Uses NVS-stored calibration
  coefficients (lux_low_k/b, lux_high_k/b).

- **Radar OTA mechanism**: Uses XMODEM protocol over existing UART, NOT SOP
  pin toggling. Firmware stored in `mcu_ota` partition (4MB, sub_type 0xFE).
  SubID 0x0127 triggers bootloader mode. Source files: `radar_ota.c`,
  `xmodem.c`. Not yet implemented in ESPHome.

- **Full partition table**: nvs, otadata, phy_init, aqara_fw1 (2MB),
  aqara_fw2 (2MB), test (76KB), mcu_ota (4MB), fctry (24KB).

## 2026-04-11 — Initial Fork

### Bug Fixes

- **Switch fall-through in `handle_report_()`**: Every case in the report
  handler's switch statement used a pattern where `break` was inside an `if`
  block. If the payload size check failed, execution fell through to the next
  case, causing malformed packets to be misinterpreted as different report types.
  Fixed by moving `break` outside the `if` blocks for all affected cases:
  `RADAR_SW_VERSION`, `WORK_MODE`, `DETECT_ZONE_MOTION`, `MOTION_DETECT`,
  `PRESENCE_DETECT`, `ZONE_PRESENCE`.

- **Null pointer dereferences**: `global_motion_sensor_` and
  `global_presence_sensor_` were dereferenced without null checks in
  `handle_report_()`. If `global_zone` was configured without `motion` or
  `presence` sensors, these would crash. Added null checks.

- **PI constant typo**: `aqara_fp2_accel.h` defined PI as `3.141614159265`
  (extra "61" inserted). Corrected to `3.14159265358979`.

- **Dead accelerometer calibration**: `calculate_calibration()` computed
  correction values then immediately zeroed them out and returned, with the
  actual return/log statements unreachable. Removed the zeroing-out code to
  restore the intended behaviour.

- **ESP-IDF 5.5+ compilation error** (upstream issue #2): Migrated from the
  removed `driver/i2c.h` legacy API to `driver/i2c_master.h`. Used
  `i2c_master_transmit_receive()` for register reads (not `i2c_master_receive()`
  which would skip the register address write — a bug in the community-proposed
  fix).

- **Wall mounting mode card** (upstream issue #3): The Lovelace card had a
  placeholder coordinate conversion for wall mode (`target.x * 0.01`). The raw
  coordinate space is identical for all mounting positions, so applied the same
  proven conversion formula used for corner modes.

### New Features

- **Global people count sensor**: The `ONTIME_PEOPLE_NUMBER` report (SubID
  0x0165) was received and logged but never exposed as an entity. Added a
  `people_count` sensor option.

- **Per-zone people count sensors** (upstream issue #1): Added `zone_people_count`
  sensor option per zone. Works by cross-referencing target positions from the
  location tracking data (SubID 0x0117) against each zone's grid bitmap.
  Location reporting is automatically enabled when any zone has this sensor
  configured.

### Re-enabled

- **Zone motion handler**: The zone motion publish logic in `DETECT_ZONE_MOTION`
  was commented out, so per-zone motion binary sensors never updated. Uncommented.

### Cleanup

- Removed commented-out `add_zone()` dead code
- Removed remaining unreachable code in accelerometer calibration
