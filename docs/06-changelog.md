# Changelog (esphome_fp2_ng)

Changes from the upstream [hansihe/esphome_fp2](https://github.com/hansihe/esphome_fp2).

## 2026-04-18 — Ghidra-verified SubID corrections, architecture clarification, XMODEM OTA hardening

### Critical corrections to prior claims

Several entries below this one contained claims that this session's Ghidra
work has now **falsified**. The corrections are authoritative — they're
derived from decompiling the specific binary that actually handles each case,
not from cross-firmware speculation.

- **Fall detection SubID is `0x0121`, not `0x0306`.** The 2026-04-15 entry
  claimed `FALL_DETECTION_RESULT = 0x0306` and that `0x0121 = angle sensor`.
  Both are wrong. Decompile of FW2 MSS (the *fall-detection* firmware —
  previously never examined) at `FUN_0001db70` shows the emission call
  `FUN_00011d3c(5, 0x121, 0, &state_byte)` with the adjacent debug string
  `"fall_detection:%d"`. Payload is uint8: `0=clear, 1=fall type A, 2=fall type B`.
  The stock ESP dispatch table `0x3ffb13b8` binds `0x0121` →
  `radar_fall_detection`. No MSS binary (FW1, FW2, FW3) emits `0x0306` at all.

- **Heart rate / respiration arrive on `SubID 0x0117` in mode 9, not floats in
  `0x0159`.** The 2026-04-15 SLEEP_DATA parser in `fp2_component.cpp` decoded
  12 bytes of `0x0159` as three IEEE-754 LE floats (`heartRate`, `breathRate`,
  `heartDev`). That matches TI's reference Vital-Signs debug strings
  (`"heartRate = %.0f ..."`), but those strings go to a separate debug-UART
  `printf`, **not** to the 0x55/0x01 protocol framer. Decompile of FW3
  (vitalsigns) `FUN_00006c84` at the 0x117 emission site shows:

  ```
  blob[0]    = 1 (fixed header byte)
  blob[1]    = track_id
  blob[2..3] = round(HR_bpm     * 100) as uint16 big-endian
  blob[4..5] = round(BR_per_min * 100) as uint16 big-endian
  blob[6..14]= zero padding
  ```

  Scaling constant `100.0f` verified in firmware data (`0x42C80000`).
  The 0x0159 blob is a parallel 12-byte per-byte metadata struct:
  `tid / count / motion / sleep_stage / posture / confidence / bed_state /
  conf2 / ...` — NOT floats. Old parser would have published garbage to the
  HR/BR sensors if sleep ever engaged. New parser in `fp2_component.cpp`
  reads 0x117 mode-aware and logs 0x159 bytes verbatim (MEDIUM confidence
  per-field naming). Heart-rate-deviation is NOT emitted by stock vitalsigns
  firmware — that sensor will stay unpopulated.

- **The three radar firmware images are NOT "the same firmware with different
  config"** (as the 2026-04-15 entry claimed). They have genuinely distinct
  MSS application binaries (type-0x04 RPRC sub-images within each MSTR
  container). Sizes: FW1 MSS = 228,544 B (Zone, mode 3), FW2 MSS = 142,720 B
  (Fall, mode 8), FW3 MSS = 210,560 B (Sleep, mode 9). Each has its own
  dedicated DSP image (types 0x0a/0x0b/0x0d). Only the 247,424 B type-0x0c
  sub-image (probably TI HSM/security runtime) is byte-identical across all
  three. Previous Ghidra analysis had only loaded FW1 MSS and FW3 MSS — FW2
  was never examined, which is why the `0x0121 → fall_detection` mapping
  remained undiscovered for so long.

- **Ghidra-binary naming**: `fp2_radar_mss.bin` ≈ FW1's RAM image (Zone).
  `fp2_radar_vitalsigns.bin` ≈ FW3's RAM image (Sleep). FW2's MSS (Fall) was
  extracted to `analysis/subimages/fp2_radar_mss_fw2.bin` this session and
  loaded fresh. The 2026-04-16 entry's "`fp2_radar_mss.bin` is misnamed — it
  is FW1's DSS content" is also wrong — sizes match FW1's combined RAM image
  (SBL + MSS + shared + DSP), not FW1's DSS alone.

### Code changes landed

- `radar ota: drop ACK gate, send trigger frame one-shot` (`0364734`) — the
  `0x0127` OTA trigger is fire-and-forget; stock firmware does not wait for a
  cluster ACK. Prior implementation waited, timed out, and aborted before the
  XMODEM 'C' handshake ever arrived. Probe test now confirms `'C'` within
  ~360 ms.
- `radar ota: flush UART after every xmodem block and EOT` (`4eea6be`) —
  `write_array()` only pushes into the ESPHome UART ring buffer; without
  `flush()` the bytes dribble out across many loop iterations and the radar's
  internal byte-gap timeout fires, triggering NAK/CAN. Adding `flush()` in
  `ota_send_current_block_()` and `ota_send_eot_()` removed the NAK storms.
- `radar ota: run xmodem transfer in a dedicated FreeRTOS task` (`c1db4ab`) —
  previously, the ACK→next-block round-trip ran inside the cooperative
  ESPHome main loop and got blocked by HA API / telemetry ticks. Moving the
  transfer into `fp2_ota_xfer` at `tskIDLE_PRIORITY+2` removes that shared
  scheduling contention.
- `debug: raw UART trace window on mode switch` (`40b39bb`) — 15 s trace of
  every TX/RX byte in hex when `set_operating_mode()` fires. Used this session
  to prove that `WORK_MODE=0x0116` writes DO cause the radar to ACK and soft-
  reboot into the new mode.
- `fall detection: fix SubID 0x0306 -> 0x0121` (`a703c9c`) — enum correction
  plus handler comment update.
- `vitals: decode HR/BR from SubID 0x0117 in sleep mode` (`dbc03ac`) —
  `handle_location_tracking_report_` is now mode-aware; in sleep mode it
  parses the 15-byte blob as vitals instead of target-tracking. SLEEP_DATA
  parser rewritten for per-byte metadata layout.

### Open questions (honest accounting of what we did NOT solve)

- **Sleep mode produces no events even after all the above fixes.** Aqara's
  product FAQ (https://www.aqara.com/eu/product/presence-sensor-fp2/faq/)
  says sleep monitoring requires "sleep space intelligent learning" as a
  mandatory setup step. Our driver never sends that command. The vitalsigns
  binary has `"learn complete!!!"` at `0x677c` and accumulator `FUN_00006390`
  that writes a learned threshold to flash via `FUN_0002cf28`, but the
  incoming SubID that *initiates* the learning phase is not locatable via
  static RE — no xrefs to the learning state functions, no stored pointers
  to the candidate addresses. Dynamic analysis (UART capture during a real
  Aqara-app sleep-setup flow) is the realistic next step.

- **Fall detection doesn't fire from "lying down" tests.** The fall ML state
  machine in FW2 MSS (`FUN_000022b8`) requires a ballistic upright→horizontal
  transition pattern plus low post-impact motion. It will not trigger from
  calm lying down, sitting, or sleeping. Real-fall validation still pending.

- **Heart-rate / respiration / heart-rate-deviation remain unobtainable in
  practice** until sleep-space-learning is solved — mode-9 with an
  un-calibrated zone keeps the presence-count at zero and the sleep task's
  emission gates never open. Once learning is solved, the 0x0117 decoder
  landed this session will populate HR/BR automatically.

- **Full radar OTA via XMODEM-1K remains slow and unstable.** The task-based
  transfer is stable for the first ~18–22 % of the 2,369 blocks, then the
  radar starts emitting CAN bytes and cancels. Root cause unknown — per-block
  turnaround of ~720 ms is radar-side, and stock Aqara's OTA is known (from
  user observation) to complete in under a minute. Speculation about shared
  QSPI flash, ROM-bootloader, or higher-baud modes was investigated and ruled
  out by Ghidra; the real mechanism of stock's fast OTA is still not known.
  For now, users who want to reflash a bricked radar image must persist
  through multiple cycles (each abort doesn't corrupt working images — the
  three active slots at `0x100000 / 0x2d2000 / 0x460000` are only overwritten
  after a successful EOT commit).

### MSTR sub-image extractor (new)

`analysis/subimages/` now contains each FW's type-0x04 RPRC body as a
separate `fwN_rprcM_type4.bin` file, stripped of the 32-byte RPRC header.
FW2's was imported into Ghidra for the fall-detection analysis this session.
The extraction was ad-hoc Python — not yet packaged as a script; future
work could extend `scripts/extract_radar_firmware.py` with a `--dump-subimages`
flag.

## 2026-04-16 — Three Radar Firmware Images Validated, SBL Safety Assessment

### RE Discoveries (Ghidra-validated)

- **Three distinct MSTR firmware images** in the `mcu_ota` partition (4MB),
  all CRC32-verified and structurally validated:
  - FW1 (MSS 65KB + DSS 683KB): Zone Detection — `Peoplecount.c`, fall area
  - FW2 (MSS 65KB + DSS 576KB): Fall Detection — DSP scoring, height estimation
  - FW3 (DSS 678KB, no SBL): Sleep/Vital Signs — heart rate, respiration, sleep stages
- **`fp2_radar_mss.bin` is misnamed** — it is FW1's DSS content, not the MSS boot loader.
  All Ghidra analysis was performed on the correct data despite the naming.
- **FW2's "deep learning"** is a small custom neural network (~9 layers, no ML framework).
  Contains `mylayer[].output_data`, `wide`, `high`, `outchannels` — likely a shallow
  fall/posture classifier. Not modern deep learning.
- **FW3 is standalone but has no SBL** — relies on the boot loader already on the radar.
  Built from TI mmWave Industrial Toolbox 4.11.0 Vital Signs demo.
- **All three share identical TI-RTOS runtime** (247KB, same SHA256) — same SDK build.
- **All three share Aqara UART protocol** (`communication.c`) — SubID handlers compatible.
- **String attribution verified**: "Deep learning" only in FW2, "Vital Signs" only in FW3,
  "Peoplecount" only in FW1. Cross-checked across all sections.
- **FW1's SBL has `SBL_WORK_MODE_OFFSET`** for multi-firmware switching. FW2's does not.
- **No direct mode-to-offset mapping table** found in stock ESP32 firmware.
  Mode selection uses SBL flash parameters.
- **OTA must use raw MSTR images** from mcu_ota, not extracted .bin files. CRC32 trailer
  (4 bytes) must be included. Extracted files have stripped headers and gap padding.
- **SBL safety assessment**: backup factory image fallback confirmed via string
  analysis. Image loaded to RAM and CRC-verified before execution. Authentication
  check exists (may block unsigned firmware). Partial write recovery and backup
  image isolation not yet verified — requires Ghidra decompilation of SBL.

## 2026-04-15 — Operating Mode Select, Fall Detection Fix, Scene Mode RE

### Documentation

- **4 operating modes documented** — Zone Detection (mode 3, wall), Fall Detection
  (mode 8, ceiling), Sleep Monitoring (mode 9, bedside), Fall + Positioning
  (mode 8 + tracking). All use same radar firmware with different config.
- **Two radar chirp configs** — Config A (10fps, wall) and Config B (6.67fps,
  ceiling/sleep). Selected on radar restart based on scene mode.
- **Mounting position requirements** — Fall detection needs ceiling, sleep needs
  bedside, zone detection works from wall/corner.
- **AI Learning** = simultaneous edge + interference auto-calibration.
- **Operating mode persists across reboots** — saved to ESP32 flash via
  ESPPreferences, restored on boot.

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
