# Aqara FP2 UART Protocol Specification

## Overview

The ESP32 and TI IWR6843AOP radar communicate over UART using a custom
Aqara-designed protocol. This is **not** TI's standard TLV frame format.

- **ESP32 TX pin**: GPIO18
- **ESP32 RX pin**: GPIO19
- **Radar NRESET**: GPIO13
- **Baud rate**: 890,000

## Frame Format

All frames follow this structure:

```
┌──────┬───────┬───────┬─────┬────────┬───────┬───────┬────────┬─────────┬───────┬───────┐
│ Sync │ Ver_H │ Ver_L │ Seq │ OpCode │ Len_H │ Len_L │ HCheck │ Payload │ CRC_L │ CRC_H │
│ 0x55 │ 0x00  │ 0x01  │     │        │       │       │        │  N bytes│       │       │
│ 1B   │ 1B    │ 1B    │ 1B  │ 1B     │ 1B    │ 1B    │ 1B     │  var    │ 1B    │ 1B    │
└──────┴───────┴───────┴─────┴────────┴───────┴───────┴────────┴─────────┴───────┴───────┘
  [0]    [1]     [2]    [3]    [4]      [5]     [6]     [7]      [8..N+7]  [N+8]  [N+9]
```

| Field | Size | Description |
|-------|------|-------------|
| Sync | 1 | Fixed `0x55` — frame start marker |
| Version | 2 | Fixed `0x0001` — protocol version |
| Sequence | 1 | Rolling frame counter (0-255) |
| OpCode | 1 | Operation type (see below) |
| Length | 2 | Payload length in bytes (big-endian) |
| Header Check | 1 | `~(sum(bytes[0:7]) - 1) & 0xFF` |
| Payload | N | Attribute data (see Payload Structure) |
| CRC-16 | 2 | CRC-16/MODBUS over entire frame excluding CRC bytes (little-endian) |

## Header Checksum

Computed over bytes 0-6 (Sync through Len_L):

```
header_check = (~(sum(frame[0:7]) - 1)) & 0xFF
```

## CRC-16/MODBUS

- Polynomial: 0xA001 (reflected)
- Initial value: 0xFFFF
- Computed over the entire frame from Sync through Payload (excluding CRC bytes)
- Stored in little-endian byte order

## OpCodes

| Value | Name | Direction | Description |
|-------|------|-----------|-------------|
| 0x01 | RESPONSE | Radar → ESP32 | Standard response to a read request, OR reverse-read request (SubID only, no data) |
| 0x02 | WRITE | ESP32 → Radar | Write attribute value |
| 0x03 | ACK | Both | Acknowledge receipt of a frame |
| 0x04 | READ | ESP32 → Radar | Standard read request, OR reverse-read response (values, replying to a 0x01 query) |
| 0x05 | REPORT | Radar → ESP32 | Asynchronous/unsolicited report |

### OpCode Dispatch Table (from RE)

Found at DROM address `3f40a6cc` in the stock firmware:

| OpCode | Name | Handler Address | Description |
|--------|------|-----------------|-------------|
| 0x01 | RESPONSE | `0x400DE904` | Response/reverse-read handler |
| 0x02 | WRITE | `0x400DE8F0` | Write handler |
| 0x03 | ACK | `0x400E1390` | ACK handler (largest) |
| 0x04 | READ | `0x400DE8DC` | Read/reverse-response handler |
| 0x05 | REPORT | `0x400DE8C8` | Report handler |

### ACK Behaviour

- All WRITE commands expect an ACK from the radar
- All REPORT frames (except heartbeat/`RADAR_SW_VERSION`) should be ACKed by the ESP32
- ACK and READ (reverse response) frames do not expect an ACK
- Timeout: 500ms per attempt, 3 retries before dropping

## Payload Structure

The payload starts with a 2-byte attribute ID (SubID), followed by a data type
byte and the value:

```
┌────────────┬──────────┬───────────┐
│ SubID (2B) │ DataType │ Data (N)  │
│ Big-endian │  (1B)    │           │
└────────────┴──────────┴───────────┘
```

### Data Types

| Value | Name | Size | Description |
|-------|------|------|-------------|
| 0x00 | UINT8 | 1 byte | Unsigned 8-bit integer |
| 0x01 | UINT16 | 2 bytes | Unsigned 16-bit integer (big-endian) |
| 0x02 | UINT32 | 4 bytes | Unsigned 32-bit integer (big-endian) |
| 0x03 | VOID | 0 bytes | No data (used in ACKs) |
| 0x04 | BOOL | 1 byte | Boolean (0 or 1) |
| 0x05 | STRING | variable | Null-terminated string |
| 0x06 | BLOB2 | 2 + N bytes | Length-prefixed binary: `[Len_H][Len_L][Data...]` |

### Reverse-Read Requests

When the radar sends a RESPONSE (0x01) with a payload of exactly 2 bytes
(SubID only, no data type or value), it is a **reverse-read request** — the
radar is asking the ESP32 to provide a value. The ESP32 replies with a READ
(0x04) frame containing the requested data.

Known reverse-read attributes:
- `0x0143` DEVICE_DIRECTION — ESP32 returns accelerometer orientation
- `0x0120` ANGLE_SENSOR_DATA — ESP32 returns accelerometer tilt angle

## Complete Attribute ID (SubID) Reference

Status: Y = implemented, P = partial (defined but not fully handled), N = not implemented

### System / Info

| SubID | Name | Type | Dir | Status | Description |
|-------|------|------|-----|--------|-------------|
| 0x0101 | HW_VERSION | ? | R→E | N | Hardware version |
| 0x0102 | RADAR_SW_VERSION | UINT8 | R→E | Y | Heartbeat / firmware version (~1Hz) |
| 0x0127 | OTA_SET_FLAG | ? | E→R | N | OTA update flag |
| 0x0201 | DEBUG_LOG | ? | R→E | N | Debug log output |

### Detection Reports

| SubID | Name | Type | Dir | Status | Description |
|-------|------|------|-----|--------|-------------|
| 0x0103 | MOTION_DETECT | UINT8 | R→E | Y | Global motion (even=active, odd=inactive) |
| 0x0104 | PRESENCE_DETECT | UINT8 | R→E | Y | Global presence (0=empty, non-zero=occupied) |
| 0x0115 | DETECT_ZONE_MOTION | UINT16 | R→E | Y | Zone motion `[zone_id, state]` |
| 0x0116 | WORK_MODE | UINT8 | Both | Y | Work mode report/config |
| 0x0142 | ZONE_PRESENCE | UINT16 | R→E | Y | Zone presence `[zone_id, state]` |

### Configuration

| SubID | Name | Type | Dir | Status | Description |
|-------|------|------|-----|--------|-------------|
| 0x0105 | MONITOR_MODE | UINT8 | E→R | Y | Detection direction (0=default, 1=L/R) |
| 0x0106 | CLOSING_SETTING | UINT8 | E→R | Y | Proximity (0=far, 1=med, 2=close) |
| 0x0111 | PRESENCE_DETECT_SENSITIVITY | UINT8 | E→R | Y | Sensitivity (1-3) |
| 0x0122 | LEFT_RIGHT_REVERSE | UINT8 | E→R | Y | L/R swap (0/1/2) |
| 0x0170 | WALL_CORNER_POS | UINT8 | E→R | Y | Mount: 1=wall, 2=left, 3=right |

### Grid Maps

| SubID | Name | Type | Dir | Status | Description |
|-------|------|------|-----|--------|-------------|
| 0x0107 | EDGE_MAP | BLOB2 | E→R | Y | Detection boundary (40B grid) |
| 0x0109 | ENTRY_EXIT_MAP | BLOB2 | E→R | Y | Enter/exit zones (40B grid) |
| 0x0110 | INTERFERENCE_MAP | BLOB2 | E→R | Y | Interference sources (40B grid) |
| 0x0114 | ZONE_MAP | BLOB2 | E→R | Y | Zone area `[ID(1) + grid(40)]` |
| 0x0151 | ZONE_SENSITIVITY | UINT16 | E→R | Y | Zone sensitivity `[ID<<8\|sens]` |
| 0x0152 | DETECT_ZONE_TYPE | ? | E→R | P | Zone type (defined, not exposed) |
| 0x0153 | ZONE_CLOSE_AWAY_ENABLE | UINT16 | E→R | Y | Zone close/away `[ID<<8\|en]` |
| 0x0202 | ZONE_ACTIVATION_LIST | BLOB2 | E→R | Y | 32-byte zone bitmap |
| 0x0203 | ZONE_CONFIG_SYNC | UINT8 | E→R | N | Zone config sync (see below) |

### Auto-Calibration

| SubID | Name | Type | Dir | Status | Description |
|-------|------|------|-----|--------|-------------|
| 0x0125 | INTERFERENCE_AUTO_SET | BLOB2 | R→E | Y | Auto-detected interference grid |
| 0x0139 | INTERFERENCE_AUTO_ENABLE | BOOL | E→R | Y | Start interference auto-detect |
| 0x0149 | EDGE_AUTO_SET | BLOB2 | R→E | Y | Auto-detected edge grid |
| 0x0150 | EDGE_AUTO_ENABLE | BOOL | E→R | Y | Start edge auto-detect |
| 0x0160 | DELETE_FALSE_TARGETS | ? | E→R | N | Delete false targets |

### Location Tracking

| SubID | Name | Type | Dir | Status | Description |
|-------|------|------|-----|--------|-------------|
| 0x0112 | LOCATION_REPORT_ENABLE | UINT8 | E→R | Y | Enable target streaming |
| 0x0117 | LOCATION_TRACKING_DATA | BLOB2 | R→E | Y | Target positions (10-20Hz) |
| 0x0120 | ANGLE_SENSOR_DATA | UINT8 | E→R | Y | Accel angle (reverse-read) |
| 0x0143 | DEVICE_DIRECTION | UINT8 | E→R | Y | Orientation (reverse-read) |

### People Counting

| SubID | Name | Type | Dir | Status | Description |
|-------|------|------|-----|--------|-------------|
| 0x0155 | PEOPLE_COUNTING | BLOB2(7B) | R→E | Y | Fall/people data: `[ZoneID:1][Count:2 BE][Ontime:4 BE]`. Non-zero ontime = fall. |
| 0x0158 | PEOPLE_COUNT_REPORT_ENABLE | BOOL | E→R | Y | **INVERTED SEMANTICS — see [Inverted-semantic attributes](#inverted-semantic-attributes) below. Send FALSE.** |
| 0x0162 | PEOPLE_NUMBER_ENABLE | BOOL | E→R | Y | **INVERTED SEMANTICS — send FALSE.** |
| 0x0163 | TARGET_TYPE_ENABLE | BOOL | E→R | Y | **INVERTED SEMANTICS — send FALSE.** |
| 0x0164 | REALTIME_PEOPLE | UINT32 | R→E | Y | Real-time total person count |
| 0x0165 | ONTIME_PEOPLE_NUMBER | UINT32 | R→E | Y | Periodic total person count |
| 0x0166 | REALTIME_COUNT | UINT32 | R→E | Y | Real-time count (logged) |
| **0x0175** | **ZONE_PEOPLE_NUMBER** | **UINT16** | **R→E** | **Y** | **`[zone_id<<8\|count]` — native per-zone people count from radar** |

### Posture / Activity

| SubID | Name | Type | Dir | Status | Description |
|-------|------|------|-----|--------|-------------|
| 0x0154 | TARGET_POSTURE | UINT16 | R→E | Y | `[zone_id<<8\|posture]` — per-zone posture (0=none,1=standing,2=sitting,3=lying) |
| 0x0157 | POSTURE_REPORT_ENABLE | BOOL | E→R | Y | **INVERTED SEMANTICS — send FALSE. See below.** |
| 0x0172 | DWELL_TIME_ENABLE | BOOL | E→R | P | Dwell tracking (disabled in init) |
| 0x0173 | WALK_DISTANCE_ENABLE | BOOL | E→R | P | Walking distance (disabled in init) |
| 0x0174 | WALK_DISTANCE_ALL | UINT32 | R→E | N | Walking distance (converted to float) |

### Fall Detection

Fall Detection mode selects FW2 at boot via `WORK_MODE=8` (SubID 0x0116).
FW2 is a distinct radar firmware image with a DSP-based fall-detection
algorithm.

| SubID | Name | Type | Dir | Status | Description |
|-------|------|------|-----|--------|-------------|
| 0x0121 | FALL_DETECTION_RESULT | UINT8 | R→E | Y | Fall event (0=clear, non-zero=fall). Emitted directly by FW2 at radar offset `0x0001db92`; stock ESP routes via RAM dispatch `0x3ffb13a0` → handler `0x400e5388`. |
| 0x0123 | FALL_SENSITIVITY | UINT8 | E→R | Y | Sensitivity, **clamped 0..3** by stock (`bltui a10, 0x4` in HandleCloud_Write_Dispatcher). Default 1 per upstream captured trace. |
| 0x0179 | FALL_DELAY_TIME | UINT16 BE | E→R | Y | Delay before confirming fall. FW1 MSS handler at `0x00026200` decodes u16, stores to config+0x290. Accepted by radar even though stock ESP's cloud-attr dispatcher never writes it. |
| 0x0180 | FALLDOWN_BLIND_ZONE | BLOB2(40B) | E→R | Y | Exclusion-zone grid. FW1 MSS handler at `0x0001da24` memcmp's 40 bytes at config+0x1c, memcpy's if changed. Same grid encoding as 0x0107/0x0109/0x0110. |
| 0x0124 | FALL_OVERTIME_REPORT_PERIOD | UINT8 | R→E | N | Ack/echo of current overtime period, radar-driven only. Cosmetic; driver ignores. |
| 0x0134 | ~~FALL_OVERTIME_PERIOD~~ | — | — | DEAD | **Not accepted by the radar.** FW1 MSS dispatcher routes 0x0134 into its unknown-SubID error path (verified: `FUN_00009718` → table[3]=0x01C1 → `0x9BFC: movw r2, #0x59f; b 0x9db0`). Never in stock's cloud-attr table. Driver's YAML option is a no-op. |
| 0x0135 | ~~FALL_OVERTIME_DETECTION~~ | — | — | DEAD | **Not a fall channel.** Stock's handler at `0x400e11ac` reads a u16 calibration/version value (format string `"13.25.85"`), nothing to do with falls. |
| 0x0136 | ~~FALL_OVERTIME_REPORT~~ | — | — | DEAD | Stock handler at `0x400df760` is a 3-byte stub. Not a fall event. |

**Fall Detection vs Fall + Positioning:** both modes select FW2; the
driver differentiates via `LOCATION_REPORT_ENABLE` (0x0112):

- *Fall Detection* → `LOCATION_REPORT_ENABLE=0` (suppresses the 0x0117
  target stream; fall events only)
- *Fall + Positioning* → `LOCATION_REPORT_ENABLE=1` (fall events plus
  live target positions)

The driver writes LOCATION_REPORT_ENABLE **before** WORK_MODE so the
value is captured atomically in the radar's flash-save.

**Superseded claim (for historical context):** earlier documentation
stated that 0x0121 was "not sent by the radar" and that fall events
came through 0x0155 PEOPLE_COUNTING. The 2026-04-23 audit against
`fp2_radar_mss_fw2.bin` proved this wrong — FW2 emits 0x0121 directly.
The `radar_fall_detection` comment at stock ESP `0x400e1e10` threw
older RE sessions off because it was mis-bound to the `left_right_reverse`
ack format string. See `docs/06-changelog.md` 2026-04-23 entry for the
full audit trail.

### Sleep Monitoring

Sleep Monitoring mode selects FW3 (vital signs) at boot via
`WORK_MODE=9` (SubID 0x0116). FW3 is built from TI's
`capon3d_vitalsigns` + GTrack reference pipeline — distinct from FW1
Zone Detection and FW2 Fall Detection.

**Mode activation sequence** (handled by `set_operating_mode`):

1. Pre-stage sleep zone params (all sent BEFORE WORK_MODE so the
   flash-save captures them atomically):
   - `SLEEP_MOUNT_POSITION` (0x0168) — U8, 0=centered
   - `SLEEP_ZONE_SIZE` (0x0169) — **U32** (not BLOB2), packed
     `(width_cm<<16) | length_cm`. FW3 cold-init clamps 0 or −1 to
     the default 0x00c800c8 (200×200 cm).
   - `SLEEP_BED_HEIGHT` (0x0177) — U16 cm, FW3 clamps to 40 if >150
   - `OVERHEAD_HEIGHT` (0x0178) — U16 cm, FW3 clamps to 220 if
     outside [150, 400]
2. `SLEEP_REPORT_ENABLE` = 1 (BOOL, dtype 0x04). Note: this is a
   no-op inside FW3 — the handler only logs — but the stock SBL
   firmware-selector also treats a persisted `byte[4]==1` as a
   secondary FW3 trigger, so it's written for compatibility.
3. `WORK_MODE` (0x0116) = 9 — triggers flash save + radar restart
   into FW3.

**Driver caveat: `emulate_stock: true` is required.** Our default
post-boot init burst (15+ WRITEs) disrupts FW3's DSS GTrack track
allocation. Stock ESP emits zero UART WRITEs on radar-ready (verified
via Ghidra of stock `fp2_aqara_fw1.bin`); the `emulate_stock` flag
skips the burst in Sleep mode so FW3's DSS can cleanly initialise.
See `docs/04-esphome-component.md` → *Operating Modes* → *Sleep
Monitoring*.

**GTrack velocity gate**: FW3's GTrack allocator requires centroid
radial velocity > 0.1 m/s to create a track. A person lying still
from outside the FOV won't be tracked. After WORK_MODE=9 the user
must walk into bed with deliberate motion. Once allocated the track
survives via `sleep2free=9000` frames (~7.5 min of stillness). Full
details in `docs/04-esphome-component.md`.

| SubID | Name | Type | Dir | Status | Description |
|-------|------|------|-----|--------|-------------|
| 0x0156 | SLEEP_REPORT_ENABLE | BOOL | E→R | Y | Written = 1 before WORK_MODE=9. **No-op inside FW3** — stock ESP's `radar_sw_version` gate at `0x400e4f28` also compares it to 1 for heartbeat-sync purposes. |
| 0x0159 | SLEEP_DATA | BLOB2(12B) | R→E | Y | **Primary vitals channel in FW3.** Direct u8 HR/BR — see layout below. |
| 0x0161 | SLEEP_STATE | UINT8 | R→E | Y | 0=awake, 1=light, 2=deep (no REM in FW3). |
| 0x0167 | SLEEP_PRESENCE | UINT8 | R→E | Y | Sleep-zone presence bit (binary_sensor). |
| 0x0168 | SLEEP_MOUNT_POSITION | UINT8 | E→R | Y | 0=centered; 1/2 shift bed region ±width/4 along X via radar FUN_0002b760. Sent before WORK_MODE=9 in Sleep mode. |
| 0x0169 | SLEEP_ZONE_SIZE | UINT32 | E→R | Y | Packed `(width_cm<<16) | length_cm`. Stock cloud handler `FUN_400e247c` writes as **U32** (dtype 0x02), not BLOB2. |
| 0x0171 | SLEEP_IN_OUT | UINT8 | R→E | Y | Sleep zone entry (1) / exit (0). Also updates `sleep_presence` on ON. |
| 0x0176 | SLEEP_EVENT | UINT8 | R→E | Y | Sleep event type (logged; no dedicated sensor). |
| 0x0177 | SLEEP_BED_HEIGHT | UINT16 | E→R | Y | Bed/mattress height (cm). Sent before WORK_MODE=9. |
| 0x0178 | OVERHEAD_HEIGHT | UINT16 | E→R | Y | Ceiling height (cm). Sent before WORK_MODE=9. |

**Secondary vitals channel — SubID 0x0117 in FW3:** FW3 can *also*
emit vitals on 0x0117 (15-byte payload: `[marker=1][state_byte]
[HR×100 u16 BE][BR×100 u16 BE][zeros reserved]`) but it's gated on
`config+0xb8 == 1` (LOCATION_REPORT_ENABLE=1) AND `target_count > 0`
AND a frame counter `+0x28 > 15` AND motion flags non-zero. For a
stationary sleeper the counter rarely climbs so 0x0117 almost never
fires. The driver logs these payloads for observability but does not
publish them to HR/BR sensors (to avoid racing 0x0159). The
`heartDev` / `breathDev` slots in this 15-byte payload are always
zero in the FW3 emit.

**Heart rate deviation** is not emitted by the radar on any SubID.
The driver derives it ESP-side as the rolling population standard
deviation over the last 10 valid HR readings from 0x0159 (~60 s at
the 6 s 0x0159 cadence). Reasonable HRV proxy; not clinical-grade.

### BLOB2 Byte Order

Typed protocol fields (UINT8, UINT16, UINT32) use **big-endian** byte order
in the UART payload. However, BLOB2 content is **raw bytes in the radar's
native little-endian** byte order (TI IWR6843 is ARM Cortex-R4, LE).

This was confirmed by decompiling `radar_sleep_data` (0x400e47c4) in the
stock firmware: it performs a raw `memcpy` of the BLOB2 content into 3 x
uint32 on the little-endian ESP32, with no byte swap.

### Sleep Data (SubID 0x0159) — Confirmed from FW3 vitals_hr_br_emitter

**12-byte BLOB2 payload. Direct u8 fields — NOT floats.** Verified by
decompiling `vitals_hr_br_emitter @ fp2_radar_vitalsigns.bin:0x00006c84`
and its emit call site at `0x0000701a`, with offsets populated from
ctx struct `+0x85..+0x90`.

| Offset | Field | Type | Unit | Description |
|--------|-------|------|------|-------------|
| 0 | `tid` | u8 | — | GTrack track ID (the allocated track emitting these vitals). |
| 1 | — | u8 | — | Reserved (0). |
| 2 | — | u8 | — | Reserved (0). |
| 3 | `HR_bpm` | **u8 direct** | bpm | Heart rate — no scaling. |
| 4 | — | u8 | — | Reserved (0). |
| 5 | `HR_conf` | u8 | 0–100 | Heart-rate confidence. Set to 100 when the frame's event byte (offset 11) is 0. |
| 6 | `BR_bpm` | **u8 direct** | br/min | Respiration rate — no scaling. |
| 7 | — | u8 | — | Reserved (0). |
| 8 | `BR_conf` | u8 | 0–100 | Respiration-rate confidence. Set to 100 when event==0. |
| 9 | `sleep_state_flag` | u8 | — | From global `DAT_000023f0[idx]`. Semantics overlap with 0x0161 SLEEP_STATE. |
| 10 | `sleep_stage` | u8 | — | From global `DAT_000023f4`. Related but distinct from sleep_state. |
| 11 | `event` | u8 | — | Event/param_8 byte; triggers the 0x0159 emission when state transitions occur. |

**Example frame** (hex payload bytes 5..16 after BLOB header):

```
0E 00 00 46 00 32 15 00 32 03 01 02
```

Decoded: `tid=14, HR=0x46=70 bpm, HR_conf=0x32=50, BR=0x15=21 br/min,
BR_conf=0x32=50, state=3, stage=1, event=2`.

Emit cadence is roughly every 6 seconds while a track is allocated.
`HR=0` / `BR=0` (with `conf=100`) is what FW3 sends during the FFT
warm-up window after track allocation — the driver treats zero as
"no valid reading yet" and publishes NaN.

**Superseded description (for historical context):** earlier
documentation described 0x0159 as "3–4× IEEE 754 float LE
(heartRate, breathRate, heartDev, breathingDev)". That was based on
debug-string grepping without reading the actual emit function. The
2026-04-22 decompile (see `docs/06-changelog.md`) proved it's direct
u8 fields. If you see raw payload bytes, they will NOT make sense as
IEEE-754 floats.

### Walking Distance (SubID 0x0174) — Confirmed

The UINT32 value is in **centimetres**. The stock firmware divides by the
constant 100.0 (confirmed at `Ram400d0ff4` = float 0x42C80000 = 100.0) to
produce metres.

### Previously Undocumented SubIDs (from handler table RE)

| SubID | Type | Dir | Description |
|-------|------|-----|-------------|
| 0x0113 | BOOL | R→E | Unknown (report only) |
| 0x0118 | any | R→E | Reserved (null handler) |
| 0x0119 | any | — | Reserved (null handler) |
| 0x0124 | any | — | Reserved (null handler) |
| 0x0126 | any | R→E | Reserved (null handler) |
| 0x0129 | any | E←R | Reverse-read request (unknown purpose) |
| 0x0130-0x0133 | any | — | Reserved (null handlers) |
| 0x0136-0x0137 | any | — | Reserved (null handlers) |
| 0x0140 | any | R→E | Report only (null handler) |

### Inverted-semantic attributes

Four `*_REPORT_ENABLE` BOOL attributes have **counter-intuitive semantics**:
setting them to `TRUE` does *not* enable reports — it switches the radar
into an alternate compact output format that **suppresses** the standard
`0x0103` (motion), `0x0104` (presence) and `0x0155` (people counting) streams.

| SubID | Name | Send |
|-------|------|------|
| `0x0158` | PEOPLE_COUNT_REPORT_ENABLE | **FALSE** |
| `0x0162` | PEOPLE_NUMBER_ENABLE | **FALSE** |
| `0x0163` | TARGET_TYPE_ENABLE | **FALSE** |
| `0x0157` | POSTURE_REPORT_ENABLE | **FALSE** |

Stock Aqara sends all four as FALSE during Zone Detection setup. Evidence
from the upstream RE repo (`hansihe/AqaraPresenceSensorFP2ReverseEngineering`,
`decoded_conf_zone.txt`) — a live packet capture of the Aqara app
configuring a fresh FP2:

```
Seq:11  WRT> people_counting_report_enable (0158) = FALSE
Seq:12  WRT> people_number_enable         (0162) = FALSE
Seq:13  WRT> target_type_enable           (0163) = FALSE
Seq:14  <REP motion_detection             (0103) = 0    ← streams BEGIN
Seq:16  <REP presence_detection           (0104) = 1
```

The `0x0103`/`0x0104` emissions start **immediately after the FALSE
writes**. When these were accidentally sent as `TRUE` in this driver
(Jan–Apr 2026), the radar would ACK the writes with no error and then
only emit the alternate `0x0117` target-tracking stream — Zone Detection
appeared to "work" superficially but `global_presence`, `global_motion`
and `people_count` stayed stuck at their initial off/0 values.

**Symptom to recognise:** Zone Detection silent on `global_presence` /
`global_motion` / `people_count` while `target_tracking` (0x0117) shows
data. Check init-burst values for these four BOOLs before anything else.

Likely internal meaning (speculation): these toggle between
"application report format" (all on = detailed per-target with type /
posture / count classification, for Aqara's Zigbee cluster) and "default
legacy UART format" (all off = simple 0x0103/0x0104/0x0155). The Aqara
app only ever uses the legacy UART channels.

Fixed in `d7e8c9a` (2026-04-23).

### Temperature

| SubID | Name | Type | Dir | Status | Description |
|-------|------|------|-----|--------|-------------|
| 0x0128 | TEMPERATURE | UINT16 | R→E | Y | Radar chip temperature |
| 0x0138 | THERMO_EN | BOOL | E→R | Y | Enable temperature reporting |
| 0x0141 | THERMO_DATA | UINT8 | E→R | Y | Temperature data mode |

*Dir: R→E = Radar to ESP32, E→R = ESP32 to Radar*

## Location Tracking Data (SubID 0x0117)

This is the richest data source, containing per-target tracking information.

### Payload Layout

```
[SubID 2B] [Type 0x06] [Len_H] [Len_L] [Count 1B] [Target0 14B] [Target1 14B] ...
```

- **Count** (byte 5 in payload): Number of tracked targets (uint8)
- **Targets**: Array of 14-byte target structures

### Target Structure (14 bytes)

| Offset | Field | Type | Range | Description |
|--------|-------|------|-------|-------------|
| 0 | Target ID | uint8 | 0-255 | Unique tracker ID |
| 1-2 | X Position | int16 BE | -400 to +400 | Horizontal position |
| 3-4 | Y Position | int16 BE | 0 to 800 | Distance from sensor |
| 5-6 | Z Position | int16 BE | — | Vertical position |
| 7-8 | Velocity | int16 BE | — | Movement speed |
| 9-10 | SNR | uint16 BE | — | Signal-to-noise ratio |
| 11 | Classifier | uint8 | — | Object classification (person vs other) |
| 12 | Posture | uint8 | — | Body posture/orientation |
| 13 | Active | uint8 | — | Activity state |

### Coordinate System

```
        Sensor
          ▼
    X=+400  X=-400
    ┌──────────────┐  Y = 0 (closest to sensor)
    │              │
    │   Detection  │
    │     Area     │
    │              │
    │              │
    └──────────────┘  Y = 800 (farthest from sensor)
```

- **X axis**: Parallel to sensor face. +400 = left edge, -400 = right edge
- **Y axis**: Perpendicular to sensor. 0 = closest, 800 = farthest
- **Physical scale**: Raw range 800 units ≈ 7 metres
- **Conversion**: `metres = raw_value / 800.0 * 7.0`

The coordinate system is the same regardless of mounting position (wall, left
corner, right corner). Mounting position affects the radar's internal
calibration, not the coordinate ranges.

## Startup Sequence

1. ESP32 resets radar via GPIO13 (NRESET low for 100ms, then high)
2. Radar begins sending heartbeat reports (`RADAR_SW_VERSION`, ~1 Hz)
3. **Wait for radar boot completion** — the radar sends heartbeats during its
   boot phase but does NOT ACK WRITE commands during this time. Init is
   deferred until a non-heartbeat frame arrives (TEMPERATURE 0x0128 or
   DEVICE_DIRECTION 0x0143), which signals the radar is fully ready.
4. ESP32 begins initialization sequence:
   a. Basic settings (monitor mode, L/R reverse, sensitivity, proximity)
   b. Feature enables (people count, target type, sleep, thermometer)
   c. Mounting position configuration
   d. Grid maps (interference, exit, edge)
   e. Zone maps with per-zone sensitivity
   f. Zone activation list (0x0202)
   g. Per-zone close/away enable
5. Each WRITE waits for ACK before proceeding (500ms timeout, 3 retries)
6. ESP32 publishes initial state (all zones = no presence/motion)
7. Steady state: radar sends reports, ESP32 ACKs and processes them

**Note**: The stock firmware also sends ZONE_CONFIG_SYNC (0x0203) on every
heartbeat after zone reconfiguration. Our component does not implement this
because zones are static (defined in YAML at compile time). See the 0x0203
section below for details.

## Grid Maps

All grids are 40 bytes encoding a 20-row x 16-column bitmap.

### Encoding

- Each row is 2 bytes, big-endian
- Bit 15 (MSB of first byte) = column 0 (leftmost)
- Bit 0 (LSB of second byte) = column 15 (rightmost)
- Row 0 is closest to the sensor

### User-Facing Grid (14x14)

The user configures zones using a 14x14 ASCII grid. This maps to the internal
20x16 grid with offsets:

- Row offset: 0 (input row 0 → internal row 0)
- Column offset: 2 (input col 0 → internal col 2)
- Active area occupies rows 0-13, columns 2-15

### Mapping Raw Coordinates to Grid

To determine which grid cell a target occupies:

```
grid_col = int((-raw_x + 400) / 800.0 * 14.0) + 2
grid_row = int(raw_y / 800.0 * 14.0)
```

Then check the zone's grid bitmap:
```
row_val = (grid[row * 2] << 8) | grid[row * 2 + 1]
is_in_zone = (row_val & (1 << (15 - col))) != 0
```

## Edge Grid Requirement

The radar does **not** send global presence/motion reports (0x0103, 0x0104)
unless an edge grid (0x0107) is configured. Without it, the radar tracks targets
(0x0117 data flows) but never triggers binary presence detection.

If no `edge_grid` is specified in the ESPHome config, a full-coverage default
is sent automatically during initialization. The default covers 14 active
rows (0-13) with columns 2-15 active (row value `0x3FFC`).

## Zone Configuration Sync (SubID 0x0203)

Reverse-engineered from the stock firmware. This SubID is **not required** for
basic operation but is documented here for future reference.

### Mechanism

The stock firmware sends `WRITE SubID=0x0203 UINT8 <value>` to the radar.
This is a zone configuration synchronization command triggered after runtime
zone changes.

### Call Chain (from RE)

```
radar_sw_version()        @ 0x400e4f28  (heartbeat handler, SubID 0x0102)
  └─ heartbeat_config_sync()  @ 0x400decd4  (sends WRITE 0x0203)
       └─ FUN_400e7e20()      @ 0x400e7e20  (frame builder, opcode=2=WRITE)
```

### When It's Sent

Called from the heartbeat handler on every heartbeat (~1Hz), but **only when**:
1. A "needs sync" flag (`Ram400d1480`) is set, AND
2. An internal zone config state flag is set

The flag is set by `FUN_400e5ebc()` (zone reconfiguration trigger), which:
- Increments a persistent NVS counter (config version)
- Triggers zone-related callbacks
- Resets ALL detection states (presence, motion) to 0xFF (unknown)
- Sets the heartbeat sync flag

### Payload

```
[SubID: 0x02 0x03] [DataType: 0x00 (UINT8)] [Value: 1 byte]
```

The value comes from offset 599 (0x257) of the main state struct at
`Ram400d0e2c`. Its exact meaning is unclear but is likely a zone
configuration version counter or active zone count.

### Handler Table

SubID 0x0203 has **no entry** in the 139-entry handler registration table at
`0x3FFB1158`. It is write-only (ESP32 → radar). SubID 0x0202
(ZONE_ACTIVATION_LIST) is also write-only with no handler entry.

### Why We Don't Implement It

Our ESPHome component uses static zones (defined in YAML at compile time).
The stock firmware sends 0x0203 after **runtime** zone reconfiguration
(e.g., via the Aqara app). Since our zones never change after init, the
one-time ZONE_ACTIVATION_LIST (0x0202) sent during init is sufficient.

If dynamic zone reconfiguration is ever added, this command should be sent
after each zone change, following the stock firmware pattern:
1. Send updated zone maps and activation list
2. Set the sync flag
3. heartbeat_config_sync fires on next heartbeat, sending 0x0203

## Handler Function Name Table (from RE)

Extracted from DROM at `3f409d00 - 3f40a6c0`. Each SubID has two handler
functions in the stock firmware:
- `radar_*` — processes data locally (HomeKit, sensor updates)
- `cloud_*` — relays data to Aqara cloud servers

| SubID | radar_ handler | cloud_ handler |
|-------|---------------|----------------|
| 0x0101 | `radar_hw_version` | — |
| 0x0102 | `radar_sw_version` | — |
| 0x0103 | `radar_motion_detection` | `cloud_motion_detection` |
| 0x0104 | `radar_presence_detection` | `cloud_presence_detection` |
| 0x0105 | — | `cloud_monitor_mode` |
| 0x0106 | — | `cloud_closing_setting` |
| 0x0107 | — | `cloud_edge_lable` |
| 0x0109 | — | `cloud_import_export_lable` |
| 0x0110 | — | `cloud_interference_source` |
| 0x0111 | — | `cloud_presence_detection_sensitivity` |
| 0x0112 | — | `cloud_location_report_enable` |
| 0x0114 | `radar_zone_map` | `cloud_detect_zone_setting` |
| 0x0115 | `radar_detect_zone_motion` | `cloud_detect_zone_motion` |
| 0x0116 | — | `cloud_work_mode` |
| 0x0117 | `radar_location_track_data` | `cloud_location_track_data` |
| 0x0120 | `radar_angle_sensor_data` | — |
| 0x0121 | `radar_fall_detection` | `cloud_fall_detection` |
| 0x0122 | — | `cloud_left_right_reverse` |
| 0x0123 | — | `cloud_fall_detection_sensitivity` |
| 0x0125 | `radar_interference_auto_setting` | — |
| 0x0128 | `radar_temperature` | `cloud_temperature` |
| 0x0134 | — | `cloud_fall_overtime_report_period` |
| 0x0135 | `radar_fall_overtime_detection` | `cloud_fall_overtime_detection` |
| 0x0138 | — | `cloud_thermodynamic_chart_enable` |
| 0x0139 | — | `cloud_interference_auto_enable` |
| 0x0141 | `radar_thermodynamic_chart_data` | `cloud_thermodynamic_chart_data` |
| 0x0142 | `radar_detect_zone_presence` | `cloud_detect_zone_presence` |
| 0x0143 | `radar_device_direction` | — |
| 0x0149 | `radar_edge_auto_setting` | — |
| 0x0150 | — | `cloud_edge_auto_enable` |
| 0x0151 | — | `cloud_detect_zone_sensitivity` |
| 0x0152 | — | `cloud_detect_zone_type` |
| 0x0153 | — | `cloud_detect_zone_close_away_enalbe` |
| 0x0154 | `radar_target_posture` | `cloud_target_posture` |
| 0x0155 | `radar_people_counting` | `cloud_people_counting` |
| 0x0156 | — | `cloud_sleep_report_enable` |
| 0x0157 | — | `cloud_posture_report_enable` |
| 0x0158 | — | `cloud_people_counting_report_enable` |
| 0x0159 | `radar_sleep_data` | `cloud_sleep_data` |
| 0x0160 | — | `cloud_delete_false_target` |
| 0x0161 | `radar_sleep_state` | `cloud_sleep_state` |
| 0x0162 | — | `cloud_people_number_enable` |
| 0x0163 | — | `cloud_target_type_enable` |
| 0x0164 | `radar_realtime_people_number` | `cloud_realtime_people_number` |
| 0x0165 | `radar_ontime_people_number` | `cloud_ontime_people_number` |
| 0x0166 | `radar_realtime_people_counting` | `cloud_realtime_people_counting` |
| 0x0167 | `radar_sleep_presence` | `cloud_sleep_presence` |
| 0x0168 | — | `cloud_sleep_zone_mount_position` |
| 0x0169 | — | `cloud_sleep_zone_size` |
| 0x0170 | — | `cloud_wall_corner_mount_position` |
| 0x0171 | `radar_sleep_inout_state` | `cloud_sleep_inout_state` |
| 0x0172 | — | `cloud_dwell_time_enable` |
| 0x0173 | — | `cloud_walking_distance_enable` |
| 0x0174 | `radar_walking_distance_all` | `cloud_walking_distance_all` |
| 0x0176 | `radar_sleep_event` | `cloud_sleep_event` |
| 0x0175 | `radar_zone_people_number` | `cloud_zone_people_number` |
| 0x0201 | `radar_debug_log_report` | — |

### Cloud-Only Attributes (from RE)

These attributes are configured/used exclusively by the Aqara cloud and have
no corresponding SubID in the radar UART protocol:

| Handler Name | Description |
|---|---|
| `cloud_sleep_bed_height` | Bed height configuration for sleep zone |
| `cloud_overhead_height` | Ceiling/overhead height configuration |
| `cloud_fall_delay_time` | Fall detection delay before alerting |
| `cloud_falldown_blind_zone` | Fall detection exclusion zone |
| `cloud_disturbance_enable` | Disturbance suppression toggle |
| `cloud_disturbance_time_setting` | Disturbance suppression timing |
| `cloud_interface_ctrl_report` | Interface control reporting |
| `cloud_reset_absent_status` | Reset absence state |

### Native Per-Zone People Counting (SubID 0x0175)

The radar natively supports per-zone person counting via SubID **0x0175**
(`radar_zone_people_number`). Payload format: **UINT16** where
`high byte = zone ID`, `low byte = people count in that zone`. This is the
same format as zone presence (0x0142) and target posture (0x0154).

**Status: Implemented.** The ESPHome component handles 0x0175 reports
directly. It also derives per-zone counts from target tracking data (0x0117)
as a fallback when location reporting is enabled.

### Handler Registration Table Structure (from RE)

The stock firmware's SubID dispatch uses a registration table at DRAM
`0x3FFB1158` with 139 entries, each 32 bytes:

```c
struct handler_entry {          // 32 bytes per entry
    uint16_t sub_id;            // +0x00: SubID
    uint8_t  data_type;         // +0x02: expected type (7 = any)
    uint8_t  padding;           // +0x03
    uint32_t user_data;         // +0x04: context passed to handler
    void    *handler_func;      // +0x08: radar handler function
    void    *cloud_func;        // +0x0C: cloud relay function
    uint8_t  reserved[8];       // +0x10 - +0x17
    uint8_t  allowed_opcodes[5];// +0x18 - +0x1C: which opcodes trigger this
};
```

The dispatcher at `FUN_400de81c` iterates all 139 entries, matching on
SubID and opcode. If the data type doesn't match (and isn't 7/any), the
frame is NACKed.

## Radar Firmware Version Compatibility

The stock ESP32 firmware (v4.66.85) contains a version compatibility table
for radar firmware versions. Found at DROM `3f40a6f4`:

```
3.1.85, 3.2.85, 3.3.85, ..., 3.23.85+
```

The `.85` suffix appears to be a hardware/product variant identifier shared
between ESP32 app firmware (4.x.85) and radar firmware (3.x.85).
