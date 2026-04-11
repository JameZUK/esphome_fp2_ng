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
| 0x0103 | MOTION_DETECT | UINT8 | R→E | Y | Global motion (0=motion, else=none) |
| 0x0104 | PRESENCE_DETECT | UINT8 | R→E | Y | Global presence (0=empty, else=occupied) |
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
| 0x0155 | PEOPLE_COUNTING | ? | R→E | N | People counting data |
| 0x0158 | PEOPLE_COUNT_REPORT_ENABLE | BOOL | E→R | Y | Enable count reports |
| 0x0162 | PEOPLE_NUMBER_ENABLE | BOOL | E→R | Y | Enable number tracking |
| 0x0163 | TARGET_TYPE_ENABLE | BOOL | E→R | Y | AI person detection |
| 0x0164 | REALTIME_PEOPLE | ? | R→E | N | Real-time people data |
| 0x0165 | ONTIME_PEOPLE_NUMBER | UINT32 | R→E | Y | Total person count |
| 0x0166 | REALTIME_COUNT | ? | R→E | N | Real-time count |

### Posture / Activity

| SubID | Name | Type | Dir | Status | Description |
|-------|------|------|-----|--------|-------------|
| 0x0154 | TARGET_POSTURE | ? | R→E | N | Target posture reports |
| 0x0157 | POSTURE_REPORT_ENABLE | BOOL | E→R | N | Enable posture reporting |
| 0x0172 | DWELL_TIME_ENABLE | UINT8 | E→R | P | Dwell tracking (disabled in init) |
| 0x0173 | WALK_DISTANCE_ENABLE | UINT8 | E→R | P | Walking distance (disabled in init) |
| 0x0174 | WALK_DISTANCE_ALL | ? | R→E | N | Walking distance data |

### Fall Detection

| SubID | Name | Type | Dir | Status | Description |
|-------|------|------|-----|--------|-------------|
| 0x0121 | FALL_DETECTION | ? | R→E | N | Fall detection event |
| 0x0123 | FALL_SENSITIVITY | UINT8 | E→R | P | Sensitivity (defined, commented in init) |
| 0x0134 | FALL_OVERTIME_PERIOD | ? | E→R | N | Fall overtime period |
| 0x0135 | FALL_OVERTIME_DETECTION | ? | R→E | N | Fall overtime detection |

### Sleep Monitoring

| SubID | Name | Type | Dir | Status | Description |
|-------|------|------|-----|--------|-------------|
| 0x0156 | SLEEP_REPORT_ENABLE | BOOL | E→R | N | Enable sleep reporting |
| 0x0159 | SLEEP_DATA | ? | R→E | N | Sleep tracking data |
| 0x0161 | SLEEP_STATE | ? | R→E | N | Current sleep state |
| 0x0167 | SLEEP_PRESENCE | ? | R→E | N | Sleep zone presence |
| 0x0168 | SLEEP_MOUNT_POSITION | UINT8 | E→R | P | Sleep mount pos (defined, unused) |
| 0x0169 | SLEEP_ZONE_SIZE | ? | E→R | P | Sleep zone size (defined, unused) |
| 0x0171 | SLEEP_IN_OUT | ? | R→E | N | Sleep zone entry/exit |
| 0x0176 | SLEEP_EVENT | ? | R→E | N | Sleep events |

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
3. ESP32 detects first heartbeat and begins initialization:
   a. Basic settings (monitor mode, L/R reverse, sensitivity, proximity)
   b. Feature enables (people count, target type, thermometer)
   c. Mounting position configuration
   d. Grid maps (interference, exit, edge)
   e. Zone maps with per-zone sensitivity
   f. Zone activation list
   g. Per-zone close/away enable
4. Each WRITE waits for ACK before proceeding (500ms timeout, 3 retries)
5. ESP32 publishes initial state (all zones = no presence/motion)
6. Steady state: radar sends reports, ESP32 ACKs and processes them

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
