# Development Guide

## Project Structure

```
esphome_fp2_ng/
├── components/
│   ├── aqara_fp2/
│   │   ├── __init__.py           # ESPHome config schema and codegen
│   │   ├── fp2_component.h       # C++ header (types, enums, class)
│   │   └── fp2_component.cpp     # C++ implementation (protocol, handlers)
│   └── aqara_fp2_accel/
│       ├── __init__.py           # Accelerometer config schema
│       ├── aqara_fp2_accel.h     # Accelerometer header
│       └── aqara_fp2_accel.cpp   # I2C driver, orientation, vibration
├── card.js                       # HA Lovelace card (target visualization)
├── fp2-card-test.html            # Browser test harness for card
├── docs/                         # This documentation
├── example_config.yaml           # Reference ESPHome configuration
├── FLASHING.md                   # Hardware flashing guide
├── hacs.json                     # HACS frontend integration metadata
└── images/                       # Flashing guide photos
```

## Building and Flashing

### Local Development

1. Clone the repository alongside your ESPHome config
2. Reference the components locally:
   ```yaml
   external_components:
     - source:
         type: local
         path: /path/to/esphome_fp2_ng/components
   ```
3. Compile: `esphome compile your_config.yaml`
4. Flash: `esphome upload your_config.yaml`

### From GitHub

```yaml
external_components:
  - source: github://JameZUK/esphome_fp2_ng@main
    refresh: 120s
    components: [ aqara_fp2, aqara_fp2_accel ]
```

## Adding New Attributes

When a new radar attribute is discovered or needs to be supported:

### 1. Define the Attribute ID

In `fp2_component.h`, add to the `AttrId` enum:

```cpp
enum class AttrId : uint16_t {
    // ...
    NEW_ATTRIBUTE = 0x0XXX,
};
```

### 2. Handle in Report Switch

In `fp2_component.cpp`, add a case to `handle_report_()`:

```cpp
case AttrId::NEW_ATTRIBUTE:
    if (payload.size() == expected_size && payload[2] == expected_type) {
        // Parse and process
        // Publish to sensor if applicable
    }
    break;  // IMPORTANT: always break unconditionally after the if block
```

**Critical**: The `break` must be outside and after the `if` block, not inside
it. Placing `break` inside the `if` causes fall-through to the next case when
the payload size check fails. This was a bug in the original code.

### 3. Add Sensor (if exposing to HA)

In `fp2_component.h`:
```cpp
// Add member
sensor::Sensor *new_sensor_{nullptr};

// Add setter
void set_new_sensor(sensor::Sensor *sensor) { new_sensor_ = sensor; }
```

In `__init__.py`:
```python
# Add config constant
CONF_NEW_SENSOR = "new_sensor"

# Add to CONFIG_SCHEMA
cv.Optional(CONF_NEW_SENSOR): sensor.sensor_schema(
    accuracy_decimals=0,
    state_class=STATE_CLASS_MEASUREMENT,
),

# Add to SENSOR_MAP
CONF_NEW_SENSOR: (sensor.new_sensor, "set_new_sensor"),
```

### 4. Send During Init (if configuration attribute)

In `check_initialization_()`:
```cpp
enqueue_command_(OpCode::WRITE, AttrId::NEW_ATTRIBUTE, (uint8_t) value);
```

## Key Implementation Patterns

### Null-Check Before Publish

Always check sensor pointers before publishing:
```cpp
if (some_sensor_ != nullptr) {
    some_sensor_->publish_state(value);
}
```

### Command Queue

Use the typed `enqueue_command_` overloads:
```cpp
enqueue_command_(OpCode::WRITE, attr_id, (uint8_t) val);   // UINT8
enqueue_command_(OpCode::WRITE, attr_id, (uint16_t) val);  // UINT16
enqueue_command_(OpCode::WRITE, attr_id, true);             // BOOL
enqueue_command_blob2_(attr_id, blob_data);                  // BLOB2
```

### Grid Bitmap Operations

Check if a coordinate falls within a grid:
```cpp
int col = ...;  // 0-15
int row = ...;  // 0-19
uint16_t row_val = (grid[row * 2] << 8) | grid[row * 2 + 1];
bool active = (row_val & (1 << (15 - col))) != 0;
```

## I2C Bus Sharing Pattern

The accelerometer (da218B, 0x27) and light sensor (OPT3001, 0x44) share the
same I2C bus on GPIO32/33. On the single-core ESP32:

- Both devices are accessed from a single FreeRTOS task (`accel_task_`)
- A 5ms `vTaskDelay` separates the accelerometer read from the OPT3001 read
- On `ESP_ERR_INVALID_STATE` or `ESP_ERR_TIMEOUT`, the bus is reset with
  `i2c_master_bus_reset(bus_handle_)`
- The OPT3001 is read every 10th cycle (~1s) to avoid excessive bus traffic
- Lux values are cached in a mutex-protected variable and published from the
  main ESPHome loop (sensor publish is not thread-safe)

The ESP-IDF `i2c_master` API (new in 5.5+) uses `i2c_master_bus_handle_t` and
`i2c_master_dev_handle_t` — each device gets its own handle on the shared bus.
Use `i2c_master_transmit_receive()` for register reads (not `i2c_master_receive`
which skips the register address write).

## Known Limitations and Future Work

### Not Yet Implemented

- **Radar firmware OTA**: The XMODEM-1K mechanism is implemented (experimental)
  but untested. Triggered by SubID 0x0127. See [03-firmware.md](03-firmware.md).
- **Radar debug log (0x0201)**: Handler captures debug strings from radar MCU
  but the radar's internal debug flag is off by default. No known SubID to
  enable it.
- **NVS lux calibration**: The stock firmware reads calibration coefficients
  (lux_low_k/b, lux_high_k/b) from NVS. Our OPT3001 driver reads raw values
  without calibration. Accuracy is good but could be improved.
- **Accelerometer calibration**: `calculate_calibration()` computes corrections
  but is never called. A calibration trigger mechanism is needed.
- **HW version (0x0101)**: Handler exists but radar does not respond to READ
  requests. The radar has a send function (`FUN_00026a94`) but only sends
  during its own boot sequence, which is before the ESP32 is ready to receive.

### Resolved (Previously Listed)

- ~~Fall detection~~ — Implemented via 0x0155 PEOPLE_COUNTING. Confirmed by
  Ghidra RE of both radar and stock ESP32 firmware.
- ~~Sleep monitoring~~ — Fully implemented: state, presence, heart rate,
  respiration, heart rate deviation. Sleep data (0x0159) is 3x IEEE 754 LE floats.
- ~~Posture reporting~~ — Implemented per-zone (standing/sitting/lying).
- ~~Real-time people count~~ — Implemented via 0x0164, 0x0165, 0x0166.
- ~~Walking distance~~ — Implemented via 0x0174 (centimetres, divided by 100).
- ~~Dwell time~~ — Now configurable via `dwell_time_enable` YAML option.
- ~~Light sensor unknown~~ — Identified as TI OPT3001 at I2C 0x44. Fully
  implemented.
- ~~Radar firmware update unknown~~ — Uses XMODEM over UART. Mechanism
  understood, implementation pending.

### Architecture Considerations

- **Frame decoder timeout**: The UART state machine has no timeout for partial
  frames. If bytes arrive partially for a frame and then stop, the decoder
  remains in a non-SYNC state until the next 0x55 byte. Consider adding a
  timeout that resets to SYNC after ~100ms of inactivity.

- **Location tracking rate**: Target data arrives at 10-20 Hz. Publishing
  per-zone counts at this rate may be excessive for HA. Consider adding a
  configurable throttle or only publishing on change.

- **Zone people count and location reporting**: When `zone_people_count` is
  configured, location reporting is auto-enabled and cannot be disabled via the
  switch. This is intentional — the count depends on tracking data — but should
  be documented clearly to users.

- **Edge grid required for global presence**: The radar does not send global
  presence/motion reports (0x0103, 0x0104) unless an edge grid is configured.
  Without it, the radar tracks targets but doesn't trigger binary presence.
  Users should always configure a full-coverage `edge_grid`.

## UART Sniffing (for Protocol Research)

To capture the raw UART traffic between ESP32 and radar without modifying
firmware:

1. Tap GPIO18 (TX) and GPIO19 (RX) with a logic analyzer or second UART adapter
2. Baud rate: 890,000
3. Decode using the frame format documented in
   [02-uart-protocol.md](02-uart-protocol.md)
4. The [AqaraPresenceSensorFP2ReverseEngineering](https://github.com/hansihe/AqaraPresenceSensorFP2ReverseEngineering)
   repository contains Python decoding scripts and a `sniff_uart_bidir.py` tool
   for Glasgow Interface Explorer hardware

## References

- [Original esphome_fp2](https://github.com/hansihe/esphome_fp2) — upstream project
- [AqaraPresenceSensorFP2ReverseEngineering](https://github.com/hansihe/AqaraPresenceSensorFP2ReverseEngineering) — protocol RE, board schematic, GPIO mapping
- [AqaraPresenceSensorFP2](https://github.com/niceboygithub/AqaraPresenceSensorFP2) — hardware details, esptool commands
- [ha-aqara-devices](https://github.com/Darkdragon14/ha-aqara-devices) — cloud API integration (alternative approach)
- [fp2-proxy](https://github.com/ebaauw/fp2-proxy) — HAP proxy to deCONZ (binary occupancy only)
- [TI IWR6843AOP Datasheet](https://www.ti.com/product/IWR6843AOP) — radar chip documentation
- [ESPHome External Components](https://esphome.io/components/external_components.html) — ESPHome docs
