#pragma once

#include "esphome/components/binary_sensor/binary_sensor.h"
#include "esphome/components/button/button.h"
#include "esphome/components/select/select.h"
#include "esphome/components/switch/switch.h"
#include "esphome/components/sensor/sensor.h"
#include "esphome/components/text_sensor/text_sensor.h"
#include "esphome/components/uart/uart.h"
#include "esphome/core/component.h"
#include "esphome/core/gpio.h"

#include "../aqara_fp2_accel/aqara_fp2_accel.h"

#include <ArduinoJson.h>
#include <array>
#include <cstdint>
#include <deque>
#include <vector>

namespace esphome {
namespace aqara_fp2 {

static const char *const TAG = "aqara_fp2";
// Build marker: 20260414-v2 — forces recompilation

// 40-byte Grid Map
using GridMap = std::array<uint8_t, 40>;

struct FP2Zone : public Component {
  FP2Zone(uint8_t zone_id, const GridMap grid, uint8_t sensitivity) : id(zone_id), grid(grid), sensitivity(sensitivity) {}

  void set_presence_sensor(binary_sensor::BinarySensor *sensor) {
    this->presence_sensor = sensor;
  }

  void set_motion_sensor(binary_sensor::BinarySensor *sensor) {
    this->motion_sensor = sensor;
  }

  void set_map_sensor(text_sensor::TextSensor *sensor) {
    this->map_sensor = sensor;
  }

  void set_zone_people_count_sensor(sensor::Sensor *sensor) {
    this->zone_people_count_sensor = sensor;
  }

  void set_posture_sensor(text_sensor::TextSensor *sensor) {
    this->posture_sensor = sensor;
  }

  void publish_presence(bool state) {
    if (this->presence_sensor != nullptr) {
      this->presence_sensor->publish_state(state);
    }
  }

  void publish_motion(bool state) {
    if (this->motion_sensor != nullptr) {
      this->motion_sensor->publish_state(state);
    }
  }

  void publish_map(const std::string &map_hex) {
    if (this->map_sensor != nullptr) {
      this->map_sensor->publish_state(map_hex);
    }
  }

  uint8_t id;
  esphome::binary_sensor::BinarySensor *presence_sensor{nullptr};
  esphome::binary_sensor::BinarySensor *motion_sensor{nullptr};
  esphome::text_sensor::TextSensor *map_sensor{nullptr};
  esphome::sensor::Sensor *zone_people_count_sensor{nullptr};
  esphome::text_sensor::TextSensor *posture_sensor{nullptr};
  GridMap grid;
  uint8_t sensitivity; // 1=Low, 2=Med, 3=High
};

class FP2Component;

enum class DataType : uint8_t {
    UINT8 = 0x00,
    UINT16 = 0x01,
    UINT32 = 0x02,
    VOID = 0x03,
    BOOL = 0x04,
    STRING = 0x05,
    BINARY = 0x06,
};

enum class OpCode : uint8_t {
  // Device -> Host: Standard Response to Read (Values).
  // Device -> Host: Reverse Read Request (SubID only, len=2).
  RESPONSE = 0x01,

  // Host -> Device: Write Attribute (Values).
  WRITE = 0x02,

  // Both: Acknowledge.
  ACK = 0x03,

  // Host -> Device: Standard Read Request (SubID only).
  // Host -> Device: Reverse Read Response (Values, in response to 0x01 Query).
  READ = 0x04,

  // Device -> Host: Async Report.
  REPORT = 0x05,
};

enum class AttrId : uint16_t {
    // --- System / Info ---
    HW_VERSION                      = 0x0101, // Hardware version (uint8, appended to SW version)
    RADAR_SW_VERSION                = 0x0102, // Software version / heartbeat (~1Hz)
    OTA_SET_FLAG                    = 0x0127, // OTA update flag
    DEBUG_LOG                       = 0x0201, // Radar MCU debug log (string, gated by debug_mode)

    // --- Detection Reports ---
    MOTION_DETECT                   = 0x0103, // Global motion (even=active, odd=inactive)
    PRESENCE_DETECT                 = 0x0104, // Global presence (0=empty, non-zero=occupied)
    DETECT_ZONE_MOTION              = 0x0115, // Zone motion event [zone_id, state]
    ZONE_PRESENCE                   = 0x0142, // Zone presence [zone_id, state]
    WORK_MODE                       = 0x0116, // Work mode report

    // --- Configuration ---
    MONITOR_MODE                    = 0x0105, // Detection direction (0=default, 1=L/R)
    CLOSING_SETTING                 = 0x0106, // Proximity (0=far, 1=med, 2=close)
    PRESENCE_DETECT_SENSITIVITY     = 0x0111, // Sensitivity (1-3)
    LEFT_RIGHT_REVERSE              = 0x0122, // L/R swap (0/1/2)
    WALL_CORNER_POS                 = 0x0170, // Mount position (1=wall, 2=left, 3=right)

    // --- Grid Maps ---
    EDGE_MAP                        = 0x0107, // Detection boundary (40B grid)
    ENTRY_EXIT_MAP                  = 0x0109, // Enter/exit zones (40B grid)
    INTERFERENCE_MAP                = 0x0110, // Interference sources (40B grid)
    ZONE_MAP                        = 0x0114, // Zone N area map [ID(1) + grid(40)]
    ZONE_SENSITIVITY                = 0x0151, // Zone N sensitivity [ID << 8 | sens]
    ZONE_ACTIVATION_LIST            = 0x0202, // Zone activation bitmap (32B)
    DETECT_ZONE_TYPE                = 0x0152, // Zone N type
    ZONE_CLOSE_AWAY_ENABLE          = 0x0153, // Zone N close/away enable

    // --- Auto-Calibration ---
    INTERFERENCE_AUTO_SET           = 0x0125, // Auto-detected interference grid (BLOB2)
    INTERFERENCE_AUTO_ENABLE        = 0x0139, // Enable interference auto-detection (BOOL)
    EDGE_AUTO_SET                   = 0x0149, // Auto-detected edge grid (BLOB2)
    EDGE_AUTO_ENABLE                = 0x0150, // Enable edge auto-detection (BOOL)
    DELETE_FALSE_TARGETS            = 0x0160, // Delete false targets

    // --- Location Tracking ---
    LOCATION_REPORT_ENABLE          = 0x0112, // Enable target streaming (0/1)
    LOCATION_TRACKING_DATA          = 0x0117, // Per-target position data (BLOB2)
    ANGLE_SENSOR_DATA               = 0x0120, // Accelerometer angle (reverse-read)
    DEVICE_DIRECTION                = 0x0143, // Device orientation (reverse-read)

    // --- People Counting ---
    PEOPLE_COUNTING                 = 0x0155, // People counting data
    PEOPLE_COUNT_REPORT_ENABLE      = 0x0158, // Enable people count reports (BOOL)
    PEOPLE_NUMBER_ENABLE            = 0x0162, // Enable people number tracking (BOOL)
    TARGET_TYPE_ENABLE              = 0x0163, // AI person detection (BOOL)
    REALTIME_PEOPLE                 = 0x0164, // Real-time people data
    ONTIME_PEOPLE_NUMBER            = 0x0165, // Periodic total person count (UINT32)
    REALTIME_COUNT                  = 0x0166, // Real-time count
    ZONE_PEOPLE_NUMBER              = 0x0175, // Native per-zone count [zone_id<<8|count]

    // --- Posture / Activity ---
    TARGET_POSTURE                  = 0x0154, // Target posture reports
    POSTURE_REPORT_ENABLE           = 0x0157, // Enable posture reporting (BOOL)
    DWELL_TIME_ENABLE               = 0x0172, // Enable dwell tracking
    WALK_DISTANCE_ENABLE            = 0x0173, // Enable walking distance
    WALK_DISTANCE_ALL               = 0x0174, // Walking distance data

    // --- Fall Detection ---
    ANGLE_SENSOR_REV                = 0x0121, // Angle sensor revision (NOT fall detection)
    FALL_DETECTION_STATE            = 0x0122, // Fall detection state (stock ESP32 handler, radar doesn't send)
    FALL_SENSITIVITY                = 0x0123, // Fall detection sensitivity
    FALL_OVERTIME_PERIOD            = 0x0134, // Fall overtime period
    FALL_OVERTIME_DETECTION         = 0x0135, // Fall overtime config (handler at 0x400e11ac)
    FALL_OVERTIME_REPORT            = 0x0136, // Fall overtime report (radar_fall_overtime_det)
    FALL_DELAY_TIME                 = 0x0179, // Delay before confirming fall (uint16)
    FALLDOWN_BLIND_ZONE             = 0x0180, // Fall detection exclusion zones (40B grid)
    FALL_DETECTION_RESULT           = 0x0306, // ACTUAL fall detection from radar (uint8: 0=no fall, 1=fall)

    // --- Sleep Monitoring ---
    SLEEP_REPORT_ENABLE             = 0x0156, // Enable sleep reporting (BOOL)
    SLEEP_DATA                      = 0x0159, // Sleep tracking data
    SLEEP_STATE                     = 0x0161, // Current sleep state
    SLEEP_PRESENCE                  = 0x0167, // Sleep zone presence
    SLEEP_MOUNT_POSITION            = 0x0168, // Sleep zone mount position
    SLEEP_ZONE_SIZE                 = 0x0169, // Sleep zone dimensions
    SLEEP_IN_OUT                    = 0x0171, // Sleep zone entry/exit
    SLEEP_EVENT                     = 0x0176, // Sleep events
    SLEEP_BED_HEIGHT                = 0x0177, // Bed/mattress height (uint16)
    OVERHEAD_HEIGHT                 = 0x0178, // Ceiling height (uint16)

    // (HW_VERSION = 0x0101 and DEBUG_LOG = 0x0201 defined in System/Info section above)

    // --- Temperature ---
    TEMPERATURE                     = 0x0128, // Radar chip temperature
    THERMO_EN                       = 0x0138, // Enable temperature reporting (BOOL)
    THERMO_DATA                     = 0x0141, // Temperature data mode

    INVALID                         = 0xFFFF,
};

struct FP2Command {
  OpCode type;
  AttrId attr_id;
  std::vector<uint8_t> data;
  uint32_t last_send_time;
  uint8_t retry_count;
};

class FP2LocationSwitch : public switch_::Switch {
public:
  void set_parent(FP2Component *parent) { parent_ = parent; }

protected:
  void write_state(bool state) override;
  FP2Component *parent_{nullptr};
};

class FP2SleepModeSwitch : public switch_::Switch {
public:
  void set_parent(FP2Component *parent) { parent_ = parent; }

protected:
  void write_state(bool state) override;
  FP2Component *parent_{nullptr};
};

class FP2OperatingModeSelect : public select::Select {
public:
  void set_parent(FP2Component *parent) { parent_ = parent; }

protected:
  void control(const std::string &value) override;
  FP2Component *parent_{nullptr};
};

class FP2CalibrateEdgeButton : public button::Button {
public:
  void set_parent(FP2Component *parent) { parent_ = parent; }

protected:
  void press_action() override;
  FP2Component *parent_{nullptr};
};

class FP2CalibrateInterferenceButton : public button::Button {
public:
  void set_parent(FP2Component *parent) { parent_ = parent; }

protected:
  void press_action() override;
  FP2Component *parent_{nullptr};
};

class FP2ClearEdgeButton : public button::Button {
public:
  void set_parent(FP2Component *parent) { parent_ = parent; }

protected:
  void press_action() override;
  FP2Component *parent_{nullptr};
};

class FP2ClearInterferenceButton : public button::Button {
public:
  void set_parent(FP2Component *parent) { parent_ = parent; }

protected:
  void press_action() override;
  FP2Component *parent_{nullptr};
};

class FP2DeleteFalseTargetsButton : public button::Button {
public:
  void set_parent(FP2Component *parent) { parent_ = parent; }

protected:
  void press_action() override;
  FP2Component *parent_{nullptr};
};

class FP2RadarOtaButton : public button::Button {
public:
  void set_parent(FP2Component *parent) { parent_ = parent; }

protected:
  void press_action() override;
  FP2Component *parent_{nullptr};
};

class FP2RadarFwStageButton : public button::Button {
public:
  void set_parent(FP2Component *parent) { parent_ = parent; }

protected:
  void press_action() override;
  FP2Component *parent_{nullptr};
};

class FP2Component : public Component, public uart::UARTDevice {
public:
  void setup() override;
  void loop() override;
  void dump_config() override;

  // Configuration setters
  void set_debug_mode(bool val) { debug_mode_ = val; }
  void set_radar_reset_pin(GPIOPin *pin) { reset_pin_ = pin; }
  void set_mounting_position(uint8_t pos) { mounting_position_ = pos; }
  void set_left_right_reverse(bool val) { left_right_reverse_ = val; }

  void set_fall_detection_sensitivity(uint8_t val) {
    fall_detection_sensitivity_ = val;
  }
  void set_fall_overtime_period(uint32_t val) {
    fall_overtime_period_ = val;
  }
  void set_fall_overtime_sensor(binary_sensor::BinarySensor *sensor) {
    fall_overtime_sensor_ = sensor;
  }
  void set_dwell_time_enable(bool val) {
    dwell_time_enable_ = val;
  }
  void set_sleep_mount_position(uint8_t val) {
    sleep_mount_position_ = val;
  }
  void set_sleep_zone_size(uint32_t val) {
    sleep_zone_size_ = val;
  }
  void set_fall_delay_time(uint16_t val) {
    fall_delay_time_ = val;
  }
  void set_sleep_bed_height(uint16_t val) {
    sleep_bed_height_ = val;
  }
  void set_overhead_height(uint16_t val) {
    overhead_height_ = val;
  }
  void set_falldown_blind_zone(const std::vector<uint8_t> &grid);

  void set_interference_grid(const std::vector<uint8_t> &grid);
  void set_exit_grid(const std::vector<uint8_t> &grid);
  void set_edge_grid(const std::vector<uint8_t> &grid);

  void set_presence_sensitivity(uint8_t val) { global_presence_sensitivity_ = val; }
  void set_motion_sensor(binary_sensor::BinarySensor *sensor) { global_motion_sensor_ = sensor; }
  void set_presence_sensor(binary_sensor::BinarySensor *sensor) { global_presence_sensor_ = sensor; }

  //void add_zone(uint8_t id, binary_sensor::BinarySensor *sens,
  //              const std::vector<uint8_t> &grid, uint8_t sensitivity);
  void set_zones(const std::vector<FP2Zone*> &zones);

  void set_target_tracking_sensor(text_sensor::TextSensor *sensor) {
    target_tracking_sensor_ = sensor;
  }
  void set_target_tracking_interval(uint32_t ms) {
    target_tracking_interval_ms_ = ms;
  }
  void set_location_report_switch(FP2LocationSwitch *sw) {
    location_report_switch_ = sw;
    sw->set_parent(this);
  }
  void set_sleep_mode_switch(FP2SleepModeSwitch *sw) {
    sleep_mode_switch_ = sw;
    sw->set_parent(this);
  }
  void set_operating_mode_select(FP2OperatingModeSelect *sel) {
    operating_mode_select_ = sel;
    sel->set_parent(this);
  }
  void set_sleep_mode_enabled(bool enabled);
  void set_operating_mode(const std::string &mode);

  void set_calibrate_edge_button(FP2CalibrateEdgeButton *btn) {
    calibrate_edge_button_ = btn;
    btn->set_parent(this);
  }
  void set_calibrate_interference_button(FP2CalibrateInterferenceButton *btn) {
    calibrate_interference_button_ = btn;
    btn->set_parent(this);
  }
  void set_clear_edge_button(FP2ClearEdgeButton *btn) {
    clear_edge_button_ = btn;
    btn->set_parent(this);
  }
  void set_clear_interference_button(FP2ClearInterferenceButton *btn) {
    clear_interference_button_ = btn;
    btn->set_parent(this);
  }
  void set_delete_false_targets_button(FP2DeleteFalseTargetsButton *btn) {
    delete_false_targets_button_ = btn;
    btn->set_parent(this);
  }
  void set_radar_ota_button(FP2RadarOtaButton *btn) {
    radar_ota_button_ = btn;
    btn->set_parent(this);
  }

  void trigger_edge_calibration();
  void trigger_interference_calibration();
  void clear_edge_calibration();
  void trigger_delete_false_targets();
  void clear_interference_calibration();
  void trigger_radar_ota();
  void trigger_radar_fw_stage();
  void set_radar_firmware_url(const std::string &url) { radar_firmware_url_ = url; }
  void set_radar_fw_stage_button(FP2RadarFwStageButton *btn) {
    radar_fw_stage_button_ = btn;
    btn->set_parent(this);
  }

  void set_edge_label_grid_sensor(text_sensor::TextSensor *sensor) {
    ESP_LOGI(TAG, "set_edge_label_grid_sensor called (has_edge_grid_=%d)", has_edge_grid_);
    edge_label_grid_sensor_ = sensor;
    if (has_edge_grid_ && edge_label_grid_sensor_ != nullptr) {
      ESP_LOGI(TAG, "Publishing edge label grid from setter");
      edge_label_grid_sensor_->publish_state(grid_to_hex_card_format(edge_grid_));
    } else {
      ESP_LOGW(TAG, "NOT publishing edge label grid from setter (has_grid=%d, sensor=%p)", has_edge_grid_, edge_label_grid_sensor_);
    }
  }
  void set_entry_exit_grid_sensor(text_sensor::TextSensor *sensor) {
    ESP_LOGI(TAG, "set_entry_exit_grid_sensor called (has_exit_grid_=%d)", has_exit_grid_);
    entry_exit_grid_sensor_ = sensor;
    if (has_exit_grid_ && entry_exit_grid_sensor_ != nullptr) {
      ESP_LOGI(TAG, "Publishing entry/exit grid from setter");
      entry_exit_grid_sensor_->publish_state(grid_to_hex_card_format(exit_grid_));
    } else {
      ESP_LOGW(TAG, "NOT publishing entry/exit grid from setter (has_grid=%d, sensor=%p)", has_exit_grid_, entry_exit_grid_sensor_);
    }
  }
  void set_interference_grid_sensor(text_sensor::TextSensor *sensor) {
    ESP_LOGI(TAG, "set_interference_grid_sensor called (has_interference_grid_=%d)", has_interference_grid_);
    interference_grid_sensor_ = sensor;
    if (has_interference_grid_ && interference_grid_sensor_ != nullptr) {
      ESP_LOGI(TAG, "Publishing interference grid from setter");
      interference_grid_sensor_->publish_state(grid_to_hex_card_format(interference_grid_));
    } else {
      ESP_LOGW(TAG, "NOT publishing interference grid from setter (has_grid=%d, sensor=%p)", has_interference_grid_, interference_grid_sensor_);
    }
  }
  void set_mounting_position_sensor(text_sensor::TextSensor *sensor) {
    mounting_position_sensor_ = sensor;
    if (mounting_position_sensor_ != nullptr) {
      const char* pos_str;
      switch (mounting_position_) {
        case 0x02: pos_str = "left_upper_corner"; break;
        case 0x03: pos_str = "right_upper_corner"; break;
        default: pos_str = "wall"; break;
      }
      mounting_position_sensor_->publish_state(pos_str);
    }
  }
  void set_radar_state_sensor(text_sensor::TextSensor *sensor) {
      radar_state_sensor_ = sensor;
  }
  void set_radar_temperature_sensor(sensor::Sensor *sensor) {
      radar_temperature_sensor_ = sensor;
  }
  void set_people_count_sensor(sensor::Sensor *sensor) {
      people_count_sensor_ = sensor;
  }
  void set_radar_software_sensor(text_sensor::TextSensor *sensor) {
      radar_software_sensor_ = sensor;
  }
  void set_fall_detection_sensor(binary_sensor::BinarySensor *sensor) {
      fall_detection_sensor_ = sensor;
  }
  void set_sleep_state_sensor(text_sensor::TextSensor *sensor) {
      sleep_state_sensor_ = sensor;
  }
  void set_sleep_presence_sensor(binary_sensor::BinarySensor *sensor) {
      sleep_presence_sensor_ = sensor;
  }
  void set_heart_rate_sensor(sensor::Sensor *sensor) {
      heart_rate_sensor_ = sensor;
  }
  void set_respiration_rate_sensor(sensor::Sensor *sensor) {
      respiration_rate_sensor_ = sensor;
  }
  void set_heart_rate_dev_sensor(sensor::Sensor *sensor) {
      heart_rate_dev_sensor_ = sensor;
  }
  void set_walking_distance_sensor(sensor::Sensor *sensor) {
      walking_distance_sensor_ = sensor;
  }

  void set_fp2_accel(aqara_fp2_accel::AqaraFP2Accel *accel) {
      fp2_accel_ = accel;
  }

  void set_location_reporting_enabled(bool enabled);

  // Grid format conversion
  std::string grid_to_hex_card_format(const GridMap &grid);

  // Map configuration
  void set_map_config_json(const std::string &json) { map_config_json_ = json; }
  JsonDocument get_map_config_json();
  void json_get_map_data(JsonObject root);

protected:
  // Internal logic
  void process_command_queue_();
  void send_next_command_();
  void handle_incoming_byte_(uint8_t byte);
  const char* get_mounting_position_string_();
  void handle_parsed_frame_(uint8_t type, AttrId attr_id,
                            const std::vector<uint8_t> &payload);
  void handle_ack_(AttrId attr_id);
  void handle_report_(AttrId attr_id, const std::vector<uint8_t> &payload);
  void handle_location_tracking_report_(const std::vector<uint8_t> &payload);
  void update_zone_people_counts_(const std::vector<uint8_t> &payload, uint8_t count);
  static bool is_target_in_zone_(int16_t raw_x, int16_t raw_y, const GridMap &grid);
  void handle_temperature_report_(const std::vector<uint8_t> &payload);
  void handle_response_(AttrId attr_id, const std::vector<uint8_t> &payload);
  void handle_reverse_read_request_(AttrId attr_id);
  void send_ack_(AttrId attr_id);

  // Initialization
  void perform_reset_();
  void check_initialization_();
  void publish_radar_state_(const char *state);

  aqara_fp2_accel::AqaraFP2Accel *fp2_accel_{nullptr};

  GPIOPin *reset_pin_{nullptr};
  bool init_done_{false};
  bool radar_ready_{false};  // Set when radar finishes booting (non-heartbeat frame received)
  bool debug_mode_{false};   // Verbose protocol logging
  bool global_presence_active_{false};
  uint32_t last_heartbeat_millis_{0};

  // Configuration State
  uint8_t mounting_position_{0x01}; // Default Wall
  bool left_right_reverse_{false};
  uint8_t fall_detection_sensitivity_{1};
  uint32_t fall_overtime_period_{0};    // 0 = not configured (ms)
  uint16_t fall_delay_time_{0};         // 0 = not configured
  bool dwell_time_enable_{false};
  uint8_t sleep_mount_position_{0};     // 0 = not configured
  uint32_t sleep_zone_size_{0};         // 0 = not configured
  uint16_t sleep_bed_height_{0};        // 0 = not configured
  uint16_t overhead_height_{0};         // 0 = not configured
  uint8_t radar_hw_version_{0};         // Captured from 0x0101 during boot
  GridMap falldown_blind_zone_{};
  bool has_falldown_blind_zone_{false};

  // Grids (Optional)
  GridMap interference_grid_{};
  bool has_interference_grid_{false};
  GridMap exit_grid_{};
  bool has_exit_grid_{false};
  GridMap edge_grid_{};
  bool has_edge_grid_{false};

  // Global zone
  uint8_t global_presence_sensitivity_{2}; // Default Medium
  binary_sensor::BinarySensor *global_presence_sensor_{nullptr};
  binary_sensor::BinarySensor *global_motion_sensor_{nullptr};

  // Zones
  std::vector<FP2Zone*> zones_;
  text_sensor::TextSensor *target_tracking_sensor_{nullptr};
  FP2LocationSwitch *location_report_switch_{nullptr};
  FP2SleepModeSwitch *sleep_mode_switch_{nullptr};
  FP2OperatingModeSelect *operating_mode_select_{nullptr};
  bool sleep_mode_active_{false};
  FP2CalibrateEdgeButton *calibrate_edge_button_{nullptr};
  FP2CalibrateInterferenceButton *calibrate_interference_button_{nullptr};
  FP2ClearEdgeButton *clear_edge_button_{nullptr};
  FP2ClearInterferenceButton *clear_interference_button_{nullptr};
  FP2DeleteFalseTargetsButton *delete_false_targets_button_{nullptr};
  FP2RadarOtaButton *radar_ota_button_{nullptr};
  FP2RadarFwStageButton *radar_fw_stage_button_{nullptr};
  bool location_reporting_active_{false};
  uint32_t target_tracking_interval_ms_{500};
  uint32_t last_target_publish_millis_{0};

  // Grid text sensors
  text_sensor::TextSensor *edge_label_grid_sensor_{nullptr};
  text_sensor::TextSensor *entry_exit_grid_sensor_{nullptr};
  text_sensor::TextSensor *interference_grid_sensor_{nullptr};
  text_sensor::TextSensor *mounting_position_sensor_{nullptr};

  text_sensor::TextSensor *radar_state_sensor_{nullptr};
  sensor::Sensor *radar_temperature_sensor_{nullptr};
  sensor::Sensor *people_count_sensor_{nullptr};
  text_sensor::TextSensor *radar_software_sensor_{nullptr};
  binary_sensor::BinarySensor *fall_detection_sensor_{nullptr};
  binary_sensor::BinarySensor *fall_overtime_sensor_{nullptr};
  text_sensor::TextSensor *sleep_state_sensor_{nullptr};
  binary_sensor::BinarySensor *sleep_presence_sensor_{nullptr};
  sensor::Sensor *heart_rate_sensor_{nullptr};
  sensor::Sensor *respiration_rate_sensor_{nullptr};
  sensor::Sensor *heart_rate_dev_sensor_{nullptr};
  sensor::Sensor *walking_distance_sensor_{nullptr};

  // Map Configuration (compile-time generated)
  std::string map_config_json_;

  // Communication State
  std::deque<FP2Command> command_queue_;

  // Frame Decoder State
  enum DecoderState {
    SYNC,
    VER_H,
    VER_L,
    SEQ,
    OPCODE,
    LEN_H,
    LEN_L,
    H_CHECK,
    PAYLOAD,
    CRC_L,
    CRC_H
  } state_{SYNC};

  uint8_t rx_seq_;
  uint8_t rx_opcode_;
  uint16_t rx_len_;
  std::vector<uint8_t> rx_payload_;
  uint16_t rx_crc_;

  // Rolling checksum for header
  uint16_t header_sum_{0};

  // Ack Manager
  // We track the SubID of tAttrId::INVALID command we are currently waiting for an ACK for.
  // 0xFFFF = Not waiting.
  AttrId waiting_for_ack_attr_id_{AttrId::INVALID};
  uint32_t last_command_sent_millis_{0};
  static const uint32_t ACK_TIMEOUT_MS = 500;
  static const uint8_t MAX_RETRIES = 3;

  void enqueue_command_(OpCode type, AttrId attr_id, uint8_t byte_val);
  void enqueue_command_(OpCode type, AttrId attr_id, uint16_t word_val);
  void enqueue_command_(OpCode type, AttrId attr_id, bool bool_val);
  void enqueue_command_blob2_(AttrId attr_id,
                              const std::vector<uint8_t> &blob_content);
  void enqueue_read_(AttrId attr_id);
  void send_reverse_response_(AttrId attr_id, uint8_t byte_val);

  // Radar OTA (XMODEM-1K)
  enum class OtaState : uint8_t {
    IDLE,
    WAITING_HANDSHAKE,  // Waiting for 'C' from radar bootloader
    TRANSFERRING,       // Sending XMODEM-1K blocks
    ENDING,             // Sending EOT, waiting for ACK
    DONE
  };
  OtaState ota_state_{OtaState::IDLE};
  uint32_t ota_state_start_millis_{0};
  uint32_t ota_firmware_size_{0};
  uint32_t ota_firmware_offset_{0};  // Current read offset
  uint8_t ota_block_num_{1};
  uint8_t ota_retry_count_{0};
  uint8_t ota_can_count_{0};
  uint8_t ota_packet_buf_[1029];     // STX + blk + ~blk + 1024 data + CRC16

  static const uint32_t MCU_OTA_FLASH_OFFSET = 0x433000;
  static const uint32_t MCU_OTA_FLASH_SIZE = 4 * 1024 * 1024;
  static const uint32_t XMODEM_BLOCK_SIZE = 1024;
  static const uint32_t OTA_HANDSHAKE_TIMEOUT_MS = 20000;
  static const uint32_t OTA_TRANSFER_TIMEOUT_MS = 3000;
  static const uint8_t OTA_MAX_RETRIES = 5;

  void ota_loop_();
  void ota_send_current_block_();
  void ota_send_eot_();
  uint32_t ota_detect_firmware_size_();
  bool ota_download_firmware_();
  static uint16_t xmodem_crc16_(const uint8_t *data, size_t len);
  std::string radar_firmware_url_;
};

} // namespace aqara_fp2
} // namespace esphome
