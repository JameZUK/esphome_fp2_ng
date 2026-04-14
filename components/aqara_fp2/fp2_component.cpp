#include "fp2_component.h"
#include "esphome/components/switch/switch.h"
#include "esphome/core/helpers.h"
#include "esphome/core/hal.h"
#include "esphome/core/log.h"
#include <cmath>
#include <cstdint>
#include <vector>
#include <esp_flash.h>
#ifdef USE_RADAR_FW_HTTP
#include <esp_http_client.h>
#endif

namespace esphome {
namespace aqara_fp2 {

// Init diagnostic counters (persist across function calls)
static uint32_t diag_acks = 0;
static uint32_t diag_drops = 0;
static uint32_t diag_init_at = 0;
static bool diag_init_used_ready = false;

// CRC16-MODBUS
static uint16_t crc16(const uint8_t *data, size_t len) {
  uint16_t crc = 0xFFFF;
  for (size_t i = 0; i < len; i++) {
    crc ^= data[i];
    for (int j = 0; j < 8; j++) {
      if ((crc & 0x0001) != 0) {
        crc >>= 1;
        crc ^= 0xA001;
      } else {
        crc >>= 1;
      }
    }
  }
  return crc;
}

void FP2Component::setup() {
  // Force recompile marker: 20260414-v2
  ESP_LOGE(TAG, "### SETUP v2: init_done=%d radar_ready=%d heartbeat=%u", init_done_, radar_ready_, last_heartbeat_millis_);

  // Reset internal state
  waiting_for_ack_attr_id_ = AttrId::INVALID;
  init_done_ = false;
  radar_ready_ = false;
  last_heartbeat_millis_ = 0;

  ESP_LOGE(TAG, "### SETUP: state reset done, init_done=%d radar_ready=%d", init_done_, radar_ready_);

  // GPIO Reset
  perform_reset_();
  ESP_LOGE(TAG, "### SETUP: perform_reset_ done");
}

void FP2Component::perform_reset_() {
  if (reset_pin_ != nullptr) {
    ESP_LOGE(TAG, "### Performing radar reset via GPIO13...");
    reset_pin_->setup();
    reset_pin_->digital_write(false);
    delay(500);  // Hold reset LOW for 500ms (was 100ms — too short for reliable reset)
    reset_pin_->digital_write(true);
    delay(1000);  // Wait 1s for radar to start boot sequence

    // Flush any stale UART data from before the reset
    int flushed = 0;
    while (available()) {
      uint8_t byte;
      read_byte(&byte);
      flushed++;
    }
    ESP_LOGE(TAG, "### Radar reset done, flushed %d stale UART bytes", flushed);
  } else {
    ESP_LOGE(TAG, "### No Reset Pin configured!");
  }

  if (this->location_report_switch_ != nullptr) {
    // Default to OFF for internal state until we know better, or optimistic?
    // Device usually starts with it OFF.
    this->location_report_switch_->publish_state(false);
  }
}

void FP2Component::set_location_reporting_enabled(bool enabled) {
  this->location_reporting_active_ = enabled;
  // Only toggle the publish flag — do NOT send LOCATION_REPORT_ENABLE=0 to
  // the radar because people counting depends on location tracking internally.
  // The radar always has location reporting enabled (set in init).
  if (!enabled && this->target_tracking_sensor_ != nullptr) {
    this->target_tracking_sensor_->set_has_state(false);
  }
}

void FP2LocationSwitch::write_state(bool state) {
  if (this->parent_ != nullptr) {
    this->parent_->set_location_reporting_enabled(state);
  }
  this->publish_state(state);
}

void FP2Component::trigger_edge_calibration() {
  ESP_LOGI(TAG, "Starting edge auto-calibration...");
  enqueue_command_(OpCode::WRITE, AttrId::EDGE_AUTO_ENABLE, true);
}

void FP2Component::trigger_interference_calibration() {
  ESP_LOGI(TAG, "Starting interference auto-calibration...");
  enqueue_command_(OpCode::WRITE, AttrId::INTERFERENCE_AUTO_ENABLE, true);
}

void FP2CalibrateEdgeButton::press_action() {
  if (this->parent_ != nullptr) {
    this->parent_->trigger_edge_calibration();
  }
}

void FP2ClearEdgeButton::press_action() {
  if (this->parent_ != nullptr) {
    this->parent_->clear_edge_calibration();
  }
}

void FP2ClearInterferenceButton::press_action() {
  if (this->parent_ != nullptr) {
    this->parent_->clear_interference_calibration();
  }
}

void FP2Component::clear_edge_calibration() {
  // Reset to full-coverage default grid (not empty — empty disables presence detection)
  ESP_LOGI(TAG, "Resetting room boundary to full-coverage default...");
  GridMap default_grid;
  default_grid.fill(0);
  for (int r = 0; r < 14; r++) {
    default_grid[r * 2] = 0x3F;      // cols 2-7: bits 13-8
    default_grid[r * 2 + 1] = 0xFF;  // cols 8-15: all bits
  }
  enqueue_command_blob2_(AttrId::EDGE_MAP,
      std::vector<uint8_t>(default_grid.begin(), default_grid.end()));
  if (edge_label_grid_sensor_ != nullptr) {
    edge_label_grid_sensor_->publish_state(grid_to_hex_card_format(default_grid));
  }
}

void FP2Component::clear_interference_calibration() {
  ESP_LOGI(TAG, "Clearing interference calibration (sending empty grid)...");
  std::vector<uint8_t> empty_grid(40, 0x00);
  enqueue_command_blob2_(AttrId::INTERFERENCE_MAP, empty_grid);
  if (interference_grid_sensor_ != nullptr) {
    GridMap empty{};
    interference_grid_sensor_->publish_state(grid_to_hex_card_format(empty));
  }
}

void FP2CalibrateInterferenceButton::press_action() {
  if (this->parent_ != nullptr) {
    this->parent_->trigger_interference_calibration();
  }
}

void FP2Component::loop() {
  // During OTA, bypass normal protocol and run XMODEM state machine
  if (ota_state_ != OtaState::IDLE) {
    ota_loop_();
    return;
  }

  int bytes_read = 0;
  while (available()) {
    uint8_t byte;
    read_byte(&byte);
    handle_incoming_byte_(byte);
    bytes_read++;
  }


  if (debug_mode_ && bytes_read > 0) {
    ESP_LOGD(TAG, "[DBG] rd=%d init=%d rdy=%d hb=%u q=%d ack=%u drop=%u init@%u rdy_gate=%d",
             bytes_read, init_done_, radar_ready_, last_heartbeat_millis_,
             (int)command_queue_.size(), diag_acks, diag_drops, diag_init_at,
             diag_init_used_ready);
  }

  check_initialization_();
  process_command_queue_();
}

void FP2Component::check_initialization_() {
  // Send init on first heartbeat, then re-send 45 seconds later
  // (radar ACKs commands during boot but doesn't apply them)
  static bool reinit_done = false;

  if (init_done_ && !reinit_done && millis() > 45000) {
    ESP_LOGE(TAG, "### RE-INIT at 45s: resending all commands to fully-booted radar");
    reinit_done = true;
    init_done_ = false;
    diag_acks = 0;
    diag_drops = 0;
    diag_init_at = 0;
    // Fall through to init code below
  }

  if (init_done_)
    return;

  if (last_heartbeat_millis_ == 0)
    return;

  diag_init_at = millis();
  diag_init_used_ready = reinit_done;
  ESP_LOGE(TAG, "### === INIT FIRING === uptime=%u reinit=%d heartbeat=%u",
           millis(), reinit_done, last_heartbeat_millis_);
    init_done_ = true;

    // 1. Basic Settings
    enqueue_command_(OpCode::WRITE, AttrId::MONITOR_MODE, (uint8_t) 0);
    enqueue_command_(OpCode::WRITE, AttrId::LEFT_RIGHT_REVERSE,
                     (uint8_t)(left_right_reverse_ ? 2 : 0));
    enqueue_command_(OpCode::WRITE, AttrId::PRESENCE_DETECT_SENSITIVITY, global_presence_sensitivity_);
    enqueue_command_(OpCode::WRITE, AttrId::CLOSING_SETTING, (uint8_t) 1);
    enqueue_command_(OpCode::WRITE, AttrId::ZONE_CLOSE_AWAY_ENABLE, (uint16_t) 0x0001);
    enqueue_command_(OpCode::WRITE, AttrId::FALL_SENSITIVITY, fall_detection_sensitivity_);
    enqueue_command_(OpCode::WRITE, AttrId::PEOPLE_COUNT_REPORT_ENABLE, true); // BOOL
    enqueue_command_(OpCode::WRITE, AttrId::PEOPLE_NUMBER_ENABLE, true); // BOOL
    enqueue_command_(OpCode::WRITE, AttrId::TARGET_TYPE_ENABLE, true); // BOOL
    enqueue_command_(OpCode::WRITE, AttrId::POSTURE_REPORT_ENABLE, true); // BOOL
    enqueue_command_(OpCode::WRITE, AttrId::SLEEP_REPORT_ENABLE, true); // BOOL
    // Location reporting must stay enabled at the radar level — people counting
    // depends on it internally. The Report Targets switch controls whether
    // target data is published to the text sensor, not whether the radar tracks.
    enqueue_command_(OpCode::WRITE, AttrId::LOCATION_REPORT_ENABLE, (uint8_t) 1);
    enqueue_command_(OpCode::WRITE, AttrId::WALL_CORNER_POS, mounting_position_);
    enqueue_command_(OpCode::WRITE, AttrId::DWELL_TIME_ENABLE, (uint8_t) 0); // dwell time enable
    enqueue_command_(OpCode::WRITE, AttrId::WALK_DISTANCE_ENABLE,
                     (uint8_t)(walking_distance_sensor_ != nullptr ? 1 : 0));
    enqueue_command_(OpCode::WRITE, AttrId::THERMO_EN, true);
    enqueue_command_(OpCode::WRITE, AttrId::THERMO_DATA, (uint8_t) 1);

    // 2. Grids
    if (has_interference_grid_) {
      // 0x0110 Interference Source
      enqueue_command_blob2_(AttrId::INTERFERENCE_MAP,
                             std::vector<uint8_t>(interference_grid_.begin(),
                                                  interference_grid_.end()));
    }
    if (has_exit_grid_) {
      // 0x0109 Enter/Exit Label
      enqueue_command_blob2_(
          AttrId::ENTRY_EXIT_MAP, std::vector<uint8_t>(exit_grid_.begin(), exit_grid_.end()));
    }
    if (has_edge_grid_) {
      // 0x0107 Edge Label
      enqueue_command_blob2_(
          AttrId::EDGE_MAP, std::vector<uint8_t>(edge_grid_.begin(), edge_grid_.end()));
    } else {
      // Send full-coverage edge grid by default — without an edge grid the radar
      // will not send global presence/motion reports (0x0103, 0x0104)
      ESP_LOGI(TAG, "No edge_grid configured, sending full-coverage default");
      GridMap full_grid;
      // Set all 14 active rows (0-13) to full width: cols 2-15 active
      // Binary: 0011 1111 1111 1100 = 0x3FFC
      full_grid.fill(0);
      for (int r = 0; r < 14; r++) {
        full_grid[r * 2] = 0x3F;
        full_grid[r * 2 + 1] = 0xFF;
      }
      enqueue_command_blob2_(AttrId::EDGE_MAP,
          std::vector<uint8_t>(full_grid.begin(), full_grid.end()));
    }

    // 3. Zones
    std::vector<uint8_t> activations(32, 0);
    for (const auto &zone : zones_) {
      // a. Send Zone Detect Setting (0x0114)
      // Structure: [ZoneID] [40 byte Map]
      std::vector<uint8_t> payload;
      payload.push_back(zone->id);
      payload.insert(payload.end(), zone->grid.begin(), zone->grid.end());
      enqueue_command_blob2_(AttrId::ZONE_MAP, payload);

      // b. Send Sensitivity (0x0151)
      // Structure: UINT16 (High=ID, Low=Sens)
      uint16_t sens_val = (zone->id << 8) | (zone->sensitivity & 0xFF);
      enqueue_command_(OpCode::WRITE, AttrId::ZONE_SENSITIVITY, sens_val);

      activations[zone->id] = zone->id;
    }

    enqueue_command_blob2_(AttrId::ZONE_ACTIVATION_LIST, activations);

    for (const auto &zone : zones_) {
        // Close/Away Enable default?
        // Trace: 0x0153 Zone Close Away Enable.
        // We can enable it by default for now or add config options later.
        enqueue_command_(OpCode::WRITE, AttrId::ZONE_CLOSE_AWAY_ENABLE, (uint16_t)((zone->id << 8) | 1));
    }

    // enqueue_read_((AttrId) 0x302); // Read radar flash ID attribute
    // enqueue_read_((AttrId) 0x303); // Read radar ID attribute
    // enqueue_read_((AttrId) 0x305); // Read radar calibration result attribute

    // 5. Publish grid sensors once initialization completes
    ESP_LOGI(TAG, "Publishing grid sensors: has_edge=%d edge_sensor=%p has_exit=%d exit_sensor=%p has_interference=%d interference_sensor=%p",
             has_edge_grid_, edge_label_grid_sensor_, has_exit_grid_, entry_exit_grid_sensor_, has_interference_grid_, interference_grid_sensor_);

    if (has_edge_grid_ && edge_label_grid_sensor_ != nullptr) {
      ESP_LOGI(TAG, "Publishing edge label grid");
      edge_label_grid_sensor_->publish_state(grid_to_hex_card_format(edge_grid_));
    } else {
      ESP_LOGW(TAG, "NOT publishing edge label grid (has_grid=%d, sensor=%p)", has_edge_grid_, edge_label_grid_sensor_);
    }

    if (has_exit_grid_ && entry_exit_grid_sensor_ != nullptr) {
      ESP_LOGI(TAG, "Publishing entry/exit grid");
      entry_exit_grid_sensor_->publish_state(grid_to_hex_card_format(exit_grid_));
    } else {
      ESP_LOGW(TAG, "NOT publishing entry/exit grid (has_grid=%d, sensor=%p)", has_exit_grid_, entry_exit_grid_sensor_);
    }

    if (has_interference_grid_ && interference_grid_sensor_ != nullptr) {
      ESP_LOGI(TAG, "Publishing interference grid");
      interference_grid_sensor_->publish_state(grid_to_hex_card_format(interference_grid_));
    } else {
      ESP_LOGW(TAG, "NOT publishing interference grid (has_grid=%d, sensor=%p)", has_interference_grid_, interference_grid_sensor_);
    }

    // 6. Publish zone map sensors
    for (const auto &zone : zones_) {
      if (zone->map_sensor != nullptr) {
        zone->map_sensor->publish_state(grid_to_hex_card_format(zone->grid));
      }
    }

    // 7. Publish known initial states after reset
    // After radar reset, we know there is no occupancy/motion detected yet
    ESP_LOGI(TAG, "Publishing initial states (no occupancy after reset)");
    for (const auto &zone : zones_) {
      zone->publish_presence(false);
      zone->publish_motion(false);
      if (zone->posture_sensor != nullptr) {
        zone->posture_sensor->publish_state("none");
      }
    }

    if (global_presence_sensor_ != nullptr) global_presence_sensor_->publish_state(false);
    if (global_motion_sensor_ != nullptr) global_motion_sensor_->publish_state(false);
    if (people_count_sensor_ != nullptr) people_count_sensor_->publish_state(0);
    if (fall_detection_sensor_ != nullptr) fall_detection_sensor_->publish_state(false);
    if (sleep_state_sensor_ != nullptr) sleep_state_sensor_->publish_state("none");
    if (sleep_presence_sensor_ != nullptr) sleep_presence_sensor_->publish_state(false);

    // Clear target tracking state - no targets after reset
    if (target_tracking_sensor_ != nullptr) {
      target_tracking_sensor_->set_has_state(false);
    }

  ESP_LOGE(TAG, "=== INIT COMPLETE: %d commands queued (uptime=%u ms) ===",
           (int)command_queue_.size(), millis());
}

void FP2Component::process_command_queue_() {
  uint32_t now = millis();

  // If waiting for ACK
  if (waiting_for_ack_attr_id_ != AttrId::INVALID) {
    if (now - last_command_sent_millis_ > ACK_TIMEOUT_MS) {
      // Timeout
      if (!command_queue_.empty()) {
        auto &cmd = command_queue_.front();
        cmd.retry_count++;
        if (cmd.retry_count >= MAX_RETRIES) {
          diag_drops++;
          ESP_LOGE(TAG, "### TIMEOUT DROP: 0x%04X after %d retries, queue=%d",
                   (uint16_t) cmd.attr_id, MAX_RETRIES, (int)command_queue_.size());
          command_queue_.pop_front();
          waiting_for_ack_attr_id_ = AttrId::INVALID;
        } else {
          ESP_LOGE(TAG, "### TIMEOUT RETRY: 0x%04X retry %d/%d",
                   (uint16_t) cmd.attr_id, cmd.retry_count, MAX_RETRIES);
          // Resend handled by send_next_command_ logic once waiting state calls
          // reset? Actually, we should just resend immediately
          send_next_command_();
        }
      } else {
        // Queue empty but waiting state mismatch?
        waiting_for_ack_attr_id_ = AttrId::INVALID;
      }
    }
    return; // Still waiting
  }

  // Not waiting, send next
  if (!command_queue_.empty()) {
    send_next_command_();
  }
}

void FP2Component::send_next_command_() {
  if (command_queue_.empty())
    return;

  auto &cmd = command_queue_.front();
  static uint8_t next_tx_seq = 0;

  ESP_LOGE(TAG, "### TX: op=%d SubID=0x%04X len=%d retry=%d queue=%d",
           (int)cmd.type, (uint16_t)cmd.attr_id, cmd.data.size(),
           cmd.retry_count, (int)command_queue_.size());

  // Build frame: [Sync][Ver][Ver][Seq][Op][Len][Len][Check][Payload][CRC][CRC]
  std::vector<uint8_t> frame;
  frame.push_back(0x55);  // Sync
  frame.push_back(0x00);  // Version High
  frame.push_back(0x01);  // Version Low
  frame.push_back(next_tx_seq++);
  frame.push_back((uint8_t)cmd.type);

  uint16_t len = cmd.data.size();
  frame.push_back((len >> 8) & 0xFF);
  frame.push_back(len & 0xFF);

  // Header checksum: NOT((Sum(bytes 0-6) - 1))
  uint8_t sum = 0;
  for (int i = 0; i < 7; i++)
    sum += frame[i];
  frame.push_back((uint8_t)(~((sum - 1))));

  // Append payload
  frame.insert(frame.end(), cmd.data.begin(), cmd.data.end());

  // Append CRC16 (Little Endian)
  uint16_t crc = crc16(frame.data(), frame.size());
  frame.push_back(crc & 0xFF);
  frame.push_back((crc >> 8) & 0xFF);

  write_array(frame);
  last_command_sent_millis_ = millis();

  // Only WRITE commands expect an ACK from the radar
  // ACK and Reverse Read Response packets don't get ACKed
  if (cmd.type == OpCode::WRITE) {
    waiting_for_ack_attr_id_ = cmd.attr_id;
  } else {
    command_queue_.pop_front();
  }
}

void FP2Component::send_ack_(AttrId attr_id) {
  FP2Command cmd;
  cmd.type = OpCode::ACK;
  cmd.attr_id = attr_id;
  cmd.retry_count = 0;
  cmd.last_send_time = 0;

  // ACK payload: [SubID 2 bytes] [DataType VOID]
  cmd.data.push_back((((uint16_t) attr_id) >> 8) & 0xFF);
  cmd.data.push_back(((uint16_t) attr_id) & 0xFF);
  cmd.data.push_back(0x03);  // DataType: VOID

  // ACKs are high priority - push to front of queue
  command_queue_.push_front(cmd);
}

void FP2Component::send_reverse_response_(AttrId attr_id, uint8_t byte_val) {
  FP2Command cmd;
  cmd.type = OpCode::READ;  // Reverse Read Response uses READ opcode
  cmd.attr_id = attr_id;
  cmd.retry_count = 0;

  // Payload: [SubID 2 bytes] [DataType UINT8] [Value 1 byte]
  cmd.data.push_back((((uint16_t) attr_id) >> 8) & 0xFF);
  cmd.data.push_back(((uint16_t) attr_id) & 0xFF);
  cmd.data.push_back(0x00);  // DataType: UINT8
  cmd.data.push_back(byte_val);

  command_queue_.push_back(cmd);
}

void FP2Component::handle_incoming_byte_(uint8_t byte) {
  if (state_ == SYNC) {
    if (byte == 0x55) {
      state_ = VER_H;
      rx_payload_.clear();
      header_sum_ = byte; // Start sum
    }
    return;
  }

  // Update sum for header fields (0..6)
  if (state_ < H_CHECK) {
    header_sum_ += byte;
  }

  switch (state_) {
  case VER_H:
    state_ = (byte == 0x00) ? VER_L : SYNC;
    break;
  case VER_L:
    state_ = (byte == 0x01) ? SEQ : SYNC;
    break;
  case SEQ:
    rx_seq_ = byte;
    state_ = OPCODE;
    break;
  case OPCODE:
    rx_opcode_ = byte;
    state_ = LEN_H;
    break;
  case LEN_H:
    rx_len_ = byte << 8;
    state_ = LEN_L;
    break;
  case LEN_L:
    rx_len_ |= byte;
    state_ = H_CHECK;
    break;

  case H_CHECK: {
    uint8_t expected = (uint8_t)(~((header_sum_ - 1)));
    if (byte != expected) {
      ESP_LOGW(TAG, "Header Checksum Fail: Exp %02X, Got %02X", expected, byte);
      state_ = SYNC;
    } else {
      if (rx_len_ > 4096) { // Sanity check, increased for potential BLOBs
        state_ = SYNC;
      } else if (rx_len_ == 0) {
        state_ = CRC_L;
      } else {
        state_ = PAYLOAD;
      }
    }
    break;
  }

  case PAYLOAD:
    rx_payload_.push_back(byte);
    if (rx_payload_.size() == rx_len_) {
      state_ = CRC_L;
    }
    break;

  case CRC_L:
    rx_crc_ = byte;
    state_ = CRC_H;
    break;

  case CRC_H: {
    rx_crc_ |= (byte << 8);
    // Validate CRC
    std::vector<uint8_t> frame;
    frame.push_back(0x55);
    frame.push_back(0x00);
    frame.push_back(0x01);
    frame.push_back(rx_seq_);
    frame.push_back(rx_opcode_);
    frame.push_back((rx_len_ >> 8) & 0xFF);
    frame.push_back(rx_len_ & 0xFF);
    frame.push_back((uint8_t)(~((header_sum_ - 1))));
    frame.insert(frame.end(), rx_payload_.begin(), rx_payload_.end());

    uint16_t calc = crc16(frame.data(), frame.size());
    if (calc == rx_crc_) {
      // Parse Payload
      // Note: rx_len_ >= 2 to allow Reverse Read Requests (RESPONSE with just SubID, no data)
      if (rx_len_ >= 2) {
        uint16_t attr_id_int = (rx_payload_[0] << 8) | rx_payload_[1];
        AttrId attr_id = (AttrId) attr_id_int;
        // DataType = rx_payload_[2] (if present)
        handle_parsed_frame_(rx_opcode_, attr_id, rx_payload_);
      }
    } else {
      ESP_LOGW(TAG, "CRC Fail: Exp %04X, Got %04X", calc, rx_crc_);
    }
    state_ = SYNC;
    break;
  }

  default:
    state_ = SYNC;
  }
}

void FP2Component::handle_parsed_frame_(uint8_t type, AttrId attr_id,
                                        const std::vector<uint8_t> &payload) {
  OpCode op = (OpCode)type;

  if (debug_mode_) {
    ESP_LOGI(TAG, "[DBG] RX frame: op=%d SubID=0x%04X len=%d", type, (uint16_t)attr_id, payload.size());
  }

  switch (op) {
    case OpCode::ACK:
      handle_ack_(attr_id);
      break;
    case OpCode::REPORT:
      handle_report_(attr_id, payload);
      break;
    case OpCode::RESPONSE:
      handle_response_(attr_id, payload);
      break;
    default:
      ESP_LOGW(TAG, "Unhandled OpCode: %d", type);
      break;
  }
}

void FP2Component::handle_ack_(AttrId attr_id) {
  if (waiting_for_ack_attr_id_ == attr_id) {
    diag_acks++;
    ESP_LOGE(TAG, "### ACK OK: 0x%04X (queue=%d)", (uint16_t) attr_id, (int)command_queue_.size());
    waiting_for_ack_attr_id_ = AttrId::INVALID;
    if (!command_queue_.empty()) {
      command_queue_.pop_front();
    }
  } else {
    ESP_LOGW(TAG, "Unexpected ACK 0x%04X (Waiting for 0x%04X)", attr_id,
             (uint16_t) waiting_for_ack_attr_id_);
  }
}

void FP2Component::handle_report_(AttrId attr_id, const std::vector<uint8_t> &payload) {
  // Send ACK for all reports except heartbeat
  if (attr_id != AttrId::RADAR_SW_VERSION) {
    send_ack_(attr_id);
  }

  // Process specific report types
  switch (attr_id) {
    case AttrId::RADAR_SW_VERSION:  // Heartbeat
      if (last_heartbeat_millis_ == 0) {
        ESP_LOGE(TAG, "### FIRST HEARTBEAT at uptime=%u ms, init_done=%d radar_ready=%d",
                 millis(), init_done_, radar_ready_);
      }
      last_heartbeat_millis_ = millis();
      if (payload.size() >= 4) {
        if (payload[2] == 0x00) {
          // Version byte is a build number (e.g. 99 = latest known fw)
          // Stock firmware uses a lookup table for display strings
          auto ver_str = std::to_string(payload[3]);
          if (radar_software_sensor_ != nullptr) {
              if (radar_software_sensor_->state != ver_str) {
                  radar_software_sensor_->publish_state(ver_str);
              }
          }
        }
      }
      break;

    case AttrId::WORK_MODE:
        if (payload.size() == 4 && payload[2] == 0x00) {
            ESP_LOGI(TAG, "Received work mode report: %u", payload[3]);
        }
        break;

    case AttrId::DETECT_ZONE_MOTION:
        // Payload: UINT16 [zone_id, state]
        // Stock firmware stores raw value; we map to binary
        if (payload.size() == 5 && payload[2] == 0x01) {
            uint8_t zone_id = payload[3];
            uint8_t state = payload[4];
            if (zone_id == 0) break;  // Zone 0 is invalid (stock rejects it)
            ESP_LOGD(TAG, "Zone Motion Report: Zone %u = %u", zone_id, state);

            for (auto &z : zones_) {
              if (z->id == zone_id) {
                // State values: 0=motion start, even=active, odd=inactive
                bool active = (state % 2 == 0);
                z->publish_motion(active);
                // Infer presence from motion — 0x0142 may not fire on boot
                if (active) {
                    z->publish_presence(true);
                }
                break;
              }
            }
        }
        break;

    case AttrId::MOTION_DETECT:
        // Stock firmware: values 0,2,4,6,7 are "active" motion states
        // Value 0 = motion entering, 2 = active, 4 = exiting
        // Odd values (1,3,5) = no motion / inactive
        if (payload.size() == 4 && payload[2]  == 0x00) {
            uint8_t state = payload[3];
            if (global_motion_sensor_ != nullptr) {
                // Even states (0,2,4,6) = motion active; odd states = inactive
                global_motion_sensor_->publish_state(state % 2 == 0);
            }
            ESP_LOGD(TAG, "Global motion report: state=%u active=%s",
                     state, (state % 2 == 0) ? "yes" : "no");
        }
        break;

    case AttrId::PRESENCE_DETECT:
        if (payload.size() == 4 && payload[2]  == 0x00) {
            uint8_t state = payload[3];
            // Stock firmware: 0 = empty, non-zero = occupied
            // (NOT the same as motion which uses even/odd)
            bool present = (state != 0);
            global_presence_active_ = present;
            if (global_presence_sensor_ != nullptr) {
                global_presence_sensor_->publish_state(present);
            }
            ESP_LOGD(TAG, "Global presence report: state=%u present=%s",
                     state, present ? "yes" : "no");
            // Stock firmware: when presence goes OFF, clear all zone states
            if (!present) {
                for (auto &z : zones_) {
                    z->publish_presence(false);
                    z->publish_motion(false);
                    if (z->zone_people_count_sensor != nullptr) {
                        z->zone_people_count_sensor->publish_state(0);
                    }
                    if (z->posture_sensor != nullptr) {
                        z->posture_sensor->publish_state("none");
                    }
                }
                if (people_count_sensor_ != nullptr) {
                    people_count_sensor_->publish_state(0);
                }
                // Clear sleep-related sensors
                if (sleep_state_sensor_ != nullptr) {
                    sleep_state_sensor_->publish_state("none");
                }
                if (sleep_presence_sensor_ != nullptr) {
                    sleep_presence_sensor_->publish_state(false);
                }
                if (heart_rate_sensor_ != nullptr) {
                    heart_rate_sensor_->publish_state(NAN);
                }
                if (respiration_rate_sensor_ != nullptr) {
                    respiration_rate_sensor_->publish_state(NAN);
                }
                if (heart_rate_dev_sensor_ != nullptr) {
                    heart_rate_dev_sensor_->publish_state(NAN);
                }
            }
        }
        break;

    case AttrId::ONTIME_PEOPLE_NUMBER:
        if (payload.size() == 7 && payload[2]  == 0x02) {
            uint32_t count = ((uint32_t) payload[3]) << 24
                | ((uint32_t) payload[4]) << 16
                | ((uint32_t) payload[5]) << 8
                | ((uint32_t) payload[6]);
            ESP_LOGI(TAG, "Received ontime people number report: %u", count);
            if (people_count_sensor_ != nullptr) {
                people_count_sensor_->publish_state((float) count);
            }
        }
        break;

    case AttrId::REALTIME_PEOPLE:
        if (payload.size() >= 4 && payload[2] == 0x02) {
            uint32_t count = ((uint32_t) payload[3]) << 24
                | ((uint32_t) payload[4]) << 16
                | ((uint32_t) payload[5]) << 8
                | ((uint32_t) payload[6]);
            ESP_LOGD(TAG, "Received realtime people report: %u", count);
            // Use same sensor as ontime — realtime is more frequent
            if (people_count_sensor_ != nullptr) {
                people_count_sensor_->publish_state((float) count);
            }
        }
        break;

    case AttrId::REALTIME_COUNT:
        if (payload.size() >= 4 && payload[2] == 0x02) {
            uint32_t count = ((uint32_t) payload[3]) << 24
                | ((uint32_t) payload[4]) << 16
                | ((uint32_t) payload[5]) << 8
                | ((uint32_t) payload[6]);
            ESP_LOGD(TAG, "Received realtime count report: %u", count);
        }
        break;

    case AttrId::ZONE_PEOPLE_NUMBER:
        // Native per-zone people count from radar
        if (payload.size() >= 5 && payload[2] == 0x01) {
            uint8_t zone_id = payload[3];
            uint8_t count = payload[4];
            if (zone_id == 0) break;  // Zone 0 is invalid
            ESP_LOGD(TAG, "Zone People Number: Zone %d = %u", zone_id, count);
            for (auto &z : zones_) {
                if (z->id == zone_id) {
                    if (z->zone_people_count_sensor != nullptr) {
                        float current = z->zone_people_count_sensor->get_raw_state();
                        if (std::isnan(current) || (int)current != count) {
                            z->zone_people_count_sensor->publish_state((float)count);
                        }
                    }
                    // Infer presence from people count — 0x0142 may not fire on boot
                    z->publish_presence(count > 0);
                    break;
                }
            }
        }
        break;

    case AttrId::FALL_DETECTION:
        if (payload.size() >= 4 && payload[2] == 0x00) {
            uint8_t state = payload[3];
            ESP_LOGI(TAG, "Fall detection report: %u", state);
            if (fall_detection_sensor_ != nullptr) {
                fall_detection_sensor_->publish_state(state != 0);
            }
        }
        break;

    case AttrId::SLEEP_STATE:
        // Sleep state: UINT8 (publishes on change in stock firmware)
        // Values observed: 0=awake, 1=light sleep, 2=deep sleep (TBD)
        if (payload.size() >= 4 && payload[2] == 0x00) {
            uint8_t state = payload[3];
            const char *state_str;
            switch (state) {
                case 0: state_str = "awake"; break;
                case 1: state_str = "light"; break;
                case 2: state_str = "deep"; break;
                default: state_str = "unknown"; break;
            }
            ESP_LOGI(TAG, "Sleep state: %u (%s)", state, state_str);
            if (sleep_state_sensor_ != nullptr) {
                sleep_state_sensor_->publish_state(state_str);
            }
        }
        break;

    case AttrId::SLEEP_PRESENCE:
        // Sleep zone presence: UINT8
        if (payload.size() >= 4 && payload[2] == 0x00) {
            uint8_t state = payload[3];
            ESP_LOGI(TAG, "Sleep presence: %u", state);
            if (sleep_presence_sensor_ != nullptr) {
                sleep_presence_sensor_->publish_state(state != 0);
            }
        }
        break;

    case AttrId::SLEEP_IN_OUT:
        // Sleep zone entry/exit: UINT8
        if (payload.size() >= 4 && payload[2] == 0x00) {
            uint8_t state = payload[3];
            ESP_LOGI(TAG, "Sleep in/out: %u (%s)", state, state != 0 ? "in" : "out");
            // Update sleep presence from in/out events too
            if (sleep_presence_sensor_ != nullptr) {
                sleep_presence_sensor_->publish_state(state != 0);
            }
        }
        break;

    case AttrId::SLEEP_DATA:
        // Sleep tracking data: BLOB2 containing IEEE 754 floats in LE byte order.
        // Confirmed from radar firmware debug strings at 0x1a1394:
        //   "heartRate = %.0f"    (offset 0, 4 bytes LE float)
        //   "breathRate = %.0f"   (offset 4, 4 bytes LE float)
        //   "heartDev = %.0f"     (offset 8, 4 bytes LE float — heart rate deviation)
        //   "breathingDev = %.0f" (offset 12, 4 bytes LE float — breath deviation)
        // Stock ESP32 firmware copies first 12 bytes (3 floats), drops breathingDev.
        // Radar firmware built from TI Vital Signs demo at:
        //   C:/ti/mmwave_industrial_toolbox_4_11_0/labs/Vital_Signs/
        if (payload.size() >= 5 && payload[2] == 0x06) {
            uint16_t blob_len = (payload[3] << 8) | payload[4];
            if (blob_len >= 12 && payload.size() >= 17) {
                // Parse as LE IEEE 754 floats (radar is ARM Cortex-R4F, LE)
                float heart_rate, resp_rate, heart_dev;
                memcpy(&heart_rate, &payload[5], 4);
                memcpy(&resp_rate, &payload[9], 4);
                memcpy(&heart_dev, &payload[13], 4);
                ESP_LOGI(TAG, "Sleep data: heart=%.1f bpm, resp=%.1f br/min, heartDev=%.1f",
                         heart_rate, resp_rate, heart_dev);
                if (heart_rate_sensor_ != nullptr) {
                    heart_rate_sensor_->publish_state(heart_rate);
                }
                if (respiration_rate_sensor_ != nullptr) {
                    respiration_rate_sensor_->publish_state(resp_rate);
                }
                if (heart_rate_dev_sensor_ != nullptr) {
                    // Third field is heart rate deviation, not "body movement"
                    // Repurposed as a sleep quality indicator
                    heart_rate_dev_sensor_->publish_state(heart_dev);
                }
            } else {
                // Log raw hex for unexpected sizes
                ESP_LOGW(TAG, "Sleep data unexpected size %d bytes", blob_len);
            }
        }
        break;

    case AttrId::SLEEP_EVENT:
        // Sleep event: UINT8 (type of sleep event)
        if (payload.size() >= 4 && payload[2] == 0x00) {
            ESP_LOGI(TAG, "Sleep event: type=%u", payload[3]);
        }
        break;

    case AttrId::TARGET_POSTURE:
        if (payload.size() >= 5 && payload[2] == 0x01) {
            uint8_t zone_id = payload[3];
            uint8_t posture = payload[4];
            if (zone_id == 0) break;  // Zone 0 is invalid
            const char *posture_str;
            switch (posture) {
                case 0: posture_str = "none"; break;
                case 1: posture_str = "standing"; break;
                case 2: posture_str = "sitting"; break;
                case 3: posture_str = "lying"; break;
                default: posture_str = "unknown"; break;
            }
            ESP_LOGD(TAG, "Target Posture: Zone %d = %s", zone_id, posture_str);
            for (auto &z : zones_) {
                if (z->id == zone_id && z->posture_sensor != nullptr) {
                    z->posture_sensor->publish_state(posture_str);
                    break;
                }
            }
        }
        break;

    case AttrId::WALK_DISTANCE_ALL:
        // Walking distance: UINT32 raw value, convert to metres
        // Stock firmware reads as uint32, converts to float via math function
        if (payload.size() >= 7 && payload[2] == 0x02) {
            uint32_t raw = ((uint32_t)payload[3] << 24) | ((uint32_t)payload[4] << 16)
                         | ((uint32_t)payload[5] << 8) | payload[6];
            // Stock firmware divides by constant 100.0 (at Ram400d0ff4).
            // Raw value is in centimetres; convert to metres.
            float distance_m = (float)raw / 100.0f;
            ESP_LOGD(TAG, "Walking distance: raw=%u (%.2f m)", raw, distance_m);
            if (walking_distance_sensor_ != nullptr) {
                walking_distance_sensor_->publish_state(distance_m);
            }
        }
        break;

    case AttrId::ZONE_PRESENCE:  // Zone Presence
        // Payload: [SubID 2B] [Type 0x01(UINT16)] [ZoneID] [State]
        if (payload.size() >= 5 && payload[2] == 0x01) {
            uint8_t zone_id = payload[3];
            uint8_t state = payload[4];
            if (zone_id == 0) break;  // Zone 0 is invalid (stock rejects it)
            ESP_LOGI(TAG, "Zone Presence Report: Zone %d = %s (raw=%u)", zone_id, state ? "ON" : "OFF", state);

            for (auto &z : zones_) {
                if (z->id == zone_id) {
                    z->publish_presence(state != 0);
                    break;
                }
            }
        }
        break;

    case AttrId::LOCATION_TRACKING_DATA:  // Location Tracking Data
      handle_location_tracking_report_(payload);
      break;

    case AttrId::TEMPERATURE: {
      // Temperature reports only arrive after radar finishes booting (~38s).
      // If init already fired during boot (commands ACKed but not applied),
      // re-run init now that the radar is truly ready.
      static bool first_temp_seen = false;
      if (!first_temp_seen) {
        first_temp_seen = true;
        radar_ready_ = true;
        ESP_LOGE(TAG, "### FIRST TEMPERATURE at uptime=%u — radar boot complete, init_done=%d",
                 millis(), init_done_);
        if (init_done_) {
          ESP_LOGE(TAG, "### RE-INIT: resending all config commands to fully-booted radar");
          init_done_ = false;
          diag_acks = 0;
          diag_drops = 0;
          diag_init_at = 0;
        }
      }
    }
      handle_temperature_report_(payload);
      break;

    case AttrId::EDGE_AUTO_SET:
        // Auto-calibration result: edge boundary grid (BLOB2, 40 bytes)
        if (payload.size() >= 5 && payload[2] == 0x06) {
            uint16_t blob_len = (payload[3] << 8) | payload[4];
            if (blob_len == 40 && payload.size() >= 45) {
                ESP_LOGI(TAG, "Received auto-calibrated edge grid (%d bytes)", blob_len);
                std::copy(payload.begin() + 5, payload.begin() + 45, edge_grid_.begin());
                has_edge_grid_ = true;
                // Apply to radar
                enqueue_command_blob2_(AttrId::EDGE_MAP,
                    std::vector<uint8_t>(edge_grid_.begin(), edge_grid_.end()));
                // Update card sensor
                if (edge_label_grid_sensor_ != nullptr) {
                    edge_label_grid_sensor_->publish_state(grid_to_hex_card_format(edge_grid_));
                }
            }
        }
        break;

    case AttrId::INTERFERENCE_AUTO_SET:
        // Auto-calibration result: interference grid (BLOB2, 40 bytes)
        if (payload.size() >= 5 && payload[2] == 0x06) {
            uint16_t blob_len = (payload[3] << 8) | payload[4];
            if (blob_len == 40 && payload.size() >= 45) {
                ESP_LOGI(TAG, "Received auto-calibrated interference grid (%d bytes)", blob_len);
                std::copy(payload.begin() + 5, payload.begin() + 45, interference_grid_.begin());
                has_interference_grid_ = true;
                // Apply to radar
                enqueue_command_blob2_(AttrId::INTERFERENCE_MAP,
                    std::vector<uint8_t>(interference_grid_.begin(), interference_grid_.end()));
                // Update card sensor
                if (interference_grid_sensor_ != nullptr) {
                    interference_grid_sensor_->publish_state(grid_to_hex_card_format(interference_grid_));
                }
            }
        }
        break;

    default:
      // Unknown report type
      ESP_LOGW(TAG, "Unhandled report 0x%04X", (uint16_t) attr_id);
      break;
  }
}

void FP2Component::handle_location_tracking_report_(const std::vector<uint8_t> &payload) {
  // Ignore stale data if location reporting has been disabled
  if (!this->location_reporting_active_) {
    return;
  }

  // Payload: [SubID 2] [Type 0x06(BLOB2)] [Len 2] [Count 1] [Target 14]...
  if (payload.size() < 6 || payload[2] != 0x06) {
    return;
  }

  uint8_t count = payload[5];

  // Build binary buffer: [count][target1 14 bytes][target2 14 bytes]...
  // Each target is 14 bytes: id(1), x(2), y(2), z(2), velocity(2), snr(2), classifier(1), posture(1), active(1)
  std::vector<uint8_t> binary_data;
  binary_data.push_back(count);

  for (int i = 0; i < count; i++) {
    int offset = 6 + (i * 14);
    if (offset + 14 > payload.size())
      break;

    // Copy raw 14-byte target data directly (already in correct big-endian format)
    binary_data.insert(binary_data.end(),
                       payload.begin() + offset,
                       payload.begin() + offset + 14);
  }

  // Throttle publishes to avoid flooding HA (radar streams at 10-20Hz)
  uint32_t now = millis();
  if (this->target_tracking_sensor_ != nullptr &&
      (now - last_target_publish_millis_ >= target_tracking_interval_ms_)) {
    std::string base64_str = esphome::base64_encode(binary_data);
    this->target_tracking_sensor_->publish_state(base64_str);
    last_target_publish_millis_ = now;
  }

  // Position-based zone people counting is available as a fallback but
  // normally disabled — native radar reports (SubID 0x0175) are preferred.
  // update_zone_people_counts_(payload, count);
}

bool FP2Component::is_target_in_zone_(int16_t raw_x, int16_t raw_y, const GridMap &grid) {
  // Map raw target coords to 20x16 internal grid
  // Raw X: -400 to +400 → 14 visible cols → grid cols 2-15 (offset_col=2)
  // Raw Y: 0 to 800 → 14 visible rows → grid rows 0-13 (offset_row=0)
  float fx = (-raw_x + 400.0f) / 800.0f * 14.0f;
  float fy = raw_y / 800.0f * 14.0f;

  int col = (int)fx + 2;  // offset_col
  int row = (int)fy;       // offset_row = 0

  if (col < 0 || col > 15 || row < 0 || row > 19) return false;

  // Each row is 2 bytes big-endian, bit 15 = col 0
  uint16_t row_val = (grid[row * 2] << 8) | grid[row * 2 + 1];
  return (row_val & (1 << (15 - col))) != 0;
}

void FP2Component::update_zone_people_counts_(const std::vector<uint8_t> &payload, uint8_t count) {
  for (auto &zone : zones_) {
    if (zone->zone_people_count_sensor == nullptr) continue;

    int zone_count = 0;
    for (int i = 0; i < count; i++) {
      int offset = 6 + (i * 14);
      if (offset + 14 > (int)payload.size()) break;

      // Target: id(1), x(2 BE), y(2 BE), z(2), velocity(2), snr(2), classifier(1), posture(1), active(1)
      int16_t x = (int16_t)((payload[offset + 1] << 8) | payload[offset + 2]);
      int16_t y = (int16_t)((payload[offset + 3] << 8) | payload[offset + 4]);

      if (is_target_in_zone_(x, y, zone->grid)) {
        zone_count++;
      }
    }

    // Only publish on change to avoid flooding HA at 10-20Hz
    float current = zone->zone_people_count_sensor->get_raw_state();
    if (std::isnan(current) || (int)current != zone_count) {
      zone->zone_people_count_sensor->publish_state((float)zone_count);
    }
  }
}

void FP2Component::handle_temperature_report_(const std::vector<uint8_t> &payload) {
    if (payload.size() == 5 && payload[2] == 0x01) {
        uint16_t temp = payload[3] << 8 | payload[4];
        if (radar_temperature_sensor_ != nullptr) {
            radar_temperature_sensor_->publish_state(temp);
        }
        ESP_LOGD(TAG, "Radar temperature report: %d", temp);
    } else {
        ESP_LOGD(TAG, "Unexpected radar temperature report format");
    }
}

void FP2Component::handle_response_(AttrId attr_id, const std::vector<uint8_t> &payload) {
  // Direction/angle queries only arrive after radar finishes booting
  if (!radar_ready_) {
    ESP_LOGE(TAG, "### RESPONSE: setting radar_ready=true (was %d, init_done=%d, SubID=0x%04X, uptime=%u)",
             radar_ready_, init_done_, (uint16_t)attr_id, millis());
    radar_ready_ = true;
  }

  // RESPONSE packets with only 2 bytes (just SubID) are Reverse Read Requests from the radar
  if (payload.size() == 2) {
    handle_reverse_read_request_(attr_id);
  } else {
    // Responses with data — route through report handler since some SubIDs
    // (e.g. zone presence 0x0142) may arrive as RESPONSE instead of REPORT
    ESP_LOGD(TAG, "Response with data for 0x%04X (%d bytes) — routing to report handler",
             (uint16_t) attr_id, payload.size());
    handle_report_(attr_id, payload);
  }
}

void FP2Component::handle_reverse_read_request_(AttrId attr_id) {
  ESP_LOGI(TAG, "Received Reverse Query for SubID 0x%04X", (uint16_t) attr_id);

  switch (attr_id) {
    case AttrId::DEVICE_DIRECTION:  // device_direction
      send_reverse_response_(attr_id, (uint8_t)fp2_accel_->get_orientation());
      ESP_LOGD(TAG, "Sending Device Direction: %d", fp2_accel_->get_orientation());
      break;

    case AttrId::ANGLE_SENSOR_DATA:  // angle_sensor_data
      {
        uint8_t angle = fp2_accel_->get_output_angle_z();
        send_reverse_response_(attr_id, angle);
        ESP_LOGD(TAG, "Sending Angle Sensor Data: %d", angle);
      }
      break;

    default:
      ESP_LOGW(TAG, "Unknown Reverse Query SubID 0x%04X", (uint16_t) attr_id);
      break;
  }
}

// Command Queue Helpers
void FP2Component::enqueue_command_(OpCode type, AttrId attr_id,
                                    uint8_t byte_val) {
  FP2Command cmd;
  cmd.type = type;
  cmd.attr_id = attr_id;
  cmd.retry_count = 0;

  // Payload: [SubID 2] [Type 1] [Data 1]
  cmd.data.push_back((((uint16_t) attr_id) >> 8) & 0xFF);
  cmd.data.push_back(((uint16_t) attr_id) & 0xFF);
  cmd.data.push_back(0x00); // UINT8
  cmd.data.push_back(byte_val);

  command_queue_.push_back(cmd);
}

void FP2Component::enqueue_command_(OpCode type, AttrId attr_id,
                                    uint16_t word_val) {
  FP2Command cmd;
  cmd.type = type;
  cmd.attr_id = attr_id;
  cmd.retry_count = 0;

  // Payload: [SubID 2] [Type 1] [Data 2]
  cmd.data.push_back((((uint16_t) attr_id) >> 8) & 0xFF);
  cmd.data.push_back(((uint16_t) attr_id) & 0xFF);
  cmd.data.push_back(0x01); // UINT16
  cmd.data.push_back((word_val >> 8) & 0xFF);
  cmd.data.push_back(word_val & 0xFF);

  command_queue_.push_back(cmd);
}

void FP2Component::enqueue_command_(OpCode type, AttrId attr_id,
                                    bool bool_val) {
  FP2Command cmd;
  cmd.type = type;
  cmd.attr_id = attr_id;
  cmd.retry_count = 0;

  // Payload: [SubID 2] [Type 1] [Data 1]
  cmd.data.push_back((((uint16_t) attr_id) >> 8) & 0xFF);
  cmd.data.push_back(((uint16_t) attr_id) & 0xFF);
  cmd.data.push_back(0x04); // BOOL
  cmd.data.push_back((uint8_t) bool_val);

  command_queue_.push_back(cmd);
}


void FP2Component::enqueue_command_blob2_(
    AttrId attr_id, const std::vector<uint8_t> &blob_content) {
  FP2Command cmd;
  cmd.type = OpCode::WRITE; // Always Write for these configs
  cmd.attr_id = attr_id;
  cmd.retry_count = 0;

  // Payload: [SubID 2] [Type 1 (0x06)] [Len 2] [Content N]
  cmd.data.push_back((((uint16_t) attr_id) >> 8) & 0xFF);
  cmd.data.push_back(((uint16_t) attr_id) & 0xFF);
  cmd.data.push_back(0x06); // BLOB2

  uint16_t len = blob_content.size();
  cmd.data.push_back((len >> 8) & 0xFF);
  cmd.data.push_back(len & 0xFF);

  cmd.data.insert(cmd.data.end(), blob_content.begin(), blob_content.end());

  command_queue_.push_back(cmd);
}

void FP2Component::enqueue_read_(AttrId attr_id) {
    FP2Command cmd;
    cmd.type = OpCode::RESPONSE;
    cmd.attr_id = attr_id;
    cmd.retry_count = 0;

    cmd.data.push_back((((uint16_t) attr_id) >> 8) & 0xFF);
    cmd.data.push_back(((uint16_t) attr_id) & 0xFF);

    command_queue_.push_back(cmd);
}

void FP2Component::set_interference_grid(const std::vector<uint8_t> &grid) {
  ESP_LOGI(TAG, "set_interference_grid called with size: %d", grid.size());
  if (grid.size() == 40) {
    std::copy(grid.begin(), grid.end(), interference_grid_.begin());
    has_interference_grid_ = true;
    ESP_LOGI(TAG, "Interference grid configured successfully");
  } else {
    ESP_LOGW(TAG, "Interference grid size mismatch! Expected 40, got %d", grid.size());
  }
}

void FP2Component::set_exit_grid(const std::vector<uint8_t> &grid) {
  ESP_LOGI(TAG, "set_exit_grid called with size: %d", grid.size());
  if (grid.size() == 40) {
    std::copy(grid.begin(), grid.end(), exit_grid_.begin());
    has_exit_grid_ = true;
    ESP_LOGI(TAG, "Exit grid configured successfully");
  } else {
    ESP_LOGW(TAG, "Exit grid size mismatch! Expected 40, got %d", grid.size());
  }
}

void FP2Component::set_edge_grid(const std::vector<uint8_t> &grid) {
  ESP_LOGI(TAG, "set_edge_grid called with size: %d", grid.size());
  if (grid.size() == 40) {
    std::copy(grid.begin(), grid.end(), edge_grid_.begin());
    has_edge_grid_ = true;
    ESP_LOGI(TAG, "Edge grid configured successfully");
  } else {
    ESP_LOGW(TAG, "Edge grid size mismatch! Expected 40, got %d", grid.size());
  }
}

void FP2Component::set_zones(const std::vector<FP2Zone*> &zones) {
    zones_ = zones;
}

std::string FP2Component::grid_to_hex_card_format(const GridMap &grid) {
  std::string result;
  result.reserve(56);  // 14 rows * 2 bytes * 2 hex chars

  // For each row R (0-13) in the card format
  for (int R = 0; R < 14; R++) {
    // Map to internal row (rows 3-16 in the 20-row grid)
    int internal_row_idx = R;
    int byte_idx = internal_row_idx * 2;

    // Encode the 2 bytes for this row as 4 hex chars
    char hex[5];
    snprintf(hex, sizeof(hex), "%02x%02x", grid[byte_idx], grid[byte_idx + 1]);
    result += hex;
  }

  return result;
}

void FP2Component::dump_config() {
  ESP_LOGCONFIG(TAG, "Aqara FP2 (built " __DATE__ " " __TIME__ "):");
  ESP_LOGCONFIG(TAG, "  Debug Mode: %s", debug_mode_ ? "ON" : "OFF");
  ESP_LOGCONFIG(TAG, "  Mounting Position: %d", mounting_position_);
  ESP_LOGCONFIG(TAG, "  Zones: %d", zones_.size());
  if (reset_pin_ != nullptr) {
    LOG_PIN("  Reset Pin: ", reset_pin_);
  }
  for (auto &z : zones_) {
    if (z->presence_sensor != nullptr) {
      LOG_BINARY_SENSOR("  ", "Zone Presence", z->presence_sensor);
    }
    if (z->motion_sensor != nullptr) {
      LOG_BINARY_SENSOR("  ", "Zone Motion", z->motion_sensor);
    }
  }
  if (radar_ota_button_ != nullptr) {
    ESP_LOGCONFIG(TAG, "  Radar OTA: EXPERIMENTAL (untested)");
    if (!radar_firmware_url_.empty()) {
      ESP_LOGCONFIG(TAG, "  Firmware URL: %s", radar_firmware_url_.c_str());
    }
  }
}

JsonDocument FP2Component::get_map_config_json() {
  JsonDocument doc;

  // Deserialize the compile-time JSON
  DeserializationError error = deserializeJson(doc, this->map_config_json_);

  if (error) {
    ESP_LOGE(TAG, "Failed to parse map config JSON: %s", error.c_str());
    return doc;
  }

  // The base structure is already in the JSON, but we can add runtime data if needed
  // For example, current zone states could be added here in the future

  return doc;
}

const char* FP2Component::get_mounting_position_string_() {
  switch (mounting_position_) {
    case 0x02: return "left_upper_corner";
    case 0x03: return "right_upper_corner";
    default: return "wall";
  }
}

void FP2Component::json_get_map_data(JsonObject root) {
  // Global settings
  root["mounting_position"] = get_mounting_position_string_();
  root["left_right_reverse"] = left_right_reverse_;

  // Global grids (if configured)
  if (has_interference_grid_) {
    root["interference_grid"] = grid_to_hex_card_format(interference_grid_);
  }
  if (has_exit_grid_) {
    root["exit_grid"] = grid_to_hex_card_format(exit_grid_);
  }
  if (has_edge_grid_) {
    root["edge_grid"] = grid_to_hex_card_format(edge_grid_);
  }

  // Zones
  if (!zones_.empty()) {
    JsonArray zones_array = root["zones"].to<JsonArray>();
    for (FP2Zone *zone : zones_) {
      JsonObject zone_obj = zones_array.add<JsonObject>();
      zone_obj["sensitivity"] = zone->sensitivity;
      zone_obj["grid"] = grid_to_hex_card_format(zone->grid);
      if (zone->presence_sensor != nullptr) {
        zone_obj["presence_sensor"] = zone->presence_sensor->get_name().c_str();
      }
    }
  }
}

// --- Radar OTA (XMODEM-1K) ---

void FP2RadarOtaButton::press_action() {
  if (this->parent_ != nullptr) {
    this->parent_->trigger_radar_ota();
  }
}

void FP2RadarFwStageButton::press_action() {
  if (this->parent_ != nullptr) {
    this->parent_->trigger_radar_fw_stage();
  }
}

void FP2Component::trigger_radar_fw_stage() {
#ifdef USE_RADAR_FW_HTTP
  if (radar_firmware_url_.empty()) {
    ESP_LOGE(TAG, "Stage firmware: no radar_firmware_url configured");
    return;
  }

  // Check if firmware already exists on flash
  uint32_t existing = ota_detect_firmware_size_();
  if (existing > 0) {
    ESP_LOGI(TAG, "Stage firmware: valid firmware already on flash (%u bytes). Re-downloading...", existing);
  }

  if (ota_download_firmware_()) {
    uint32_t size = ota_detect_firmware_size_();
    ESP_LOGW(TAG, "Firmware staged: %u bytes written to flash. Ready for OTA.", size);
  } else {
    ESP_LOGE(TAG, "Firmware staging failed");
  }
#else
  ESP_LOGE(TAG, "Stage firmware: HTTP download not available (radar_firmware_url not configured at build time)");
#endif
}

uint16_t FP2Component::xmodem_crc16_(const uint8_t *data, size_t len) {
  uint16_t crc = 0x0000;
  for (size_t i = 0; i < len; i++) {
    crc ^= (uint16_t)data[i] << 8;
    for (int j = 0; j < 8; j++) {
      if (crc & 0x8000)
        crc = (crc << 1) ^ 0x1021;
      else
        crc = crc << 1;
    }
  }
  return crc;
}

uint32_t FP2Component::ota_detect_firmware_size_() {
  // Validate the firmware starts with TI MSTR magic header
  uint8_t magic[4];
  esp_err_t err = esp_flash_read(NULL, magic, MCU_OTA_FLASH_OFFSET, 4);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "OTA: cannot read flash at 0x%06x (err=0x%x)", MCU_OTA_FLASH_OFFSET, err);
    return 0;
  }

  // TI IWR6843 firmware starts with "MSTR" (0x4D535452)
  if (magic[0] != 'M' || magic[1] != 'S' || magic[2] != 'T' || magic[3] != 'R') {
    ESP_LOGE(TAG, "OTA: invalid firmware header (expected MSTR, got %02x %02x %02x %02x)",
             magic[0], magic[1], magic[2], magic[3]);
    return 0;
  }

  // Scan backwards from end of partition to find last non-0xFF byte
  uint8_t buf[256];
  uint32_t offset = MCU_OTA_FLASH_SIZE;

  while (offset > 0) {
    uint32_t chunk = (offset >= sizeof(buf)) ? sizeof(buf) : offset;
    offset -= chunk;
    err = esp_flash_read(NULL, buf, MCU_OTA_FLASH_OFFSET + offset, chunk);
    if (err != ESP_OK) {
      ESP_LOGE(TAG, "OTA: flash read error at 0x%06x: 0x%x", MCU_OTA_FLASH_OFFSET + offset, err);
      return 0;
    }
    for (int i = chunk - 1; i >= 0; i--) {
      if (buf[i] != 0xFF) {
        uint32_t size = offset + i + 1;
        // Round up to XMODEM block boundary
        size = ((size + XMODEM_BLOCK_SIZE - 1) / XMODEM_BLOCK_SIZE) * XMODEM_BLOCK_SIZE;
        return size;
      }
    }
  }
  return 0;  // Partition is empty
}

#ifdef USE_RADAR_FW_HTTP
bool FP2Component::ota_download_firmware_() {
  if (radar_firmware_url_.empty()) {
    ESP_LOGE(TAG, "OTA: no radar_firmware_url configured");
    return false;
  }

  ESP_LOGI(TAG, "OTA: downloading firmware from %s", radar_firmware_url_.c_str());

  esp_http_client_config_t config = {};
  config.url = radar_firmware_url_.c_str();
  config.timeout_ms = 30000;
  config.buffer_size = 4096;

  esp_http_client_handle_t client = esp_http_client_init(&config);
  if (client == nullptr) {
    ESP_LOGE(TAG, "OTA: failed to init HTTP client");
    return false;
  }

  esp_err_t err = esp_http_client_open(client, 0);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "OTA: HTTP open failed (0x%x)", err);
    esp_http_client_cleanup(client);
    return false;
  }

  int content_length = esp_http_client_fetch_headers(client);
  int status = esp_http_client_get_status_code(client);
  if (status != 200) {
    ESP_LOGE(TAG, "OTA: HTTP status %d", status);
    esp_http_client_close(client);
    esp_http_client_cleanup(client);
    return false;
  }

  if (content_length <= 0) {
    ESP_LOGE(TAG, "OTA: unknown content length");
    esp_http_client_close(client);
    esp_http_client_cleanup(client);
    return false;
  }

  if ((uint32_t)content_length > MCU_OTA_FLASH_SIZE) {
    ESP_LOGE(TAG, "OTA: firmware too large (%d bytes, max %u)", content_length, MCU_OTA_FLASH_SIZE);
    esp_http_client_close(client);
    esp_http_client_cleanup(client);
    return false;
  }

  ESP_LOGI(TAG, "OTA: firmware size %d bytes, erasing flash...", content_length);

  // Erase the flash region (must be 4KB-aligned)
  uint32_t erase_size = ((content_length + 4095) / 4096) * 4096;
  err = esp_flash_erase_region(NULL, MCU_OTA_FLASH_OFFSET, erase_size);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "OTA: flash erase failed (0x%x)", err);
    esp_http_client_close(client);
    esp_http_client_cleanup(client);
    return false;
  }

  // Stream firmware to flash in chunks
  uint8_t buf[4096];
  uint32_t written = 0;
  bool header_validated = false;
  int last_pct = -1;

  while (written < (uint32_t)content_length) {
    int to_read = std::min((int)sizeof(buf), content_length - (int)written);
    int read = esp_http_client_read(client, (char *)buf, to_read);
    if (read <= 0) {
      ESP_LOGE(TAG, "OTA: download stalled at %u/%d bytes", written, content_length);
      esp_http_client_close(client);
      esp_http_client_cleanup(client);
      return false;
    }

    // Validate MSTR header on first chunk
    if (!header_validated) {
      if (read < 4 || buf[0] != 'M' || buf[1] != 'S' || buf[2] != 'T' || buf[3] != 'R') {
        ESP_LOGE(TAG, "OTA: downloaded file has invalid header (expected MSTR)");
        esp_http_client_close(client);
        esp_http_client_cleanup(client);
        return false;
      }
      header_validated = true;
    }

    err = esp_flash_write(NULL, buf, MCU_OTA_FLASH_OFFSET + written, read);
    if (err != ESP_OK) {
      ESP_LOGE(TAG, "OTA: flash write failed at offset %u (0x%x)", written, err);
      esp_http_client_close(client);
      esp_http_client_cleanup(client);
      return false;
    }

    written += read;
    int pct = (int)(written * 100 / content_length);
    if (pct / 10 != last_pct / 10) {
      ESP_LOGI(TAG, "OTA: download %d%% (%u/%d bytes)", pct, written, content_length);
      last_pct = pct;
    }
  }

  esp_http_client_close(client);
  esp_http_client_cleanup(client);

  // Verify what we wrote by re-reading the header
  uint8_t verify[4];
  esp_flash_read(NULL, verify, MCU_OTA_FLASH_OFFSET, 4);
  if (verify[0] != 'M' || verify[1] != 'S' || verify[2] != 'T' || verify[3] != 'R') {
    ESP_LOGE(TAG, "OTA: flash verification failed!");
    return false;
  }

  ESP_LOGI(TAG, "OTA: firmware downloaded and verified (%u bytes)", written);
  return true;
}
#endif  // USE_RADAR_FW_HTTP

void FP2Component::trigger_radar_ota() {
  if (ota_state_ != OtaState::IDLE) {
    ESP_LOGW(TAG, "Radar OTA already in progress");
    return;
  }

  ESP_LOGW(TAG, "=== Radar OTA: validating firmware ===");

  // Check if firmware exists on flash
  ota_firmware_size_ = ota_detect_firmware_size_();

#ifdef USE_RADAR_FW_HTTP
  // If no firmware on flash but URL configured, download it
  if (ota_firmware_size_ == 0 && !radar_firmware_url_.empty()) {
    ESP_LOGI(TAG, "OTA: no firmware on flash, downloading from configured URL...");
    if (!ota_download_firmware_()) {
      ESP_LOGE(TAG, "OTA ABORTED: firmware download failed");
      return;
    }
    ota_firmware_size_ = ota_detect_firmware_size_();
  }
#endif

  if (ota_firmware_size_ == 0) {
    ESP_LOGE(TAG, "OTA ABORTED: no valid radar firmware available.");
    if (radar_firmware_url_.empty()) {
      ESP_LOGE(TAG, "Configure 'radar_firmware_url' in YAML to enable firmware download.");
    }
    return;
  }

  // Sanity check firmware size
  if (ota_firmware_size_ < 1024) {
    ESP_LOGE(TAG, "OTA ABORTED: firmware too small (%u bytes)", ota_firmware_size_);
    return;
  }
  if (ota_firmware_size_ > MCU_OTA_FLASH_SIZE) {
    ESP_LOGE(TAG, "OTA ABORTED: firmware too large (%u bytes, max %u)", ota_firmware_size_, MCU_OTA_FLASH_SIZE);
    return;
  }

  uint32_t blocks = ota_firmware_size_ / XMODEM_BLOCK_SIZE;
  ESP_LOGW(TAG, "=== Starting Radar OTA: %u bytes (%u blocks, ~%u seconds) ===",
           ota_firmware_size_, blocks, blocks / 50 + 10);
  ESP_LOGW(TAG, "WARNING: Do not power off the device during transfer!");

  // Send OTA trigger command via protocol
  enqueue_command_(OpCode::WRITE, AttrId::OTA_SET_FLAG, true);

  ota_firmware_offset_ = 0;
  ota_block_num_ = 1;
  ota_retry_count_ = 0;
  ota_can_count_ = 0;
  ota_state_ = OtaState::WAITING_HANDSHAKE;
  ota_state_start_millis_ = millis();

  // Flush the command queue immediately so the OTA flag gets sent
  // before we switch to XMODEM mode
  while (!command_queue_.empty()) {
    process_command_queue_();
    delay(10);
  }
}

void FP2Component::ota_send_current_block_() {
  // Read 1024 bytes from flash
  uint8_t *data = &ota_packet_buf_[3];  // Skip STX, blk, ~blk
  uint32_t read_offset = MCU_OTA_FLASH_OFFSET + ota_firmware_offset_;
  uint32_t remaining = ota_firmware_size_ - ota_firmware_offset_;
  uint32_t to_read = (remaining >= XMODEM_BLOCK_SIZE) ? XMODEM_BLOCK_SIZE : remaining;

  esp_err_t err = esp_flash_read(NULL, data, read_offset, to_read);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Flash read error at 0x%06x", read_offset);
    ota_state_ = OtaState::DONE;
    return;
  }

  // Pad with 0xFF if last block is short
  if (to_read < XMODEM_BLOCK_SIZE) {
    memset(data + to_read, 0xFF, XMODEM_BLOCK_SIZE - to_read);
  }

  // Build XMODEM-1K packet
  ota_packet_buf_[0] = 0x02;  // STX
  ota_packet_buf_[1] = ota_block_num_;
  ota_packet_buf_[2] = ~ota_block_num_;

  // CRC-16/XMODEM over the 1024 data bytes only
  uint16_t crc = xmodem_crc16_(data, XMODEM_BLOCK_SIZE);
  ota_packet_buf_[1027] = (crc >> 8) & 0xFF;  // CRC high
  ota_packet_buf_[1028] = crc & 0xFF;          // CRC low

  write_array(ota_packet_buf_, 1029);

  ESP_LOGD(TAG, "OTA: sent block %d (offset %u/%u, %d%%)",
           ota_block_num_, ota_firmware_offset_,
           ota_firmware_size_,
           (int)(ota_firmware_offset_ * 100 / ota_firmware_size_));
}

void FP2Component::ota_send_eot_() {
  uint8_t eot = 0x04;
  write_array(&eot, 1);
}

void FP2Component::ota_loop_() {
  uint32_t now = millis();

  switch (ota_state_) {
    case OtaState::WAITING_HANDSHAKE: {
      // Wait for 'C' (CRC mode) or NAK from radar bootloader
      while (available()) {
        uint8_t byte;
        read_byte(&byte);
        if (byte == 'C' || byte == 0x15) {  // 'C' or NAK
          ESP_LOGI(TAG, "OTA: radar handshake received (0x%02X), starting transfer", byte);
          ota_state_ = OtaState::TRANSFERRING;
          ota_state_start_millis_ = now;
          ota_retry_count_ = 0;
          ota_send_current_block_();
          return;
        } else if (byte == 0x18) {  // CAN
          ota_can_count_++;
          if (ota_can_count_ > 10) {
            ESP_LOGE(TAG, "OTA: too many CAN bytes, aborting");
            ota_state_ = OtaState::DONE;
            return;
          }
        }
      }
      // Timeout check
      if (now - ota_state_start_millis_ > OTA_HANDSHAKE_TIMEOUT_MS) {
        ESP_LOGE(TAG, "OTA: handshake timeout (20s), aborting");
        ota_state_ = OtaState::DONE;
      }
      break;
    }

    case OtaState::TRANSFERRING: {
      while (available()) {
        uint8_t byte;
        read_byte(&byte);
        if (byte == 0x06) {  // ACK
          ota_retry_count_ = 0;
          ota_firmware_offset_ += XMODEM_BLOCK_SIZE;
          ota_block_num_++;

          // Log progress every 10%
          if ((ota_firmware_offset_ * 10 / ota_firmware_size_) !=
              ((ota_firmware_offset_ - XMODEM_BLOCK_SIZE) * 10 / ota_firmware_size_)) {
            ESP_LOGI(TAG, "OTA: %d%% (%u/%u bytes)",
                     (int)(ota_firmware_offset_ * 100 / ota_firmware_size_),
                     ota_firmware_offset_, ota_firmware_size_);
          }

          if (ota_firmware_offset_ >= ota_firmware_size_) {
            // All data sent, transition to ending
            ESP_LOGI(TAG, "OTA: all data sent, sending EOT");
            ota_state_ = OtaState::ENDING;
            ota_state_start_millis_ = now;
            ota_retry_count_ = 0;
            ota_send_eot_();
          } else {
            ota_state_start_millis_ = now;
            ota_send_current_block_();
          }
          return;
        } else if (byte == 0x15) {  // NAK — resend
          ota_retry_count_++;
          if (ota_retry_count_ >= OTA_MAX_RETRIES) {
            ESP_LOGE(TAG, "OTA: max retries on block %d, aborting", ota_block_num_);
            ota_state_ = OtaState::DONE;
            return;
          }
          ESP_LOGW(TAG, "OTA: NAK on block %d, retry %d", ota_block_num_, ota_retry_count_);
          ota_state_start_millis_ = now;
          ota_send_current_block_();
          return;
        } else if (byte == 0x18) {  // CAN
          ota_can_count_++;
          if (ota_can_count_ > 10) {
            ESP_LOGE(TAG, "OTA: cancelled by radar");
            ota_state_ = OtaState::DONE;
            return;
          }
        }
      }
      // Timeout — retransmit
      if (now - ota_state_start_millis_ > OTA_TRANSFER_TIMEOUT_MS) {
        ota_retry_count_++;
        if (ota_retry_count_ >= OTA_MAX_RETRIES) {
          ESP_LOGE(TAG, "OTA: timeout, max retries on block %d", ota_block_num_);
          ota_state_ = OtaState::DONE;
          return;
        }
        ESP_LOGW(TAG, "OTA: timeout on block %d, retry %d", ota_block_num_, ota_retry_count_);
        ota_state_start_millis_ = now;
        ota_send_current_block_();
      }
      break;
    }

    case OtaState::ENDING: {
      while (available()) {
        uint8_t byte;
        read_byte(&byte);
        if (byte == 0x06) {  // ACK
          ESP_LOGW(TAG, "=== Radar OTA complete! Radar will restart. ===");
          ota_state_ = OtaState::DONE;
          return;
        } else if (byte == 0x18) {  // CAN
          ESP_LOGW(TAG, "OTA: CAN during EOT — treating as success");
          ota_state_ = OtaState::DONE;
          return;
        }
      }
      if (now - ota_state_start_millis_ > OTA_TRANSFER_TIMEOUT_MS) {
        ota_retry_count_++;
        if (ota_retry_count_ >= OTA_MAX_RETRIES) {
          ESP_LOGE(TAG, "OTA: EOT timeout, giving up");
          ota_state_ = OtaState::DONE;
          return;
        }
        ota_state_start_millis_ = now;
        ota_send_eot_();
      }
      break;
    }

    case OtaState::DONE: {
      ESP_LOGI(TAG, "OTA: resetting radar and resuming normal operation");
      // Reset the radar to restart it with new firmware
      if (reset_pin_ != nullptr) {
        reset_pin_->digital_write(false);
        delay(100);
        reset_pin_->digital_write(true);
      }
      // Reset protocol state for fresh init
      init_done_ = false;
      radar_ready_ = false;
      last_heartbeat_millis_ = 0;
      state_ = SYNC;
      command_queue_.clear();
      waiting_for_ack_attr_id_ = AttrId::INVALID;
      ota_state_ = OtaState::IDLE;
      break;
    }

    default:
      break;
  }
}

} // namespace aqara_fp2
} // namespace esphome
