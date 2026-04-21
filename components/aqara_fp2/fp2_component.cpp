#include "fp2_component.h"
#include "esphome/components/api/api_server.h"
#include "esphome/components/switch/switch.h"
#include "esphome/core/application.h"
#include "esphome/core/helpers.h"
#include "esphome/core/hal.h"
#include "esphome/core/log.h"
#include <cmath>
#include <cstdint>
#include <vector>
#include <esp_flash.h>
#include <esp_partition.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <lwip/sockets.h>
#include <lwip/netdb.h>
#include <esp_system.h>
#include <esp_netif.h>
#include <cstring>
#include <string>
#ifdef USE_RADAR_FW_HTTP
#include <esp_http_client.h>
#include <esp_crt_bundle.h>
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

void FP2Component::publish_radar_state_(const char *state) {
  if (radar_state_sensor_ != nullptr) {
    radar_state_sensor_->publish_state(state);
  }
}

void FP2Component::setup() {
  // Reset internal state
  waiting_for_ack_attr_id_ = AttrId::INVALID;
  init_done_ = false;
  radar_ready_ = false;
  last_heartbeat_millis_ = 0;

  // Restore last operating mode from flash (state published in loop when API connects)
  operating_mode_pref_ = global_preferences->make_preference<uint8_t>(fnv1_hash("fp2_operating_mode"));
  uint8_t saved_mode = 0;
  if (operating_mode_pref_.load(&saved_mode) && saved_mode < 4) {
    sleep_mode_active_ = (saved_mode == 2);  // Sleep Monitoring
    ESP_LOGI(TAG, "Restored operating mode index=%d (sleep=%d)", saved_mode, sleep_mode_active_);
  }

  // Look up the radar firmware staging partition by name. Pointer may be
  // null if the partition table doesn't include mcu_ota (e.g. running on a
  // stock ESPHome partition layout that hasn't been re-flashed for this
  // component). All OTA entry points must check the pointer and fail
  // gracefully if null.
  mcu_ota_partition_ =
      esp_partition_find_first(ESP_PARTITION_TYPE_ANY, ESP_PARTITION_SUBTYPE_ANY, "mcu_ota");
  if (mcu_ota_partition_ != nullptr) {
    ESP_LOGI(TAG, "mcu_ota partition: offset=0x%06x size=%u bytes",
             (unsigned) mcu_ota_partition_->address,
             (unsigned) mcu_ota_partition_->size);
  } else {
    ESP_LOGW(TAG, "mcu_ota partition not found — radar OTA staging/flash will be disabled");
    ESP_LOGW(TAG, "Custom partition table required. Serial-flash a build with flash_size: 16MB.");
  }

  // GPIO Reset
  perform_reset_();
  publish_radar_state_("Booting");

  // Start telnet bridge (TCP server on telnet_port_, default 6666).
  start_telnet_();
}

void FP2Component::perform_reset_() {
  if (reset_pin_ != nullptr) {
    ESP_LOGD(TAG, "Performing radar reset via GPIO13...");
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
    ESP_LOGD(TAG, "Radar reset done, flushed %d stale UART bytes", flushed);
  } else {
    ESP_LOGW(TAG, "No Reset Pin configured!");
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

void FP2OperatingModeSelect::control(const std::string &value) {
  if (this->parent_ != nullptr) {
    this->parent_->set_operating_mode(value);
  }
  this->publish_state(value);
}

void FP2Component::set_operating_mode(const std::string &mode) {
  // Scene modes map to distinct radar firmware images that WORK_MODE selects:
  //   3 = Zone Detection  → FW1 (mcu_ota group 0, stripped build paths)
  //   8 = Fall Detection  → FW2 3d_people_counting (mcu_ota group 1)
  //   9 = Sleep / Vitals  → FW3 vital signs (mcu_ota group 2)
  //
  // 2026-04-20 correction (superseding earlier 2026-04-19 reversal):
  // Full Ghidra re-analysis (aggressive analyzers + gap force-disassembly)
  // recovered 1152 previously-hidden functions in FW3 including the attribute
  // WRITE dispatcher FUN_00009e80. It has a case for SubID 0x0112
  // (LOCATION_REPORT_ENABLE) that calls the handler at 0x2c9c8, which writes
  // config+0xb8 = 1 — opening the HR/BR emit gate in FUN_00006c84.
  //
  // So FW3 IS functional and the standard Aqara activation path works:
  //   WRITE 0x0112 = 1   (sent during init, fp2_component.cpp:427)
  //   WRITE 0x0116 = 9   (triggers radar flash save + restart into FW3)
  //
  // The earlier symptom ("0 HR/BR frames overnight in mode 9") was likely
  // caused by sleep-zone params not being in flash when FW3 booted — DSS had
  // no bed region to track, so target_count stayed 0 and the second emit gate
  // (target_count != 0) suppressed output. Sending SLEEP_MOUNT_POSITION /
  // SLEEP_ZONE_SIZE / SLEEP_BED_HEIGHT / OVERHEAD_HEIGHT before the WORK_MODE
  // write lets them ride along in the flash-save-on-restart.

  uint8_t scene_mode = 3;
  bool sleep = false;

  if (mode == "Zone Detection") {
    scene_mode = 3;
  } else if (mode == "Fall Detection") {
    scene_mode = 8;
  } else if (mode == "Sleep Monitoring") {
    scene_mode = 9;
    sleep = true;
  } else if (mode == "Fall + Positioning") {
    scene_mode = 8;
  } else {
    ESP_LOGW(TAG, "Unknown operating mode: %s", mode.c_str());
    return;
  }

  ESP_LOGI(TAG, "Operating mode: %s (scene=%d, sleep=%d)", mode.c_str(), scene_mode, sleep);
  sleep_mode_active_ = sleep;

  // Save mode index to flash for restore on boot
  uint8_t mode_index = 0;
  if (mode == "Fall Detection") mode_index = 1;
  else if (mode == "Sleep Monitoring") mode_index = 2;
  else if (mode == "Fall + Positioning") mode_index = 3;
  operating_mode_pref_.save(&mode_index);
  global_preferences->sync();  // Flush to flash immediately
  ESP_LOGI(TAG, "Saved operating mode index=%d to flash", mode_index);

  // For sleep mode: send zone params BEFORE WORK_MODE=9 triggers the restart.
  // Each attribute handler writes to radar RAM. The WORK_MODE handler
  // (FUN_00016e18) then calls flash_write functions (FUN_00026b68 etc.) which
  // save the full 3000-byte config blob to flash at 0x31000 — including
  // sleep_mount_position (+0xb94), sleep_zone_size (+0xb98), sleep_bed_height
  // (+0xb92), and overhead_height (+0xbb0) — before the radar restarts.
  //
  // After restart FW3's FUN_00002c50 reads the blob back from flash (CRC
  // checked) and restores these fields into RAM, giving DSS the bed region
  // info it needs. Without these in flash, FW3 would boot with default
  // (zero-width) sleep zone and DSS would never lock onto a target — which
  // is likely what produced the earlier "0 HR/BR frames" symptom.
  //
  // The ESP init also re-sends these params after the restart (see below),
  // giving belt-and-braces coverage.
  if (sleep) {
    if (sleep_mount_position_ > 0) {
      enqueue_command_(OpCode::WRITE, AttrId::SLEEP_MOUNT_POSITION, (uint8_t) sleep_mount_position_);
    }
    if (sleep_zone_size_ > 0) {
      // UINT32 (type 0x02), not BLOB2 — stock cloud handler
      // FUN_400e247c writes as U32. BLOB2 (type 0x06) has a different
      // wire format the radar's attribute dispatcher may not route to the
      // same handler.
      enqueue_command_(OpCode::WRITE, AttrId::SLEEP_ZONE_SIZE, sleep_zone_size_);
    }
    if (sleep_bed_height_ > 0) {
      enqueue_command_(OpCode::WRITE, AttrId::SLEEP_BED_HEIGHT, sleep_bed_height_);
    }
    if (overhead_height_ > 0) {
      enqueue_command_(OpCode::WRITE, AttrId::OVERHEAD_HEIGHT, overhead_height_);
    }
  }

  // Write sleep enable flag to radar RAM.
  //
  // 2026-04-21 CORRECTION (supersedes earlier "value=9" comment):
  // The stock Aqara ESP32 firmware validates SLEEP_REPORT_ENABLE <2 before
  // sending to the radar (verified via Ghidra decompile of the cloud-write
  // handler at fp2_aqara_fw1.bin FUN_400e3399 @ 0x400e3751). Only 0 or 1 are
  // accepted. And the stock heartbeat sync gate at `radar_sw_version`
  // (0x400e4f28) compares `sleep_report_enable == 1` — meaning it uses this
  // flag as a bool, not as a sentinel value 9.
  //
  // The SBL firmware selector does accept `byte[4] == 1` as a FW3 trigger
  // alongside `byte[2] == 9`, so sending SLEEP_REPORT_ENABLE=1 while FW1 is
  // running causes FW1 to flash-save byte[4]=1, and the next radar boot
  // loads FW3. Sending value 9 via this SubID is not what stock does and
  // causes the radar to reject/clamp it.
  // Must encode as BOOL (data_type 0x04), not UINT8 (0x00). Stock's cloud
  // handler writes this with data_type 4 (FUN_400e28f0 @ 0x400e2a0b sets
  // uStack_36 = 4 before FUN_400e7e20 frame-build). Sending as UINT8 gets
  // rejected by the radar's attribute dispatcher with a type mismatch.
  enqueue_command_(OpCode::WRITE, AttrId::SLEEP_REPORT_ENABLE, sleep);  // BOOL
  // WORK_MODE write triggers flash save + radar self-restart
  enqueue_command_(OpCode::WRITE, (AttrId) 0x0116, scene_mode);

  publish_radar_state_(sleep ? "Sleep" : "Booting");

  // Reset init state — radar will self-restart
  init_done_ = false;
  radar_ready_ = false;
  last_heartbeat_millis_ = 0;

  // For Fall + Positioning, location reporting is enabled during init.
  // For other modes it follows the location_report_switch setting.
  // The init sequence already sends LOCATION_REPORT_ENABLE=1 always.
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

void FP2DeleteFalseTargetsButton::press_action() {
  if (this->parent_ != nullptr) {
    this->parent_->trigger_delete_false_targets();
  }
}

void FP2Component::trigger_delete_false_targets() {
  ESP_LOGI(TAG, "Sending delete false targets command...");
  enqueue_command_(OpCode::WRITE, AttrId::DELETE_FALSE_TARGETS, (uint8_t) 1);
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
  // Publish restored operating mode once HA API client is connected
  if (!operating_mode_published_ && operating_mode_select_ != nullptr) {
    auto *server = api::global_api_server;
    if (server != nullptr && server->is_connected()) {
      uint8_t mode = 0;
      static const char *NAMES[] = {"Zone Detection", "Fall Detection", "Sleep Monitoring", "Fall + Positioning"};
      if (operating_mode_pref_.load(&mode) && mode < 4) {
        operating_mode_select_->publish_state(NAMES[mode]);
        ESP_LOGI(TAG, "Published restored operating mode: %s", NAMES[mode]);
      } else {
        operating_mode_select_->publish_state(NAMES[0]);
        ESP_LOGI(TAG, "No saved mode, defaulting to Zone Detection");
      }
      operating_mode_published_ = true;
    }
  }

  // During OTA, bypass normal protocol. If the dedicated transfer task is
  // running, keep the main loop completely out of the UART — otherwise drive
  // the probe / recovery state machine from here.
  if (ota_transfer_task_running_) {
    return;
  }
  if (ota_state_ != OtaState::IDLE) {
    ota_loop_();
    return;
  }

  int bytes_read = 0;
  while (available()) {
    uint8_t byte;
    read_byte(&byte);
    telnet_observe_rx_(byte);
    // In raw mode the telnet client owns the UART — skip ESPHome's frame
    // decode so no ACKs/commands get injected underneath the client.
    if (!telnet_is_raw_mode_()) {
      handle_incoming_byte_(byte);
    }
    bytes_read++;
  }
  // Flush accumulated RX bytes to the telnet client as one line per idle gap.
  telnet_flush_rx_burst_();


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
    ESP_LOGI(TAG, "Re-init at 45s: resending all commands to fully-booted radar");
    publish_radar_state_("Re-init");
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

  // Full init runs in every mode. FW3 (sleep/vitals) needs the same set of
  // attributes FW1/FW2 need: grids, presence/motion enable, LOCATION_REPORT_ENABLE
  // (this is the attr that opens the HR/BR emit gate — config+0xb8 in FW3
  // via dispatcher FUN_00009e80 → handler 0x2c9c8), plus sleep-zone params for
  // FW3 to locate the bed region. Without these FW3 boots with empty config
  // and DSS never locks onto a target, so vitals frames never emit.

  diag_init_at = millis();
  diag_init_used_ready = reinit_done;
  ESP_LOGI(TAG, "Init firing: uptime=%u reinit=%d heartbeat=%u",
           millis(), reinit_done, last_heartbeat_millis_);
    init_done_ = true;
    publish_radar_state_(reinit_done ? "Ready" : "Init sent");

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
    // SLEEP_REPORT_ENABLE is sent LAST — see end of init sequence.
    // A READ in the 0x01xx range triggers scene mode 3, which clears sleep_report_enable.
    // Location reporting must stay enabled at the radar level — people counting
    // depends on it internally. The Report Targets switch controls whether
    // target data is published to the text sensor, not whether the radar tracks.
    // BOOL (type 0x04), not UINT8 — matches stock cloud handler at
    // FUN_400e4e7c which sets uStack_36=4. Sending as UINT8 gets rejected.
    enqueue_command_(OpCode::WRITE, AttrId::LOCATION_REPORT_ENABLE, true);  // BOOL
    enqueue_command_(OpCode::WRITE, AttrId::WALL_CORNER_POS, mounting_position_);
    enqueue_command_(OpCode::WRITE, AttrId::DWELL_TIME_ENABLE, (uint8_t)(dwell_time_enable_ ? 1 : 0));
    enqueue_command_(OpCode::WRITE, AttrId::WALK_DISTANCE_ENABLE,
                     (uint8_t)(walking_distance_sensor_ != nullptr ? 1 : 0));
    enqueue_command_(OpCode::WRITE, AttrId::THERMO_EN, true);
    enqueue_command_(OpCode::WRITE, AttrId::THERMO_DATA, (uint8_t) 1);
    if (fall_overtime_period_ > 0) {
      // UINT32 — send as two uint16 WRITEs (high word then low word) via blob
      std::vector<uint8_t> fop_data = {
        (uint8_t)((fall_overtime_period_ >> 24) & 0xFF),
        (uint8_t)((fall_overtime_period_ >> 16) & 0xFF),
        (uint8_t)((fall_overtime_period_ >> 8) & 0xFF),
        (uint8_t)(fall_overtime_period_ & 0xFF)
      };
      enqueue_command_blob2_(AttrId::FALL_OVERTIME_PERIOD, fop_data);
    }
    if (sleep_mount_position_ > 0) {
      enqueue_command_(OpCode::WRITE, AttrId::SLEEP_MOUNT_POSITION, (uint8_t) sleep_mount_position_);
    }
    if (sleep_zone_size_ > 0) {
      std::vector<uint8_t> szs_data = {
        (uint8_t)((sleep_zone_size_ >> 24) & 0xFF),
        (uint8_t)((sleep_zone_size_ >> 16) & 0xFF),
        (uint8_t)((sleep_zone_size_ >> 8) & 0xFF),
        (uint8_t)(sleep_zone_size_ & 0xFF)
      };
      enqueue_command_blob2_(AttrId::SLEEP_ZONE_SIZE, szs_data);
    }
    if (fall_delay_time_ > 0) {
      enqueue_command_(OpCode::WRITE, AttrId::FALL_DELAY_TIME, fall_delay_time_);
    }
    if (sleep_bed_height_ > 0) {
      enqueue_command_(OpCode::WRITE, AttrId::SLEEP_BED_HEIGHT, sleep_bed_height_);
    }
    if (overhead_height_ > 0) {
      enqueue_command_(OpCode::WRITE, AttrId::OVERHEAD_HEIGHT, overhead_height_);
    }
    if (has_falldown_blind_zone_) {
      enqueue_command_blob2_(AttrId::FALLDOWN_BLIND_ZONE,
          std::vector<uint8_t>(falldown_blind_zone_.begin(), falldown_blind_zone_.end()));
    }

    // 2. Grids — all three must be sent every init for the radar to produce
    //    presence/motion reports.  Send configured grids or empty defaults.
    {
      std::vector<uint8_t> empty_grid(40, 0x00);

      auto interference_data = has_interference_grid_
          ? std::vector<uint8_t>(interference_grid_.begin(), interference_grid_.end())
          : empty_grid;
      auto exit_data = has_exit_grid_
          ? std::vector<uint8_t>(exit_grid_.begin(), exit_grid_.end())
          : empty_grid;

      // Log first 8 bytes of each grid for debugging
      if (debug_mode_) {
        ESP_LOGD(TAG, "GRID interference (has=%d): %02x%02x%02x%02x %02x%02x%02x%02x",
                 has_interference_grid_,
                 interference_data[0], interference_data[1], interference_data[2], interference_data[3],
                 interference_data[4], interference_data[5], interference_data[6], interference_data[7]);
        ESP_LOGD(TAG, "GRID exit (has=%d): %02x%02x%02x%02x %02x%02x%02x%02x",
                 has_exit_grid_,
                 exit_data[0], exit_data[1], exit_data[2], exit_data[3],
                 exit_data[4], exit_data[5], exit_data[6], exit_data[7]);
      }

      // 0x0110 Interference Source
      enqueue_command_blob2_(AttrId::INTERFERENCE_MAP, interference_data);

      // 0x0109 Enter/Exit Label
      enqueue_command_blob2_(AttrId::ENTRY_EXIT_MAP, exit_data);

      // 0x0107 Edge Label — full-coverage default when not configured
      if (has_edge_grid_) {
        enqueue_command_blob2_(AttrId::EDGE_MAP,
            std::vector<uint8_t>(edge_grid_.begin(), edge_grid_.end()));
      } else {
        GridMap default_edge;
        default_edge.fill(0);
        for (int r = 0; r < 14; r++) {
          default_edge[r * 2] = 0x3F;      // cols 2-7
          default_edge[r * 2 + 1] = 0xFF;  // cols 8-15
        }
        enqueue_command_blob2_(AttrId::EDGE_MAP,
            std::vector<uint8_t>(default_edge.begin(), default_edge.end()));
        ESP_LOGI(TAG, "No edge_grid configured, sending full-coverage default");
      }
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

    // HW_VERSION read removed — radar doesn't respond to READ requests for 0x0101,
    // and any READ in the 0x01xx range triggers scene mode 3 which clears sleep_report_enable.

    // SLEEP_REPORT_ENABLE is NOT sent during init — it's controlled by the
    // sleep_mode_switch. Sleep and presence are mutually exclusive radar modes
    // (scene mode 9 vs 3). The switch sends SLEEP_REPORT_ENABLE and suppresses
    // 0x01xx ACKs to prevent the scene mode mapper from clearing it.

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

  // In sleep mode, also send the 0x0203=0 sync that stock firmware emits
  // once per mode-9 boot. This is in the 0x02xx range (outside the scene-
  // mode mapper) so it's safe to send alongside the full 0x01xx init.
  if (sleep_mode_active_) {
    enqueue_command_(OpCode::WRITE, (AttrId) 0x0203, (uint8_t) 0);
    publish_radar_state_("Sleep");
  }

  // Stock ESP's lazy-read sequence: on first cloud-channel activation after
  // a radar restart, stock issues READs for 0x0102/0x0116/0x0128 if its
  // cached values are zero (FUN_400ded60/deda4/dedec @ fp2_aqara_fw1.bin).
  // On a fresh FW3 boot the caches are zero so all three fire. In TI mmwave
  // SDK protocols, READing a report SubID can register the ESP as a
  // subscriber for that periodic report — without it, the radar may never
  // emit 0x0128 temperature, and (hypothesis) the same gating may apply to
  // the 0x0117 target/vitals stream. Our driver has never issued a READ;
  // this is the single biggest protocol-level difference vs stock found in
  // the 2026-04-21 deep-trace agent analysis.
  //
  // Send these AFTER all WRITE-based config commands so the radar has its
  // state set up before we ask for status.
  enqueue_read_(AttrId::RADAR_SW_VERSION);  // 0x0102
  enqueue_read_((AttrId) 0x0116);           // WORK_MODE
  enqueue_read_((AttrId) 0x0128);           // RADAR_TEMPERATURE

  ESP_LOGI(TAG, "Init complete: %d commands queued (uptime=%u ms)",
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

  if (debug_mode_) {
    ESP_LOGD(TAG, "TX: op=%d SubID=0x%04X len=%d retry=%d queue=%d",
             (int)cmd.type, (uint16_t)cmd.attr_id, cmd.data.size(),
             cmd.retry_count, (int)command_queue_.size());
  }

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
  // Telnet client sees our TX frames too — useful for Python scripts to see
  // what the ESP is injecting vs what it's receiving.
  if (telnet_client_fd_ >= 0) {
    char line[256];
    int pos = snprintf(line, sizeof(line), "TXLOG t=%u", (unsigned) millis());
    for (size_t i = 0; i < frame.size() && pos + 4 < (int) sizeof(line); i++) {
      pos += snprintf(line + pos, sizeof(line) - pos, " %02X", frame[i]);
    }
    pos += snprintf(line + pos, sizeof(line) - pos, "\n");
    telnet_send_line_(line);
  }
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

void FP2Component::enqueue_read_(AttrId attr_id) {
  FP2Command cmd;
  cmd.type = OpCode::READ;  // opcode = 1
  cmd.attr_id = attr_id;
  cmd.retry_count = 0;

  // READ payload is just [SubID_HI][SubID_LO] — no data-type, no data.
  cmd.data.push_back((((uint16_t) attr_id) >> 8) & 0xFF);
  cmd.data.push_back(((uint16_t) attr_id) & 0xFF);

  command_queue_.push_back(cmd);
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
    if (debug_mode_) {
      ESP_LOGD(TAG, "ACK OK: 0x%04X (queue=%d)", (uint16_t) attr_id, (int)command_queue_.size());
    }
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
  // Send ACK for reports, with sleep mode protection.
  // The radar's scene mode mapper (FUN_00025dfc) treats any received opcode != 1
  // for SubIDs 0x0100-0x017F as triggering scene mode 3, which clears
  // sleep_report_enable. To prevent this, suppress ACKs for 0x01xx SubIDs
  // when sleep mode is active.
  uint16_t sid = (uint16_t) attr_id;
  if (attr_id != AttrId::RADAR_SW_VERSION) {
    if (sleep_mode_active_ && sid >= 0x0100 && sid < 0x0180) {
      // Don't ACK — would reset radar to scene mode 3 and clear sleep
    } else {
      send_ack_(attr_id);
    }
  }

  // Process specific report types
  switch (attr_id) {
    case AttrId::RADAR_SW_VERSION:  // Heartbeat
      if (last_heartbeat_millis_ == 0) {
        ESP_LOGI(TAG, "First heartbeat at uptime=%u ms",
                 millis(), init_done_, radar_ready_);
      }
      last_heartbeat_millis_ = millis();

      // Heartbeat-driven config sync for sleep mode.
      //
      // Stock ESP32 fires WRITE 0x0203 on every incoming radar heartbeat
      // (0x0102) when sleep_report_enable==1 OR work_mode==9, per
      // radar_sw_version @ 0x400e4f28 + heartbeat_config_sync @ 0x400decd4
      // in fp2_aqara_fw1.bin. The payload is a u8 config-version counter
      // from persistent NVS (Ram400d0e2c+0x257). Missing this keep-alive
      // appears to leave the radar's sleep state machine stuck after
      // WORK_MODE=9 — the radar accepts config but never kicks the DSS
      // pipeline into data-emitting mode.
      //
      // The counter value doesn't seem to matter to the radar (it just
      // needs to see the write). We use a simple incrementing byte.
      if (sleep_mode_active_ && init_done_) {
        enqueue_command_(OpCode::WRITE, (AttrId) 0x0203,
                         (uint8_t) zone_config_sync_counter_++);
      }

      if (payload.size() >= 4) {
        if (payload[2] == 0x00) {
          // Version byte is a build number (e.g. 99 = latest known fw)
          auto ver_str = std::to_string(payload[3]);
          if (radar_hw_version_ > 0) {
            ver_str += " (HW:" + std::to_string(radar_hw_version_) + ")";
          }
          if (radar_software_sensor_ != nullptr) {
              if (radar_software_sensor_->state != ver_str) {
                  radar_software_sensor_->publish_state(ver_str);
              }
          }
        }
      }
      break;

    case AttrId::HW_VERSION:
        // 0x0101 — Hardware version byte from radar. Store it; will be
        // appended to the SW version string on the next heartbeat.
        if (payload.size() >= 4 && payload[2] == 0x00) {
            radar_hw_version_ = payload[3];
            ESP_LOGI(TAG, "Radar hardware version: %u", radar_hw_version_);
        }
        break;

    case AttrId::DEBUG_LOG:
        // 0x0201 — Debug log string from radar MCU (only when debug_mode enabled)
        if (debug_mode_ && payload.size() >= 5 && payload[2] == 0x05) {
            // STRING type: [SubID 2B] [Type 0x05] [Len_HI] [Len_LO] [chars...]
            uint16_t str_len = (payload[3] << 8) | payload[4];
            if (payload.size() >= 5 + str_len) {
                std::string msg(payload.begin() + 5, payload.begin() + 5 + str_len);
                ESP_LOGW(TAG, "[RADAR] %s", msg.c_str());
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
            publish_radar_state_(state != 0 ? "Presence" : "Ready");
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
                // Clear fall detection
                if (fall_detection_sensor_ != nullptr) {
                    fall_detection_sensor_->publish_state(false);
                }
                if (fall_overtime_sensor_ != nullptr) {
                    fall_overtime_sensor_->publish_state(false);
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

    case AttrId::FALL_DETECTION_RESULT:
        // 0x0121 — fall detection event from FW2's fall ML state machine.
        // Emitted as op=5 with UINT8: 0=clear, 1=fall type A, 2=fall type B.
        // Confirmed via Ghidra of FW2 MSS (fp2_radar_mss_fw2.bin): FUN_0001db70
        // calls the frame serializer with SubID=0x121 and 1-byte payload. Debug
        // string "fall_detection:%d" sits at the emit site. Only fires in
        // work_mode=8 when the fall ML flags a ballistic upright→horizontal
        // motion pattern — lying down calmly will NOT trigger it.
        if (payload.size() >= 4 && payload[2] == 0x00) {
            uint8_t state = payload[3];
            ESP_LOGI(TAG, "Fall detection (0x0121): %u", state);
            if (fall_detection_sensor_ != nullptr) {
                fall_detection_sensor_->publish_state(state != 0);
            }
        }
        break;

    case AttrId::FALL_DETECTION_STATE:
        // 0x0122 — Stock ESP32 handler exists but radar never sends this SubID.
        // Kept for completeness.
        if (payload.size() >= 4 && payload[2] == 0x00) {
            uint8_t state = payload[3];
            ESP_LOGI(TAG, "Fall detection state (0x0122): %u", state);
            if (fall_detection_sensor_ != nullptr) {
                fall_detection_sensor_->publish_state(state != 0);
            }
        }
        break;

    case AttrId::PEOPLE_COUNTING:
        // 0x0155 — BLOB2, 7 bytes per report. People counting + dwell time.
        // Format: [ZoneID:1] [PeopleCount:2 BE] [DwellTime:4 BE]
        // DwellTime = 0.15 * cumulative_frame_count (NOT a fall indicator).
        // This SubID is sent from the radar's people counting function, which
        // also handles the "fall area" debug output — but the ontime/dwell field
        // is NOT fall detection. Actual fall detection uses SubID 0x0306.
        if (payload.size() >= 12 && payload[2] == 0x06) {
            uint16_t blob_len = (payload[3] << 8) | payload[4];
            if (blob_len >= 7 && payload.size() >= 5 + blob_len) {
                uint8_t zone_id = payload[5];
                uint16_t people_count = (payload[6] << 8) | payload[7];
                uint32_t dwell_time = ((uint32_t)payload[8] << 24) |
                                      ((uint32_t)payload[9] << 16) |
                                      ((uint32_t)payload[10] << 8) |
                                      ((uint32_t)payload[11]);

                ESP_LOGD(TAG, "People counting (0x0155): zone=%u people=%u dwell=%u",
                         zone_id, people_count, dwell_time);

                // Update per-zone people count if zone matches
                if (zone_id > 0) {
                    for (auto &z : zones_) {
                        if (z->id == zone_id && z->zone_people_count_sensor != nullptr) {
                            float current = z->zone_people_count_sensor->get_raw_state();
                            if (std::isnan(current) || (int)current != people_count) {
                                z->zone_people_count_sensor->publish_state((float)people_count);
                            }
                            break;
                        }
                    }
                }
            }
        }
        break;

    case AttrId::FALL_OVERTIME_DETECTION:
    case AttrId::FALL_OVERTIME_REPORT:
        // 0x0135/0x0136 — Fall overtime. Handler for both SubIDs since dispatch
        // table analysis shows radar_fall_overtime_det handles 0x0136 while
        // 0x0135 goes to a config handler. Accept either.
        if (payload.size() >= 7 && payload[2] == 0x02) {
            uint32_t value = ((uint32_t)payload[3] << 24) | ((uint32_t)payload[4] << 16) |
                             ((uint32_t)payload[5] << 8) | ((uint32_t)payload[6]);
            ESP_LOGW(TAG, "Fall overtime (0x%04X): value=%u", (uint16_t)attr_id, value);
            if (fall_overtime_sensor_ != nullptr) {
                fall_overtime_sensor_->publish_state(value != 0);
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
        // Sleep-state metadata: BLOB2 of 12 bytes emitted by vitalsigns firmware.
        // Previous IEEE-754-floats interpretation was INCORRECT. Ghidra of
        // fp2_radar_vitalsigns.bin FUN_00006c84 (emits via FUN_0001c71c(5,0x159,6,...))
        // shows 12 individual byte fields from ctx struct offsets +0x85..+0x90:
        //   blob[0]  sleep track id / person_id
        //   blob[1]  count
        //   blob[2]  motion
        //   blob[3]  sleep_stage (0 = idle)
        //   blob[4]  reserved / posture
        //   blob[5]  confidence  (≈ 100 at idle)
        //   blob[6]  bed_state / event
        //   blob[7]  reserved
        //   blob[8]  secondary confidence (≈ 100 at idle)
        //   blob[9..11]  reserved / terminator
        // HR and BR are NOT in this blob — they're on SubID 0x0117 in mode 9
        // (see handle_location_tracking_report_). Field semantics MEDIUM confidence.
        if (payload.size() >= 5 && payload[2] == 0x06) {
            uint16_t blob_len = (payload[3] << 8) | payload[4];
            if (blob_len >= 12 && payload.size() >= 17) {
                const uint8_t *b = &payload[5];
                ESP_LOGI(TAG,
                         "Sleep blob 0x159: tid=%u count=%u motion=%u stage=%u "
                         "posture=%u conf=%u bed=%u conf2=%u "
                         "(raw %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X)",
                         b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[8],
                         b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                         b[8], b[9], b[10], b[11]);
            } else {
                ESP_LOGW(TAG, "Sleep blob 0x159 unexpected size %d bytes", blob_len);
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
        ESP_LOGI(TAG, "First temperature at uptime=%u — radar boot complete", millis());
        if (init_done_) {
          ESP_LOGI(TAG, "Re-init: resending config commands to fully-booted radar");
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
  // Payload: [SubID 2] [Type 0x06(BLOB2)] [Len 2] [data...]
  if (payload.size() < 6 || payload[2] != 0x06) {
    return;
  }
  // SubID 0x0117 has the SAME 14-byte-per-target wire format but DIFFERENT
  // semantics depending on which radar firmware is booted:
  //
  //   FW1 (zone, mode 3) and FW2 (3d_people_counting, mode 8):
  //     blob[0]          target_count
  //     per target, 14 bytes:
  //       [0]            track_id  (u8)
  //       [1..2]         X         (u16 BE, cm)
  //       [3..4]         Y         (u16 BE, cm; clamped >=0 in mode 3)
  //       [5..6]         reserved (0)
  //       [7..8]         velocity  (u16 BE, cm/s)
  //       [9..10]        SNR       (u16 BE)
  //       [11..13]       status flags
  //     Emitter: FUN_0000cdbc in fp2_radar_dsp.bin (FW2) and
  //              FUN_00012f4c in fp2_radar_mss.bin (FW1).
  //
  //   FW3 (vital signs, mode 9) via FUN_00006c84:
  //     blob[0] = 1 (always single-target vitals frame)
  //     per target, 14 bytes:
  //       [0]            track_id  (u8)
  //       [1..2]         HR_bpm * 100  (u16 BE)
  //       [3..4]         BR_bpm * 100  (u16 BE)
  //       [5..13]        zeros
  //     Emitter: FUN_00006c84 @ 0x6c84 in fp2_radar_vitalsigns.bin.
  //     Gated on config+0xb8 == 1 (set by LOCATION_REPORT_ENABLE attr 0x0112).
  //
  // When sleep_mode_active_ we route to the vitals decode; otherwise to the
  // tracking decode.
  if (this->sleep_mode_active_) {
    // Diagnostic: dump the raw blob so we can see what FW3 is actually sending.
    if (debug_mode_) {
      char hexbuf[128];
      int n = 0;
      for (size_t i = 0; i < payload.size() && n < 120; i++) {
        n += snprintf(hexbuf + n, sizeof(hexbuf) - n, "%02x ", payload[i]);
      }
      ESP_LOGD(TAG, "Vitals frame (size=%zu): %s", payload.size(), hexbuf);
    }
    uint8_t vcount = payload[5];
    if (vcount == 0 || payload.size() < 6 + 14) {
      // Empty vitals frame (FW3 FUN_0002dc40 clear-path) or truncated payload.
      ESP_LOGD(TAG, "Vitals: empty frame (count=%u size=%zu) — no target locked", vcount, payload.size());
      if (heart_rate_sensor_ != nullptr) heart_rate_sensor_->publish_state(NAN);
      if (respiration_rate_sensor_ != nullptr) respiration_rate_sensor_->publish_state(NAN);
      return;
    }
    const int off = 6;
    uint16_t hr_x100 = ((uint16_t) payload[off + 1] << 8) | payload[off + 2];
    uint16_t br_x100 = ((uint16_t) payload[off + 3] << 8) | payload[off + 4];
    float hr_bpm = hr_x100 / 100.0f;
    float br_bpm = br_x100 / 100.0f;
    if (heart_rate_sensor_ != nullptr) heart_rate_sensor_->publish_state(hr_bpm);
    if (respiration_rate_sensor_ != nullptr) respiration_rate_sensor_->publish_state(br_bpm);
    ESP_LOGD(TAG, "Vitals: track_id=%u HR=%.1f BR=%.1f", payload[off], hr_bpm, br_bpm);
    return;
  }

  if (!this->location_reporting_active_) {
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
        ESP_LOGV(TAG, "Radar temperature report: %d", temp);
    } else {
        ESP_LOGD(TAG, "Unexpected radar temperature report format");
    }
}

void FP2Component::handle_response_(AttrId attr_id, const std::vector<uint8_t> &payload) {
  // Direction/angle queries only arrive after radar finishes booting
  if (!radar_ready_) {
    ESP_LOGI(TAG, "Radar ready (SubID=0x%04X, uptime=%u)", (uint16_t)attr_id, millis());
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
  ESP_LOGV(TAG, "Received Reverse Query for SubID 0x%04X", (uint16_t) attr_id);

  switch (attr_id) {
    case AttrId::DEVICE_DIRECTION:  // device_direction
      send_reverse_response_(attr_id, (uint8_t)fp2_accel_->get_orientation());
      ESP_LOGV(TAG, "Sending Device Direction: %d", fp2_accel_->get_orientation());
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
                                    uint32_t dword_val) {
  FP2Command cmd;
  cmd.type = type;
  cmd.attr_id = attr_id;
  cmd.retry_count = 0;

  // Payload: [SubID 2] [Type 1 (0x02 UINT32)] [Data 4 BE]
  cmd.data.push_back((((uint16_t) attr_id) >> 8) & 0xFF);
  cmd.data.push_back(((uint16_t) attr_id) & 0xFF);
  cmd.data.push_back(0x02); // UINT32
  cmd.data.push_back((dword_val >> 24) & 0xFF);
  cmd.data.push_back((dword_val >> 16) & 0xFF);
  cmd.data.push_back((dword_val >> 8) & 0xFF);
  cmd.data.push_back(dword_val & 0xFF);

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

void FP2Component::set_falldown_blind_zone(const std::vector<uint8_t> &grid) {
  ESP_LOGI(TAG, "set_falldown_blind_zone called with size: %d", grid.size());
  if (grid.size() == 40) {
    std::copy(grid.begin(), grid.end(), falldown_blind_zone_.begin());
    has_falldown_blind_zone_ = true;
  } else {
    ESP_LOGW(TAG, "Falldown blind zone size mismatch! Expected 40, got %d", grid.size());
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

void FP2RadarOtaProbeButton::press_action() {
  if (this->parent_ != nullptr) {
    this->parent_->trigger_radar_ota_probe();
  }
}

void FP2ResetRadarButton::press_action() {
  if (this->parent_ != nullptr) {
    this->parent_->trigger_reset_radar();
  }
}

void FP2RebootSensorButton::press_action() {
  if (this->parent_ != nullptr) {
    this->parent_->trigger_reboot_sensor();
  }
}

#ifdef USE_RADAR_FW_HTTP
// FreeRTOS task entry point. The download can spend 10+ s inside
// esp_http_client_open() (TLS handshake + crypto), which starves the
// idle task if run directly from press_action on the API task. Moving
// it to its own task lets FreeRTOS keep the idle task watchdog fed
// while blocking socket I/O naturally yields via lwIP.
void FP2Component::fw_stage_task_entry_(void *arg) {
  auto *self = static_cast<FP2Component *>(arg);

  ESP_LOGW(TAG, "=== Firmware staging task started ===");
  uint32_t existing = self->ota_detect_firmware_size_();
  if (existing > 0) {
    ESP_LOGI(TAG, "Stage firmware: valid firmware already on flash (%u bytes). Re-downloading...", existing);
  }

  if (self->ota_download_firmware_()) {
    uint32_t size = self->ota_detect_firmware_size_();
    ESP_LOGW(TAG, "Firmware staged: %u bytes written to flash. Ready for OTA.", size);
  } else {
    ESP_LOGE(TAG, "Firmware staging failed");
  }

  self->fw_stage_task_running_ = false;
  ESP_LOGI(TAG, "Firmware staging task finished");
  vTaskDelete(nullptr);
}
#endif

void FP2Component::trigger_radar_fw_stage() {
#ifdef USE_RADAR_FW_HTTP
  if (radar_firmware_url_.empty()) {
    ESP_LOGE(TAG, "Stage firmware: no radar_firmware_url configured");
    return;
  }

  if (fw_stage_task_running_) {
    ESP_LOGW(TAG, "Stage firmware: download already in progress, ignoring press");
    return;
  }

  // Spawn a background task so the API task returns immediately and the
  // TLS handshake / HTTPS read loop doesn't starve the idle task.
  //   stack=8 KB is enough for mbedTLS + lwIP in a slim caller
  //   priority=tskIDLE_PRIORITY+1 keeps it below the main loop so
  //     sensor publishing stays responsive during download
  fw_stage_task_running_ = true;
  BaseType_t ok = xTaskCreate(
      &FP2Component::fw_stage_task_entry_, "fp2_fw_stage", 8192,
      this, tskIDLE_PRIORITY + 1, nullptr);
  if (ok != pdPASS) {
    ESP_LOGE(TAG, "Stage firmware: failed to create download task");
    fw_stage_task_running_ = false;
    return;
  }
  ESP_LOGI(TAG, "Stage firmware: download started in background task");
#else
  ESP_LOGE(TAG, "Stage firmware: HTTP download not available (radar_firmware_url not configured at build time)");
#endif
}

void FP2Component::ota_send_trigger_frame_() {
  // Send OTA_SET_FLAG (SubID=0x0127 BOOL=true) as a raw one-shot frame,
  // bypassing the command_queue_ / ACK-retry machinery. Stock firmware does
  // not wait for a cluster ACK on this SubID — it installs raw-UART RX hooks
  // and polls for the XMODEM 'C' handshake instead. See Ghidra RE notes:
  // FUN_400e6e8c in fp2_aqara_fw1.bin at image_base 0x3ffadb5c.
  static uint8_t next_tx_seq = 0;

  std::vector<uint8_t> frame;
  frame.push_back(0x55);                                 // Sync
  frame.push_back(0x00);                                 // Version Hi
  frame.push_back(0x01);                                 // Version Lo
  frame.push_back(next_tx_seq++);                        // Seq
  frame.push_back((uint8_t) OpCode::WRITE);              // Op
  frame.push_back(0x00);                                 // Len Hi
  frame.push_back(0x04);                                 // Len Lo

  uint8_t sum = 0;
  for (int i = 0; i < 7; i++)
    sum += frame[i];
  frame.push_back((uint8_t)(~(sum - 1)));                // Header checksum

  frame.push_back(0x01);                                 // SubID Hi
  frame.push_back(0x27);                                 // SubID Lo
  frame.push_back(0x04);                                 // Type: BOOL
  frame.push_back(0x01);                                 // Value: true

  uint16_t crc = crc16(frame.data(), frame.size());
  frame.push_back(crc & 0xFF);
  frame.push_back((crc >> 8) & 0xFF);

  ESP_LOGD(TAG, "TX: op=2 SubID=0x0127 len=4 (one-shot, no ACK)");
  write_array(frame);
  flush();
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
  if (mcu_ota_partition_ == nullptr) {
    ESP_LOGE(TAG, "OTA: mcu_ota partition not available (custom partition table required)");
    return 0;
  }

  // Validate the firmware starts with TI MSTR magic header
  uint8_t magic[4];
  esp_err_t err = esp_partition_read(mcu_ota_partition_, 0, magic, 4);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "OTA: cannot read mcu_ota partition (err=0x%x)", err);
    return 0;
  }

  // TI IWR6843 firmware starts with "MSTR" (0x4D535452).
  // Distinguish three cases:
  //   - all 0xFF  -> partition is empty (fresh erase, nothing to stage yet)
  //   - all 0x00  -> partition was wiped but not erased properly
  //   - anything else -> garbage / corrupted / wrong file was written
  bool all_ff = magic[0] == 0xFF && magic[1] == 0xFF && magic[2] == 0xFF && magic[3] == 0xFF;
  bool all_00 = magic[0] == 0x00 && magic[1] == 0x00 && magic[2] == 0x00 && magic[3] == 0x00;
  if (all_ff) {
    ESP_LOGI(TAG, "OTA: mcu_ota partition is empty — no staged firmware");
    return 0;
  }
  if (all_00) {
    ESP_LOGW(TAG, "OTA: mcu_ota partition is all zeros — needs re-erase before use");
    return 0;
  }
  if (magic[0] != 'M' || magic[1] != 'S' || magic[2] != 'T' || magic[3] != 'R') {
    ESP_LOGE(TAG, "OTA: staged data looks corrupted — expected MSTR header, got %02x %02x %02x %02x. Re-stage to recover.",
             magic[0], magic[1], magic[2], magic[3]);
    return 0;
  }

  // Scan backwards from end of partition to find last non-0xFF byte
  uint8_t buf[256];
  uint32_t offset = mcu_ota_partition_->size;

  while (offset > 0) {
    uint32_t chunk = (offset >= sizeof(buf)) ? sizeof(buf) : offset;
    offset -= chunk;
    err = esp_partition_read(mcu_ota_partition_, offset, buf, chunk);
    if (err != ESP_OK) {
      ESP_LOGE(TAG, "OTA: partition read error at offset %u: 0x%x", offset, err);
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
  if (mcu_ota_partition_ == nullptr) {
    ESP_LOGE(TAG, "OTA: mcu_ota partition not available (custom partition table required)");
    return false;
  }
  if (radar_firmware_url_.empty()) {
    ESP_LOGE(TAG, "OTA: no radar_firmware_url configured");
    return false;
  }

  ESP_LOGI(TAG, "OTA: downloading firmware from %s", radar_firmware_url_.c_str());

  esp_http_client_config_t config = {};
  config.url = radar_firmware_url_.c_str();
  config.timeout_ms = 30000;
  config.buffer_size = 4096;
  config.crt_bundle_attach = esp_crt_bundle_attach;  // HTTPS via mbedTLS cert bundle

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

  if ((uint32_t)content_length > mcu_ota_partition_->size) {
    ESP_LOGE(TAG, "OTA: firmware too large (%d bytes, partition is %u)",
             content_length, (unsigned) mcu_ota_partition_->size);
    esp_http_client_close(client);
    esp_http_client_cleanup(client);
    return false;
  }

  ESP_LOGI(TAG, "OTA: firmware size %d bytes, erasing flash...", content_length);

  // Erase the partition in 64KB chunks. A single multi-MB erase call blocks
  // ~20-30s, which starves the idle task and trips the IDF task watchdog.
  // Yielding between chunks keeps the scheduler alive.
  uint32_t erase_size = ((content_length + 4095) / 4096) * 4096;
  const uint32_t ERASE_CHUNK = 64 * 1024;
  for (uint32_t off = 0; off < erase_size; off += ERASE_CHUNK) {
    uint32_t this_chunk = std::min(ERASE_CHUNK, erase_size - off);
    err = esp_partition_erase_range(mcu_ota_partition_, off, this_chunk);
    if (err != ESP_OK) {
      ESP_LOGE(TAG, "OTA: partition erase failed at offset %u (0x%x)", off, err);
      esp_http_client_close(client);
      esp_http_client_cleanup(client);
      return false;
    }
    App.feed_wdt();
    delay(1);  // yield to scheduler (idle task must run)
    if ((off & 0xfffff) == 0) {
      ESP_LOGI(TAG, "OTA: erased %u/%u bytes", off + this_chunk, erase_size);
    }
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

    err = esp_partition_write(mcu_ota_partition_, written, buf, read);
    if (err != ESP_OK) {
      ESP_LOGE(TAG, "OTA: partition write failed at offset %u (0x%x)", written, err);
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

    // Yield to scheduler every chunk. HTTPS reads + flash writes together
    // can starve the idle task past the 5s task watchdog timeout.
    App.feed_wdt();
    delay(1);
  }

  esp_http_client_close(client);
  esp_http_client_cleanup(client);

  // Verify what we wrote by re-reading the header
  uint8_t verify[4];
  esp_partition_read(mcu_ota_partition_, 0, verify, 4);
  if (verify[0] != 'M' || verify[1] != 'S' || verify[2] != 'T' || verify[3] != 'R') {
    ESP_LOGE(TAG, "OTA: flash verification failed!");
    return false;
  }

  ESP_LOGI(TAG, "OTA: firmware downloaded and verified (%u bytes)", written);
  return true;
}
#endif  // USE_RADAR_FW_HTTP

void FP2Component::trigger_radar_ota_probe() {
  if (ota_state_ != OtaState::IDLE) {
    ESP_LOGW(TAG, "Radar OTA already in progress, probe skipped");
    return;
  }

  ESP_LOGW(TAG, "=== Radar OTA Probe: SAFE TEST (no flash write) ===");
  ESP_LOGW(TAG, "Step 1: send WRITE 0x0127 (OTA_SET_FLAG) as one-shot frame (no ACK wait)");
  ESP_LOGW(TAG, "Step 2: watch for sustained 'C' (0x43) from XMODEM bootloader (20s)");
  ESP_LOGW(TAG, "Step 3: on handshake confirm, send CAN x3 to abort without writing flash");

  ota_probe_only_ = true;
  ota_firmware_size_ = 0;
  ota_firmware_offset_ = 0;
  ota_block_num_ = 1;
  ota_retry_count_ = 0;
  ota_can_count_ = 0;
  ota_probe_c_count_ = 0;
  ota_probe_last_c_millis_ = 0;
  ota_probe_sof_count_ = 0;

  // Stock firmware (Ghidra: FUN_400e6e8c) sends this frame once and does NOT
  // wait for a cluster ACK. The radar never emits one for SubID 0x0127 — it
  // switches its UART into raw XMODEM mode and emits 'C' bytes instead.
  // Previous implementations that waited for ACK falsely concluded the trigger
  // was rejected, then aborted before ever seeing the handshake.
  ota_send_trigger_frame_();

  ota_state_ = OtaState::WAITING_HANDSHAKE;
  ota_state_start_millis_ = millis();
}

void FP2Component::trigger_radar_ota() {
  if (ota_state_ != OtaState::IDLE) {
    ESP_LOGW(TAG, "Radar OTA already in progress");
    return;
  }

  ota_probe_only_ = false;

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
  if (mcu_ota_partition_ == nullptr ||
      ota_firmware_size_ > mcu_ota_partition_->size) {
    ESP_LOGE(TAG, "OTA ABORTED: firmware too large or partition missing (%u bytes)",
             ota_firmware_size_);
    return;
  }

  uint32_t blocks = ota_firmware_size_ / XMODEM_BLOCK_SIZE;
  ESP_LOGW(TAG, "=== Starting Radar OTA: %u bytes (%u blocks) ===",
           ota_firmware_size_, blocks);
  ESP_LOGW(TAG, "WARNING: Do not power off the device during transfer!");

  ota_firmware_offset_ = 0;
  ota_block_num_ = 1;
  ota_retry_count_ = 0;
  ota_can_count_ = 0;

  if (ota_transfer_task_running_) {
    ESP_LOGW(TAG, "OTA: transfer task already running, ignoring press");
    return;
  }

  // Gate main loop out of UART while the task drives the transfer.
  ota_state_ = OtaState::TRANSFERRING;
  ota_transfer_task_running_ = true;

  BaseType_t ok = xTaskCreate(
      &FP2Component::ota_transfer_task_entry_,
      "fp2_ota_xfer",
      8192,
      this,
      tskIDLE_PRIORITY + 2,
      nullptr);
  if (ok != pdPASS) {
    ESP_LOGE(TAG, "OTA: failed to spawn transfer task");
    ota_transfer_task_running_ = false;
    ota_state_ = OtaState::IDLE;
    return;
  }
  ESP_LOGI(TAG, "OTA: transfer task spawned");
}

void FP2Component::ota_transfer_task_entry_(void *arg) {
  auto *self = static_cast<FP2Component *>(arg);
  self->ota_transfer_task_run_();
  // Important: set DONE before clearing the running flag so the main loop
  // never observes TRANSFERRING with the task already gone.
  self->ota_state_ = OtaState::DONE;
  self->ota_transfer_task_running_ = false;
  vTaskDelete(nullptr);
}

// ---------------------------------------------------------------------------
// Reset / reboot helpers
// ---------------------------------------------------------------------------

void FP2Component::trigger_reset_radar() {
  ESP_LOGW(TAG, "Reset radar: pulsing GPIO13");
  if (reset_pin_ != nullptr) {
    reset_pin_->digital_write(false);
    delay(100);
    reset_pin_->digital_write(true);
  }
  // Clear ESP-side radar state so it re-inits on the next heartbeat.
  init_done_ = false;
  radar_ready_ = false;
  last_heartbeat_millis_ = 0;
  state_ = SYNC;
  command_queue_.clear();
  waiting_for_ack_attr_id_ = AttrId::INVALID;
}

void FP2Component::trigger_reboot_sensor() {
  ESP_LOGW(TAG, "Reboot sensor: esp_restart() in 100ms");
  delay(100);
  esp_restart();
}

// ---------------------------------------------------------------------------
// Telnet server — TCP bridge on telnet_port_ (default 6666)
// ---------------------------------------------------------------------------
//
// Text protocol, one line per command. Line endings may be \n or \r\n.
// Commands:
//   TX <hex> [<hex> ...]   Write raw bytes to UART (hex pairs, space-separated
//                          or packed). Checksum/CRC is caller's responsibility.
//   MODE RAW               Stop ESPHome's UART decode path; client owns UART.
//   MODE NORMAL            Resume normal ESPHome operation.
//   RESET RADAR            Pulse GPIO13 and clear ESP-side init state.
//   REBOOT ESP             esp_restart() — client will be disconnected.
//   STATUS                 One line with mode, uptime, connection state.
//   HELP                   List commands.
// Asynchronous stream:
//   RX t=<ms> <hex> ...    Each contiguous UART burst from the radar.
//   TXLOG t=<ms> <hex> ... ESPHome's own TX frames (observability only).

void FP2Component::start_telnet_() {
  telnet_client_fd_ = -1;
  telnet_listen_fd_ = -1;
  BaseType_t ok = xTaskCreate(
      &FP2Component::telnet_task_entry_,
      "fp2_telnet",
      6144,
      this,
      tskIDLE_PRIORITY + 1,
      nullptr);
  if (ok != pdPASS) {
    ESP_LOGE(TAG, "Telnet: failed to create accept task");
    return;
  }
  ESP_LOGI(TAG, "Telnet: listening on port %u", (unsigned) telnet_port_);
}

void FP2Component::telnet_task_entry_(void *arg) {
  auto *self = static_cast<FP2Component *>(arg);
  self->telnet_task_run_();
  vTaskDelete(nullptr);
}

void FP2Component::telnet_task_run_() {
  // Wait for the lwip tcpip_thread mutex to be valid before calling
  // lwip_socket() — otherwise we hit an assertion in sys_mutex_lock and the
  // whole app panics. The mutex is initialized once esp_netif_init()
  // completes. Easiest portable check: wait until any netif exists.
  for (int i = 0; i < 200; i++) {  // up to ~20 s
    esp_netif_t *any = esp_netif_next_unsafe(nullptr);
    if (any != nullptr) {
      break;
    }
    vTaskDelay(pdMS_TO_TICKS(100));
  }
  // Extra grace period so WiFi sta has actually started, not just esp_netif.
  vTaskDelay(pdMS_TO_TICKS(2000));

  struct sockaddr_in server_addr = {};
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  server_addr.sin_port = htons(telnet_port_);

  // Use lwip-prefixed names to avoid symbol collisions with ESPHome's own
  // esphome::socket::Socket class and similar wrappers.
  telnet_listen_fd_ = lwip_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (telnet_listen_fd_ < 0) {
    ESP_LOGE(TAG, "Telnet: socket() failed");
    return;
  }
  int yes = 1;
  lwip_setsockopt(telnet_listen_fd_, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
  if (lwip_bind(telnet_listen_fd_, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
    ESP_LOGE(TAG, "Telnet: bind(%u) failed", (unsigned) telnet_port_);
    lwip_close(telnet_listen_fd_);
    telnet_listen_fd_ = -1;
    return;
  }
  if (lwip_listen(telnet_listen_fd_, 1) < 0) {
    ESP_LOGE(TAG, "Telnet: listen() failed");
    lwip_close(telnet_listen_fd_);
    telnet_listen_fd_ = -1;
    return;
  }

  while (true) {
    struct sockaddr_in client_addr = {};
    socklen_t addrlen = sizeof(client_addr);
    int new_fd = lwip_accept(telnet_listen_fd_, (struct sockaddr *) &client_addr, &addrlen);
    if (new_fd < 0) {
      vTaskDelay(pdMS_TO_TICKS(100));
      continue;
    }
    // Only one client at a time — kick any existing client.
    if (telnet_client_fd_ >= 0) {
      const char *bye = "NOTICE new client connected, closing\n";
      lwip_send(telnet_client_fd_, bye, strlen(bye), 0);
      lwip_close(telnet_client_fd_);
    }
    telnet_client_fd_ = new_fd;
    ESP_LOGI(TAG, "Telnet: client connected (fd=%d)", new_fd);
    const char *banner =
        "# FP2 telnet bridge. TX <hex>, MODE RAW|NORMAL, RESET RADAR, "
        "REBOOT ESP, STATUS, HELP\n";
    lwip_send(new_fd, banner, strlen(banner), 0);

    // Per-client read loop — parses commands line by line.
    std::string line_buf;
    char recv_buf[256];
    while (true) {
      ssize_t n = lwip_recv(new_fd, recv_buf, sizeof(recv_buf), 0);
      if (n <= 0) {
        ESP_LOGI(TAG, "Telnet: client disconnected");
        break;
      }
      for (ssize_t i = 0; i < n; i++) {
        char c = recv_buf[i];
        if (c == '\r')
          continue;
        if (c == '\n') {
          if (!line_buf.empty()) {
            telnet_handle_command_(line_buf);
            line_buf.clear();
          }
        } else {
          if (line_buf.size() < 512)
            line_buf.push_back(c);
        }
      }
    }
    telnet_close_client_();
  }
}

void FP2Component::telnet_close_client_() {
  if (telnet_client_fd_ >= 0) {
    lwip_close(telnet_client_fd_);
    telnet_client_fd_ = -1;
  }
  telnet_raw_mode_ = false;  // failsafe — never leave radio gagged
}

void FP2Component::telnet_send_line_(const char *line) {
  int fd = telnet_client_fd_;
  if (fd < 0)
    return;
  ssize_t n = lwip_send(fd, line, strlen(line), MSG_DONTWAIT);
  if (n < 0) {
    // Client likely dropped — close and let accept loop pick up new one
    telnet_close_client_();
  }
}

static int hex_nibble_(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return 10 + c - 'a';
  if (c >= 'A' && c <= 'F')
    return 10 + c - 'A';
  return -1;
}

void FP2Component::telnet_handle_command_(const std::string &line) {
  // Uppercase the first word for matching
  size_t space = line.find(' ');
  std::string cmd = line.substr(0, space);
  std::string rest = space == std::string::npos ? "" : line.substr(space + 1);
  for (auto &c : cmd)
    c = (c >= 'a' && c <= 'z') ? (c - 'a' + 'A') : c;

  if (cmd == "TX") {
    // Parse hex pairs (ignore whitespace)
    std::vector<uint8_t> bytes;
    int hi = -1;
    for (char c : rest) {
      if (c == ' ' || c == '\t')
        continue;
      int n = hex_nibble_(c);
      if (n < 0) {
        telnet_send_line_("ERR bad hex digit\n");
        return;
      }
      if (hi < 0) {
        hi = n;
      } else {
        bytes.push_back((uint8_t)((hi << 4) | n));
        hi = -1;
      }
    }
    if (hi >= 0) {
      telnet_send_line_("ERR odd hex digit count\n");
      return;
    }
    if (bytes.empty()) {
      telnet_send_line_("ERR TX needs hex bytes\n");
      return;
    }
    write_array(bytes.data(), bytes.size());
    flush();
    char reply[64];
    snprintf(reply, sizeof(reply), "OK TX %u bytes\n", (unsigned) bytes.size());
    telnet_send_line_(reply);
    return;
  }
  if (cmd == "MODE") {
    // MODE RAW / MODE NORMAL
    std::string arg = rest;
    for (auto &c : arg)
      c = (c >= 'a' && c <= 'z') ? (c - 'a' + 'A') : c;
    if (arg == "RAW") {
      telnet_raw_mode_ = true;
      telnet_send_line_("OK MODE RAW (ESPHome UART decode suspended)\n");
    } else if (arg == "NORMAL") {
      telnet_raw_mode_ = false;
      telnet_send_line_("OK MODE NORMAL\n");
    } else {
      telnet_send_line_("ERR MODE needs RAW or NORMAL\n");
    }
    return;
  }
  if (cmd == "RESET" && rest == "RADAR") {
    trigger_reset_radar();
    telnet_send_line_("OK RESET RADAR\n");
    return;
  }
  if (cmd == "REBOOT" && rest == "ESP") {
    telnet_send_line_("OK REBOOT ESP (goodbye)\n");
    delay(50);
    trigger_reboot_sensor();
    return;
  }
  if (cmd == "STATUS") {
    char reply[256];
    snprintf(reply, sizeof(reply),
             "STATUS mode=%s uptime_ms=%u hb=%u init=%d rdy=%d q=%d ack=%u drop=%u\n",
             telnet_raw_mode_ ? "RAW" : "NORMAL",
             (unsigned) millis(),
             (unsigned) last_heartbeat_millis_,
             (int) init_done_,
             (int) radar_ready_,
             (int) command_queue_.size(),
             (unsigned) diag_acks,
             (unsigned) diag_drops);
    telnet_send_line_(reply);
    return;
  }
  if (cmd == "HELP" || cmd == "?") {
    telnet_send_line_(
        "HELP\n"
        "  TX <hex>           Write raw bytes to radar UART\n"
        "  MODE RAW           Suspend ESPHome UART decode (client exclusive)\n"
        "  MODE NORMAL        Resume ESPHome UART decode\n"
        "  RESET RADAR        Pulse GPIO13, clear ESP-side init state\n"
        "  REBOOT ESP         esp_restart() (connection drops)\n"
        "  STATUS             Print current state\n"
        "Stream: RX t=<ms> <hex>... | TXLOG t=<ms> <hex>...\n"
        "OK HELP\n");
    return;
  }
  telnet_send_line_("ERR unknown command — try HELP\n");
}

void FP2Component::telnet_observe_rx_(uint8_t byte) {
  if (telnet_client_fd_ < 0)
    return;
  if (telnet_rx_burst_len_ == 0) {
    telnet_rx_burst_start_ms_ = millis();
  }
  if (telnet_rx_burst_len_ < sizeof(telnet_rx_burst_)) {
    telnet_rx_burst_[telnet_rx_burst_len_++] = byte;
  }
}

void FP2Component::telnet_flush_rx_burst_() {
  if (telnet_rx_burst_len_ == 0)
    return;
  if (telnet_client_fd_ < 0) {
    telnet_rx_burst_len_ = 0;
    return;
  }
  // Format: "RX t=<ms> HH HH HH ...\n" with enough buffer for the max burst
  char out[4 + 12 + 3 * 256 + 2];
  int pos = snprintf(out, sizeof(out), "RX t=%u", (unsigned) telnet_rx_burst_start_ms_);
  for (size_t i = 0; i < telnet_rx_burst_len_ && pos + 4 < (int) sizeof(out); i++) {
    pos += snprintf(out + pos, sizeof(out) - pos, " %02X", telnet_rx_burst_[i]);
  }
  pos += snprintf(out + pos, sizeof(out) - pos, "\n");
  telnet_send_line_(out);
  telnet_rx_burst_len_ = 0;
}

void FP2Component::ota_transfer_task_run_() {
  ESP_LOGI(TAG, "[xfer] sending 0x0127 trigger and waiting for handshake");
  ota_send_trigger_frame_();

  // Drain any stale bytes (the trigger ACK we don't need, residual protocol frames)
  // so we don't mistake them for XMODEM bytes.
  while (available()) {
    uint8_t drop;
    read_byte(&drop);
  }

  // Wait for 'C' handshake — ≥2 'C's with ≥500 ms separation
  uint32_t start = millis();
  uint32_t last_c = 0;
  uint32_t c_count = 0;
  while (millis() - start < OTA_HANDSHAKE_TIMEOUT_MS) {
    while (available()) {
      uint8_t b;
      read_byte(&b);
      if (b == 'C') {
        if (c_count == 0 || (millis() - last_c) >= 500) {
          c_count++;
          last_c = millis();
          ESP_LOGI(TAG, "[xfer] handshake 'C' #%u", c_count);
          if (c_count >= 2)
            goto handshake_ok;
        }
      }
    }
    vTaskDelay(pdMS_TO_TICKS(10));
  }
  ESP_LOGE(TAG, "[xfer] handshake timeout — aborting");
  return;

handshake_ok:
  ESP_LOGI(TAG, "[xfer] handshake confirmed, streaming %u blocks", ota_firmware_size_ / XMODEM_BLOCK_SIZE);

  uint32_t xfer_start = millis();
  uint32_t last_progress_pct = 0;
  uint8_t retry_count = 0;
  uint32_t can_count = 0;

  while (ota_firmware_offset_ < ota_firmware_size_) {
    ota_send_current_block_();

    // Wait tight for ACK/NAK/CAN
    uint32_t block_start = millis();
    bool advanced = false;
    bool retransmit = false;

    while (!advanced && !retransmit) {
      if (available()) {
        uint8_t b;
        read_byte(&b);
        if (b == 0x06) {  // ACK
          ota_firmware_offset_ += XMODEM_BLOCK_SIZE;
          ota_block_num_++;
          retry_count = 0;
          advanced = true;
        } else if (b == 0x15) {  // NAK
          retry_count++;
          if (retry_count >= OTA_MAX_RETRIES) {
            ESP_LOGE(TAG, "[xfer] max NAK retries on block %d, aborting", ota_block_num_);
            return;
          }
          ESP_LOGW(TAG, "[xfer] NAK on block %d, retry %d", ota_block_num_, retry_count);
          retransmit = true;
        } else if (b == 0x18) {  // CAN
          can_count++;
          if (can_count > 10) {
            ESP_LOGE(TAG, "[xfer] cancelled by radar at block %d (offset %u)",
                     ota_block_num_, ota_firmware_offset_);
            return;
          }
        }
        // ignore any other byte
      } else if (millis() - block_start > OTA_TRANSFER_TIMEOUT_MS) {
        retry_count++;
        if (retry_count >= OTA_MAX_RETRIES) {
          ESP_LOGE(TAG, "[xfer] timeout max retries on block %d", ota_block_num_);
          return;
        }
        ESP_LOGW(TAG, "[xfer] timeout on block %d, retry %d", ota_block_num_, retry_count);
        retransmit = true;
      } else {
        // Short sleep — task yield, keeps watchdog happy, doesn't burn CPU
        vTaskDelay(1);  // 1 tick ≈ 10 ms; ACK inter-arrival is much longer than that
      }
    }

    uint32_t pct = (uint64_t) ota_firmware_offset_ * 100 / ota_firmware_size_;
    if (pct >= last_progress_pct + 5) {
      last_progress_pct = pct;
      uint32_t elapsed_s = (millis() - xfer_start) / 1000;
      uint32_t rate_bps = elapsed_s ? (ota_firmware_offset_ / elapsed_s) : 0;
      ESP_LOGI(TAG, "[xfer] %u%% (%u/%u bytes, %us elapsed, %u B/s)",
               pct, ota_firmware_offset_, ota_firmware_size_, elapsed_s, rate_bps);
    }
  }

  ESP_LOGI(TAG, "[xfer] all blocks ACK'd, sending EOT");
  ota_send_eot_();

  // Wait for final ACK on EOT
  uint32_t eot_start = millis();
  while (millis() - eot_start < OTA_TRANSFER_TIMEOUT_MS) {
    if (available()) {
      uint8_t b;
      read_byte(&b);
      if (b == 0x06) {
        uint32_t total_s = (millis() - xfer_start) / 1000;
        ESP_LOGW(TAG, "[xfer] === OTA COMPLETE: %u bytes in %u seconds ===",
                 ota_firmware_size_, total_s);
        return;
      }
    }
    vTaskDelay(1);
  }
  ESP_LOGE(TAG, "[xfer] EOT timeout, radar did not confirm end-of-transfer");
}

void FP2Component::ota_send_current_block_() {
  // Read 1024 bytes from flash via mcu_ota partition
  uint8_t *data = &ota_packet_buf_[3];  // Skip STX, blk, ~blk
  uint32_t remaining = ota_firmware_size_ - ota_firmware_offset_;
  uint32_t to_read = (remaining >= XMODEM_BLOCK_SIZE) ? XMODEM_BLOCK_SIZE : remaining;

  esp_err_t err = esp_partition_read(mcu_ota_partition_, ota_firmware_offset_, data, to_read);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Flash read error at offset %u (err=0x%x)", ota_firmware_offset_, err);
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
  // flush() blocks until the UART ring buffer has drained onto the wire.
  // Without this, ESPHome dribbles bytes out over many loop iterations and
  // the radar's internal XMODEM timeout can fire mid-block, triggering a
  // NAK or CAN. Observed ~640 ms/block without flush vs ~15 ms expected.
  flush();

  ESP_LOGD(TAG, "OTA: sent block %d (offset %u/%u, %d%%)",
           ota_block_num_, ota_firmware_offset_,
           ota_firmware_size_,
           (int)(ota_firmware_offset_ * 100 / ota_firmware_size_));
}

void FP2Component::ota_send_eot_() {
  uint8_t eot = 0x04;
  write_array(&eot, 1);
  flush();
}

void FP2Component::ota_loop_() {
  uint32_t now = millis();

  switch (ota_state_) {
    case OtaState::WAITING_HANDSHAKE: {
      // Looking for XMODEM-1K bootloader output. CRC mode: repeated 'C' (0x43)
      // every ~3s. We require ≥2 'C' bytes separated by ≥500ms to suppress
      // false positives from the radar's normal protocol traffic.
      while (available()) {
        uint8_t byte;
        read_byte(&byte);

        if (byte == 0x55) {
          // Aqara protocol SOF — radar is still in normal mode, not bootloader
          ota_probe_sof_count_++;
        } else if (byte == 'C') {
          if (ota_probe_c_count_ == 0 ||
              (now - ota_probe_last_c_millis_) >= 500) {
            ota_probe_c_count_++;
            ota_probe_last_c_millis_ = now;
            if (ota_probe_only_) {
              ESP_LOGW(TAG, "Probe: isolated 'C' #%u received", ota_probe_c_count_);
            }
          }

          if (ota_probe_c_count_ >= 2) {
            if (ota_probe_only_) {
              ESP_LOGW(TAG, "=== PROBE SUCCESS: sustained XMODEM 'C' handshake confirmed ===");
              ESP_LOGW(TAG, "OTA endpoint confirmed. Sending CAN x3 to abort without writing flash.");
              uint8_t can_abort[3] = {0x18, 0x18, 0x18};
              write_array(can_abort, 3);
              flush();
              ota_state_ = OtaState::DONE;
              return;
            }
            ESP_LOGI(TAG, "OTA: XMODEM handshake confirmed, starting transfer");
            ota_state_ = OtaState::TRANSFERRING;
            ota_state_start_millis_ = now;
            ota_retry_count_ = 0;
            ota_send_current_block_();
            return;
          }
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
        if (ota_probe_only_) {
          ESP_LOGE(TAG, "=== PROBE RESULT: NO XMODEM HANDSHAKE (20s) ===");
          ESP_LOGE(TAG, "Trigger frame sent but radar never emitted 'C' (0x43)");
          ESP_LOGE(TAG, "  isolated 'C' bytes: %u (need >=2 for success)", ota_probe_c_count_);
          ESP_LOGE(TAG, "  Aqara SOF (0x55) bytes seen: %u", ota_probe_sof_count_);
          if (ota_probe_sof_count_ > 0) {
            ESP_LOGE(TAG, "  -> radar is still emitting normal protocol frames");
            ESP_LOGE(TAG, "  -> 0x0127 alone may be insufficient; check for 2-stage init");
          }
        } else {
          ESP_LOGE(TAG, "OTA: handshake timeout (20s), aborting");
        }
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
      if (ota_probe_only_) {
        ESP_LOGW(TAG, "=== PROBE DONE: resetting radar to recover from bootloader ===");
      } else {
        ESP_LOGI(TAG, "OTA: resetting radar and resuming normal operation");
      }
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
      ota_probe_only_ = false;
      break;
    }

    default:
      break;
  }
}

} // namespace aqara_fp2
} // namespace esphome
