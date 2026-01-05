#pragma once

#include "esphome/core/component.h"
#include <cstdint>
#include <array>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/semphr.h>
#include <driver/i2c.h>

namespace esphome {
namespace aqara_fp2_accel {

static const char *const TAG = "aqara_fp2_accel";

// I2C address for the accelerometer
static const uint8_t ACC_SENSOR_ADDR = 0x27;

// Number of samples to buffer
static const uint8_t ACC_SAMPLE_COUNT = 10;

// Constants for angle calculations
static const double PI = 3.141614159265;
static const double RAD_TO_SCALED_DEG = 180.0 / PI / 0.5;
static const double EPSILON = 0.00001;

// Orientation enumeration
enum class Orientation : uint8_t {
  UP = 0,
  UP_TILT = 1,
  UP_TILT_REV = 2,
  SIDE = 3,
  SIDE_REV = 4,
  DOWN = 5,
  DOWN_TILT = 6,
  DOWN_TILT_REV = 7,
  INVALID = 8
};

// String mapping for logging
static const char *orientation_to_string(Orientation orient) {
  switch (orient) {
    case Orientation::UP: return "UP";
    case Orientation::UP_TILT: return "UP_TILT";
    case Orientation::UP_TILT_REV: return "UP_TILT_REV";
    case Orientation::SIDE: return "SIDE";
    case Orientation::SIDE_REV: return "SIDE_REV";
    case Orientation::DOWN: return "DOWN";
    case Orientation::DOWN_TILT: return "DOWN_TILT";
    case Orientation::DOWN_TILT_REV: return "DOWN_TILT_REV";
    case Orientation::INVALID: return "INVALID";
    default: return "UNKNOWN";
  }
}

// Accelerometer state tracking
struct AccelState {
  uint8_t deb_invalid{0};
  uint8_t deb_side{0};
  uint8_t deb_side_rev{0};
  int32_t last_acc_sum{0};
  uint8_t vib_high_cnt{0};
  uint8_t vib_low_cnt{0};
  bool is_vibrating{false};
};

class AqaraFP2Accel : public Component {
 public:
  void setup() override;
  void loop() override {}
  void dump_config() override;

  float get_setup_priority() const override { return setup_priority::BUS; }

  // Public accessors for outputs (thread-safe)
  int get_output_angle_z() const;
  Orientation get_orientation() const;
  bool is_vibrating() const;

  // Calibration
  bool calculate_calibration();

  // Task configuration
  void set_update_interval(uint32_t interval_ms) { update_interval_ms_ = interval_ms; }

 protected:
  // I2C initialization
  bool i2c_init_bus();

  // I2C low level functions (using ESP-IDF driver directly)
  bool i2c_read_accel_xyz(int16_t *x, int16_t *y, int16_t *z);
  bool i2c_write_reg(uint8_t reg, uint8_t value);
  void i2c_init_acc();

  // Data processing
  void read_process_accel();
  void acc_data_deal(int32_t acc_raw_x, int32_t acc_raw_y, int32_t acc_raw_z, int acc_mag_sum);

  // Sample buffers
  std::array<int16_t, ACC_SAMPLE_COUNT> read_acc_x_buf_{};
  std::array<int16_t, ACC_SAMPLE_COUNT> read_acc_y_buf_{};
  std::array<int16_t, ACC_SAMPLE_COUNT> read_acc_z_buf_{};
  uint8_t accel_samples_read_{0};

  // Averaged values
  int16_t acc_x_avg_{0};
  int16_t acc_y_avg_{0};
  int16_t acc_z_avg_{0};

  // Factory calibration corrections
  int16_t accel_corr_x_{0};
  int16_t accel_corr_y_{0};
  int16_t accel_corr_z_{0};

  // State tracking
  AccelState acc_state_{};
  Orientation stable_orientation_{Orientation::INVALID};
  Orientation raw_orientation_{Orientation::INVALID};
  bool prev_vib_state_{false};
  int output_angle_z_{0};

  // FreeRTOS task management
  TaskHandle_t task_handle_{nullptr};
  SemaphoreHandle_t mutex_{nullptr};
  uint32_t update_interval_ms_{100};
  bool task_running_{false};

  // ESP-IDF I2C configuration
  i2c_port_t i2c_port_{I2C_NUM_0};
  uint8_t sda_pin_{33};
  uint8_t scl_pin_{32};
  uint32_t frequency_{400000};  // 400kHz
  bool i2c_initialized_{false};

  // Static task function
  static void accel_task_(void *param);

  // Thread-safe task loop
  void task_loop_();
};

}  // namespace aqara_fp2_accel
}  // namespace esphome
