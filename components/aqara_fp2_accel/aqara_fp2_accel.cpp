#include "aqara_fp2_accel.h"
#include "esphome/core/log.h"
#include "esphome/core/hal.h"
#include <cmath>

namespace esphome {
namespace aqara_fp2_accel {

bool AqaraFP2Accel::i2c_init_bus() {
  ESP_LOGI(TAG, "Initializing I2C bus on port %d (SDA=%d, SCL=%d, freq=%d Hz)",
           i2c_port_, sda_pin_, scl_pin_, frequency_);

  i2c_config_t conf = {};
  conf.mode = I2C_MODE_MASTER;
  conf.sda_io_num = static_cast<gpio_num_t>(sda_pin_);
  conf.scl_io_num = static_cast<gpio_num_t>(scl_pin_);
  conf.sda_pullup_en = GPIO_PULLUP_ENABLE;
  conf.scl_pullup_en = GPIO_PULLUP_ENABLE;
  conf.master.clk_speed = frequency_;

  esp_err_t err = i2c_param_config(i2c_port_, &conf);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "I2C param config failed: %s", esp_err_to_name(err));
    return false;
  }

  err = i2c_driver_install(i2c_port_, I2C_MODE_MASTER, 0, 0, 0);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "I2C driver install failed: %s", esp_err_to_name(err));
    return false;
  }

  ESP_LOGI(TAG, "I2C bus initialized successfully");
  i2c_initialized_ = true;
  return true;
}

void AqaraFP2Accel::setup() {
  ESP_LOGCONFIG(TAG, "Setting up Aqara FP2 Accelerometer...");

  // Initialize I2C bus
  if (!i2c_init_bus()) {
    ESP_LOGE(TAG, "Failed to initialize I2C bus");
    this->mark_failed();
    return;
  }

  // Initialize the accelerometer
  i2c_init_acc();

  // Create mutex for thread-safe access
  mutex_ = xSemaphoreCreateMutex();
  if (mutex_ == nullptr) {
    ESP_LOGE(TAG, "Failed to create mutex");
    this->mark_failed();
    return;
  }

  // Create FreeRTOS task for I2C operations
  task_running_ = true;
  BaseType_t result = xTaskCreate(
    accel_task_,           // Task function
    "accel_task",          // Task name
    4096,                  // Stack size
    this,                  // Parameter (this pointer)
    1,                     // Priority
    &task_handle_          // Task handle
  );

  if (result != pdPASS) {
    ESP_LOGE(TAG, "Failed to create accelerometer task");
    this->mark_failed();
    task_running_ = false;
  } else {
    ESP_LOGI(TAG, "Accelerometer task created successfully");
  }
}

void AqaraFP2Accel::accel_task_(void *param) {
  AqaraFP2Accel *accel = static_cast<AqaraFP2Accel *>(param);
  accel->task_loop_();
}

void AqaraFP2Accel::task_loop_() {
  ESP_LOGI(TAG, "Accelerometer task started (interval: %d ms)", update_interval_ms_);

  while (task_running_) {
    // Read and process accelerometer data
    read_process_accel();

    // Delay for the configured interval
    vTaskDelay(pdMS_TO_TICKS(update_interval_ms_));
  }

  ESP_LOGI(TAG, "Accelerometer task stopped");
  vTaskDelete(nullptr);
}

// Thread-safe public accessors
int AqaraFP2Accel::get_output_angle_z() const {
  if (mutex_ == nullptr) return 0;
  xSemaphoreTake(mutex_, portMAX_DELAY);
  int value = output_angle_z_;
  xSemaphoreGive(mutex_);
  return value;
}

Orientation AqaraFP2Accel::get_orientation() const {
  if (mutex_ == nullptr) return Orientation::INVALID;
  xSemaphoreTake(mutex_, portMAX_DELAY);
  Orientation value = stable_orientation_;
  xSemaphoreGive(mutex_);
  return value;
}

bool AqaraFP2Accel::is_vibrating() const {
  if (mutex_ == nullptr) return false;
  xSemaphoreTake(mutex_, portMAX_DELAY);
  bool value = acc_state_.is_vibrating;
  xSemaphoreGive(mutex_);
  return value;
}

void AqaraFP2Accel::dump_config() {
  ESP_LOGCONFIG(TAG, "Aqara FP2 Accelerometer:");
  ESP_LOGCONFIG(TAG, "  I2C Port: %d", i2c_port_);
  ESP_LOGCONFIG(TAG, "  SDA Pin: GPIO%d", sda_pin_);
  ESP_LOGCONFIG(TAG, "  SCL Pin: GPIO%d", scl_pin_);
  ESP_LOGCONFIG(TAG, "  Frequency: %d Hz", frequency_);
  ESP_LOGCONFIG(TAG, "  I2C Address: 0x%02X", ACC_SENSOR_ADDR);
  ESP_LOGCONFIG(TAG, "  Update Interval: %d ms", update_interval_ms_);
  ESP_LOGCONFIG(TAG, "  Calibration X: %d", accel_corr_x_);
  ESP_LOGCONFIG(TAG, "  Calibration Y: %d", accel_corr_y_);
  ESP_LOGCONFIG(TAG, "  Calibration Z: %d", accel_corr_z_);
}

bool AqaraFP2Accel::i2c_read_accel_xyz(int16_t *x, int16_t *y, int16_t *z) {
  // Read all 6 registers at once (0x02-0x07)
  // X: 0x02, 0x03
  // Y: 0x04, 0x05
  // Z: 0x06, 0x07
  uint8_t data[6];
  uint8_t reg_addr = 0x02;

  // Use ESP-IDF I2C driver directly for better control
  esp_err_t err = i2c_master_write_read_device(
    i2c_port_,
    ACC_SENSOR_ADDR,
    &reg_addr,
    1,
    data,
    6,
    pdMS_TO_TICKS(1000)  // 1 second timeout
  );

  if (err != ESP_OK) {
    ESP_LOGW(TAG, "Failed to read accelerometer data: %s", esp_err_to_name(err));
    *x = 0;
    *y = 0;
    *z = 0;
    return false;
  }

  // Parse X axis (registers 0x02, 0x03)
  uint16_t x_raw = (uint16_t)(data[0] >> 4) | ((uint16_t)data[1] << 4);
  if ((x_raw & 0x800) != 0) {
    x_raw |= 0xf000;  // Sign extension
  }
  *x = (int16_t)x_raw;

  // Parse Y axis (registers 0x04, 0x05)
  uint16_t y_raw = (uint16_t)(data[2] >> 4) | ((uint16_t)data[3] << 4);
  if ((y_raw & 0x800) != 0) {
    y_raw |= 0xf000;  // Sign extension
  }
  *y = (int16_t)y_raw;

  // Parse Z axis (registers 0x06, 0x07)
  uint16_t z_raw = (uint16_t)(data[4] >> 4) | ((uint16_t)data[5] << 4);
  if ((z_raw & 0x800) != 0) {
    z_raw |= 0xf000;  // Sign extension
  }
  *z = (int16_t)z_raw;

  return true;
}

bool AqaraFP2Accel::i2c_write_reg(uint8_t reg, uint8_t value) {
  uint8_t write_buf[2] = {reg, value};

  esp_err_t err = i2c_master_write_to_device(
    i2c_port_,
    ACC_SENSOR_ADDR,
    write_buf,
    2,
    pdMS_TO_TICKS(1000)  // 1 second timeout
  );

  if (err != ESP_OK) {
    ESP_LOGW(TAG, "Failed to write register 0x%02X: %s", reg, esp_err_to_name(err));
    return false;
  }

  return true;
}

void AqaraFP2Accel::i2c_init_acc() {
  ESP_LOGI(TAG, "Initializing accelerometer");

  // Write 0x0E to Reg 0x11, 0x40 to Reg 0x0F
  if (!i2c_write_reg(0x11, 0x0e)) {
    ESP_LOGW(TAG, "Failed to write to register 0x11");
  }

  if (!i2c_write_reg(0x0f, 0x40)) {
    ESP_LOGW(TAG, "Failed to write to register 0x0F");
  }
}

bool AqaraFP2Accel::calculate_calibration() {
  ESP_LOGD(TAG, "acc_x=%d y=%d z=%d", acc_x_avg_, acc_y_avg_, acc_z_avg_);

  // Sanity check: If all axes equal, or pairs equal, invalid state
  if (acc_x_avg_ == acc_z_avg_) return false;
  if (acc_z_avg_ == acc_y_avg_) return false;
  if (acc_x_avg_ == acc_y_avg_) return false;

  // Calculate correction
  // Target is 0, 0, -1024 (1G downward)
  accel_corr_x_ = -acc_x_avg_;
  accel_corr_y_ = -acc_y_avg_;
  accel_corr_z_ = -1024 - acc_z_avg_;

  accel_corr_x_ = 0;
  accel_corr_y_ = 0;
  accel_corr_z_ = 0;
  return true;

  // ESP_LOGD(TAG, "correction_x=%d y=%d z=%d", accel_corr_x_, accel_corr_y_, accel_corr_z_);

  // return true;
}

static const double SCALE_FACTOR = 57.2957795;  // 180.0 / PI - radians to degrees

void AqaraFP2Accel::acc_data_deal(int32_t acc_raw_x, int32_t acc_raw_y, int32_t acc_raw_z, int acc_mag_sum) {
    // 1. Calculate Standard Inclination Angles
    // These represent the angle of each axis relative to the horizontal plane.
    // Range: -90 to +90 degrees.
    // atan2(axis, hypot(other_axes)) handles all quadrants and avoids div-by-zero.

    double dx = (double)acc_raw_x;
    double dy = (double)acc_raw_y;
    double dz = (double)acc_raw_z;

    // Angle Y: calculated from X axis (reference: i_angle_y = atan(x / sqrt(y² + z²)))
    int16_t i_angle_y = (int16_t)(atan2(dx, hypot(dy, dz)) * SCALE_FACTOR);

    // Angle X: calculated from Y axis (reference: i_angle_x = atan(y / sqrt(x² + z²)))
    int16_t i_angle_x = (int16_t)(atan2(dy, hypot(dx, dz)) * SCALE_FACTOR);

    // Angle Z: Vertical Tilt
    int16_t i_angle_z = (int16_t)(atan2(dz, hypot(dx, dy)) * SCALE_FACTOR);

    int32_t angle_z_int = (int32_t)i_angle_z;

    // 2. Output Angle Calculation
    // Logic from reference: output_angle_z = 90 - abs(angle_z)
    // Maps vertical (z pointing up/down) to 0 and horizontal to 90.
    int16_t c31 = i_angle_z;
    if (angle_z_int < 1) c31 = -c31; // abs()

    if (mutex_ != nullptr) xSemaphoreTake(mutex_, portMAX_DELAY);
    output_angle_z_ = 90 - c31;
    if (mutex_ != nullptr) xSemaphoreGive(mutex_);

    //ESP_LOGI(TAG, "Angles: %d Ax:%d Ay:%d Az:%d", output_angle_z_, i_angle_x, i_angle_y, i_angle_z);

    // 3. Orientation State Machine
    // We use the exact logic from decompilation, but with clear variable names.
    // Note: In assembly, 'acc_raw_z' register was repurposed to hold 'i_angle_y'.
    // We use proper variables here.

    Orientation curr_orient = Orientation::INVALID;

    // Pre-calculate windows for unsigned comparisons (standard compiler trick for range checks)
    // (val + offset) < width  <=>  -offset <= val < width - offset
    uint16_t u_angle_z = (uint16_t)angle_z_int;
    uint16_t check_y_window = (uint16_t)(i_angle_y + 19);
    uint16_t check_x_window = (uint16_t)(i_angle_x + 19);

    // --- ORIENT_UP ---
    // Z is effectively -1g (<-69 units is <-35 deg), X and Y are flat (+/- 10 deg)
    if (angle_z_int < -69) {
      if (check_y_window < 39 && check_x_window < 39) {
        curr_orient = Orientation::UP;
      }
    }

    // --- ORIENT_UP_TILT & REV ---
    // Z is between -69 and -20 units. Y is flat. X is tilted > 10 deg.
    // (u_angle_z + 69) < 49  =>  -69 <= Z < -20
    else if (((uint16_t)(u_angle_z + 69)) < 49) {
      if (check_y_window < 39) {
        int abs_angle_x = std::abs(i_angle_x);
        if (abs_angle_x > 20) {
          curr_orient = (i_angle_x < 0) ? Orientation::UP_TILT : Orientation::UP_TILT_REV;
        }
      }
    }

    // --- ORIENT_DOWN ---
    // Z is +1g (>70 units / >35 deg), X and Y are flat
    else if (angle_z_int > 70) {
      if (check_y_window < 39 && check_x_window < 39) {
        curr_orient = Orientation::DOWN;
      }
    }

    // --- ORIENT_SIDE & REV ---
    // Z is flat (+/- 10 deg). Y is flat. X is vertical (> +/- 25 deg).
    // (u_angle_z + 20) < 40  =>  -20 <= Z < 20
    else if (((uint16_t)(u_angle_z + 20)) < 40) {
      if (check_y_window < 39) {
        int abs_angle_x = std::abs(i_angle_x);
        if (abs_angle_x > 50) {
          curr_orient = (i_angle_x < 0) ? Orientation::SIDE : Orientation::SIDE_REV;
        }
      }
    }

    // --- ORIENT_DOWN_TILT & REV ---
    // Z is between 20 and 70. Y is flat. X is within reasonable bounds (<70 deg).
    // (u_angle_z - 20) < 51  =>  20 <= Z < 71
    else if (((uint16_t)(u_angle_z - 20)) < 51) {
      if (check_y_window < 39) {
        // Check X upper bound (approx 70 deg)
        if ((uint16_t)(i_angle_x + 69) < 139) {
           curr_orient = (i_angle_x < 0) ? Orientation::DOWN_TILT : Orientation::DOWN_TILT_REV;
        }
      }
    }

    // 4. Debouncing and State Updates
    // (This logic remains identical to your previous correct implementation)
    if (acc_state_.deb_invalid < 30) {
      if (curr_orient == Orientation::INVALID) {
        acc_state_.deb_invalid++;
        curr_orient = stable_orientation_;
      } else {
        acc_state_.deb_invalid = 0;
      }
    }

    Orientation stable_orientation = stable_orientation_;
    if (curr_orient != Orientation::INVALID) {
      // Side debounce specific logic
      if (curr_orient == Orientation::SIDE && stable_orientation_ == Orientation::DOWN_TILT) {
        if (acc_state_.deb_side < 10) {
          acc_state_.deb_side++;
          curr_orient = stable_orientation_;
        }
      } else {
        acc_state_.deb_side = 0;
      }
      stable_orientation = curr_orient;

      if (curr_orient == Orientation::SIDE_REV && stable_orientation_ == Orientation::DOWN_TILT_REV) {
        if (acc_state_.deb_side_rev < 10) {
          acc_state_.deb_side_rev++;
          curr_orient = stable_orientation_;
          stable_orientation = stable_orientation_;  // Reset stable_orientation too (per reference)
        }
      } else {
        acc_state_.deb_side_rev = 0;
      }
    }

    // Commit state
    if (mutex_ != nullptr) xSemaphoreTake(mutex_, portMAX_DELAY);
    Orientation prev_raw = raw_orientation_;
    stable_orientation_ = stable_orientation;
    raw_orientation_ = curr_orient;
    if (mutex_ != nullptr) xSemaphoreGive(mutex_);

    // Log change (helpful for debugging "broken" state)
    if (curr_orient != prev_raw) {
      ESP_LOGI(TAG, "Orientation State: %s -> %s (Ax:%d Ay:%d Az:%d)", orientation_to_string(prev_raw), orientation_to_string(curr_orient), i_angle_x, i_angle_y, i_angle_z);
      // Call orientation callback here
    }

  // Vibration Detection
  // Thread-safe update of vibration state
  if (mutex_ != nullptr) {
    xSemaphoreTake(mutex_, portMAX_DELAY);
  }

  uint32_t delta_sum;
  if (acc_mag_sum < acc_state_.last_acc_sum) {
    delta_sum = acc_state_.last_acc_sum - acc_mag_sum;
  } else {
    delta_sum = acc_mag_sum - acc_state_.last_acc_sum;
  }

  // Vibration counters
  if (delta_sum < 1000) {
    acc_state_.vib_high_cnt = 0;
    acc_state_.vib_low_cnt++;
  } else {
    acc_state_.vib_high_cnt++;
    acc_state_.vib_low_cnt = 0;
  }

  // Vibration Trigger (High delta or sustained high count)
  if (delta_sum > 5000 || acc_state_.vib_high_cnt > 4) {
    acc_state_.is_vibrating = true;
    acc_state_.vib_high_cnt = 0;
  }

  // Vibration Reset (Sustained low count)
  if (acc_state_.vib_low_cnt > 9) {
    acc_state_.is_vibrating = false;
    acc_state_.vib_low_cnt = 0;
  }

  acc_state_.last_acc_sum = acc_mag_sum;

  bool vib_state = acc_state_.is_vibrating;

  if (mutex_ != nullptr) {
    xSemaphoreGive(mutex_);
  }

  // Vibration State Change (logging outside mutex to avoid blocking)
  if (prev_vib_state_ != vib_state) {
    ESP_LOGI(TAG, "vibration=%s", vib_state ? "true" : "false");
    prev_vib_state_ = vib_state;
  }
}

void AqaraFP2Accel::read_process_accel() {
  int z, y, x;
  int x2, y2, z2;
  uint8_t sampleIdx;

  // Read all accelerometer axes in a single I2C transaction
  if (!i2c_read_accel_xyz(
      &read_acc_x_buf_[accel_samples_read_],
      &read_acc_y_buf_[accel_samples_read_],
      &read_acc_z_buf_[accel_samples_read_])) {
    // Failed to read, skip this sample
    return;
  }

  accel_samples_read_++;

  // Once buffer is full (10 samples)
  if (accel_samples_read_ > 9) {
    accel_samples_read_ = 0;

    // 1. Calculate Average
    x = 0; y = 0; z = 0;
    for (sampleIdx = 0; sampleIdx < 10; sampleIdx++) {
      x += read_acc_x_buf_[sampleIdx];
      y += read_acc_y_buf_[sampleIdx];
      z += read_acc_z_buf_[sampleIdx];
    }
    acc_x_avg_ = (int16_t)(x / 10);
    acc_y_avg_ = (int16_t)(y / 10);
    acc_z_avg_ = (int16_t)(z / 10);

    // 2. Calculate Variance / Energy (Sum of squared differences)
    x2 = 0; y2 = 0; z2 = 0;
    for (sampleIdx = 0; sampleIdx < 10; sampleIdx++) {
      z = (int)(read_acc_x_buf_[sampleIdx]) - (int)(accel_corr_x_ + acc_x_avg_);
      x2 += (z * z);

      z = (int)(read_acc_y_buf_[sampleIdx]) - (int)(accel_corr_y_ + acc_y_avg_);
      y2 += (z * z);

      z = (int)(read_acc_z_buf_[sampleIdx]) - (int)(accel_corr_z_ + acc_z_avg_);
      z2 += (z * z);
    }

    int energy_sum = (x2 / 10) + (y2 / 10) + (z2 / 10);

    // 3. Process Data
    acc_data_deal(
      (int32_t)(accel_corr_x_ + acc_x_avg_),
      (int32_t)(accel_corr_y_ + acc_y_avg_),
      (int32_t)(accel_corr_z_ + acc_z_avg_),
      energy_sum
    );

    //ESP_LOGI(TAG, "got samples %d %d %d",
    //    (int32_t)(accel_corr_x_ + acc_x_avg_),
    //    (int32_t)(accel_corr_y_ + acc_y_avg_),
    //    (int32_t)(accel_corr_z_ + acc_z_avg_)
    //);
  }
}

}  // namespace aqara_fp2_accel
}  // namespace esphome
