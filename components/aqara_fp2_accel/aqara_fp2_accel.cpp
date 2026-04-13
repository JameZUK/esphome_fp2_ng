#include "aqara_fp2_accel.h"
#include "esphome/core/log.h"
#include "esphome/core/hal.h"
#include <cmath>
#include <nvs_flash.h>
#include <nvs.h>

namespace esphome {
namespace aqara_fp2_accel {

bool AqaraFP2Accel::i2c_init_bus() {
  ESP_LOGI(TAG, "Initializing I2C bus on port %d (SDA=%d, SCL=%d, freq=%d Hz)",
           i2c_port_, sda_pin_, scl_pin_, frequency_);

  i2c_master_bus_config_t bus_conf = {};
  bus_conf.clk_source = I2C_CLK_SRC_DEFAULT;
  bus_conf.i2c_port = i2c_port_;
  bus_conf.sda_io_num = static_cast<gpio_num_t>(sda_pin_);
  bus_conf.scl_io_num = static_cast<gpio_num_t>(scl_pin_);
  bus_conf.flags.enable_internal_pullup = true;

  esp_err_t err = i2c_new_master_bus(&bus_conf, &bus_handle_);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "I2C new master bus failed: %s", esp_err_to_name(err));
    return false;
  }

  i2c_device_config_t dev_conf = {};
  dev_conf.dev_addr_length = I2C_ADDR_BIT_LEN_7;
  dev_conf.device_address = ACC_SENSOR_ADDR;
  dev_conf.scl_speed_hz = frequency_;

  err = i2c_master_bus_add_device(bus_handle_, &dev_conf, &device_handle_);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "I2C add device failed: %s", esp_err_to_name(err));
    return false;
  }

  ESP_LOGI(TAG, "I2C bus initialized successfully");
  i2c_initialized_ = true;
  return true;
}

// --- OPT3001 Light Sensor ---

bool AqaraFP2Accel::opt3001_init_() {
  // Add OPT3001 as a second device on the I2C bus
  i2c_device_config_t dev_conf = {};
  dev_conf.dev_addr_length = I2C_ADDR_BIT_LEN_7;
  dev_conf.device_address = OPT3001_ADDR;
  dev_conf.scl_speed_hz = frequency_;

  esp_err_t err = i2c_master_bus_add_device(bus_handle_, &dev_conf, &opt3001_handle_);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "OPT3001: failed to add I2C device: %s", esp_err_to_name(err));
    return false;
  }

  // Verify manufacturer ID (should be 0x5449 = "TI")
  uint16_t mfr_id = 0;
  if (!opt3001_read_reg_(OPT3001_REG_MANUFACTURER_ID, &mfr_id)) {
    ESP_LOGE(TAG, "OPT3001: failed to read manufacturer ID");
    return false;
  }
  ESP_LOGI(TAG, "OPT3001: Manufacturer ID = 0x%04X %s", mfr_id,
           mfr_id == 0x5449 ? "(TI - correct)" : "(unexpected!)");

  // Verify device ID (should be 0x3001)
  uint16_t dev_id = 0;
  if (!opt3001_read_reg_(OPT3001_REG_DEVICE_ID, &dev_id)) {
    ESP_LOGE(TAG, "OPT3001: failed to read device ID");
    return false;
  }
  ESP_LOGI(TAG, "OPT3001: Device ID = 0x%04X %s", dev_id,
           dev_id == 0x3001 ? "(OPT3001 - correct)" : "(unexpected!)");

  // Configure: automatic full-scale, 800ms conversion, continuous mode
  // Config = 0xCE10:
  //   [15:12] = 0xC (automatic range)
  //   [11]    = 1 (800ms conversion time)
  //   [10:9]  = 1,1 (continuous conversion)
  //   [8:5]   = 0000
  //   [4]     = 1 (latch interrupt)
  //   [3:0]   = 0000
  uint16_t config = 0xCE10;
  if (!opt3001_write_reg_(OPT3001_REG_CONFIG, config)) {
    ESP_LOGE(TAG, "OPT3001: failed to write config");
    return false;
  }

  ESP_LOGI(TAG, "OPT3001: initialized successfully (continuous mode, 800ms, auto-range)");
  opt3001_initialized_ = true;
  return true;
}

bool AqaraFP2Accel::opt3001_read_reg_(uint8_t reg, uint16_t *value) {
  uint8_t data[2];
  esp_err_t err = i2c_master_transmit_receive(
      opt3001_handle_, &reg, 1, data, 2, 1000);
  if (err != ESP_OK) {
    if (err == ESP_ERR_INVALID_STATE || err == ESP_ERR_TIMEOUT) {
      i2c_master_bus_reset(bus_handle_);
    }
    return false;
  }
  *value = ((uint16_t)data[0] << 8) | data[1];
  return true;
}

bool AqaraFP2Accel::opt3001_write_reg_(uint8_t reg, uint16_t value) {
  uint8_t buf[3] = {reg, (uint8_t)(value >> 8), (uint8_t)(value & 0xFF)};
  esp_err_t err = i2c_master_transmit(opt3001_handle_, buf, 3, 1000);
  return err == ESP_OK;
}

bool AqaraFP2Accel::opt3001_read_lux_(float *lux) {
  uint16_t raw = 0;
  if (!opt3001_read_reg_(OPT3001_REG_RESULT, &raw)) {
    return false;
  }

  // Exponent = bits [15:12], Mantissa = bits [11:0]
  // Raw centilux = 2^exponent * mantissa (in 1/100 lux units)
  uint8_t exponent = (raw >> 12) & 0x0F;
  uint16_t mantissa = raw & 0x0FFF;
  float raw_centilux = (float)(1 << exponent) * (float)mantissa;

  if (lux_calibration_loaded_) {
    // Two-range piecewise linear calibration from factory NVS
    float calibrated;
    if (raw_centilux > (float)lux_low_max_) {
      calibrated = raw_centilux * lux_high_k_ + lux_high_b_;
    } else {
      calibrated = raw_centilux * lux_low_k_ + lux_low_b_;
    }
    if (calibrated < 0.0f) calibrated = 0.0f;
    if (calibrated > 83000.0f) calibrated = 83000.0f;
    *lux = calibrated / 100.0f;  // centilux → lux
  } else {
    // No calibration: raw centilux to lux
    *lux = raw_centilux * 0.01f;
  }
  return true;
}

float AqaraFP2Accel::get_lux() const {
  if (mutex_ == nullptr) return 0.0f;
  xSemaphoreTake(mutex_, portMAX_DELAY);
  float value = lux_value_;
  xSemaphoreGive(mutex_);
  return value;
}

void AqaraFP2Accel::load_factory_calibration_() {
  esp_err_t err = nvs_flash_init_partition("fctry");
  if (err != ESP_OK) {
    ESP_LOGW(TAG, "Factory NVS partition not available (0x%x) — using defaults", err);
    return;
  }

  nvs_handle_t handle;
  err = nvs_open_from_partition("fctry", "fac", NVS_READONLY, &handle);
  if (err != ESP_OK) {
    ESP_LOGW(TAG, "Failed to open factory NVS namespace 'fac' (0x%x)", err);
    return;
  }

  auto read_i16 = [&](const char *key, int16_t *out) -> bool {
    size_t size = sizeof(int16_t);
    return nvs_get_blob(handle, key, out, &size) == ESP_OK;
  };
  auto read_i32 = [&](const char *key, int32_t *out) -> bool {
    size_t size = sizeof(int32_t);
    return nvs_get_blob(handle, key, out, &size) == ESP_OK;
  };

  // Lux calibration coefficients
  int16_t low_k = 0, low_b = 0, high_k = 0, high_b = 0;
  int32_t low_max = 0;
  bool have_lux = true;
  have_lux &= read_i16("lux_low_k", &low_k);
  have_lux &= read_i16("lux_low_b", &low_b);
  have_lux &= read_i16("lux_high_k", &high_k);
  have_lux &= read_i16("lux_high_b", &high_b);
  have_lux &= read_i32("lux_low_max", &low_max);

  if (have_lux && low_k != 0) {
    lux_low_k_ = (float)low_k / 1000.0f;
    lux_low_b_ = (float)low_b / 10.0f;
    lux_high_k_ = (float)high_k / 1000.0f;
    lux_high_b_ = (float)high_b / 10.0f;
    lux_low_max_ = low_max;
    lux_calibration_loaded_ = true;
    ESP_LOGI(TAG, "Factory lux calibration: low k=%.3f b=%.1f, high k=%.3f b=%.1f, crossover=%d",
             lux_low_k_, lux_low_b_, lux_high_k_, lux_high_b_, lux_low_max_);
  } else {
    ESP_LOGW(TAG, "No factory lux calibration — using raw OPT3001 values");
  }

  // Accelerometer corrections
  int16_t cx = 0, cy = 0, cz = 0;
  if (read_i16("corr_x", &cx) && read_i16("corr_y", &cy) && read_i16("corr_z", &cz)) {
    accel_corr_x_ = cx;
    accel_corr_y_ = cy;
    accel_corr_z_ = cz;
    ESP_LOGI(TAG, "Factory accel corrections: x=%d y=%d z=%d", cx, cy, cz);
  }

  nvs_close(handle);
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

  // Initialize OPT3001 light sensor
  if (!opt3001_init_()) {
    ESP_LOGW(TAG, "OPT3001 light sensor not available");
  }

  // Load factory calibration from NVS (lux coefficients + accel corrections)
  load_factory_calibration_();

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

void AqaraFP2Accel::loop() {
  // Publish lux from main loop (sensor publish is not thread-safe)
  if (opt3001_initialized_ && light_sensor_ != nullptr) {
    float lux = get_lux();
    // Only publish on meaningful change (>5% or crossing zero)
    float last = light_sensor_->get_raw_state();
    if (std::isnan(last) || std::abs(lux - last) > (last * 0.05f + 0.5f)) {
      light_sensor_->publish_state(lux);
    }
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

    // Yield between I2C devices to let the bus settle on single-core ESP32
    vTaskDelay(pdMS_TO_TICKS(5));

    // Read OPT3001 light sensor every 10th cycle (~1s at 100ms interval)
    if (opt3001_initialized_) {
      opt3001_read_counter_++;
      if (opt3001_read_counter_ >= 10) {
        opt3001_read_counter_ = 0;
        float lux = 0.0f;
        if (opt3001_read_lux_(&lux)) {
          if (mutex_ != nullptr) xSemaphoreTake(mutex_, portMAX_DELAY);
          lux_value_ = lux;
          if (mutex_ != nullptr) xSemaphoreGive(mutex_);
        }
      }
    }

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
  ESP_LOGCONFIG(TAG, "  OPT3001 Light Sensor: %s", opt3001_initialized_ ? "YES" : "NO");
  ESP_LOGCONFIG(TAG, "  Lux Calibration: %s", lux_calibration_loaded_ ? "factory NVS" : "uncalibrated");
  if (lux_calibration_loaded_) {
    ESP_LOGCONFIG(TAG, "    Low:  k=%.3f b=%.1f (<%d centilux)", lux_low_k_, lux_low_b_, lux_low_max_);
    ESP_LOGCONFIG(TAG, "    High: k=%.3f b=%.1f (>%d centilux)", lux_high_k_, lux_high_b_, lux_low_max_);
  }

}

bool AqaraFP2Accel::i2c_read_accel_xyz(int16_t *x, int16_t *y, int16_t *z) {
  // Read all 6 registers at once (0x02-0x07)
  // X: 0x02, 0x03
  // Y: 0x04, 0x05
  // Z: 0x06, 0x07
  uint8_t data[6];
  uint8_t reg_addr = 0x02;

  esp_err_t err = i2c_master_transmit_receive(
    device_handle_,
    &reg_addr,
    1,
    data,
    6,
    1000
  );

  if (err != ESP_OK) {
    // Recover the bus if it's stuck — common on single-core ESP32
    // with two devices sharing the bus
    if (err == ESP_ERR_INVALID_STATE || err == ESP_ERR_TIMEOUT) {
      i2c_master_bus_reset(bus_handle_);
    } else {
      ESP_LOGW(TAG, "Failed to read accelerometer data: %s", esp_err_to_name(err));
    }
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

  esp_err_t err = i2c_master_transmit(
    device_handle_,
    write_buf,
    2,
    1000
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

  ESP_LOGD(TAG, "correction_x=%d y=%d z=%d", accel_corr_x_, accel_corr_y_, accel_corr_z_);

  return true;
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
