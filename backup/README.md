# Backup files

## `radar_firmware.bin`  (~2.4 MB)

The three TI IWR6843 radar firmware MSTR container images (FW1 / FW2 / FW3)
extracted from a stock Aqara FP2's `mcu_ota` partition. Byte-identical to
the upstream Aqara binary, no transformation applied.

This is what gets HTTP-downloaded into the ESP32's `mcu_ota` partition when
you press **Stage Radar Firmware** in Home Assistant, then streamed to the
radar chip via XMODEM-1K when you press **Trigger Radar OTA**.

SHA256: `964d1fc24a78b1dcb1b8c18e3b4167ef475bb4b7cb87c68485909407ba31d2c2`

## `aqara_fp2_stock_sanitized.bin`  (16 MB)

A **sanitized** full-flash image of a stock Aqara FP2 — the `nvs` and
`fctry` partitions have been overwritten with `0xFF` to remove:

- WiFi SSID + password (`user` namespace, `nvs.net80211` AP PMK)
- HomeKit pairing keys (`hap.00`/`hap.90`/`hap.92`/`hap.A0` namespaces)
- Device-specific factory cache

All other partitions (bootloader, partition table, both app slots, test
partition, and `mcu_ota` with the radar firmware) are preserved
byte-for-byte from the original stock flash.

SHA256: `449ed87485c0eec0036148b6dbc5117576c3731d44c3bac74112572ad1248a15`

### What this is useful for

- **Reference** — inspecting the stock Aqara partition layout, bootloader,
  and app binaries for reverse engineering.
- **Radar firmware recovery** — if your own backup is lost, you can run
  `scripts/extract_radar_firmware.py` against this file to get a fresh
  `radar_firmware.bin`.
- **Comparison** — diff against ESPHome builds to understand what changed.

### What this is NOT

- **Not flashable to a real device.** The per-unit factory calibration was
  wiped along with the secrets. Flashing this to your FP2 would:
  - Leave the accelerometer uncalibrated (mounting angle wrong)
  - Break OPT3001 light-sensor lux calibration (wrong lux readings)
  - Lose your HomeKit pairing (device appears unpaired to Apple Home)
  - Lose your Aqara cloud association (if you were using the stock app)

  Always flash your own `aqara_fp2_<serial>.bin` to restore stock.

### How it was sanitized

```bash
python scripts/sanitize_flash_backup.py \
    <private>/aqara_fp2_homekit-<serial>.bin \
    -o backup/aqara_fp2_stock_sanitized.bin
```

The sanitizer script is auditable and has 14 passing tests that verify:
- Only `nvs` and `fctry` partitions are touched
- All kept partitions are byte-identical to the input
- Zero known secret patterns survive in the wiped regions
- No ASCII strings >= 8 chars remain in the wiped regions

See `scripts/sanitize_flash_backup.py` and
`scripts/test_sanitize_flash_backup.py` for the details.
