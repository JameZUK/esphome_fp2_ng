#!/usr/bin/env python3
"""
Tests for sanitize_flash_backup.py.

Covers:
- Synthetic stock-layout flash → correct partitions wiped, others kept
- Reject non-16MB input
- Reject input with a non-stock partition layout
- Reject input with a corrupted partition table (bad MD5)
- Verify zero NVS-keyed secret patterns survive in the wiped regions
- End-to-end CLI behaviour (stdout report, --force, refuses overwrite)
- If the real private 16 MB backup is available at
  ~/fp2-private-backup/aqara_fp2_homekit-52322103_ALL.bin,
  assert that sanitizing it removes all discovered secret strings and
  leaves mcu_ota / app partitions byte-identical.
"""

from __future__ import annotations

import hashlib
import re
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))
import sanitize_flash_backup as sfb  # noqa: E402

REAL_BACKUP = Path.home() / "fp2-private-backup" / "aqara_fp2_homekit-52322103_ALL.bin"


def _entry(label: str, ptype: int, subtype: int, offset: int, size: int) -> bytes:
    return struct.pack(
        "<HBBII16sI",
        0x50AA, ptype, subtype, offset, size,
        label.encode().ljust(16, b"\x00"), 0,
    )


def _build_stock_pt(with_md5: bool = True) -> bytes:
    payload = b""
    for label, ptype, subtype, offset, size in sfb.REQUIRED_PARTITIONS:
        payload += _entry(label, ptype, subtype, offset, size)
    if with_md5:
        md5 = hashlib.md5(payload).digest()
        payload += b"\xeb\xeb" + b"\xff" * 14 + md5
    return payload.ljust(sfb.PT_SECTOR_SIZE, b"\xff")


def build_synthetic_stock_flash(
    nvs_body: bytes = b"",
    fctry_body: bytes = b"",
    with_md5: bool = True,
) -> bytes:
    flash = bytearray(b"\xff" * sfb.EXPECTED_TOTAL)
    flash[0x1000] = 0xE9  # ESP32 image magic
    flash[sfb.PT_OFFSET:sfb.PT_OFFSET + sfb.PT_SECTOR_SIZE] = _build_stock_pt(with_md5)
    flash[0x009000:0x009000 + len(nvs_body)] = nvs_body
    flash[0x833000:0x833000 + len(fctry_body)] = fctry_body
    return bytes(flash)


class ParsePartitionTableTests(unittest.TestCase):
    def test_stock_layout_parses(self):
        flash = build_synthetic_stock_flash()
        parts = sfb.parse_partition_table(flash)
        labels = [p.label for p in parts]
        for required, _, _, _, _ in sfb.REQUIRED_PARTITIONS:
            self.assertIn(required, labels)

    def test_md5_mismatch_rejected(self):
        flash = bytearray(build_synthetic_stock_flash())
        # Corrupt one byte of the stored MD5
        md5_offset = sfb.PT_OFFSET + len(sfb.REQUIRED_PARTITIONS) * 32 + 16
        flash[md5_offset] ^= 0xFF
        with self.assertRaises(sfb.SanitizeError) as cm:
            sfb.parse_partition_table(bytes(flash))
        self.assertEqual(cm.exception.exit_code, 2)
        self.assertIn("MD5 mismatch", str(cm.exception))


class ValidateLayoutTests(unittest.TestCase):
    def test_stock_accepted(self):
        flash = build_synthetic_stock_flash()
        parts = sfb.parse_partition_table(flash)
        sfb.validate_stock_aqara_layout(parts)  # must not raise

    def test_missing_partition_rejected(self):
        # Build a PT with mcu_ota missing
        payload = b""
        for label, ptype, subtype, offset, size in sfb.REQUIRED_PARTITIONS:
            if label == "mcu_ota":
                continue
            payload += _entry(label, ptype, subtype, offset, size)
        md5 = hashlib.md5(payload).digest()
        payload += b"\xeb\xeb" + b"\xff" * 14 + md5
        payload = payload.ljust(sfb.PT_SECTOR_SIZE, b"\xff")
        flash = bytearray(b"\xff" * sfb.EXPECTED_TOTAL)
        flash[sfb.PT_OFFSET:sfb.PT_OFFSET + sfb.PT_SECTOR_SIZE] = payload
        with self.assertRaises(sfb.SanitizeError) as cm:
            parts = sfb.parse_partition_table(bytes(flash))
            sfb.validate_stock_aqara_layout(parts)
        self.assertEqual(cm.exception.exit_code, 2)
        self.assertIn("missing partition", str(cm.exception))

    def test_wrong_offset_rejected(self):
        # nvs moved to 0x10000
        parts = [
            sfb.Partition("nvs", 1, 2, 0x10000, 0x8000),
            sfb.Partition("otadata", 1, 0, 0x11000, 0x2000),
            sfb.Partition("phy_init", 1, 1, 0x13000, 0x1000),
            sfb.Partition("aqara_fw1", 0, 0x10, 0x20000, 0x200000),
            sfb.Partition("aqara_fw2", 0, 0x11, 0x220000, 0x200000),
            sfb.Partition("test", 0, 0x20, 0x420000, 0x13000),
            sfb.Partition("mcu_ota", 1, 0xFE, 0x433000, 0x400000),
            sfb.Partition("fctry", 1, 2, 0x833000, 0x6000),
        ]
        with self.assertRaises(sfb.SanitizeError) as cm:
            sfb.validate_stock_aqara_layout(parts)
        self.assertEqual(cm.exception.exit_code, 2)
        self.assertIn("layout mismatch", str(cm.exception))


class SanitizeTests(unittest.TestCase):
    def test_wipes_nvs_and_fctry(self):
        # Stuff nvs and fctry with known plaintext
        nvs_payload = b"SSIDNAME-EXAMPLE" + b"\x00" * 8 + b"PASSWORDEXAMPLE!" + b"\x00" * 200
        fctry_payload = b"hap.90\x00pairingpayload" + b"\x00" * 100
        flash = build_synthetic_stock_flash(nvs_body=nvs_payload, fctry_body=fctry_payload)

        sanitized = sfb.sanitize(flash)

        self.assertEqual(len(sanitized), len(flash))
        # Wiped ranges are now all 0xFF
        self.assertEqual(sanitized[0x009000:0x011000], b"\xff" * 0x8000)
        self.assertEqual(sanitized[0x833000:0x839000], b"\xff" * 0x6000)
        # Payloads are gone
        self.assertNotIn(b"SSIDNAME-EXAMPLE", sanitized)
        self.assertNotIn(b"PASSWORDEXAMPLE!", sanitized)
        self.assertNotIn(b"pairingpayload", sanitized)

    def test_keeps_bootloader_pt_app_and_mcu_ota(self):
        flash = bytearray(build_synthetic_stock_flash())
        # Put distinctive markers in each "kept" partition
        flash[0x1000:0x1010] = b"BOOTLOADER_KEEP1"
        flash[0x20000:0x20010] = b"APP1_REGION_KEEP"
        flash[0x220000:0x220010] = b"APP2_REGION_KEEP"
        flash[0x420000:0x420010] = b"TEST_REGION_KEEP"
        flash[0x433000:0x433010] = b"MCU_OTA_REGN_KP!"
        # Fix the 0xE9 after our overwrite
        flash[0x1000] = 0xE9
        sanitized = sfb.sanitize(bytes(flash))
        self.assertEqual(sanitized[0x1001:0x1010], flash[0x1001:0x1010])
        self.assertEqual(sanitized[0x20000:0x20010], flash[0x20000:0x20010])
        self.assertEqual(sanitized[0x220000:0x220010], flash[0x220000:0x220010])
        self.assertEqual(sanitized[0x420000:0x420010], flash[0x420000:0x420010])
        self.assertEqual(sanitized[0x433000:0x433010], flash[0x433000:0x433010])

    def test_rejects_non_16mb_input(self):
        with self.assertRaises(sfb.SanitizeError) as cm:
            sfb.sanitize(b"\x00" * 1024)
        self.assertEqual(cm.exception.exit_code, 1)
        self.assertIn("expected 16777216", str(cm.exception))


class CLITests(unittest.TestCase):
    def _run(self, *args) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(REPO_ROOT / "scripts" / "sanitize_flash_backup.py"), *args],
            capture_output=True, text=True,
        )

    def test_help(self):
        r = self._run("--help")
        self.assertEqual(r.returncode, 0)
        # Help is word-wrapped; check for a fragment that always appears
        self.assertIn("Erase secrets", r.stdout)

    def test_missing_input(self):
        r = self._run("/nonexistent/flash.bin")
        self.assertEqual(r.returncode, 1)
        self.assertIn("does not exist", r.stderr)

    def test_synthetic_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "flash.bin"
            nvs_body = b"SSIDX" + b"\x00" + b"ap.passwd\x00hunter2hunter2" + b"\x00" * 100
            src.write_bytes(build_synthetic_stock_flash(nvs_body=nvs_body))
            r = self._run(str(src))
            self.assertEqual(r.returncode, 0, msg=r.stderr)
            out = src.with_name("flash_sanitized.bin")
            self.assertTrue(out.exists())
            # Output must not contain the plaintext secrets
            blob = out.read_bytes()
            self.assertNotIn(b"ap.passwd", blob)
            self.assertNotIn(b"hunter2hunter2", blob)

    def test_refuses_overwrite_without_force(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "flash.bin"
            src.write_bytes(build_synthetic_stock_flash())
            out = Path(tmp) / "existing.bin"
            out.write_bytes(b"existing")
            r = self._run(str(src), "-o", str(out))
            self.assertEqual(r.returncode, 1)
            self.assertIn("already exists", r.stderr)
            # Original output file unchanged
            self.assertEqual(out.read_bytes(), b"existing")

    def test_force_overwrites(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "flash.bin"
            src.write_bytes(build_synthetic_stock_flash())
            out = Path(tmp) / "existing.bin"
            out.write_bytes(b"existing")
            r = self._run(str(src), "-o", str(out), "--force")
            self.assertEqual(r.returncode, 0, msg=r.stderr)
            self.assertEqual(len(out.read_bytes()), sfb.EXPECTED_TOTAL)


class RealBackupTests(unittest.TestCase):
    """If the private real backup is available, verify end-to-end."""

    @unittest.skipUnless(REAL_BACKUP.exists(),
                         f"{REAL_BACKUP} not present")
    def test_real_backup_sanitized_safely(self):
        flash = REAL_BACKUP.read_bytes()
        self.assertEqual(len(flash), sfb.EXPECTED_TOTAL)

        sanitized = sfb.sanitize(flash)

        # Same overall size
        self.assertEqual(len(sanitized), len(flash))

        # Wiped regions are all 0xFF
        self.assertEqual(sanitized[0x009000:0x011000], b"\xff" * 0x8000,
                         "NVS region must be fully 0xFF after sanitize")
        self.assertEqual(sanitized[0x833000:0x839000], b"\xff" * 0x6000,
                         "fctry region must be fully 0xFF after sanitize")

        # Secret patterns that existed in the original must NOT exist anywhere
        # in the sanitized NVS + fctry regions.
        for pat in [
            b"ap.passwd", b"ap.pmk_info", b"sta.ssid",
            b"hap.00", b"hap.90", b"hap.92", b"hap.A0",
        ]:
            self.assertNotIn(pat, sanitized[0x009000:0x011000],
                             f"pattern {pat!r} still in nvs region")
            self.assertNotIn(pat, sanitized[0x833000:0x839000],
                             f"pattern {pat!r} still in fctry region")

        # mcu_ota must be byte-identical (extraction tests depend on this)
        self.assertEqual(flash[0x433000:0x833000],
                         sanitized[0x433000:0x833000],
                         "mcu_ota region changed unexpectedly")

        # Stock app binaries must be byte-identical
        self.assertEqual(flash[0x20000:0x220000],
                         sanitized[0x20000:0x220000],
                         "aqara_fw1 changed unexpectedly")
        self.assertEqual(flash[0x220000:0x420000],
                         sanitized[0x220000:0x420000],
                         "aqara_fw2 changed unexpectedly")


def main() -> int:
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    return 0 if runner.run(suite).wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
