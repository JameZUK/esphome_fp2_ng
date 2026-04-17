#!/usr/bin/env python3
"""
Sanitize an Aqara FP2 stock flash backup by erasing partitions that contain
per-device secrets. Produces a safe-to-share image suitable for reference,
reverse engineering, or archival — NOT for restoring to a real device
(per-unit factory calibration is wiped with the secrets).

What gets wiped (overwritten with 0xFF, same as an erased sector):
  - `nvs`   partition at 0x009000 (32 KB)
        Contains: WiFi SSID + password (user namespace & nvs.net80211),
        HomeKit pairing keys (hap.*), misc cached state, aiot tokens.
  - `fctry` partition at 0x833000 (24 KB)
        Contains: HomeKit factory pairing setup data, some Aqara
        factory NVS. Also wiped to be safe.

What stays (public / non-sensitive):
  - bootloader (0x1000)
  - partition table (0x8000)
  - otadata (0x11000)  — just slot selector flags, no secrets
  - phy_init (0x13000) — RF calibration, generic
  - aqara_fw1 (0x20000) — stock ESP32 app binary
  - aqara_fw2 (0x220000) — stock ESP32 app binary
  - test (0x420000) — factory test app binary
  - mcu_ota (0x433000) — three TI radar firmware MSTR images

Usage:
    python scripts/sanitize_flash_backup.py full_backup.bin [-o safe.bin]

The script refuses to overwrite an existing output file unless --force is
passed, and refuses to operate on a file that doesn't look like a stock
Aqara FP2 flash dump.

Exit codes:
    0 — success
    1 — input file problem
    2 — partition table / layout problem
    3 — post-sanitize verification failed (secret pattern still present)
"""

from __future__ import annotations

import argparse
import hashlib
import re
import struct
import sys
from dataclasses import dataclass
from pathlib import Path


# Partition layout of a stock Aqara FP2 (fixed; we require this exactly)
PT_OFFSET = 0x8000
PT_SECTOR_SIZE = 0x1000

# Partitions that MUST exist at these exact (offset, size) for a stock Aqara dump
REQUIRED_PARTITIONS = [
    ("nvs",       0x01, 0x02, 0x009000, 0x008000),
    ("otadata",   0x01, 0x00, 0x011000, 0x002000),
    ("phy_init",  0x01, 0x01, 0x013000, 0x001000),
    ("aqara_fw1", 0x00, 0x10, 0x020000, 0x200000),
    ("aqara_fw2", 0x00, 0x11, 0x220000, 0x200000),
    ("test",      0x00, 0x20, 0x420000, 0x013000),
    ("mcu_ota",   0x01, 0xFE, 0x433000, 0x400000),
    ("fctry",     0x01, 0x02, 0x833000, 0x006000),
]

# Partitions to wipe with 0xFF (erased-sector state)
WIPE_PARTITIONS = ["nvs", "fctry"]

# Secret patterns we'll scan for after wipe — any hit = abort
SECRET_PATTERNS_IN_WIPED = [
    b"ap.passwd",
    b"ap.pmk_info",
    b"sta.ssid",
    b"hap.90",
    b"hap.92",
    b"hap.A0",
    b"hap.00",
]

EXPECTED_TOTAL = 0x1000000  # 16 MB


@dataclass
class Partition:
    label: str
    type: int
    subtype: int
    offset: int
    size: int

    @property
    def end(self) -> int:
        return self.offset + self.size


class SanitizeError(Exception):
    def __init__(self, message: str, exit_code: int = 1) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def parse_partition_table(flash: bytes) -> list[Partition]:
    if len(flash) < PT_OFFSET + PT_SECTOR_SIZE:
        raise SanitizeError("file too small to contain a partition table", exit_code=1)

    pt = flash[PT_OFFSET:PT_OFFSET + PT_SECTOR_SIZE]
    partitions: list[Partition] = []
    entries_bytes = b""

    for i in range(0, PT_SECTOR_SIZE, 32):
        entry = pt[i:i + 32]
        magic = struct.unpack("<H", entry[:2])[0]
        if magic == 0x50AA:
            ptype, subtype = entry[2], entry[3]
            offset, size = struct.unpack("<II", entry[4:12])
            label = entry[12:28].rstrip(b"\x00").decode("ascii", errors="replace")
            partitions.append(Partition(label, ptype, subtype, offset, size))
            entries_bytes += entry
        elif magic == 0xEBEB:
            stored = entry[16:32]
            calc = hashlib.md5(entries_bytes).digest()
            if stored != calc:
                raise SanitizeError(
                    f"partition table MD5 mismatch (stored={stored.hex()}, calc={calc.hex()})",
                    exit_code=2,
                )
            return partitions
        elif entry == b"\xFF" * 32:
            return partitions
        else:
            raise SanitizeError(
                f"unknown partition entry magic 0x{magic:04x} at PT offset 0x{i:03x}",
                exit_code=2,
            )

    return partitions


def validate_stock_aqara_layout(partitions: list[Partition]) -> None:
    """Require the stock Aqara layout exactly. This script won't sanitize anything else."""
    got = {p.label: (p.type, p.subtype, p.offset, p.size) for p in partitions}
    missing = []
    wrong = []
    for label, ptype, subtype, offset, size in REQUIRED_PARTITIONS:
        if label not in got:
            missing.append(label)
            continue
        if got[label] != (ptype, subtype, offset, size):
            wrong.append((label, got[label], (ptype, subtype, offset, size)))
    if missing:
        raise SanitizeError(
            f"not a stock Aqara FP2 flash: missing partition(s) {missing}. "
            "This script only sanitizes stock layouts.",
            exit_code=2,
        )
    if wrong:
        detail = "; ".join(f"{l}: got {g} expected {e}" for l, g, e in wrong)
        raise SanitizeError(
            f"not a stock Aqara FP2 flash: partition layout mismatch — {detail}",
            exit_code=2,
        )


def sanitize(flash: bytes) -> bytes:
    """Return a copy of `flash` with sensitive partitions overwritten with 0xFF."""
    if len(flash) != EXPECTED_TOTAL:
        raise SanitizeError(
            f"expected {EXPECTED_TOTAL}-byte flash dump, got {len(flash)} bytes. "
            "Only 16 MB full-flash dumps are supported.",
            exit_code=1,
        )

    partitions = parse_partition_table(flash)
    validate_stock_aqara_layout(partitions)

    out = bytearray(flash)
    for label in WIPE_PARTITIONS:
        p = next(p for p in partitions if p.label == label)
        out[p.offset:p.end] = b"\xFF" * p.size

    # Post-wipe verification: none of the known secret patterns may remain
    # inside the wiped ranges.
    for label in WIPE_PARTITIONS:
        p = next(p for p in partitions if p.label == label)
        region = bytes(out[p.offset:p.end])
        for pat in SECRET_PATTERNS_IN_WIPED:
            if pat in region:
                raise SanitizeError(
                    f"verification failed: pattern {pat!r} still present in "
                    f"'{label}' after wipe",
                    exit_code=3,
                )

    return bytes(out)


def post_sanitize_report(flash: bytes, sanitized: bytes) -> dict:
    """Describe what changed. Used by the CLI to print a summary."""
    partitions = parse_partition_table(flash)
    report = {"wiped": [], "kept": []}
    for p in partitions:
        before = flash[p.offset:p.end]
        after = sanitized[p.offset:p.end]
        nonff_before = sum(1 for b in before if b != 0xFF)
        nonff_after = sum(1 for b in after if b != 0xFF)
        entry = {
            "label": p.label, "offset": p.offset, "size": p.size,
            "nonff_before": nonff_before, "nonff_after": nonff_after,
        }
        (report["wiped"] if before != after else report["kept"]).append(entry)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Erase secrets (WiFi creds, HomeKit pairing) from an "
                    "Aqara FP2 stock flash backup so it can be shared safely."
    )
    parser.add_argument("input", type=Path, help="Full-flash backup (16 MB .bin)")
    parser.add_argument("-o", "--output", type=Path, default=None,
                        help="Output path (default: <input>_sanitized.bin)")
    parser.add_argument("-f", "--force", action="store_true",
                        help="Overwrite existing output file")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Only report errors")
    args = parser.parse_args(argv)

    if not args.input.exists():
        print(f"error: {args.input} does not exist", file=sys.stderr)
        return 1

    out_path = args.output or args.input.with_name(args.input.stem + "_sanitized.bin")
    if out_path.exists() and not args.force:
        print(f"error: {out_path} already exists (use --force to overwrite)",
              file=sys.stderr)
        return 1

    def log(msg: str) -> None:
        if not args.quiet:
            print(msg)

    try:
        log(f"Reading {args.input} ({args.input.stat().st_size:,} bytes)...")
        flash = args.input.read_bytes()

        log("Sanitizing...")
        sanitized = sanitize(flash)

        report = post_sanitize_report(flash, sanitized)

        log("")
        log("Wiped partitions:")
        for e in report["wiped"]:
            log(f"  {e['label']:<12} offset 0x{e['offset']:06x}  "
                f"{e['size']:>8} bytes  "
                f"non-0xFF before: {e['nonff_before']:>6} → after: {e['nonff_after']}")

        log("")
        log("Kept partitions:")
        for e in report["kept"]:
            log(f"  {e['label']:<12} offset 0x{e['offset']:06x}  "
                f"{e['size']:>8} bytes  (unchanged, {e['nonff_before']} non-0xFF bytes)")

        log("")
        sha_before = hashlib.sha256(flash).hexdigest()
        sha_after = hashlib.sha256(sanitized).hexdigest()
        log(f"SHA256 before: {sha_before}")
        log(f"SHA256 after:  {sha_after}")

        out_path.write_bytes(sanitized)
        log("")
        log(f"Wrote {out_path}  ({len(sanitized):,} bytes)")
        log("")
        log("NOTE: this image is missing per-device factory NVS — do NOT flash it to")
        log("      a real device. It's for reference, reverse engineering, and archival.")
        return 0

    except SanitizeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return exc.exit_code


if __name__ == "__main__":
    sys.exit(main())
