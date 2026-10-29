#!/usr/bin/env python3
"""Validate manifest structure; do not claim firmware or flash compatibility."""
import json
import re
import sys
from pathlib import Path

PATH = Path(__file__).resolve().parents[1] / "config/compatibility/regions.json"
CODES = {"MIXM", "IDXM", "CNXM", "EUXM", "INXM", "TWXM", "RUXM"}
STATES = {"planned", "reference_only", "verified"}

def validate(data):
    if data.get("schema_version") != 1 or data.get("device_codename") != "kunzite":
        raise ValueError("Invalid schema or device")
    if data.get("policy") != "deny_unverified":
        raise ValueError("Compatibility policy must fail closed")
    regions = data.get("regions")
    if not isinstance(regions, list) or not regions:
        raise ValueError("Missing regions")
    seen = set()
    for region in regions:
        code = region.get("code")
        if code not in CODES or code in seen:
            raise ValueError(f"Invalid or duplicate region: {code}")
        seen.add(code)
        status = region.get("status")
        if status not in STATES:
            raise ValueError(f"Invalid status: {status}")
        firmwares = region.get("firmwares")
        if not isinstance(firmwares, list):
            raise ValueError(f"Invalid firmware list: {code}")
        if status == "planned" and firmwares:
            raise ValueError(f"Planned region cannot contain asserted firmware: {code}")
        if status == "verified" and not firmwares:
            raise ValueError(f"Verified region has no firmware: {code}")
        for fw in firmwares:
            version = fw.get("version", "")
            if not re.fullmatch(r"OS[0-9.]+[A-Z0-9]+", version) or not version.endswith(code):
                raise ValueError(f"Invalid firmware-region mapping: {version} / {code}")
            checks = ("source_verified", "build_verified", "boot_verified",
                      "vendor_modules_verified")
            if any(type(fw.get(k)) is not bool for k in checks):
                raise ValueError(f"Missing boolean verification fields: {version}")
            all_checked = all(fw[k] for k in checks)
            if status == "verified" and not all_checked:
                raise ValueError(f"Unsupported verified claim: {version}")
            if status != "verified" and all_checked:
                raise ValueError(f"Fully checked firmware must be reviewed for promotion: {version}")
    if seen != CODES:
        raise ValueError(f"Region set incomplete: {sorted(CODES - seen)}")

if __name__ == "__main__":
    try:
        validate(json.loads(PATH.read_text(encoding="utf-8")))
        print("Region manifest: PASS (schema only; no firmware approved for flashing)")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Region manifest: FAIL — {exc}", file=sys.stderr)
        sys.exit(1)
