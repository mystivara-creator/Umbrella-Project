#!/usr/bin/env python3
"""Validate only foundation metadata. Does not compile or verify a kernel."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = [
    "README.md", "docs/ARCHITECTURE.md", "docs/DEVICE_BRINGUP.md",
    "docs/ROADMAP.md", "docs/SOURCE_POLICY.md", "interfaces/README.md",
    "interfaces/coreflow-capabilities.v0.example.json",
    "config/devices/redmi-note-15-5g.example.json",
]


def main() -> None:
    for name in REQUIRED:
        path = ROOT / name
        if not path.is_file() or not path.read_text(encoding="utf-8").strip():
            raise SystemExit(f"Missing or empty foundation file: {name}")
    device = json.loads((ROOT / "config/devices/redmi-note-15-5g.example.json").read_text())
    if device.get("status") != "unverified":
        raise SystemExit("Foundation device template must remain unverified until bring-up")
    if device.get("hardware_boot_tested") is not False:
        raise SystemExit("Hardware boot testing must not be claimed")
    example = json.loads((ROOT / "interfaces/coreflow-capabilities.v0.example.json").read_text())
    if example.get("status") != "example-not-implemented":
        raise SystemExit("Interface design must not be presented as implemented")
    print("Umbrella foundation metadata: PASS (kernel not built or validated)")


if __name__ == "__main__":
    main()
