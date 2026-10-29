#!/usr/bin/env python3
"""Fail closed until the device-specific source provenance and commit pins are recorded."""
import json
import re
import sys
from pathlib import Path

SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
REQUIRED_COMPONENTS = (
    "msm_kernel",
    "kernel_devicetree",
    "kernel_build",
    "common_kernel",
    "external_dtc",
)


def audit_source_manifest(data: dict) -> None:
    if data.get("device") != "kunzite_global":
        raise ValueError("Invalid device identifier")
    observed = data.get("kernel_release_observed", "")
    if not observed.startswith("6.6.118-android15-8-"):
        raise ValueError("Unexpected observed kernel release")
    status = data.get("source_status")
    if status not in ("unverified", "verified"):
        raise ValueError(f"Invalid source_status: {status}")

    if status == "verified":
        for key in ("repository", "commit", "defconfig", "toolchain", "clang_version"):
            val = data.get(key)
            if not isinstance(val, str) or not val.strip():
                raise ValueError(f"Missing required string field: {key}")
        if not SHA1_RE.fullmatch(data["commit"]):
            raise ValueError(f"Top-level commit must be a 40-hex SHA-1: {data['commit']}")

        components = data.get("components")
        if not isinstance(components, dict):
            raise ValueError("Missing components map for Kleaf mixed build")
        for comp_name in REQUIRED_COMPONENTS:
            comp = components.get(comp_name)
            if not isinstance(comp, dict):
                raise ValueError(f"Missing pinned component: {comp_name}")
            for field in ("path", "repository", "commit"):
                if not isinstance(comp.get(field), str) or not comp[field].strip():
                    raise ValueError(f"Component {comp_name} missing {field}")
            if not SHA1_RE.fullmatch(comp["commit"]):
                raise ValueError(f"Component {comp_name} commit is not 40-hex SHA-1: {comp['commit']}")

        if components["msm_kernel"]["commit"] != data["commit"]:
            raise ValueError("msm_kernel commit does not match top-level commit")

        targets = data.get("bazel_targets")
        if not isinstance(targets, dict):
            raise ValueError("Missing bazel_targets map")
        expected_targets = {
            "base_kernel": "//common:kernel_aarch64",
            "kernel_build": "//msm-kernel:kunzite_perf",
            "kernel_images": "//msm-kernel:kunzite_perf_images",
            "kernel_dist": "//msm-kernel:kunzite_perf_dist",
        }
        for tkey, expected in expected_targets.items():
            if targets.get(tkey) != expected:
                raise ValueError(f"Unexpected Bazel target {tkey}: {targets.get(tkey)} != {expected}")

        flags = data.get("bazel_flags")
        if not isinstance(flags, list) or not any(f.startswith("--define=FACTORY_BUILD=") for f in flags):
            raise ValueError("bazel_flags must define FACTORY_BUILD for MiCode kernel_config.bzl")


def main() -> None:
    path = Path(__file__).resolve().parents[1] / "config/sources/kernel-source.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    audit_source_manifest(data)
    if data["source_status"] == "verified":
        print(
            "Source metadata: VERIFIED BY DECLARATION "
            f"(msm-kernel@{data['commit'][:12]}, "
            f"common@{data['components']['common_kernel']['commit'][:12]}; "
            "technical/flash compatibility still requires post-build verification)"
        )
    else:
        print("Source metadata: PENDING — source and compatibility not verified")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"Source audit FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
