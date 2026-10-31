#!/usr/bin/env python3
"""Fail closed until the device-specific source provenance and commit pins are recorded."""
import json
import re
import sys
from pathlib import Path
from gki_module_trust import audit_trust_policy

ROOT = Path(__file__).resolve().parents[1]
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
REQUIRED_COMPONENTS = (
    "msm_kernel",
    "kernel_devicetree",
    "kernel_build",
    "common_kernel",
    "external_dtc",
)
REQUIRED_KERNEL_DIRS = (
    "arch/arm64",
    "drivers",
    "include",
    "kernel",
    "mm",
    "scripts",
    "tools/build",
)


def parse_makefile_version(makefile: Path) -> str:
    vals: dict[str, str] = {}
    for line in makefile.read_text(encoding="utf-8", errors="replace").splitlines()[:20]:
        if "=" in line:
            k, v = line.split("=", 1)
            k = k.strip()
            if k in ("VERSION", "PATCHLEVEL", "SUBLEVEL"):
                vals[k] = v.strip()
    if len(vals) != 3:
        raise ValueError(f"Incomplete Linux version header in {makefile}")
    return f"{vals['VERSION']}.{vals['PATCHLEVEL']}.{vals['SUBLEVEL']}"


def audit_source_manifest(data: dict, repo_root: Path = ROOT) -> None:
    if data.get("device") != "kunzite_global":
        raise ValueError("Invalid device identifier")
    observed = data.get("kernel_release_observed", "")
    if not observed.startswith("6.6.118-android15-8-"):
        raise ValueError("Unexpected observed kernel release")
    status = data.get("source_status")
    if status not in ("unverified", "verified"):
        raise ValueError(f"Invalid source_status: {status}")

    if status == "verified":
        if data.get("gki_module_trust"):
            audit_trust_policy(repo_root, data["gki_module_trust"])
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

        in_repo = data.get("in_repo_tree")
        if in_repo is not None:
            if not isinstance(in_repo, dict):
                raise ValueError("in_repo_tree must be an object when present")
            role = in_repo.get("role")
            if role not in ("common_kernel", "msm_kernel"):
                raise ValueError(f"Invalid in_repo_tree.role: {role}")
            upstream_commit = in_repo.get("upstream_commit", "")
            expected_commit = components[role]["commit"]
            if not SHA1_RE.fullmatch(upstream_commit) or upstream_commit != expected_commit:
                raise ValueError(
                    f"in_repo_tree.upstream_commit ({upstream_commit}) does not match pinned {role} ({expected_commit})"
                )
            upstream_doc = repo_root / "docs/UPSTREAM.md"
            if not upstream_doc.is_file() or not upstream_doc.read_text(encoding="utf-8").strip():
                raise ValueError("docs/UPSTREAM.md is required before declaring an in-repo kernel tree")
            for req_file in ("COPYING", "Makefile", "Kconfig", "BUILD.bazel"):
                fp = repo_root / req_file
                if not fp.is_file():
                    raise ValueError(f"Declared in_repo_tree missing required kernel root file: {req_file}")
            for req_dir in REQUIRED_KERNEL_DIRS:
                if not (repo_root / req_dir).is_dir():
                    raise ValueError(f"Declared in_repo_tree missing required kernel directory: {req_dir}")
            actual_ver = parse_makefile_version(repo_root / "Makefile")
            expected_ver = components[role].get("linux_version")
            if expected_ver and actual_ver != expected_ver:
                raise ValueError(
                    f"Kernel Makefile version {actual_ver} does not match expected {expected_ver} for {role}"
                )
            if role == "msm_kernel" and not (repo_root / "kunzite.bzl").is_file():
                raise ValueError("in_repo_tree role msm_kernel requires kunzite.bzl at repository root")


def main() -> None:
    path = ROOT / "config/sources/kernel-source.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    audit_source_manifest(data, repo_root=ROOT)
    in_repo = data.get("in_repo_tree")
    tree_note = (
        f"in-repo={in_repo['role']}@{in_repo['upstream_commit'][:12]}"
        if isinstance(in_repo, dict)
        else "layout=metadata-only"
    )
    if data["source_status"] == "verified":
        print(
            "Source metadata: VERIFIED BY DECLARATION "
            f"(msm-kernel@{data['commit'][:12]}, "
            f"common@{data['components']['common_kernel']['commit'][:12]}, "
            f"{tree_note}; "
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

