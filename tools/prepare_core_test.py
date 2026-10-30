#!/usr/bin/env python3
"""Prepare a temporary-boot candidate, retaining every on-device stock module.

No device is accessed or flashed. Supports the observed kunzite v4 boot layout
with an uncompressed ARM64 kernel and an empty boot ramdisk. AVB metadata is
rebuilt unsigned; this is not an OEM-signed image or a flash approval.
"""
import argparse
import collections
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

from audit_stock_module_abi import normalize_modules
from verify_build_artifacts import CRITICAL_CONFIGS, extract_embedded_kconfig, parse_kconfig

ROOT = Path(__file__).resolve().parents[1]
AVBTOOL_SHA256 = "aa080bb3dd613cbbcaea410a8cff62225811fc79a4af05613a63ec3acec7ab92"
AVBTOOL_SOURCE = "LineageOS/android_external_avb@cb5eae91a6b83e1394882decbf6de133239107e1"
DEBUG_CONFIGS = {"CONFIG_DEBUG_INFO_COMPRESSED_NONE", "CONFIG_DEBUG_INFO_COMPRESSED_ZSTD"}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def verify_baseline(root):
    root = Path(root).resolve()
    checked = set()
    for line in (root / "SHA256SUMS").read_text().splitlines():
        digest, name = line.split(None, 1)
        path = (root / name.strip()).resolve()
        if not path.is_relative_to(root) or not path.is_file() or sha(path) != digest:
            raise ValueError(f"Invalid baseline checksum or path: {name}")
        checked.add(path)
    for name in ("device.properties", "boot-backup.img", "running-kernel.config",
                 "export-owners.txt", "loaded-modules.txt"):
        if (root / name).resolve() not in checked:
            raise ValueError(f"Baseline checksum coverage missing: {name}")
    return checked


def device_properties(root):
    props = dict(line.split("=", 1) for line in (root / "device.properties").read_text().splitlines())
    if props.get("ro.product.device") != "kunzite" or props.get("kernel.arch") != "aarch64":
        raise ValueError("Expected an ARM64 kunzite baseline")
    if props.get("ro.boot.slot_suffix") not in ("_a", "_b"):
        raise ValueError("Active A/B slot not established")
    if (props.get("ro.boot.flash.locked") != "0"
            or props.get("ro.boot.vbmeta.device_state") != "unlocked"):
        raise ValueError("This unsigned test image requires an unlocked bootloader")
    return props


def read_owners(root, checked):
    owners = collections.defaultdict(set)
    for line in (root / "export-owners.txt").read_text().splitlines():
        fields = line.split()
        if len(fields) == 2:
            owners[fields[0]].add(fields[1].replace("-", "_"))
    for path in (root / "metadata").rglob("modules.symbols"):
        if path.resolve() not in checked:
            raise ValueError(f"Unverified depmod index: {path}")
        for line in path.read_text().splitlines():
            fields = line.split()
            if len(fields) == 3 and fields[0] == "alias" and fields[1].startswith("symbol:"):
                owners[fields[1][7:]].add(fields[2].replace("-", "_"))
    return owners


def read_core_exports(path):
    exports = {}
    for line in Path(path).read_text().splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[2] == "vmlinux":
            crc, name = fields[:2]
            if name in exports and exports[name] != crc.lower():
                raise ValueError(f"Conflicting core export: {name}")
            exports[name] = crc.lower()
    if len(exports) < 2000:
        raise ValueError("Incomplete core export table")
    return exports


def audit_core_only(baseline, core, owners):
    if baseline.get("errors"):
        raise ValueError("Stock module extraction contains errors")
    counts = collections.Counter()
    findings = []
    fallback = []
    modules = normalize_modules(baseline)
    for module, imports, _ in modules:
        for symbol, crc in imports.items():
            providers = owners.get(symbol, set())
            if not crc:
                status = "unversioned"
            elif len(providers) > 1:
                status = "ambiguous_provider"
            elif providers and providers != {"vmlinux"}:
                status = "core_conflicts_with_stock_module" if symbol in core else "retained_stock_module"
            elif symbol not in core:
                status = "core_export_missing" if providers else "owner_unknown"
            elif core[symbol] != str(crc).lower():
                status = "core_crc_mismatch"
            else:
                status = "core_matched"
                if not providers:
                    fallback.append({"module": module, "symbol": symbol})
            counts[status] += 1
            if status not in ("core_matched", "retained_stock_module"):
                findings.append({"module": module, "symbol": symbol, "status": status,
                                 "stock_crc": crc, "core_crc": core.get(symbol),
                                 "runtime_providers": sorted(providers)})
    return {"module_count": len(modules), "import_count": sum(counts.values()),
            "counts": dict(counts), "findings": findings,
            "core_matches_without_runtime_owner": fallback,
            "scoped_baseline_passed": not findings,
            "scope": "Only vmlinux is replaced; all stock module partitions are retained"}


def boot_payload(stock, kernel):
    if len(stock) < 4096 or stock[:8] != b"ANDROID!":
        raise ValueError("Invalid boot backup")
    size, ramdisk, _, header = struct.unpack_from("<IIII", stock, 8)
    if struct.unpack_from("<I", stock, 40)[0] != 4 or header != 1584 or ramdisk:
        raise ValueError("Expected v4 boot header with empty ramdisk")
    if not size or 4096 + size > len(stock):
        raise ValueError("Truncated stock kernel payload")
    if (len(kernel) < 64 or kernel[56:60] != b"ARM\x64"
            or stock[4096 + 56:4096 + 60] != b"ARM\x64"):
        raise ValueError("Expected uncompressed ARM64 kernels")
    page = bytearray(stock[:4096])
    struct.pack_into("<I", page, 8, len(kernel))
    # An old GKI certificate cannot authenticate a changed kernel.
    struct.pack_into("<I", page, 1580, 0)
    return bytes(page) + kernel + bytes((-len(kernel)) % 4096)


def run(*args):
    subprocess.run(list(map(str, args)), check=True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--device-baseline", type=Path, required=True)
    p.add_argument("--stock-modules", type=Path, required=True)
    p.add_argument("--dist-dir", type=Path, required=True)
    p.add_argument("--avbtool", type=Path, required=True)
    p.add_argument("--output-dir", type=Path, required=True)
    args = p.parse_args()
    args.device_baseline = args.device_baseline.resolve()
    args.avbtool = args.avbtool.resolve()
    if args.output_dir.exists():
        raise ValueError("Output directory already exists")
    checked = verify_baseline(args.device_baseline)
    props = device_properties(args.device_baseline)
    source = json.loads((ROOT / "config/sources/kernel-source.json").read_text())
    if props["kernel.release"] != source["kernel_release_observed"]:
        raise ValueError("Running firmware kernel release differs from the qualified baseline")
    config_path = args.device_baseline / "running-kernel.config"
    if sha(config_path) != source["stock_config_local"]["expected_sha256"]:
        raise ValueError("Running stock config does not match the qualified checksum")
    kernel = (args.dist_dir / "Image").read_bytes()
    config = extract_embedded_kconfig(args.dist_dir / "Image")
    with tempfile.TemporaryDirectory() as temp:
        cfg = Path(temp) / "gki.config"
        cfg.write_bytes(config)
        built_cfg, stock_cfg = parse_kconfig(cfg), parse_kconfig(config_path)
        diff = {k: {"stock": stock_cfg.get(k), "built": built_cfg.get(k)}
                for k in sorted(stock_cfg.keys() | built_cfg.keys())
                if stock_cfg.get(k) != built_cfg.get(k)}
        if set(diff) - DEBUG_CONFIGS:
            raise ValueError("GKI configuration differs beyond the qualified debug-compression options")
        if any(built_cfg.get(k) != v for k, v in {**CRITICAL_CONFIGS, "CONFIG_MODULE_SIG_ALL": "y"}.items()):
            raise ValueError("Critical GKI configuration mismatch")
    baseline = json.loads(args.stock_modules.read_text())
    audit = audit_core_only(baseline, read_core_exports(args.dist_dir / "gki.Module.symvers"),
                            read_owners(args.device_baseline, checked))
    if not audit["scoped_baseline_passed"]:
        raise ValueError("Kernel-only ABI check failed: " + json.dumps(audit["counts"]))
    if sha(args.avbtool) != AVBTOOL_SHA256:
        raise ValueError("avbtool does not match the pinned source hash")
    spec = importlib.util.spec_from_file_location("qualified_avbtool", args.avbtool)
    avb = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(avb)
    backup = args.device_baseline / "boot-backup.img"
    handler = avb.ImageHandler(str(backup), read_only=True)
    footer, header, descriptors, partition_size = avb.Avb()._parse_image(handler)
    hashes = [d for d in descriptors if isinstance(d, avb.AvbHashDescriptor)]
    properties = [d for d in descriptors if isinstance(d, avb.AvbPropertyDescriptor)]
    if not footer or len(hashes) != 1 or hashes[0].partition_name != "boot":
        raise ValueError("Expected one AVB boot hash descriptor")
    if len(descriptors) != len(hashes) + len(properties) or header.flags:
        raise ValueError("Unsupported AVB descriptor or flags; preserve policy manually")
    original_hash = sha(backup)
    payload = boot_payload(backup.read_bytes(), kernel)
    if len(payload) + 69632 > partition_size:
        raise ValueError("Kernel payload exceeds boot partition capacity")
    args.output_dir.mkdir(parents=True)
    try:
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp)
            (work / "boot.img").symlink_to(backup)
            run(sys.executable, args.avbtool, "verify_image", "--image", work / "boot.img")
        image = args.output_dir / "boot.img"
        image.write_bytes(payload)
        command = [sys.executable, args.avbtool, "add_hash_footer", "--image", image,
                   "--partition_name", "boot", "--partition_size", partition_size,
                   "--algorithm", "NONE", "--hash_algorithm", hashes[0].hash_algorithm,
                   "--salt", hashlib.sha256(kernel).hexdigest(),
                   "--rollback_index", header.rollback_index,
                   "--rollback_index_location", header.rollback_index_location]
        for prop in properties:
            command.extend(["--prop", prop.key + ":" + prop.value.decode("utf-8")])
        run(*command)
        run(sys.executable, args.avbtool, "verify_image", "--image", image)
        if sha(backup) != original_hash or image.stat().st_size != partition_size:
            raise ValueError("Backup changed or output partition size differs")
        candidate = image.read_bytes()
        if candidate[4096:4096 + len(kernel)] != kernel:
            raise ValueError("Repacked kernel payload mismatch")
        loaded = set((args.device_baseline / "loaded-modules.txt").read_text().split())
        covered = {Path(name).name.removesuffix(".ko").replace("-", "_")
                   for name, _, _ in normalize_modules(baseline)}
        report = {"kind": "temporary-boot-only engineering candidate", "device": props,
                  "boot_image_sha256": sha(image), "stock_boot_sha256": original_hash,
                  "kernel_sha256": hashlib.sha256(kernel).hexdigest(),
                  "stock_modules_sha256": sha(args.stock_modules), "gki_config_diff": diff,
                  "abi": audit, "partition_bytes": partition_size,
                  "loaded_module_count": len(loaded),
                  "loaded_modules_without_import_metadata": sorted(loaded - covered),
                  "boot_header_version": 4, "boot_ramdisk_bytes": 0,
                  "source_commits": {k: v["commit"] for k, v in source["components"].items()},
                  "avb": {"algorithm": "NONE", "oem_signed": False,
                          "rollback_index": header.rollback_index,
                          "properties": {d.key: d.value.decode() for d in properties},
                          "avbtool_source": AVBTOOL_SOURCE},
                  "hardware_tested": False, "flash_approved": False,
                  "limitations": ["Stock import metadata baseline does not cover every loaded module",
                                  "Retained stock modules are not rebuilt or replaced",
                                  "Bootloader acceptance of temporary boot is untested",
                                  "Root persistence is not hardware verified"]}
        (args.output_dir / "candidate-report.json").write_text(json.dumps(report, indent=2) + "\n")
    except Exception:
        # Preserve diagnostics for review; never make a failed run look complete.
        (args.output_dir / "FAILED").write_text("Candidate generation failed; do not use this image.\n")
        raise
    print("Candidate prepared; hardware_tested=false, flash_approved=false")


if __name__ == "__main__":
    main()
