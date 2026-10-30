#!/usr/bin/env python3
"""Read-only module coverage and embedded signing-key checks for core replacement.

CRC equality alone cannot establish Android GKI module loadability. Certificate
scanning is conservative evidence, not proof of membership in the trusted keyring
or verification of an actual module signature. No device operations are performed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess

from audit_stock_module_abi import normalize_modules
from verify_build_artifacts import extract_embedded_kconfig


def stock_boot_kernel(data):
    if len(data) < 4096 or data[:8] != b"ANDROID!":
        raise ValueError("Invalid stock boot backup")
    size, ramdisk, _, header = struct.unpack_from("<IIII", data, 8)
    if (struct.unpack_from("<I", data, 40)[0] != 4 or header != 1584
            or ramdisk or not size or 4096 + size > len(data)):
        raise ValueError("Expected a complete v4 boot image with empty ramdisk")
    kernel = data[4096:4096 + size]
    if len(kernel) < 64 or kernel[56:60] != b"ARM\x64":
        raise ValueError("Expected an uncompressed ARM64 stock kernel")
    return kernel


def embedded_certificate_keys(data):
    """Find bounded DER X.509 objects; compare SPKI keys, not certificate serials."""
    openssl = shutil.which("openssl")
    if not openssl:
        raise ValueError("OpenSSL is required for the module signing-key audit")
    certificates = []
    offset = 0
    attempts = 0
    while True:
        offset = data.find(b"\x30\x82", offset)
        if offset < 0:
            break
        start = offset
        offset += 2
        if start + 5 > len(data):
            continue
        size = 4 + int.from_bytes(data[start + 2:start + 4], "big")
        if not 128 < size <= 8192 or start + size > len(data) or data[start + 4] != 0x30:
            continue
        attempts += 1
        if attempts > 512:
            raise ValueError("Too many possible certificates; refusing an unbounded scan")
        der = data[start:start + size]
        result = subprocess.run([openssl, "x509", "-inform", "DER", "-pubkey", "-noout"],
                                input=der, capture_output=True, timeout=5)
        if result.returncode:
            continue
        key = subprocess.run([openssl, "pkey", "-pubin", "-outform", "DER"],
                             input=result.stdout, capture_output=True, timeout=5, check=True)
        certificates.append({"offset": start, "bytes": size,
                             "certificate_sha256": hashlib.sha256(der).hexdigest(),
                             "public_key_sha256": hashlib.sha256(key.stdout).hexdigest()})
    return certificates


def audit_module_policy(stock_kernel, built_kernel, config, baseline, loaded):
    if baseline.get("errors"):
        raise ValueError("Stock module extraction contains errors")
    modules = normalize_modules(baseline)
    covered = {Path(name).name.removesuffix(".ko").replace("-", "_")
               for name, _, _ in modules}
    missing = sorted({name.replace("-", "_") for name in loaded} - covered)
    findings = []
    if not loaded:
        findings.append({"status": "empty_loaded_module_inventory"})
    if missing:
        findings.append({"status": "loaded_modules_without_import_metadata", "modules": missing})
    stock = embedded_certificate_keys(stock_kernel)
    built = embedded_certificate_keys(built_kernel)
    stock_keys = {c["public_key_sha256"] for c in stock}
    built_keys = {c["public_key_sha256"] for c in built}
    protect = config.get("CONFIG_MODULE_SIG_PROTECT") == "y"
    enforce = config.get("CONFIG_MODULE_SIG_FORCE") == "y"
    if protect or enforce:
        if not stock_keys or not built_keys:
            findings.append({"status": "module_signing_key_inventory_unavailable"})
        elif stock_keys - built_keys:
            findings.append({"status": "stock_signing_key_not_observed_in_candidate",
                             "public_key_sha256": sorted(stock_keys - built_keys)})
    return {"loaded_module_count": len(set(loaded)), "baseline_module_count": len(modules),
            "loaded_modules_without_import_metadata": missing,
            "module_sig_protect": protect, "module_sig_force": enforce,
            "stock_embedded_certificates": stock, "built_embedded_certificates": built,
            "findings": findings, "host_checks_passed": not findings,
            "module_loading_verified": False, "flash_approved": False,
            "limitations": [
                "Embedded certificates do not prove membership in the kernel trusted keyring",
                "Actual retained module signatures and protected-symbol access remain to be checked",
                "Import coverage does not establish complete dependency or early-boot load order",
                "Host checks do not diagnose the cause of an observed device boot hang"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device-baseline", type=Path, required=True)
    parser.add_argument("--stock-modules", type=Path, required=True)
    parser.add_argument("--dist-dir", type=Path, required=True)
    parser.add_argument("--report-out", type=Path, required=True)
    args = parser.parse_args()
    # Reuse checksum validation without introducing a circular top-level import.
    from prepare_core_test import verify_baseline
    verify_baseline(args.device_baseline)
    config_data = extract_embedded_kconfig(args.dist_dir / "Image").decode()
    # Only enabled options are used by this audit; parse the embedded payload
    # directly rather than trusting a separately supplied config file.
    config = {}
    for line in config_data.splitlines():
        if line.startswith("CONFIG_") and "=" in line:
            key, value = line.split("=", 1)
            config[key] = value
    report = audit_module_policy(
        stock_boot_kernel((args.device_baseline / "boot-backup.img").read_bytes()),
        (args.dist_dir / "Image").read_bytes(), config,
        json.loads(args.stock_modules.read_text()),
        set((args.device_baseline / "loaded-modules.txt").read_text().split()))
    report["kernel_sha256"] = hashlib.sha256((args.dist_dir / "Image").read_bytes()).hexdigest()
    args.report_out.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"host_checks_passed": report["host_checks_passed"],
                      "findings": [f["status"] for f in report["findings"]]}))
    return 0 if report["host_checks_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
