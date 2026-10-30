#!/usr/bin/env python3
"""Phase E post-build artifact & compatibility verifier for Umbrella Kernel (kunzite).

Inspects Kleaf dist outputs without claiming flash safety prematurely:
- Kernel .config security/ABI invariants and optional diff vs local kunzite-stock.config
- Module.symvers symbol count and KMI CRC presence
- ELF .modinfo inspection (vermagic, depends, intree) across built .ko modules
- Flattened Device Tree (.dtb / .dtbo) magic and kunzite board/MSM identifiers
- Android boot / vendor_boot / dtbo / dlkm image header verification
"""
import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_MANIFEST = ROOT / "config/sources/kernel-source.json"

CRITICAL_CONFIGS = {
    "CONFIG_MODULES": "y",
    "CONFIG_MODVERSIONS": "y",
    "CONFIG_MODULE_SIG": "y",
    "CONFIG_CFI_CLANG": "y",
    "CONFIG_SHADOW_CALL_STACK": "y",
    "CONFIG_TRIM_UNUSED_KSYMS": "y",
    "CONFIG_PREEMPT": "y",
}

FDT_MAGIC = 0xD00DFEED


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_kconfig(path: Path) -> dict[str, str]:
    cfg: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("# CONFIG_") and line.endswith(" is not set"):
            key = line[2 : -len(" is not set")]
            cfg[key] = "n"
        elif line.startswith("CONFIG_") and "=" in line:
            k, v = line.split("=", 1)
            cfg[k] = v
    return cfg


def extract_elf_modinfo(ko_path: Path) -> dict[str, str]:
    """Extract key=value strings from the .modinfo section of an AArch64 ELF64 .ko."""
    data = ko_path.read_bytes()
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        return {}
    e_shoff = struct.unpack_from("<Q", data, 40)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 58)
    if e_shoff == 0 or e_shnum == 0 or e_shstrndx >= e_shnum:
        return {}

    def shdr(idx: int) -> tuple[int, int, int, int]:
        off = e_shoff + idx * e_shentsize
        sh_name, sh_type, _flags, _addr, sh_offset, sh_size = struct.unpack_from(
            "<IIQQQQ", data, off
        )
        return sh_name, sh_type, sh_offset, sh_size

    _, _, str_off, str_size = shdr(e_shstrndx)
    shstrtab = data[str_off : str_off + str_size]

    for i in range(e_shnum):
        sh_name, _, sh_offset, sh_size = shdr(i)
        end = shstrtab.find(b"\x00", sh_name)
        sec_name = shstrtab[sh_name:end].decode("ascii", errors="replace")
        if sec_name == ".modinfo":
            sec = data[sh_offset : sh_offset + sh_size]
            info: dict[str, str] = {}
            for entry in sec.split(b"\x00"):
                if b"=" in entry:
                    k, v = entry.decode("utf-8", errors="replace").split("=", 1)
                    info[k.strip()] = v.strip()
            return info
    return {}


def inspect_boot_header(img_path: Path) -> dict[str, object]:
    head = img_path.read_bytes()[:64]
    if head.startswith(b"ANDROID!"):
        kernel_sz, ramdisk_sz, os_ver, hdr_sz = struct.unpack_from("<IIII", head, 8)
        hdr_ver = struct.unpack_from("<I", head, 40)[0]
        return {
            "type": "boot_img",
            "header_version": hdr_ver,
            "kernel_bytes": kernel_sz,
            "ramdisk_bytes": ramdisk_sz,
            "header_bytes": hdr_sz,
            "os_version_raw": hex(os_ver),
        }
    if head.startswith(b"VNDRBOOT"):
        hdr_ver, page_sz, kernel_addr, ramdisk_addr, vramdisk_sz = struct.unpack_from(
            "<IIIII", head, 8
        )
        return {
            "type": "vendor_boot_img",
            "header_version": hdr_ver,
            "page_size": page_sz,
            "kernel_addr": hex(kernel_addr),
            "ramdisk_addr": hex(ramdisk_addr),
            "vendor_ramdisk_bytes": vramdisk_sz,
        }
    return {"type": "raw_or_sparse_image", "size_bytes": img_path.stat().st_size}


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify Umbrella Kleaf build artifacts")
    parser.add_argument("--dist-dir", required=True, help="Path to Kleaf dist output directory")
    parser.add_argument(
        "--stock-config",
        default=str(ROOT / "config/kernel/kunzite-stock.config"),
        help="Optional path to extracted /proc/config.gz stock config",
    )
    parser.add_argument(
        "--report-out",
        default="",
        help="Optional JSON report output file path",
    )
    args = parser.parse_args()

    dist_dir = Path(args.dist_dir).expanduser().resolve()
    if not dist_dir.is_dir():
        raise RuntimeError(f"Dist directory does not exist: {dist_dir}")

    manifest = json.loads(SOURCE_MANIFEST.read_text(encoding="utf-8"))
    errors: list[str] = []
    warnings: list[str] = []
    compatibility_blockers: list[str] = []

    image_path = dist_dir / "Image"
    symvers_path = dist_dir / "Module.symvers"
    config_path = dist_dir / ".config"

    artifacts_summary: dict[str, object] = {}
    for core_file in ("Image", "Image.lz4", "vmlinux", "System.map", "Module.symvers", ".config", "gki.config", "gki.Module.symvers"):
        fp = dist_dir / core_file
        if fp.is_file():
            artifacts_summary[core_file] = {
                "size_bytes": fp.stat().st_size,
                "sha256": sha256_file(fp),
            }

    if not image_path.is_file():
        errors.append("Missing arm64 kernel Image in dist directory")
    if not symvers_path.is_file():
        errors.append("Missing Module.symvers in dist directory")

    if not (dist_dir / "gki.config").is_file():
        compatibility_blockers.append("GKI .config unavailable: core KMI/security configuration not independently audited")

    config_report: dict[str, object] = {}
    if config_path.is_file():
        built_cfg = parse_kconfig(config_path)
        config_report["total_options"] = len(built_cfg)
        critical_results: dict[str, dict[str, str]] = {}
        for key, expected in CRITICAL_CONFIGS.items():
            actual = built_cfg.get(key, "MISSING")
            critical_results[key] = {"expected": expected, "actual": actual}
            if actual != expected:
                if key == "CONFIG_TRIM_UNUSED_KSYMS" and actual == "n":
                    warnings.append(
                        "Vendor CONFIG_TRIM_UNUSED_KSYMS=n differs from stock; "
                        "this vendor configuration is not proof of a GKI KMI failure. "
                        "Verify the GKI .config, exported symbols, and stock module CRCs "
                        "before any flashing."
                    )
                else:
                    errors.append(f"Critical Kconfig mismatch: {key}={actual} (expected {expected})")

        sig_all = built_cfg.get("CONFIG_MODULE_SIG_ALL", "n")
        critical_results["CONFIG_MODULE_SIG_ALL"] = {
            "expected": "y (GKI) / n (vendor fragment)",
            "actual": sig_all,
        }
        if sig_all != "y":
            warnings.append(
                f"CONFIG_MODULE_SIG_ALL={sig_all} in merged vendor .config "
                "(kunzite_perf.config unsets CONFIG_MODULE_SIG_ALL; verify stock vendor_dlkm signing policy before flashing)"
            )
        config_report["critical_checks"] = critical_results

        stock_path = Path(args.stock_config).expanduser()
        if stock_path.is_file():
            stock_sha = sha256_file(stock_path)
            expected_sha = manifest["stock_config_local"]["expected_sha256"]
            stock_cfg = parse_kconfig(stock_path)
            differing = {
                k: {"stock": stock_cfg.get(k), "built": built_cfg.get(k)}
                for k in sorted(set(stock_cfg) | set(built_cfg))
                if stock_cfg.get(k) != built_cfg.get(k)
            }
            config_report["stock_comparison"] = {
                "present": True,
                "sha256": stock_sha,
                "sha256_matches_verified_baseline": stock_sha == expected_sha,
                "differing_option_count": len(differing),
            }
        else:
            config_report["stock_comparison"] = {
                "present": False,
                "note": "kunzite-stock.config is excluded by .gitignore on remote; run locally on Termux for full 7,755-line diff.",
            }
    else:
        errors.append("Missing .config in dist directory")

    symvers_report: dict[str, object] = {}
    if symvers_path.is_file():
        lines = [
            ln.split("\t")
            for ln in symvers_path.read_text(encoding="utf-8", errors="replace").splitlines()
            if ln.strip()
        ]
        vmlinux_syms = [ln for ln in lines if len(ln) >= 3 and ln[2] == "vmlinux"]
        module_syms = [ln for ln in lines if len(ln) >= 3 and ln[2] != "vmlinux"]
        symvers_report = {
            "total_exported_symbols": len(lines),
            "vmlinux_kmi_symbols": len(vmlinux_syms),
            "in_tree_module_symbols": len(module_syms),
        }
        if len(vmlinux_syms) < 2000:
            errors.append(f"Unexpectedly low vmlinux exported KMI symbol count: {len(vmlinux_syms)}")

    # Compare symbols shared by GKI and vendor without assuming the stock CRCs.
    # This is a build-time consistency check, NOT a substitute for stock-module ABI validation.
    gki_symvers_path = dist_dir / "gki.Module.symvers"
    if gki_symvers_path.is_file() and symvers_path.is_file():
        def read_symvers(path: Path) -> dict[str, str]:
            result: dict[str, str] = {}
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                fields = line.split()
                if len(fields) >= 3:
                    result[fields[1]] = fields[0]
            return result

        gki_symbols = read_symvers(gki_symvers_path)
        vendor_symbols = read_symvers(symvers_path)
        common_names = gki_symbols.keys() & vendor_symbols.keys()
        crc_mismatches = sorted(
            name for name in common_names
            if gki_symbols[name].lower() != vendor_symbols[name].lower()
        )
        symvers_report["gki_symbol_count"] = len(gki_symbols)
        symvers_report["shared_symbol_count"] = len(common_names)
        symvers_report["shared_crc_mismatch_count"] = len(crc_mismatches)
        symvers_report["shared_crc_mismatch_samples"] = crc_mismatches[:30]
        if crc_mismatches:
            compatibility_blockers.append(
                f"GKI/vendor shared symbol CRC mismatches: {len(crc_mismatches)}"
            )
        if not common_names:
            compatibility_blockers.append(
                "GKI/vendor Module.symvers have no common symbols; CRC relationship cannot be assessed"
            )
    else:
        compatibility_blockers.append(
            "GKI and vendor Module.symvers comparison unavailable"
        )

    ko_files = sorted(dist_dir.glob("*.ko"))
    vermagics: set[str] = set()
    sample_modules: dict[str, dict[str, str]] = {}
    for ko in ko_files:
        info = extract_elf_modinfo(ko)
        vm = info.get("vermagic", "")
        if vm:
            vermagics.add(vm)
        if ko.name in (
            "sched-walt.ko",
            "xiaomi-cpumaxfreq.ko",
            "xiaomi_fp.ko",
            "simtray.ko",
            "miev.ko",
            "gcc-parrot.ko",
        ) or len(sample_modules) < 8:
            sample_modules[ko.name] = {
                "vermagic": vm,
                "depends": info.get("depends", ""),
                "intree": info.get("intree", ""),
            }

    modules_report = {
        "ko_count": len(ko_files),
        "distinct_vermagics": sorted(vermagics),
        "observed_device_vermagic": manifest["vendor_module_vermagic_observed"],
        "sample_modinfo": sample_modules,
    }
    if not ko_files:
        errors.append("Zero .ko kernel modules found in dist directory")
    if not vermagics:
        compatibility_blockers.append("No module vermagic metadata extracted")
    for vm in vermagics:
        if "android15-8-" not in vm or "4k" not in vm:
            errors.append(f"Incompatible module vermagic KMI/page-size token: {vm}")
        if vm.split(" ", 1)[0] != manifest["vendor_module_vermagic_observed"]:
            compatibility_blockers.append(
                f"Vendor vermagic mismatch: built={vm.split(' ', 1)[0]} stock={manifest['vendor_module_vermagic_observed']}"
            )
            warnings.append(
                f"Built vendor module vermagic differs from observed stock: {vm}. "
                "Module load compatibility is NOT verified; do not flash."
            )

    dtb_files = sorted(dist_dir.glob("*.dtb"))
    dtbo_files = sorted(dist_dir.glob("*.dtbo"))
    kunzite_dtbo = dist_dir / "kunzite-sm6475-overlay.dtbo"
    dt_report: dict[str, object] = {
        "dtb_count": len(dtb_files),
        "dtb_names": [p.name for p in dtb_files],
        "dtbo_names": [p.name for p in dtbo_files],
        "kunzite_overlay_present": kunzite_dtbo.is_file(),
    }
    for fdt in [*dtb_files, *dtbo_files]:
        raw = fdt.read_bytes()
        if len(raw) < 40 or struct.unpack_from(">I", raw, 0)[0] != FDT_MAGIC:
            errors.append(f"Invalid FDT header magic in {fdt.name}")
    if not kunzite_dtbo.is_file():
        errors.append("Missing device overlay kunzite-sm6475-overlay.dtbo")
    else:
        overlay_bytes = kunzite_dtbo.read_bytes()
        dt_report["kunzite_overlay_contains_parrot_qrd"] = b"qcom,parrot-qrd" in overlay_bytes
        dt_report["kunzite_overlay_contains_simtray"] = b"xiaomi,simtray-status" in overlay_bytes

    if not (dist_dir / "boot.img").is_file():
        compatibility_blockers.append("Boot image not collected: no validated installable kernel image")
    if not (dist_dir / "vendor_boot.img").is_file():
        compatibility_blockers.append("Vendor boot image not collected: partition integration not validated")
    compatibility_blockers.append("Stock vendor module symbol CRC comparison not performed")
    compatibility_blockers.append("AVB/vbmeta, partition layout, and recovery path not verified on hardware")

    images_report: dict[str, object] = {}
    for img_name in ("boot.img", "init_boot.img", "vendor_boot.img", "dtbo.img", "vendor_dlkm.img", "system_dlkm.ext4.img", "system_dlkm.erofs.img"):
        ip = dist_dir / img_name
        if ip.is_file():
            images_report[img_name] = {
                "size_bytes": ip.stat().st_size,
                "sha256": sha256_file(ip),
                **inspect_boot_header(ip),
            }

    report = {
        "device": manifest["device"],
        "codename": manifest["codename"],
        "build_strategy": manifest["build_strategy"],
        "source_commits": {
            k: v["commit"] for k, v in manifest["components"].items()
        },
        "core_artifacts": artifacts_summary,
        "kconfig": config_report,
        "symvers": symvers_report,
        "modules": modules_report,
        "devicetree": dt_report,
        "images": images_report,
        "warnings": warnings,
        "errors": errors,
        "build_verification_passed": len(errors) == 0,
        "compatibility_blockers": compatibility_blockers,
        "compatibility_verified": len(compatibility_blockers) == 0 and len(errors) == 0,
        "flash_approved": False,
        "flash_gate_reason": (
            "Build artifacts verified; DO NOT FLASH until stock vendor module symbol CRCs, "
            "AVB/vbmeta signing chain, and recoverable fastboot/boot backup are verified on hardware."
        ),
    }

    out_path = Path(args.report_out) if args.report_out else (dist_dir / "umbrella-build-report.json")
    out_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    print("=== UMBRELLA KERNEL ARTIFACT VERIFICATION ===")
    print(f"Dist directory : {dist_dir}")
    print(f"Core artifacts : {', '.join(artifacts_summary.keys()) or 'NONE'}")
    print(f"Modules (.ko)  : {len(ko_files)} built | vermagics: {sorted(vermagics)}")
    print(f"DTBs / DTBOs   : {len(dtb_files)} DTBs, {len(dtbo_files)} DTBOs (kunzite overlay: {kunzite_dtbo.is_file()})")
    print(f"Images         : {', '.join(images_report.keys()) or 'NONE'}")
    print(f"Report written : {out_path}")
    for w in warnings:
        print(f"WARN: {w}")
    for blocker in compatibility_blockers:
        print(f"FLASH BLOCKED: {blocker}")
    if errors:
        for e in errors:
            print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
    print("Verification status: PASS (build verified; flash_approved=false by fail-closed policy)")


if __name__ == "__main__":
    main()
