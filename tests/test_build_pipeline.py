#!/usr/bin/env python3
"""Unit and integration tests for Umbrella Kernel build provenance, ELF/FDT verifiers, and CI workflows."""
import copy
import gzip
import json
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

try:
    import yaml  # type: ignore[import-untyped]
except ImportError:
    yaml = None

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import source_audit  # noqa: E402
import verify_build_artifacts  # noqa: E402
from gki_module_trust import certificate_der


def build_minimal_aarch64_ko(modinfo_kv: dict[str, str]) -> bytes:
    """Construct a valid minimal 64-bit little-endian AArch64 ELF relocatable (.ko) with .modinfo."""
    shstrtab = b"\x00.shstrtab\x00.modinfo\x00"
    sh_name_shstrtab = 1
    sh_name_modinfo = 11

    modinfo_payload = b"".join(f"{k}={v}\x00".encode("utf-8") for k, v in modinfo_kv.items())

    ehdr_size = 64
    off_shstrtab = ehdr_size
    off_modinfo = off_shstrtab + len(shstrtab)
    # Align section header table to 8 bytes
    pad_len = (8 - (off_modinfo + len(modinfo_payload)) % 8) % 8
    e_shoff = off_modinfo + len(modinfo_payload) + pad_len

    e_ident = (
        b"\x7fELF"
        + bytes([2, 1, 1, 0])  # ELFCLASS64, ELFDATA2LSB, EV_CURRENT, ELFOSABI_NONE
        + b"\x00" * 8
    )
    ehdr = e_ident + struct.pack(
        "<HHIQQQIHHHHHH",
        1,          # ET_REL
        183,        # EM_AARCH64
        1,          # EV_CURRENT
        0,          # e_entry
        0,          # e_phoff
        e_shoff,    # e_shoff
        0,          # e_flags
        ehdr_size,  # e_ehsize
        0,          # e_phentsize
        0,          # e_phnum
        64,         # e_shentsize
        3,          # e_shnum (NULL, .shstrtab, .modinfo)
        1,          # e_shstrndx (.shstrtab)
    )

    sh_null = struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    sh_str = struct.pack(
        "<IIQQQQIIQQ",
        sh_name_shstrtab,
        3,  # SHT_STRTAB
        0,
        0,
        off_shstrtab,
        len(shstrtab),
        0,
        0,
        1,
        0,
    )
    sh_mod = struct.pack(
        "<IIQQQQIIQQ",
        sh_name_modinfo,
        1,  # SHT_PROGBITS
        2,  # SHF_ALLOC
        0,
        off_modinfo,
        len(modinfo_payload),
        0,
        0,
        1,
        0,
    )
    return ehdr + shstrtab + modinfo_payload + (b"\x00" * pad_len) + sh_null + sh_str + sh_mod


def build_minimal_fdt(extra_strings: bytes = b"") -> bytes:
    """Construct a binary blob with valid big-endian FDT magic (0xd00dfeed) and ≥40-byte header."""
    body = b"\x00" * 36 + extra_strings
    totalsize = 4 + len(body)
    return struct.pack(">II", 0xD00DFEED, totalsize) + body[4:]


class BuildPipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest_path = ROOT / "config/sources/kernel-source.json"
        self.manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))

    def test_verified_source_manifest_passes_audit(self) -> None:
        source_audit.audit_source_manifest(self.manifest)

    def test_source_audit_rejects_unpinned_branch_or_short_sha(self) -> None:
        bad = copy.deepcopy(self.manifest)
        bad["components"]["kernel_devicetree"]["commit"] = "kunzite-v-oss"
        with self.assertRaises(ValueError):
            source_audit.audit_source_manifest(bad)

    def test_source_audit_requires_factory_build_define(self) -> None:
        bad = copy.deepcopy(self.manifest)
        bad["bazel_flags"] = [f for f in bad["bazel_flags"] if not f.startswith("--define=FACTORY_BUILD=")]
        with self.assertRaises(ValueError):
            source_audit.audit_source_manifest(bad)

    def test_elf_modinfo_extraction_aarch64(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ko = Path(tmp) / "xiaomi-cpumaxfreq.ko"
            ko.write_bytes(
                build_minimal_aarch64_ko(
                    {
                        "vermagic": "6.6.118-android15-8-ge56cf6b09cca-4k SMP preempt mod_unload modversions aarch64",
                        "depends": "sched-walt",
                        "intree": "Y",
                    }
                )
            )
            info = verify_build_artifacts.extract_elf_modinfo(ko)
            self.assertEqual(info["intree"], "Y")
            self.assertEqual(info["depends"], "sched-walt")
            self.assertIn("6.6.118-android15-8-", info["vermagic"])
            self.assertIn("4k", info["vermagic"])

    def test_embedded_kconfig_requires_complete_gzip_and_end_marker(self) -> None:
        config = b"# Kernel configuration\nCONFIG_MODULES=y\n"
        compressed = gzip.compress(config)
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp) / "Image"
            image.write_bytes(b"IKCFG_STinvalid" + b"padding" +
                              b"IKCFG_ST" + compressed + b"IKCFG_EDtrailer")
            self.assertEqual(verify_build_artifacts.extract_embedded_kconfig(image), config)
            for payload in (b"IKCFG_ST" + compressed,
                            b"IKCFG_ST" + compressed[:-4] + b"IKCFG_ED",
                            b"IKCFG_ST" + gzip.compress(b"x" * (4 * 1024 * 1024 + 1)) + b"IKCFG_ED"):
                image.write_bytes(payload)
                with self.assertRaises(ValueError):
                    verify_build_artifacts.extract_embedded_kconfig(image)

    def test_verify_build_artifacts_end_to_end_fail_closed_flash_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dist = Path(tmp) / "dist"
            dist.mkdir()
            (dist / ".config").write_text(
                "\n".join(
                    [
                        "CONFIG_MODULES=y",
                        "CONFIG_MODVERSIONS=y",
                        "CONFIG_MODULE_SIG=y",
                        "# CONFIG_MODULE_SIG_ALL is not set",
                        "CONFIG_CFI_CLANG=y",
                        "CONFIG_SHADOW_CALL_STACK=y",
                        "CONFIG_TRIM_UNUSED_KSYMS=y",
                        "CONFIG_PREEMPT=y",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            sym_lines = [
                f"0x{i:08x}\tkmi_sym_{i}\tvmlinux\tEXPORT_SYMBOL_GPL"
                for i in range(2100)
            ] + ["0x12345678\twalt_sym\tsched-walt\tEXPORT_SYMBOL_GPL"]
            (dist / "Module.symvers").write_text("\n".join(sym_lines) + "\n", encoding="utf-8")

            (dist / "sched-walt.ko").write_bytes(
                build_minimal_aarch64_ko(
                    {
                        "vermagic": "6.6.118-android15-8-ge56cf6b09cca-4k SMP preempt mod_unload modversions aarch64",
                        "depends": "",
                        "intree": "Y",
                    }
                )
            )
            (dist / "parrot.dtb").write_bytes(build_minimal_fdt(b"qcom,parrot"))
            (dist / "kunzite-sm6475-overlay.dtbo").write_bytes(
                build_minimal_fdt(b"qcom,parrot-qrd\x00xiaomi,simtray-status\x00")
            )
            boot_hdr = (
                b"ANDROID!"
                + struct.pack("<IIII", 4096, 0, 0x20000100, 1580)
                + (b"\x00" * 16)
                + struct.pack("<I", 4)
                + (b"\x00" * 20)
            )
            (dist / "boot.img").write_bytes(boot_hdr)

            trust = json.loads((ROOT / "config/sources/kernel-source.json").read_text())["gki_module_trust"]
            trust_config = ('CONFIG_MODULE_SIG_PROTECT=y\nCONFIG_SYSTEM_TRUSTED_KEYRING=y\n'
                            'CONFIG_SYSTEM_TRUSTED_KEYS=' + json.dumps(trust["kernel_certificate_path"]) + '\n')
            valid_gki = (dist / ".config").read_text().replace(
                "# CONFIG_MODULE_SIG_ALL is not set", "CONFIG_MODULE_SIG_ALL=y") + trust_config
            public_cert = certificate_der(ROOT / trust["certificate_path"])
            (dist / "Image").write_bytes(b"kernel-prefix" + public_cert + b"IKCFG_ST"
                                         + gzip.compress(valid_gki.encode()) + b"IKCFG_ED")

            report_file = Path(tmp) / "report.json"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "tools/verify_build_artifacts.py"),
                    "--dist-dir",
                    str(dist),
                    "--report-out",
                    str(report_file),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr + proc.stdout)
            report = json.loads(report_file.read_text(encoding="utf-8"))
            self.assertTrue(report["build_verification_passed"])
            self.assertFalse(report["flash_approved"])
            self.assertEqual(report["symvers"]["vmlinux_kmi_symbols"], 2100)
            self.assertTrue(report["devicetree"]["kunzite_overlay_contains_parrot_qrd"])
            self.assertEqual(report["images"]["boot.img"]["header_version"], 4)

            # A present GKI config must be audited, independently of vendor config.
            gki = dist / "gki.config"
            gki.write_text(valid_gki)
            command = [sys.executable, str(ROOT / "tools/verify_build_artifacts.py"),
                       "--dist-dir", str(dist), "--report-out", str(report_file)]
            passed = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(passed.returncode, 0, passed.stderr)
            good_report = json.loads(report_file.read_text())
            self.assertEqual(good_report["gki_kconfig"]["CONFIG_MODULE_SIG_ALL"]["actual"], "y")

            cases = [
                ("gki-cfi", gki, valid_gki.replace("CONFIG_CFI_CLANG=y", "CONFIG_CFI_CLANG=n").encode(),
                 "Critical GKI Kconfig mismatch: CONFIG_CFI_CLANG=n"),
                ("gki-trim", gki, valid_gki.replace("CONFIG_TRIM_UNUSED_KSYMS=y", "CONFIG_TRIM_UNUSED_KSYMS=n").encode(),
                 "Critical GKI Kconfig mismatch: CONFIG_TRIM_UNUSED_KSYMS=n"),
                ("broken-module", dist / "broken.ko", b"\\x7fELF", "Invalid module broken.ko"),
                ("missing-vermagic", dist / "broken.ko", build_minimal_aarch64_ko({"intree": "Y"}),
                 "Missing vermagic in module broken.ko"),
                ("truncated-boot", dist / "boot.img", b"ANDROID!", "Invalid image boot.img"),
            ]
            for label, path, payload, expected in cases:
                with self.subTest(label=label):
                    original = path.read_bytes() if path.exists() else None
                    path.write_bytes(payload)
                    failed = subprocess.run(command, capture_output=True, text=True)
                    self.assertEqual(failed.returncode, 1, failed.stderr)
                    rejected = json.loads(report_file.read_text())
                    self.assertFalse(rejected["build_verification_passed"])
                    self.assertFalse(rejected["flash_approved"])
                    self.assertTrue(any(expected in e for e in rejected["errors"]), rejected["errors"])
                    self.assertNotIn("Traceback", failed.stderr)
                    if original is None:
                        path.unlink()
                    else:
                        path.write_bytes(original)

            gki.unlink()
            (dist / "Image").write_bytes(
                b"kernel-prefix" + public_cert + b"IKCFG_ST" + gzip.compress(valid_gki.encode()) + b"IKCFG_ED")
            recovered = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(recovered.returncode, 0, recovered.stderr)
            recovered_report = json.loads(report_file.read_text())
            self.assertEqual(gki.read_text(), valid_gki)
            self.assertEqual(recovered_report["gki_config_source"], "Image/IKCONFIG")
            self.assertIn("gki.config", recovered_report["core_artifacts"])
            self.assertFalse(any("GKI .config unavailable" in b for b in recovered_report["compatibility_blockers"]))

    def test_rejects_malformed_elf_section_tables_and_wrong_architecture(self) -> None:
        good = build_minimal_aarch64_ko({"vermagic": "6.6.118-4k"})
        wrong_arch = bytearray(good)
        struct.pack_into("<H", wrong_arch, 18, 62)  # EM_X86_64
        bad_stride = bytearray(good)
        struct.pack_into("<H", bad_stride, 58, 1)
        outside = bytearray(good)
        struct.pack_into("<Q", outside, 40, len(good) + 1)
        bad_name = bytearray(good)
        section_table = struct.unpack_from("<Q", good, 40)[0]
        struct.pack_into("<I", bad_name, section_table + 128, 1000)
        bad_modinfo = bytearray(good)
        struct.pack_into("<Q", bad_modinfo, section_table + 128 + 32, len(good))
        with tempfile.TemporaryDirectory() as tmp:
            ko = Path(tmp) / "module.ko"
            for payload in (good[:63], good[:-1], wrong_arch, bad_stride, outside, bad_name, bad_modinfo):
                with self.subTest(payload_length=len(payload)):
                    ko.write_bytes(payload)
                    with self.assertRaises(ValueError):
                        verify_build_artifacts.extract_elf_modinfo(ko)

    def test_github_workflows_valid_yaml_and_no_masked_bazel_failures(self) -> None:
        wf_dir = ROOT / ".github/workflows"
        workflows = sorted(wf_dir.glob("*.yml"))
        self.assertGreaterEqual(len(workflows), 4)
        for wf in workflows:
            text = wf.read_text(encoding="utf-8")
            self.assertNotIn("\t", text, msg=f"Tab indentation forbidden in YAML: {wf.name}")
            self.assertIn("permissions:\n  contents: read", text, msg=wf.name)
            if yaml is not None:
                parsed = yaml.safe_load(text)
                self.assertIsInstance(parsed, dict, msg=f"Invalid YAML root in {wf.name}")
                self.assertEqual(parsed.get("permissions"), {"contents": "read"}, msg=wf.name)

        raw_kb = (wf_dir / "kernel-build.yml").read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", raw_kb)
        self.assertIn("push:", raw_kb)
        self.assertIn("inputs:", raw_kb)
        self.assertIn("include-hidden-files: true", raw_kb)
        if yaml is not None:
            kb = yaml.safe_load(raw_kb)
            triggers = kb.get("on") or kb.get(True)
            self.assertIsInstance(triggers, dict)
            self.assertIn("workflow_dispatch", triggers)
            self.assertIn("push", triggers)
            self.assertIn("inputs", triggers["workflow_dispatch"])

        for line in raw_kb.splitlines():
            if "tools/bazel" in line or "verify_build_artifacts.py" in line or "setup_kleaf_workspace.py" in line:
                self.assertNotIn("|| true", line)


if __name__ == "__main__":
    unittest.main()

