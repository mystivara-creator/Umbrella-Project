"""Regression checks for the temporary boot image preparation boundary."""
import struct
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from prepare_core_test import audit_core_only, boot_payload, device_properties, verify_baseline, review_stock_lkm
from test_build_pipeline import build_minimal_aarch64_ko


class CoreTestTests(unittest.TestCase):
    def root_review_fixture(self, root):
        files = {"boot-backup.img": b"stock boot", "init_boot-backup.img": b"stock init",
                 "Image": b"exact reviewed image", "kernelsu.ko": build_minimal_aarch64_ko({"name": "kernelsu"}),
                 "early.txt": b"stock-release\nwelcome to KernelSU version 33355\ninit is init.real\n"}
        for name, data in files.items():
            (root / name).write_bytes(data)
        review = {"scope": "temporary-boot-only", "target_runtime_verified": False,
                  "flash_approved": False, "stock_kernel_release": "stock-release",
                  "stock_version_observed": 33355, "evidence": {}, "limitations": ["target runtime unverified"]}
        for name, key in (("boot-backup.img", "stock_boot_sha256"),
                          ("init_boot-backup.img", "stock_init_boot_sha256"),
                          ("Image", "kernel_sha256"), ("kernelsu.ko", "stock_lkm_sha256"),
                          ("early.txt", "stock_early_log_sha256")):
            review[key] = hashlib.sha256(files[name]).hexdigest()
        return review

    def test_dynamic_lkm_review_is_not_a_native_crc_or_target_runtime_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            review = self.root_review_fixture(root)
            result = review_stock_lkm(review, root, {(root / "init_boot-backup.img").resolve()},
                                      root / "Image", root / "kernelsu.ko", root / "early.txt", {"kernelsu"})
            self.assertTrue(result["stock_loading_observed"])
            self.assertFalse(result["native_crc_pass"])
            self.assertFalse(result["target_runtime_verified"])
            self.assertFalse(result["flash_approved"])

    def test_dynamic_lkm_review_rejects_other_uncovered_modules_and_changed_image(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            review = self.root_review_fixture(root)
            args = (review, root, {(root / "init_boot-backup.img").resolve()},
                    root / "Image", root / "kernelsu.ko", root / "early.txt")
            with self.assertRaisesRegex(ValueError, "other uncovered"):
                review_stock_lkm(*args, {"kernelsu", "unreviewed_driver"})
            (root / "Image").write_bytes(b"different build")
            with self.assertRaisesRegex(ValueError, "kernel_sha256"):
                review_stock_lkm(*args, {"kernelsu"})

    def test_dynamic_lkm_review_requires_checksummed_init_boot(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            review = self.root_review_fixture(root)
            with self.assertRaisesRegex(ValueError, "baseline checksums"):
                review_stock_lkm(review, root, set(), root / "Image", root / "kernelsu.ko",
                                 root / "early.txt", {"kernelsu"})

    def test_core_mismatch_and_missing_export_are_never_resolved_by_retention(self):
        baseline = {"modules": [{"module": "vendor/client.ko", "imported_symbols": {
            "changed": "0x00000001", "absent": "0x00000002"}}]}
        report = audit_core_only(baseline, {"changed": "0x00000003"},
                                 {"changed": {"vmlinux"}, "absent": {"vmlinux"}})
        self.assertFalse(report["scoped_baseline_passed"])
        self.assertEqual(report["counts"], {"core_crc_mismatch": 1, "core_export_missing": 1})

    def test_retained_provider_is_distinct_from_a_new_core_export(self):
        baseline = {"modules": [{"module": "vendor/client.ko",
                                 "imported_symbols": {"coldstart_app_tasks": "0x8e477f5f"}}]}
        owners = {"coldstart_app_tasks": {"metis"}}
        kept = audit_core_only(baseline, {}, owners)
        self.assertTrue(kept["scoped_baseline_passed"])
        self.assertEqual(kept["counts"]["retained_stock_module"], 1)
        duplicate = audit_core_only(baseline, {"coldstart_app_tasks": "0x8e477f5f"}, owners)
        self.assertFalse(duplicate["scoped_baseline_passed"])
        self.assertEqual(duplicate["findings"][0]["status"], "core_conflicts_with_stock_module")

    def test_unknown_and_ambiguous_providers_fail(self):
        baseline = {"modules": [{"module": "client.ko", "imported_symbols": {"foo": "0x01"}}]}
        for owners in ({}, {"foo": {"vmlinux", "module"}}):
            self.assertFalse(audit_core_only(baseline, {}, owners)["scoped_baseline_passed"])

    def test_kernel_replacement_preserves_header_fields_and_discards_stale_certificate(self):
        old_kernel = bytearray(64)
        old_kernel[56:60] = b"ARM\x64"
        header = bytearray(4096)
        header[:8] = b"ANDROID!"
        struct.pack_into("<IIII", header, 8, 64, 0, 1234, 1584)
        struct.pack_into("<I", header, 40, 4)
        struct.pack_into("<I", header, 1580, 16384)
        header[44:53] = b"cmdline\x00\x00"
        stock = bytes(header) + old_kernel + bytes(4096 - 64) + b"old certificate"
        replacement = old_kernel + b"new kernel bytes"
        output = boot_payload(stock, replacement)
        expected = bytearray(header)
        struct.pack_into("<I", expected, 8, len(replacement))
        struct.pack_into("<I", expected, 1580, 0)
        self.assertEqual(output[:4096], expected)
        self.assertEqual(output[4096:4096 + len(replacement)], replacement)
        self.assertNotIn(b"old certificate", output)
        self.assertEqual(len(output) % 4096, 0)
        with self.assertRaises(ValueError):
            boot_payload(stock, b"not an ARM64 kernel")
        struct.pack_into("<I", header, 12, 1)
        with self.assertRaises(ValueError):
            boot_payload(bytes(header) + old_kernel, replacement)

    def test_locked_bootloader_and_missing_checksum_coverage_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "device.properties").write_text(
                "ro.product.device=kunzite\nkernel.arch=aarch64\nro.boot.slot_suffix=_a\n"
                "ro.boot.flash.locked=1\nro.boot.vbmeta.device_state=locked\n")
            with self.assertRaises(ValueError):
                device_properties(root)
            (root / "SHA256SUMS").write_text("")
            with self.assertRaises(ValueError):
                verify_baseline(root)


if __name__ == "__main__":
    unittest.main()
