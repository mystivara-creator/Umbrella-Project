"""Check real X.509 key rotation and incomplete stock-module coverage."""
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from audit_core_module_policy import audit_module_policy, embedded_certificate_keys, stock_boot_kernel


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL is required")
class CoreModulePolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        root = Path(cls.temp.name)
        certs = []
        for name in ("stock", "rebuilt"):
            key, cert = root / (name + ".key"), root / (name + ".der")
            subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
                            "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", str(key),
                            "-out", str(cert), "-outform", "DER", "-days", "1",
                            "-subj", "/CN=module-policy-test"], check=True, capture_output=True)
            certs.append(cert.read_bytes())
        renewed = root / "renewed.der"
        subprocess.run(["openssl", "req", "-x509", "-key", str(root / "stock.key"),
                        "-out", str(renewed), "-outform", "DER", "-set_serial", "2",
                        "-days", "1", "-subj", "/CN=module-policy-test"],
                       check=True, capture_output=True)
        cls.stock, cls.rebuilt, cls.renewed = *certs, renewed.read_bytes()
        cls.baseline = {"modules": [{"module": "system/client.ko",
                                    "imported_symbols": {"module_layout": "0x12345678"}}]}
        cls.config = {"CONFIG_MODULE_SIG_PROTECT": "y"}

    def audit(self, built, loaded=None, config=None):
        return audit_module_policy(self.stock, built, config or self.config, self.baseline,
                                   {"client"} if loaded is None else loaded)

    def test_rotated_key_blocks_even_with_complete_import_coverage(self):
        report = self.audit(self.rebuilt)
        self.assertFalse(report["host_checks_passed"])
        self.assertEqual(report["findings"][0]["status"],
                         "stock_signing_key_not_observed_in_candidate")

    def test_renewed_certificate_with_same_public_key_does_not_look_like_key_rotation(self):
        report = self.audit(self.renewed)
        self.assertTrue(report["host_checks_passed"])
        self.assertNotEqual(report["stock_embedded_certificates"][0]["certificate_sha256"],
                            report["built_embedded_certificates"][0]["certificate_sha256"])
        self.assertFalse(report["module_loading_verified"])
        self.assertFalse(report["flash_approved"])

    def test_retaining_stock_certificate_does_not_hide_uncovered_loaded_module(self):
        report = self.audit(self.stock + self.rebuilt, {"client", "early_driver"})
        self.assertFalse(report["host_checks_passed"])
        self.assertEqual(report["loaded_modules_without_import_metadata"], ["early_driver"])

    def test_missing_certificate_is_unknown_not_a_pass(self):
        report = self.audit(b"no certificate")
        self.assertFalse(report["host_checks_passed"])
        self.assertEqual(report["findings"][0]["status"], "module_signing_key_inventory_unavailable")

    def test_empty_loaded_inventory_cannot_claim_coverage(self):
        self.assertFalse(self.audit(self.stock, set())["host_checks_passed"])

    def test_force_signatures_also_requires_stock_key(self):
        report = self.audit(self.rebuilt, config={"CONFIG_MODULE_SIG_FORCE": "y"})
        self.assertFalse(report["host_checks_passed"])

    def test_truncated_der_is_not_a_certificate(self):
        self.assertEqual(embedded_certificate_keys(self.stock[:-1]), [])


class StockBootKernelTests(unittest.TestCase):
    def test_truncated_payload_and_nonempty_ramdisk_are_rejected(self):
        header = bytearray(4096)
        header[:8] = b"ANDROID!"
        struct.pack_into("<IIII", header, 8, 64, 0, 0, 1584)
        struct.pack_into("<I", header, 40, 4)
        kernel = bytearray(64)
        kernel[56:60] = b"ARM\x64"
        self.assertEqual(stock_boot_kernel(header + kernel), bytes(kernel))
        with self.assertRaises(ValueError):
            stock_boot_kernel(header + kernel[:-1])
        struct.pack_into("<I", header, 12, 1)
        with self.assertRaises(ValueError):
            stock_boot_kernel(header + kernel)


if __name__ == "__main__":
    unittest.main()
