"""Qualify the public trust anchor and reject incomplete or weakened Images."""
import gzip
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from gki_module_trust import audit_trust_policy, certificate_der, inspect_image


class GkiModuleTrustTests(unittest.TestCase):
    def setUp(self):
        self.policy = json.loads((ROOT / "config/sources/kernel-source.json").read_text())["gki_module_trust"]
        self.cert = certificate_der(ROOT / self.policy["certificate_path"])
        self.config = ('CONFIG_MODULE_SIG=y\nCONFIG_MODULE_SIG_PROTECT=y\n'
                       'CONFIG_SYSTEM_TRUSTED_KEYRING=y\nCONFIG_SYSTEM_TRUSTED_KEYS='
                       + json.dumps(self.policy["kernel_certificate_path"]) + '\n')

    def inspect(self, cert, config):
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp) / "Image"
            image.write_bytes(b"synthetic-image" + cert + b"IKCFG_ST"
                              + gzip.compress(config.encode()) + b"IKCFG_ED")
            return inspect_image(image, self.policy)

    def test_public_certificate_and_source_patch_match_qualified_checksums(self):
        audit_trust_policy(ROOT, self.policy)
        report = self.inspect(self.cert, self.config)
        self.assertTrue(report["qualified_stock_certificate_present"])
        self.assertFalse(report["hardware_module_loading_verified"])

    def test_claimed_config_without_embedded_certificate_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "absent from built Image"):
            self.inspect(b"", self.config)

    def test_protection_cannot_be_disabled_to_pass_trust_checks(self):
        with self.assertRaisesRegex(ValueError, "configuration"):
            self.inspect(self.cert, self.config.replace("CONFIG_MODULE_SIG_PROTECT=y", "CONFIG_MODULE_SIG_PROTECT=n"))

    def test_unqualified_certificate_path_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "configuration"):
            self.inspect(self.cert, self.config.replace(self.policy["kernel_certificate_path"], "certs/unqualified.pem"))


if __name__ == "__main__":
    unittest.main()
