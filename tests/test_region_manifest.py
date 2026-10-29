import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from validate_regions import validate

class RegionManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = json.loads((ROOT / "config/compatibility/regions.json").read_text())

    def test_reference_manifest(self):
        validate(self.base)

    def test_rejects_unverified_promotion(self):
        data = copy.deepcopy(self.base)
        data["regions"][0]["status"] = "verified"
        with self.assertRaises(ValueError):
            validate(data)

    def test_rejects_wrong_region_suffix(self):
        data = copy.deepcopy(self.base)
        data["regions"][0]["firmwares"][0]["version"] = "OS3.0.304.0.WPQIDXM"
        with self.assertRaises(ValueError):
            validate(data)

    def test_rejects_duplicate_region(self):
        data = copy.deepcopy(self.base)
        data["regions"][1]["code"] = "MIXM"
        with self.assertRaises(ValueError):
            validate(data)

if __name__ == "__main__":
    unittest.main()
