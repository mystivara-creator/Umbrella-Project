#!/usr/bin/env python3
"""Regression tests for provider-aware stock module ABI comparison."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from audit_stock_module_abi import audit, compare, normalize_modules


class StockModuleAbiTests(unittest.TestCase):
    def test_match_and_mismatch(self):
        baseline = {"modules": [
            {"module": "vendor/mhi_dev_dtr.ko", "vermagic": "6.6.118-4k",
             "imported_symbols": {"mhi_queue_buf": "0x201ac5db", "unknown": "0x00000001"}}
        ]}
        result = compare(baseline, {"mhi_queue_buf": {("drivers/bus/mhi/host/mhi", "0x56e4f3df")}})
        self.assertEqual(result["counts"]["crc_mismatch"], 1)
        self.assertEqual(result["counts"]["missing_export"], 1)
        self.assertFalse(result["compatible"])

    def test_duplicate_providers_different_crc_are_ambiguous(self):
        baseline = {"modules": [{"module": "hidp.ko",
                                 "imported_symbols": {"l2cap_conn_get": "0xe0fa0035"}}]}
        result = compare(baseline, {"l2cap_conn_get": {
            ("net/bluetooth/bluetooth", "0xe0fa0035"),
            ("net/bluetooth/bluetooth", "0xa991844b")}})
        self.assertEqual(result["counts"]["ambiguous_export"], 1)

    def test_duplicate_providers_same_crc_are_not_ambiguous(self):
        baseline = {"modules": [{"module": "a.ko", "imported_symbols": {"foo": "0x12345678"}}]}
        result = compare(baseline, {"foo": {("vmlinux", "0x12345678"),
                                           ("drivers/example", "0x12345678")}})
        self.assertTrue(result["compatible"])

    def test_metadata_and_missing_export_source_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "baseline.json").write_text(json.dumps(
                {"modules": [{"module": "a.ko",
                              "imported_symbols": {"foo": "0x12345678"}}]}))
            (base / "Module.symvers").write_text(
                "0x12345678\tfoo\tdrivers/example\tEXPORT_SYMBOL\n")
            report = audit(base / "baseline.json", base)
            self.assertFalse(report["compatible"])
            self.assertFalse(report["export_sources_present"]["gki.Module.symvers"])

    def test_malformed_baseline_rejected(self):
        with self.assertRaises(ValueError):
            normalize_modules({"modules": [{"module": "broken.ko"}]})


if __name__ == "__main__":
    unittest.main()
