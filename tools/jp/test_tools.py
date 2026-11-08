"""Run with: python -m unittest discover -s tools/jp -p 'test_*.py' -v"""
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from inspect_disc import inventory_disc, read_boot_filename
from scaffold_profile import build_config


class DiscInspectionTests(unittest.TestCase):
    def test_boot_parser(self):
        self.assertEqual(read_boot_filename("BOOT2 = cdrom0:\\SLPM_661.01;1\nVER=1.00"), "SLPM_661.01")
        self.assertEqual(read_boot_filename("boot2=cdrom0:/slps_123.45;1"), "SLPS_123.45")

    def test_inventory_and_config(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "SYSTEM.CNF").write_text("BOOT2 = cdrom0:\\SLPM_661.01;1\n", encoding="ascii")
            (root / "SLPM_661.01").write_bytes(b"test-elf-not-copyrighted")
            (root / "OVL_00.BIN").write_bytes(b"test-overlay")
            (root / "MODULES").mkdir()
            (root / "MODULES" / "TEST.IRX").write_bytes(b"test-module")
            (root / "LARGE.BIN").write_bytes(b"skipped")
            report = inventory_disc(root)
            self.assertEqual(report["boot_executable"], "SLPM_661.01")
            self.assertEqual(report["file_count_on_disc"], 5)
            self.assertEqual(len(report["files"]), 4)
            main = next(f for f in report["files"] if f["kind"] == "boot")
            self.assertEqual(main["sha256"], hashlib.sha256(b"test-elf-not-copyrighted").hexdigest())
            self.assertIn("input = \"game/dw5xl_jp/SLPM_661.01\"", build_config(report))
            self.assertEqual(len(inventory_disc(root, hash_all=True)["files"]), 5)

    def test_rejects_other_regions(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "SYSTEM.CNF").write_text("BOOT2 = cdrom0:\\SLES_538.60;1", encoding="ascii")
            (root / "SLES_538.60").write_bytes(b"pal")
            with self.assertRaisesRegex(ValueError, "expects a Japanese"):
                inventory_disc(root)

    def test_invalid_manifest(self):
        with self.assertRaisesRegex(ValueError, "Expected Japanese"):
            build_config({"boot_executable": "SLES_538.60"})


if __name__ == "__main__":
    unittest.main()
