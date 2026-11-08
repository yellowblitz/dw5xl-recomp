"""Synthetic regression checks; no original game content required."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from preflight import verify_inputs


class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.records = []
        for name in ('SYSTEM.CNF', 'SLPM_661.01', 'OVL_00.BIN', 'OVL_01.BIN', 'OVL_02.BIN'):
            data = ('synthetic ' + name).encode()
            (self.root / name.lower()).write_bytes(data)
            self.records.append(dict(file=name, size=len(data), sha256=hashlib.sha256(data).hexdigest()))
        self.baseline = dict(schema_version=1, system_cnf=self.records[0], elf=self.records[1], overlays=self.records[2:])

    def test_lowercase_files_match(self):
        self.assertTrue(all(x['status'] == 'verified' for x in verify_inputs(self.root, self.baseline)))

    def test_changed_same_size_rejected(self):
        p = self.root / 'ovl_00.bin'
        p.write_bytes(b'x' * p.stat().st_size)
        self.assertEqual(verify_inputs(self.root, self.baseline)[2]['status'], 'mismatch')

    def test_missing_overlay_reported(self):
        (self.root / 'ovl_02.bin').unlink()
        self.assertEqual(verify_inputs(self.root, self.baseline)[4]['status'], 'missing')

    def test_case_collision_rejected(self):
        upper = self.root / 'SYSTEM.CNF'
        if upper.exists():
            self.skipTest('case-insensitive filesystem')
        upper.write_bytes(b'other')
        self.assertEqual(verify_inputs(self.root, self.baseline)[0]['status'], 'ambiguous')

    def test_symlink_not_accepted(self):
        p = self.root / 'ovl_00.bin'
        p.unlink()
        try:
            p.symlink_to(self.root / 'ovl_01.bin')
        except OSError:
            self.skipTest('symlinks unavailable')
        self.assertEqual(verify_inputs(self.root, self.baseline)[2]['status'], 'not-regular-file')

    def test_cli_separates_inputs_from_build_readiness(self):
        baseline = self.root / 'revision.json'
        baseline.write_text(json.dumps(self.baseline))
        cmd = [sys.executable, str(Path(__file__).with_name('preflight.py')), str(self.root), '--revision', str(baseline), '--json']
        check = subprocess.run(cmd, text=True, capture_output=True)
        self.assertEqual(check.returncode, 1, check.stderr)
        report = json.loads(check.stdout)
        self.assertTrue(report['inputs_verified'])
        self.assertFalse(report['build_ready'])
        self.assertTrue(report['blockers'])
        self.assertEqual(subprocess.run(cmd + ['--inputs-only'], capture_output=True).returncode, 0)
        (self.root / 'ovl_00.bin').unlink()
        self.assertEqual(subprocess.run(cmd + ['--inputs-only'], capture_output=True).returncode, 1)

    def test_missing_directory_is_actionable(self):
        with self.assertRaisesRegex(ValueError, 'directory'):
            verify_inputs(self.root / 'missing', self.baseline)


if __name__ == '__main__':
    unittest.main()
