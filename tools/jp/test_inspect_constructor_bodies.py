"""Synthetic tests for bounded Japanese constructor return-span review."""
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from inspect_samples import inspect_overlay
from inspect_constructor_bodies import inspect_local, span_candidate, transfer, main

BASE = 0x0060C800


def fixture(root: Path):
    game = root / 'game'
    game.mkdir()
    entries = []
    for i in range(3):
        name = f'OVL_0{i}.BIN'
        b = bytearray(0x200)
        begin = BASE + 0xB0
        end = begin + (8 if i == 0 else 0)
        struct.pack_into('<8I', b, 0, 0x336F574D, i + 1, BASE,
                         0x80, 0x80, 0, begin, end)
        if i == 0:
            # Two synthetic in-file thunks: each ends with JR $ra and NOP.
            for off in (0x80, 0xA0):
                struct.pack_into('<2I', b, off, 0x3C050068, 0x24A50010)
            struct.pack_into('<I', b, 0x98, 0x03E00008)
            struct.pack_into('<I', b, 0xA8, 0x03E00008)
            struct.pack_into('<2I', b, 0xB0, BASE + 0x80, BASE + 0xA0)
        path = game / name
        path.write_bytes(b)
        entries.append(inspect_overlay(path))
    revision = root / 'revision.json'
    revision.write_text(json.dumps({
        'schema_version': 1, 'boot_executable': 'SLPM_661.01',
        'overlays': entries}))
    return game, revision


def refresh(game, revision, index=0):
    obj = json.loads(revision.read_text())
    obj['overlays'][index] = inspect_overlay(game / f'OVL_0{index}.BIN')
    revision.write_text(json.dumps(obj))


class ConstructorBodyTests(unittest.TestCase):
    def test_two_linear_return_candidates(self):
        with tempfile.TemporaryDirectory() as folder:
            game, revision = fixture(Path(folder))
            result, rows = inspect_local(game, revision)
            self.assertEqual(result['candidate_total'], 2)
            self.assertEqual(result['linear_return_candidate_total'], 2)
            self.assertEqual(result['verified_function_count'], 0)
            self.assertFalse(result['native_japanese_build_ready'])
            self.assertEqual(rows[0]['candidate_start'], f'0x{BASE+0x80:08X}')
            self.assertEqual(rows[0]['candidate_end_exclusive'], f'0x{BASE+0xA0:08X}')
            self.assertEqual(rows[0]['candidate_bytes'], 32)
            self.assertEqual(rows[1]['candidate_end_exclusive'], f'0x{BASE+0xB0:08X}')
            self.assertEqual(rows[0]['recognized_earlier_control_transfers'], 0)
            self.assertEqual(result['modules']['ovl01']['candidate_spans'], 0)

    def test_branch_before_return_stays_ambiguous(self):
        b = bytearray(0x80)
        struct.pack_into('<I', b, 0x40, 0x10000003)  # BEQ zero,zero
        struct.pack_into('<I', b, 0x50, 0x03E00008)
        row = span_candidate(b, BASE, BASE + 0x40, BASE + 0x60, 'ovl00')
        self.assertEqual(row['status'], 'CONTROL_TRANSFER_BEFORE_RETURN_REVIEW')
        self.assertEqual(row['recognized_earlier_control_transfers'], 1)

    def test_missing_return_stays_ambiguous(self):
        row = span_candidate(bytes(0x100), BASE, BASE + 0x40, BASE + 0x80, 'ovl00')
        self.assertEqual(row['status'], 'NO_RETURN_IN_BOUNDED_WINDOW')
        self.assertEqual(row['candidate_end_exclusive'], '')

    def test_delay_slot_required(self):
        b = bytearray(0x100)
        struct.pack_into('<I', b, 0x7C, 0x03E00008)
        row = span_candidate(b, BASE, BASE + 0x70, BASE + 0x80, 'ovl00')
        self.assertEqual(row['status'], 'NO_DELAY_SLOT_IN_BOUNDED_WINDOW')

    def test_reject_nonzero_trailing_gap(self):
        b = bytearray(0x100)
        struct.pack_into('<I', b, 0x48, 0x03E00008)
        struct.pack_into('<I', b, 0x5C, 0x24020001)
        row = span_candidate(b, BASE, BASE + 0x40, BASE + 0x60, 'ovl00')
        self.assertEqual(row['status'], 'NONZERO_OR_EXCESSIVE_PADDING_REVIEW')

    def test_reject_excessive_padding(self):
        b = bytearray(0x100)
        struct.pack_into('<I', b, 0x48, 0x03E00008)
        row = span_candidate(b, BASE, BASE + 0x40, BASE + 0x90, 'ovl00')
        self.assertEqual(row['status'], 'NONZERO_OR_EXCESSIVE_PADDING_REVIEW')

    def test_recognizes_cop_and_special_transfers(self):
        self.assertTrue(transfer(0x03E00008))
        self.assertTrue(transfer(0x08000000))
        self.assertTrue(transfer(0x0C000000))
        self.assertTrue(transfer(0x10000001))
        self.assertTrue(transfer(0x45010001))
        self.assertTrue(transfer(0x42000018))
        self.assertFalse(transfer(0x00000000))
        self.assertFalse(transfer(0x3C040068))

    def test_reject_mutated_overlay(self):
        with tempfile.TemporaryDirectory() as folder:
            game, revision = fixture(Path(folder))
            file = game / 'OVL_01.BIN'
            b = bytearray(file.read_bytes())
            b[-1] ^= 1
            file.write_bytes(b)
            with self.assertRaisesRegex(ValueError, 'differs'):
                inspect_local(game, revision)

    def test_reject_duplicate_constructor_pointers(self):
        with tempfile.TemporaryDirectory() as folder:
            game, revision = fixture(Path(folder))
            file = game / 'OVL_00.BIN'
            b = bytearray(file.read_bytes())
            struct.pack_into('<I', b, 0xB4, BASE + 0x80)
            file.write_bytes(b)
            refresh(game, revision)
            with self.assertRaisesRegex(ValueError, 'duplicate'):
                inspect_local(game, revision)

    def test_supports_lowercase_disc_filename(self):
        with tempfile.TemporaryDirectory() as folder:
            game, revision = fixture(Path(folder))
            for i in range(3):
                p = game / f'OVL_0{i}.BIN'
                p.rename(game / p.name.lower())
            obj, rows = inspect_local(game, revision)
            self.assertEqual(len(rows), 2)

    def test_report_created_and_not_overwritten(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            game, revision = fixture(root)
            out = root / 'output'
            self.assertEqual(main([str(game), '--revision', str(revision), '--out', str(out)]), 0)
            summary = json.loads((out / 'summary.json').read_text())
            self.assertFalse(summary['boundaries_confirmed_with_ghidra'])
            self.assertNotIn('machine_code', (out / 'constructor_span_candidates.csv').read_text())
            with self.assertRaises(SystemExit):
                main([str(game), '--revision', str(revision), '--out', str(out)])


if __name__ == '__main__':
    unittest.main()
