"""Public synthetic tests for prologue *review* seeds, never game binaries."""
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from survey_prologues import (candidates, executable_segments, is_stack_allocation,
                              saves_return_address, scan_local_samples, main)
from inspect_samples import inspect_overlay
from test_survey_runtime_entries import setup as runtime_fixture


class PrologueSeedTests(unittest.TestCase):
    def test_known_mips_instruction_encodings(self):
        self.assertTrue(is_stack_allocation(0x27BDFFF0))
        self.assertTrue(is_stack_allocation(0x67BDFFE0))
        self.assertFalse(is_stack_allocation(0x27BD0010))
        self.assertFalse(is_stack_allocation(0x24020001))
        self.assertTrue(saves_return_address(0xFFBF0010))
        self.assertTrue(saves_return_address(0xAFBF0008))
        self.assertFalse(saves_return_address(0xAFB00008))

    def test_one_prologue_emits_only_candidate_metadata(self):
        blob = bytearray(64)
        struct.pack_into('<2I', blob, 0, 0x27BDFFF0, 0xFFBF0010)
        rows, total = candidates('main', blob, 0, len(blob), 0x00100000)
        self.assertEqual(total, 1)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['guest_address'], '0x00100000')
        self.assertEqual(rows[0]['status'], 'CANDIDATE_NOT_VERIFIED')
        self.assertEqual(set(rows[0]), {'module', 'guest_address', 'evidence', 'status'})

    def test_stack_alloc_without_ra_save_is_not_emitted(self):
        blob = bytearray(64)
        struct.pack_into('<I', blob, 0, 0x27BDFFE0)
        rows, total = candidates('ovl00', blob, 0, len(blob), 0x0060C800)
        self.assertEqual(total, 1)
        self.assertEqual(rows, [])

    def test_elf_segment_file_offsets(self):
        with tempfile.TemporaryDirectory() as folder:
            game, rev = runtime_fixture(Path(folder))
            raw = (game / 'SLPM_661.01').read_bytes()
            self.assertEqual(executable_segments(raw), [(0, len(raw), 0x00100000)])

    def test_realistic_four_sample_identity_and_seeds(self):
        with tempfile.TemporaryDirectory() as folder:
            game, revision = runtime_fixture(Path(folder))
            path = game / 'OVL_00.BIN'
            blob = bytearray(path.read_bytes())
            struct.pack_into('<I', blob, 0x8C, 0xFFBF0010)
            path.write_bytes(blob)
            rev = json.loads(revision.read_text())
            rev['overlays'][0] = inspect_overlay(path)
            revision.write_text(json.dumps(rev))
            result, rows = scan_local_samples(game, revision)
            self.assertEqual(result['module_counts']['ovl00']['strong_review_seeds'], 1)
            self.assertEqual(result['total_strong_review_seeds'], len(rows))
            self.assertEqual(rows[0]['guest_address'], '0x0060C880')
            self.assertFalse(result['code_data_boundaries_verified'])
            self.assertEqual(result['function_count_verified'], 0)

    def test_reject_changed_source_binary(self):
        with tempfile.TemporaryDirectory() as folder:
            game, revision = runtime_fixture(Path(folder))
            path = game / 'OVL_01.BIN'
            buf = bytearray(path.read_bytes())
            buf[-1] ^= 0x22
            path.write_bytes(buf)
            with self.assertRaisesRegex(ValueError, 'differs'):
                scan_local_samples(game, revision)

    def test_safe_output_directory(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            game, revision = runtime_fixture(root)
            dest = root / 'candidate-report'
            self.assertEqual(main([str(game), '--revision', str(revision),
                                   '--out', str(dest)]), 0)
            self.assertTrue((dest / 'prologue_review_seeds.csv').is_file())
            with self.assertRaises(SystemExit):
                main([str(game), '--revision', str(revision), '--out', str(dest)])


if __name__ == '__main__':
    unittest.main()
