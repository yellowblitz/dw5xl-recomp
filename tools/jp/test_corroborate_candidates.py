"""Synthetic-only candidate xref tests. No actual Japanese game code is stored."""
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from corroborate_candidates import corroborate, jal_words, main
from inspect_samples import inspect_elf, inspect_overlay
from test_survey_runtime_entries import setup as sample_fixture

BASE = 0x0060C800


def fixture(root: Path):
    game, revision = sample_fixture(root)
    rev = json.loads(revision.read_text())
    elf = game / 'SLPM_661.01'
    code = bytearray(elf.read_bytes())
    code.extend(bytes(0xA0 - len(code)))
    # Synthetic file-backed load range, no real game instructions.
    struct.pack_into('<I', code, 52 + 16, 0xA0)
    struct.pack_into('<I', code, 52 + 20, 0xA0)
    struct.pack_into('<I', code, 0x58, (3 << 26) | (0x100070 >> 2))
    struct.pack_into('<I', code, 0x5C, (3 << 26) | ((BASE + 0x80) >> 2))
    struct.pack_into('<I', code, 0x70, 0x27BDFFE0)
    struct.pack_into('<I', code, 0x74, 0xAFBF001C)
    elf.write_bytes(code)
    rev['elf'] = inspect_elf(elf)

    overlay = game / 'OVL_00.BIN'
    raw = bytearray(overlay.read_bytes())
    struct.pack_into('<I', raw, 0x84, (3 << 26) | (0x100070 >> 2))
    struct.pack_into('<I', raw, 0x88, (3 << 26) | ((BASE + 0x80) >> 2))
    struct.pack_into('<I', raw, 0x8C, 0xAFBF001C)
    overlay.write_bytes(raw)
    rev['overlays'][0] = inspect_overlay(overlay)
    revision.write_text(json.dumps(rev))
    return game, revision


class CorroborationTests(unittest.TestCase):
    def test_decode_real_guest_pc_high_nibble(self):
        raw = bytearray(16)
        pc_base = 0x81234000
        target = 0x8ABCDEF0
        struct.pack_into('<I', raw, 0, (3 << 26) | ((target >> 2) & 0x3ffffff))
        self.assertEqual(list(jal_words(raw, 0, 16, pc_base)),
                         [(pc_base, target)])

    def test_skip_other_opcodes_and_reject_invalid_ranges(self):
        raw = struct.pack('<3I', 0x00000000, 0x27BDFFE0, 0xFFFFFFFF)
        self.assertEqual(list(jal_words(raw, 0, len(raw), 0x100000)), [])
        with self.assertRaisesRegex(ValueError, 'Invalid'):
            list(jal_words(raw, 4, 40, 0x100000))

    def test_full_synthetic_four_sample_correlation(self):
        with tempfile.TemporaryDirectory() as folder:
            game, rev = fixture(Path(folder))
            report, rows = corroborate(game, rev)
            entries = {(r['module'], r['guest_address']): r for r in rows}
            main = entries[('main', '0x00100070')]
            self.assertGreaterEqual(main['direct_jal_word_hits'], 2)
            self.assertIn('main', main['source_modules'])
            self.assertIn('ovl00', main['source_modules'])
            self.assertEqual(main['review_status'], 'CANDIDATE_NOT_VERIFIED')
            local = entries[('ovl00', f'0x{BASE+0x80:08X}')]
            self.assertIn('constructor_table_pointer_candidate', local['evidence'])
            self.assertEqual(local['source_modules'], 'ovl00')
            self.assertEqual(report['ambiguous_main_to_overlaid_address_slot_words'], 1)
            self.assertGreaterEqual(report['candidate_counts']['main']['with_syntactic_jal_references'], 1)
            self.assertEqual(report['verified_function_count'], 0)
            self.assertFalse(report['recompiler_run'])
            self.assertFalse(report['native_jp_boot_tested'])

    def test_lowercase_filenames_are_accepted(self):
        with tempfile.TemporaryDirectory() as folder:
            game, rev = fixture(Path(folder))
            for n in range(3):
                p = game / f'OVL_0{n}.BIN'
                p.rename(game / p.name.lower())
            report, _ = corroborate(game, rev)
            self.assertEqual(set(report['candidate_counts']), {'main','ovl00','ovl01','ovl02'})

    def test_binary_hash_mismatch_fails_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            game, rev = fixture(Path(folder))
            file = game / 'OVL_02.BIN'
            raw = bytearray(file.read_bytes())
            raw[-1] ^= 0xFF
            file.write_bytes(raw)
            with self.assertRaisesRegex(ValueError, 'differs'):
                corroborate(game, rev)

    def test_output_is_local_and_not_overwritten(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            game, rev = fixture(root)
            out = root / 'output'
            self.assertEqual(main([str(game), '--revision', str(rev), '--out', str(out)]), 0)
            report = json.loads((out / 'summary.json').read_text())
            self.assertFalse(report['function_boundaries_validated'])
            csv_data = (out / 'ranked_candidates.csv').read_text()
            self.assertIn('CANDIDATE_NOT_VERIFIED', csv_data)
            self.assertNotIn('machine_code', csv_data)
            with self.assertRaises(SystemExit):
                main([str(game), '--revision', str(rev), '--out', str(out)])


if __name__ == '__main__':
    unittest.main()
