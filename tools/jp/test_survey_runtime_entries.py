"""Synthetic tests: no real Japanese game binaries or extracted code."""
import hashlib
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from inspect_samples import inspect_elf, inspect_overlay
from survey_runtime_entries import survey, opcode_class, candidate_calls
from test_inspect_constructors import fixture as overlay_fixture

BASE = 0x0060C800


def setup(root: Path):
    game, revision, _ = overlay_fixture(root)
    # MIPS ELF32 with one file-backed main load section; public test bytes only.
    binary = game / 'SLPM_661.01'
    ident = b'\x7fELF\x01\x01\x01' + b'\0' * 9
    hdr = struct.pack('<16sHHIIIIIHHHHHH', ident, 2, 8, 1, 0x100008,
                      52, 0, 0, 52, 32, 1, 40, 0, 0)
    phdr = struct.pack('<8I', 1, 0, 0x100000, 0, 84, 96, 7, 4)
    binary.write_bytes(hdr + phdr)
    rev = json.loads(revision.read_text())
    rev['elf'] = inspect_elf(binary)
    for n in range(3):
        path = game / f'OVL_0{n}.BIN'
        contents = bytearray(path.read_bytes())
        struct.pack_into('<I', contents, 0x80, 0x27BDFFF0)
        if n == 0:
            struct.pack_into('<I', contents, 0x84, (3 << 26) | (0x100008 >> 2))
            struct.pack_into('<I', contents, 0x88, (3 << 26) | ((BASE + 0xC0) >> 2))
        path.write_bytes(contents)
        rev['overlays'][n] = inspect_overlay(path)
    revision.write_text(json.dumps(rev))
    return game, revision


class SurveyTests(unittest.TestCase):
    def test_realistic_cross_module_targets(self):
        with tempfile.TemporaryDirectory() as folder:
            game, rev = setup(Path(folder))
            report, bookmarks = survey(game, rev)
            self.assertEqual(len(report['modules']), 3)
            self.assertEqual(len(bookmarks), 4)
            # The synthetic OVL_00 constructor table has exactly one aligned in-file pointer.
            self.assertEqual(report['modules'][0]['header_constructor_table_word_count'], 4)
            self.assertEqual(report['modules'][0]['first_word_class'], 'addiu_sp_negative_stack_frame')
            calls = report['modules'][0]['linear_first_0x100_bytes_direct_jal']
            self.assertEqual(calls[0]['target'], '0x00100008')
            self.assertEqual(calls[0]['target_class'], 'main_elf_file_backed')
            self.assertEqual(calls[1]['target'], f'0x{BASE+0xC0:08X}')
            self.assertEqual(calls[1]['target_class'], 'overlay_file_backed')
            self.assertFalse(report['native_jp_build_ready'])
            self.assertFalse(report['function_boundaries_verified'])
            self.assertNotIn('machine_code', json.dumps(report))

    def test_lowercase_input_names(self):
        with tempfile.TemporaryDirectory() as folder:
            game, rev = setup(Path(folder))
            for n in range(3):
                p = game / f'OVL_0{n}.BIN'
                p.rename(game / p.name.lower())
            result, _ = survey(game, rev)
            self.assertEqual(len(result['modules']), 3)

    def test_main_executable_hash_mismatch_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            game, rev = setup(Path(folder))
            p = game / 'SLPM_661.01'
            data = bytearray(p.read_bytes())
            data[-1] ^= 1
            p.write_bytes(data)
            with self.assertRaisesRegex(ValueError, 'differs'):
                survey(game, rev)

    def test_overlay_mutation_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            game, rev = setup(Path(folder))
            p = game / 'OVL_02.BIN'
            data = bytearray(p.read_bytes())
            data[0x120] = 0xff
            p.write_bytes(data)
            with self.assertRaisesRegex(ValueError, 'differs'):
                survey(game, rev)

    def test_opcode_classification(self):
        self.assertEqual(opcode_class(0x27BDFFE0), 'addiu_sp_negative_stack_frame')
        self.assertEqual(opcode_class(0x3C040068), 'lui')
        self.assertEqual(opcode_class(0x00000000), 'zero_word')
        self.assertEqual(opcode_class(0x0C040002), 'jal')

    def test_preview_bounds_and_high_jump_bits(self):
        buf = bytearray(0xA0)
        pc = BASE + 0x80
        target = 0x01234560
        struct.pack_into('<I', buf, 0x80, (3 << 26) | ((target >> 2) & 0x3ffffff))
        r = candidate_calls(buf, BASE, [])
        self.assertEqual(r[0]['instruction_address'], f'0x{pc:08X}')
        self.assertEqual(r[0]['target'], f'0x{target:08X}')
        self.assertEqual(r[0]['target_class'], 'other_or_unverified')


if __name__ == '__main__':
    unittest.main()
