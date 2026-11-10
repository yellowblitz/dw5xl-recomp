"""Synthetic-only tests for Japanese overlay constructor-pointer inspection."""
import hashlib
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from inspect_constructors import inspect_directory, inspect_table, main

BASE = 0x0060C800


def fixture(root: Path):
    game = root / 'game'
    game.mkdir()
    records = []
    for i in range(3):
        name = f'OVL_0{i}.BIN'
        start = BASE + 0x100
        end = start + (16 if i == 0 else 0)
        buf = bytearray(0x200)
        struct.pack_into('<8I', buf, 0, 0x336F574D, i + 1, BASE,
                         128, 128, 0, start, end)
        if i == 0:
            struct.pack_into('<4I', buf, 0x100,
                             BASE + 0x80, BASE + 0x85, 0, 0x10100000)
        (game / name).write_bytes(buf)
        records.append({
            'file': name, 'size': len(buf), 'sha256': hashlib.sha256(buf).hexdigest(),
            'module_id': i + 1, 'load_base': f'0x{BASE:08X}',
            'header_field_0c': 128, 'header_field_10': 128, 'bss_size': 0,
            'constructor_start': f'0x{start:08X}', 'constructor_end': f'0x{end:08X}'
        })
    revision = root / 'revision.json'
    revision.write_text(json.dumps({
        'schema_version': 1, 'boot_executable': 'SLPM_661.01', 'overlays': records
    }), encoding='utf-8')
    return game, revision, records


class ConstructorInspectionTests(unittest.TestCase):
    def test_candidate_values_and_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            game, revision, _ = fixture(Path(tmp))
            report = inspect_directory(game, revision)
            self.assertEqual(report['scope'], 'three exact Japanese overlay samples only')
            self.assertFalse(report['function_addresses_confirmed'])
            self.assertFalse(report['native_build_ready'])
            ovl0 = report['overlays'][0]
            self.assertEqual(ovl0['table_word_count'], 4)
            self.assertEqual(ovl0['classifications'], {
                'aligned_in_file': 1, 'unaligned_in_file': 1,
                'outside_file': 1, 'null': 1})
            self.assertEqual(ovl0['candidate_function_addresses'], [f'0x{BASE+0x80:08X}'])
            self.assertEqual(ovl0['slots'][0]['slot_address'], f'0x{BASE+0x100:08X}')
            self.assertEqual(ovl0['table_file_offset'], '0x00000100')
            self.assertEqual(report['overlays'][1]['table_word_count'], 0)
            self.assertEqual(report['overlays'][2]['slots'], [])

    def test_unknown_pointer_not_promoted_to_function(self):
        with tempfile.TemporaryDirectory() as tmp:
            game, revision, _ = fixture(Path(tmp))
            result = inspect_directory(game, revision)['overlays'][0]
            self.assertEqual(result['verified_function_count'], 0)
            self.assertEqual(len(result['candidate_function_addresses']), 1)
            self.assertIn('assumed', result['note'].lower())

    def test_payload_change_invalidates_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            game, revision, _ = fixture(Path(tmp))
            name = game / 'OVL_01.BIN'
            buf = bytearray(name.read_bytes())
            buf[-1] = 0x20
            name.write_bytes(buf)
            with self.assertRaisesRegex(ValueError, 'differs from reference'):
                inspect_directory(game, revision)

    def test_wrong_header_magic_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            game, revision, _ = fixture(Path(tmp))
            name = game / 'OVL_00.BIN'
            buf = bytearray(name.read_bytes())
            struct.pack_into('<I', buf, 0, 0xABCDEF01)
            name.write_bytes(buf)
            with self.assertRaisesRegex(ValueError, 'signature'):
                inspect_directory(game, revision)

    def test_duplicate_revision_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            game, revision, records = fixture(Path(tmp))
            records[2]['file'] = 'OVL_01.BIN'
            revision.write_text(json.dumps({'schema_version': 1,
                'boot_executable': 'SLPM_661.01', 'overlays': records}))
            with self.assertRaisesRegex(ValueError, 'duplicated'):
                inspect_directory(game, revision)

    def test_unknown_revision_filename_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            game, revision, records = fixture(Path(tmp))
            records[0]['file'] = '../OVL_00.BIN'
            revision.write_text(json.dumps({'schema_version': 1,
                'boot_executable': 'SLPM_661.01', 'overlays': records}))
            with self.assertRaisesRegex(ValueError, 'Unexpected overlay name'):
                inspect_directory(game, revision)

    def test_out_of_bounds_constructor_range_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            game, revision, _ = fixture(Path(tmp))
            name = game / 'OVL_00.BIN'
            buf = bytearray(name.read_bytes())
            struct.pack_into('<I', buf, 0x1C, BASE + 0x204)
            name.write_bytes(buf)
            with self.assertRaisesRegex(ValueError, 'constructor range'):
                inspect_directory(game, revision)

    def test_reject_symlink_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            game, revision, _ = fixture(Path(tmp))
            file = game / 'OVL_02.BIN'
            original = Path(tmp) / 'original'
            original.write_bytes(file.read_bytes())
            file.unlink()
            try:
                file.symlink_to(original)
            except OSError:
                self.skipTest('Symlink creation unavailable')
            with self.assertRaisesRegex(ValueError, 'non-symlink'):
                inspect_directory(game, revision)

    def test_missing_overlay_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            game, revision, _ = fixture(Path(tmp))
            (game / 'OVL_01.BIN').unlink()
            with self.assertRaisesRegex(ValueError, 'Missing known game file'):
                inspect_directory(game, revision)

    def test_output_must_not_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            game, revision, _ = fixture(root)
            output = root / 'report.json'
            output.write_text('keep')
            with self.assertRaises(SystemExit):
                main([str(game), '--revision', str(revision), '--json', str(output)])
            self.assertEqual(output.read_text(), 'keep')

    def test_new_report_created_without_game_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            game, revision, _ = fixture(root)
            output = root / 'report.json'
            self.assertEqual(main([str(game), '--revision', str(revision),
                                   '--json', str(output)]), 0)
            obj = json.loads(output.read_text())
            self.assertEqual(obj['overlays'][0]['file'], 'OVL_00.BIN')
            self.assertEqual(obj['overlays'][0]['table_word_count'], 4)
            self.assertNotIn('payload', output.read_text())

    def test_lowercase_extracted_files_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            game, revision, _ = fixture(Path(tmp))
            for i in range(3):
                original = game / f'OVL_0{i}.BIN'
                original.rename(game / original.name.lower())
            result = inspect_directory(game, revision)
            self.assertEqual(result['overlays'][0]['table_word_count'], 4)

    def test_missing_game_directory_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _, rev, _ = fixture(root)
            with self.assertRaisesRegex(ValueError, 'existing'):
                inspect_directory(root / 'missing', rev)


if __name__ == '__main__':
    unittest.main()
