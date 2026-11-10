"""Synthetic overlay checkpoint tests: no game data or translated code."""
import hashlib
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from checkpoint_overlay_maps import checkpoint

BASE = 0x0060C800


def fixture(root: Path):
    game, maps, rawmaps, profiles = (root / x for x in ('game', 'maps', 'rawmaps', 'profiles'))
    for p in (game, maps, rawmaps, profiles):
        p.mkdir()
    records = []
    for n in range(3):
        name = f'OVL_0{n}.BIN'
        header = struct.pack('<8I', 0x336F574D, n + 1, BASE,
                             0x100, 0x100, 0x0, BASE + 0x180, BASE + 0x180)
        binary = game / name
        binary.write_bytes(header + bytes(0x200 - len(header)))
        metadata = {'file': name, 'size': binary.stat().st_size,
                    'sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                    'module_id': n + 1, 'load_base': f'0x{BASE:08X}',
                    'header_field_0c': 0x100, 'header_field_10': 0x100,
                    'bss_size': 0, 'constructor_start': f'0x{BASE + 0x180:08X}',
                    'constructor_end': f'0x{BASE + 0x180:08X}'}
        records.append(metadata)
        stem = f'ovl0{n}'
        (profiles / stem).mkdir()
        (profiles / stem / f'{stem}.toml').write_text(
            '[general]\n'
            f'input = "game/dw5xl_jp/{name}"\n'
            'input_format = "raw"\n'
            f'module_id = "dw5xl_jp_{stem}"\n'
            f'raw_base = 0x{BASE:08X}\n'
            'raw_code_offset = 0x80\n')
        (maps / f'{stem}.csv').write_text(
            f'Name,Start,End,Size\nf,0x{BASE+0x80:08X},0x{BASE+0xA0:08X},32\n')
        (rawmaps / f'{stem}.csv').write_text(
            f'Name,Start,End,Size\nf,0x{BASE+0x80:08X},0x{BASE+0xA0:08X},32\n'
            f'data,0x{BASE+0xA0:08X},0x{BASE+0xA4:08X},4\n')
    revision = root / 'revision.json'
    revision.write_text(json.dumps({'schema_version': 1,
        'boot_executable': 'SLPM_661.01', 'overlays': records}))
    return game, maps, rawmaps, profiles, revision


class OverlayCheckpointTests(unittest.TestCase):
    def test_all_three_overlay_manifests(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            game, maps, raw, profiles, revision = fixture(root)
            out = root / 'checkpoint'
            result = checkpoint(game, maps, out, raw, revision, profiles)
            manifest = json.loads((out / 'manifest.json').read_text())
            self.assertEqual(result['overlay_files_verified'], 3)
            self.assertEqual(len(manifest['modules']), 3)
            self.assertEqual(manifest['modules'][0]['id'], 'dw5xl_jp_ovl00')
            self.assertEqual(manifest['modules'][0]['raw_base'], BASE)
            self.assertEqual(manifest['modules'][0]['raw_code_offset'], 0x80)
            self.assertEqual(manifest['modules'][0]['baseline_map'], 'raw')
            self.assertFalse(result['native_jp_build_ready'])
            self.assertFalse(result['modules'][0]['code_offset_verified'])
            self.assertEqual(result['modules'][1]['delta']['removed_rows'], 1)
            self.assertNotIn('OVL binary payload', (out / 'summary.json').read_text())

    def test_no_raw_exports_required(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            game, maps, _, profiles, revision = fixture(root)
            out = root / 'checkpoint'
            checkpoint(game, maps, out, None, revision, profiles)
            modules = json.loads((out / 'manifest.json').read_text())['modules']
            self.assertTrue(all('baseline_map' not in m for m in modules))

    def test_changed_binary_rejected_before_output(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            game, maps, raw, profiles, revision = fixture(root)
            (game / 'OVL_01.BIN').write_bytes(b'altered')
            with self.assertRaises(ValueError):
                checkpoint(game, maps, root / 'checkpoint', raw, revision, profiles)
            self.assertFalse((root / 'checkpoint').exists())

    def test_wrong_profile_base_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            game, maps, raw, profiles, revision = fixture(root)
            p = profiles / 'ovl01' / 'ovl01.toml'
            p.write_text(p.read_text().replace(f'0x{BASE:08X}', '0x0061A800'))
            with self.assertRaisesRegex(ValueError, 'profile disagrees'):
                checkpoint(game, maps, root / 'checkpoint', raw, revision, profiles)

    def test_wrong_profile_module_id_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            game, maps, raw, profiles, revision = fixture(root)
            p = profiles / 'ovl02' / 'ovl02.toml'
            p.write_text(p.read_text().replace('dw5xl_jp_ovl02', 'dw5xl_jp_ovl01'))
            with self.assertRaisesRegex(ValueError, 'profile disagrees'):
                checkpoint(game, maps, root / 'checkpoint', raw, revision, profiles)

    def test_header_region_row_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            game, maps, raw, profiles, revision = fixture(root)
            (maps / 'ovl00.csv').write_text(
                f'Name,Start,End,Size\nbad,0x{BASE+0x10:08X},0x{BASE+0x20:08X},16\n')
            with self.assertRaisesRegex(ValueError, 'outside the candidate'):
                checkpoint(game, maps, root / 'checkpoint', raw, revision, profiles)

    def test_out_of_file_row_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            game, maps, raw, profiles, revision = fixture(root)
            (maps / 'ovl02.csv').write_text(
                f'Name,Start,End,Size\nbad,0x{BASE+0x1FC:08X},0x{BASE+0x204:08X},8\n')
            with self.assertRaisesRegex(ValueError, 'outside the candidate'):
                checkpoint(game, maps, root / 'checkpoint', raw, revision, profiles)

    def test_unexpected_overlay_in_revision_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            game, maps, raw, profiles, revision = fixture(root)
            r = json.loads(revision.read_text())
            r['overlays'][2]['file'] = 'OVL_03.BIN'
            revision.write_text(json.dumps(r))
            with self.assertRaisesRegex(ValueError, 'Unexpected or duplicate'):
                checkpoint(game, maps, root / 'checkpoint', raw, revision, profiles)

    def test_symlinked_overlay_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            game, maps, raw, profiles, revision = fixture(root)
            f = game / 'OVL_00.BIN'
            other = root / 'target'
            other.write_bytes(f.read_bytes())
            f.unlink()
            try:
                f.symlink_to(other)
            except OSError:
                self.skipTest('symlink permissions unavailable')
            with self.assertRaisesRegex(ValueError, 'symlink'):
                checkpoint(game, maps, root / 'checkpoint', raw, revision, profiles)

    def test_no_overwrite_existing_checkpoint(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            game, maps, raw, profiles, revision = fixture(root)
            out = root / 'checkpoint'
            out.mkdir()
            with self.assertRaisesRegex(ValueError, 'already exists'):
                checkpoint(game, maps, out, raw, revision, profiles)

    def test_missing_overlay_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            game, maps, raw, profiles, revision = fixture(root)
            (game / 'OVL_01.BIN').unlink()
            with self.assertRaisesRegex(ValueError, 'Missing known game file'):
                checkpoint(game, maps, root / 'checkpoint', raw, revision, profiles)

    def test_lowercase_extracted_files_accepted(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            game, maps, raw, profiles, revision = fixture(root)
            for i in range(3):
                source = game / f'OVL_0{i}.BIN'
                source.rename(game / source.name.lower())
            result = checkpoint(game, maps, root / 'checkpoint', raw, revision, profiles)
            self.assertEqual(result['overlay_files_verified'], 3)

    def test_offset_below_header_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            game, maps, raw, profiles, revision = fixture(root)
            p = profiles / 'ovl01' / 'ovl01.toml'
            p.write_text(p.read_text().replace('raw_code_offset = 0x80', 'raw_code_offset = 0x20'))
            with self.assertRaisesRegex(ValueError, 'profile disagrees'):
                checkpoint(game, maps, root / 'checkpoint', raw, revision, profiles)


if __name__ == '__main__':
    unittest.main()
