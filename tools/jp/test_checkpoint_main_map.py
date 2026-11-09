"""Synthetic-only tests; no Japanese game content is used."""
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from checkpoint_main_map import checkpoint, csv_rows


def setup(root):
    elf = root / 'SLPM_661.01'
    elf.write_bytes(b'synthetic-elf')
    rev = root / 'revision.json'
    rev.write_text(json.dumps({'schema_version': 1, 'boot_executable': elf.name,
        'elf': {'file': elf.name, 'size': elf.stat().st_size,
                'sha256': hashlib.sha256(elf.read_bytes()).hexdigest()}}))
    profile = root / 'main.toml'
    profile.write_text('[general]\ninput="game/dw5xl_jp/SLPM_661.01"\n')
    raw = root / 'raw.csv'
    raw.write_text('Name,Start,End,Size\nf,0x100000,0x100020,32\n'
                   'possible_text,0x100020,0x100024,4\n'
                   'shared_tail,0x100028,0x100040,24\n')
    clean = root / 'clean.csv'
    clean.write_text('Name,Start,End,Size\nf,0x100000,0x100024,36\n'
                     'shared_tail,0x100028,0x100040,24\n')
    return elf, clean, raw, profile, rev


class CheckpointTests(unittest.TestCase):
    def test_manifest_and_delta(self):
        with tempfile.TemporaryDirectory() as t:
            elf, clean, raw, profile, rev = setup(Path(t))
            out = Path(t) / 'cp'
            result = checkpoint(elf, clean, raw, profile, rev, out)
            manifest = json.loads((out / 'manifest.json').read_text())
            self.assertEqual(manifest['modules'][0]['baseline_map'], 'raw')
            self.assertEqual(result['delta']['removed_rows'], 2)
            self.assertEqual(result['delta']['added_or_modified_rows'], 1)
            self.assertEqual(result['delta']['removed_unique_starts'], 1)
            self.assertEqual(result['validator_status'], 'NOT_RUN')
            self.assertNotIn('synthetic-elf', (out / 'summary.json').read_text())

    def test_without_raw(self):
        with tempfile.TemporaryDirectory() as t:
            elf, clean, _, profile, rev = setup(Path(t))
            out = Path(t) / 'cp'
            result = checkpoint(elf, clean, None, profile, rev, out)
            self.assertNotIn('delta', result)
            self.assertNotIn('baseline_map', json.loads((out / 'manifest.json').read_text())['modules'][0])

    def test_reject_modified_executable(self):
        with tempfile.TemporaryDirectory() as t:
            elf, clean, raw, profile, rev = setup(Path(t))
            elf.write_bytes(b'wrong')
            with self.assertRaisesRegex(ValueError, 'mismatch'):
                checkpoint(elf, clean, raw, profile, rev, Path(t) / 'cp')

    def test_reject_pal_profile(self):
        with tempfile.TemporaryDirectory() as t:
            elf, clean, raw, profile, rev = setup(Path(t))
            profile.write_text('[general]\ninput="SLES_538.60"\n')
            with self.assertRaisesRegex(ValueError, 'JP main ELF'):
                checkpoint(elf, clean, raw, profile, rev, Path(t) / 'cp')

    def test_reject_invalid_csv(self):
        with tempfile.TemporaryDirectory() as t:
            file = Path(t) / 'csv'
            file.write_text('Start,End,Size,Name\n')
            with self.assertRaisesRegex(ValueError, 'header'):
                csv_rows(file)
            file.write_text('Name,Start,End,Size\nf,0x100004,0x100000,4\n')
            with self.assertRaisesRegex(ValueError, 'address/size'):
                csv_rows(file)

    def test_alias_review_information(self):
        with tempfile.TemporaryDirectory() as t:
            elf, clean, raw, profile, rev = setup(Path(t))
            clean.write_text('Name,Start,End,Size\na,0x100000,0x100010,16\n'
                             'b,0x100000,0x100010,16\nc,0x100000,0x100020,32\n')
            result = checkpoint(elf, clean, None, profile, rev, Path(t) / 'cp')
            self.assertEqual(result['cleaned']['conflicting_end_starts'], 1)

    def test_never_overwrite(self):
        with tempfile.TemporaryDirectory() as t:
            elf, clean, raw, profile, rev = setup(Path(t))
            out = Path(t) / 'cp'
            out.mkdir()
            with self.assertRaisesRegex(ValueError, 'already exists'):
                checkpoint(elf, clean, raw, profile, rev, out)

    def test_reject_symlinks(self):
        with tempfile.TemporaryDirectory() as t:
            elf, clean, raw, profile, rev = setup(Path(t))
            link = Path(t) / 'link.csv'
            try:
                link.symlink_to(clean)
            except OSError:
                self.skipTest('Symlinks unavailable')
            with self.assertRaisesRegex(ValueError, 'non-symlink'):
                csv_rows(link)


if __name__ == '__main__':
    unittest.main()
