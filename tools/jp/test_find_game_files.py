"""Synthetic tests for case-safe local JP game filename lookup."""
import tempfile
import unittest
from pathlib import Path
from find_game_files import known_file


class NameLookupTests(unittest.TestCase):
    def test_lowercase_files_on_case_sensitive_filesystems(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / 'ovl_00.bin'
            source.write_bytes(b'test')
            self.assertEqual(known_file(root, 'OVL_00.BIN'), source)

    def test_missing_filename_is_an_error(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(ValueError, 'Missing known'):
                known_file(Path(folder), 'OVL_00.BIN')

    def test_case_collisions_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            first = root / 'OVL_00.BIN'
            second = root / 'ovl_00.bin'
            first.write_bytes(b'a')
            second.write_bytes(b'b')
            if len(list(root.iterdir())) == 1:
                self.skipTest('case-sensitive filesystem unavailable')
            with self.assertRaisesRegex(ValueError, 'Ambiguous'):
                known_file(root, first.name)

    def test_reject_path_traversal_and_absolute(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for bad in ('../OVL_00.BIN', 'OVL_00.BIN/../foo', '/tmp/OVL_00.BIN', 'foo\\bar', '', '.'):
                with self.subTest(bad=bad):
                    with self.assertRaises(ValueError):
                        known_file(root, bad)

    def test_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            target = root / 'binary'
            target.write_bytes(b'abc')
            link = root / 'ovl_00.bin'
            try:
                link.symlink_to(target)
            except OSError:
                self.skipTest('Symlinks unavailable')
            with self.assertRaisesRegex(ValueError, 'non-symlink'):
                known_file(root, 'OVL_00.BIN')


if __name__ == '__main__':
    unittest.main()
