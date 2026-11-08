"""Synthetic test inputs contain no game code or game assets."""
import hashlib
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from inspect_samples import inspect_samples, inspect_overlay, inspect_elf


class SampleTests(unittest.TestCase):
    def test_samples(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            system = p / 'system.cnf'
            system.write_text('BOOT2 = cdrom0:\\SLPM_661.01;1\r\nVER = 1.01\r\nVMODE = NTSC\r\n')
            elf = p / 'SLPM_661.01'
            ident = b'\x7fELF\x01\x01\x01' + b'\0' * 9
            hdr = struct.pack('<16sHHIIIIIHHHHHH', ident, 2, 8, 1, 0x100008,
                              52, 0, 0, 52, 32, 1, 40, 0, 0)
            ph = struct.pack('<8I', 1, 0, 0x100000, 0, 84, 96, 7, 4)
            elf.write_bytes(hdr + ph)
            ovl = p / 'ovl_00.bin'
            ovl.write_bytes(struct.pack('<8I', 0x336F574D, 1, 0x60C800, 0x40, 0x10,
                                        0, 0x60C880, 0x60C880) + b'\0' * 96)
            obj = inspect_samples(system, elf, [ovl])
            self.assertEqual(obj['boot_executable'], 'SLPM_661.01')
            self.assertEqual(obj['system_cnf']['video_mode'], 'NTSC')
            self.assertEqual(obj['elf']['elf_entry'], '0x00100008')
            self.assertEqual(obj['overlays'][0]['load_base'], '0x0060C800')
            self.assertEqual(obj['overlays'][0]['sha256'], hashlib.sha256(ovl.read_bytes()).hexdigest())

    def test_mismatch_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p/'system.cnf').write_text('BOOT2 = cdrom0:\\SLPM_999.99;1\r\n')
            (p/'SLPM_661.01').write_bytes(b'not elf')
            with self.assertRaisesRegex(ValueError, 'does not match'):
                inspect_samples(p/'system.cnf', p/'SLPM_661.01', [])

    def test_overlay_id_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)/'ovl_01.bin'
            p.write_bytes(struct.pack('<8I', 0x336F574D, 1, 0x60C800, 0, 0,
                                      0, 0x60C800, 0x60C800) + b'\0' * 96)
            with self.assertRaisesRegex(ValueError, 'module ID'):
                inspect_overlay(p)

    def test_elf_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)/'SLPM_661.01'
            p.write_bytes(b'wrong elf')
            with self.assertRaisesRegex(ValueError, 'too short'):
                inspect_elf(p)


if __name__ == '__main__':
    unittest.main()
