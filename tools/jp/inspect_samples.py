#!/usr/bin/env python3
"""Identify JP PS2 ELF + game overlay samples without copying their contents.

Accepts the exact five files supplied by the developer/user, not a complete ISO.
Only structural metadata and SHA-256 digests are written. Nothing from the
copyrighted code or assets is emitted into the JSON file.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
from pathlib import Path

from inspect_disc import read_boot_filename

ELF = struct.Struct('<16sHHIIIIIHHHHHH')
PHDR = struct.Struct('<8I')
OVL_HEADER = struct.Struct('<8I')
OVERLAY_NAME = re.compile(r'OVL_([0-9A-F]{2})\.BIN', re.IGNORECASE)


def file_hash(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            sha.update(chunk)
    return sha.hexdigest()


def inspect_elf(path: Path) -> dict:
    with path.open('rb') as f:
        header = f.read(ELF.size)
        if len(header) != ELF.size:
            raise ValueError('ELF too short')
        ident, e_type, machine, version, entry, phoff, _, flags, _, phentsize, phnum, _, _, _ = ELF.unpack(header)
        if ident[:6] != b'\x7fELF\x01\x01' or e_type != 2 or machine != 8 or version != 1:
            raise ValueError('Expected a 32-bit little-endian MIPS executable')
        size = path.stat().st_size
        if phnum > 256 or phentsize != PHDR.size or phoff + phentsize * phnum > size:
            raise ValueError('Invalid ELF program-header table')
        segments = []
        f.seek(phoff)
        for _ in range(phnum):
            ptype, offset, vaddr, _, filesz, memsz, pflags, align = PHDR.unpack(f.read(PHDR.size))
            if ptype != 1:
                continue
            if filesz and (offset + filesz > size):
                raise ValueError('ELF segment is outside the provided file')
            segments.append({'vaddr': f'0x{vaddr:08X}', 'file_size': filesz,
                             'mem_size': memsz, 'flags': pflags, 'alignment': align})
        return {'file': path.name, 'size': size, 'sha256': file_hash(path),
                'elf_entry': f'0x{entry:08X}', 'elf_flags': f'0x{flags:08X}',
                'load_segments': segments}


def inspect_overlay(path: Path) -> dict:
    match = OVERLAY_NAME.fullmatch(path.name)
    if not match:
        raise ValueError('Expected an OVL_XX.BIN file')
    with path.open('rb') as f:
        buf = f.read(0x80)
    if len(buf) < 0x80:
        raise ValueError('Overlay too short')
    magic, module_id, base, field_0c, field_10, bss, ctor_start, ctor_end = OVL_HEADER.unpack_from(buf)
    if magic != 0x336F574D or module_id != int(match.group(1), 16) + 1:
        raise ValueError('Invalid overlay signature or module ID')
    size = path.stat().st_size
    if ctor_start > ctor_end or (ctor_start & 3) or (ctor_end & 3) or not (base <= ctor_start <= ctor_end <= base + size):
        raise ValueError('Invalid overlay constructor range')
    return {'file': path.name.upper(), 'size': size, 'sha256': file_hash(path),
            'module_id': module_id, 'load_base': f'0x{base:08X}',
            'header_field_0c': field_0c, 'header_field_10': field_10,
            'bss_size': bss, 'constructor_start': f'0x{ctor_start:08X}',
            'constructor_end': f'0x{ctor_end:08X}'}


def inspect_samples(system: Path, executable: Path, overlays: list[Path]) -> dict:
    system_text = system.read_text(encoding='ascii')
    boot = read_boot_filename(system_text)
    if boot != executable.name.upper():
        raise ValueError('SYSTEM.CNF boot name does not match the provided ELF')
    if not re.fullmatch(r'(?:SLPM|SLPS)_[0-9]{3}\.[0-9]{2}', boot):
        raise ValueError('Expected a Japanese SLPM/SLPS boot executable')
    named = {}
    for file in overlays:
        ovl = inspect_overlay(file)
        if ovl['file'] in named:
            raise ValueError('Duplicate overlay name')
        named[ovl['file']] = ovl
    return {'schema_version': 1, 'scope': 'five sample files; full disc unverified',
            'boot_executable': boot, 'system_cnf': {'file': 'SYSTEM.CNF',
            'size': system.stat().st_size, 'sha256': file_hash(system),
            'version': next((x.strip().split('=', 1)[-1].strip() for x in system_text.splitlines() if x.upper().strip().startswith('VER')), None),
            'video_mode': next((x.strip().split('=', 1)[-1].strip() for x in system_text.splitlines() if x.upper().strip().startswith('VMODE')), None)},
            'elf': inspect_elf(executable), 'overlays': [named[k] for k in sorted(named)],
            'notice': 'Hashes and header metadata only. No game code or game assets are included. No claim of playability.'}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--system', type=Path, required=True, help='SYSTEM.CNF')
    parser.add_argument('--elf', type=Path, required=True, help='SLPM or SLPS boot ELF')
    parser.add_argument('--overlay', action='append', type=Path, default=[], help='Repeat for each OVL_XX.BIN')
    parser.add_argument('--json', type=Path, help='Where to write the metadata-only report')
    args = parser.parse_args()
    try:
        result = inspect_samples(args.system, args.elf, args.overlay)
        data = json.dumps(result, indent=2, ensure_ascii=False) + '\n'
        if args.json:
            args.json.parent.mkdir(parents=True, exist_ok=True)
            args.json.write_text(data, encoding='utf-8')
            print(f'Wrote metadata-only report to {args.json}')
        else:
            print(data, end='')
        return 0
    except (ValueError, OSError, UnicodeError) as exc:
        parser.error(str(exc))


if __name__ == '__main__':
    raise SystemExit(main())
