#!/usr/bin/env python3
"""Export conservative Japanese MIPS prologue *candidates*, not a function map.

A candidate is a negative SP stack allocation (ADDIU or DADDIU) followed by
SW/SD of $ra relative to $sp within eight following instruction words.
These patterns can also occur in data, and do not establish function bodies.
No original game instruction bytes are emitted. Inputs stay local.
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import struct

from checkpoint_main_map import regular_file
from find_game_files import known_file
from survey_runtime_entries import survey, REVISION, ROOT

ELF = struct.Struct('<16sHHIIIIIHHHHHH')
PHDR = struct.Struct('<8I')
MAX_FILE_BYTES = 64 * 1024 * 1024


def executable_segments(blob: bytes) -> list[tuple[int, int, int]]:
    """File range and guest address translation for each file-backed PT_LOAD."""
    if len(blob) < ELF.size:
        raise ValueError('Truncated ELF header')
    hdr = ELF.unpack_from(blob)
    if hdr[0][:6] != b'\x7fELF\x01\x01' or hdr[2] != 8:
        raise ValueError('Expected 32-bit little-endian MIPS ELF')
    phoff, phentsize, phnum = hdr[5], hdr[9], hdr[10]
    if phnum > 256 or phentsize != PHDR.size or phoff + phentsize * phnum > len(blob):
        raise ValueError('Invalid program header layout')
    segments = []
    for i in range(phnum):
        ptype, offset, vaddr, _, filesz, _, _, _ = PHDR.unpack_from(blob, phoff + i * phentsize)
        if ptype != 1 or filesz == 0:
            continue
        if offset + filesz > len(blob) or vaddr + filesz > 0x100000000:
            raise ValueError('Invalid file-backed ELF load range')
        segments.append((offset, offset + filesz, vaddr - offset))
    if not segments:
        raise ValueError('No file-backed ELF segment')
    return segments


def is_stack_allocation(word: int) -> bool:
    op = word >> 26
    return (op in (9, 25) and (word >> 21) & 31 == 29
            and (word >> 16) & 31 == 29 and word & 0x8000 != 0)


def saves_return_address(word: int) -> bool:
    return (word >> 26 in (43, 63)
            and (word >> 21) & 31 == 29
            and (word >> 16) & 31 == 31)


def candidates(module: str, data: bytes, first: int, last: int,
               guest_bias: int) -> tuple[list[dict], int]:
    """Review seeds only: aligned scan can misinterpret non-code as MIPS."""
    if first < 0 or last > len(data) or first > last:
        raise ValueError('Invalid scan range')
    records: list[dict] = []
    alloc_count = 0
    for offset in range(first, last - 8 * 4, 4):
        word = struct.unpack_from('<I', data, offset)[0]
        if not is_stack_allocation(word):
            continue
        alloc_count += 1
        following = struct.unpack_from('<8I', data, offset + 4)
        if not any(saves_return_address(next_word) for next_word in following):
            continue
        addr = guest_bias + offset
        if not 0 <= addr < 0x100000000:
            raise ValueError('Candidate address is outside 32-bit guest space')
        records.append({'module': module, 'guest_address': f'0x{addr:08X}',
                        'evidence': 'stack-allocation-and-nearby-return-address-save',
                        'status': 'CANDIDATE_NOT_VERIFIED'})
        if len(records) > 200_000:
            raise ValueError('Excessive candidate count')
    return records, alloc_count


def scan_local_samples(game_dir: Path, revision: Path = REVISION) -> tuple[dict, list[dict]]:
    # Perform independent SHA-256/headers/profiles checks before reading code.
    verified, _ = survey(game_dir, revision)
    elf_path = regular_file(known_file(game_dir, verified['main_elf']['file']), MAX_FILE_BYTES)
    elf_data = elf_path.read_bytes()
    all_rows = []
    stats = {}
    segments = executable_segments(elf_data)
    for first, last, bias in segments:
        rows, count = candidates('main', elf_data, first, last, bias)
        all_rows.extend(rows)
        previous = stats.setdefault('main', {'stack_allocation_words': 0, 'strong_review_seeds': 0})
        previous['stack_allocation_words'] += count
        previous['strong_review_seeds'] += len(rows)
    for overlay in verified['modules']:
        path = regular_file(known_file(game_dir, overlay['file']), MAX_FILE_BYTES)
        data = path.read_bytes()
        name = overlay['file'].split('.')[0].lower().replace('_', '')
        base = int(overlay['load_base'], 16)
        rows, count = candidates(name, data, 0x80, len(data), base)
        all_rows.extend(rows)
        stats[name] = {'stack_allocation_words': count, 'strong_review_seeds': len(rows)}
    report = {
        'schema_version': 1,
        'revision': verified['main_elf']['file'],
        'scope': 'four exact Japanese samples, file-backed load regions',
        'module_counts': stats,
        'total_strong_review_seeds': len(all_rows),
        'function_count_verified': 0,
        'code_data_boundaries_verified': False,
        'native_japanese_build_ready': False,
        'notice': ('Candidate scan includes possible non-code bytes. Many leaf functions '
                   'have no stack frame and will be missed. This is not a Ghidra '
                   'function map and must not be used as PS2Recomp input.')
    }
    return report, all_rows


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('game_dir', type=Path, help='Directory containing local Japanese ELF/overlays')
    p.add_argument('--revision', type=Path, default=REVISION)
    p.add_argument('--out', type=Path, required=True, help='New output folder outside checkout')
    args = p.parse_args(argv)
    try:
        report, rows = scan_local_samples(args.game_dir, args.revision)
        output = args.out.expanduser()
        if output.resolve(strict=False).is_relative_to(ROOT.resolve()):
            raise ValueError('Reports must be outside the public checkout')
        if output.exists() or output.is_symlink():
            raise ValueError('Refusing to overwrite existing report path')
        output.mkdir(parents=True, exist_ok=False)
        (output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        with (output / 'prologue_review_seeds.csv').open('x', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['module', 'guest_address', 'evidence', 'status'])
            writer.writeheader()
            writer.writerows(rows)
        print(f"Saved {len(rows)} candidates across the four JP files. None validated as functions.")
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, struct.error) as exc:
        p.error(str(exc))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
