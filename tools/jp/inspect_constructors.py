#!/usr/bin/env python3
"""Inspect candidate constructor-pointer tables in the three known JP overlays.

The MWo3 header's constructor_start/end words are treated as a *candidate*
half-open table of 32-bit little-endian pointers. This is a hypothesis for
Ghidra review, not proof that these values are callable functions.

Only hashes, addresses, counts and classifications are output; never raw code
or complete game data. Keep reports local outside the public repository.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import struct

from checkpoint_main_map import regular_file
from inspect_samples import inspect_overlay
from find_game_files import known_file

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_REVISION = ROOT / 'recomp/dw5xl_jp/known_revision.json'
IDENTITY_FIELDS = ('file', 'size', 'sha256', 'module_id', 'load_base',
                   'header_field_0c', 'header_field_10', 'bss_size',
                   'constructor_start', 'constructor_end')
MAX_TABLE_WORDS = 16384


def fmt(value: int) -> str:
    return f'0x{value:08X}'


def inspect_table(path: Path, expected: dict) -> dict:
    """Verify the exact overlay revision, then examine its constructor word range."""
    path = regular_file(path)
    actual = inspect_overlay(path)
    if any(actual.get(field) != expected.get(field) for field in IDENTITY_FIELDS):
        raise ValueError(f'{path.name}: header, size, or SHA-256 differs from reference')
    base = int(actual['load_base'], 16)
    start = int(actual['constructor_start'], 16)
    end = int(actual['constructor_end'], 16)
    size = actual['size']
    if start % 4 or end % 4 or end < start:
        raise ValueError('Invalid aligned constructor range')
    word_count = (end - start) // 4
    if word_count > MAX_TABLE_WORDS:
        raise ValueError('Constructor table exceeds inspection limit')
    file_offset = start - base
    if file_offset < 0 or file_offset + 4 * word_count > size:
        raise ValueError('Constructor table exceeds the overlay file')
    with path.open('rb') as stream:
        stream.seek(file_offset)
        data = stream.read(4 * word_count)
    if len(data) != 4 * word_count:
        raise ValueError('Truncated constructor range')
    slots = []
    for i in range(word_count):
        value = struct.unpack_from('<I', data, i * 4)[0]
        if value == 0:
            classification = 'null'
        elif base <= value < base + size:
            classification = 'aligned_in_file' if value % 4 == 0 else 'unaligned_in_file'
        else:
            classification = 'outside_file'
        slots.append({'slot_address': fmt(start + 4 * i),
                      'pointer_value': fmt(value), 'classification': classification})
    counts = Counter(slot['classification'] for slot in slots)
    return {
        'file': actual['file'],
        'sha256': actual['sha256'],
        'module_id': actual['module_id'],
        'load_base': actual['load_base'],
        'file_size': size,
        'candidate_table_start': actual['constructor_start'],
        'candidate_table_end_exclusive': actual['constructor_end'],
        'table_file_offset': fmt(file_offset),
        'table_word_count': word_count,
        'classifications': {k: counts[k] for k in
                            ('aligned_in_file', 'unaligned_in_file', 'outside_file', 'null')},
        'candidate_function_addresses': sorted({slot['pointer_value'] for slot in slots
                                                 if slot['classification'] == 'aligned_in_file'}),
        'slots': slots,
        'verified_function_count': 0,
        'note': ('Only addresses are inspected. Header fields are *assumed* to delimit '
                 'an exclusive-end little-endian constructor table; this must be '
                 'checked by Japanese Ghidra disassembly and runtime usage.')
    }


def inspect_directory(game_dir: Path, revision: Path = DEFAULT_REVISION) -> dict:
    if not game_dir.is_dir() or game_dir.is_symlink():
        raise ValueError('Use an existing, non-symlink directory containing local JP overlay files')
    revision = regular_file(revision, 1024 * 1024)
    baseline = json.loads(revision.read_text(encoding='utf-8'))
    records = baseline.get('overlays')
    if (baseline.get('schema_version') != 1 or not isinstance(records, list)
            or len(records) != 3 or not isinstance(baseline.get('boot_executable'), str)):
        raise ValueError('Expected a three-overlay, schema-1 Japanese revision')
    names = []
    for item in records:
        if not isinstance(item, dict) or item.get('file') not in ('OVL_00.BIN', 'OVL_01.BIN', 'OVL_02.BIN'):
            raise ValueError('Unexpected overlay name in revision')
        names.append(item['file'])
    if len(set(names)) != 3:
        raise ValueError('Missing or duplicated Japanese overlay name')
    analyses = [inspect_table(known_file(game_dir, item['file']), item) for item in sorted(records, key=lambda x: x['file'])]
    return {
        'schema_version': 1,
        'scope': 'three exact Japanese overlay samples only',
        'boot_executable': baseline['boot_executable'],
        'function_addresses_confirmed': False,
        'header_table_semantics_confirmed': False,
        'overlay_code_offset_confirmed': False,
        'native_build_ready': False,
        'overlays': analyses,
        'notice': ('Read-only local analysis. Address candidates are not decompilation, '
                   'verified functions, a function map, or a playable build.')
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('game_dir', type=Path, help='Local folder containing the three Japanese overlay files')
    parser.add_argument('--revision', type=Path, default=DEFAULT_REVISION)
    parser.add_argument('--json', type=Path, help='Save metadata report to a new path outside this source checkout')
    args = parser.parse_args(argv)
    try:
        result = inspect_directory(args.game_dir, args.revision)
        contents = json.dumps(result, indent=2, ensure_ascii=True) + '\n'
        if args.json:
            target = args.json.expanduser()
            if target.resolve(strict=False).is_relative_to(ROOT.resolve()):
                raise ValueError('Choose an output path outside the repository checkout')
            if target.exists() or target.is_symlink():
                raise ValueError('Refusing to overwrite an existing report')
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open('x', encoding='utf-8') as f:
                f.write(contents)
            print(f'Saved candidate-table report to {target}')
        else:
            print(contents, end='')
        return 0
    except (OSError, ValueError, TypeError, KeyError, UnicodeError) as exc:
        parser.error(str(exc))


if __name__ == '__main__':
    raise SystemExit(main())
