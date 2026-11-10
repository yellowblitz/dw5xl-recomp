#!/usr/bin/env python3
"""Conservative Japanese DW5XL runtime entry-candidate survey.

Reads exact known Japanese sample binaries locally. Reports only hashes,
addresses and MIPS opcode *classes*, never copied game code. Every candidate
must be verified in Ghidra before being entered into PS2Recomp profiles.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
import struct

from checkpoint_main_map import regular_file
from find_game_files import known_file
from inspect_constructors import inspect_directory
from inspect_samples import inspect_elf

ROOT = Path(__file__).resolve().parents[2]
REVISION = ROOT / 'recomp/dw5xl_jp/known_revision.json'
PREVIEW_OFFSET = 0x80
PREVIEW_BYTES = 0x100


def hex32(num: int) -> str:
    return f'0x{num:08X}'


def opcode_class(word: int) -> str:
    op = word >> 26
    if op == 9 and (word >> 21) & 31 == 29 and (word >> 16) & 31 == 29 and word & 0x8000:
        return 'addiu_sp_negative_stack_frame'
    if op == 15:
        return 'lui'
    if op == 3:
        return 'jal'
    if word == 0:
        return 'zero_word'
    return 'unclassified_mips_word'


def candidate_calls(data: bytes, base: int, main_ranges: list[tuple[int, int]]) -> list[dict]:
    """Bounded *linear* JAL inspection; not a reachable-code graph."""
    end = min(len(data), PREVIEW_OFFSET + PREVIEW_BYTES)
    found = []
    for offset in range(PREVIEW_OFFSET, end - 3, 4):
        instruction = struct.unpack_from('<I', data, offset)[0]
        if instruction >> 26 != 3:
            continue
        pc = base + offset
        target = ((pc + 4) & 0xF0000000) | ((instruction & 0x03FFFFFF) << 2)
        if base <= target < base + len(data):
            destination = 'overlay_file_backed'
        elif any(start <= target < stop for start, stop in main_ranges):
            destination = 'main_elf_file_backed'
        else:
            destination = 'other_or_unverified'
        found.append({'instruction_address': hex32(pc), 'target': hex32(target),
                      'target_class': destination})
    return found


def survey(game_dir: Path, revision: Path = REVISION) -> tuple[dict, list[dict]]:
    baseline = json.loads(regular_file(revision, 1024 * 1024).read_text(encoding='utf-8'))
    expected_main = baseline.get('elf')
    boot = baseline.get('boot_executable')
    if (baseline.get('schema_version') != 1 or not isinstance(expected_main, dict)
            or not isinstance(boot, str) or expected_main.get('file') != boot
            or boot != 'SLPM_661.01'):
        raise ValueError('Expected Japanese SLPM_661.01 metadata')
    elfpath = regular_file(known_file(game_dir, boot), 64 * 1024 * 1024)
    actual_main = inspect_elf(elfpath)
    for key in ('file', 'size', 'sha256', 'elf_entry', 'elf_flags', 'load_segments'):
        if actual_main.get(key) != expected_main.get(key):
            raise ValueError(f'Main Japanese executable differs from reference: {key}')
    main_ranges = [
        (int(x['vaddr'], 16), int(x['vaddr'], 16) + x['file_size'])
        for x in actual_main['load_segments'] if x['file_size']
    ]
    candidate_report = inspect_directory(game_dir, revision)
    modules = []
    bookmarks = []
    for item in candidate_report['overlays']:
        name = item['file']
        path = regular_file(known_file(game_dir, name), 64 * 1024 * 1024)
        data = path.read_bytes()
        base = int(item['load_base'], 16)
        if len(data) < 0x84:
            raise ValueError(f'{name}: too short to inspect candidate entry')
        start_word = struct.unpack_from('<I', data, PREVIEW_OFFSET)[0]
        code_class = opcode_class(start_word)
        prefix_zero = data[0x40:PREVIEW_OFFSET] == bytes(PREVIEW_OFFSET - 0x40)
        calls = candidate_calls(data, base, main_ranges)
        constructor_entries = []
        for slot in item['slots']:
            target = int(slot['pointer_value'], 16)
            offset = target - base
            classification = (opcode_class(struct.unpack_from('<I', data, offset)[0])
                              if slot['classification'] == 'aligned_in_file' and
                              0 <= offset <= len(data) - 4 else 'not_file_backed_candidate')
            constructor_entries.append({
                'slot': slot['slot_address'],
                'candidate_address': slot['pointer_value'],
                'range_class': slot['classification'],
                'first_word_class': classification,
                'is_verified_function': False,
            })
            if slot['classification'] == 'aligned_in_file':
                bookmarks.append({
                    'module': name, 'kind': 'constructor_pointer_candidate',
                    'address': slot['pointer_value'],
                    'evidence': 'header-referenced aligned word, semantics unverified'})
        bookmarks.append({
            'module': name, 'kind': 'candidate_entry_after_prefix',
            'address': hex32(base + PREVIEW_OFFSET),
            'evidence': '0x40-0x7F zero-fill and first opcode: ' + code_class})
        modules.append({
            'file': name, 'sha256': item['sha256'],
            'module_id': item['module_id'], 'load_base': item['load_base'],
            'prefix_0x40_to_0x7f_all_zero': prefix_zero,
            'candidate_entry_file_offset': '0x80',
            'first_word_class': code_class,
            'candidate_entry_verified': False,
            'header_constructor_table_word_count': item['table_word_count'],
            'constructor_candidates': constructor_entries,
            'linear_first_0x100_bytes_direct_jal': calls,
            'linear_jal_is_runtime_reachable': 'NOT_DETERMINED',
        })
    report = {
        'schema_version': 1,
        'scope': 'four exact Japanese SLPM_661.01 / OVL_00-02 samples',
        'source': 'local, user-supplied game files; hashes match reference',
        'main_elf': {'file': boot, 'sha256': actual_main['sha256'],
                     'entry': actual_main['elf_entry'],
                     'file_backed_load_ranges': [{
                         'start': hex32(a), 'end_exclusive': hex32(b)
                     } for a, b in main_ranges]},
        'modules': modules,
        'function_boundaries_verified': False,
        'constructor_table_semantics_verified': False,
        'overlay_code_offset_proven': False,
        'native_jp_build_ready': False,
        'notice': ('Address/opcode-class survey only. JAL preview is linear, may '
                   'include unreachable instructions or data. No game code bytes '
                   'or translated functions are included.')
    }
    return report, bookmarks


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('game_dir', type=Path,
                   help='Folder containing your local JP main executable and three overlays')
    p.add_argument('--revision', type=Path, default=REVISION)
    p.add_argument('--out', type=Path, required=True,
                   help='New empty output directory outside the source checkout')
    args = p.parse_args(argv)
    try:
        report, bookmarks = survey(args.game_dir, args.revision)
        output = args.out.expanduser()
        if output.resolve(strict=False).is_relative_to(ROOT.resolve()):
            raise ValueError('Choose a report directory outside the source repository')
        if output.exists() or output.is_symlink():
            raise ValueError('Refusing to overwrite an existing report directory')
        output.mkdir(parents=True, exist_ok=False)
        (output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n',
                                             encoding='utf-8')
        with (output / 'candidate_bookmarks.csv').open('x', encoding='utf-8', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=('module', 'kind', 'address', 'evidence'))
            writer.writeheader()
            writer.writerows(bookmarks)
        print(f'Wrote {len(bookmarks)} *candidate* bookmarks and a metadata summary to {output}')
        print('Functions and code offset NOT verified; review in Ghidra before codegen.')
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, struct.error) as exc:
        p.error(str(exc))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
