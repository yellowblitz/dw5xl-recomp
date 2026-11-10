#!/usr/bin/env python3
"""Inspect tentative function bounds for known Japanese overlay constructors.

Strictly read-only input analysis. A reported JR $ra + delay-slot boundary
is a review candidate, not an R5900-validated function or PS2Recomp CSV.
No source game instructions, assets or machine-code translations are written.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
import json
from pathlib import Path
import struct

from checkpoint_main_map import regular_file
from find_game_files import known_file
from inspect_constructors import inspect_directory
from survey_runtime_entries import ROOT, REVISION

MAX_BINARY_BYTES = 64 * 1024 * 1024
MAX_PADDING_BYTES = 16
JR_RA = 0x03E00008
ROW_FIELDS = ('module', 'candidate_start', 'candidate_end_exclusive',
              'return_instruction', 'candidate_bytes', 'zero_padding_bytes',
              'recognized_earlier_control_transfers', 'status')


def transfer(word: int) -> bool:
    """Recognize conservative standard MIPS/EE branch or jump encodings.

    This is NOT a complete R5900 decoder. Unknown EE instructions and
    dynamic/exception paths require independent Ghidra analysis.
    """
    opcode = word >> 26
    if opcode in (1, 2, 3, 4, 5, 6, 7, 20, 21, 22, 23):
        return True
    if opcode == 0 and (word & 0x3F) in (8, 9, 12, 13):
        return True  # JR, JALR, SYSCALL, BREAK
    if opcode in (16, 17, 18):
        rs = (word >> 21) & 31
        if rs == 8:  # BC0, BC1, BC2 (+ likely variants)
            return True
        if opcode == 16 and rs == 16 and (word & 0x3F) == 24:
            return True  # ERET
    return False


def span_candidate(blob: bytes, base: int, first: int, exclusive_limit: int,
                   module: str) -> dict:
    """Inspect a pointer target through the next pointer (or table).

    An end is proposed only at the first recognized JR $ra plus its delay
    slot; no function definition is produced.
    """
    result = {'module': module, 'candidate_start': f'0x{first:08X}',
              'candidate_end_exclusive': '', 'return_instruction': '',
              'candidate_bytes': 0, 'zero_padding_bytes': 0,
              'recognized_earlier_control_transfers': 0,
              'status': 'AMBIGUOUS_REVIEW'}
    if (first < base or exclusive_limit > base + len(blob)
            or first >= exclusive_limit or first % 4 or exclusive_limit % 4):
        result['status'] = 'OUT_OF_RANGE_REVIEW'
        return result
    prior_controls = 0
    return_pc = None
    for pc in range(first, exclusive_limit, 4):
        word = struct.unpack_from('<I', blob, pc - base)[0]
        if word == JR_RA:
            return_pc = pc
            break
        if transfer(word):
            prior_controls += 1
    result['recognized_earlier_control_transfers'] = prior_controls
    if return_pc is None:
        result['status'] = 'NO_RETURN_IN_BOUNDED_WINDOW'
        return result
    end = return_pc + 8
    if end > exclusive_limit:
        result['status'] = 'NO_DELAY_SLOT_IN_BOUNDED_WINDOW'
        return result
    padding = blob[end - base:exclusive_limit - base]
    result['candidate_end_exclusive'] = f'0x{end:08X}'
    result['return_instruction'] = f'0x{return_pc:08X}'
    result['candidate_bytes'] = end - first
    result['zero_padding_bytes'] = len(padding) if not any(padding) else 0
    if (prior_controls == 0 and len(padding) <= MAX_PADDING_BYTES
            and not any(padding) and result['candidate_bytes'] >= 8):
        result['status'] = 'LINEAR_RETURN_CANDIDATE_NOT_VERIFIED'
    elif prior_controls:
        result['status'] = 'CONTROL_TRANSFER_BEFORE_RETURN_REVIEW'
    else:
        result['status'] = 'NONZERO_OR_EXCESSIVE_PADDING_REVIEW'
    return result


def inspect_local(game_dir: Path, revision: Path = REVISION) -> tuple[dict, list[dict]]:
    """Validate all three SHA-locked overlays before reporting any spans."""
    verified = inspect_directory(game_dir, revision)
    rows: list[dict] = []
    modules: dict[str, dict] = {}
    for item in verified['overlays']:
        name = item['file']
        module = name.split('.')[0].lower().replace('_', '')
        base = int(item['load_base'], 16)
        table_begin = int(item['candidate_table_start'], 16)
        file = regular_file(known_file(game_dir, name), MAX_BINARY_BYTES)
        contents = file.read_bytes()
        values = [int(slot['pointer_value'], 16) for slot in item['slots']]
        if len(set(values)) != len(values):
            raise ValueError(f'{name}: duplicate constructor pointers need manual review')
        # All 32-bit words are retained as candidates. Never drop suspicious
        # pointers silently or pretend that the layout is verified.
        sorted_pointers = sorted(values)
        for i, ptr in enumerate(sorted_pointers):
            end = sorted_pointers[i + 1] if i + 1 < len(sorted_pointers) else table_begin
            row = span_candidate(contents, base, ptr, end, module)
            rows.append(row)
        counts = Counter(r['status'] for r in rows if r['module'] == module)
        modules[module] = {'header_table_word_count': item['table_word_count'],
                           'candidate_spans': sum(counts.values()),
                           'linear_return_candidates': counts['LINEAR_RETURN_CANDIDATE_NOT_VERIFIED'],
                           'requires_additional_review': sum(
                               n for status, n in counts.items()
                               if status != 'LINEAR_RETURN_CANDIDATE_NOT_VERIFIED'),
                           'binary_sha256': item['sha256']}
    summary = {
        'schema_version': 1,
        'boot_executable': verified['boot_executable'],
        'scope': 'three exact Japanese overlay binaries, header-referenced pointers only',
        'modules': modules,
        'candidate_total': len(rows),
        'linear_return_candidate_total': sum(
            row['status'] == 'LINEAR_RETURN_CANDIDATE_NOT_VERIFIED' for row in rows),
        'verified_function_count': 0,
        'boundaries_confirmed_with_ghidra': False,
        'constructor_table_semantics_confirmed': False,
        'native_japanese_build_ready': False,
        'notice': ('Only the first JR $ra and its delay slot are proposed as bounds. '
                   'No R5900 decode proof, control-flow reachability, actual function '
                   'ownership, or PS2Recomp generation is claimed.'),
    }
    return summary, rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('game_dir', type=Path,
                        help='Local folder with OVL_00..02.BIN from the Japanese disc')
    parser.add_argument('--revision', type=Path, default=REVISION)
    parser.add_argument('--out', type=Path, required=True,
                        help='New scratch output directory outside the public checkout')
    args = parser.parse_args(argv)
    try:
        summary, rows = inspect_local(args.game_dir, args.revision)
        output = args.out.expanduser()
        if output.resolve(strict=False).is_relative_to(ROOT.resolve()):
            raise ValueError('Output must be outside the public source checkout')
        if output.exists() or output.is_symlink():
            raise ValueError('Refusing to overwrite existing output')
        output.mkdir(parents=True, exist_ok=False)
        (output / 'summary.json').write_text(
            json.dumps(summary, indent=2) + '\n', encoding='utf-8')
        with (output / 'constructor_span_candidates.csv').open(
                'x', encoding='utf-8', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=ROW_FIELDS)
            writer.writeheader()
            writer.writerows(rows)
        print(f"{summary['linear_return_candidate_total']} of "
              f"{summary['candidate_total']} constructor entries have "
              f"tentative straight-line return bounds. NONE verified in Ghidra.")
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, struct.error) as exc:
        parser.error(str(exc))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
