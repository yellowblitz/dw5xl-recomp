#!/usr/bin/env python3
"""Rank Japanese PS2Recomp review candidates using *syntactic* JAL references.

Uses exactly fingerprinted SLPM_661.01 / OVL_00..02.BIN input files.
JAL opcodes are scanned linearly: they MAY be data or unreachable code.
Overlays share the same guest-address slot; main->overlay targets cannot
be attributed to a specific overlay without runtime dispatch evidence.
No guest machine-code bytes or decoded instruction sequences are written.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import csv
import json
from pathlib import Path
import struct

from checkpoint_main_map import regular_file
from find_game_files import known_file
from survey_prologues import executable_segments, scan_local_samples
from survey_runtime_entries import survey, ROOT, REVISION

MAX_FILE_BYTES = 64 * 1024 * 1024
FIELDS = ('module', 'guest_address', 'evidence', 'direct_jal_word_hits',
          'distinct_source_modules', 'source_modules', 'review_status')


def jal_words(data: bytes, first: int, last: int, guest_bias: int):
    """Yield (guest instruction PC, decoded JAL target); no reachability claim."""
    if first < 0 or last > len(data) or first > last:
        raise ValueError('Invalid JAL scan window')
    first = (first + 3) & ~3
    for offset in range(first, last - 3, 4):
        word = struct.unpack_from('<I', data, offset)[0]
        if word >> 26 != 3:
            continue
        pc = guest_bias + offset
        if not 0 <= pc < 0x100000000:
            raise ValueError('JAL source outside 32-bit guest address space')
        target = (((pc + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2)) & 0xFFFFFFFF
        yield pc, target


def corroborate(game_dir: Path, revision: Path = REVISION) -> tuple[dict, list[dict]]:
    # scan_local_samples and survey independently verify hashes/headers for all 4.
    seed_report, seeds = scan_local_samples(game_dir, revision)
    evidence, _ = survey(game_dir, revision)
    expected = {'main', 'ovl00', 'ovl01', 'ovl02'}
    candidates: dict[str, dict[int, set[str]]] = {m: {} for m in expected}
    for seed in seeds:
        module, addr = seed['module'], int(seed['guest_address'], 16)
        if module not in candidates:
            raise ValueError('Unexpected Japanese module in seed report')
        candidates[module].setdefault(addr, set()).add('stack_prologue_pattern')

    for module in evidence['modules']:
        name = module['file'].split('.')[0].lower().replace('_', '')
        if name not in candidates:
            raise ValueError('Unexpected module in header survey')
        address = int(module['load_base'], 16) + 0x80
        candidates[name].setdefault(address, set()).add('header_prefix_entry_candidate')
        for ctor in module['constructor_candidates']:
            if ctor['range_class'] == 'aligned_in_file':
                addr = int(ctor['candidate_address'], 16)
                candidates[name].setdefault(addr, set()).add('constructor_table_pointer_candidate')
    candidates['main'].setdefault(int(evidence['main_elf']['entry'], 16), set()).add(
        'elf_entry_point')

    hits: dict[tuple[str, int], Counter] = defaultdict(Counter)
    scanned: dict[str, int] = {}
    main_hits_from_overlays: Counter = Counter()
    ambiguous_main_to_overlay = 0
    overlay_ranges = []
    for module in evidence['modules']:
        base = int(module['load_base'], 16)
        size = next(x['file_size'] for x in (
            {'file_size': item['size']} for item in json.loads(
                regular_file(revision, 1024 * 1024).read_text(encoding='utf-8'))['overlays']
            if item['file'] == module['file']))
        overlay_ranges.append((base, base + size))

    for source_module in ('main', 'ovl00', 'ovl01', 'ovl02'):
        if source_module == 'main':
            data = regular_file(known_file(game_dir, 'SLPM_661.01'), MAX_FILE_BYTES).read_bytes()
            areas = executable_segments(data)
        else:
            path = regular_file(known_file(game_dir,
                                f"OVL_{source_module[-2:]}.BIN"), MAX_FILE_BYTES)
            data = path.read_bytes()
            areas = [(0x80, len(data), 0x0060C800)]
        n = 0
        for first, last, bias in areas:
            for pc, target in jal_words(data, first, last, bias):
                n += 1
                if target in candidates['main']:
                    hits[('main', target)][source_module] += 1
                    if source_module != 'main':
                        main_hits_from_overlays[source_module] += 1
                # Guest overlay slots overlap and a call from the main ELF
                # alone cannot identify which overlay will be loaded.
                if source_module == 'main':
                    if any(a <= target < b for a, b in overlay_ranges):
                        ambiguous_main_to_overlay += 1
                elif target in candidates[source_module]:
                    # Contextual guess only: overlays can replace each other
                    # in this exact guest memory range.
                    hits[(source_module, target)][source_module] += 1
        scanned[source_module] = n

    output_rows: list[dict] = []
    counts = {}
    for module in ('main', 'ovl00', 'ovl01', 'ovl02'):
        corroborated = 0
        for address, labels in sorted(candidates[module].items()):
            source_counts = hits.get((module, address), Counter())
            count = sum(source_counts.values())
            if count:
                corroborated += 1
            output_rows.append({
                'module': module, 'guest_address': f'0x{address:08X}',
                'evidence': '+'.join(sorted(labels)),
                'direct_jal_word_hits': count,
                'distinct_source_modules': len(source_counts),
                'source_modules': ';'.join(sorted(source_counts)),
                'review_status': 'CANDIDATE_NOT_VERIFIED',
            })
        counts[module] = {
            'candidate_addresses': len(candidates[module]),
            'with_syntactic_jal_references': corroborated,
            'without_syntactic_jal_references': len(candidates[module]) - corroborated
        }
    output_rows.sort(key=lambda x: (
        -x['direct_jal_word_hits'],
        -int('constructor_table_pointer_candidate' in x['evidence']),
        x['module'], x['guest_address']))
    metadata = {
        'schema_version': 1,
        'source_identity': 'four exact Japanese SLPM_661.01 sample SHA-256 fingerprints',
        'scope': 'review-candidate ranking, not a validated call graph',
        'underlying_prologue_seeds': seed_report['total_strong_review_seeds'],
        'direct_jal_opcode_words_scanned': scanned,
        'candidate_counts': counts,
        'ambiguous_main_to_overlaid_address_slot_words': ambiguous_main_to_overlay,
        'main_candidate_hits_from_overlays': dict(sorted(main_hits_from_overlays.items())),
        'candidate_total': len(output_rows),
        'verified_function_count': 0,
        'function_boundaries_validated': False,
        'recompiler_run': False,
        'native_jp_boot_tested': False,
        'caveats': [
            'A raw word with JAL opcode may be data, dead code, or a nonexecuted instruction.',
            'An apparent call to a prologue is only corroborating evidence for manual review.',
            'Overlays share overlapping guest address ranges; main->overlay targets are unassigned.',
            'Overlay->same-slot hits do not prove the referenced overlay is resident.',
            'No indirect calls, branch reachability, function ends or dynamic code copies are resolved.'
        ]
    }
    return metadata, output_rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('game_dir', type=Path)
    parser.add_argument('--revision', type=Path, default=REVISION)
    parser.add_argument('--out', required=True, type=Path,
                        help='New output directory outside the checkout')
    args = parser.parse_args(argv)
    try:
        report, rows = corroborate(args.game_dir, args.revision)
        output = args.out.expanduser()
        if output.resolve(strict=False).is_relative_to(ROOT.resolve()):
            raise ValueError('Output must be outside the public checkout')
        if output.exists() or output.is_symlink():
            raise ValueError('Refusing to overwrite existing output directory')
        output.mkdir(parents=True, exist_ok=False)
        (output / 'summary.json').write_text(json.dumps(report, indent=2) + '\n',
                                             encoding='utf-8')
        with (output / 'ranked_candidates.csv').open('x', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=FIELDS)
            writer.writeheader()
            writer.writerows(rows)
        print(f"Wrote {len(rows)} ranked but UNVERIFIED candidates to {output}")
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, struct.error) as exc:
        parser.error(str(exc))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
