#!/usr/bin/env python3
"""Hash-lock Japanese overlay function maps for the existing read-only validator.

This is a local metadata/checkpoint operation, NOT code boundary validation,
PS2Recomp translation, or evidence that the Japanese port is playable.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import re
import tomllib

from checkpoint_main_map import csv_rows, regular_file, snapshot, stats
from inspect_samples import inspect_overlay

ROOT = Path(__file__).resolve().parents[2]
REVISION = ROOT / 'recomp/dw5xl_jp/known_revision.json'
PROFILE_ROOT = ROOT / 'recomp/dw5xl_jp/overlays'
OVERLAY_NAME = re.compile(r'OVL_([0-9A-F]{2})\.BIN\Z')
IDENTITY_FIELDS = ('file', 'size', 'sha256', 'module_id', 'load_base',
                   'header_field_0c', 'header_field_10', 'bss_size',
                   'constructor_start', 'constructor_end')


def inspect_profiles(game_dir: Path, maps_dir: Path, raw_maps_dir: Path | None,
                     revision: Path, profile_root: Path) -> tuple[list[dict], list[dict]]:
    """Check every known overlay before writing any files; do not infer code validity."""
    if not game_dir.is_dir() or not maps_dir.is_dir():
        raise ValueError('Existing Japanese overlay folder and cleaned-map folder required')
    if raw_maps_dir is not None and not raw_maps_dir.is_dir():
        raise ValueError('Existing raw-map folder required')
    rev = json.loads(regular_file(revision, 1024 * 1024).read_text(encoding='utf-8'))
    records = rev.get('overlays')
    if rev.get('schema_version') != 1 or not isinstance(records, list) or len(records) != 3:
        raise ValueError('Expected the three-overlay Japanese sample revision')
    ids: set[str] = set()
    modules: list[dict] = []
    findings: list[dict] = []
    for expected in records:
        if not isinstance(expected, dict) or not isinstance(expected.get('file'), str):
            raise ValueError('Invalid overlay revision record')
        match = OVERLAY_NAME.fullmatch(expected['file'])
        if match is None:
            raise ValueError('Unsafe or invalid overlay filename in revision')
        number = match.group(1).lower()
        if number not in ('00', '01', '02') or number in ids:
            raise ValueError('Unexpected or duplicate Japanese overlay ID')
        ids.add(number)
        binary = regular_file(game_dir / expected['file'])
        actual = inspect_overlay(binary)
        if any(actual.get(field) != expected.get(field) for field in IDENTITY_FIELDS):
            raise ValueError(f'{expected["file"]}: header, size or SHA-256 mismatch')

        stem = f'ovl{number}'
        profile = regular_file(profile_root / stem / f'{stem}.toml', 1024 * 1024)
        try:
            general = tomllib.loads(profile.read_text(encoding='utf-8'))['general']
        except KeyError as exc:
            raise ValueError(f'{stem}: missing [general] profile section') from exc
        base = int(expected['load_base'], 16)
        code_offset = general.get('raw_code_offset')
        if (general.get('input_format') != 'raw'
                or Path(general.get('input', '')).name.upper() != expected['file']
                or general.get('module_id') != f'dw5xl_jp_{stem}'
                or type(general.get('raw_base')) is not int or general['raw_base'] != base
                or type(code_offset) is not int or code_offset < 0x80
                or code_offset >= actual['size'] or code_offset % 4):
            raise ValueError(f'{stem}: profile disagrees with JP overlay metadata or has unsafe raw mapping')
        if base + actual['size'] > 0x100000000:
            raise ValueError(f'{stem}: invalid raw mapping address range')
        cleaned = regular_file(maps_dir / f'{stem}.csv', 32 * 1024 * 1024)
        clean_rows = csv_rows(cleaned)
        first, limit = base + code_offset, base + actual['size']
        for name, start, end, size in clean_rows:
            if not (first <= start < end <= limit):
                raise ValueError(f'{stem}: function row {name!r} lies outside the candidate file-backed code range')
        maps = {'cleaned': snapshot(cleaned)}
        module = {'id': general['module_id'], 'serial': rev.get('boot_executable'),
                  'format': 'raw', 'raw_base': base, 'raw_code_offset': code_offset,
                  'profile': snapshot(profile), 'binary': snapshot(binary), 'maps': maps}
        entry = {'module_id': module['id'], 'file': actual['file'],
                 'binary_sha256': actual['sha256'], 'base': actual['load_base'],
                 'candidate_code_offset': f'0x{code_offset:X}',
                 'code_offset_verified': False, 'function_bounds_verified': False,
                 'cleaned': stats(clean_rows), 'cleaned_sha256': maps['cleaned']['sha256']}
        if raw_maps_dir is not None:
            raw = regular_file(raw_maps_dir / f'{stem}.csv', 32 * 1024 * 1024)
            raw_rows = csv_rows(raw)
            # An uncorrected raw export may include suspect rows; don't assume it is valid code.
            maps['raw'] = snapshot(raw)
            module['baseline_map'] = 'raw'
            entry['raw_sha256'] = maps['raw']['sha256']
            entry['raw'] = stats(raw_rows)
            entry['delta'] = {
                'removed_rows': sum((Counter(raw_rows) - Counter(clean_rows)).values()),
                'added_or_modified_rows': sum((Counter(clean_rows) - Counter(raw_rows)).values()),
                'note': 'Informational only; raw map may contain header/data false positives.'}
        modules.append(module)
        findings.append(entry)
    if ids != {'00', '01', '02'}:
        raise ValueError('JP overlay baseline must contain OVL_00, OVL_01, OVL_02')
    return modules, findings


def checkpoint(game_dir: Path, maps_dir: Path, out: Path,
               raw_maps_dir: Path | None = None, revision: Path = REVISION,
               profile_root: Path = PROFILE_ROOT) -> dict:
    modules, findings = inspect_profiles(game_dir, maps_dir, raw_maps_dir,
                                         revision, profile_root)
    report = {'schema_version': 1, 'scope': 'three known Japanese sample overlays',
              'overlay_files_verified': len(modules),
              'validator_status': 'NOT_RUN', 'native_jp_build_ready': False,
              'notes': ['SHA-256 and header identity established, not code correctness.',
                        'raw_code_offset remains provisional until independently reviewed in Ghidra.',
                        'Any CSV row can be misclassified code; run the existing boundary validator.',
                        'A complete disc, IOP and VU inputs, native boot and gameplay remain unverified.'],
              'modules': findings}
    out = out.expanduser()
    if out.resolve(strict=False).is_relative_to(ROOT.resolve()):
        raise ValueError('Choose a scratch output directory outside the repository')
    if out.exists() or out.is_symlink():
        raise ValueError('Output already exists; use a new directory')
    out.mkdir(parents=True, exist_ok=False)
    (out / 'manifest.json').write_text(json.dumps({'schema_version': 1,
        'modules': modules}, indent=2) + '\n', encoding='utf-8')
    (out / 'summary.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    return report


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--game-dir', required=True, type=Path,
                   help='Folder containing your private JP OVL_00..02.BIN files')
    p.add_argument('--maps-dir', required=True, type=Path,
                   help='Folder with three reviewed ovl00.csv, ovl01.csv, ovl02.csv maps')
    p.add_argument('--raw-maps-dir', type=Path,
                   help='Optional folder with corresponding untouched Ghidra CSV exports')
    p.add_argument('--revision', type=Path, default=REVISION)
    p.add_argument('--profile-root', type=Path, default=PROFILE_ROOT)
    p.add_argument('--out', required=True, type=Path)
    a = p.parse_args(argv)
    try:
        result = checkpoint(a.game_dir, a.maps_dir, a.out, a.raw_maps_dir,
                            a.revision, a.profile_root)
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        p.error(str(exc))
    print(f"Checkpointed {result['overlay_files_verified']} overlays. Code offsets and functions UNVERIFIED.")
    for entry in result['modules']:
        stem = entry['module_id'][-5:]
        print(f'Next {stem}: python tools/debug/validate_function_map.py '
              f'--manifest "{a.out / "manifest.json"}" '
              f'--module {entry["module_id"]} --map cleaned --out "{a.out}-{stem}-validation"')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
