#!/usr/bin/env python3
"""Hash-locked local checkpoint for the Japanese DW5XL main-ELF function map.

No copyrighted game bytes or function CSV contents are copied. Structural
CSV checks and input identities do not establish that the port works.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
import hashlib
import io
import json
from pathlib import Path
import re
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_REVISION = ROOT / 'recomp/dw5xl_jp/known_revision.json'
DEFAULT_PROFILE = ROOT / 'recomp/dw5xl_jp/main.toml'
HEX = re.compile(r'0[xX][0-9a-fA-F]+\Z')
DECIMAL = re.compile(r'[0-9]+\Z')


def regular_file(path: Path, max_size: int | None = None) -> Path:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f'Expected regular non-symlink file: {path}')
    if max_size is not None and path.stat().st_size > max_size:
        raise ValueError(f'Input file exceeds size limit: {path}')
    return path.resolve(strict=True)


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def snapshot(path: Path) -> dict:
    return {'path': str(path), 'sha256': digest(path)}


def csv_rows(path: Path) -> list[tuple[str, int, int, int]]:
    data = regular_file(path, 32 * 1024 * 1024).read_bytes()
    try:
        r = csv.reader(io.StringIO(data.decode('utf-8-sig'), newline=''), strict=True)
        if next(r, None) != ['Name', 'Start', 'End', 'Size']:
            raise ValueError('Expected Name,Start,End,Size header')
        rows = []
        for line, fields in enumerate(r, 2):
            if not fields:
                continue
            if (len(fields) != 4 or not fields[0].strip() or
                    not HEX.fullmatch(fields[1].strip()) or
                    not HEX.fullmatch(fields[2].strip()) or
                    not DECIMAL.fullmatch(fields[3].strip())):
                raise ValueError(f'Malformed CSV at line {line}')
            a, b, n = int(fields[1], 16), int(fields[2], 16), int(fields[3])
            if a % 4 or b % 4 or b <= a or b > 0x100000000 or n <= 0 or n > 0x100000000:
                raise ValueError(f'Invalid address/size at line {line}')
            rows.append((fields[0], a, b, n))
            if len(rows) > 100_000:
                raise ValueError('Too many rows')
    except (UnicodeError, csv.Error) as exc:
        raise ValueError('Invalid UTF-8 or CSV') from exc
    if not rows:
        raise ValueError('Empty function CSV')
    return rows


def stats(rows: list[tuple[str, int, int, int]]) -> dict:
    ends: dict[int, set[int]] = {}
    for _, start, end, _ in rows:
        ends.setdefault(start, set()).add(end)
    return {'rows': len(rows), 'unique_starts': len(ends),
            'duplicate_rows': sum(n - 1 for n in Counter(rows).values() if n > 1),
            'conflicting_end_starts': sum(len(v) > 1 for v in ends.values())}


def checkpoint(binary: Path, cleaned: Path, raw: Path | None, profile: Path,
               revision: Path, out: Path) -> dict:
    binary = regular_file(binary)
    cleaned = regular_file(cleaned, 32 * 1024 * 1024)
    raw = regular_file(raw, 32 * 1024 * 1024) if raw else None
    profile = regular_file(profile, 1024 * 1024)
    revision = regular_file(revision, 1024 * 1024)
    rev = json.loads(revision.read_text(encoding='utf-8'))
    elf = rev.get('elf')
    boot = rev.get('boot_executable')
    if rev.get('schema_version') != 1 or not isinstance(elf, dict) or not isinstance(boot, str):
        raise ValueError('Invalid JP revision metadata')
    if binary.name.upper() != boot.upper() or elf.get('file', '').upper() != boot.upper():
        raise ValueError('Executable filename differs from JP revision')
    if (not isinstance(elf.get('sha256'), str) or
            not re.fullmatch('[0-9a-f]{64}', elf['sha256']) or
            binary.stat().st_size != elf.get('size') or
            digest(binary) != elf['sha256']):
        raise ValueError('Executable size/SHA-256 mismatch')
    config = tomllib.loads(profile.read_text(encoding='utf-8'))
    general = config.get('general')
    if (not isinstance(general, dict) or general.get('input_format', 'elf') != 'elf'
            or Path(general.get('input', '')).name.upper() != boot.upper()):
        raise ValueError('Profile does not describe JP main ELF')
    clean_rows = csv_rows(cleaned)
    raw_rows = csv_rows(raw) if raw else None
    maps = {'cleaned': snapshot(cleaned)}
    module = {'id': 'main', 'serial': boot, 'format': 'elf',
              'profile': snapshot(profile), 'binary': snapshot(binary), 'maps': maps}
    summary = {'schema_version': 1, 'boot_executable': boot,
               'notice': 'Hashes and CSV structure only; translation and native boot NOT validated.',
               'cleaned_sha256': maps['cleaned']['sha256'],
               'cleaned': stats(clean_rows), 'validator_status': 'NOT_RUN'}
    if raw:
        maps['raw'] = snapshot(raw)
        module['baseline_map'] = 'raw'
        summary['raw_sha256'] = maps['raw']['sha256']
        summary['raw'] = stats(raw_rows)
        summary['delta'] = {
            'removed_rows': sum((Counter(raw_rows) - Counter(clean_rows)).values()),
            'added_or_modified_rows': sum((Counter(clean_rows) - Counter(raw_rows)).values()),
            'removed_unique_starts': len({r[1] for r in raw_rows} - {r[1] for r in clean_rows}),
            'added_unique_starts': len({r[1] for r in clean_rows} - {r[1] for r in raw_rows}),
            'note': 'Differences are informational; manually review aliases and shared tails.'}
    out = out.expanduser()
    if out.resolve(strict=False).is_relative_to(ROOT.resolve()):
        raise ValueError('Choose an output directory outside the repository')
    if out.exists() or out.is_symlink():
        raise ValueError('Output already exists; choose a new directory')
    out.mkdir(parents=True, exist_ok=False)
    (out / 'manifest.json').write_text(json.dumps({'schema_version': 1,
        'modules': [module]}, indent=2) + '\n', encoding='utf-8')
    (out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
    return summary


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--cleaned-csv', type=Path, required=True)
    p.add_argument('--raw-csv', type=Path)
    p.add_argument('--profile', type=Path, default=DEFAULT_PROFILE)
    p.add_argument('--revision', type=Path, default=DEFAULT_REVISION)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args(argv)
    try:
        result = checkpoint(a.binary, a.cleaned_csv, a.raw_csv, a.profile, a.revision, a.out)
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        p.error(str(exc))
    print(f"Checkpoint: {result['cleaned']['rows']} rows; validator NOT RUN.")
    print(f'Next: python tools/debug/validate_function_map.py --manifest "{a.out / "manifest.json"}" --module main --map cleaned --out "{a.out}-validation"')
    return 0


if __name__ == '__main__':
    sys.exit(main())
