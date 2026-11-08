#!/usr/bin/env python3
"""Verify local JP samples and report development blockers; never launch codegen.

Exit 0 means build ready (currently never), or matching sample fingerprints when
--inputs-only is explicitly selected. Exit 1 means incomplete/mismatched inputs
or unresolved development work. Exit 2 means invalid command/configuration.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from inspect_samples import file_hash

ROOT = Path(__file__).resolve().parents[2]
REVISION = ROOT / 'recomp/dw5xl_jp/known_revision.json'


def verify_inputs(directory: Path, revision: dict) -> list[dict]:
    if not directory.is_dir():
        raise ValueError('Pass an existing extracted game directory, not an ISO file')
    if revision.get('schema_version') != 1:
        raise ValueError('Unsupported revision schema')
    records = [revision['system_cnf'], revision['elf'], *revision['overlays']]
    lookup: dict[str, list[Path]] = {}
    for path in directory.iterdir():
        lookup.setdefault(path.name.upper(), []).append(path)
    results = []
    for expected in records:
        name = expected['file']
        result = {'file': name, 'expected_size': expected['size'],
                  'expected_sha256': expected['sha256']}
        candidates = lookup.get(name.upper(), [])
        if not candidates:
            result['status'] = 'missing'
        elif len(candidates) != 1:
            result['status'] = 'ambiguous'
        else:
            path = candidates[0]
            if path.is_symlink() or not path.is_file():
                result['status'] = 'not-regular-file'
            else:
                try:
                    result['actual_size'] = path.stat().st_size
                    result['actual_sha256'] = file_hash(path)
                    result['status'] = ('verified' if result['actual_size'] == expected['size']
                                        and result['actual_sha256'] == expected['sha256'] else 'mismatch')
                except OSError as exc:
                    result.update(status='unreadable', error=str(exc))
        results.append(result)
    return results


def development_blockers(root: Path) -> list[str]:
    blockers = []
    profile = root / 'recomp/dw5xl_jp'
    for name, folder in [('main', profile), *[(f'ovl{i:02}', profile / 'overlays' / f'ovl{i:02}') for i in range(3)]]:
        path = folder / 'ghidra_functions.code.csv'
        if not path.is_file() or path.stat().st_size == 0:
            blockers.append(f'{name}: Japanese function map missing; analyze the JP binary in Ghidra.')
        else:
            blockers.append(f'{name}: function map present; boundary and generated-output validation still required.')
    # These remain explicit gates until actual evidence and integration replace them.
    # File existence or verified sample hashes must never silently enable PAL hooks.
    blockers.extend([
        'Overlay code offsets and function boundaries remain provisional.',
        'JP runtime hooks, module switching, VU/IOP inputs and build selection are not integrated.',
        'The complete JP disc and MODULES hashes have not been verified.',
        'No Japanese native boot or gameplay validation has been completed.',
    ])
    return blockers


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path, help='Extracted folder containing the five sample files')
    parser.add_argument('--revision', type=Path, default=REVISION, help='Fingerprint baseline (default: committed JP revision)')
    parser.add_argument('--inputs-only', action='store_true', help='Exit successfully if all baseline sample hashes match; does not claim build readiness')
    parser.add_argument('--json', action='store_true', help='Print a metadata-only JSON report to stdout')
    args = parser.parse_args(argv)
    try:
        revision = json.loads(args.revision.read_text(encoding='utf-8'))
        files = verify_inputs(args.directory, revision)
        blockers = development_blockers(ROOT)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.error(str(exc))
    verified = bool(files) and all(x['status'] == 'verified' for x in files)
    report = dict(schema_version=1, scope='sample fingerprints only; not a full-disc verification',
                  inputs_verified=verified, build_ready=False, files=files, blockers=blockers)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for record in files:
            print(f"{record['status'].upper()}: {record['file']}")
        print('Sample fingerprints: ' + ('VERIFIED' if verified else 'FAILED'))
        print('JP native build: BLOCKED (not playable)')
        for blocker in blockers:
            print(f'  - {blocker}')
    return 0 if args.inputs_only and verified else 1


if __name__ == '__main__':
    raise SystemExit(main())
