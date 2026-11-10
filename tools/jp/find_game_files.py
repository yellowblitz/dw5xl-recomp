"""Resolve the exact known game-file name with safe, case-insensitive matching.

ISO 9660 filenames are commonly uppercase, while extracted files may be lowercase.
Reject ambiguities and symlinks rather than guessing which binary to analyze.
"""
from __future__ import annotations

from pathlib import Path


def known_file(directory: Path, filename: str) -> Path:
    if (not isinstance(filename, str) or not filename
            or Path(filename).name != filename
            or '/' in filename or '\\' in filename or filename in ('.', '..')):
        raise ValueError('Expected a simple known game filename')
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError(f'Expected a regular existing game-files directory: {directory}')
    matches = [p for p in directory.iterdir() if p.name.casefold() == filename.casefold()]
    if not matches:
        raise ValueError(f'Missing known game file: {filename}')
    if len(matches) != 1:
        raise ValueError(f'Ambiguous case-insensitive game filename: {filename}')
    path = matches[0]
    if path.is_symlink() or not path.is_file():
        raise ValueError(f'Expected a non-symlink regular game file: {path}')
    return path
