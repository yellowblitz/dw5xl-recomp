#!/usr/bin/env python3
"""Inventory a locally extracted, personally owned JP DW5XL disc.

Only relative paths, file sizes, and cryptographic hashes are emitted. The
utility neither exports copyrighted bytes nor makes claims about compatibility.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

BOOT_PATTERN = re.compile(r"^\s*BOOT2?\s*=\s*cdrom0:\\?/?([^;\s]+)(?:;\d+)?", re.I | re.M)
SYSTEM_NAME = "SYSTEM.CNF"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_boot_filename(system_text: str) -> str:
    match = BOOT_PATTERN.search(system_text)
    if not match:
        raise ValueError("SYSTEM.CNF has no recognizable BOOT/BOOT2 cdrom0 entry")
    name = match.group(1).replace("\\", "/").rsplit("/", 1)[-1]
    if name in ("", ".", "..") or "/" in name:
        raise ValueError("Invalid boot executable name")
    return name.upper()


def inventory_disc(root: Path, hash_all: bool = False) -> dict:
    root = root.expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Pass an extracted disc folder, not a .iso file. Extract your own ISO first.")
    # Enumerate regular files only; never follow symlinks into unrelated folders.
    files = sorted((path for path in root.rglob("*") if path.is_file() and not path.is_symlink()),
                   key=lambda p: p.relative_to(root).as_posix().upper())
    lookup = {path.relative_to(root).as_posix().upper(): path for path in files}
    system = lookup.get(SYSTEM_NAME)
    if system is None:
        raise ValueError("SYSTEM.CNF not found in the extracted disc root")
    boot = read_boot_filename(system.read_text(encoding="ascii", errors="replace"))
    executable = lookup.get(boot)
    if executable is None:
        raise ValueError(f"Boot executable '{boot}' named in SYSTEM.CNF is missing")
    if not re.fullmatch(r"(?:SLPM|SLPS|SLES|SLUS|SCPS|SCES|SCUS|SCAJ|SCKA|SCED|SLED)_[0-9]{3}\.[0-9]{2}", boot):
        raise ValueError(f"Unexpected PS2 boot filename: {boot}")
    if not (boot.startswith("SLPM_") or boot.startswith("SLPS_")):
        raise ValueError(f"Disc boots {boot}; this inspector expects a Japanese SLPM/SLPS release")
    records = []
    for name, path in sorted(lookup.items()):
        chosen = name in (SYSTEM_NAME, boot) or name.startswith("MODULES/") or re.fullmatch(r"OVL_[0-9A-F]+\.BIN", name)
        if not chosen and not hash_all:
            continue
        stat = path.stat()
        records.append({
            "path": path.relative_to(root).as_posix(),
            "size": stat.st_size,
            "sha256": sha256_file(path),
            "kind": ("boot" if name == boot else "overlay" if re.fullmatch(r"OVL_[0-9A-F]+\.BIN", name)
                     else "iop-module" if name.startswith("MODULES/") else "other"),
        })
    return {
        "schema_version": 1,
        "project": "dw5xl-recomp Japanese port inventory",
        "boot_executable": boot,
        "disc_region": "JP (disc boot ID; precise revision unverified)",
        "file_count_on_disc": len(files),
        "inventory_scope": "all files" if hash_all else "boot, SYSTEM.CNF, overlays and MODULES",
        "files": records,
        "note": "Not a compatibility claim. No copyrighted game bytes included.",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("extracted_disc", type=Path, help="Folder extracted from your personally owned PS2 disc")
    parser.add_argument("--all", action="store_true", help="Hash every disc file (can take longer)")
    parser.add_argument("--json", type=Path, help="Save hash-only JSON inventory to this path")
    args = parser.parse_args(argv)
    try:
        report = inventory_disc(args.extracted_disc, hash_all=args.all)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    output = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(output, encoding="utf-8")
        print(f"Saved: {args.json}")
    else:
        print(output, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
