# DW5XL Recomp — Japanese Version (SLPM_661.01)

**Status: verified binary fingerprints and development scaffolding only; NOT a playable Japanese port.**

This development branch adapts [TheSlackbringer/dw5xl-recomp](https://github.com/TheSlackbringer/dw5xl-recomp), a GPL-3.0 native PS2 recompilation project, for **Shin Sangoku Musou 4 Moushouden** (真・三國無双4 猛将伝). The existing PAL port is preserved on the original `main` branch.

## Verified Japanese samples (2026-11-08)

The project maintainer supplied the boot executable `SLPM_661.01`, `SYSTEM.CNF` and `OVL_00.BIN` through `OVL_02.BIN`. Their SHA-256 fingerprints, sizes, ELF segment layout, and overlay headers are recorded at [`recomp/dw5xl_jp/known_revision.json`](recomp/dw5xl_jp/known_revision.json). This is **not** a complete-disc manifest, and no game bytes have been committed.

- `SYSTEM.CNF` confirms `SLPM_661.01` and `VMODE = NTSC`.
- The executable is a 32-bit little-endian MIPS ELF; its entry point is `0x00100008`.
- Three verified overlay headers have IDs 1, 2 and 3, all reporting a load base of `0x0060C800` (the PAL branch uses `0x0061A800`).
- The Japanese ELF and overlay source metadata are structurally readable, but **function boundaries, VU programs, runtime hooks and compilation have not been validated**.

## Development files

- [`tools/jp/inspect_samples.py`](tools/jp/inspect_samples.py): inspect individual JP ELF/overlay samples, no ISO required.
- [`tools/jp/inspect_disc.py`](tools/jp/inspect_disc.py): inspect an extracted *complete* Japanese PS2 disc to produce a hash-only inventory.
- [`tools/jp/scaffold_profile.py`](tools/jp/scaffold_profile.py): safely create a main PS2Recomp template from the inventory.
- [`recomp/dw5xl_jp/main.toml`](recomp/dw5xl_jp/main.toml): main JP ELF candidate configuration, awaiting a JP Ghidra map.
- [`recomp/dw5xl_jp/overlays/`](recomp/dw5xl_jp/overlays): three candidate JP overlay configurations. The `raw_code_offset = 0x80` is **not yet verified for JP**.
- [`tools/jp/checkpoint_overlay_maps.py`](tools/jp/checkpoint_overlay_maps.py): check the three JP overlay samples and hash-lock independently reviewed function CSVs for validation. See [overlay handoff](docs/JP_OVERLAY_CHECKPOINT.md).
- [`docs/JP_PORT_PLAN.md`](docs/JP_PORT_PLAN.md): remaining reverse engineering and native integration milestones.
- [`docs/index.html`](docs/index.html): static GitHub Pages landing page (requires one-time Pages setting in GitHub).

## Preserve main-ELF analysis checkpoints

Use [`tools/jp/checkpoint_main_map.py`](tools/jp/checkpoint_main_map.py) to hash-lock a reviewed Japanese function CSV and compare it with its raw Ghidra export. The tool generates a local manifest for the existing validator; **it does not certify functions or make this port playable**. See [the checkpoint handoff](docs/JP_MAIN_CHECKPOINT.md). Eight synthetic unit tests cover the tool.

## Japanese overlay map checkpointing

The new overlay checkpoint tool verifies binary/header identities, Japanese load bases and candidate map bounds for OVL_00/01/02. **It does not establish that `raw_code_offset = 0x80` or any function boundary is correct.** Review the overlays in Ghidra first; then follow [the overlay validation instructions](docs/JP_OVERLAY_CHECKPOINT.md). The 12 new tests use synthetic input only.

## Check your inputs before development

Python 3.11 or newer; no extra Python packages are required:

```powershell
python tools/jp/preflight.py "C:\Games\DW5XL-JP" --inputs-only
python tools/jp/preflight.py "C:\Games\DW5XL-JP" --json
```

The first command succeeds only when every sample's size and SHA-256 matches
`known_revision.json`. It accepts upper/lowercase filenames and rejects missing,
changed, ambiguous or symlinked inputs. The second command reports remaining
porting work and currently exits **1** because the native JP build is blocked.
Neither command runs recompilation or validates a complete disc. `--revision`
selects a different fingerprint baseline; success then applies only to that baseline.

See [the JP analysis handoff](docs/JP_ANALYSIS.md) for the next development step.

## Reproduce the metadata locally

From your own Japanese game files (nothing is uploaded by this command):

```powershell
python tools/jp/inspect_samples.py --system "C:\Games\DW5XL-JP\SYSTEM.CNF" --elf "C:\Games\DW5XL-JP\SLPM_661.01" --overlay "C:\Games\DW5XL-JP\OVL_00.BIN" --overlay "C:\Games\DW5XL-JP\OVL_01.BIN" --overlay "C:\Games\DW5XL-JP\OVL_02.BIN" --json jp-samples.json
python -m unittest discover -s tools/jp -p "test_*.py" -v
```

If you have the extracted **entire ISO**, use `python tools/jp/inspect_disc.py "C:\Games\DW5XL-JP" --json jp-inventory.json` to inspect the `MODULES` folder as well. Hashes alone do not establish cross-version function compatibility.

## Safety, authorship and licensing

Preserve upstream GPL-3.0 `LICENSE`, `THIRD_PARTY.md`, and vendored dependency notices. **Never publish any game executable, disc image, sound/movie asset, IRX module, original machine-code blob, or game-derived generated C++**. Developer tools and non-copyrightable format metadata are published; each user supplies their own legal game copy to generate game code locally. Not affiliated with or endorsed by Koei Tecmo.
