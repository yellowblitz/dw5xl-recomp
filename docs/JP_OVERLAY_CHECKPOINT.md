# Japanese overlay checkpoint and Ghidra handoff

**Status: metadata tooling only. Not compiled or playable.** This guide covers the three known Japanese overlays for SLPM_661.01: OVL_00.BIN, OVL_01.BIN and OVL_02.BIN.

The recorded header metadata in recomp/dw5xl_jp/known_revision.json identifies module IDs 1/2/3 and load base 0x0060C800, unlike the PAL overlay base. **The raw_code_offset = 0x80 values in JP profiles remain provisional.** Hash/header identity is not proof of an executable code boundary.

## Preliminary constructor-pointer review

Before creating overlay function maps, run [`inspect_constructors.py`](../tools/jp/inspect_constructors.py) against the exact Japanese sample files to examine possible header-referenced constructor pointers. The header reports a 14-word candidate range for OVL_00 and empty ranges for OVL_01 and OVL_02, assuming exclusive ends. **Neither the pointer-table format nor any address is verified as a callable function.** See [JP_CONSTRUCTOR_REVIEW.md](JP_CONSTRUCTOR_REVIEW.md) for the local command and required Ghidra cross-checks.

## 1. Independently analyze the overlays

Use your own legal Japanese disc files locally, outside this repository. Run:

    python tools/jp/preflight.py "C:\JP" --inputs-only

In Ghidra with an appropriate R5900 language extension, import each overlay **separately** as raw little-endian data at guest base **0x0060C800**, including file offset zero. Mark the MWo3 header as data and independently identify the code start, constructor table, code/data boundaries and any shared function tails. Do not copy PAL addresses or assume that 0x80 is correct merely because it is present in the TOMLs.

Keep untouched Ghidra function exports as a raw baseline. Place independently reviewed Name,Start,End,Size function CSVs in a separate local folder named ovl00.csv, ovl01.csv and ovl02.csv. Verify the real code offsets before updating the JP profiles.

## 2. Create a SHA-256-locked local checkpoint

After all three function maps exist, from the repository root:

    python tools/jp/checkpoint_overlay_maps.py --game-dir "C:\JP" --maps-dir "C:\JP-analysis\reviewed-overlays" --raw-maps-dir "C:\JP-analysis\raw-overlays" --out "C:\JP-analysis\overlay-checkpoint-01"

The raw-maps-dir argument is optional. The tool checks the exact known sample hashes and headers, compares the module profiles and rejects CSV rows outside their **candidate** file-backed code ranges. It creates manifest.json (for the existing validator) and summary.json (metadata only) in a *new* directory outside Git.

The tool does **not** run Ghidra, prove function boundaries, establish whether 0x80 is correct, run recompilation, or produce a native boot. Local paths in the generated manifest must not be published.

## 3. Run the existing validator for each module

    python tools/debug/validate_function_map.py --manifest "C:\JP-analysis\overlay-checkpoint-01\manifest.json" --module dw5xl_jp_ovl00 --map cleaned --out "C:\JP-analysis\validation-ovl00"
    python tools/debug/validate_function_map.py --manifest "C:\JP-analysis\overlay-checkpoint-01\manifest.json" --module dw5xl_jp_ovl01 --map cleaned --out "C:\JP-analysis\validation-ovl01"
    python tools/debug/validate_function_map.py --manifest "C:\JP-analysis\overlay-checkpoint-01\manifest.json" --module dw5xl_jp_ovl02 --map cleaned --out "C:\JP-analysis\validation-ovl02"

Review all findings and unknowns. A clean validator report is not proof that the overlays execute correctly. See docs/JP_MAIN_CHECKPOINT.md and docs/JP_PORT_PLAN.md for other prerequisites.

Never commit original game binaries or assets, extracted code, raw function exports, generated translated game C++, or local absolute-path manifests.
