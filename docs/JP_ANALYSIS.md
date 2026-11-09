# Japanese analysis handoff

**Current handoff:** [main-ELF checkpoint and reproduction instructions](JP_MAIN_CHECKPOINT.md). Earlier main-ELF analysis observations were local and are not checked-in map/validator artifacts; treat them as unverified until reproduced.


## Verified checkpoint — 2026-11-08

The five supplied files reproduce `recomp/dw5xl_jp/known_revision.json` exactly,
including all SHA-256 hashes and parsed metadata. `tools/jp/preflight.py` now
checks those fingerprints and reports remaining development prerequisites.
The 15 synthetic JP tests pass locally with Python 3.12. CI is configured for
Python 3.11 and 3.12 on Linux and Windows; that configuration is not evidence
that those remote jobs have passed.

The broader upstream tooling suite ran 122 tests: 34 failures, 12 errors and
1 skip. Missing CMake and the built recompiler prevent those checks from passing
in this workspace; a full build/test pass is not claimed.

This is still a development scaffold, not a compiled or playable Japanese port.
`main` retains the PAL implementation. Do not run `tools/regen.sh` expecting a
Japanese build: it still targets PAL, including PAL VU/IOP inputs.

## Next step: analyze Japanese functions

Use Ghidra with an R5900 language extension, in a separate local project. The
upstream setup documents `r5900:LE:32:default`; ordinary MIPS analysis alone
cannot establish correct decoding of all Emotion Engine instructions. Ghidra analysis was attempted in an earlier local session, but no reviewed JP function map or validation artifact is preserved on this branch.

1. Run the input-only preflight against the source folder. Keep the exact files
   unchanged and outside Git. The supplied sample set does not include MODULES.
2. Import `SLPM_661.01` as ELF and verify entry `0x00100008` and the segments
   against `known_revision.json`. Use the JP input itself for function analysis;
   do not copy the PAL function map or apply a global address shift.
3. Export to local scratch paths using the existing
   `tools/ghidra_scripts/ExportPS2Functions.java`. Its first script argument is
   the output TOML and its second is the CSV. Review the generated stubs before
   copying any configuration into the JP profile. Keep raw exports local while
   reviewing code/data separation, jump tables, discontiguous functions and
   indirect calls. Do not overwrite the hand-maintained main profile.
4. Import each overlay separately as raw R5900 little-endian data at
   `0x0060C800`, including its header (file offset zero). Mark the header as data.
   The candidate code offset `0x80` is not yet established as the correct code
   boundary. Verify code and constructor ranges before producing each map.
5. Once a reviewed map exists, use the upstream boundary validator, supplying
   the exact corresponding Japanese binary and profile. Example for main:

   ```sh
   python tools/debug/validate_function_map.py --profile recomp/dw5xl_jp/main.toml --binary game/dw5xl_jp/SLPM_661.01 --csv recomp/dw5xl_jp/ghidra_functions.code.csv --out notes/issues/tests/out/jp-main-map
   ```

   Follow `tools/debug/validate_function_map.md` for selected passes and generated
   output auditing. A present CSV is not proof of correct boundaries. The
   preflight deliberately continues to report validation work when maps exist.

## Gates after function analysis

- Verify overlay code boundaries, constructors and module dispatch from JP code.
- Identify JP equivalents of hardcoded PAL hooks in `app/src`; no relocation guesses.
- Inventory the full extracted disc and verify IOP modules and VU program inputs.
- Implement explicit JP generation/build selection with isolated output folders.
- Compile, boot and compare startup, menus and gameplay against the Japanese game.

The current preflight does not implement these steps or bypass them. Its build
readiness remains false until real validation and runtime integration justify
replacing the explicit gates. Hash matching only establishes sample identity.
