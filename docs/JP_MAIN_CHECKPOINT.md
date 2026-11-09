# Japanese main executable: analysis and checkpoint handoff

**Branch:** jp-port | **Game revision:** SLPM_661.01 | **Native JP port:** NOT BUILDABLE OR PLAYABLE

## Historical local analysis versus committed artifacts

The Japanese executable and three overlays have verified sizes and SHA-256
fingerprints in [known_revision.json](../recomp/dw5xl_jp/known_revision.json).
These header/hash facts are not proof of recompilation.

A prior local Ghidra 12.1.4 session with an R5900 extension (2026-11-08)
reportedly found 7,290 functions and about 35,740 executable labels in
the main Japanese ELF. An initial experimental translation was blocked near
address 0x00315E70 by apparent Japanese text/data entries treated as code.
Later, local correction of the candidate map reportedly allowed translation
and reduced boundary-validator errors from 2,355 to zero, with three findings
still needing review. This information describes an earlier session; the
corrected map, validator report, generated C++, and exact three findings are
**not persisted in this repository** and have **not been reproduced in CI**.
Do not treat this historical observation as verified native build progress.

## Reproduce the main-ELF analysis and preserve evidence locally

1. Verify your lawful Japanese input against the exact five-file baseline:

       python tools/jp/preflight.py "C:\JP" --inputs-only

   The baseline is not a complete-disc manifest. Keep game files out of Git.
2. Import SLPM_661.01 in Ghidra using an actual R5900 processor language
   extension. Check ELF entry 0x00100008, loaded segments and section
   classifications. Run the existing script
   tools/ghidra_scripts/ExportPS2Functions.java. Its first script argument
   specifies the output TOML and its second specifies the output CSV.
3. Preserve the untouched Ghidra Name,Start,End,Size CSV as the raw baseline.
   Analyze false code/data positives, jump-table boundaries, and shared
   function tails manually. Save any corrected map as a separate CSV. Do not
   copy PAL function addresses or apply a global relocation guess.
4. Run the new fingerprint-locked checkpoint tool, writing to an entirely
   new local scratch directory **outside the checkout**:

       python tools/jp/checkpoint_main_map.py --binary "C:\JP\SLPM_661.01" --raw-csv "C:\JP-analysis\main-raw.csv" --cleaned-csv "C:\JP-analysis\main-reviewed.csv" --out "C:\JP-analysis\checkpoint-01"

   The tool compares the exact executable SHA-256 and size to the committed
   baseline; verifies CSV structure; and writes summary.json with row counts,
   raw-to-cleaned differences and SHA-256 fingerprints. It creates a
   manifest.json accepted by the upstream function-map validator. It **does
   not** determine which rows are real functions, copy game bytes, run the
   translator, or mark any build as ready.
5. Run boundary/reachability validation using that locked manifest:

       python tools/debug/validate_function_map.py --manifest "C:\JP-analysis\checkpoint-01\manifest.json" --module main --map cleaned --out "C:\JP-analysis\validation-01"

   Read all findings and unknowns in report.md and report.json. A zero-error
   count is not proof of correct instruction decoding, translation, or boot.
   See [the upstream validation guide](../tools/debug/validate_function_map.md)
   for generated-output audits. Use a fresh output directory for every run.

Do not commit original game binaries, overlays, sound or movie files, raw
function-map exports, generated translated game C++, or machine-local
checkpoint manifests containing local paths. Reviewed source tooling,
non-copyrightable metadata and summarized engineering findings are appropriate.

## Next gates

Recover/reproduce the corrected main function map and three remaining findings.
Then independently analyze OVL_00.BIN, OVL_01.BIN and OVL_02.BIN at the actual
JP overlay load base 0x0060C800, verifying headers, constructor ranges,
code/data boundaries and code offsets. Only then implement isolated JP codegen,
JP-specific hooks and runtime selection. PAL main remains unchanged.
