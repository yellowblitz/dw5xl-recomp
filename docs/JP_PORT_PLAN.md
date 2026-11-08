# Japanese port engineering plan

## Foundation at upstream commit

Source project: https://github.com/TheSlackbringer/dw5xl-recomp

Examined upstream branch `main` commit `3e19b41146117fc58e7d108e5d5c54b29526b05f` (2026-11-08 session). Prefer a true fork preserving history, not a source ZIP republished as unrelated work.

## Verified sample-file baseline — 2026-11-08

`SYSTEM.CNF` boots `SLPM_661.01`, `VER=1.01`, `VMODE=NTSC`. The supplied ELF is a valid MIPS ELF with entry `0x00100008`. Three Japanese overlays have valid `MWo3` module headers with IDs 1, 2 and 3; all are loaded at `0x0060C800` (compared with the upstream PAL overlay base `0x0061A800`). Refer to `recomp/dw5xl_jp/known_revision.json` for exact file sizes and SHA-256. The complete ISO, IO modules, audio/video data, Ghidra maps and native-code build have not yet been examined. These facts are from supplied game file headers, not a successful boot.

The initial `main.toml` and three overlay TOMLs are placeholders with no function maps. In particular, `raw_code_offset=0x80` is copied as a **candidate** from PAL and must be validated from Japanese disassembly before compilation.

## Known PAL-coupled modules to audit

| Area | Upstream file | Migration action |
|---|---|---|
| Main EE function map | `recomp/dw5xl/ghidra_functions.code.csv` | Generate a Japanese map from Japanese executable analysis |
| Main PS2Recomp profile | `recomp/dw5xl/dw5xl.toml` | New JP profile: addresses, stubs, entry points, patches checked |
| Overlay profiles and hashes | `recomp/dw5xl/overlays/*` | Inspect JP overlays, bases, constructors, hashes and code boundaries |
| Runtime hooks / overlay switching | `app/src/dw5xl_overlays.cpp` | Remap and verify all literal guest addresses; keep PAL behavior intact |
| Disc validation | `app/src/dw5xl_disc_validation.h` | Version-specific identities based on real JP disc, not PAL hashes |
| Installer manifest | `app/setup/disc_manifest.h` | Compute separate JP manifest from owned disc, no game bytes |
| Generation script | `tools/regen.sh` | Add JP target/profile selection; do not overwrite PAL output |
| Setup and code generation | `app/setup/codegen.cpp`, `app/setup/setup_pipeline.cpp`, `app/setup/setup_layout.h` | Make build profiles explicit and separate |
| VU0/VU1 code | `app/setup/vu1lift/vu1_inputs.h` | Identify executable and overlay payloads anew; recompute checksums |
| IOP modules | `app/setup/ioplift/iop_inputs.h` | Compare Japanese IRX hashes and actual load addresses |
| CMake | `app/CMakeLists.txt` | Select compiled modules and avoid PAL-only function-file assumptions |
| Optional DW5 disc | `app/src/dw5xl_load_original.cpp` and disc validation | Later milestone: Japanese original-game Load Original support |

**Pitfall:** Three known PAL overlays and a PAL loader do not guarantee the JP disc has identical overlays, load bases, function addresses, constructor tables or offsets. An unchanged engine feature is not evidence of identical guest-machine-code layout.

## Execution milestones and proof

1. **Input validation:** [Partially verified] Five provided Japanese files; verify the remaining complete extracted ISO and IOP modules, compare disc layout with PAL and identify any additional revisions.
2. **Ghidra function census:** Analyze PS2 EE ELF and all overlays; export function maps with the repository's Ghidra script. Check code segments, indirect branches, code/data classification, and guest-call trampolines. Keep an address comparison spreadsheet or script for ported fixes.
3. **Standalone recompilation:** Validate translator accepts main JP ELF. Compile a test binary with JP code + reused runtime; explicitly disable or gate PAL-specific patches and hooks rather than run them at wrong addresses.
4. **Native boot:** Implement JP module registration, entry, disc I/O, region/language behavior, and overlay switching. Capture deterministic logs for game startup and main menu.
5. **3D and audio:** Re-find VU programs; translate them from Japanese disc inputs; check scene rendering, graphics packets, animations, audio/video, and Japanese text.
6. **Gameplay test matrix:** Main menu, Legend/Musou/Free modes as applicable, battle load, input, pause, exit, cutscenes, save/load. Compare with PCSX2 on the same legal disc.
7. **Separate packaging:** The installer recognizes JP discs by exact hashes and refuses mismatched revisions. Releases contain code/tooling only, not recompiled copyrighted game code or game assets.

## Working agreements

- Region-specific functionality should be selected via explicit profiles; preserve tested PAL functionality.
- All hardcoded guest addresses require proof from Japanese disassembly, not relocation guesses.
- Each issue/commit claims only verified progress; avoid indicating the JP game is playable until it actually boots and passes tests.
- Keep GPL-3.0 copyright notices, license and third-party acknowledgements intact.
- No disc data, ISO extracts, game content or generated machine-code translations in Git.

## Development checkpoint — 2026-11-08

Added an exact five-file verification command and explicit build blockers in
`tools/jp/preflight.py`, with synthetic regression tests. The provided samples
reproduce the committed metadata exactly. See [JP_ANALYSIS.md](JP_ANALYSIS.md)
for the Ghidra handoff and remaining gates. Native compilation and boot remain
unverified; no Japanese function maps have been created.
