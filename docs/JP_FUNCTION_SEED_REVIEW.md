# Japanese main/overlay MIPS prologue review seeds

**2026-11-09, direct analysis of the four re-supplied game binaries.**

The `SLPM_661.01` main executable and `OVL_00.BIN` through
`OVL_02.BIN` matched the known JP SHA-256 fingerprints. A conservative,
bounded MIPS instruction-pattern scan found these **review candidates**:

| Module | Stack-allocation words | Also save $ra through $sp in the next eight words |
| --- | ---: | ---: |
| main ELF | 5,517 | **5,259** |
| OVL_00 | 1,259 | **1,235** |
| OVL_01 | 813 | **813** |
| OVL_02 | 309 | **308** |
| **Total** | **7,898** | **7,615** |

The scans consider file-backed ELF load regions and candidate overlay payloads
starting at offset `0x80`. An entry is reported when a 32-bit MIPS
`ADDIU $sp,$sp,-n` or `DADDIU $sp,$sp,-n` is followed within eight words
by an `SW $ra,...($sp)` or `SD $ra,...($sp)` encoding.
These are opcode-pattern classes, not extracted instruction listings.

**These numbers are NOT verified function counts.** Real leaf functions may not
allocate stack frames; data/jump tables can contain the same bit patterns;
the scan ignores control flow, dynamic dispatch, discontiguous blocks and
nested/overlapping bodies.

## Reproduce against your private Japanese files

The standalone command uses the full four-file SHA/header identity checks
before inspecting machine-code patterns; it does not upload your source files:

```powershell
python tools/jp/survey_prologues.py "C:\Games\DW5XL-JP" --out "C:\JP-analysis\prologue-seeds-01"
```

It creates a metadata-only `summary.json` and local
`prologue_review_seeds.csv`. The columns are:

- `module`: main, ovl00, ovl01, ovl02
- `guest_address`: candidate starting address, in 32-bit hexadecimal
- `evidence`: short opcode-pattern description, **not code bytes**
- `status`: always `CANDIDATE_NOT_VERIFIED`

Keep the generated files outside the Git checkout; never commit original
binaries, machine-code disassembly, extracted translated functions or
game-derived build output.

## Use in Ghidra

Start with a Japanese R5900 project as described in
[JP_ANALYSIS.md](JP_ANALYSIS.md). Treat the generated CSV as a **candidate
bookmark/review list**, not `Name,Start,End,Size` output for PS2Recomp.

1. Cross-check high-value constructor candidates from
   [JP_REAL_BINARY_ANALYSIS.md](JP_REAL_BINARY_ANALYSIS.md).
2. Investigate the 0x80 code-start signature and the overlay module loader.
3. Review prologue candidates against function references and R5900 control
   flow, including delay slots, shared tails, code copies and jump tables.
   Watch for data being incorrectly disassembled as code, especially near
   the earlier reported main ELF analysis obstruction at `0x00315E70`.
4. Export a genuinely reviewed function map using the existing Ghidra
   `ExportPS2Functions.java` exporter. Do not invent Ends or Sizes for
   the seeds.
5. Hash-lock the reviewed main map with
   [JP_MAIN_CHECKPOINT.md](JP_MAIN_CHECKPOINT.md), overlay maps with
   [JP_OVERLAY_CHECKPOINT.md](JP_OVERLAY_CHECKPOINT.md), and run the existing
   `validate_function_map.py` tool. These checks still do not prove
   native game boot or gameplay.

The seed scanner is a preprocessing aid for reverse engineering, **not** a
replacement for Ghidra, the actual PS2Recomp translation, or a working
Japanese runtime.
