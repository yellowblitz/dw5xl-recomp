# Japanese SLPM_661.01 actual-binary structural review

**Checkpoint: 2026-11-09.** The developer re-supplied the Japanese main ELF and
three overlays for local analysis. All four files were read in a private
scratch environment and their full SHA-256 digests matched
[known_revision.json](../recomp/dw5xl_jp/known_revision.json). No original game
bytes, game-derived translation output or disassembly listings are committed.

## Direct observations from these exact binaries

- The main executable is a little-endian 32-bit MIPS ELF with entry
  **0x00100008**. Its file-backed main load region begins at **0x00100000**
  and ends just before **0x0035D100**. Separately declared zero-file-size
  overlay regions begin at **0x0060C800**.
- All three overlay files have zeros at file offsets **0x40 through 0x7F**.
  At **0x80**, the first 32-bit word in each file has an **ADDIU $sp,$sp,
  negative immediate** encoding. This is concrete support for the candidate
  `raw_code_offset=0x80` used in the JP profiles. It is not independent proof
  of the loader's code start or that all overlay bytes after 0x80 are code.
- The `OVL_00.BIN` header reports 14 consecutive aligned words in the
  candidate constructor-table range. Inspection of the real binary found
  **14/14** values aligned and within its file-backed guest-address span.
  Each pointed-to first 32-bit word has the **LUI** opcode class. That is
  compatible with executable initialization routines but is not sufficient
  to certify a callable function. The other two overlay headers report empty
  candidate constructor-table ranges; this does not establish that they
  have no initialization logic.
- Bounded linear inspection of file offsets **0x80–0x17F** found MIPS
  **JAL** encodings targeting both the main ELF's file-backed range and the
  current overlay's file-backed range. This establishes useful *syntactic*
  call-target candidates, not a complete control-flow graph. Data or
  unreachable code could also contain such encodings.

## Reproduce the local hash-locked evidence

From the repository root, use extracted legal game files in a directory
outside the repository, e.g. `C:\Games\DW5XL-JP`. The overlay filenames can
be uppercase or lowercase; ambiguous case-colliding names and symlinks are
rejected.

```powershell
python tools/jp/preflight.py "C:\Games\DW5XL-JP" --inputs-only
python tools/jp/inspect_constructors.py "C:\Games\DW5XL-JP" --json "C:\JP-analysis\constructor-candidates-01.json"
python tools/jp/survey_runtime_entries.py "C:\Games\DW5XL-JP" --out "C:\JP-analysis\runtime-survey-01"
```

The last command produces `summary.json` and
`candidate_bookmarks.csv`, with the three overlay 0x80 starts and aligned
header-derived constructor targets as **review candidates**. The list is
not a function CSV and must not be fed blindly to the Ghidra
`ImportFunctionList.java` tool or the PS2Recomp generator.

Every source binary, ELF structural field and overlay header is checked
against the committed revision before a report is written. Reports contain
hashes, addresses, opcode classes and classifications, **not executable
instruction bytes**. Output must be a new folder outside Git.

## Tentative function-entry seed census

An additional conservative MIPS stack-frame/return-address-save scan of these exact four binaries yielded 5,259 main ELF and 2,356 overlay candidate starts, **7,615 unverified candidate entries total**. They are *not* a function list; shared tails, leaf functions, data misclassification and dynamic code require Ghidra. See [JP_FUNCTION_SEED_REVIEW.md](JP_FUNCTION_SEED_REVIEW.md) for the locally reproducible scanner, safety limits and exact breakdown.

## Engineering conclusions and next gate

The original candidate offset `0x80` is now supported by direct observations
from each uploaded Japanese overlay, rather than only by inheritance from
PAL. **Leave it marked unconfirmed** until Japanese loader analysis and
Ghidra code/data boundaries corroborate the mapping.

In Ghidra, inspect the three 0x80 entry candidates and all 14 OVL_00
constructor-pointer candidates. Confirm the table's actual semantics,
each routine boundary, main-versus-overlay direct targets, shared tails,
jump tables, and dynamic/indirect calls. Export reviewed Ghidra function maps
and use [JP_OVERLAY_CHECKPOINT.md](JP_OVERLAY_CHECKPOINT.md) to run the
existing boundary validator.

The complete Japanese ISO, `MODULES` directory, IOP/VU programs, validated
Japanese function CSVs and native boot/graphics/audio test results are still
missing. **No Japanese PC release is ready or claimed playable.**
