# Japanese function-candidate cross-reference review

**Direct four-binary checkpoint: 2026-11-09 (SLPM_661.01, OVL_00-02).**
Every file matched the recorded Japanese SHA-256 revision. All analysis was
performed against the user's local sample files; no game bytes or generated
guest-code translations belong in this public repository.

## Measured, deliberately unverified leads

The new [corroborate_candidates.py](../tools/jp/corroborate_candidates.py)
cross-references Japanese prologue review seeds with **syntactic** MIPS
JAL target words, and adds the known ELF entry and candidate header-defined
constructor pointers:

| Analysis module | Distinct candidates | Candidates with one or more syntactic JAL target matches |
| --- | ---: | ---: |
| main | 5,260 | 3,830 |
| ovl00 | 1,249 | 691 |
| ovl01 | 813 | 783 |
| ovl02 | 308 | 298 |
| **Total** | **7,630** | **5,602** |

Other bounded structural observations:

- Exactly **14** constructor-pointer candidates in OVL_00;
  **none** matched an explicit JAL target in the scan. Loader or indirect
  invocation is a hypothesis to review, **not** an established conclusion.
- The linear scan found **39** JAL-opcode words in the main ELF whose target
  falls within an overlaid guest address range. They are intentionally
  **not attributed** to any one of the three overlays, which share guest
  memory around 0x0060C800.
- The scanner examined **39,278** candidate JAL words in the file-backed
  main ELF region and **4,438 / 12,319 / 4,004** in overlay 00/01/02.
  These counts include potentially unreachable/data words and are not
  call-instruction counts from a verified control-flow graph.

The apparent high match rate of overlay 01/02 must **not** be interpreted
as high confidence. Call opcode words may occur in data and branch-unreachable
regions. A syntactic JAL target reference is only one manual-review cue.
All rows have `CANDIDATE_NOT_VERIFIED`.

## Reproduce locally

Using the four known Japanese files from your own game disc, outside Git,
with Python 3.11 or newer:

```powershell
python tools/jp/corroborate_candidates.py "C:\Games\DW5XL-JP" --out "C:\JP-analysis\call-candidates-01"
```

The tool refuses binaries whose SHA-256 or structural header differs from
`known_revision.json`, and accepts safely case-insensitive overlay
filenames. The destination must not already exist and must be outside
the public repository checkout. It writes:

- `summary.json`: bounded counts, source identities and explicit limits.
- `ranked_candidates.csv`: module, guest address, reason, syntactic JAL-word
  count and source module labels, sorted for review.

The address CSV contains **no game machine-code bytes or disassembly**.
It is **not** the PS2Recomp `Name,Start,End,Size` function map.
No generated translation or native game boot was attempted.

## Import review bookmarks in Ghidra without defining functions

In an R5900-capable Ghidra project, import `SLPM_661.01` normally and
each `OVL_XX.BIN` separately as a raw overlay at 0x0060C800 including
the file header. Preserve original program filenames so that the
candidate script can check the selected module against the open program.

1. Add `tools/ghidra_scripts` as a Script Manager folder.
2. Run `BookmarkJPReviewCandidates.java`.
3. Choose `ranked_candidates.csv`, and enter `main`, `ovl00`,
   `ovl01` or `ovl02` for the *currently opened* Ghidra program.
4. Inspect the new **Analysis** bookmarks; compare bytes, references,
   delay slots, data classification, return edges and real call paths
   before creating any function or editing any PS2Recomp CSV.
5. When review is complete, independently export function maps with
   `ExportPS2Functions.java` and run the [main](JP_MAIN_CHECKPOINT.md)
   or [overlay](JP_OVERLAY_CHECKPOINT.md) validator checkpoint.

The bookmark script also accepts the new `constructor_span_candidates.csv`
from [inspect_constructor_bodies.py](../tools/jp/inspect_constructor_bodies.py),
with proposed return/end addresses in the Analysis bookmark description.
No function boundaries are created, and the Java importer still needs an
actual Ghidra run to establish runtime compatibility.

The bookmark script also accepts the earlier
`prologue_review_seeds.csv` and `candidate_bookmarks.csv` formats.
It validates module names, 32-bit addresses, file size and CSV schema
before touching any bookmarks. It **only creates Analysis bookmarks**,
not disassembly, functions, labels, or code. On import failure it does
not promote candidates to verified functions.

**Verification limit:** The Python static/synthetic tests have been
run in CI; the Java bookmark script has not been run inside a real Ghidra
instance in this environment. Actual Ghidra validation, full JP function
maps, Japanese PS2Recomp compilation and gameplay tests are still open.
