# Japanese OVL_00 constructor-body boundary review

**2026-11-10 checkpoint. Actual Japanese OVL_00.BIN provided by the user.**
Its SHA-256 matches the committed revision:
`b14612f09d69ce47f42010c20a1d71e33a3d1859228589b6d7ca7c4ee2d48a49`.

The MWo3 header points to a 14-word candidate constructor table at
`0x0068BF50..0x0068BF88` (interpreted as end-exclusive). All 14
32-bit words are unique aligned addresses into the OVL_00 file-backed
guest range. A bounded linear MIPS control-transfer scan from each
pointer to the next pointer, or to the table start for the final entry,
found **14/14** with:

- Exactly a conventional `JR $ra` return and a readable delay slot.
- No recognized `J` / `JAL` / conditional branch / `JR` / `JALR` /
  COP conditional branch / `ERET` / trap **before** that return.
- A zero-filled return delay slot.
- No nonzero bytes between the return delay slot and the next pointer
  entry; four entries have 8 bytes of zero alignment padding, the
  other ten have no gap.
- **29,360 combined tentative function-body bytes** and 32 bytes of
  inter-routine zero padding.

This is substantially stronger than a prologue-only match because the
14 routines are referenced by the same header-defined table and have
plausible contiguous return boundaries. Many do not use a stack-frame
prologue, so they are absent from the earlier stack-prologue-only seeds.

## Candidate guest ranges

Exclusive ends include the return's delay-slot instruction, not
trailing padding. Each is **a Ghidra review candidate**, NOT yet a
function that the PS2Recomp translator can safely consume.

| Pointer target / candidate start | Candidate exclusive end | Body bytes |
| --- | --- | ---: |
| `0x00684C80` | `0x00685400` | 1,920 |
| `0x00685400` | `0x006869E0` | 5,600 |
| `0x006869E0` | `0x00687340` | 2,400 |
| `0x00687340` | `0x006886F0` | 5,040 |
| `0x006886F0` | `0x00689680` | 3,984 |
| `0x00689680` | `0x0068A440` | 3,520 |
| `0x0068A440` | `0x0068A4E0` | 160 |
| `0x0068A4E0` | `0x0068ACA8` | 1,992 |
| `0x0068ACB0` | `0x0068AE40` | 400 |
| `0x0068AE40` | `0x0068B160` | 800 |
| `0x0068B160` | `0x0068B2C0` | 352 |
| `0x0068B2C0` | `0x0068BB78` | 2,232 |
| `0x0068BB80` | `0x0068BDF8` | 632 |
| `0x0068BE00` | `0x0068BF48` | 328 |

The four zero gaps are `0x0068ACA8..0x0068ACB0`,
`0x0068BB78..0x0068BB80`, `0x0068BDF8..0x0068BE00` and
`0x0068BF48..0x0068BF50`.

## Reproduce without uploading or committing game code

From the source checkout, with the three known Japanese overlay files in
a private local folder, use Python 3.11+:

```powershell
python tools/jp/inspect_constructor_bodies.py "C:\Games\DW5XL-JP" --out "C:\JP-analysis\constructor-bodies-01"
```

The script checks the exact known SHA-256 hashes and header metadata for
**all three** overlays before producing a local `summary.json` and a
`constructor_span_candidates.csv`. It rejects existing output paths
and writes no game machine-code bytes or translated C++.

In Ghidra with the R5900 language installed, open the separately
imported Japanese `OVL_00.BIN` program (loaded at `0x0060C800`
including its header). Run
[BookmarkJPReviewCandidates.java](../tools/ghidra_scripts/BookmarkJPReviewCandidates.java)
with this CSV and choose module `ovl00`. The script adds **Analysis
bookmarks only**, including the proposed end and return address;
it never creates or adjusts functions. This Java script has not yet
been exercised in an actual Ghidra installation.

Verify the loader's constructor-table semantics, body boundaries,
R5900 instructions, possible alternate entry points, data references,
delay slots, VU/IOP interactions and any code copies. Only afterward,
export the reviewed `Name,Start,End,Size` map and use
[JP_OVERLAY_CHECKPOINT.md](JP_OVERLAY_CHECKPOINT.md) to validate it.

**No Japanese function-map acceptance, PS2Recomp translation or native
gameplay boot is claimed.** This narrowly covers 14 plausible init
routines in OVL_00; OVL_01 and OVL_02 expose no pointer entries in
their header-reported ranges and still require full analysis.
