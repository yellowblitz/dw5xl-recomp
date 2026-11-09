# Japanese overlay constructor-table review

**Status:** exploratory pointer evidence, not verified functions or a native JP build.

The known Japanese sample revision for `SLPM_661.01` records three `MWo3`
overlays, all loaded at `0x0060C800`. The header-reported constructor address
ranges are:

| Module | Candidate range | Number of 32-bit words if end-exclusive |
| --- | --- | ---: |
| `OVL_00.BIN` | `0x0068BF50`–`0x0068BF88` | 14 |
| `OVL_01.BIN` | `0x00687380`–`0x00687380` | 0 |
| `OVL_02.BIN` | `0x00634A80`–`0x00634A80` | 0 |

These ranges are **header metadata**, not a statement that `OVL_01` and
`OVL_02` have no initialization code. The interpretation as exclusive-end
little-endian pointer tables has not yet been independently verified.

## Run the new inspector locally

Use the exact Japanese game files from your own disc, outside Git:

```powershell
python tools/jp/preflight.py "C:\Games\DW5XL-JP" --inputs-only
python tools/jp/inspect_constructors.py "C:\Games\DW5XL-JP" --json "C:\JP-analysis\overlay-constructors-01.json"
```

`inspect_constructors.py` verifies *each overlay's* size, SHA-256 and
complete parsed `MWo3` header against `known_revision.json` before reading
the candidate table. It refuses symlinked source files, unexpected names,
existing report paths, and report destinations inside the repository. There
is no download or upload step.

The output includes per-slot guest addresses, possible pointer values, and
four conservative categories:

- `aligned_in_file`: aligned 32-bit address inside the overlay's file-backed
  guest-address range; a **candidate** only, not proof of code.
- `unaligned_in_file`: address inside that range but not 4-byte aligned.
- `outside_file`: nonzero word outside this overlay's file-backed range.
  It may be an external pointer, relocation encoding, or nonpointer data;
  it is *not* automatically an error.
- `null`: zero word.

A pointer into the overlay could refer to data, not code. The report never
populates a PS2Recomp `entry_points` or `stubs` list and never invokes the
upstream recompiler. The original word range may not even be a pointer table;
review it in Japanese disassembly before drawing conclusions.

## Verify candidates in Ghidra

1. Import each overlay separately as R5900 little-endian data at guest
   `0x0060C800`, **including** its 0x80-byte provisional header/prefix.
   Do not treat `raw_code_offset = 0x80` as established code start.
2. Check the header-reported constructor start/end fields against references
   and the actual loader behavior. Confirm whether the endpoints and table
   entries really use the assumed format.
3. If the format is verified, **bookmark** aligned in-file pointer targets
   for review. Check each target's bytes and cross-references before creating
   a function. Do not feed the address candidates directly to
   `ImportFunctionList.java` as verified function rows.
4. Determine actual code/data ranges, constructors, shared tails and indirect
   dispatch. Save independently reviewed function maps as `ovl00.csv`,
   `ovl01.csv`, and `ovl02.csv` in a local scratch directory.
5. Follow [JP_OVERLAY_CHECKPOINT.md](JP_OVERLAY_CHECKPOINT.md) to hash-lock those
   reviewed maps and run the upstream read-only function-map validator.

Keep the inspector's local report and all private game files out of Git;
the repository contains no original game bytes, generated game C++, or
Japanese disassembly output. Successful inspector tests certify only tool
behavior on synthetic inputs, not the constructor-table hypothesis.
