# Japanese version — validated metadata, unfinished recompilation

The repository now contains verified **metadata-only** identities for five sample files from `SLPM_661.01`, at [`known_revision.json`](known_revision.json). The ELF entry point and three overlay base addresses come from the supplied file headers. These are *not* substitutes for full disassembly or recompiled code.

The `main.toml` and three `overlays/ovlXX/ovlXX.toml` profiles are candidate PS2Recomp configurations. They are **not runnable**: required Japanese Ghidra function maps have not been generated, any PAL stubs/entry points must be reconsidered, and overlay code offset `0x80` is still provisional. No existing PAL codegen or CMake target is switched to Japanese.

Next: import `SLPM_661.01` into Ghidra with the upstream PS2 setup, analyze the code and export Japanese functions using `tools/ghidra_scripts/ExportPS2Functions.java`. Analyze overlays with their actual `0x0060C800` load base, verify code/data boundaries and constructor entry points. Only then populate JP function CSVs, test PS2Recomp translation and integrate JP-specific runtime dispatch. See [`docs/JP_PORT_PLAN.md`](../../docs/JP_PORT_PLAN.md).
