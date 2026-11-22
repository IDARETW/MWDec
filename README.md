# MWDec

Static decryption of the Arxan protection in **Call of Duty: Modern Warfare (2019)**, and removal of the protection
from the shipped executable.

MWDec reads the shipped `ModernWarfare.exe` and writes a file. It never loads, maps for execution or runs the game,
and it needs nothing from a running process. Everything it uses (cipher keys, range lists, writer tables, routine
addresses, published values) is read from the file itself, so it works on builds it has never seen. It has been run
on every generation of the game from the September 2019 beta (0.01.2) to 1.69.0.

Its counterpart is [MWHook](https://github.com/IDARETW/MWHook): in-process mitigations for the protected game, the
research notes on how the protection works, and the emulation lab the results here were checked with.

## What it produces

- **`mwdec decrypt`**: the image with every encrypted byte readable and the protection still in it. For a
  disassembler.
- **`mwdec remove`**: the image with the protection taken out. One entry path, one import table, direct jumps where
  the protection had disguised ones, its routines replaced by the stores the calling code depends on, its checks
  answered, its junk constructs removed, and its code and data filled with `int3`. That holds for the code a static
  walk can reach; code behind computed jumps, with everything it touches, is left byte for byte as shipped (see
  [Limits](#limits)).

## Build

Visual Studio 2022, CMake 3.20+, C++20. The control-flow passes use capstone and unicorn; CMake takes their headers
and DLLs from the Python packages (`py -3 -m pip install capstone unicorn`), or from `CAPSTONE_DIR` / `UNICORN_DIR`.
The two DLLs are copied next to `mwdec.exe` and bound at run time, so the decryption commands run without them.

```powershell
cmake -S . -B build -A x64
cmake --build build --config Release
build\Release\mwdec_selftest.exe
```

The Python tools in `tools/` are the reference implementation of every pass. They need Python 3 with `capstone`,
`unicorn` and `numpy`.

## Use

```powershell
# the whole removal, one process, from the shipped file alone
mwdec remove ModernWarfare.exe -o ModernWarfare.clean.exe --work work --unlock-sections

# decryption only
mwdec info    ModernWarfare.exe
mwdec decrypt ModernWarfare.exe -o ModernWarfare.dec.exe
mwdec strings ModernWarfare.exe -o strings.tsv
mwdec imports ModernWarfare.exe -o imports.tsv
mwdec verify  ModernWarfare.exe --dump dump.exe
```

`remove` options:

- `--unlock-sections` also writes the export with every section marked readable, writable and executable, which is
  what the protection's first start-up routine did at run time. Use it for anything meant to run as a process.
- `--work DIR` keeps the tables and plans of the run there (`--keep-work` keeps the intermediate images too).
- `--full` adds what only feeds reports and proofs: the flow pass's report-only walks, the live map, the junk
  constructs' emulator proof. The default leaves them out and writes the same export.

Nothing is cached between runs; every export starts from the shipped file. A cold export takes about half a minute
for 0.01.2, one minute for 1.30.0 and under two minutes for 1.69.0, at a few GB of memory.

The steps of `remove` are also commands of their own (`writers`, `tables`, `boot`, `flow`, `junk`, `export`), and
`tools/remove_build.py SHIPPED.exe -o clean.exe --work DIR --steps` runs the Python tools one by one instead, as the
reference. `tools/remove_all.py <folder of builds>` runs the removal over a folder of builds
(`<folder>\<build>\ModernWarfare.exe`), one at a time, and keeps one row per build in `results.tsv`.

## What the protection does, and how it is undone

### Two layers of encryption

| layer | what the protection does | how MWDec undoes it |
|---|---|---|
| 1. Bootstrap | Both code sections (209 MB on 1.51.2) are XORed with an XTEA-64 output-feedback keystream, in over a million ranges that step around every relocation. | Reads the key, the starting block and the range list from the file and runs the same keystream (about 4 s). |
| 2. Writers | Some functions, the entries of a family of small subroutines and some string tables stay unreadable after the bootstrap. A writer routine overwrites each from its own encoded copy just before use, with one of four encodings (`Xor`, `Sub`, `XorAuto`, `MulRol`). | Finds every writer in the code, decodes its copy and writes it where the writer would, in dependency order (some writers prepare other writers' data). |
| Engine strings | Later builds keep thousands of strings in `.data` as XOR-keyed blobs, decrypted lazily (17,205 on 1.51.2). | Decrypts every blob in place and clears its "encrypted" flag, the state the game leaves it in. |
| Imports | Two import tables: the loader fills one, a start-up routine copies it to the other. | `mwdec imports` names every slot of both. |

Every writer has a twin that puts noise back over the same ranges after use. Only the decrypting half of each pair is
applied.

**Layer 1 from the file.** The range list is found through the relocation table: the cipher steps around every
relocated qword, so a run of nearby relocations fixes a run of `(gap, length)` pairs, whose LEB128 encoding is
searched for and the list read backwards to its first byte. The key, the starting block and the cycle count are read
from the cipher's own set-up code, which is plain compiled code on every build:

```
mov dword ptr [rbp+10h], 40h          ; cycles
mov dword ptr [rbp+14h], 9E3779B9h
lea rax, [rip+KEY]   ; mov [rbp], rax
lea rax, [rip+BLOCK] ; mov [rbp+8], rax
```

**Layer 2 from the file.** Every writer is an instance of one compiled routine and names its stash, its list and its
key in fixed instruction shapes (frame offsets change between builds, so the shapes are matched, not the offsets).
The protection cuts this code into pieces and keeps some of them in the padding of read-only sections, so the finder
reads instructions as a stream through joining and disguised jumps, across every read-only section. Each candidate is
decoded: output that is code or data and differs from what is in place is a decryptor and is kept; output equal to
what is in place is a repair writer; noise is a twin, or a writer that prepares another writer's stash (found by
trying it and seeing whether a row further down then decodes). Rounds repeat until one keeps nothing.

`mwdec decrypt --writers writers.tsv` applies a table from `tools/find_writers.py`; `--no-profile` makes `mwdec` find
everything from the file even on the one build it has a built-in profile for (1.51.2, build 19936). On that build
both routes give the same image byte for byte.

### The protection inside the code

| construct | what it is | what the removal does |
|---|---|---|
| Start-up routines | Three calls in front of the entry point's first `call` and TLS callback 0: unlock the sections, decrypt, copy the imports. | Points both back at the code behind them. |
| Second import table | Code that calls imports through the protection's copy of the table. | Retargets those instructions to the loader's table. |
| Routines (551 to 744 per build) | Spliced into game functions behind `push R ; push G ; ret` chains. A routine writes three qwords on its caller's stack: two `ret` gadgets and the address where the game function continues. The calling code pushes decoys in the same slots. | Reads the three addresses from each routine's own stores, replaces the routine by a 53-byte stub that makes the same three stores, and folds chains into a direct jump to the continuation where the registers it leaves are dead. |
| Checksum guards and checks | Guards hash code and publish a digest into a code slot; checks elsewhere read published values (`mov r,[P] ; add r,[A] ; xor r,[B]` must give zero). | Stores the published values the checks need (`B - A`), folds checks whose value holds from the start, and keeps any check whose value is published at run time by a routine that is kept. |
| Disguised control flow | Branches, calls and jumps written as push/ret sequences and stack-pointer arithmetic, and stack instructions written as pairs (184,000 and 114,000 of them on 1.51.2). | Rewrites each as the direct instruction. |
| Junk constructs | `pushfq ; push R ; op R, imm ; call` back into that immediate, a fake epilogue, then `pop R ; … ; popfq` (12,500 to 24,000 per build). Oldest builds skip the flag save; 1.69 adds a no-op filler between the pops. | Replaces each with a two-byte jump over itself, only where it restores everything it touches (for the form without the flag save, only where every path afterwards rewrites all six status flags before reading one). |
| Dead protection code and data | Routine bodies, range lists, tables and stashes nothing left in the image uses. | Filled with `int3`. |

After the rewrites the PE is settled around them: relocation entries under a patch or a wipe are dropped,
exception-directory records whose code was wiped are removed, the protection's import descriptor is removed once
nothing refers to it, the certificate table is cleared and the checksum recomputed.

The rewrites are *plans*: data files of byte patches, relocation entries to delete and ranges to fill.
`mwdec export <exe> -o <out> --plan a.plan --plan b.plan …` applies a set of plans; `tools/planfile.py` prints one.
`profiles/` holds the plans and the writer-table amendment of build 19936 (1.51.2), the build the method was worked
out on; no other build needs a profile.

## Tested builds

Ten versions, each exported from its shipped file with no per-build input, then checked in the emulator (MWHook's
`tools/arxan`): a sample of functions run in both images from the same state with the protection's routines
executing in the protected one, and both images started at the entry point and compared stretch by stretch. Where
the archive has a memory dump of the running game, every section, pointer and function record of the export was also
checked to sit at the same address as in the dump.

| version | routines | junk constructs removed | functions compared | equal | out of time or no verdict | different | start: stretches compared | equal | memory dump |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| 0.01.2 | 551 | 12,578 | 396 | 383 | 13 | 0 | 6,181 | 6,181 | none to compare |
| 1.07.0 | 567 | 12,868 | 402 | 391 | 11 | 0 | 6,294 | 6,294 | none to compare |
| 1.23.2 | 616 | 18,538 | 410 | 396 | 14 | 0 | 6,505 | 6,505 | none to compare |
| 1.30.0 | 621 | 20,774 | 411 | 396 | 15 | 0 | 6,539 | 6,539 | none to compare |
| 1.31.5 | 621 | 20,730 | 411 | 397 | 14 | 0 | 6,551 | 6,551 | same addresses |
| 1.39.3 | 625 | 21,085 | 411 | 394 | 17 | 0 | 6,027 | 6,027 | same addresses |
| 1.41.2 | 626 | 21,183 | 412 | 393 | 19 | 0 | 6,032 | 6,032 | none to compare |
| 1.51.2 | 734 | 23,674 | 407 | 392 | 15 | 0 | 6,463 | 6,463 | same addresses |
| 1.64.0 | 744 | 23,341 | 408 | 393 | 15 | 0 | 6,995 | 6,995 | same addresses |
| 1.69.0 | 735 | 22,429 | 406 | 392 | 14 | 0 | 6,950 | 6,950 | same addresses |

"Out of time or no verdict" means the protected side did not get far enough to compare, never that the two sides
disagreed. The 1.20 export was also started as a real process: it shows the splash screen and the game window and
goes on as the shipped file does.

On 1.51.2 the method was checked more deeply against the real code: the first TLS callback run to the end in an
emulator equals `decrypt --layer1-only` in all but 25 of 224 million bytes (the routines' own bookkeeping); every
writer's output equals the result of running the writer; every routine table, check value and stub read from the
file equals the one measured by running each routine; and each kind of rewrite was compared, construct by construct,
with the shipped construct running.

## Tools

| tool | what it does |
|---|---|
| `tools/remove_build.py` | the whole removal for one build (`--flow-exe` runs `mwdec remove`, `--steps` the Python steps) |
| `tools/remove_all.py` | the removal for a folder of builds, with copying from a slow share, delivery and one results row per build |
| `tools/find_bootstrap.py` | layer 1's key, starting block and range list, with every step printed |
| `tools/find_lists.py` | every range list in an image (each ends with a five-byte gap to `0xFFFFFFFF`, read backwards) |
| `tools/find_writers.py` | the writer table from the code |
| `tools/find_routines.py` | each routine's three caller-stack addresses, and the 53-byte stubs |
| `tools/find_checks.py` | the values the checks need |
| `tools/devirt_boot.py`, `tools/devirt_flow.py` | the start-up and control-flow plans (`mwdec flow` is the C++ port, byte for byte) |
| `tools/find_junk.py` | the junk-construct plan |
| `tools/check_clean.py` | counts on an export what should be zero (bad relocations, second-table references, flagged strings, start-up chains, routine stubs and disguised jumps left as code, noise pages) |
| `tools/check_functions.py` | function pieces that still decode as noise |
| `tools/check_dump.py` | whether everything in an export sits at the address a memory dump of the same build has it at |
| `tools/test_builds.py`, `tools/survey_builds.py` | decryption over a folder of builds, with per-build counts |
| `tools/entry_layout.py`, `tools/arxan_strings.py` | the entry path as straight-line code; the protection's two-pad strings |
| `tools/planfile.py`, `tools/gen_writers.py`, `tools/find_writer_key.py`, `tools/riprefs.py` | plan files, the built-in writer table, a writer's key by exhaustion, RIP-relative references |

## Layout

```
src/pe.*          PE32+ mapped by RVA
src/xtea.h        XTEA and the output-feedback keystream
src/ranges.h      the protection's LEB128 (gap, length) range lists
src/bootstrap.*   layer 1
src/autoboot.*    layer 1's parameters and the import lists, found in the file
src/writers.*     layer 2;  src/writerkey.* a writer's key by exhaustion (findkey)
src/strings.*     engine string blobs
src/imports.*     the two import tables
src/plan.*        plan files, relocation and exception-directory upkeep
src/verify.*      comparison with a memory dump
src/profile.*     the built-in profile of build 19936
src/flow/         the removal passes in C++: writers, tables, boot, flow (walks, sweeps, rewrites), junk, remove
profiles/         plans and the writer-table amendment of build 19936
tools/            the Python reference tools
```

## Limits

- **Coverage.** Removal is exact for the code a static walk reaches. A static walk does not follow computed jumps,
  and the game's anti-cheat is built on them. Code found behind them is kept exactly as shipped, with everything it
  reaches (on 1.51.2: 8.9 MB holding about 60,000 disguised branches and 344 routine call sites), and so is the
  protection's import descriptor where kept code still uses it. About a third of the protection's section stays in
  the export.
- **Checks published at run time.** A check whose value a kept routine publishes at run time stays as shipped, as
  does that routine.
- **Registers.** A routine table read from the code does not know what a routine leaves in registers its chain does
  not save, so a chain is folded only where `rax, rcx, rdx, r8-r11` (less the ones saved) are dead after it.
- **What was checked.** The exports were compared with the protected images in an emulator, which reaches the game's
  code only as far as an emulator without a GPU, a file system or a network gets. One export (1.20) has been started
  as a real process. The emulator has no page protections; use `--unlock-sections` for anything run as a process.
- **Running old builds today.** A retail build from 2020 or earlier runs a static initialiser that lays `gdi32.dll`
  out as a private image and calls that copy's `GdiDllInitialize`, which on current Windows is a delay-load stub, and
  the process executes address 0. The shipped file does the same; it is not the protection.
- **The anti-cheat** is out of scope. MWDec does not analyse or modify it.

The research behind every number here is in the MWHook repository under `docs/research` (notes 008 to 015).
