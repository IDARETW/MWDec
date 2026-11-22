# MWDec

Static decryption of the Arxan-protected `modernwarfare.exe` (Call of Duty:
Modern Warfare 2019, build 1.51.2 / 19936), and export of an image with the
protection removed.

MWDec reads the shipped file and writes a file. It never loads, maps for
execution, or runs the game, and it needs nothing from a running process. A
memory dump is used only by `verify`, as a reference to check the result
against.

There are two outputs, for two purposes.

- `mwdec decrypt` writes the image with every encrypted byte readable and
  the protection still in it. It is for a disassembler.
- `mwdec export` writes the same image with the protection taken out: one
  entry path, one import table, direct jumps where the protection had
  disguised ones, its routines and their data filled with `int3`. That
  holds for the code a static walk can reach. Code behind computed jumps,
  with everything it touches, is left byte for byte as shipped (see
  "Limits"). The export has been compared with the protected image in an
  emulator. It has not been started as a process.

## What `decrypt` undoes

| layer | what the protection does | how MWDec undoes it |
|---|---|---|
| 1. Bootstrap | 208.9 MB of both code sections are XORed with an XTEA-64 output-feedback keystream, in 1,324,188 ranges that step around every relocation | reads the key, the starting block and the range list from the file and runs the same keystream (26.1 M blocks, about 4 s) |
| 2. Writers | 59 functions, the entries of 14 small subroutines and one table of 619 strings stay unreadable after the bootstrap; a writer routine overwrites each from its own encoded copy just before use | decodes each writer's copy and writes it where the writer would, in dependency order: 12 writers that prepare other writers' data, then 88 that produce code (3,825,256 bytes in 151,337 ranges) |
| Strings (engine) | 17,205 strings in `.data` are XOR-keyed blobs, decrypted lazily at run time | decrypts every blob in place and clears its "encrypted" flag, which is the state the game leaves it in |
| Strings (protection) | the two names the protection looks up are stored as pairs of XOR pads inside code | `tools/arxan_strings.py` lists all 544 pairs |
| Imports | two import tables; the loader fills one, a start-up routine copies it to the other | `mwdec imports` names every slot of both |
| Entry point | the entry path is scattered and its jumps are disguised | `tools/entry_layout.py` prints each TLS callback and the entry point as straight-line code |

Every writer has a twin that puts the noise back over the same ranges after
use. The table holds only the decrypting half of each pair; applying the
other half would undo the work.

## What `export` removes

`export` decrypts as above and then applies *plans*. A plan is a data file:
byte patches, base-relocation entries to delete, and ranges to fill with
`int3`. The analysis tools write plans; `mwdec` only applies them.

| plan | written by | what it does |
|---|---|---|
| `19936.boot.plan` | `tools/devirt_boot.py` | points the entry point's first `call` and TLS callback 0 back at the code the protection had put its three start-up routines in front of (8 bytes), and retargets the 1,251 instructions that still used the second import table to the loader's table |
| `19936.checks.plan` | routine census (MWHook, `tools/arxan/d1_*.py`) | stores the 40 values (160 bytes) that the checksum guards publish at run time and that 55 checks elsewhere in the code read |
| `19936.flow.plan` | `tools/devirt_flow.py` | rewrites the disguised control flow in live code as direct instructions, folds each routine call chain into a jump to the place the routine would have continued at, folds the 55 checks, and wipes the protection code this leaves unreachable |
| `19936.dead.plan` | `tools/devirt_flow.py --dead-plan` | wipes the rest of the protection's section that nothing left in the image executes, reads or points at: routine bodies, range lists, tables and stashes |
| `19936.stubs.plan` | `tools/devirt_flow.py --stubs-out` | the 53-byte replacement at each routine that code left in the image still calls (891 patches). The dead plan assumes it is applied |
| `19936.routines.plan`, `19936.routines_cont.plan` | routine census | a 53-byte replacement for each of the 730 routines called from game code, which performs the three stack writes the calling code depends on. Inputs to `devirt_flow.py`, and the reference in the proofs; not applied by an export |

After the plans, `export` settles the PE around them: relocation entries
under a patch or a wipe are dropped, exception-directory records whose code
was wiped are removed, the protection's own import descriptor is removed
once nothing refers to its slots, the certificate table is cleared (the
signature no longer matches) and the checksum is recomputed. On build
19936 the descriptor stays: 1,308 instructions in code that is left as
shipped still load its two slots.

## Build

```
cmake -S . -B build -A x64
cmake --build build --config Release
build\Release\mwdec_selftest.exe
```

C++20, no dependencies. The Python tools need Python 3, `capstone` and
`numpy`.

## Use

```
mwdec info    modernwarfare.exe
mwdec decrypt modernwarfare.exe -o modernwarfare.dec.exe
mwdec strings modernwarfare.exe -o strings.tsv
mwdec imports modernwarfare.exe -o imports.tsv
mwdec verify  modernwarfare.exe --dump dump.exe --runs-out diff.tsv
mwdec export  modernwarfare.exe -o modernwarfare.clean.exe ^
      --plan profiles\19936.boot.plan --plan profiles\19936.checks.plan ^
      --plan profiles\19936.flow.plan --plan profiles\19936.dead.plan ^
      --plan profiles\19936.stubs.plan

py -3 tools\find_bootstrap.py modernwarfare.exe
py -3 tools\entry_layout.py  modernwarfare.dec.exe -o entry.md
py -3 tools\arxan_strings.py modernwarfare.dec.exe -o arxan_strings.tsv
py -3 tools\check_clean.py   modernwarfare.clean.exe --imports imports.tsv
py -3 tools\planfile.py      profiles\19936.flow.plan
```

`decrypt` options: `--layer1-only` stops after the bootstrap layer (the
image exactly as the first TLS callback leaves it); `--keep-strings` leaves
the string blobs encrypted.

`export` applies, across all plans, the wipes first, then the patches in
the order the plans are given, then the relocation drops. A later plan wins
over an earlier one, and a patch wins over a wipe. `--unlock-sections`
marks every section readable, writable and executable in the headers, which
is what the protection's first start-up routine did at run time. Without
it the sections keep the protections their headers give them, and no test
here says whether everything left in the image is content with that: the
emulator the export was compared in has no page protections. Use the
option for a first run as a process.

`verify` decrypts in memory, rebases the result to the dump's load address
through the relocation table, and reports per section how many bytes differ
and where. A dump of a running process is not the same thing as the
start-up image: the process keeps rewriting its own code. See "Checking the
result" below for what the numbers mean.

`check_clean.py` counts, on an exported image, what should be zero: bad
relocation entries, references to the second import table, string blobs
still flagged encrypted, start-up chains in front of the entry point and
the TLS callbacks, routine call stubs and disguised jumps still present as
code, and code pages that look like noise. With `--live` and the bitmap
`devirt_flow.py --live` writes, it counts only what live code can reach.

## Making the plans

The plans for build 19936 are in `profiles/`. They were made like this, on
the decrypted image:

```
py -3 tools\devirt_boot.py modernwarfare.dec.exe --imports imports.tsv -o 19936.boot.plan
py -3 tools\devirt_flow.py modernwarfare.dec.exe -o 19936.flow.plan ^
      --dead-plan 19936.dead.plan --stubs-out 19936.stubs.plan ^
      --routines 011_routines.json ^
      --routines-extra d9_continuations.json --routines-extra d2_continuations_extra.json ^
      --proven 25FEC6E9 --proven 262A8912 ^
      --keep-plan 19936.checks.plan --keep-plan 19936.boot.plan ^
      --stub-plan 19936.routines.plan --stub-plan 19936.routines_cont.plan ^
      --report flow.json --live live.npy
```

Run as written, the second command writes the three plan files in
`profiles/` byte for byte (checked by hash).

`devirt_boot.py` and `devirt_flow.py` are static: they decode and walk the
image and run nothing. `devirt_flow.py` takes about 20 minutes and needs
one thing it cannot read off the image, the routine table. For each routine
called from game code it gives the three addresses the routine writes on
its caller's stack; the third is where the game function continues. They
are not in the calling code, which pushes three decoys in the same slots.
The table was measured by running each routine once in an emulator (MWHook,
`docs/research/011_routines.json`; the two `--routines-extra` files are in
MWHook's `tools/arxan/out`; research notes 011 to 013). `--proven` names
two routines the table does not mark as proven: `25FEC6E9`, whose chain
proof passed after the table was written, and `262A8912`, which the census
did not cover and whose fold is checked against the real routine instead.

`devirt_flow.py` works in this order:

1. It walks the image from the entries the file names (exception records,
   relocated code pointers, the entry point, TLS callbacks, exports) and
   plans every rewrite in the code that walk reaches.
2. It sweeps the gaps the walk left inside live exception records for
   blocks that look like compiler output. Those are code behind computed
   jumps, which the walk cannot follow. Everything reachable from them is
   kept as shipped, and a planned rewrite that such code enters is taken
   back.
3. It walks the patched image again, with the routine stubs in place, and
   wipes what nothing kept executes, reads or points at.

`planfile.py a.plan` prints what a plan holds. `planfile.py --kinds
bake,stub in.plan out.plan` copies only the patches of the named kinds.

## Layout

```
src/pe.*          PE32+ mapped by RVA
src/xtea.h        XTEA and the output-feedback keystream
src/ranges.h      the protection's LEB128 (gap, length) range lists
src/bootstrap.*   layer 1
src/autoboot.*    layer 1's key, starting block and list, and the import lists, found in the file
src/writerkey.*   a writer's key by exhaustion (`findkey`)
src/writers.*     layer 2
src/strings.*     engine string blobs
src/imports.*     the two import tables
src/plan.*        plan files, relocation and exception-directory upkeep
src/verify.*      comparison with a reference dump
src/profile.*     per-build parameters
profiles/         plans and the writer-table amendment for build 19936
tools/            entry layout, protection strings, removal passes, checks;
                  for any build: find_bootstrap, find_lists, find_writers,
                  check_functions, test_builds
```

## The per-build profile

Nothing is derived from the machine, the clock or the process. Every
parameter is the RVA of data that sits in the file. For build 19936:

| parameter | RVA | how it was found |
|---|---|---|
| XTEA key (16 bytes) | `0x23BF3897` | the key pointer in the block function's frame, read once in an emulator |
| starting block (8 bytes) | `0x26D860DC` | the first input to the block function |
| bootstrap range list | `0x25A8CA90` | search the file for the LEB128 encoding of the first few plaintext gaps; it is the start of the largest plaintext island in the protection's section |
| import copy lists | `0x26D045AE`, `0x23B163B3` | the two byte streams the third start-up routine reads |
| writers | `src/writers_19936.inc` | one row per writer: range list, stash, key, variant |

## A build without a profile

None of that table has to be typed in. Both layers of a build `mwdec` has
never seen are decrypted from its file, with no emulator and no dump:

```
mwdec decrypt ModernWarfare.exe -o layer1.exe --layer1-only --keep-strings
py -3 tools\find_writers.py layer1.exe -o writers.tsv
mwdec decrypt ModernWarfare.exe -o ModernWarfare.dec.exe --writers writers.tsv
```

`--no-profile` makes `mwdec` work this way on a build it does have a
profile for. That is the check: on build 19936 the three commands give an
image that is byte for byte the one the profile gives (0 of 297,288,240
bytes differ), and the profile's writer table came from running every
writer in an emulator.

**Layer 1** (`src/autoboot.*`; `tools/find_bootstrap.py` is the same search
in Python with every step printed).

- The range list is found through the relocation table. The cipher steps
  around every relocated qword, so a run of nearby relocations fixes a run
  of (gap, length) pairs. Their LEB128 encoding is searched for in the
  image, and the list is read backwards from the match to its first byte:
  LEB128 has no ambiguity in that direction, and the list begins at the gap
  that equals the whole remaining cursor.
- The key, the starting block and the cycle count are read from the
  cipher's own set-up code, which the protection leaves as plain compiled
  code:

  ```
  mov dword ptr [rbp+10h], 40h          ; cycles
  mov dword ptr [rbp+14h], 9E3779B9h
  lea rax, [rip+KEY]   ; mov [rbp], rax
  lea rax, [rip+BLOCK] ; mov [rbp+8], rax
  ```

  They are accepted when they turn the first 512 bytes of the stream into
  code (over half of them common code bytes, against a fifth for noise).
- If that code is not found, the key and the starting block are looked
  for by position: they are bytes the cipher has to skip and no relocation
  explains, and very few such islands are exactly 16 or 8 bytes long.

**Layer 2** (`tools/find_writers.py`). Every writer is an instance of one
compiled routine, and names its three things in fixed ways:

```
lea rax, [rip+STASH] ; mov [rbp+D], rax                      the encoded copy
lea rax, [rip+LIST]  ; mov [rbp+D], rax ; mov eax, 1 ; test eax, eax
xor eax, [rip+KEY]   ; mov rdx, [rbp+D] ; mov [rdx], eax     Xor  (in the loop)
add eax, [rip+KEY]   ; mov rdx, [rbp+D] ; mov [rdx], eax     Sub  (in the loop)
mov eax, [rip+KEY]   ; mov [rbp+D], eax                      XorAuto, MulRol (before the set-up)
```

The frame offsets `D` change from build to build, so the tool matches the
shapes. The protection cuts this code into pieces, so the tool reads
instructions as a stream, following joining jumps and resolving disguised
ones. A loop with an `imul` is MulRol; one that xors a frame slot is
XorAuto. Two details matter on the older builds:

- The stash is the *last* address stored into the frame before the list's.
  Before it the set-up stores another one, which it uses to measure how
  far the image was moved (its own address minus an unrelocated qword
  holding the address the linker gave it).
- The protection keeps pieces of its code in the padding at the end of
  read-only data sections: `.rdata` on build 19936, `_RDATA` and `.pdata`
  on 0.01.2, where the set-up of the largest writer is in the last page of
  `.pdata`. So the stream may enter any read-only section, and the scan
  for set-ups covers them all.

Each candidate row is then decoded:

- output that is code or data, and differs from what is in place: a
  decryptor, kept;
- output equal to what is in place: a repair writer, left out;
- noise: either the twin that hides the ranges again, or a writer that
  prepares another writer's stash. The second kind is found by trying it
  in place and seeing whether a row down the chain then decodes.

Kept rows are applied and the search runs again on the result, until a
round keeps nothing.

"Code or data" is judged on the first 64 KB of the output, by two rules:

- over 35% of the bytes are ones that are common in code (decryptors
  produce 58% and more, noise 20%, a weakly encoded twin under 24%); or
- the output is 4 KB or more, over 28% of it are such bytes **and** it has
  under 7.0 bits of entropy per byte. A list can name functions and the
  data they use together: build 1.30.0 has a writer for 48,843 bytes of
  functions that register 2,797 names (`lea rcx, [name] ; call ; mov
  [slot], eax`, more displacement than opcode) and for the 51,128 bytes of
  `.rdata` holding the names. Its output has 34% and 5.96 bits. Under the
  first rule alone it was dropped, and the functions and the names stayed
  encrypted in the export.

At the end the tool prints the sets of ranges that still hold noise and for
which only noise was decoded (`ranges_without_a_decryptor` in
`summary.json`). It is 0 on every build checked; anything else is a
writer the rules did not recognise.

An executable with a single code section is reported as not protected.

Two smaller tools came out of the same work.

- `tools/find_lists.py` lists every range list in an image: a list ends
  with a five-byte gap to `0xFFFFFFFF`, and is read backwards from there.
  On build 19936 it finds 310 lists, among them the range list of every
  writer.
- `mwdec findkey <image> --stash RVA --bytes N` looks for a writer's key
  and encoding from its stash alone, on an image whose bootstrap layer is
  off: all 2^32 keys against the four encodings. It finds the key of a
  `MulRol` writer of build 19936 (`309F06A8`, 76.7% common code bytes
  against 28.1% for the next) in a few seconds. It cannot name the key of
  an `XorAuto` writer: that encoding forgets its starting key within 32
  words, so every key decodes the rest of the stash alike. It is the
  cross-check for `find_writers.py`: on 0.01.2 it read `Xor`, `1AD6DCB2`
  out of a stash whose writer had not been found yet, and the set-up, once
  found, names a dword holding that value.

`tools/test_builds.py <folder of builds> -o results.tsv` runs the three
commands above on every build in a folder (`<folder>\<build>\ModernWarfare.exe`),
counts the code pages that are still unreadable after each layer, and
deletes everything each attempt wrote as soon as it is measured: the local
copy of the build and the two executables. What stays is one row per build
and the build's writer table, a kilobyte or two.

- A page counts as unreadable above 7.2 bits per byte *and* under 30%
  common code bytes. Entropy alone flags a few pages per build that are
  plain code full of 64-bit constants. The table also keeps the count by
  entropy alone after both layers (`over72_final`).
- The folder may be a network share. Each build is copied by a child
  process, and a copy that receives nothing for 30 seconds is abandoned
  and the build recorded as `not read`. `fetch(…, first=)` is a separate
  allowance for the first byte: an archive that extracts a file before it
  can send it takes 14 s when idle and minutes when short of memory
  (`remove_all.py --fetch-first 400 --fetch-stall 120`, and one more try
  per build).
- `--builds table.tsv` takes the build names from a table instead of
  listing the folder, `--only REGEX` picks some, `--resume` keeps the rows
  already measured and tries the others again, and
  `test_builds.py --summary results.tsv` prints the table.

- The last step is `tools/check_functions.py <image>`, a finer check than
  pages: every record of the exception directory in the game's code
  section is disassembled straight through, and a piece of 32 bytes or
  more that fails and has the byte statistics of noise is counted as
  encrypted (failing alone means little: the game's own obfuscated
  functions fail too, 64.5 MB of them on build 19936). On the shipped
  19936 file it counts 91,100 pieces and 93.1 MB; after layer 1, 136
  pieces and 944 KB; after both, 10 pieces and 1,253 bytes.

What it gives on the builds read so far:

| build | linked | game code pages | unreadable shipped | after layer 1 | after both | set-ups | rows kept | string blobs | function pieces encrypted after both |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 0.01.2.7089334 | 2019-09-19 | 10,533 | 10,403 | 238 | 0 | 64 | 22 | 0 | 0 of 109,250 |
| 1.03.0.7209368 | 2019-10-24 | 11,475 | 11,345 | 243 | 0 | 74 | 22 | 0 | 0 of 115,804 |
| 1.20.4.7623265 | 2020-05-04 | 15,857 | 15,800 | 433 | 0 | 82 | 25 | 0 | 0 of 122,294 |
| 1.51.2.10930490 | 2022-01-18 | 29,329 | 28,981 | 222 | 1 | 212 | 90 | 17,205 | 10 of 127,963 |

The one page of 1.51.2 is a table at `0x9F9000` that no writer touches.
By entropy alone 1.51.2 has six pages above the line after both layers,
1.03.0 three, 0.01.2 one and 1.20.4 none; the ones looked at are code
full of 64-bit constants, tables, and on 1.51.2 two pages holding part of
a stash and one written in part. The ten pieces of 1.51.2 are nine of 67
bytes or fewer and one of 806 bytes at `0x07022490`, in which 684 bytes
of noise lie in the lists the guards hash and in no writer's list.

Those four are all that has been measured. A run over the 119 builds of
the archive on 2026-11-19 read two of them (the first two rows); for the
other 117 the share returned names and sizes but no file contents. The
rows are in `out/builds/test.tsv`, and the same command with `--resume`
carries on from there:

```
py -3 tools\test_builds.py O:\Builds\odin -o out\builds\test.tsv --builds out\builds\odin_manifest.tsv --resume
```

The built-in writer table of build 19936 was produced the long way, before
any of this: by emulating each writer routine once on the image as the
bootstrap leaves it and recording what it reads and writes.
One run is enough to recover a writer's parameters: the stash is the longest
run of image bytes it reads, the key is the one dword it reads elsewhere
that turns the stash into what it wrote, and the range list is found by
encoding the written ranges and searching the image for that byte string.
`tools/gen_writers.py` turns the record into the `.inc` file;
`profiles/19936.writers_amend.json` holds the fifteen rows that had to be
taken from such runs rather than from a memory dump (a dump cannot tell a
decryptor from its re-encrypting twin, and a guard's range list is easily
mistaken for its writer's). At run time MWDec only reads the image.

## Removing the protection from a build without a profile

`devirt_flow.py` needs two things that are not in the calling code: where
each routine sends its caller, and the values the guards publish. For
build 19936 both were measured by running every routine in an emulator.
Both are constants in the file, and two tools read them.

```
py -3 tools\find_routines.py dec.exe -o routines.json --stubs-out routine_stubs.plan
py -3 tools\find_checks.py   dec.exe -o checks.plan
py -3 tools\remove_build.py  ModernWarfare.exe -o clean.exe --work work\
py -3 tools\remove_all.py    <folder of builds> --results out\removed --builds manifest.tsv --deliver <dir>
```

**`find_routines.py`.** A routine reached through a `push R ; push G ; ret`
chain writes three qwords on its caller's stack before it returns: two
`ret` gadgets and the address where the game function continues. It always
does so with a store of the form `mov [base + R*8 (+ d)], V`, where `V` was
just loaded from a qword of the image that holds an address, and `R` was
just loaded from, or had added to it, a qword that holds a small number.
The registers and the base differ:

```
mov rax,[rip+I] ; mov rdx,[rbp+D] ; mov rcx,[rip+Q] ; mov [rdx+rax*8],rcx      19936, in the epilogue
mov rax,[rbp+D] ; add rax,[rip+I] ; mov rdx,[rip+Q] ; mov [rbp+rax*8+d],rdx    1.20, early in the routine
mov rax,[rip+Q] ; mov rdx,[rbp+D] ; add rdx,[rip+I] ; mov [rbp+rdx*8+d],rax    1.20, other kinds of routine
```

The tool takes every routine entry from the chains
(`devirt_flow.census_chains`), walks the routine's code from its entry
(joining and disguised jumps followed, both ways through branches, calls
stepped over) and collects the stores it meets. A routine has several
exits; they must name the same three addresses, with consecutive index
constants. Where the slots are is known from the chain: just above its
register save, `118h + 8 x registers pushed` from the routine's entry
`rsp`. The index constant has to differ from that by the same amount in
every routine of a build (it is -1 qword in both builds checked), or the
routine is left out.

It also writes the replacement of every routine as a plan: `ret` for the
three start-up routines, which are called and return, and the 53-byte
stub (see "What `export` removes") for the others, placed in the routine's
own first instructions.

On build 19936, against the emulated census (`011_routines.json`): 730 of
730 routines have the same three addresses, and the tool reads the one
routine the census had not covered. 1,185 stub pieces are byte for byte the
profile's. 52 differ: for those routines the measured stub also sets
`r8d`, a leftover the routine leaves in a register its chain does not
restore. The table read from the code does not claim to know leftovers.
It lists `rax, rcx, rdx, r8-r11` as possibly changed, and `devirt_flow.py`
folds a construct only where the ones its chain does not save are dead
afterwards.

**`find_checks.py`.** A check reads a published dword and combines it with
its own constants (`mov r,[P] ; add r,[A] ; xor r,[B]`, or without the
`add`, or with `sub`), and the result has to be zero. So the value is
`B - A`, or `B`. The plan the tool writes for build 19936 is the same file
as `profiles/19936.checks.plan` (40 values, byte for byte). The three
instructions are read through joining jumps: the protection cuts its code
anywhere, and on 1.20 three of 53 sequences have a jump after the `mov`.
A check whose value is not in the file does not fail quietly. It turns
the wrong value into a jump target, which is how the two missing values
of 1.20 were found: an export took that path in the emulator.

**`devirt_flow.py` with such a table.** No emulated run says which image
bytes the routines write, which the tool uses to refuse folding a check
that reads one. For a table read from the code it takes instead every
location the protection's code stores to through a RIP-relative operand or
takes the address of (37,806 on build 19936); all 55 checks still fold.
And the code regions outside the code sections are found by a second rule
besides "pages many jumps land in": the padding after the last data
directory of a section, when a jump lands in it. Build 1.20 has such a
piece at the end of every section, `.idata` included.

**`mwdec flow`** is `devirt_flow.py` again, in C++ (`src/flow`). It takes
the same arguments and writes the same files, and it is held to that: on
0.01.2 and on 1.20 its `flow.plan`, `dead.plan`, `stubs.plan` and start
list equal the Python tool's byte for byte. The Python stays the
reference; the C++ is what a run over many builds uses.

| build | `devirt_flow.py` | `mwdec flow` |
|---|---:|---:|
| 0.01.2 | 617 s | 74 s, 2.0 GB |
| 1.20 | 722 s, about 8 GB | 112 s, 2.7 GB |
| 1.51.2 (19936) | 1,500 s, 9.9 GB | 618 s, 4.0 GB |

It is built with the capstone and unicorn libraries of the Python
installation (`cmake -B build_flow`, which asks `py -3` where they are),
binds them when `flow` is called and finds the two DLLs next to
`mwdec.exe`; the other commands still need nothing. `--regions v1` leaves
pushed and called addresses out of the rule for code in section tails.
`remove_build.py --flow-exe build_flow\Release\mwdec.exe` and
`remove_all.py --flow-exe …` use it in place of the Python pass.

**TLS callbacks.** The protection adds no callback and owns none. It puts
its three start-up calls in front of the first one, behind a plain `jmp`,
and they run on every call of that callback, for every reason (process
attach, each thread attach and detach, process detach); after the first
time they do nothing. `devirt_boot.py` retargets the `jmp` to the
callback's body. The other callbacks are the game's and its anti-cheat's,
rewritten like any covered function (45% to 90% of their instructions
moved into the protection's section), and go through the flow pass like
other code. Every callback of 1.20, 1.30.0 and 1.51.2 was run in the
emulator for reasons 1, 2, 3 and 0, alone and after all process-attach
calls, in the protected image and in the export: 132 calls, the same
import calls, stops, return values and data in each
(`MWHook\tools\arxan\d11_tls_emu.py`; note `015_tls_callbacks_log.md`).
`remove_build.py` fails a build in which a callback's start-up calls could
not be taken off; none of the 15 builds looked at is one.

**Memory and running beside other things.** The images are 300 to 700 MB
and every step maps at least one, so the steps are written to hold one
copy and to work through it a stretch at a time:

- the emulated comparison maps each image copy-on-write from one file
  laid out by RVA (`<image>.rva`, written once by `disklab.flat_image`,
  sparse), so the pages nobody writes are the same physical pages in
  every shard, and the 300 to 460 MB of uninitialised data in the middle
  of an image is mapped a megabyte at a time when something touches it. A
  shard (two images) takes about 0.17 GB of its own where it took 1.1 GB;
- every tool sets `OPENBLAS_NUM_THREADS=1` before it imports numpy, whose
  math library otherwise reserves 31 MB per processor core on import (620
  MB of commit per Python process on 20 cores) for threads nothing here
  uses;
- `find_lists.py` keeps a range list as two arrays (`Ranges`, which reads
  like the list of pairs it replaced) and decodes a list in bulk: a build
  has 11 to 12.5 million ranges in about 200 lists, which as Python tuples
  was 1.3 GB a pass;
- `devirt_boot.py` and `check_dump.py` scan 8 or 16 MB at a time instead
  of turning a whole section into 64-bit numbers;
- `mwdec flow` lets go of the file once it is mapped and keeps its
  reference sets as sorted vectors.

| step, on 1.31.5 | peak memory before | after | seconds before | after |
|---|---:|---:|---:|---:|
| writers (`find_writers.py`) | 4.2 GB | 1.4 GB | 121 | 43 |
| boot plan (`devirt_boot.py`) | 5.1 GB | 0.95 GB | 24 | 10 |
| comparison, per shard | 1.1 GB | 0.17 GB | | |
| dump check (`check_dump.py`) | 2.5 GB | 0.2 GB committed | | 11 |
| flow (`mwdec flow`, on 1.20) | 2.67 GB | 2.44 GB | | |

(Writers, boot plan and the shard figure were measured on 1.30.0 after the
change and on 1.31.5 before it; the two builds are a week apart and the
same size.) The largest step left is `mwdec flow`: eight byte maps of the
code regions, one per walk, and some thirty bit sets of the same extent in
its last phase.

Time went the same way once it was measured. `mwdec flow` spent most of a
late build's ten minutes planning (411 of 567 s on 1.51.0), and all of that
in one helper: `Bits::any_range` answered "is any bit set in these 15
bytes?" by looking for the next set bit anywhere, megabytes away in the
sparse map of `--keep-plan` ranges, once per instruction of every disguised
branch. Reading only the words the range lies in: 22 to 46 s down to 1 s on
1.20, every output byte-identical, and on a late build (1.57.2) the whole
flow pass takes 138 s. The log now has a `plan phases:` line.
What is left, on 1.20: the two sweeps (31 s, 39 rounds each) and the
settling of the wipe (50 s).

`tools/lowmem.py` is the other half: `remove_build.py` and `remove_all.py`
put themselves and everything they start at below-normal priority, give
each step the memory it is known to need or wait until that much is free
(a game was started), take as many comparison shards as the free memory
and the cores allow (`--verify-shards auto`), and record each step's peak
working set and commit in `summary.json` (`peak_mb`). `mwdec flow --mem`
and `MWDEC_MEM=1` for `find_writers.py` print what the process holds at
each stage. `out\run_batch.ps1` runs from a snapshot of the tools and the
two executables (`out\snapshot\<time>`), so the tools can be worked on
while a run is under way.

**`remove_build.py`** runs everything for one shipped file: both layers,
imports, checks, routines (with what each publishes), the two plan tools,
`mwdec export`, and the two checks of the result.

**`mwdec remove SHIPPED.exe -o clean.exe --work DIR [--unlock-sections] [--full] [--keep-work]`**
does all of it in one process, and is what `remove_build.py --flow-exe`
runs (`--steps` runs the tools one by one instead, as the reference). The
shipped file is read once and each step hands its image and tables to the
next in memory; the writer finder, the checks, the routine table, the boot
plan and the junk constructs are C++ ports (`src/flow`) that write the same
files as the Python tools, byte for byte. Nothing is kept from one run to
the next: every export starts from the shipped file alone. The default
leaves out what only feeds a report or a proof (the flow pass's
report-only walks, the live map, the junk constructs' emulator proof);
`--full` puts them back, and `remove_build.py --full` adds the two
self-checks of the export. The flow pass runs its five walks of the
patched image side by side (the three with the routines' stubs on a
copy-on-write view of the image), judges each sweep round's gaps on all
cores, and in later sweep rounds looks again only at the gaps next to what
the last walk marked. On the three test builds the outputs are byte for
byte those of the step-by-step chain (`--full` also gives the same
`flow.json`); a cold export, shipped file to both executables:

| build | tools one by one | `mwdec remove` |
|---|---:|---:|
| 0.01.2 | 120 s | 31 s |
| 1.30.0 | 208 s | 59 s |
| 1.69.0 | 343 s | 107 s |

`remove_all.py` does that for every build of a
folder, one copy from the share at a time, delivers each cleaned
executable (to a folder, or with `scp`), deletes its local copies, and
keeps a row per build in `results.tsv`.

**`check_dump.py EXPORT.exe DUMP.exe [--dec DEC.exe]`** answers one
question: is everything in the export at the address a memory dump of the
same build has it at? A dump taken from the running game is the image as
Windows laid it out. Work done from a dump counts addresses from the start
of the image (base 0), which is an RVA, and an offset found that way has to
mean the same thing in the export. Both files are read by RVA through their
own section tables (a Scylla dump's header holds the address the game was
loaded at, and its file offsets are not always its RVAs). Compared:

- the layout: every section's RVA and its size in pages, `SizeOfImage`;
- pointers: at each relocation site of the export, its value minus the
  export's image base against the dump's value minus the address the dump
  was loaded at. Judged on read-only data, because `.data` moves as the
  game runs and the removal rewrites code that held pointers;
- the exception directory: one record per function piece, begin and end
  as RVAs. Each record of the export is looked for in the dump's
  directory wherever it sits there, not slot against slot: the export
  drops the record of a piece of protection code it removed from the
  game's code section, and every later record is then one slot earlier
  (1.59.1: one record of 126,534, `0x6CB966F`, at slot 111,309; slot
  against slot that read as 88% and failed the build);
- the game's code section byte for byte, and the first 16 bytes of every
  function;
- a control: the same byte count with the dump moved by 16 bytes and by a
  page either way.

On 1.51.2 (export against a Scylla dump of the running game, loaded at
`0x7FF6D7950000`): 9 of 9 sections; 78,973 of 78,973 pointers in read-only
data; 127,967 of 127,967 function records; 97.6% of 120,134,656 code bytes
the same at the same RVA against 3.5% to 4.5% with the dump moved; 98.3% of
function starts. With `--dec` the code is compared three ways: of the bytes
that differ, 1.57 MB are what the removal rewrote, and 1.28 MB are bytes
the removal left alone where the decrypted image and the dump disagree
(the tool prints their entropy on both sides: a dump is one moment of the
game, and what the protection had hidden again at that moment is noise in
it). `remove_all.py --dump-index <dump-index.json>` runs the check for
every build that has a dump and holds back a build whose addresses do not
match.

**The checks that run something** are in `MWHook\tools\arxan`, and they run
it in an emulator, never as a process.

- `d10_cross.py DEC.exe routines.json imports.tsv`: every routine of a
  build is entered the way its chain enters it, on the decrypted image,
  and what it writes above its entry `rsp` is compared with the table.
- `d10_cfg.py DEC.exe routines.json imports.tsv CFG\` writes the small
  tables the comparison harness needs for a build, from the image.
- `d10_verify.py DEC.exe CLEAN.exe CFG\ --checks checks.plan --tag NAME`
  runs function entries in both images from the same state, the
  protection's routines executing in the decrypted one, and compares what
  the program can see afterwards. Start lists: the functions that reach a
  folded construct or check (`devirt_flow.py --starts-out`) and a random
  sample. With the build's `checks.json` and `flow.json` in `CFG\` it also
  knows three ways in which a function entered at its top, with no history
  and filler for arguments, says nothing about the export, and gives each
  its own verdict instead of "different":
  - *the reference met a check before its guard*: every check's read of
    its published dword is hooked; when the protected side reads a value
    that is not the needed one and then ends on a fault without having
    made a call or entered a routine, it died on the check's failing path
    (a jump through a table of wrong addresses), which the program never
    takes. A check whose failing branch is the normal way on (1.20's
    `WinMain`) goes on into routines and calls, and is compared like any
    other path. A difference in an import call made before the check
    still counts;
  - *both images met a check before its guard*: the export keeps a check
    whose value is published at run time by a routine it also kept (1.59.1:
    18 of the 40 published dwords; the other 22 are stored in the file).
    Entered cold, both images fail that check after the same number of
    calls and both end on a fault, each through its own wrong address
    (the export's table is wiped), so what each runs into on the way is
    its own (1.59.1, `0x5C9EF70`: the protected side met a `GetLastError`
    before it faulted);
  - *stored stack bytes the function never wrote*: calls and stops equal,
    data bytes differ, and every one of those bytes changes when the
    export is run again with the stack below the function filled with
    another value (the padding of a structure built on the stack; in the
    protected run it holds what a routine left there);
  - *an index made of filler read bytes the export removed*: the export is
    run twice more with a hook on reads of bytes that are 0xCC in it and
    something else in the protected image, the second time with other
    filler in the argument buffers and in the registers nobody set. An
    address read under one filler and not under the other was computed
    from it. A read of removed bytes named by the instruction itself, or
    at an address that is read under both, stays a difference: those are
    bytes the export should have kept.
  The end-state comparison of data sections looks at the bytes either run
  changed, not at whole pages, and leaves out the protection's code
  regions in data sections (`extra_code_regions` of `flow.json`), which
  the protection decrypts and hides again as it runs. The dwords that
  guards publish live in code sections, so they are compared on their
  own: a value one side holds as needed at the end of a path and the
  other does not is a difference ("published").
  The random sample is taken from primary exception records that begin on
  a 16-byte boundary. A record that begins elsewhere, or whose unwind data
  is flagged as chained to another record, is a later piece of a function,
  an exception funclet, or a record laid over the middle of a construct,
  and is not something to enter with arguments (1.64.0: the chained record
  at `0x6D9BFD0` begins on a boundary and inside the `movabs` of a
  disguised jump; 3,856 of that build's 74,136 aligned records are
  chained).
  Between functions the lab restores the emulated processor's own state
  as well as memory: Unicorn remembers an exception nobody took, and
  reports the second divide error of one emulator instance as a double
  fault (interrupt 8 for interrupt 0), which made two labs that had met
  different numbers of them name the same stop differently (1.07.0).
  `remove_all.py --verify` delivers a build only when no function is
  "different", and withdraws an earlier delivery of a build that is.
- `d10_trace.py DEC.exe CLEAN.exe START` prints where the two runs of one
  function part ways.
- `d10_api.py DEC.exe CLEAN.exe START` lists the API calls one function
  makes in each image, with the text its arguments point at and the
  answers, and says where the two lists part.
- `d10_init.py IMAGE.exe --side reference|export --game-dir DIR -o LOG`
  starts one image at its entry point the way Windows does (TLS block and
  callbacks, then the C runtime), with a loader list and the real DLL
  files around it, and logs every static initialiser as `_initterm` calls
  it; `--at RVA --read RVA,…` prints dwords when an address is reached,
  and `--compare` puts two logs side by side. It is how the order "check,
  then guard" in `WinMain` was seen. Start-up code of later builds asks
  the kernel directly, so the emulator answers that too
  (`d10_api.py`): the file and memory services by their `Nt` names
  (`NtCreateFile`, `NtQueryInformationFile`, `NtReadFile`,
  `NtAllocateVirtualMemory`, `NtQuerySystemInformation` ...), and the
  `syscall` instruction itself, the service found by its number in the
  `Zw` stubs of the machine's `ntdll.dll` (the file the start-up reads the
  numbers from), whether the instruction is the program's own or the one
  at the end of a stub inside the mapped `ntdll`. Unanswered, the
  instruction did nothing and both images stopped at initialiser 43 of
  6,539 (1.30.0) or 49 of 6,950 (1.69.0) on a null pointer. Exceptions
  are delivered too: the protection's debugger probes register a vectored
  handler and execute `ud2`, and the lab builds the exception record and
  the context on the stack, enters the registered handlers in Windows'
  order and, on "continue execution", loads the registers from the
  context the handler was given (1.69.0's `main` reaches such a probe in
  the protected image after 145 routines). `--idle N` ends a run when N
  API calls in a row only wait or read the clock (the start-up has got as
  far as one thread goes), so both images end at the same call; a stretch
  that was cut short is compared as far as the shorter run went, by
  digests taken at 1, 2, 4 ... 128 calls and then every 256. The run ends
  with a count of the calls that had no model (answered 0, nothing
  written). `--blocks LO-HI [--blocks-from RVA] [--blocks-last]` prints
  the path of basic blocks through a range, loops folded.
  `remove_all.py --start-wall SECONDS` runs this for every build, both
  images side by side while the function comparison runs, records the
  number of stretches compared and where the start ended, and holds back
  a build whose two starts differ in any stretch.
- `d10_sel.py DEC.exe CLEAN.exe START --game-dir DIR` runs one function
  under each of the 256 values of the timestamp counter's low byte, which
  the protection's dispatchers branch on.
- `d10_win.py DEC.exe CLEAN.exe START --game-dir DIR` does the same for a
  function that finds its APIs by walking the process's module list. It
  gives the emulated process a loader list (`PEB->Ldr`) and maps the real
  DLL files as images that can be read and are never executed; a call that
  lands on one of their exports is answered like a call through the
  import table. `LoadLibrary` maps the DLL asked for, `GetProcAddress`
  answers from its export table, and the file calls read the disk.

`find_junk.py DEC.exe -o junk.plan [--plan EARLIER ...] [--prove N]` plans the removal of the protection's junk
constructs: `pushfq ; push R ; op R, imm ; call` back into that immediate (onto a short jump), a never-executed
fake epilogue with random bytes, then `pop R ; op R ... ; pop R ; popfq`. A never-protected build has none; 1.20
has 19,064 and 1.51.2 has 23,674, all in the game's code. Each candidate is checked instruction by instruction to
restore everything it touches, becomes a two-byte jump over itself, and its bytes are wiped unless a branch at
any offset, a pointer, an exception record or an earlier plan's patch refers into them. `--prove` runs N of them
(every instruction shape first) in an emulator from random state. `remove_build.py` runs it after the flow plans
and applies its plan last. Two later and earlier forms are taken as well. The oldest builds (0.01.2, 1.07.0, about
12,600 each) push the register alone and never save the flags, so their arithmetic leaves the flags changed: such
a construct is removed only where every path after it writes all six status flags before reading any (0.01.2:
12,568 by an instruction that writes them, 10 reach a call or `ret` first, which flags do not survive). From 1.69
on a filler that changes nothing sits between the two pops: a `nop` of any length, `xchg`/`mov` of a 64- or
16-bit register with itself (never 32-bit, which clears the upper half), `lea r64, [r64]` (1.69.0: 21,751 of
22,429). `--no-older` leaves the first form out. The few function pieces `check_functions.py` still calls noise after that begin with
a jump into the protection's section, where the function's body was moved, and hold fragments of the protection's
own code or unexecuted bytes behind it; each is byte for byte what the running game holds (1.51.2: four of ten
pieces were junk constructs, six are of this kind).

The static counts are not a substitute. The first 1.20 export passed all
of them and was wrong in two places (a check without its value; a return
thunk in `_RDATA` the walk did not know as code); the comparison found
both in three minutes.

## Checking the result

### Decryption

1. **Against the real routines.** The first TLS callback was run to the end
   of the protection's code in an emulator, on the shipped file. Its two
   code sections equal `mwdec decrypt --layer1-only` in all but 25 of
   224,083,968 bytes. The 25 are the routines' own bookkeeping: their "done"
   flags, the keystream state, and the first key word, which the decryptor
   overwrites when it finishes. MWDec's final keystream state equals the one
   the real routine leaves in memory.
2. **Against a memory dump.** After layer 1 the game's code section equals
   the dump in 99.05% of its bytes (3.67% before). The rest is code the
   running process had rewritten or encrypted again, and pages the dump
   could not read.
3. **Layer 2, against a dump.** The 59 functions produced by MWDec from the
   shipped file equal, byte for byte (883,737 bytes), the result of applying
   the same writers to the memory dump, which was itself checked against the
   emulated output of each writer.
4. **Layer 2, against the routines.** Every writer routine was run on the
   bootstrap-layer image and the entropy of its output compared with what
   it overwrote. 82 only put noise back, and are not applied. The output of the
   fifteen decryptors that a dump does not show (17,717 bytes) equals
   MWDec's in 17,717 of 17,717 bytes.

Counting 4 KB pages of the game's code that still look like noise (above 7.2
bits per byte): 29,094 of 29,329 in the shipped file, 251 after layer 1, 6
after layer 2. No routine that was found writes to those six.

### Removal

Every row is an emulator run on the final plans. "No verdict" means the
protected side did not get far enough to compare, never that the two sides
disagreed.

Each kind of rewrite, alone:

| rewrite | compared with | result |
|---|---|---|
| 1,251 import instructions retargeted | the function the old table named | 1,251 equal |
| 615 start-up chains skipped | the chain, from its first instruction to its exit | 615 equal |
| 730 routine replacements (53 bytes) | the real routine, from its call to the continuation | 730 equal |
| 309 nests folded into a jump | the shipped nest with the real routines running | 309 equal (260 in the first pass; 47 on a second run with another pinned timestamp and a new random state; 2 with a longer time limit) |
| 183,544 disguised branches rewritten | the shipped idiom: one of each of 1,605 shapes plus a sample, 4,585 idioms, 42,717 runs | all equal |
| 113,572 stack pairs rewritten | the shipped pair: 24,610 pairs over 22,202 shapes | all equal |
| 55 checks folded | the shipped check on the stored values | 55 equal |

Whole functions, exported image against the decrypted image with its
protection running (`tools/arxan/d9_verify_export.py` in MWHook). Compared:
the sequence of import calls with arguments, stack pointer and non-volatile
registers, and the end state (return value, changed data pages, heap,
argument buffers).

| functions run | how many | equal | of those, ran to return | no verdict | different |
|---|---:|---:|---:|---:|---:|
| the entry path | 1 | 1 | 0 | 0 | 0 |
| every function that reaches a routine call site, a folded nest or a folded check | 170 | 161 | 47 | 9 | 0 |
| a random sample of function entries (seed 1) | 3,000 | 2,987 | 449 | 13 | 0 |
| a second sample (seed 7), arguments full of pointers | 3,000 | 2,940 | 615 | 60 | 0 |

All 82 runs without a verdict are the protected side running out of time
(20 s per function in the second row, 6 s in the samples). An equal run
that did not return stopped at the same instruction in the same state on
both sides. The protected side made 498 routine calls in the second row.

The protected side has to be made repeatable before these numbers mean
anything: the protection draws random numbers from `rdtsc`, including
from `rdtsc` instructions it writes into its own code at run time, and
picks a debugger probe with them. `d9_e2e.py` pins both kinds and, where
the protected side ends at a probe that raises an exception the emulator
cannot deliver, runs the function again with the next of a fixed list of
timestamp values (7 of the 170 needed that).

Static checks on the exported file (`tools/check_clean.py`): checksum
correct; 208,359 relocation entries, all pointing into the image; no
reference to the second import table; no string blob still flagged
encrypted; no start-up chain in front of the entry point or a TLS
callback. In code the walk reaches: 1 routine call site and 598
`jmp [rsp-8]`. In the whole file, kept code included: 426 and 55,304.

## Limits

- One build has a profile, and neither decryption nor removal needs one:
  everything `remove_build.py` uses is read from the shipped file. What
  differs between builds is how much of the result has been checked.
  For 19936 the tables read from the file equal the measured ones and the
  plans come out patch for patch, and the measured export was compared
  with the protected image in an emulator function by function. For 1.20
  the routine table was checked against the routines themselves in an
  emulator (595 of 613 returned and agree, none disagrees). For any other
  build the checks are the static ones the tools make on every run: three
  consecutive slots per routine, the slot number against the chain, and
  the counts of `check_clean.py` and `check_functions.py` on the export.
- A table read from the code does not know what a routine leaves in
  registers its chain does not save, so `devirt_flow.py` folds a construct
  only where `rax, rcx, rdx, r8-r11` (less the ones saved) are dead after
  it. On 19936 that costs one fold of 309.
- Builds other than 19936 have no reference image. "Decrypts completely"
  means no page of game code is left above 7.2 bits per byte with under
  30% common code bytes; it does not mean every byte was compared with
  anything.
- The exported image has been compared with the protected one in an
  emulator. The comparison reaches the game's own code only as far as an
  emulator without a GPU, a file system or a network gets.
- One export has been started as a process: 1.20's. It shows the splash
  screen, then the game's window, and goes on to the same name lookups the
  shipped file makes (four starts of four; the back end the game then
  waits for was not running, so nothing past that is known). A retail
  build of that age needs help unrelated to the protection on a current
  Windows: its 31st static initialiser (`0x383F80`) lays `gdi32.dll` out
  as a private image and calls that copy's `GdiDllInitialize`, which is
  now a delay-load stub that cannot resolve for an image the loader does
  not know, and the process executes address 0. The shipped file does the
  same (in the emulator, `d10_win.py`, and in Windows' crash history on
  the test machine). The test ran with an exception handler in the
  process that repairs that one fault, started as the game is started
  (`ModernWarfare.exe -uid …`).
- The real start found three things the emulated comparison had passed
  over, all now rules of the tools:
  - *A published value is an event.* A guard writes its dword when its
    construct runs, and a check can be placed before its guard so that
    its failing branch is the normal path (1.20's `WinMain` sets a flag on
    it and returns 0 without the flag). `find_routines.py --checks`
    records which routine stores which published dword; only values that
    hold from the start are baked; a construct whose routine publishes is
    not folded and nothing is aimed past it; the routine's replacement
    stores the value; checks that read it stay as shipped.
  - *Blocks behind junk.* A block reached only by a computed jump sits
    behind a five-byte `jmp` with junk on both sides, which no linear
    decode reads. The planner searches every unwalked, unwiped byte for a
    direct branch or a `lea rbp,[rip+X] ; xchg [rsp],rbp` at any offset
    and keeps wiped targets (1.20: 1,651).
  - *Pointers in the code section.* A relocated qword in kept code must
    not point at a wiped byte (1.20: 799).
  All three are in `mwdec flow` and in `devirt_flow.py`. The two were
  equal byte for byte before these rules; they have not been compared
  since, and the archive run uses `mwdec flow`.
- Of 1.20's 40 published dwords, 20 had no storing routine found by the
  static walk and are still baked from the start. 15 of them have no
  `mov [rip+P], r32` anywhere in the image and no pointer to them either,
  so how they are written is not known; the export runs with them baked.
- A failing check's table is wiped. A check that is left as shipped keeps
  its three operands and its key, and loses the four table entries its
  failing path indexes, because no walk reaches them as data of that size.
  The program never reads them. A comparison that enters a function cold
  does (see `d10_verify.py`).
- The export is not free of the protection's bytes. A static walk does not
  follow computed jumps, and the game's anti-cheat is built on them. Code
  found behind them by layout, with everything it reaches, is kept exactly
  as shipped: 8.9 MB, holding 60,869 disguised branches, 59,790 stack pairs
  and 344 routine call sites. 32.1 MB of the protection's 103.9 MB section
  stay (walked code, kept code, patches, data), and the protection's import
  descriptor stays because 1,308 kept instructions load its slots.
- Some of what the walk reaches is not code: it follows branches that are
  never taken. At least 5.6% of the 16.9 MB it reaches in the protection's
  section is reached only through an instruction that cannot be real.
- About 8.3 MB of the protection's section is wiped on a rule about how far
  a data reference extends (a sized read keeps its operand size; an address
  taken keeps up to the next address taken, the next code byte or 64 KB).
  The rule is not proven.
- The emulator has no page protections. 378 instructions in walked code
  store into a code section; whether any of them is real is not known. Use
  `--unlock-sections` for a first run as a process.
- 15 of the 40 published values come from the arithmetic of the checks that
  read them, not from a run of the routine that publishes them.
- Six 4 KB pages of build 19936's game code look like noise after both
  layers. Two of them hold the encoded copies (stashes) of two writers,
  which the protection keeps inside the game's code section, so they are
  noise by design. Three are touched by no writer. None is the target of
  a writer that was missed.
- The engine also replaces console-variable names with hashes at build
  time. That is not encryption and there is nothing to decrypt.
- The game's anti-cheat is out of scope. MWDec does not analyse or modify
  it.

The research notes behind every number here are in the MWHook repository
under `docs/research` (`008` to `013`).
