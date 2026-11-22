"""Removal pass, part 1: the start-up path and the import tables.

Input: an executable decrypted by `mwdec decrypt`, and the listing written
by `mwdec imports`. Output: a patch plan for `mwdec export`. Nothing is run.

What it restores:

  * Entry point. The protection redirected the first `call` of the
    compiler's entry point to a thunk that runs its start-up routines and
    then tail-jumps to the function the call originally named. The call is
    pointed back at that function.

  * TLS callbacks. A callback that begins with start-up routine calls gets
    its first jump pointed straight at its own first instruction.

  * Imports. The file has two import address tables; the loader fills one
    and a start-up routine copies it to the other. Every reference to the
    second table (code or relocated data pointer) is retargeted to the
    loader's table, so the copy is no longer needed.

    py -3 devirt_boot.py modernwarfare.dec.exe --imports imports.tsv -o boot.plan [--report boot.json]
"""
from __future__ import annotations

import argparse
import json
import os
import struct
import sys

import capstone
import os as _os
_os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")    # numpy's math library reserves 31 MB a core when loaded; nothing here uses it
import numpy as np
from capstone import x86_const as X

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, ".."))
from entry_layout import Walker, fold  # noqa: E402
from mwdec.pe import Image  # noqa: E402
from planfile import KIND_BOOT, KIND_IMPORT, Plan  # noqa: E402


def continuation(walker: Walker, start: int):
    """If the path from `start` opens with routine call chains, return the
    address where the original code resumes after the last one; else None."""
    rows = walker.walk(start)
    lines = fold(rows)
    if not lines or not lines[0][1].startswith("; save context"):
        return None, 0
    last = max(i for i, l in enumerate(lines) if l[1].startswith("; restore context"))
    calls = sum(1 for l in lines[:last] if l[2] in ("call", "ccall"))
    if last + 1 >= len(lines):
        return None, calls
    rva, text, kind = lines[last + 1]
    if kind == "cjmp":                     # the resume point is a disguised jump
        for r, t, k, extra in rows:
            if r == rva and k == "cjmp":
                return extra, calls
    if kind == "fold":
        return None, calls
    return rva, calls


def boot_patches(im: Image, plan: Plan, report: dict):
    w = Walker(im, {})
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True

    # ---- entry point: first call within the first few instructions --------
    pc = im.entry_rva
    for _ in range(4):
        i = next(md.disasm(bytes(im.mem[pc:pc + 16]), pc), None)
        if i is None:
            break
        if i.mnemonic == "call" and i.operands[0].type == X.X86_OP_IMM and i.size == 5:
            thunk = i.operands[0].imm
            callee, calls = continuation(w, thunk)
            if callee is not None:
                plan.patch(pc + 1, struct.pack("<i", callee - (pc + 5)), KIND_BOOT)
                report["entry_point"] = {"call_site": pc, "thunk": thunk, "routines_called": calls,
                                         "original_callee": callee}
            else:
                report["entry_point"] = {"call_site": pc, "thunk": thunk, "note": "call target is not a thunk"}
            break
        pc += i.size

    # ---- TLS callbacks ----------------------------------------------------
    report["tls"] = []
    for n, cb in enumerate(im.tls_callbacks()):
        body, calls = continuation(w, cb)
        row = {"index": n, "callback": cb, "routines_called": calls, "body": body}
        if body is not None:
            if im.mem[cb] == 0xE9:
                plan.patch(cb + 1, struct.pack("<i", body - (cb + 5)), KIND_BOOT)
                row["patched"] = True
            else:
                row["patched"] = False
                row["note"] = "callback does not begin with jmp rel32"
        report["tls"].append(row)


def import_patches(im: Image, tsv: str, plan: Plan, report: dict):
    alias = {}
    for line in open(tsv, encoding="utf-8").read().splitlines()[1:]:
        f = line.split("\t")
        if len(f) >= 4 and f[1]:
            alias[int(f[1], 16)] = (int(f[0], 16), f[2], f[3])
    if not alias:
        report["imports"] = {"note": "no aliased slots"}
        return
    lo, hi = min(alias), max(alias) + 8
    slots = np.array(sorted(alias), dtype=np.int64)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True

    by_mnem: dict[str, int] = {}
    rejected = 0
    patched_sites = set()
    # Every 4-byte field of the code read as a displacement, 8 MB of code
    # at a time. (The whole section at once, as 64-bit numbers, was nine
    # arrays of 900 MB on a late build: 5 GB for a step of 24 seconds.)
    CH = 1 << 23
    for s in im.exec_sections():
        size = min(s.rsize, s.vsize)
        cand = set()
        for c0 in range(0, size - 3, CH):
            cnt = min(CH, size - 3 - c0)    # fields that begin in this stretch
            buf = np.frombuffer(im.mem, dtype=np.uint8, count=cnt + 3, offset=s.rva + c0)
            disp = (buf[:-3].astype(np.uint32) | (buf[1:-2].astype(np.uint32) << 8) |
                    (buf[2:-1].astype(np.uint32) << 16) | (buf[3:].astype(np.uint32) << 24)).view(np.int32)
            pos = np.arange(cnt, dtype=np.int64) + (s.rva + c0)
            base = pos + disp
            for imm in (0, 1, 2, 4):        # bytes of immediate after the displacement
                tgt = base + (4 + imm)
                hit = np.nonzero((tgt >= lo) & (tgt < hi))[0]
                if len(hit):
                    hit = hit[np.isin(tgt[hit], slots)]
                    cand.update(pos[hit].tolist())
        for p in sorted(cand):
            ok = False
            for back in range(1, 12):
                st = p - back
                i = next(md.disasm(bytes(im.mem[st:st + 16]), st), None)
                if i is None or i.disp_offset != back or i.disp_size != 4:
                    continue
                tgt = None
                for op in i.operands:
                    if op.type == X.X86_OP_MEM and op.mem.base == X.X86_REG_RIP:
                        tgt = st + i.size + op.mem.disp
                if tgt in alias:
                    new = alias[tgt][0] - (st + i.size)
                    if -(1 << 31) <= new < (1 << 31) and p not in patched_sites:
                        plan.patch(p, struct.pack("<i", new), KIND_IMPORT)
                        patched_sites.add(p)
                        by_mnem[i.mnemonic] = by_mnem.get(i.mnemonic, 0) + 1
                    ok = True
                    break
            rejected += not ok

    # relocated data pointers that name a slot of the second table
    relocs = im.relocations()
    data_ptrs = 0
    for r in relocs:
        r = int(r)
        v = im.u64(r) - im.image_base
        if v in alias:
            plan.patch(r, struct.pack("<Q", im.image_base + alias[v][0]), KIND_IMPORT)
            data_ptrs += 1

    # image-relative uses ([base + index + disp32] with disp32 == slot RVA): report only
    abs_hits = 0
    slots32 = slots.astype(np.uint32)
    for s in im.exec_sections():
        size = min(s.rsize, s.vsize)
        for al in range(4):
            n = (size - al) // 4
            for c0 in range(0, n, CH):
                v = np.frombuffer(im.mem, dtype="<u4", count=min(CH, n - c0), offset=s.rva + al + 4 * c0)
                v = v[(v >= lo) & (v < hi)]
                if len(v):
                    abs_hits += int(np.isin(v, slots32).sum())
    report["imports"] = {"aliased_slots": len(alias), "code_references_retargeted": len(patched_sites),
                         "by_instruction": by_mnem, "candidates_rejected_by_decode": rejected,
                         "data_pointers_retargeted": data_ptrs,
                         "image_relative_candidates_not_patched": abs_hits}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("exe")
    ap.add_argument("--imports", required=True, help="TSV written by `mwdec imports`")
    ap.add_argument("-o", "--out", required=True)
    ap.add_argument("--report")
    a = ap.parse_args()
    im = Image(a.exe)
    plan = Plan()
    report: dict = {}
    boot_patches(im, plan, report)
    import_patches(im, a.imports, plan, report)
    plan.save(a.out)
    print(plan.summary())
    print(json.dumps(report, indent=1, default=lambda x: hex(x) if isinstance(x, int) else str(x))[:3000])
    if a.report:
        json.dump(report, open(a.report, "w"), indent=1)


if __name__ == "__main__":
    main()
