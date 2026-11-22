"""The values the checksum guards publish, read from the checks that use them.

    py -3 tools\\find_checks.py decrypted.exe -o checks.plan [--json checks.json] [--compare other.plan]

Input: an image with both layers off. Nothing is run.

A guard stores its digest in a dword of code memory. Elsewhere, game code
that the protection has woven a check into reads that dword and combines
it with constants of its own:

    mov r, [rip+P] ; add r, [rip+A] ; xor r, [rip+B]      (or sub)
    mov r, [rip+P] ; xor r, [rip+B]                       (or sub)

and then uses the result as a stack adjustment or a branch condition that
has to come out as zero. So the value the guard must have published is in
the check itself: B - A, or B. With the guards gone, those values are
written into the file ("baked"), and each check sees what it expects.

The plan this writes holds one 4-byte patch per published dword whose
value in the file is not already the needed one.
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, ".."))
import find_writers as FW  # noqa: E402
import planfile  # noqa: E402
from mwdec.pe import Image  # noqa: E402

MOV = re.compile(b"(?=\x8B[\x05\x0D\x15\x1D\x25\x2D\x35\x3D])", re.S)     # mov r32, [rip+d32], any register
RIP_DWORD = re.compile(r"^(\w+), dword ptr \[rip ([+-]) (0x[0-9a-f]+|\d+)\]$")
USES = ("add rsp", "j", "cmov", "push rbp", "lea rsp", "mov qword ptr [rsp - 8]")


def scan(im: Image, st: FW.Stream | None = None):
    """Every slot-check sequence: dicts with at, P, A, B, op, need, static, use."""
    st = st or FW.Stream(im)
    size = im.size_of_image
    mem = im.mem

    def u32(a):
        return struct.unpack_from("<I", mem, a)[0]

    def s32(b):
        return int.from_bytes(b, "little", signed=True)

    code = st.code

    def plain(pc):
        """(address, instruction) of the first instruction at or after pc
        that is not a joining jump. Read as written, not through the idiom
        resolver: the use of a check's result may itself be the first
        instruction of a disguised branch."""
        for _ in range(8):
            d = code.insn(pc) if code.in_code(pc) else None
            if d is None:
                return None
            if d[1] == "jmp" and d[2].startswith("0x"):
                pc = int(d[2], 16)
                continue
            return pc, d
        return None

    def rip_dword(pc, d, mnems):
        """(register, address) when d is `<mnem> r32, dword ptr [rip+x]`."""
        if d[1] not in mnems:
            return None
        m = RIP_DWORD.match(d[2])
        if not m:
            return None
        disp = int(m.group(3), 0)
        return m.group(1), pc + d[0] + (disp if m.group(2) == "+" else -disp)

    # The three instructions of a check are usually adjacent, but the
    # protection cuts its code into pieces anywhere: build 1.20 has checks
    # with a joining jump after the `mov` (found when an export of that
    # build took a check's failure path in the emulator: the value had not
    # been baked). So the sequence is read through joining jumps. A cheap
    # test on the bytes after the `mov` (another instruction on the same
    # register, or a jump) keeps the decoding to the places that can match.
    out = []
    for lo, hi in code.ex:
        buf = bytes(mem[lo:hi])
        for mt in MOV.finditer(buf):
            o = mt.start()
            nb = buf[o + 6:o + 8]
            if len(nb) < 2 or not ((nb[0] in (0x03, 0x33, 0x2B) and nb[1] == buf[o + 1]) or nb[0] == 0xE9):
                continue
            a = lo + o
            d1 = code.insn(a)
            r1 = rip_dword(a, d1, ("mov",)) if d1 else None
            if r1 is None:
                continue
            reg, P = r1
            nx = plain(a + d1[0])
            if nx is None:
                continue
            pc, d = nx
            A = None
            r2 = rip_dword(pc, d, ("add",))
            if r2 is not None and r2[0] == reg:
                A = r2[1]
                nx = plain(pc + d[0])
                if nx is None:
                    continue
                pc, d = nx
            r3 = rip_dword(pc, d, ("xor", "sub"))
            if r3 is None or r3[0] != reg:
                continue
            B = r3[1]
            if not all(0 <= x <= size - 4 for x in (P, B) + ((A,) if A is not None else ())):
                continue
            # The published dword and the check's constants sit in code: a
            # guard stores into code memory, and the protection keeps its
            # constants between instructions. The same three instructions on
            # variables in a data section are the game's own arithmetic
            # (of 2,440 sequences over 46 builds two are that: `mov ; xor ; js`
            # on two dwords of .data in 1.59.0, and one ending in `jbe` in
            # 1.65.1. Every other build has 53 sequences on 40 dwords.)
            if not all(code.in_code(x) for x in (P, B) + ((A,) if A is not None else ())):
                continue
            nx = plain(pc + d[0])
            use = ("%s %s" % (nx[1][1], nx[1][2])) if nx else None
            if not use or not use.startswith(USES):
                continue
            need = ((u32(B) - u32(A)) & 0xFFFFFFFF) if A is not None else u32(B)
            out.append({"at": a, "P": P, "A": A, "B": B, "op": d[1], "need": need, "static": u32(P), "use": use,
                        "cut": pc != a + (12 if A is not None else 6)})
    return out


def values(checks):
    """{P: need} and the Ps that two checks disagree about."""
    need, ats, bad = {}, collections.defaultdict(list), {}
    for c in checks:
        if c["P"] in need and need[c["P"]] != c["need"]:
            bad.setdefault(c["P"], set()).update((need[c["P"]], c["need"]))
            continue
        need[c["P"]] = c["need"]
        ats[c["P"]].append(c["at"])
    for p in bad:
        need.pop(p, None)
    return need, ats, bad


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("exe")
    ap.add_argument("-o", "--out", help="plan to write")
    ap.add_argument("--json", help="every check found, as JSON")
    ap.add_argument("--compare", help="a plan to compare the baked values with")
    a = ap.parse_args()
    im = Image(a.exe)
    checks = scan(im)
    need, ats, bad = values(checks)
    uses = collections.Counter(c["use"].split()[0] + (" rsp" if " rsp" in c["use"] else "") for c in checks)
    # Every needed value goes into the plan, also where the file already
    # holds it: the plan then lists every dword a check reads, and
    # devirt_flow treats exactly those as constants.
    plan = planfile.Plan()
    already = 0
    for P in sorted(need):
        already += struct.unpack_from("<I", im.mem, P)[0] == need[P]
        plan.patch(P, struct.pack("<I", need[P]), planfile.KIND_BAKE)
    print("checks: %d sequences on %d published dwords (%s); already holding the needed value: %d; changed by "
          "the plan: %d; two checks disagreeing: %d; sequences cut by a joining jump: %d" % (
              len(checks), len(need) + len(bad), dict(uses), already, len(need) - already, len(bad),
              sum(1 for c in checks if c.get("cut"))))
    if a.out:
        plan.save(a.out)
        print("wrote", a.out)
    if a.json:
        with open(a.json, "w") as f:
            json.dump({"checks": [dict(c, at="0x%x" % c["at"], P="0x%x" % c["P"],
                                       A=("0x%x" % c["A"]) if c["A"] is not None else None, B="0x%x" % c["B"],
                                       need="0x%08x" % c["need"], static="0x%08x" % c["static"]) for c in checks],
                       "disagree": {"0x%x" % p: ["0x%08x" % v for v in sorted(vs)] for p, vs in bad.items()}}, f,
                      indent=1)
    if a.compare:
        other = {rva: data for rva, kind, data in planfile.Plan.load(a.compare).patches if kind == planfile.KIND_BAKE}
        mine = {rva: data for rva, kind, data in plan.patches}
        same = sum(1 for r in mine if other.get(r) == mine[r])
        print("against %s: %d equal, %d of mine it lacks, %d of its I lack, %d at the same place with another value" % (
            os.path.basename(a.compare), same, sum(1 for r in mine if r not in other),
            sum(1 for r in other if r not in mine), sum(1 for r in mine if r in other and other[r] != mine[r])))
        for r in sorted(set(mine) ^ set(other))[:12]:
            print("   %08X mine %s theirs %s  checks at %s" % (
                r, mine[r].hex() if r in mine else "-", other[r].hex() if r in other else "-",
                ["%08X" % x for x in ats.get(r, [])]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
