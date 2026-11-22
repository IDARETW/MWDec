"""List the protection's own strings: the "two-pad" strings.

Input: an executable already decrypted by `mwdec decrypt`. Nothing is run.

The protection needs a handful of names at run time (a module and an export
to look up). It never stores them. Each use site carries two byte arrays of
the same length and a length dword, all three inside a code section, and the
name is their XOR:

    lea  r, [rip + padA]  ; mov [frame], r
    lea  r, [rip + padB]  ; mov [frame], r
    mov  r32, [rip + len]
    ...  out[i] = padA[i] ^ padB[i]

Every site has its own pair of pads, so no two sites share bytes even when
they decode to the same name. Finding a site needs a disassembler, because
the instructions above are scattered and joined by jumps; that is why this
is a script and not part of the native tool.

    py -3 arxan_strings.py modernwarfare.dec.exe [-o arxan_strings.tsv]
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from collections import Counter, defaultdict

import capstone
from capstone import x86_const as X

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from mwdec.pe import Image  # noqa: E402

# lea r64,[rip+d] immediately followed by mov [rbp+d], r64
LEA_MOV = re.compile(
    rb"[\x48\x4C]\x8D[\x05\x0D\x15\x1D\x25\x2D\x35\x3D]....[\x48\x4C]\x89"
    rb"[\x45\x4D\x55\x5D\x65\x6D\x75\x7D\x85\x8D\x95\x9D\xA5\xAD\xB5\xBD]", re.DOTALL)
PRINTABLE = set(range(32, 127))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("exe")
    ap.add_argument("-o", "--out")
    a = ap.parse_args()

    im = Image(a.exe)
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    cs.detail = True

    def rip_target(i):
        for op in i.operands:
            if op.type == X.X86_OP_MEM and op.mem.base == X.X86_REG_RIP:
                return i.address + i.size + op.mem.disp
        return None

    def walk(rva, n):
        out = []
        while len(out) < n:
            i = next(cs.disasm(bytes(im.mem[rva:rva + 16]), rva, 1), None)
            if i is None:
                break
            if i.mnemonic == "jmp" and i.operands[0].type == X.X86_OP_IMM:
                rva = i.operands[0].imm
                continue
            out.append(i)
            if i.mnemonic in ("ret", "int3"):
                break
            rva += i.size
        return out

    found = {}
    sites = defaultdict(set)
    for s in im.exec_sections():
        data = bytes(im.mem[s.rva:s.rva + min(s.rsize, s.vsize)])
        for m in LEA_MOV.finditer(data):
            site = s.rva + m.start()
            ins = walk(site, 14)
            leas = [rip_target(i) for i in ins if i.mnemonic == "lea" and rip_target(i) is not None]
            if len(leas) < 2:
                continue
            len_at = next((rip_target(i) for i in ins
                           if i.mnemonic == "mov" and i.operands[0].type == X.X86_OP_REG
                           and i.operands[0].size == 4 and rip_target(i)), None)
            if len_at is None or not 0 <= len_at < len(im.mem) - 4:
                continue
            n = im.u32(len_at)
            pa, pb = leas[0], leas[1]
            if not 1 <= n <= 1024 or max(pa, pb) + n > len(im.mem) or min(pa, pb) < 0:
                continue
            text = bytes(x ^ y for x, y in zip(im.read(pa, n), im.read(pb, n))).rstrip(b"\0")
            if len(text) < 3 or any(c not in PRINTABLE for c in text):
                continue
            found[(pa, pb)] = (len_at, n, text.decode("ascii"))
            sites[(pa, pb)].add(site)

    lines = ["pad_a\tpad_b\tlength_at\tlength\tsites\ttext"]
    for (pa, pb), (len_at, n, text) in sorted(found.items()):
        lines.append("%08X\t%08X\t%08X\t%d\t%d\t%s" % (pa, pb, len_at, n, len(sites[(pa, pb)]), text))
    count = Counter(t for _, _, t in found.values())
    print("%d pad pairs; distinct strings:" % len(found))
    for t, c in count.most_common():
        print("  %5d  %s" % (c, t))
    if a.out:
        open(a.out, "w", encoding="utf-8").write("\n".join(lines) + "\n")
        print("wrote", a.out)


if __name__ == "__main__":
    main()
