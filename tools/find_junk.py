"""Find the protection's junk constructs in a decrypted image and plan their removal.

    py -3 -I find_junk.py DEC.exe -o junk.plan [--report junk.json] [--plan EARLIER.plan ...] [--prove N]

The construct is a stretch of 34 to 47 bytes that does nothing, built so
that a disassembler reading straight through it goes wrong:

    pushfq ; push R              (in either order)
    op R, imm                    the immediate holds the two bytes EB d8
    call  back into that immediate
    <a believable epilogue and a few random bytes, never executed>
    pop R                        the call's return address, thrown away
    op R, imm ...                more arithmetic on the scratch register
    pop R ; popfq                (in the reverse order of the pushes)

The call lands on `EB d8`, a short jump over the bytes that are never
executed, and what follows puts the register and the flags back. Nothing
else is touched. A build that was never protected has none of these; a
protected one has about twenty thousand, all in the game's own code.

Two other forms are taken too. The oldest builds (0.01.2, 1.07.0) push the
register alone and do not save the flags, so their arithmetic leaves the
flags changed: such a construct counts only where every path after it
writes all six status flags before it reads any (flags_after; a call or a
`ret` ends a path, since flags do not survive a call). From 1.69 on, a
filler that changes nothing (a nop of any length, `xchg`/`mov` of a 64- or
16-bit register with itself, `lea r64, [r64]`) may sit between the pops.

Each candidate is checked instruction by instruction before it counts:
the pushes are exactly the flags and one register, every instruction in
between writes only that register and the flags, the pops undo the pushes
in order, and no arithmetic comes after the flags or the register were put
back. A construct that passes is replaced by a two-byte `jmp` over itself.
Its remaining bytes are filled with int3 when nothing else in the image
refers into them (a branch encoded at any offset, a relocated pointer, an
exception record that begins inside, or a patch of an earlier plan);
otherwise they are left as they are and only the jump is written.

`--prove N` runs N of the accepted constructs (one of every distinct
instruction shape first) in an emulator from random registers and flags and
checks that everything is as it was when execution reaches the end.
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import random
import re
import struct
import sys

os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")
import numpy as np
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone import x86_const as X

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import check_dump as C  # noqa: E402
import planfile  # noqa: E402

CALL_BACK = re.compile(rb"\xE8[\xF0-\xFB]\xFF\xFF\xFF")
ARITH = {X.X86_INS_MOV, X.X86_INS_MOVABS, X.X86_INS_ADD, X.X86_INS_SUB, X.X86_INS_XOR, X.X86_INS_OR, X.X86_INS_AND,
         X.X86_INS_ADC, X.X86_INS_SBB, X.X86_INS_ROL, X.X86_INS_ROR, X.X86_INS_SHL, X.X86_INS_SHR, X.X86_INS_SAR,
         X.X86_INS_NOT, X.X86_INS_NEG, X.X86_INS_INC, X.X86_INS_DEC, X.X86_INS_BSWAP, X.X86_INS_IMUL}
NO_FLAGS = {X.X86_INS_MOV, X.X86_INS_MOVABS, X.X86_INS_NOT, X.X86_INS_BSWAP}
STATUS = (("CF", X.X86_EFLAGS_TEST_CF, (X.X86_EFLAGS_MODIFY_CF, X.X86_EFLAGS_RESET_CF, X.X86_EFLAGS_SET_CF,
                                        X.X86_EFLAGS_UNDEFINED_CF)),
          ("PF", X.X86_EFLAGS_TEST_PF, (X.X86_EFLAGS_MODIFY_PF, X.X86_EFLAGS_RESET_PF, X.X86_EFLAGS_SET_PF,
                                        X.X86_EFLAGS_UNDEFINED_PF)),
          ("AF", X.X86_EFLAGS_TEST_AF, (X.X86_EFLAGS_MODIFY_AF, X.X86_EFLAGS_RESET_AF, X.X86_EFLAGS_SET_AF,
                                        X.X86_EFLAGS_UNDEFINED_AF)),
          ("ZF", X.X86_EFLAGS_TEST_ZF, (X.X86_EFLAGS_MODIFY_ZF, X.X86_EFLAGS_RESET_ZF, X.X86_EFLAGS_SET_ZF,
                                        X.X86_EFLAGS_UNDEFINED_ZF)),
          ("SF", X.X86_EFLAGS_TEST_SF, (X.X86_EFLAGS_MODIFY_SF, X.X86_EFLAGS_RESET_SF, X.X86_EFLAGS_SET_SF,
                                        X.X86_EFLAGS_UNDEFINED_SF)),
          ("OF", X.X86_EFLAGS_TEST_OF, (X.X86_EFLAGS_MODIFY_OF, X.X86_EFLAGS_RESET_OF, X.X86_EFLAGS_SET_OF,
                                        X.X86_EFLAGS_UNDEFINED_OF)))


def family(name):
    """The 64-bit register a register name is part of."""
    m = re.fullmatch(r"r(\d+)[dwb]?", name)
    if m:
        return "r" + m[1]
    m = re.fullmatch(r"[re]?([abcd])x|([abcd])[lh]", name)
    if m:
        return "r" + (m[1] or m[2]) + "x"
    m = re.fullmatch(r"[re]?(si|di|bp|sp)l?", name)
    return "r" + m[1] if m else None


class Finder:
    def __init__(self, path, older=False):
        self.im = C.Img(path)
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md.detail = True
        self.older = older

    def one(self, b, off, rva):
        return next(self.md.disasm(b[off:off + 15], rva, 1), None)

    def scratch(self, ins, reg):
        """Arithmetic on `reg` and the flags only: no memory, no other register."""
        if ins.id not in ARITH or not ins.operands or ins.operands[0].type != X.X86_OP_REG:
            return False
        for op in ins.operands:
            if op.type == X.X86_OP_REG:
                if family(ins.reg_name(op.reg)) != reg:
                    return False
            elif op.type != X.X86_OP_IMM:
                return False
        return True

    def push_of(self, ins):
        if ins.id == X.X86_INS_PUSHFQ:
            return "flags"
        if ins.id == X.X86_INS_PUSH and len(ins.operands) == 1 and ins.operands[0].type == X.X86_OP_REG:
            name = ins.reg_name(ins.operands[0].reg)
            return name if family(name) == name and name != "rsp" else None
        return None

    def pop_of(self, ins):
        if ins.id == X.X86_INS_POPFQ:
            return "flags"
        if ins.id == X.X86_INS_POP and len(ins.operands) == 1 and ins.operands[0].type == X.X86_OP_REG:
            return ins.reg_name(ins.operands[0].reg)
        return None

    def at_call(self, b, base, c, why):
        """The construct whose `call` is at offset c of b, or None. (start, end, register, shape)"""
        t = c + 5 + struct.unpack_from("<i", b, c + 1)[0]
        if b[t] != 0xEB or not 0 < b[t + 1] < 0x80:
            why["the call does not land on a short jump"] += 1
            return None
        cont = t + 2 + b[t + 1]
        if cont <= c + 5:
            why["the short jump does not pass the call"] += 1
            return None
        for s_op in range(c - 2, c - 11, -1):
            op = self.one(b, s_op, base + s_op)
            if op is None or op.size != c - s_op or not s_op < t:
                continue
            for k in (2, 3):
                p1 = self.one(b, s_op - k, base + s_op - k)
                if p1 is None or p1.size >= k:
                    continue
                p2 = self.one(b, s_op - k + p1.size, base + s_op - k + p1.size)
                if p2 is None or p1.size + p2.size != k:
                    continue
                pushes = [self.push_of(p1), self.push_of(p2)]
                if "flags" not in pushes or None in pushes or pushes[0] == pushes[1]:
                    continue
                reg = pushes[0] if pushes[1] == "flags" else pushes[1]
                if not self.scratch(op, reg):
                    continue
                r, fail = self.tail(b, base, s_op - k, op, cont, [p1, p2], pushes, reg)
                if r is not None:
                    return r
                # a flags push in front that is not the construct's: the older form may still be there
                if not self.older:
                    why[fail] += 1
                    return None
                return self.older_form(b, base, c, t, cont, why, fail)
        return self.older_form(b, base, c, t, cont, why,
                               "no flags-and-register pushes with arithmetic in front of the call")

    def older_form(self, b, base, c, t, cont, why, fail0):
        """The older form: one register pushed and the flags not saved, so the
        flags are left changed; it counts only where they are proved unused
        afterwards (see flags_after). `fail0` is recorded when it is not there."""
        if self.older:
            for s_op in range(c - 2, c - 11, -1):
                op = self.one(b, s_op, base + s_op)
                if op is None or op.size != c - s_op or not s_op < t:
                    continue
                for k in (1, 2):
                    p1 = self.one(b, s_op - k, base + s_op - k)
                    reg = self.push_of(p1) if p1 is not None and p1.size == k else None
                    if reg in (None, "flags") or not self.scratch(op, reg):
                        continue
                    r, fail = self.tail(b, base, s_op - k, op, cont, [p1], [reg], reg)
                    if r is None:
                        why[fail] += 1
                    return r
        why[fail0] += 1
        return None

    def filler(self, ins, rva):
        """An instruction that changes nothing at all: a nop of any length;
        xchg or mov of a register with itself at 64 or 16 bits (at 32 bits
        either clears the upper half); lea of a 64-bit register from itself.
        Builds from 1.69 put one between the pops."""
        if ins.id == X.X86_INS_NOP:
            return True
        ops = ins.operands
        if ins.id in (X.X86_INS_XCHG, X.X86_INS_MOV) and len(ops) == 2 and ops[0].type == X.X86_OP_REG and \
                ops[1].type == X.X86_OP_REG and ops[0].reg == ops[1].reg and \
                not re.fullmatch(r"e(ax|bx|cx|dx|si|di|bp|sp)|r(8|9|1[0-5])d", ins.reg_name(ops[0].reg)):
            return True
        if ins.id == X.X86_INS_LEA and len(ops) == 2 and ops[0].type == X.X86_OP_REG:
            name = ins.reg_name(ops[0].reg)
            m = ops[1]
            return family(name) == name and m.type == X.X86_OP_MEM and m.mem.base == ops[0].reg and \
                m.mem.index == 0 and m.mem.disp == 0 and m.mem.segment == 0
        return False

    def tail(self, b, base, start, op, cont, pushed, pushes, reg):
        """After the short jump: the return address goes, then the pushes are
        undone in reverse order. (construct, None) or (None, why not)."""
        pc = cont
        ins = self.one(b, pc, base + pc)
        if ins is None or self.pop_of(ins) != reg:
            return None, "no pop of the return address into the scratch register"
        shape = [p.mnemonic for p in pushed] + [op.mnemonic, "call", "|", "pop"]
        pc += ins.size
        need = pushes[::-1]
        reg_back = flags_back = False
        for _ in range(10):
            ins = self.one(b, pc, base + pc)
            if ins is None:
                break
            got = self.pop_of(ins)
            if got is not None and need and got == need[0]:
                need.pop(0)
                reg_back |= got == reg
                flags_back |= got == "flags"
                shape.append("popfq" if got == "flags" else "pop")
                pc += ins.size
                if not need:
                    return (base + start, base + pc, reg, " ".join(shape)), None
                continue
            if self.scratch(ins, reg) and not reg_back and not (flags_back and ins.id not in NO_FLAGS):
                shape.append(ins.mnemonic)
                pc += ins.size
                continue
            if self.filler(ins, base + pc):
                shape.append(ins.mnemonic)
                pc += ins.size
                continue
            break
        return None, "what follows does not put the register and the flags back"

    def flags_after(self, rva, depth=64):
        """Are the six status flags unused from rva on: written on every path before any is read?

        'dead', 'live' or 'unknown' (an indirect jump, the end of the search,
        or an instruction that stops execution). A call or a ret counts as
        writing them all: under the Windows x64 convention they do not
        survive a call. A junk construct's own call is followed through its
        short jump instead, since it is not a call at all."""
        work, seen = [(rva, frozenset(n for n, _, _ in STATUS), 0)], set()
        at_call = False         # some path ended at a call or ret with the flags not yet written
        while work:
            pc, pend, n = work.pop()
            while True:
                if (pc, pend) in seen:
                    break
                seen.add((pc, pend))
                n += 1
                if n > depth:
                    return "unknown"
                raw = bytes(self.im.span(pc, 16))
                i = self.one(raw, 0, pc)
                if i is None:
                    return "unknown"
                m = i.mnemonic
                if m in ("pushfq", "pushf", "lahf"):
                    return "live"
                ef = i.eflags
                if any(name in pend and ef & test for name, test, _ in STATUS):
                    return "live"
                pend = pend - {name for name, _, wr in STATUS if any(ef & w for w in wr)}
                if m in ("popfq", "popf", "sahf"):
                    pend = frozenset()
                if not pend:
                    break
                if m in ("int3", "ud2", "hlt", "int1", "iretq", "sysret", "retf"):
                    return "unknown"
                if m == "ret":
                    at_call = True
                    break
                direct = i.op_str.startswith("0x")
                if m == "call":
                    if raw[0] == 0xE8:
                        t = int(i.op_str, 16)
                        jb = bytes(self.im.span(t, 2))
                        if jb[0] == 0xEB and jb[1] < 0x80 and t + 2 + jb[1] > pc + 5:
                            pc = t + 2 + jb[1]
                            continue
                    at_call = True
                    break
                if m == "jmp":
                    if not direct:
                        return "unknown"
                    pc = int(i.op_str, 16)
                    continue
                if m.startswith("j") or m.startswith("loop"):
                    if not direct:
                        return "unknown"
                    work.append((int(i.op_str, 16), pend, n))
                pc += i.size
        return "dead at a call or ret" if at_call else "dead"

    def find(self):
        out, why = [], collections.Counter()
        for s in self.im.secs:
            if not s["exec"]:
                continue
            b = bytes(self.im.span(s["rva"], s["have"]))
            for m in CALL_BACK.finditer(b):
                if m.start() < 16 or m.start() + 160 > len(b):
                    continue
                r = self.at_call(b, s["rva"], m.start(), why)
                if r:
                    out.append(r)
        out.sort()
        keep, last = [], -1
        for r in out:                   # a construct inside another's never-executed bytes is not one
            if r[0] >= last:
                keep.append(r)
                last = r[1]
            else:
                why["inside another construct"] += 1
        self.flags = collections.Counter()
        out, keep = keep, []
        for r in out:                   # the older form leaves the flags changed: only where nothing reads them
            if "popfq" in r[3]:
                keep.append(r)
                continue
            v = self.flags_after(r[1])
            self.flags[v] += 1
            if v in ("dead", "dead at a call or ret"):
                keep.append(r)
            else:
                why["the flags are left changed and may be read after (%s)" % v] += 1
        return keep, why


def foreign_references(im, found, plans):
    """Constructs whose inside something else refers to: {index: reason}."""
    lo = min(r[0] for r in found)
    hi = max(r[1] for r in found)
    owner = np.full(hi - lo + 1, -1, dtype=np.int32)          # byte -> construct, for the bytes after the first
    for i, (a, e, _, _) in enumerate(found):
        owner[a + 1 - lo:e - lo] = i
    bad = {}

    def hit(targets, sources, reason):
        ok = (targets > lo) & (targets < hi)
        t, s = targets[ok], sources[ok]
        own = owner[t - lo]
        sel = own >= 0
        for i, src in zip(own[sel].tolist(), s[sel].tolist()):
            a, e = found[i][0], found[i][1]
            if not a <= src < e:                    # its own call and short jump are inside it
                bad.setdefault(i, "%s at %08X" % (reason, src))

    for s in im.secs:
        raw = im.span(s["rva"], s["have"])
        n = len(raw)
        CH = 1 << 24
        for off in range(0, n - 5, CH):
            m = np.asarray(raw[off:min(n, off + CH + 6)])
            k = len(m) - 6
            if k <= 0:
                break
            first, second = m[:k], m[1:k + 1]
            near = (first == 0xE8) | (first == 0xE9)                  # call / jmp rel32
            cond = (first == 0x0F) & ((second & 0xF0) == 0x80)        # jcc rel32
            for sel, skip in ((near, 1), (cond, 2)):
                at = np.nonzero(sel)[0]
                if not len(at):
                    continue
                rel = (m[at + skip].astype(np.uint32) | (m[at + skip + 1].astype(np.uint32) << 8) |
                       (m[at + skip + 2].astype(np.uint32) << 16) | (m[at + skip + 3].astype(np.uint32) << 24)).view(np.int32)
                src = at.astype(np.int64) + off + s["rva"]
                hit(src + skip + 4 + rel, src, "a branch")
    rel = im.relocs()
    if len(rel):
        q = im.qwords(rel).astype(np.int64) - np.int64(im.base)
        hit(q, rel.astype(np.int64), "a relocated pointer")
    fn = im.functions()
    if len(fn):
        hit(fn[:, 0].astype(np.int64), fn[:, 0].astype(np.int64) - 1, "an exception record begins")
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    starts = np.array([r[0] for r in found], dtype=np.int64)
    ends = np.array([r[1] for r in found], dtype=np.int64)
    overlap = {}
    for p in plans:
        for rva, kind, data in planfile.Plan.load(p).patches:
            i = int(np.searchsorted(starts, rva + len(data) - 1, "right")) - 1
            if i >= 0 and rva < ends[i] and rva + len(data) > starts[i]:
                overlap.setdefault(i, "a patch of %s at %08X" % (os.path.basename(p), rva))
            if data[:1] in (b"\xE9", b"\xE8", b"\x0F", b"\xEB") or 0x70 <= data[0] < 0x80:
                for ins in md.disasm(data, rva):
                    if ins.op_str.startswith("0x") and ins.mnemonic[0] in "jc":
                        t = int(ins.op_str, 16)
                        if lo < t < hi and owner[t - lo] >= 0:
                            bad.setdefault(int(owner[t - lo]), "a branch written by %s at %08X" % (os.path.basename(p), ins.address))
    return bad, overlap


def prove(im, found, count, seed=1):
    """Run constructs in an emulator: every register, the flags and rsp as they were at the end."""
    import unicorn
    from unicorn import x86_const as U
    rnd = random.Random(seed)
    by_shape = {}
    for r in found:
        by_shape.setdefault(r[3], r)
    todo = list(by_shape.values())
    rest = [r for r in found if by_shape[r[3]] is not r]
    todo += rnd.sample(rest, max(0, min(len(rest), count - len(todo))))
    regs = [getattr(U, "UC_X86_REG_" + n) for n in ("RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "R8", "R9", "R10",
                                                     "R11", "R12", "R13", "R14", "R15")]
    bad = []
    for a, e, reg, shape in todo:
        uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
        page = a & ~0xFFF
        uc.mem_map(0x140000000 + page, 0x2000)
        uc.mem_write(0x140000000 + page, bytes(im.span(page, 0x2000)))
        uc.mem_map(0x7000000, 0x10000)
        vals = [rnd.getrandbits(64) for _ in regs]
        for r, v in zip(regs, vals):
            uc.reg_write(r, v)
        flags = 0x202 | (rnd.getrandbits(12) & 0x8D5)
        uc.reg_write(U.UC_X86_REG_EFLAGS, flags)
        sp = 0x7008000
        above = bytes(rnd.getrandbits(8) for _ in range(64))
        uc.mem_write(sp, above)
        uc.reg_write(U.UC_X86_REG_RSP, sp)
        try:
            uc.emu_start(0x140000000 + a, 0x140000000 + e, count=64)
        except unicorn.UcError as x:
            bad.append((a, "stopped: %s" % x))
            continue
        mask = ~0 if "popfq" in shape else ~0x8D5         # the older form: status flags proved unused instead
        same = (uc.reg_read(U.UC_X86_REG_RIP) == 0x140000000 + e and uc.reg_read(U.UC_X86_REG_RSP) == sp and
                uc.reg_read(U.UC_X86_REG_EFLAGS) & mask == flags & mask and bytes(uc.mem_read(sp, 64)) == above and
                all(uc.reg_read(r) == v for r, v in zip(regs, vals)))
        if not same:
            bad.append((a, "state differs"))
    return len(todo), len(by_shape), bad


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("image")
    ap.add_argument("-o", "--out", required=True)
    ap.add_argument("--report")
    ap.add_argument("--plan", action="append", default=[], help="an earlier plan: its patches are not written over")
    ap.add_argument("--prove", type=int, default=0)
    ap.add_argument("--no-older", action="store_true",
                    help="leave out the older form that does not save the flags (kept, without it, where "
                         "the flags are proved unused after it)")
    a = ap.parse_args()
    f = Finder(a.image, older=not a.no_older)
    found, why = f.find()
    print("call-back constructs that restore everything they touch: %d" % len(found))
    for k, v in why.most_common():
        print("   not counted, %s: %d" % (k, v))
    rep = {"constructs": len(found), "not_counted": dict(why)}
    plan = planfile.Plan()
    if found:
        bad, overlap = foreign_references(f.im, found, a.plan)
        wiped = jumped = 0
        for i, (start, end, reg, shape) in enumerate(found):
            if i in overlap:
                continue
            d = end - (start + 2)
            plan.patch(start, bytes([0xEB, d]) if d < 0x80 else b"\xE9" + struct.pack("<i", end - (start + 5)),
                       planfile.KIND_FLOW)
            jumped += 1
            if i not in bad and d < 0x80:
                plan.wipe(start + 2, end - start - 2)
                wiped += end - start - 2
        reasons = collections.Counter(v.split(" at ")[0] for v in bad.values())
        print("replaced by a jump over themselves: %d; bytes filled with int3: %d" % (jumped, wiped))
        print("left untouched because an earlier plan writes there: %d" % len(overlap))
        print("jump written but bytes kept, because something refers into them: %d %s" % (len(bad), dict(reasons)))
        sizes = collections.Counter(e - s for s, e, _, _ in found)
        rep.update(replaced=jumped, wiped_bytes=wiped, left_for_an_earlier_plan=len(overlap), bytes_kept=len(bad),
                   bytes_kept_why=dict(reasons), total_bytes=sum(e - s for s, e, _, _ in found),
                   shapes=len({r[3] for r in found}), registers=dict(collections.Counter(r[2] for r in found)),
                   length_range=[min(sizes), max(sizes)],
                   examples=["%08X-%08X %s" % (s, e, sh) for s, e, _, sh in found[:6]])
        if f.flags:
            rep["older_form_flags_after"] = dict(f.flags)
        if a.prove:
            n, shapes, wrong = prove(f.im, found, a.prove)
            print("run in the emulator: %d constructs covering all %d shapes; not a no-op: %d %s" % (
                n, shapes, len(wrong), ["%08X %s" % w for w in wrong[:5]]))
            rep.update(proved=n, proved_shapes=shapes, proved_wrong=len(wrong))
    plan.save(a.out)
    if a.report:
        json.dump(rep, open(a.report, "w"), indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
