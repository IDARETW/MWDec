"""Undo the protection's control-flow disguise in a decrypted image, statically.

Input: an executable already decrypted by `mwdec decrypt` (both code layers
removed). Nothing is run. Output: a patch plan (`planfile.Plan`) and a JSON
report.

What it does, in order:

1. Finds every call chain the protection wraps around its routines:

       save context (14 pushes, lea rsp,[rsp-100h], 16 XMM stores)
       push 10h ; test rsp,0Fh ; jne L ; push 18h ; L: sub rsp,8 (long form)
       call G            (or push R ; push G ; ret)
       R: add rsp,[rsp+8]
       restore context
       E: ...            the game's own code continues

   and bypasses each one: S becomes `jmp E` when it owns five bytes that
   nothing else enters, otherwise every rel32 branch into S is retargeted
   to E. A chain met inside an idiom (between `push X` and the jump that
   pops it) goes away with that idiom's rewrite, unless code after it reads
   the flags the chain left behind.
   Exception records that begin inside a chain, or on protection code that
   only the routines reach, are not used as roots.
2. Walks all code reachable from the image's own roots (exception
   directory, relocated pointers in data, entry point, TLS callbacks,
   exports, scope tables, jump tables, code addresses taken by live code)
   with the chains bypassed, and records every byte executed or read.
3. Rewrites each disguised jump, branch and call found in live code as the
   direct instruction(s):

       lea rsp,[rsp-8] ; mov [rsp],rbp ; lea rbp,[rip+X] ; xchg [rsp],rbp ;
       lea rsp,[rsp+8] ; jmp [rsp-8]                      ->  jmp X
       push rbp ; movabs rbp,A ; xchg [rsp],rbp ; push rcx ; push rdx ;
       mov rcx,[rsp+10h] ; movabs rdx,B ; cmovcc rcx,rdx ;
       mov [rsp+10h],rcx ; pop rdx ; pop rcx ; ret        ->  jcc B ; jmp A
       push R ; push G ; ret                              ->  call G ; jmp R

   Idioms are recognised by meaning, not by spelling: a run of stack and
   register moves (none of which touches the flags) is evaluated
   symbolically and accepted only when every register and every stack slot
   at or above the final stack pointer ends where it started, and the
   transfer target is a constant or a cmov selection between two constants.
4. Lists the protection's bytes that nothing live executes or reads, for
   wiping with int3.

    py -3 devirt_flow.py modernwarfare.dec.exe -o 19936.flow.plan --report flow.json
"""
from __future__ import annotations

import argparse
import bisect
import collections
import json
import os
import re
import struct
import sys
import time

import capstone
import os as _os
_os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")    # numpy's math library reserves 31 MB a core when loaded; nothing here uses it
import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mwdec.pe import Image  # noqa: E402
import planfile  # noqa: E402

GPR64 = ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9",
         "r10", "r11", "r12", "r13", "r14", "r15")
GPRSET = frozenset(GPR64)
CC = {"o": 0, "no": 1, "b": 2, "ae": 3, "e": 4, "ne": 5, "be": 6, "a": 7,
      "s": 8, "ns": 9, "p": 10, "np": 11, "l": 12, "ge": 13, "le": 14, "g": 15}
CC_ALIAS = {"c": "b", "nae": "b", "nc": "ae", "nb": "ae", "z": "e", "nz": "ne",
            "na": "be", "nbe": "a", "pe": "p", "po": "np", "nge": "l",
            "nl": "ge", "ng": "le", "nle": "g"}
LONG_SUB8 = b"\x48\x81\xEC\x08\x00\x00\x00"
ADD_RSP_RSP8 = b"\x48\x03\x64\x24\x08"

RE_RSPMEM = re.compile(r"^qword ptr \[rsp(?: ([+-]) (0x[0-9a-f]+|\d+))?\]$")
RE_XMMMEM = re.compile(r"^xmmword ptr \[rsp(?: \+ (0x[0-9a-f]+|\d+))?\]$")
RE_RIP = re.compile(r"\[rip(?: ([+-]) (0x[0-9a-f]+|\d+))?\]")
RE_LEA_RSP = re.compile(r"^rsp, \[rsp(?: ([+-]) (0x[0-9a-f]+|\d+))?\]$")
JCC_MN = {"j" + k for k in CC} | {"j" + k for k in CC_ALIAS}
COND_REL8 = {"loop", "loope", "loopne", "jrcxz", "jecxz", "jcxz"}
STOP_MN = {"ret", "retf", "int3", "ud2", "hlt", "iretq", "iretd", "int1", "sysret"}
XMM_MOV = {"movupd", "movups", "movdqu", "movaps", "movapd", "movdqa"}
# instructions that leave all six status flags untouched (used only for the
# idiom evaluator's whitelist and for liveness; anything else is assumed to
# read and write flags)
FLAGS_NEUTRAL = {"push", "pop", "lea", "mov", "movabs", "xchg", "jmp", "call",
                 "nop", "movzx", "movsx", "movsxd"} | XMM_MOV


def norm_cc(c: str) -> str | None:
    c = CC_ALIAS.get(c, c)
    return c if c in CC else None


def rsp_disp(s: str):
    """'qword ptr [rsp + 0x10]' -> 16 ; None if not a plain rsp slot."""
    m = RE_RSPMEM.match(s)
    if not m:
        return None
    if m.group(1) is None:
        return 0
    v = int(m.group(2), 0)
    return v if m.group(1) == "+" else -v


def lea_rsp_disp(op: str):
    m = RE_LEA_RSP.match(op)
    if not m:
        return None
    if m.group(1) is None:
        return 0
    v = int(m.group(2), 0)
    return v if m.group(1) == "+" else -v


def rip_target(op: str, nxt: int):
    m = RE_RIP.search(op)
    if not m:
        return None
    if m.group(1) is None:
        return nxt
    v = int(m.group(2), 0)
    return nxt + (v if m.group(1) == "+" else -v)


class Code:
    """Decoding over the mapped image (RVA-addressed)."""

    def __init__(self, im: Image, extra: list | None = None, model=None):
        self.im = im
        self.model = model
        self.mem = im.mem
        self.base = im.image_base
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.md.detail = False
        self.ex = [(s.rva, s.rva + s.vsize) for s in im.exec_sections()]
        # code the protection placed in a data section's tail (found by
        # extra_code_regions); executed, so walked and rewritten, never wiped
        self.extra = list(extra or [])
        self.ex += self.extra
        self._c: dict[int, tuple] = {}

    def in_code(self, rva: int) -> bool:
        for lo, hi in self.ex:
            if lo <= rva < hi:
                return True
        return False

    def insn(self, a: int):
        """(size, mnemonic, op_str) or None."""
        r = self._c.get(a)
        if r is not None:
            return r
        r = None
        for _, size, m, op in self.md.disasm_lite(bytes(self.mem[a:a + 16]), a, 1):
            r = (size, m, op)
        if len(self._c) > 4_000_000:
            self._c.clear()
        self._c[a] = r
        return r

    def run(self, a: int, limit: int = 4096):
        """Linear decode from a: yields (addr, size, mnem, op)."""
        return self.md.disasm_lite(bytes(self.mem[a:a + limit]), a)


# ---------------------------------------------------------------- idioms --

class Idiom:
    __slots__ = ("start", "kind", "cc", "target", "fall", "ret", "insns", "end", "inner",
                 "effects", "pop", "flags_clob", "clob")

    def __init__(self, start, kind, cc, target, fall, ret, insns, end, inner=()):
        self.inner = list(inner)  # routine-call chains sitting inside the idiom
        self.effects = []         # their routines' modelled effect
        self.pop = 0              # popjmp: stack slots dropped before the jump
        self.flags_clob = any("flags" not in c.push_order for c in self.inner)
        self.clob = []            # registers a routine inside leaves changed
        self.start = start      # first instruction
        self.kind = kind        # "jmp", "jcc", "call"
        self.cc = cc            # condition (jcc)
        self.target = target    # jmp X / jcc taken B / call G   (RVA)
        self.fall = fall        # jcc not taken A               (RVA)
        self.ret = ret          # call: return address R        (RVA)
        self.insns = insns      # [(addr, size)] in execution order, incl. joining jmps
        self.end = end          # address of the final ret / jmp [rsp+d]

    def shape(self, code: Code) -> str:
        parts = []
        for a, _ in self.insns:
            s, m, op = code.insn(a)
            if m == "jmp" and op.startswith("0x"):
                continue
            op = re.sub(r"0x[0-9a-f]{6,}", "IMM", op)
            op = re.sub(r"\[rip [+-] 0x[0-9a-f]+\]", "[rip+D]", op)
            parts.append((m + " " + op).strip())
        return " ; ".join(parts)


IDIOM_FIRST = {"push", "lea", "mov"}


def resolve_idiom(code: Code, a: int, max_insns: int = 64, chains: bool = True):
    """Symbolically evaluate a run of flag-neutral stack moves starting at a.

    Returns an Idiom when the run ends in ret / jmp [rsp+d] with a constant
    (or cmov-selected) target and leaves every register and every stack slot
    at or above the final rsp as it found them."""
    first = code.insn(a)
    if first is None or first[1] not in IDIOM_FIRST:
        return None
    base = code.base
    regs: dict[str, tuple] = {}
    mem: dict[int, tuple] = {}
    sp = 0
    pc = a
    insns = []
    inner = []
    clobbered = False
    seen = set()
    for _ in range(max_insns):
        if pc in seen:
            return None
        seen.add(pc)
        d = code.insn(pc)
        if d is None:
            return None
        size, m, op = d
        if chains and pc != a and ((m == "push" and op in GPRSET) or m == "pushfq"):
            # a routine-call chain inside the idiom: with the routine
            # returning at once it is net zero on registers and stack, and
            # it overwrites the flags unless it saves them
            ch = match_chain(code, pc)
            if ch is not None:
                inner.append(ch)
                insns.extend(ch.insns)
                if "flags" not in ch.push_order:
                    clobbered = True
                pc = ch.E_raw
                continue
        insns.append((pc, size))
        nxt = pc + size
        if m == "jmp":
            if op.startswith("0x"):
                pc = int(op, 16)
                continue
            dd = rsp_disp(op)
            if dd is None:
                return None
            tgt = mem.get(sp + dd, ("m", sp + dd))
            return _finish(code, a, regs, mem, sp, tgt, insns, pc, inner)
        if m == "ret":
            if op:
                return None
            tgt = mem.get(sp, ("m", sp))
            sp += 8
            return _finish(code, a, regs, mem, sp, tgt, insns, pc, inner)
        ops = op.split(", ") if op else []
        if m == "push":
            if len(ops) != 1 or ops[0] not in GPRSET or ops[0] == "rsp":
                return None
            sp -= 8
            mem[sp] = regs.get(ops[0], ("r", ops[0]))
        elif m == "pop":
            if len(ops) != 1 or ops[0] not in GPRSET or ops[0] == "rsp":
                return None
            regs[ops[0]] = mem.get(sp, ("m", sp))
            sp += 8
        elif m == "lea":
            dd = lea_rsp_disp(op)
            if dd is not None:
                if dd % 8:
                    return None
                sp += dd
            elif len(ops) == 2 and ops[0] in GPRSET and ops[0] != "rsp" and \
                    ops[1].startswith("[rip"):
                t = rip_target(ops[1], nxt)
                regs[ops[0]] = ("c", t)
            else:
                return None
        elif m in ("mov", "movabs"):
            if len(ops) != 2:
                return None
            d0, d1 = ops
            if d0 in GPRSET and d0 != "rsp":
                if d1 in GPRSET and d1 != "rsp":
                    regs[d0] = regs.get(d1, ("r", d1))
                elif d1.startswith("qword ptr [rsp"):
                    dd = rsp_disp(d1)
                    if dd is None:
                        return None
                    regs[d0] = mem.get(sp + dd, ("m", sp + dd))
                elif m == "movabs" and re.fullmatch(r"0x[0-9a-f]+|\d+", d1):
                    v = int(d1, 0)
                    if not (base <= v < base + len(code.mem)):
                        return None
                    regs[d0] = ("c", v - base)
                else:
                    return None
            elif d0.startswith("qword ptr [rsp") and d1 in GPRSET and d1 != "rsp":
                dd = rsp_disp(d0)
                if dd is None:
                    return None
                mem[sp + dd] = regs.get(d1, ("r", d1))
            else:
                return None
        elif m == "xchg":
            if len(ops) != 2:
                return None
            x0, x1 = ops
            if x1.startswith("qword ptr [rsp"):
                x0, x1 = x1, x0
            if x0.startswith("qword ptr [rsp") and x1 in GPRSET and x1 != "rsp":
                dd = rsp_disp(x0)
                if dd is None:
                    return None
                old = mem.get(sp + dd, ("m", sp + dd))
                mem[sp + dd] = regs.get(x1, ("r", x1))
                regs[x1] = old
            elif x0 in GPRSET and x1 in GPRSET and "rsp" not in (x0, x1):
                v0 = regs.get(x0, ("r", x0))
                regs[x0] = regs.get(x1, ("r", x1))
                regs[x1] = v0
            else:
                return None
        elif m.startswith("cmov"):
            cc = norm_cc(m[4:])
            if clobbered:
                return None
            if cc is None or len(ops) != 2 or ops[0] not in GPRSET or ops[1] not in GPRSET:
                return None
            v0 = regs.get(ops[0], ("r", ops[0]))
            v1 = regs.get(ops[1], ("r", ops[1]))
            if v0[0] != "c" or v1[0] != "c":
                return None
            regs[ops[0]] = ("sel", cc, v1[1], v0[1])     # cc ? v1 : v0
        else:
            return None
        pc = nxt
    return None


def _finish(code, a, regs, mem, sp, tgt, insns, endpc, inner=()):
    for r, v in regs.items():
        if v != ("r", r):
            return None
    kind = None
    if sp == 0:
        kind = "jmp"
    elif sp == -8:
        rv = mem.get(-8)
        if rv is None or rv[0] != "c":
            return None
        kind = "call"
    else:
        return None
    for off, v in mem.items():
        if off >= sp and not (kind == "call" and off == -8):
            if v != ("m", off):
                return None
    if tgt[0] == "c":
        if not code.in_code(tgt[1]):
            return None
        if kind == "call":
            r = mem[-8][1]
            if not code.in_code(r):
                return None
            return Idiom(a, "call", None, tgt[1], None, r, insns, endpc, inner)
        return Idiom(a, "jmp", None, tgt[1], None, None, insns, endpc, inner)
    if tgt[0] == "sel" and kind == "jmp":
        _, cc, b, aa = tgt
        if not (code.in_code(b) and code.in_code(aa)):
            return None
        return Idiom(a, "jcc", cc, b, aa, None, insns, endpc, inner)
    return None


# ---------------------------------------------------------------- chains --

class Chain:
    __slots__ = ("S", "E_raw", "E", "G", "R", "call_form", "sub_site", "insns",
                 "push_order", "preds", "flags", "bypass", "why", "S_patch",
                 "final")

    def __init__(self):
        self.preds = []
        self.bypass = None
        self.why = None
        self.S_patch = None
        self.final = None
        self.flags = None

    def as_json(self):
        return {"S": self.S, "E": self.E, "E_raw": self.E_raw, "final": self.final,
                "G": self.G, "R": self.R, "call_form": self.call_form,
                "sub_site": self.sub_site, "flags_at_E": self.flags,
                "preds": self.preds, "bypass": self.bypass, "why": self.why}


def match_chain(code: Code, s: int):
    """Match the routine-call chain beginning at s. Returns Chain or None."""
    insns = []
    pc = s
    budget = [400]

    def step():
        """Next non-link instruction from pc (follows jmp rel32 and jmp idioms)."""
        nonlocal pc
        while budget[0] > 0:
            budget[0] -= 1
            d = code.insn(pc)
            if d is None:
                return None
            size, m, op = d
            if m == "jmp" and op.startswith("0x"):
                insns.append((pc, size))
                pc = int(op, 16)
                continue
            if m in ("lea", "mov", "push"):
                idm = resolve_idiom(code, pc, chains=False)
                if idm is not None and idm.kind == "jmp":
                    insns.extend(idm.insns)
                    pc = idm.target
                    continue
            return pc, size, m, op
        return None

    pushes = []
    while True:
        x = step()
        if x is None:
            return None
        a, size, m, op = x
        if (m == "push" and op in GPRSET and op != "rsp") or m == "pushfq":
            r = op if m == "push" else "flags"
            if r in pushes:
                return None
            pushes.append(r)
            insns.append((a, size))
            pc = a + size
            continue
        break
    if not pushes:
        return None
    if not (m == "lea" and lea_rsp_disp(op) == -0x100):
        return None
    insns.append((a, size))
    pc = a + size
    xsave = {}
    for _ in range(16):
        x = step()
        if x is None:
            return None
        a, size, m, op = x
        ops = op.split(", ")
        if m not in XMM_MOV or len(ops) != 2 or not ops[1].startswith("xmm"):
            return None
        mm = RE_XMMMEM.match(ops[0])
        if not mm:
            return None
        off = int(mm.group(1), 0) if mm.group(1) else 0
        xsave[off] = ops[1]
        insns.append((a, size))
        pc = a + size
    if sorted(xsave) != list(range(0, 0x100, 0x10)) or len(set(xsave.values())) != 16:
        return None
    x = step()
    if x is None or x[2:] != ("push", "0x10"):
        return None
    insns.append((x[0], x[1]))
    pc = x[0] + x[1]
    x = step()
    if x is None or x[2:] != ("test", "rsp, 0xf"):
        return None
    insns.append((x[0], x[1]))
    pc = x[0] + x[1]
    x = step()
    if x is None or x[2] != "jne" or not x[3].startswith("0x"):
        return None
    insns.append((x[0], x[1]))
    L = int(x[3], 16)
    pc = x[0] + x[1]
    x = step()
    if x is None or x[2:] != ("push", "0x18"):
        return None
    insns.append((x[0], x[1]))
    pc = x[0] + x[1]
    x = step()
    if x is None or x[0] != L:
        # the push 0x18 path must arrive at L (possibly via links)
        return None
    if bytes(code.mem[L:L + 7]) != LONG_SUB8:
        return None
    insns.append((L, 7))
    pc = L + 7
    x = step()
    if x is None:
        return None
    a, size, m, op = x
    ch = Chain()
    if m == "call" and op.startswith("0x"):
        ch.G, ch.R, ch.call_form = int(op, 16), a + size, "call"
        insns.append((a, size))
    else:
        idm = resolve_idiom(code, a, chains=False)
        if idm is None or idm.kind != "call":
            return None
        ch.G, ch.R, ch.call_form = idm.target, idm.ret, "push-ret"
        insns.extend(idm.insns)
    pc = ch.R
    x = step()
    if x is None or bytes(code.mem[x[0]:x[0] + 5]) != ADD_RSP_RSP8:
        return None
    insns.append((x[0], x[1]))
    pc = x[0] + x[1]
    for _ in range(16):
        x = step()
        if x is None:
            return None
        a, size, m, op = x
        ops = op.split(", ")
        if m not in XMM_MOV or len(ops) != 2:
            return None
        mm = RE_XMMMEM.match(ops[1])
        if not mm:
            return None
        off = int(mm.group(1), 0) if mm.group(1) else 0
        if xsave.get(off) != ops[0]:
            return None
        insns.append((a, size))
        pc = a + size
    x = step()
    if x is None or not (x[2] == "lea" and lea_rsp_disp(x[3]) == 0x100):
        return None
    insns.append((x[0], x[1]))
    pc = x[0] + x[1]
    for r in reversed(pushes):
        x = step()
        if x is None or x[2:] != (("popfq", "") if r == "flags" else ("pop", r)):
            return None
        insns.append((x[0], x[1]))
        pc = x[0] + x[1]
    ch.S = s
    ch.E_raw = pc
    ch.sub_site = L
    ch.insns = insns
    ch.push_order = pushes
    # E: skip plain joining jumps / jmp idioms after the restore
    x = step()
    ch.E = x[0] if x is not None else pc
    return ch


# ---------------------------------------------------------- xref index --

class _Rgn:
    def __init__(self, rva, vsize):
        self.rva, self.vsize = rva, vsize


def extra_code_regions(im: Image, min_hits: int = 8, tails: bool = True):
    """Parts of non-executable sections that code jumps into.

    The protection puts pieces of its scattered code in the padding at the
    end of data sections. Two rules find them.

    Busy pages (the only rule until other builds were looked at): a page of
    a read-only section counts when at least `min_hits` decoded jmp rel32 /
    jcc rel32 from the executable sections land in it and it holds the
    bytes of a disguised jump; adjacent pages are merged.

    Tails (`tails`): build 1.20 has a few such pieces at the end of every
    section, `.idata` included, with two to five jumps each, and 0.01.2 has
    the set-up of its largest writer in the last 0x200 bytes of `.pdata`.
    The end of a section is where the linker left room, so:

      * in a section that holds data directories, the bytes after the last
        of them are padding. If a jump lands there, everything from the
        first landing to the end of the section is a region;
      * in a section without one, the last page counts when a jump lands
        in it and it holds a disguised jump, or three jumps land in it;
      * a region found by the first rule is extended to the end of its
        section, and backwards over pages that take a jump and hold a
        disguised jump.

    A region only says where instructions may be decoded when control flow
    leads there; nothing in it is touched for being in it."""
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    xr = RawXrefs(im)
    pages = collections.Counter()
    lands = collections.defaultdict(list)
    data = [s for s in im.sections if not s.executable]
    sel = np.zeros(len(xr.tgt), bool)
    for s in data:
        sel |= (xr.tgt >= s.rva) & (xr.tgt < s.rva + s.vsize)
    for i in np.nonzero(sel & ((xr.kind == 0) | (xr.kind == 2)))[0]:
        src, t = int(xr.src[i]), int(xr.tgt[i])
        for _, size, m, op in md.disasm_lite(bytes(im.mem[src:src + 16]), src, 1):
            if op.startswith("0x") and int(op, 16) == t and (m == "jmp" or m in JCC_MN):
                pages[t & ~0xFFF] += 1
                lands[t & ~0xFFF].append(t)

    def idiom(p):
        return bytes(im.mem[p:p + 0x1000]).count(b"\xFF\x64\x24\xF8") > 0

    # Other proof that an address in a data section is code: it is pushed
    # as a return or jump address (`lea rbp,[rip+X] ; xchg [rsp],rbp`, a
    # joining jump allowed between the two), or it is called. A chain's
    # return thunk is reached that way and by nothing else: on 1.20 one
    # sits in `_RDATA` 0x11C bytes before the first jump landing of that
    # tail, and the code it jumps on to was wiped as unreachable. These
    # only move the start of a tail region; they do not make a page busy.
    more = collections.defaultdict(list)
    size = len(im.mem)
    # (the bytes are escaped: 24h is `$` and 2Dh is `-` to the regex engine)
    push_pat = re.compile(re.escape(b"\x48\x8D\x2D") + b"(....)(?:" + re.escape(b"\x48\x87\x2C\x24") + b"|" +
                          re.escape(b"\xE9") + b"(....))", re.S)
    for s in im.exec_sections():
        buf = bytes(im.mem[s.rva:s.rva + s.vsize])
        for mt in push_pat.finditer(buf):
            a = s.rva + mt.start()
            t = a + 7 + int.from_bytes(mt.group(1), "little", signed=True)
            if mt.group(2) is not None:
                j = a + 12 + int.from_bytes(mt.group(2), "little", signed=True)
                if not (0 <= j <= size - 4 and bytes(im.mem[j:j + 4]) == b"\x48\x87\x2C\x24"):
                    continue
            if 0 <= t < size:
                ts = im.section_of(t)
                if ts is not None and not ts.executable:
                    more[t & ~0xFFF].append(t)
    for i in np.nonzero(sel & (xr.kind == 1))[0]:
        src, t = int(xr.src[i]), int(xr.tgt[i])
        for _, sz_, m, op in md.disasm_lite(bytes(im.mem[src:src + 16]), src, 1):
            if op.startswith("0x") and int(op, 16) == t and m == "call":
                more[t & ~0xFFF].append(t)

    good = []
    for p, n in pages.items():
        s = im.section_of(p)
        if n < min_hits or s.chars & 0x80000000:          # writable: no
            continue
        if not idiom(p):
            continue
        good.append(p)
    good.sort()
    out = []
    for p in good:
        if out and out[-1][1] >= p:
            out[-1][1] = p + 0x1000
        else:
            out.append([p, p + 0x1000])
    res = []
    for lo, hi in out:
        s = im.section_of(lo)
        res.append((lo, min(hi, s.rva + s.vsize)))
    if not tails:
        return res
    regs = []
    for s in data:
        end = s.rva + min(s.vsize, s.rsize) if s.rsize else 0
        if end <= s.rva:
            continue
        mine = [(lo, hi) for lo, hi in res if s.rva <= lo < end]
        lo_reg = None
        if mine:
            # busy pages: to the end of the section, and back over quieter pages of the same kind
            lo_reg = min(lo for lo, _ in mine)
            while lo_reg - 0x1000 >= s.rva and pages.get(lo_reg - 0x1000) and idiom(lo_reg - 0x1000):
                lo_reg -= 0x1000
        # (directory 4, the certificate table, is addressed by file offset, not RVA)
        dir_end = max((rva + sz for k, (rva, sz) in enumerate(im.dirs) if k != 4 and sz and s.rva <= rva < end),
                      default=None)
        if dir_end is not None and dir_end < end and not (mine and lo_reg <= dir_end):
            first = min((t for d_ in (lands, more) for p, ts in d_.items() for t in ts if dir_end <= t < end),
                        default=None)
            if first is not None:
                lo_reg = first if lo_reg is None else min(lo_reg, first)
        elif dir_end is None and not mine and not (s.chars & 0x80000000) and s.vsize <= 0x4000000:
            last = (end - 1) & ~0xFFF
            if pages.get(last) and (idiom(last) or pages[last] >= 3):
                lo_reg = min(lands[last] + more.get(last, []))
        if lo_reg is not None:
            regs.append((lo_reg, end))
    return sorted(regs)


class RawXrefs:
    """Every rel32/rel8 branch encoding in the code sections, by target.

    False positives are expected (the opcode inside another instruction);
    users confirm by decoding the source."""

    def __init__(self, im: Image, extra: list | None = None):
        tg, sr, kd = [], [], []
        for s in [_Rgn(s.rva, s.vsize) for s in im.exec_sections()] + [_Rgn(lo, hi - lo) for lo, hi in (extra or [])]:
            a = np.frombuffer(im.mem, dtype=np.uint8, count=s.vsize, offset=s.rva)
            n = len(a) - 8

            def rel32(pos, k):
                r = (a[pos + k].astype(np.int64) | (a[pos + k + 1].astype(np.int64) << 8)
                     | (a[pos + k + 2].astype(np.int64) << 16)
                     | (a[pos + k + 3].astype(np.int64) << 24))
                return np.where(r >= 1 << 31, r - (1 << 32), r)

            def rel8(pos, k):
                r = a[pos + k].astype(np.int64)
                return np.where(r >= 128, r - 256, r)

            for kind, pos, tgt in (
                    (0, p := np.nonzero(a[:n] == 0xE9)[0], None),
                    (1, q := np.nonzero(a[:n] == 0xE8)[0], None),
                    (2, w := np.nonzero((a[:n] == 0x0F) & ((a[1:n + 1] & 0xF0) == 0x80))[0], None),
                    (3, e := np.nonzero(a[:n] == 0xEB)[0], None),
                    (4, f := np.nonzero((a[:n] & 0xF0) == 0x70)[0], None)):
                if kind == 0 or kind == 1:
                    t = s.rva + pos + 5 + rel32(pos, 1)
                elif kind == 2:
                    t = s.rva + pos + 6 + rel32(pos, 2)
                else:
                    t = s.rva + pos + 2 + rel8(pos, 1)
                ok = (t >= 0) & (t < len(im.mem))
                tg.append(t[ok])
                sr.append(s.rva + pos[ok])
                kd.append(np.full(int(ok.sum()), kind, dtype=np.int8))
            # lea r64,[rip+d32]
            pos = np.nonzero(((a[:n] & 0xFB) == 0x48) & (a[1:n + 1] == 0x8D)
                             & ((a[2:n + 2] & 0xC7) == 0x05))[0]
            t = s.rva + pos + 7 + rel32(pos, 3)
            ok = (t >= 0) & (t < len(im.mem))
            tg.append(t[ok]); sr.append(s.rva + pos[ok])
            kd.append(np.full(int(ok.sum()), 5, dtype=np.int8))
            # movabs r64, imm64 holding a VA in the image
            pos = np.nonzero(((a[:n] & 0xFE) == 0x48) & ((a[1:n + 1] & 0xF8) == 0xB8))[0]
            pos = pos[pos + 10 <= len(a)]
            v = np.zeros(len(pos), dtype=np.uint64)
            for i in range(8):
                v |= a[pos + 2 + i].astype(np.uint64) << np.uint64(8 * i)
            t = v.astype(np.int64) - np.int64(im.image_base)
            ok = (t >= 0) & (t < len(im.mem))
            tg.append(t[ok]); sr.append(s.rva + pos[ok])
            kd.append(np.full(int(ok.sum()), 6, dtype=np.int8))
        t = np.concatenate(tg)
        o = np.argsort(t, kind="stable")
        self.tgt = t[o]
        self.src = np.concatenate(sr)[o]
        self.kind = np.concatenate(kd)[o]

    def to(self, rva: int):
        lo = np.searchsorted(self.tgt, rva, "left")
        hi = np.searchsorted(self.tgt, rva, "right")
        return [(int(self.src[i]), int(self.kind[i])) for i in range(lo, hi)]


KIND_ENC = {0: ("jmp", 5), 1: ("call", 5), 2: (None, 6), 3: ("jmp", 2), 4: (None, 2),
            5: ("lea", 7), 6: ("movabs", 10)}


def confirmed_refs_to(code: Code, xr: RawXrefs, rva: int):
    """Decoded lea-rip / movabs instructions whose value is rva: [src]."""
    out = []
    for src, k in xr.to(rva):
        if k < 5:
            continue
        d = code.insn(src)
        if d is None or d[0] != KIND_ENC[k][1] or d[1] != KIND_ENC[k][0]:
            continue
        out.append(src)
    return out


def confirmed_branches_to(code: Code, xr: RawXrefs, rva: int):
    """Decoded branches whose immediate target is rva: [(src, mnem, size)]."""
    out = []
    for src, k in xr.to(rva):
        if k >= 5:
            continue
        d = code.insn(src)
        if d is None:
            continue
        size, m, op = d
        if size != KIND_ENC[k][1] or not op.startswith("0x") or int(op, 16) != rva:
            continue
        if m == "jmp" or m == "call" or m in JCC_MN:
            out.append((src, m, size))
    return out


# ------------------------------------------------------------- byte map --

START, CODE, IDIOM, CHAIN, DREAD, PATCH, WIPE, ISTART = 1, 2, 4, 8, 16, 32, 64, 128


class ByteMap:
    """One flag byte per byte of the executable sections."""

    def __init__(self, im: Image, extra: list | None = None):
        self.secs = []
        off = 0
        regs = [(s.rva, s.rva + s.vsize) for s in im.exec_sections()] + list(extra or [])
        for lo, hi in regs:
            self.secs.append((lo, hi, off))
            off += hi - lo
        self.total = off
        self.f = np.zeros(off, dtype=np.uint8)

    def idx(self, rva: int) -> int:
        for lo, hi, off in self.secs:
            if lo <= rva < hi:
                return off + rva - lo
        return -1

    def rva(self, i: int) -> int:
        for lo, hi, off in self.secs:
            if off <= i < off + hi - lo:
                return lo + i - off
        return -1

    def set(self, rva: int, n: int, bit: int):
        i = self.idx(rva)
        if i >= 0:
            self.f[i:i + n] |= bit

    def get(self, rva: int) -> int:
        i = self.idx(rva)
        return int(self.f[i]) if i >= 0 else 0

    def any_in(self, rva: int, n: int, bit: int) -> bool:
        i = self.idx(rva)
        return i >= 0 and bool((self.f[i:i + n] & bit).any())


# ----------------------------------------------------------------- roots --

UNW_EHANDLER, UNW_UHANDLER, UNW_CHAININFO = 1, 2, 4


def collect_roots(im: Image, code: Code):
    """[(rva, why)] for every place the image itself says code begins."""
    roots = []
    rf = im.runtime_functions()
    for b in rf[:, 0]:
        roots.append((int(b), "pdata"))
    roots.append((im.entry_rva, "entry"))
    for t in im.tls_callbacks():
        roots.append((t, "tls"))
    # exports
    erva, esz = im.dirs[0]
    if erva:
        nfun, = struct.unpack_from("<I", im.mem, erva + 20)
        afun, = struct.unpack_from("<I", im.mem, erva + 28)
        for k in range(nfun):
            r = im.u32(afun + 4 * k)
            if r and code.in_code(r):
                roots.append((r, "export"))
    # relocated pointers in data sections
    rel = im.relocations()
    for s in im.sections:
        if s.executable:
            continue
        sel = rel[(rel >= s.rva) & (rel < s.rva + s.vsize)]
        for r in sel:
            r = int(r)
            v = im.u64(r) - im.image_base
            if code.in_code(v):
                roots.append((v, "reloc:" + s.name))
    # unwind info: handlers and C scope tables
    handlers = collections.Counter()
    scope = []
    for b, e, u in rf:
        b, e, u = int(b), int(e), int(u)
        if u & 1:
            continue
        flags = im.mem[u] >> 3
        ncodes = im.mem[u + 2]
        p = u + 4 + 2 * ((ncodes + 1) & ~1)
        if flags & UNW_CHAININFO:
            continue
        if flags & (UNW_EHANDLER | UNW_UHANDLER):
            h = im.u32(p)
            handlers[h] += 1
            scope.append((b, e, h, p + 4))
    for h in handlers:
        if code.in_code(h):
            roots.append((h, "handler"))
    # a handler whose data parses as a C scope table for (nearly) all of its
    # users is __C_specific_handler; its filters and __except targets are code
    good = collections.Counter()
    parsed = collections.defaultdict(list)
    for b, e, h, d in scope:
        n = im.u32(d)
        ok = 0 < n < 256
        recs = []
        if ok:
            for k in range(n):
                sb, se, sh, st = struct.unpack_from("<IIII", im.mem, d + 4 + 16 * k)
                if not (b <= sb < e and b < se <= e + 1):
                    ok = False
                    break
                recs.append((sh, st))
        if ok:
            good[h] += 1
            parsed[h].append(recs)
    for h, cnt in good.items():
        if cnt >= 0.9 * handlers[h] and cnt >= 3:
            for recs in parsed[h]:
                for sh, st in recs:
                    if sh > 1 and code.in_code(sh):
                        roots.append((sh, "scope-handler"))
                    if st and code.in_code(st):
                        roots.append((st, "scope-target"))
    return roots


# ------------------------------------------------- routine model / folds --
#
# A routine reached through a `push R ; push G ; ret` chain does not return
# to the slot the construct around the chain pushed. On its success path it
# writes three qwords on the caller's stack, starting at the slot just above
# the chain's register save: T0 and T1 (addresses of `ret`-equivalent
# gadgets) and T2 (the real continuation). The construct's own tail pops the
# first, the gadgets pop the other two. So the whole nest of constructs
# around the chain is "drop k slots, jump to T2". The table of routines and
# their continuations comes from emulating each routine (`--routines`).

class RoutineModel:
    def __init__(self, path: str | None, image_base: int):
        self.r: dict[int, dict] = {}
        self.writes: list[tuple[int, int]] = []   # image bytes any routine writes
        self.extra_used, self.extra_given = set(), set()
        self.not_routines = []
        if not path:
            return
        tab = json.load(open(path))
        self.meta = tab.get("meta")
        tab = tab.get("routines", tab)
        self.not_routines = []
        for k, v in tab.items():
            g = int(k, 16)
            stub = v.get("stub")
            if isinstance(stub, dict):
                # the routine census's own format: stub kind "continuation"
                # (with cont), "ret" (none learnt yet) or "none" (not a
                # routine: a decoy wrapper in front of a chain)
                if stub.get("stub") == "none":
                    self.not_routines.append(g)
                    continue
                cont = stub.get("cont") if stub.get("stub") == "continuation" else []
            else:
                cont = v.get("cont") or []
            self.r[g] = {
                "form": v.get("form"),
                "class": v.get("class"),
                "stop": v.get("stop"),
                "cont": [(int(o), int(t, 16) - image_base) for o, t in (cont or [])],
                "regs_changed": list(v.get("regs_changed") or []),
                # the routine census proved, per routine, that running the
                # chain with its stub in place of the routine gives the same
                # rip, rsp, GPRs, flags and live stack as the real routine.
                # The stub writes rax, rcx, rdx (and r8 when it sets r8d).
                "proven": any(isinstance(x, dict) and x.get("kind") == "chain" and x.get("pass")
                              for x in (v.get("proof") or [])) if "proof" in v else None,
                "stub_r8": (stub or {}).get("r8") if isinstance(stub, dict) else None,
                # a table read from the routines' code (find_routines.py)
                # says which registers a routine may leave changed
                "clobbers": v.get("clobbers"),
                # the dwords a guard publishes when it runs (find_routines.py
                # --checks): a construct with such a routine stays in place
                "publishes": v.get("publishes") or [],
            }
            for w in (v.get("success_writes") or v.get("writes") or []):
                self.writes.append((int(w["rva"]), int(w["size"])))

    def add_extra(self, path: str, image_base: int):
        """Continuations measured separately, for routines the main table
        has none for: {"0x<G>": {"cont_rva": [T0, T1, T2], "offset_measured": o}}."""
        tab = json.load(open(path))
        for k, v in tab.items():
            g = int(k, 16)
            m = self.r.get(g)
            if m is not None and len(m["cont"]) == 3:
                continue                       # the main table wins
            if m is None:
                m = self.r[g] = {"form": "pushret", "class": v.get("class_in_census"), "stop": None,
                                 "cont": [], "regs_changed": [], "proven": None, "stub_r8": None}
            o = int(v.get("offset_measured") or 0)
            m["cont"] = [(o + 8 * i, int(t, 16)) for i, t in enumerate(v["cont_rva"])]
            m["extra"] = True
            self.extra_given.add(g)

    def get(self, g):
        return self.r.get(g)

    def effect(self, ch):
        """('net', None) for a routine that returns (start-up, call form),
        ('cont', (T0, T1, T2), clobbered regs) for a continuation writer,
        ('unknown', why) otherwise."""
        m = self.r.get(ch.G)
        if m is None:
            return ("unknown", "routine not in table")
        if m["form"] == "call":
            return ("net", None)
        c = m["cont"]
        if len(c) != 3:
            return ("unknown", "continuation has %d slots" % len(c))
        # offsets from the routine's entry rsp; the alignment push is 10h or
        # 18h, which moves them by 8; the slots relative to the save are the same
        o = 0x118 + 8 * len(ch.push_order)
        got = [x[0] for x in c]
        if got not in ([o, o + 8, o + 16], [o + 8, o + 16, o + 24]):
            return ("unknown", "continuation offsets %s, expected %d" % ([x[0] for x in c], o))
        saved = set(ch.push_order)
        if m.get("clobbers") is not None and not m.get("proven"):
            # no run on record, but the routine's exit code was read: the
            # chain restores what it saved, the rest of the listed set may
            # come back changed
            clob = [r for r in m["clobbers"] if r not in saved]
        elif m.get("proven"):
            # the chain proof (routine census) shows the routine's effect at
            # the chain's end is exactly its stub's: rax, rcx, rdx, and r8
            # where the stub sets r8d. Saved or not: the stub, like the
            # routine, writes them through the chain's save area.
            clob = [r for r in ["rax", "rcx", "rdx"] + (["r8"] if m.get("stub_r8") is not None else [])
                    if r not in saved]
            # (a register the chain saves can come back changed, as at
            # 0x2464E5EB, but only where it is dead after the construct: the
            # fold proof compares every live register and found no case
            # where a saved, live register differs)
        elif m.get("proven") is False:
            return ("unknown", "the routine's chain proof did not pass")
        else:
            # no proof on record (a continuation measured separately): any
            # volatile register, and whatever the table saw change
            vol = ("rax", "rcx", "rdx", "r8", "r9", "r10", "r11")
            clob = sorted(set(r for r in list(vol) + m["regs_changed"] if r in GPRSET and r != "rsp"))
        if m.get("extra"):
            self.extra_used.add(ch.G)
        return ("cont", tuple(t for _, t in c), clob)


class Unknown:
    """A construct that runs through a chain whose routine has no usable
    continuation: it is left alone and everything it reaches is kept."""
    __slots__ = ("start", "chain", "why", "insns")

    def __init__(self, start, chain, why, insns):
        self.start, self.chain, self.why, self.insns = start, chain, why, insns


class _St:
    __slots__ = ("regs", "mem", "sp", "insns", "inner", "flags_clob", "clob", "seen", "n")

    def copy(self):
        s = _St()
        s.regs = dict(self.regs)
        s.mem = dict(self.mem)
        s.sp = self.sp
        s.insns = list(self.insns)
        s.inner = list(self.inner)
        s.flags_clob = self.flags_clob
        s.clob = set(self.clob)
        s.seen = set(self.seen)
        s.n = self.n
        return s


def _continuable(code, t):
    d = code.insn(t)
    if d is None:
        return False
    m, op = d[1], d[2]
    return (m in IDIOM_FIRST or (m == "ret" and not op) or m == "pushfq" or
            (m == "jmp" and (op.startswith("0x") or rsp_disp(op) is not None)))


def resolve_construct(code: Code, a: int, max_insns: int = 1200, max_depth: int = 24):
    """Evaluate the stack-move construct starting at a, stepping over the
    chains inside it with their routine's effect and continuing into any
    constant target that is itself such a construct (or a ret gadget).

    Returns an Idiom (kinds jmp, jcc, call, popjmp), an Unknown, or None."""
    first = code.insn(a)
    if first is None or not (first[1] in IDIOM_FIRST or first[1] == "pushfq"):
        return None
    st = _St()
    st.regs, st.mem, st.sp = {}, {}, 0
    st.insns, st.inner, st.flags_clob, st.clob, st.seen, st.n = [], [], False, set(), set(), 0
    return _eval(code, a, a, st, 0, max_insns, max_depth)


def _eval(code, a, pc, st, depth, max_insns, max_depth):
    base = code.base
    model = getattr(code, "model", None)
    regs, mem = st.regs, st.mem
    while st.n < max_insns:
        st.n += 1
        if pc in st.seen:
            return None
        st.seen.add(pc)
        d = code.insn(pc)
        if d is None:
            return None
        size, m, op = d
        if (m == "push" and op in GPRSET) or m == "pushfq":
            ch = match_chain(code, pc)
            if ch is not None:
                eff = model.effect(ch) if model is not None else ("net", None)
                if eff[0] == "unknown":
                    return Unknown(a, ch, eff[1], st.insns + ch.insns)
                st.inner.append((ch, eff))
                st.insns.extend(ch.insns)
                if "flags" not in ch.push_order:
                    st.flags_clob = True
                if eff[0] == "cont":
                    t0, t1, t2 = eff[1]
                    mem[st.sp] = ("c", t0)
                    mem[st.sp + 8] = ("c", t1)
                    mem[st.sp + 16] = ("c", t2)
                    for r in eff[2]:
                        regs[r] = ("clob", r)
                        st.clob.add(r)
                pc = ch.E_raw
                continue
        st.insns.append((pc, size))
        nxt = pc + size
        if m == "jmp" or m == "ret":
            if m == "jmp":
                if op.startswith("0x"):
                    pc = int(op, 16)
                    continue
                dd = rsp_disp(op)
                if dd is None:
                    return None
                tgt = mem.get(st.sp + dd, ("m", st.sp + dd))
            else:
                if op:
                    return None
                tgt = mem.get(st.sp, ("m", st.sp))
                st.sp += 8
            if tgt[0] == "c" and depth < max_depth and _continuable(code, tgt[1]):
                r = _eval(code, a, tgt[1], st.copy(), depth + 1, max_insns, max_depth)
                if r is not None:
                    return r
            return _finish2(code, a, st, tgt, pc)
        ops = op.split(", ") if op else []
        sp = st.sp
        if m == "push":
            if len(ops) != 1 or ops[0] not in GPRSET or ops[0] == "rsp":
                return None
            st.sp -= 8
            mem[st.sp] = regs.get(ops[0], ("r", ops[0]))
        elif m == "pop":
            if len(ops) != 1 or ops[0] not in GPRSET or ops[0] == "rsp":
                return None
            regs[ops[0]] = mem.get(sp, ("m", sp))
            st.sp += 8
        elif m == "lea":
            dd = lea_rsp_disp(op)
            if dd is not None:
                if dd % 8:
                    return None
                st.sp += dd
            elif len(ops) == 2 and ops[0] in GPRSET and ops[0] != "rsp" and ops[1].startswith("[rip"):
                regs[ops[0]] = ("c", rip_target(ops[1], nxt))
            else:
                return None
        elif m in ("mov", "movabs"):
            if len(ops) != 2:
                return None
            d0, d1 = ops
            if d0 in GPRSET and d0 != "rsp":
                if d1 in GPRSET and d1 != "rsp":
                    regs[d0] = regs.get(d1, ("r", d1))
                elif d1.startswith("qword ptr [rsp"):
                    dd = rsp_disp(d1)
                    if dd is None:
                        return None
                    regs[d0] = mem.get(sp + dd, ("m", sp + dd))
                elif m == "movabs" and re.fullmatch(r"0x[0-9a-f]+|\d+", d1):
                    v = int(d1, 0)
                    if not (base <= v < base + len(code.mem)):
                        return None
                    regs[d0] = ("c", v - base)
                else:
                    return None
            elif d0.startswith("qword ptr [rsp") and d1 in GPRSET and d1 != "rsp":
                dd = rsp_disp(d0)
                if dd is None:
                    return None
                mem[sp + dd] = regs.get(d1, ("r", d1))
            else:
                return None
        elif m == "xchg":
            if len(ops) != 2:
                return None
            x0, x1 = ops
            if x1.startswith("qword ptr [rsp"):
                x0, x1 = x1, x0
            if x0.startswith("qword ptr [rsp") and x1 in GPRSET and x1 != "rsp":
                dd = rsp_disp(x0)
                if dd is None:
                    return None
                old = mem.get(sp + dd, ("m", sp + dd))
                mem[sp + dd] = regs.get(x1, ("r", x1))
                regs[x1] = old
            elif x0 in GPRSET and x1 in GPRSET and "rsp" not in (x0, x1):
                v0 = regs.get(x0, ("r", x0))
                regs[x0] = regs.get(x1, ("r", x1))
                regs[x1] = v0
            else:
                return None
        elif m.startswith("cmov"):
            cc = norm_cc(m[4:])
            if st.flags_clob or cc is None or len(ops) != 2 or ops[0] not in GPRSET \
                    or ops[1] not in GPRSET:
                return None
            v0 = regs.get(ops[0], ("r", ops[0]))
            v1 = regs.get(ops[1], ("r", ops[1]))
            if v0[0] != "c" or v1[0] != "c":
                return None
            regs[ops[0]] = ("sel", cc, v1[1], v0[1])
        else:
            return None
        pc = nxt
    return None


def _finish2(code, a, st, tgt, endpc):
    for r, v in st.regs.items():
        if v != ("r", r) and v != ("clob", r):
            return None
    sp, mem = st.sp, st.mem
    if sp == -8:
        rv = mem.get(-8)
        if rv is None or rv[0] != "c":
            return None
        kind = "call"
    elif sp >= 0 and sp % 8 == 0:
        kind = "jmp" if sp == 0 else "popjmp"
    else:
        return None
    for off, v in mem.items():
        if off >= sp and not (kind == "call" and off == -8):
            if v != ("m", off):
                return None
    inner = [c for c, _ in st.inner]
    if tgt[0] == "c":
        if not code.in_code(tgt[1]):
            return None
        if kind == "call":
            r = mem[-8][1]
            if not code.in_code(r):
                return None
            i = Idiom(a, "call", None, tgt[1], None, r, st.insns, endpc, inner)
        else:
            i = Idiom(a, kind, None, tgt[1], None, None, st.insns, endpc, inner)
    elif tgt[0] == "sel" and kind == "jmp":
        _, cc, b, aa = tgt
        if not (code.in_code(b) and code.in_code(aa)):
            return None
        i = Idiom(a, "jcc", cc, b, aa, None, st.insns, endpc, inner)
    else:
        return None
    i.pop = sp // 8 if kind == "popjmp" else 0
    i.effects = [e for _, e in st.inner]
    i.flags_clob = st.flags_clob
    i.clob = sorted(st.clob)
    return i


# register liveness (for registers a folded routine would have changed)
_R64 = {}
for _r in GPR64:
    _R64[_r] = _r
for _a, _b in (("eax", "rax"), ("ax", "rax"), ("al", "rax"), ("ah", "rax"),
               ("ebx", "rbx"), ("bx", "rbx"), ("bl", "rbx"), ("bh", "rbx"),
               ("ecx", "rcx"), ("cx", "rcx"), ("cl", "rcx"), ("ch", "rcx"),
               ("edx", "rdx"), ("dx", "rdx"), ("dl", "rdx"), ("dh", "rdx"),
               ("esi", "rsi"), ("si", "rsi"), ("sil", "rsi"), ("edi", "rdi"), ("di", "rdi"),
               ("dil", "rdi"), ("ebp", "rbp"), ("bp", "rbp"), ("bpl", "rbp")):
    _R64[_a] = _b
for _k in range(8, 16):
    for _s in ("d", "w", "b"):
        _R64["r%d%s" % (_k, _s)] = "r%d" % _k


class RegLiveness:
    """Is any of `regs` read before being fully written, on any path?
    'dead' / 'live' / 'unknown'. A call reads rcx, rdx, r8, r9 and ends the
    path for the volatile rest; ret reads rax."""

    def __init__(self, code: Code):
        self.code = code
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.md.detail = True

    def _insn(self, a):
        for i in self.md.disasm(bytes(self.code.mem[a:a + 16]), a, 1):
            return i
        return None

    VOL = frozenset(("rax", "rcx", "rdx", "r8", "r9", "r10", "r11"))

    def _through_call(self, target, pend, depth, cdepth):
        """At a call: a volatile register is live only if the callee reads it
        before writing it (bounded descent, all paths); after the call it is
        dead (the callee may change it, the caller cannot rely on it).
        Non-volatile registers pass through. Returns (verdict or None, pend)."""
        vp = pend & self.VOL
        if vp:
            if target is None or cdepth >= 3:
                return "live", pend
            r = self.at(target, vp, depth, callee=True, cdepth=cdepth + 1)
            if r != "dead":
                return r, pend
        return None, pend - self.VOL

    def at(self, a, regs, depth=160, callee=False, cdepth=0):
        if not regs:
            return "dead"
        work = [(a, frozenset(regs), 0)]
        seen = set()
        while work:
            pc, pend, n = work.pop()
            while True:
                if (pc, pend) in seen:
                    break
                seen.add((pc, pend))
                if n > depth:
                    return "unknown"
                n += 1
                d = self.code.insn(pc)
                if d is None:
                    return "unknown"
                if d[1] in IDIOM_FIRST or d[1] == "pushfq":
                    idm = resolve_construct(self.code, pc)
                    if isinstance(idm, Unknown):
                        return "unknown"
                    if idm is not None:
                        if idm.clob and pend & set(idm.clob):
                            pend = pend - set(idm.clob)    # overwritten by a routine
                        if idm.kind in ("jmp", "popjmp"):
                            pc = idm.target
                            continue
                        if idm.kind == "jcc":
                            work.append((idm.target, pend, n))
                            pc = idm.fall
                            continue
                        v, pend = self._through_call(idm.target, pend, depth, cdepth)
                        if v is not None:
                            return v
                        if not pend:
                            break
                        pc = idm.ret
                        continue
                i = self._insn(pc)
                if i is None:
                    return "unknown"
                m = i.mnemonic
                if m == "nop":
                    pc += i.size          # a multi-byte nop's operand is never read
                    continue
                if m == "call":
                    tgt = int(i.op_str, 16) if i.op_str.startswith("0x") else None
                    v, pend = self._through_call(tgt, pend, depth, cdepth)
                    if v is not None:
                        return v
                    if not pend:
                        break
                    pc += i.size
                    continue
                if m == "ret":
                    if "rax" in pend and not callee:
                        return "live"
                    break         # in a callee: volatile registers end at its return
                try:
                    rd, wr = i.regs_access()
                except Exception:
                    return "unknown"
                rd = set(_R64.get(i.reg_name(x), "") for x in rd)
                if pend & rd:
                    # xor r,r and sub r,r read nothing in effect
                    if not (m in ("xor", "sub") and len(i.operands) == 2 and
                            i.op_str.split(", ")[0] == i.op_str.split(", ")[1]):
                        return "live"
                full = set()
                for x in wr:
                    nm = i.reg_name(x)
                    p = _R64.get(nm)
                    if p and (nm == p or nm.startswith("e") or nm.endswith("d")):
                        full.add(p)
                pend = pend - full
                if not pend:
                    break
                if m in STOP_MN:
                    break
                if m == "jmp":
                    if i.op_str.startswith("0x"):
                        pc = int(i.op_str, 16)
                        continue
                    return "unknown"
                if (m in JCC_MN or m in COND_REL8) and i.op_str.startswith("0x"):
                    work.append((int(i.op_str, 16), pend, n))
                pc += i.size
        return "dead"


# ---------------------------------------------------------------- walker --

RE_JT =re.compile(r"^(e\w\w|r\d+d), dword ptr \[(r\w+) \+ (r\w+)\*4 \+ (0x[0-9a-f]+)\]$")


class Walker:
    """Recursive descent over everything reachable from the roots.

    With `bypass` the routine-call chains are stepped over (S -> E); with
    `rewrite` the idioms found are taken as their direct equivalents."""

    def __init__(self, im: Image, code: Code, bypass: bool = True,
                 known_idioms: dict | None = None, known_chains: dict | None = None,
                 resolve: bool = True):
        self.im = im
        self.code = code
        self.bm = ByteMap(im, code.extra)
        self.bypass = bypass
        self.resolve = resolve
        self.idioms: dict[int, Idiom] = {}
        self.chains: dict[int, Chain] = {}
        self.known_idioms = known_idioms
        self.known_chains = known_chains
        self.overlaps = []
        self.undecodable = []
        self.outside = []
        self.jtables = []
        self.datarefs = []          # (from_insn, target)
        self.coderefs = []          # (from_insn, target) lea/movabs into code
        self.indirect = 0
        self.insns = 0
        self.work = []
        self.src = {}
        self.call_targets = set()
        self.unknowns: dict[int, Unknown] = {}
        self.found_in: dict[int, int] = {}   # construct start -> start of the run it was met in
        self.checks: dict = {}
        self.atomic = True          # constructs with chains inside: one step
        self.rewritten: set = set() # (patched image) starts that were rewritten
        self.frozen: set[int] = set()
        self.md = code.md
        self.base = im.image_base
        self.size = len(im.mem)
        self.src_pc = {}            # work item -> the instruction that sent the walk there
        self.track: set = set()     # instruction starts whose first visit is recorded
        self.track_hit = {}         # tracked address -> start of the run that reached it
        self._pc = None
        self._run0 = None
        self.stop_f = None          # flags of another walk: stop at its instruction starts
        self.poison: set = set()    # instruction starts never executed by this walk
        self.follow_refs = True     # walk code addresses taken by lea / movabs
        self.tables = True          # recover jump tables

    def _push(self, rva, src):
        self.work.append(rva)
        if rva not in self.src:
            self.src[rva] = src
            self.src_pc[rva] = self._pc

    def walk(self, roots):
        for r, why in roots:
            self.work.append(r)
            if r not in self.src:
                self.src[r] = why
        while self.work:
            self._run(self.work.pop())

    def origin(self, rva, depth=8):
        """Provenance chain of a work item: [rva, src, src-of-src, ...]."""
        out = [rva]
        for _ in range(depth):
            s = self.src.get(out[-1])
            if s is None or isinstance(s, str):
                if s is not None:
                    out.append(s)
                break
            out.append(s)
        return out

    def _mark(self, insns, bit):
        bm = self.bm
        for a, n in insns:
            bm.set(a, n, bit)
            bm.set(a, 1, ISTART)
            if self.track and a in self.track:
                self.track_hit.setdefault(a, (self._run0, self._pc))

    def _run(self, pc):
        run0 = pc
        self._run0 = run0
        code = self.code
        bm = self.bm
        f = bm.f
        hist = collections.deque(maxlen=24)
        mem = self.im.mem
        md = self.md
        track = self.track
        while True:
            i = bm.idx(pc)
            if i < 0:
                self.outside.append((pc, run0))
                return
            fl = f[i]
            if fl & START:
                return
            if self.stop_f is not None and self.stop_f[i] & START:
                return
            if pc in self.poison:
                return
            self._pc = pc
            if track and pc in track:
                self.track_hit.setdefault(pc, (run0, pc))
            if fl & (CODE | IDIOM | CHAIN):
                self.overlaps.append((pc, run0))
            d = None
            for _, size, m, op in md.disasm_lite(bytes(mem[pc:pc + 16]), pc, 1):
                d = (size, m, op)
            if d is None:
                self.undecodable.append((pc, run0))
                return
            size, m, op = d
            nxt = pc + size
            is_push = (m == "push" and op in GPRSET) or m == "pushfq"
            ck = self.checks.get(pc) if self.bypass else None
            if ck is not None and ck.why is None:
                # a check with one outcome on the baked image: step over
                self.found_in[pc] = run0
                self._mark(ck.insns, CHAIN)
                f[i] |= START
                self._push(ck.E, run0)
                return
            if self.bypass and is_push and pc not in self.frozen:
                ch = self.known_chains.get(pc) if self.known_chains is not None else None
                if ch is None and self.resolve:
                    ch = match_chain(code, pc)
                model = getattr(code, "model", None)
                if ch is not None and (model is None or model.effect(ch)[0] == "net"):
                    # a routine that returns (the start-up routines): step over
                    self.chains[pc] = ch
                    self._mark(ch.insns, CHAIN)
                    f[i] |= START
                    self._push(ch.E, run0)
                    return
            if pc not in self.frozen and (is_push or (m in IDIOM_FIRST and (
                    (m == "lea" and op.startswith("rsp, [rsp - ")) or
                    (m == "mov" and op.startswith("qword ptr [rsp - "))))):
                idm = None
                if self.known_idioms is not None:
                    idm = self.known_idioms.get(pc)
                if idm is None and self.resolve:
                    idm = resolve_construct(code, pc)
                if idm is not None and not isinstance(idm, Unknown) and idm.inner                         and not self.atomic and pc not in self.rewritten:
                    # a construct with a routine call inside that is not
                    # rewritten: the original runs all of it, so walk it
                    idm = None
                if isinstance(idm, Unknown):
                    # leave it alone: walk it as plain code, keep all it reaches
                    self.unknowns.setdefault(pc, idm)
                    for a_, n_ in idm.insns:
                        self.frozen.add(a_)
                    idm = None
                if idm is not None:
                    self.idioms[pc] = idm
                    self.found_in[pc] = run0
                    self._mark(idm.insns, IDIOM)
                    f[i] |= START
                    if idm.kind == "jmp" and not idm.inner:
                        # a plain disguised jump: carry on in the same run,
                        # so the instruction history (jump tables) survives
                        if idm.target not in self.src:
                            self.src[idm.target] = run0
                            self.src_pc[idm.target] = pc
                        pc = idm.target
                        continue
                    if idm.kind == "jcc" and not idm.inner:
                        self._push(idm.target, run0)
                        if idm.fall not in self.src:
                            self.src[idm.fall] = run0
                            self.src_pc[idm.fall] = pc
                        hist.append((pc, 0, "j" + idm.cc, "0x%x" % idm.target))
                        pc = idm.fall
                        continue
                    if idm.kind in ("jmp", "popjmp"):
                        self._push(idm.target, run0)
                    elif idm.kind == "jcc":
                        self._push(idm.target, run0)
                        self._push(idm.fall, run0)
                    else:
                        self._push(idm.target, run0)
                        self._push(idm.ret, run0)
                        self.call_targets.add(idm.target)
                    return
            f[i] |= START
            f[i:i + size] |= CODE
            self.insns += 1
            if "rip" in op:
                t = rip_target(op, nxt)
                if t is not None:
                    if m == "lea" and code.in_code(t):
                        self.coderefs.append((pc, t))
                        if self.follow_refs:
                            self._push(t, run0)
                    else:
                        self.datarefs.append((pc, t))
                        if m in ("jmp", "call"):
                            self.indirect += 1
                            if m == "jmp":
                                return
            elif m == "movabs":
                ops = op.split(", ")
                if len(ops) == 2 and ops[1].startswith("0x"):
                    v = int(ops[1], 16) - self.base
                    if 0 <= v < self.size:
                        if code.in_code(v):
                            self.coderefs.append((pc, v))
                            if self.follow_refs:
                                self._push(v, run0)
                        else:
                            self.datarefs.append((pc, v))
            if m == "jmp":
                if op.startswith("0x"):
                    # joining jumps are not kept in the history: the jump
                    # table pattern is spread over many pieces
                    pc = int(op, 16)
                    continue
                self.indirect += 1
                if op in GPRSET and self.tables:
                    self._jump_table(pc, op, hist)
                elif op == "qword ptr [rsp - 8]" and len(hist) >= 3 and self.tables:
                    # `mov [rsp-8],r ; lea rsp,[rsp-8] ; lea rsp,[rsp+8] ;
                    # jmp [rsp-8]` is `push r ; ret`, i.e. `jmp r`: the
                    # protection's spelling of a switch's indirect jump
                    hl = [h for h in hist if not (h[2] == "jmp" and h[3].startswith("0x"))]
                    h3 = hl[-3:]
                    if len(h3) == 3 and h3[1][2] == "lea" and h3[2][2] == "lea" \
                            and lea_rsp_disp(h3[1][3]) == -8 and lea_rsp_disp(h3[2][3]) == 8 \
                            and h3[0][2] == "mov" and h3[0][3].startswith("qword ptr [rsp - 8], "):
                        r = h3[0][3].split(", ")[1]
                        if r in GPRSET and r != "rsp":
                            self._jump_table(pc, r, collections.deque(hl[:-3], maxlen=24))
                return
            if m in JCC_MN or m in COND_REL8:
                if op.startswith("0x"):
                    self._push(int(op, 16), run0)
            elif m == "call":
                if op.startswith("0x"):
                    self._push(int(op, 16), run0)
                    self.call_targets.add(int(op, 16))
                else:
                    self.indirect += 1
            elif m in STOP_MN or m == "int":
                return
            hist.append((pc, size, m, op))
            pc = nxt

    def _jump_table(self, site, reg, hist):
        """MSVC: lea B,[__ImageBase] ; mov r32,[B+I*4+T] ; add r64,B ; jmp r64."""
        h = list(hist)
        r32 = None
        table = None
        idx_reg = None
        for k in range(len(h) - 1, -1, -1):
            _, _, m, op = h[k]
            if m == "add" and table is None and op.startswith(reg + ", "):
                continue
            if m == "mov":
                mm = RE_JT.match(op)
                if mm and table is None:
                    table = int(mm.group(4), 16)
                    idx_reg = mm.group(3)
                    r32 = mm.group(1)
                    kk = k
                    break
        if table is None:
            return
        bound = None
        for k in range(kk - 1, max(-1, kk - 16), -1):
            _, _, m, op = h[k]
            if m == "cmp":
                ops = op.split(", ")
                if len(ops) == 2 and re.fullmatch(r"0x[0-9a-f]+|\d+", ops[1]):
                    bound = int(ops[1], 0) + 1
                    break
        lo_sec = None
        for lo, hi in self.code.ex:
            if lo <= site < hi:
                lo_sec = (lo, hi)
        n = 0
        tg = []
        cap = bound if bound is not None and bound <= 4096 else 512
        while n < cap:
            if not (0 <= table + 4 * n + 4 <= self.size):
                break
            t = self.im.u32(table + 4 * n)
            if bound is None and not (lo_sec and lo_sec[0] <= t < lo_sec[1]):
                break
            if not self.code.in_code(t):
                break
            tg.append(t)
            n += 1
        self.jtables.append((site, table, n, bound))  # noqa
        self.datarefs.append((site, table))
        self.bm.set(table, 4 * n, DREAD)
        for t in tg:
            # provenance: the run that holds the dispatch (src_pc is the site)
            self._push(t, self._run0 if self._run0 is not None else site)


# -------------------------------------------------------- flag liveness --

from capstone import x86_const as XC  # noqa: E402

STATUS = (("CF", XC.X86_EFLAGS_TEST_CF, (XC.X86_EFLAGS_MODIFY_CF, XC.X86_EFLAGS_RESET_CF,
                                          XC.X86_EFLAGS_SET_CF, XC.X86_EFLAGS_UNDEFINED_CF)),
          ("PF", XC.X86_EFLAGS_TEST_PF, (XC.X86_EFLAGS_MODIFY_PF, XC.X86_EFLAGS_RESET_PF,
                                          XC.X86_EFLAGS_SET_PF, XC.X86_EFLAGS_UNDEFINED_PF)),
          ("AF", XC.X86_EFLAGS_TEST_AF, (XC.X86_EFLAGS_MODIFY_AF, XC.X86_EFLAGS_RESET_AF,
                                          XC.X86_EFLAGS_SET_AF, XC.X86_EFLAGS_UNDEFINED_AF)),
          ("ZF", XC.X86_EFLAGS_TEST_ZF, (XC.X86_EFLAGS_MODIFY_ZF, XC.X86_EFLAGS_RESET_ZF,
                                          XC.X86_EFLAGS_SET_ZF, XC.X86_EFLAGS_UNDEFINED_ZF)),
          ("SF", XC.X86_EFLAGS_TEST_SF, (XC.X86_EFLAGS_MODIFY_SF, XC.X86_EFLAGS_RESET_SF,
                                          XC.X86_EFLAGS_SET_SF, XC.X86_EFLAGS_UNDEFINED_SF)),
          ("OF", XC.X86_EFLAGS_TEST_OF, (XC.X86_EFLAGS_MODIFY_OF, XC.X86_EFLAGS_RESET_OF,
                                          XC.X86_EFLAGS_SET_OF, XC.X86_EFLAGS_UNDEFINED_OF)))


class FlagLiveness:
    """Are the status flags read before being written, on any path from a?

    'dead'   every path overwrites all six before reading any (a call or
             ret counts as overwriting: flags do not survive a call under
             the Windows x64 convention),
    'live'   some path reads one first,
    'unknown' the search ran out (indirect jump, depth)."""

    def __init__(self, code: Code, chains: dict | None = None):
        self.code = code
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.md.detail = True
        self.chains = chains or {}

    def _insn(self, a):
        for i in self.md.disasm(bytes(self.code.mem[a:a + 16]), a, 1):
            return i
        return None

    def at(self, a: int, depth: int = 96):
        work = [(a, frozenset(n for n, _, _ in STATUS), 0)]
        seen = set()
        res = "dead"
        while work:
            pc, pend, n = work.pop()
            while True:
                if (pc, pend) in seen:
                    break
                seen.add((pc, pend))
                if n > depth:
                    return "unknown"
                n += 1
                ch = self.chains.get(pc)
                if ch is not None and ch.E != pc:
                    # a chain with pushfq/popfq preserves flags; otherwise its
                    # own test rsp,0Fh overwrites them all
                    if "flags" in ch.push_order:
                        pc = ch.E
                        continue
                    break
                idm = resolve_construct(self.code, pc) if self.code.insn(pc) and \
                    self.code.insn(pc)[1] in IDIOM_FIRST else None
                if isinstance(idm, Unknown):
                    return "unknown"
                if idm is not None:
                    if idm.kind == "jcc":
                        return "live"
                    if idm.flags_clob:
                        break  # a chain on the way overwrites them all
                    if idm.kind in ("jmp", "popjmp"):
                        pc = idm.target
                        continue
                    break      # call: flags volatile across calls
                i = self._insn(pc)
                if i is None:
                    return "unknown"
                ef = i.eflags
                for name, tbit, wbits in STATUS:
                    if name in pend and ef & tbit:
                        return "live"
                if i.mnemonic in ("pushfq", "pushf", "lahf"):
                    return "live"
                w = set()
                for name, tbit, wbits in STATUS:
                    if any(ef & b for b in wbits):
                        w.add(name)
                pend = pend - w
                if i.mnemonic in ("popfq", "popf", "sahf"):
                    pend = frozenset()
                if not pend:
                    break
                m = i.mnemonic
                if m in ("ret", "call") or m in STOP_MN:
                    break
                if m == "jmp":
                    if i.op_str.startswith("0x"):
                        pc = int(i.op_str, 16)
                        continue
                    return "unknown"
                if (m in JCC_MN or m in COND_REL8) and i.op_str.startswith("0x"):
                    work.append((int(i.op_str, 16), pend, n))
                pc += i.size
        return res


# ---------------------------------------------------------- chain census --

def long_sub_sites(im: Image, code: Code):
    mem = bytes(im.mem)
    out = []
    for lo, hi in code.ex:
        o = lo
        while True:
            k = mem.find(LONG_SUB8, o, hi)
            if k < 0:
                break
            out.append(k)
            o = k + 1
    return out


def census_chains(im: Image, code: Code, xr: RawXrefs, depth: int = 120):
    """For each long-form `sub rsp,8`, search backwards for the chain whose
    alignment step it is. Returns ({site: Chain}, [sites without one])."""

    def preds(a):
        out = []
        for src, m, size in confirmed_branches_to(code, xr, a):
            if m != "call":
                out.append(src)
        out += confirmed_refs_to(code, xr, a)
        for k in range(1, 16):
            d = code.insn(a - k)
            if d and d[0] == k and d[1] not in STOP_MN and d[1] != "jmp":
                out.append(a - k)
        return out

    res, fail = {}, []
    for x in long_sub_sites(im, code):
        seen = {x}
        q = collections.deque([(x, 0)])
        found = None
        while q:
            a, dep = q.popleft()
            d = code.insn(a)
            if d and ((d[1] == "push" and d[2] in GPRSET) or d[1] == "pushfq"):
                ch = match_chain(code, a)
                if ch is not None and ch.sub_site == x:
                    if found is None or len(ch.push_order) > len(found.push_order):
                        found = ch
            if dep >= depth:
                continue
            for p in preds(a):
                if p not in seen:
                    seen.add(p)
                    q.append((p, dep + 1))
        if found is None:
            fail.append(x)
        else:
            res[x] = found
    return res, fail


def filter_roots(roots, census: dict):
    """Drop exception-directory entries that begin strictly inside a chain's
    instructions: the protection laid its chain pieces over the space of
    some function records, and such a record is not a function entry."""
    inside = set()
    starts = set()
    for ch in census.values():
        starts.add(ch.S)
        for a, n in ch.insns:
            inside.update(range(a, a + n))
    keep, dropped = [], []
    for r, why in roots:
        if why == "pdata" and r in inside and r not in starts:
            dropped.append(r)
        else:
            keep.append((r, why))
    return keep, dropped


# --------------------------------------------------------------- planner --

def chunks_of(insns):
    """Split an idiom's or chain's instruction list into contiguous chunks:
    [(start, end, [insn addrs])]. A joining jmp ends its chunk."""
    out = []
    cur = None
    for a, n in insns:
        if cur is not None and a == cur[1]:
            cur[1] = a + n
            cur[2].append(a)
        else:
            if cur is not None:
                out.append(tuple(cur))
            cur = [a, a + n, [a]]
    if cur is not None:
        out.append(tuple(cur))
    return out


def rel32(frm_next: int, to: int) -> bytes:
    d = to - frm_next
    if not -(1 << 31) <= d < (1 << 31):
        raise ValueError("rel32 out of range")
    return struct.pack("<i", d)


class Planner:
    def __init__(self, im: Image, code: Code, xr: RawXrefs, walk: Walker,
                 roots: list, keep=None):
        self.keep = keep                 # ByteMap of bytes other plans own
        self.keep_overlaps = []
        self.inner_regs: dict[int, str] = {}
        self.fold_dead: dict[int, tuple] = {}
        self.im = im
        self.code = code
        self.xr = xr
        self.w = walk
        self.bm = walk.bm
        self.rootset = set(r for r, _ in roots)
        self.rel = im.relocations()
        self.chain_by_S = dict(walk.chains)
        self.patches: dict[int, tuple] = {}      # rva -> (bytes, kind, tag)
        self.claimed = ByteMap(im, code.extra)  # bytes already patched
        self.idiom_res: dict[int, tuple] = {}    # start -> (status, detail)
        self.chain_res: dict[int, tuple] = {}
        self.drops: set[int] = set()
        self.inner_flags: dict[int, str] = {}

    # -- helpers --------------------------------------------------------
    def entered(self, lo: int, hi: int, own: set = frozenset(), lo_start_ok: bool = True) -> list:
        """Ways into [lo, hi) from outside: walk starts, live references, roots.
        `own` holds source addresses that belong to the construct itself."""
        why = []
        f = self.bm
        # entering at lo itself is fine when the patch is written at lo:
        # whoever came in there gets the rewritten instruction
        first = lo + 1 if lo_start_ok else lo
        for a in range(first, hi):
            if a in self.rootset:
                why.append(("root", a))
            if f.get(a) & START:
                why.append(("walk-start", a))
        i0 = np.searchsorted(self.xr.tgt, first, "left")
        i1 = np.searchsorted(self.xr.tgt, hi, "left")
        for i in range(i0, i1):
            src, k, t = int(self.xr.src[i]), int(self.xr.kind[i]), int(self.xr.tgt[i])
            if src in own:
                continue
            if not (f.get(src) & (START | ISTART)):
                continue
            d = self.code.insn(src)
            if d is None or d[0] != KIND_ENC[k][1]:
                continue
            if k < 5:
                if not (d[2].startswith("0x") and int(d[2], 16) == t):
                    continue
            elif d[1] != KIND_ENC[k][0]:
                continue
            why.append(("xref", src, t))
        return why

    def final(self, x: int) -> int:
        """Follow joining jumps, jmp idioms and bypassed chains."""
        seen = set()
        for _ in range(64):
            if x in seen:
                break
            seen.add(x)
            ch = self.chain_by_S.get(x)
            if ch is not None and ch.bypass:
                x = ch.E
                continue
            idm = self.w.idioms.get(x)
            if idm is not None and idm.kind == "jmp" and not self.publishing(idm):
                x = idm.target
                continue
            d = self.code.insn(x)
            if d is not None and d[1] == "jmp" and d[2].startswith("0x") and d[0] == 5:
                x = int(d[2], 16)
                continue
            break
        return x

    publishers = frozenset()

    def publishing(self, idm) -> bool:
        """The construct calls a guard that publishes a value when it runs.
        Such a construct is not a jump in disguise: it stays as shipped, and
        nothing else may be aimed past it (1.20: a check's fold landed on the
        continuation of the guard that follows the check, the guard never
        ran, and the next check of its value took the tamper path)."""
        return bool(self.publishers) and any(ch.G in self.publishers for ch in idm.inner)

    def _free(self, lo, hi):
        return not self.claimed.any_in(lo, hi - lo, 1)

    def _put(self, rva, data, kind, tag, fill_to=None):
        if fill_to is not None and fill_to > rva + len(data):
            data = data + b"\xCC" * (fill_to - rva - len(data))
        self.patches[rva] = (bytes(data), kind, tag)
        self.claimed.set(rva, len(data), 1)
        lo = np.searchsorted(self.rel, rva - 7, "left")
        hi = np.searchsorted(self.rel, rva + len(data), "left")
        for r in self.rel[lo:hi]:
            self.drops.add(int(r))

    # -- chains ---------------------------------------------------------
    def plan_chains(self):
        # decide first, emit second: final() must only see through chains
        # that really are bypassed
        for S, ch in sorted(self.chain_by_S.items()):
            ch.bypass = self._decide_chain(S, ch)
        for S, ch in sorted(self.chain_by_S.items()):
            if not ch.bypass:
                continue
            ch.final = self.final(ch.E)
            if ch.S_patch == "jmp":
                self._put(S, b"\xE9" + rel32(S + 5, ch.final), planfile.KIND_BYPASS,
                          "chain %X" % S)
            else:
                for kind, src in ch.preds:
                    d = self.code.insn(src)
                    n = d[0]
                    op = bytes(self.im.mem[src:src + n - 4])
                    self._put(src, op + rel32(src + n, ch.final), planfile.KIND_BYPASS,
                              "chain %X pred" % S)

    def _decide_chain(self, S, ch):
        if True:
            first = chunks_of(ch.insns)[0]
            lo, hi = first[0], first[1]
            if lo != S:
                ch.why = "first chunk does not start at S"
                return False
            preds = self.preds_of(S)
            ch.preds = preds
            own = set(a for a, _ in ch.insns)
            if self.keep is not None and self.keep.any_in(S, 5, 1):
                self.keep_overlaps.append(("chain", S))
                ch.why = "S overlaps a --keep-plan range"
                return False
            if hi - S >= 5 and not self.entered(S, S + 5, own):
                ch.S_patch = "jmp"
                ch.why = None
                return True
            # retarget every predecessor instead
            if not preds or any(kind not in ("jmp", "jcc") for kind, _ in preds):
                ch.why = "S too short and a predecessor is not a rel32 branch"
                return False
            ch.S_patch = "preds"
            return True

    def preds_of(self, S):
        out = []
        for src, m, size in confirmed_branches_to(self.code, self.xr, S):
            if not (self.bm.get(src) & (START | CODE)):
                continue
            if size == 2:
                out.append(("rel8", src))
            elif m == "call":
                out.append(("call", src))
            else:
                out.append(("jmp" if m == "jmp" else "jcc", src))
        for src in confirmed_refs_to(self.code, self.xr, S):
            if self.bm.get(src) & (IDIOM | CODE):
                out.append(("idiom-or-ref", src))
        for k in range(1, 16):
            a = S - k
            if self.bm.get(a) & START:
                d = self.code.insn(a)
                if d and d[0] == k and d[1] not in STOP_MN and d[1] != "jmp":
                    out.append(("fall", a))
        if S in self.rootset:
            out.append(("root", S))
        return out

    # -- idioms ---------------------------------------------------------
    def plan_idioms(self):
        for s, idm in sorted(self.w.idioms.items()):
            self.idiom_res[s] = self._plan_idiom(s, idm)

    # -- peephole: single stack instructions written as pairs ---------------
    #   lea rsp,[rsp+8] ; jmp [rsp-8]                 -> ret
    #   mov r,[rsp] ; lea rsp,[rsp+8]                 -> pop r
    #   lea rsp,[rsp+8] ; mov r,[rsp-8]               -> pop r
    #   lea rsp,[rsp-8] ; mov [rsp],r                 -> push r
    #   mov [rsp-8],r ; lea rsp,[rsp-8]               -> push r
    #   mov [rsp-8],r ; lea rsp,[rsp-8] ; lea rsp,[rsp+8] ; jmp [rsp-8]  -> jmp r
    # None of them touches the flags in either form; each leaves the same
    # registers, rsp, and memory at and above rsp (and the pushed slot).

    def _shape(self, a):
        d = self.code.insn(a)
        if d is None:
            return None
        size, m, op = d
        if m == "lea":
            dd = lea_rsp_disp(op)
            if dd == 8:
                return ("up", None, size)
            if dd == -8:
                return ("down", None, size)
            return None
        if m == "jmp" and rsp_disp(op) == -8:
            return ("jmp8", None, size)
        if m == "mov":
            ops = op.split(", ")
            if len(ops) != 2:
                return None
            if ops[0] in GPRSET and ops[0] != "rsp" and ops[1].startswith("qword ptr [rsp"):
                dd = rsp_disp(ops[1])
                if dd == 0:
                    return ("ld0", ops[0], size)
                if dd == -8:
                    return ("ld8", ops[0], size)
            if ops[1] in GPRSET and ops[1] != "rsp" and ops[0].startswith("qword ptr [rsp"):
                dd = rsp_disp(ops[0])
                if dd == 0:
                    return ("st0", ops[1], size)
                if dd == -8:
                    return ("st8", ops[1], size)
        return None

    def _next(self, a, size):
        """Following instruction: (addr, joined_by_jmp_at or None)."""
        n = a + size
        d = self.code.insn(n)
        if d is not None and d[1] == "jmp" and d[2].startswith("0x") and d[0] == 5:
            return int(d[2], 16), n
        return n, None

    def _other_way_in(self, a, own=()):
        if a in self.w.src or a in self.rootset:
            return True
        for src, m, size in confirmed_branches_to(self.code, self.xr, a):
            if src in own:
                continue
            if self.bm.get(src) & (START | ISTART):
                return True
        for src in confirmed_refs_to(self.code, self.xr, a):
            if self.bm.get(src) & (START | ISTART):
                return True
        return False

    @staticmethod
    def _rnum(r):
        # the x86 register number (ModRM / opcode+r order), not GPR64's order
        return ("rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15").index(r)

    def _enc1(self, form, r):
        if form == "ret":
            return b"\xC3"
        k = self._rnum(r)
        pre = b"\x41" if k >= 8 else b""
        k &= 7
        if form == "pop":
            return pre + bytes([0x58 + k])
        if form == "push":
            return pre + bytes([0x50 + k])
        return pre + bytes([0xFF, 0xE0 + k])          # jmp r

    NOPS = {1: b"\x90", 2: b"\x66\x90", 3: b"\x0F\x1F\x00", 4: b"\x0F\x1F\x40\x00",
            5: b"\x0F\x1F\x44\x00\x00", 6: b"\x66\x0F\x1F\x44\x00\x00",
            7: b"\x0F\x1F\x80\x00\x00\x00\x00", 8: b"\x0F\x1F\x84\x00\x00\x00\x00\x00",
            9: b"\x66\x0F\x1F\x84\x00\x00\x00\x00\x00"}

    def _nopfill(self, n):
        out = b""
        while n > 0:
            k = min(n, 9)
            out += self.NOPS[k]
            n -= k
        return out

    def plan_peephole(self):
        f = self.bm.f
        mem = np.frombuffer(self.im.mem, dtype=np.uint8)
        self.peep_count = collections.Counter()      # forms seen in live code
        self.peep_done = collections.Counter()
        self.peep_skip = collections.Counter()
        self.peep_sites = collections.defaultdict(list)
        self.peep_reg = {}
        self.peep_seen = {}            # site -> [form, result]
        cands = []
        for lo, hi, off in self.bm.secs:
            seg = mem[lo:hi]
            fl = f[off:off + hi - lo]
            n = len(seg) - 6
            ok = ((fl[:n] & START) != 0) & ((fl[:n] & (IDIOM | CHAIN)) == 0)
            rex = (seg[:n] & 0xFB) == 0x48
            lea = rex & (seg[1:n + 1] == 0x8D) & (seg[2:n + 2] == 0x64) & (seg[3:n + 3] == 0x24) & \
                ((seg[4:n + 4] == 0x08) | (seg[4:n + 4] == 0xF8))
            mov = rex & ((seg[1:n + 1] == 0x8B) | (seg[1:n + 1] == 0x89)) & \
                (((seg[2:n + 2] & 0xC7) == 0x04) | ((seg[2:n + 2] & 0xC7) == 0x44)) & (seg[3:n + 3] == 0x24)
            for i in np.flatnonzero(ok & (lea | mov)):
                cands.append(lo + int(i))
        claimed = self.claimed
        frozen = self.w.frozen
        for a in cands:
            if claimed.get(a) or a in frozen:
                continue
            s1 = self._shape(a)
            if s1 is None:
                continue
            a2, j1 = self._next(a, s1[2])
            s2 = self._shape(a2)
            if s2 is None:
                continue
            form = None
            r = None
            seq = [(a, s1[2])]
            if s1[0] == "up" and s2[0] == "jmp8":
                form = "ret"
            elif s1[0] == "ld0" and s2[0] == "up":
                form, r = "pop", s1[1]
            elif s1[0] == "up" and s2[0] == "ld8":
                form, r = "pop", s2[1]
            elif s1[0] == "down" and s2[0] == "st0":
                form, r = "push", s2[1]
            elif s1[0] == "st8" and s2[0] == "down":
                form, r = "push", s1[1]
                # push r ; ret  ==  jmp r
                a3, j2 = self._next(a2, s2[2])
                s3 = self._shape(a3)
                if s3 is not None and s3[0] == "up":
                    a4, j3 = self._next(a3, s3[2])
                    s4 = self._shape(a4)
                    if s4 is not None and s4[0] == "jmp8" and j2 is None and j3 is None and j1 is None:
                        if not self._other_way_in(a3) and not self._other_way_in(a4):
                            form = "jmp r"
                            seq += [(a2, s2[2]), (a3, s3[2]), (a4, s4[2])]
            if form is None:
                continue
            if form != "jmp r":
                seq.append((a2, s2[2]))
            self.peep_count[form] += 1
            self.peep_seen[a] = [form, None]
            if any((self.bm.get(x) & (IDIOM | CHAIN)) or claimed.get(x) or x in frozen for x, _ in seq):
                self.peep_skip["part of an idiom or chain"] += 1
                self.peep_seen[a][1] = "part of an idiom or chain"
                continue
            if self.keep is not None and any(self.keep.any_in(x, n, 1) for x, n in seq):
                self.peep_skip["overlaps a --keep-plan range"] += 1
                self.peep_seen[a][1] = "overlaps a --keep-plan range"
                continue
            if self._other_way_in(a2, own=(j1,) if j1 else ()):
                self.peep_skip["second half %sentered from elsewhere" % ("(after a joining jmp) " if j1 else "")] += 1
                self.peep_seen[a][1] = "second half %sentered from elsewhere" % ("(after a joining jmp) " if j1 else "")
                continue
            span_end = (j1 + 5) if j1 else (seq[-1][0] + seq[-1][1])
            if any(b in self.rootset or b in self.w.src for b in range(a + 1, span_end)
                   if b != a2) or (j1 and self._other_way_in(j1)):
                self.peep_skip["a root or branch lands inside the pair"] += 1
                self.peep_seen[a][1] = "a root or branch lands inside the pair"
                continue
            one = self._enc1("ret" if form == "ret" else ("jmp" if form == "jmp r" else form), r)
            stops = form in ("ret", "jmp r")
            if j1 is None:
                end = seq[-1][0] + seq[-1][1]
                if form == "jmp r":
                    end = a4 + s4[2]
                body = one
                fill = (b"\xCC" * (end - a - len(one))) if stops else self._nopfill(end - a - len(one))
                if not self._free(a, end):
                    self.peep_skip["bytes already patched"] += 1
                    self.peep_seen[a][1] = "bytes already patched"
                    continue
                self._put(a, body + fill, planfile.KIND_FLOW, "peep %s %X" % (form, a))
                self.peep_reg[a] = r
            else:
                # first half, its joining jmp: one instruction, then jump past
                # the second half (or nothing more, for ret)
                end = j1 + 5
                if stops:
                    body = one + b"\xCC" * (end - a - len(one))
                else:
                    nxt = a2 + s2[2]
                    body = one + b"\xE9" + rel32(a + len(one) + 5, nxt)
                    if len(body) > end - a:
                        self.peep_skip["no room after a joining jmp"] += 1
                        self.peep_seen[a][1] = "no room after a joining jmp"
                        continue
                    body += b"\xCC" * (end - a - len(body))
                if not self._free(a, end):
                    self.peep_skip["bytes already patched"] += 1
                    self.peep_seen[a][1] = "bytes already patched"
                    continue
                self._put(a, body, planfile.KIND_FLOW, "peep %s %X" % (form, a))
                self.peep_reg[a] = r
                self.peep_done["joined by jmp"] += 0
            self.peep_done[form] += 1
            self.peep_seen[a][1] = "ok"
            if len(self.peep_sites[form]) < 200:
                self.peep_sites[form].append(a)

    def _plan_idiom(self, s, idm):
        if self.publishing(idm):
            return ("skip", "a routine inside publishes a value")
        ch = chunks_of(idm.insns)
        lo, hi = ch[0][0], ch[0][1]
        if lo != s:
            return ("skip", "first instruction not at chunk start")
        in_chain = set(a for c in idm.inner for a, _ in c.insns)
        for a, _ in idm.insns:
            if a in in_chain:
                continue
            m = self.code.insn(a)[1]
            if not (m in ("push", "pop", "lea", "mov", "movabs", "xchg", "jmp", "ret")
                    or m.startswith("cmov")):
                return ("skip", "non flag-neutral instruction " + m)
        own = set(a for a, _ in idm.insns)
        if any(a in self.w.frozen for a in own):
            return ("skip", "part of a construct whose routine has no known continuation")
        if self.keep is not None:
            for a, n in idm.insns:
                if self.keep.any_in(a, n, 1):
                    self.keep_overlaps.append(("idiom", s))
                    return ("skip", "overlaps a --keep-plan range")
        t = idm.ret if idm.kind == "call" else idm.target
        if idm.inner and idm.flags_clob:
            # a chain inside the idiom overwrote the flags in the original;
            # the rewrite keeps them. Record whether anything reads them.
            if not hasattr(self, "_fl"):
                self._fl = FlagLiveness(self.code, self.chain_by_S)
            self.inner_flags[s] = self._fl.at(t)
            if self.inner_flags[s] != "dead":
                # the original branches on flags the chain left behind (for
                # example a jne after `add rsp,[rsp+8]`, always taken); the
                # rewrite would branch on older flags. Leave it alone.
                return ("skip", "flags %s after a chain inside the idiom" % self.inner_flags[s])
        if idm.clob:
            # registers the routine leaves changed and the chain does not
            # restore: the original arrives with the routine's leftovers,
            # the rewrite with the old values. Both must be unread.
            if not hasattr(self, "_rl"):
                self._rl = RegLiveness(self.code)
            self.inner_regs[s] = self._rl.at(t, idm.clob)
            if self.inner_regs[s] != "dead":
                return ("skip", "registers %s %s after the routine" % (
                    ",".join(idm.clob), self.inner_regs[s]))
        if any(e[0] == "cont" for e in idm.effects):
            # for the proof: which registers (and the flags) are dead where
            # the folded construct lands; only the others are compared
            if not hasattr(self, "_rl"):
                self._rl = RegLiveness(self.code)
            if not hasattr(self, "_fl"):
                self._fl = FlagLiveness(self.code, self.chain_by_S)
            self.fold_dead[s] = ([r for r in GPR64 if r != "rsp" and self._rl.at(t, [r]) == "dead"],
                                 self._fl.at(t) == "dead")
        if idm.kind == "popjmp":
            body = [("pop", idm.pop), ("jmp", self.final(idm.target))]
        elif idm.kind == "jmp":
            body = [("jmp", self.final(idm.target))]
        elif idm.kind == "jcc":
            body = [("jcc", idm.cc, self.final(idm.target)), ("jmp", self.final(idm.fall))]
        else:
            g = self.final(idm.target)
            d = self.code.insn(g)
            if d is not None and d[1] == "ret" and not d[2]:
                body = [("jmp", self.final(idm.ret))]       # call of an empty routine
            else:
                body = [("call", g), ("jmp", self.final(idm.ret))]
        need = sum(6 if b[0] == "jcc" else (5 if b[0] != "pop" or 8 * b[1] < 128 else 8)
                   for b in body)

        def enc(at):
            out = b""
            for b in body:
                nx = at + len(out)
                if b[0] == "pop":                 # lea rsp,[rsp+8k]
                    k8 = 8 * b[1]
                    out += (b"\x48\x8D\x64\x24" + bytes([k8])) if k8 < 128 else \
                        (b"\x48\x8D\xA4\x24" + struct.pack("<i", k8))
                elif b[0] == "jmp":
                    out += b"\xE9" + rel32(nx + 5, b[1])
                elif b[0] == "call":
                    out += b"\xE8" + rel32(nx + 5, b[1])
                else:
                    out += bytes([0x0F, 0x80 + CC[b[1]]]) + rel32(nx + 6, b[2])
            return out

        ent = self.entered(lo, hi, own)
        if ent:
            return ("skip", "first chunk entered from elsewhere")
        if not self._free(lo, hi):
            return ("skip", "bytes already patched")
        if hi - lo >= need:
            self._put(lo, enc(lo), planfile.KIND_FLOW, "%s %X" % (idm.kind, s), fill_to=hi)
            return ("ok", "inline", body)
        if hi - lo < 5:
            return ("skip", "first chunk shorter than 5 bytes")
        for c in ch[1:]:
            clo, chi = c[0], c[1]
            if chi - clo >= need and self._free(clo, chi) and \
                    not self.entered(clo, chi, own, lo_start_ok=False):
                # the chunk is entered only by the idiom's own joining jump
                self._put(lo, b"\xE9" + rel32(lo + 5, clo), planfile.KIND_FLOW,
                          "%s %X hop" % (idm.kind, s), fill_to=hi)
                self._put(clo, enc(clo), planfile.KIND_FLOW, "%s %X" % (idm.kind, s),
                          fill_to=chi)
                return ("ok", "two-hop", body)
        return ("skip", "no chunk with %d free bytes" % need)

    # -- folded checks ---------------------------------------------------
    def plan_checks(self, checks: dict):
        """A check on published values, constant once they are baked: its
        first instruction becomes `jmp E` (E: where its one outcome goes on,
        with the state it found)."""
        self.check_res = {}
        for c, ck in sorted(checks.items()):
            if ck.why:
                self.check_res[c] = ("skip", ck.why)
                continue
            if not (self.bm.get(c) & START):
                self.check_res[c] = ("skip", "not reached from game roots")
                continue
            if self.keep is not None and self.keep.any_in(c, 5, 1):
                self.keep_overlaps.append(("check", c))
                self.check_res[c] = ("skip", "overlaps a --keep-plan range")
                continue
            first = chunks_of(ck.insns)[0]
            if first[0] != c or first[1] - c < 5:
                self.check_res[c] = ("skip", "first chunk shorter than 5 bytes")
                continue
            own = set(a for a, _ in ck.insns)
            if self.entered(c, c + 5, own) or not self._free(c, c + 5):
                self.check_res[c] = ("skip", "first bytes entered from elsewhere")
                continue
            if ck.flags_changed:
                if not hasattr(self, "_fl"):
                    self._fl = FlagLiveness(self.code, self.chain_by_S)
                fl = self._fl.at(ck.E)
                if fl != "dead":
                    self.check_res[c] = ("skip", "flags changed by the check are %s at E" % fl)
                    continue
            if ck.regs_changed:
                if not hasattr(self, "_rl"):
                    self._rl = RegLiveness(self.code)
                rl = self._rl.at(ck.E, ck.regs_changed)
                if rl != "dead":
                    self.check_res[c] = ("skip", "registers %s changed by the check are %s at E" % (
                        ",".join(ck.regs_changed), rl))
                    continue
            self._put(c, b"\xE9" + rel32(c + 5, self.final(ck.E)), planfile.KIND_FLOW, "check %X" % c)
            self.check_res[c] = ("ok", "jmp", self.final(ck.E))


# ------------------------------------------------------------ check folds --

class CheckFold:
    __slots__ = ("c", "site", "E", "insns", "flags_changed", "regs_changed", "reads", "why",
                 "outcome")

    def __init__(self, c, site):
        self.c, self.site = c, site
        self.E = None
        self.insns = []
        self.flags_changed = False
        self.regs_changed = []
        self.reads = []
        self.why = None
        self.outcome = None

    def as_json(self):
        return {"start": "%08X" % self.c, "site": "%08X" % self.site,
                "E": "%08X" % self.E if self.E is not None else None,
                "flags_changed": self.flags_changed, "regs_changed": self.regs_changed,
                "reads": ["%08X+%d" % r for r in self.reads], "why": self.why}


class MiniEmu:
    """Unicorn over the mapped image, pages copied in lazily; a 1 MiB stack."""
    STACK = 0x0000_00E0_0000_0000

    def __init__(self, im: Image):
        import unicorn
        from unicorn import x86_const as UX
        self.U, self.UX = unicorn, UX
        self.im = im
        self.base = im.image_base
        self.uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
        self.uc.mem_map(self.STACK, 0x100000)
        self.mapped = set()
        self.uc.hook_add(unicorn.UC_HOOK_MEM_UNMAPPED, self._miss)
        self.regs = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "r8", "r9", "r10", "r11",
                     "r12", "r13", "r14", "r15"]
        self.rid = {r: getattr(UX, "UC_X86_REG_" + r.upper()) for r in self.regs + ["rsp", "rip", "eflags"]}

    def _miss(self, uc, access, addr, size, value, ud):
        ok = True
        for a in range(addr & ~0xFFF, (addr + max(size, 1) + 0xFFF) & ~0xFFF, 0x1000):
            r = a - self.base
            if 0 <= r < len(self.im.mem) and a not in self.mapped:
                uc.mem_map(a, 0x1000)
                uc.mem_write(a, bytes(self.im.mem[r:r + 0x1000]))
                self.mapped.add(a)
            elif not (0 <= r < len(self.im.mem)):
                ok = False
        return ok

    def state(self):
        st = {r: self.uc.reg_read(self.rid[r]) for r in self.regs + ["rsp"]}
        st["flags"] = self.uc.reg_read(self.rid["eflags"]) & 0x8D5
        return st

    def set(self, st, stack):
        for r in self.regs + ["rsp"]:
            self.uc.reg_write(self.rid[r], st[r])
        self.uc.reg_write(self.rid["eflags"], 0x202 | st["flags"])
        self.uc.mem_write(self.STACK, stack)


def find_checks(im: Image, code: Code, xr: RawXrefs, sites, routine_writes, baked, depth=60):
    """Each long-form site that is not a routine call: find the first
    instruction of its save, emulate the sequence on the (baked) image from
    two random states, and take the first point after the alignment is undone
    where registers, rsp and the stack are as they were. Same point and same
    path for both states: one outcome."""
    import random
    rng = random.Random(1400)
    em = MiniEmu(im)
    U = em.U
    base = im.image_base
    written = set()
    for rva, n in routine_writes:
        written.update(range(rva, rva + n))
    baked_set = set()
    for rva, n in baked:
        baked_set.update(range(rva, rva + n))
    SAVE = ("push", "pushfq", "test", "jne", "jmp", "lea", "sub")
    out = {}

    def preds(a):
        r = []
        for src, m, size in confirmed_branches_to(code, xr, a):
            if m != "call":
                r.append(src)
        r += confirmed_refs_to(code, xr, a)
        for k in range(1, 16):
            d = code.insn(a - k)
            if d and d[0] == k and d[1] not in STOP_MN and d[1] != "jmp":
                r.append(a - k)
        return r

    def path_ok(c, x):
        """c reaches x through save / alignment instructions only."""
        pc = c
        for _ in range(64):
            if pc == x:
                return True
            d = code.insn(pc)
            if d is None:
                return False
            size, m, op = d
            if m == "jmp" and op.startswith("0x"):
                pc = int(op, 16)
                continue
            if m == "jne" and op.startswith("0x"):
                pc += size        # the push 18h side; both arrive at x
                continue
            if m not in SAVE or (m == "lea" and lea_rsp_disp(op) is None) or \
                    (m == "sub" and op != "rsp, 8"):
                return False
            pc += size
        return False

    def run(c, x, seed):
        st0 = {r: rng.getrandbits(64) for r in em.regs}
        st0["rsp"] = em.STACK + 0x80000 + rng.randrange(0, 0x100, 8)
        st0["flags"] = rng.getrandbits(12) & 0x8D5
        stack = rng.randbytes(0x100000)
        em.set(st0, stack)
        trace, reads = [], []
        hit = {"x": False, "undo": False, "E": None}
        rsp0 = st0["rsp"]

        def code_h(uc, a, size, ud):
            r = a - base
            if hit["undo"] and hit["E"] is None and r != c:
                s = em.state()
                if s["rsp"] == rsp0 and bytes(uc.mem_read(rsp0, 0x200)) == \
                        stack[rsp0 - em.STACK:rsp0 - em.STACK + 0x200]:
                    hit["E"] = r
                    hit["flags"] = s["flags"] != st0["flags"]
                    hit["regs"] = sorted(k for k in em.regs if s[k] != st0[k])
                    uc.emu_stop()
                    return
            trace.append(r)
            if r == x:
                hit["x"] = True
            if hit["x"] and bytes(im.mem[r:r + 5]) == ADD_RSP_RSP8:
                hit["undo"] = True

        def read_h(uc, access, addr, size, value, ud):
            if base <= addr < base + len(im.mem):
                reads.append((addr - base, size))

        h1 = em.uc.hook_add(U.UC_HOOK_CODE, code_h)
        h2 = em.uc.hook_add(U.UC_HOOK_MEM_READ, read_h)
        try:
            em.uc.emu_start(base + c, 0, count=600)
        except U.UcError:
            pass
        em.uc.hook_del(h1)
        em.uc.hook_del(h2)
        regs_changed = []
        return hit, trace, reads

    for x in sites:
        seen = {x}
        q = collections.deque([(x, 0)])
        cands = []
        while q:
            a, dep = q.popleft()
            d = code.insn(a)
            if d and ((d[1] == "push" and d[2] in GPRSET) or d[1] == "pushfq") and path_ok(a, x):
                cands.append((dep, a))
            if dep >= depth:
                continue
            for p in preds(a):
                if p not in seen:
                    seen.add(p)
                    q.append((p, dep + 1))
        ck = None
        for dep, c in sorted(cands, reverse=True):          # farthest save first
            h1, t1, r1 = run(c, x, 1)
            if h1["E"] is None:
                continue
            h2, t2, r2 = run(c, x, 2)
            ck = CheckFold(c, x)
            # the alignment step takes one of two paths depending on rsp, so
            # the traces may differ there; the end point and every value
            # read must not
            if h2["E"] != h1["E"] or sorted(set(r1)) != sorted(set(r2)):
                ck.why = "outcome depends on the state (two runs differ)"
            ck.E = h1["E"]
            ck.flags_changed = bool(h1.get("flags") or h2.get("flags"))
            ck.regs_changed = sorted(set(h1.get("regs", [])) | set(h2.get("regs", [])))
            seq = []
            for a in t1:
                d = code.insn(a)
                if d is not None:
                    seq.append((a, d[0]))
            ck.insns = seq
            # data reads (the stack is outside the image, so all of these are
            # image reads): in the image by construction; written by no
            # routine except as a published (baked) value
            ck.reads = sorted(set(r1))
            for a, n in ck.reads:
                for b in range(a, a + n):
                    if b in written and b not in baked_set:
                        ck.why = ck.why or "reads %08X, which a routine writes (not a baked value)" % a
                        break
            break
        if ck is None:
            ck = CheckFold(cands[-1][1] if cands else x, x)
            ck.why = "no start found whose run comes back to the same state"
        out[ck.c] = ck
    return out


def static_writes(im: Image, code: Code, bm: ByteMap):
    """[(rva, size)] of the image locations the code marked in `bm` may
    write: the target of every RIP-relative operand it stores to, and of
    every RIP-relative `lea` (an address taken can be written through).

    Stands in for the writes an emulated routine census records, when the
    routine table was read from the code instead. It only has to be a
    superset of what a check could read: a check that reads one of these
    locations, other than a baked one, is left alone."""
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    out = set()
    mem = im.mem
    for lo, hi, off in bm.secs:
        starts = np.nonzero(bm.f[off:off + hi - lo] & ISTART)[0]
        for k in starts.tolist():
            a = lo + k
            d = code.insn(a)
            if d is None or "rip" not in d[2]:
                continue
            ins = next(md.disasm(bytes(mem[a:a + d[0]]), a, 1), None)
            if ins is None:
                continue
            for o in ins.operands:
                if o.type == XC.X86_OP_MEM and o.mem.base == XC.X86_REG_RIP:
                    t = a + ins.size + o.mem.disp
                    if not (0 <= t < len(mem)):
                        continue
                    if ins.mnemonic == "lea":
                        out.add((t, 8))
                    elif o.access & capstone.CS_AC_WRITE:
                        out.add((t, max(1, o.size)))
    return sorted(out)


# -------------------------------------------------------------- pipeline --

def data_extent(starts: np.ndarray, code_idx: np.ndarray, cap: int):
    """For each data start, the end of its extent: the next code byte or
    `cap` bytes on, whichever comes first."""
    k = np.searchsorted(code_idx, starts + 1, "left")
    nxt = np.where(k < len(code_idx), code_idx[np.minimum(k, len(code_idx) - 1)], starts + cap)
    return np.minimum(nxt, starts + cap)


def idx_np(bm, rva: np.ndarray) -> np.ndarray:
    """ByteMap.idx over an array (-1 outside the code regions)."""
    out = np.full(len(rva), -1, dtype=np.int64)
    for lo, hi, off in bm.secs:
        m = (rva >= lo) & (rva < hi)
        out[m] = rva[m] - lo + off
    return out


def data_extent_to(starts: np.ndarray, bounds: np.ndarray, code_idx: np.ndarray, cap: int):
    """For each data start, the end of its extent: the next referenced
    address after it, the next code byte, or `cap` bytes on, whichever
    comes first."""
    if len(starts) == 0:
        return starts.copy()
    e = data_extent(starts, code_idx, cap)
    if len(bounds):
        k = np.searchsorted(bounds, starts, "right")
        nb = np.where(k < len(bounds), bounds[np.minimum(k, len(bounds) - 1)], e)
        e = np.minimum(e, nb)
    return e


PE_DIR_NAMES = ("export", "import", "resource", "exception", "security", "basereloc", "debug", "architecture",
                "globalptr", "tls", "load_config", "bound_import", "iat", "delay_import", "clr", "reserved")


def ranges_of(mask: np.ndarray):
    """[(lo, hi)] index runs where mask is True."""
    z = np.zeros(1, dtype=np.int8)
    d = np.diff(mask.view(np.int8), prepend=z, append=z)      # int8: no 1.7 GB temporaries
    return list(zip(np.flatnonzero(d == 1).tolist(), np.flatnonzero(d == -1).tolist()))


RE_PTR = re.compile(r"\b(byte|word|dword|qword|tbyte|xmmword|ymmword|zmmword) ptr \[rip")
PTR_SIZE = {"byte": 1, "word": 2, "dword": 4, "qword": 8, "tbyte": 10, "xmmword": 16, "ymmword": 32,
            "zmmword": 64}


def access_size(code: Code, pc: int):
    """Bytes an instruction with a RIP-relative memory operand reads or
    writes there, or None when it only takes the address (lea) or the size
    is not stated."""
    d = code.insn(pc)
    if d is None or d[1] == "lea":
        return None
    m = RE_PTR.search(d[2])
    if not m:
        return None
    if d[1].startswith("rep") or d[1] in ("fxsave", "fxrstor", "xsave", "xrstor", "fxsave64", "fxrstor64"):
        return None
    return PTR_SIZE[m.group(1)]


# ----------------------------------------------------------------- sweep --
#
# Unwalked bytes inside live exception records: block starts come from the
# byte layout only (the byte after a walked instruction that does not fall
# through). A block is accepted when every instruction passes tests that
# compiler output always meets. The tests are the ones of the coordinator's
# d9_sweep_stats.py `why_bad`, reimplemented here so the tool stands alone.

SW_BAD = {"in", "out", "insb", "insd", "insw", "outsb", "outsd", "outsw", "hlt", "cli", "sti", "iretd", "iretq",
          "iret", "retf", "retfq", "lcall", "ljmp", "int", "into", "bound", "arpl", "salc", "getsec", "sysenter",
          "sysexit", "sysret", "rsm", "wrmsr", "rdmsr", "clts", "lgdt", "lidt", "sgdt", "sidt", "lldt", "sldt",
          "ltr", "str", "xlatb", "loop", "loope", "loopne", "jrcxz", "jecxz", "enter", "int1", "icebp", "lahf",
          "sahf", "cmc", "std", "clc", "stc", "invd", "wbinvd", "lar", "lsl", "verr", "verw", "smsw", "lmsw",
          "swapgs", "rdpmc", "wait", "fwait", "pushfq", "popfq", "vmcall", "vmlaunch", "vmresume", "vmxoff",
          "movsb", "movsd", "movsw", "movsq", "cmpsb", "cmpsd", "cmpsw", "cmpsq", "scasb", "scasd", "scasw",
          "scasq", "lodsb", "lodsd", "lodsw", "lodsq", "stosb", "stosd", "stosw", "stosq", "xchg"}
SW_SOFT = {"movsb", "movsd", "movsw", "movsq", "cmpsb", "scasb", "stosb", "stosd", "stosw", "stosq", "lodsb",
           "xchg", "pushfq", "popfq", "clc", "stc", "cmc", "std", "lahf", "sahf"}
SW_TERM = {"ret", "jmp", "int3", "ud2"}
_X = capstone.x86_const
SW_SEG_BAD = {_X.X86_REG_ES, _X.X86_REG_CS, _X.X86_REG_SS, _X.X86_REG_DS, _X.X86_REG_FS}
SW_SP32 = {_X.X86_REG_ESP, _X.X86_REG_SP, _X.X86_REG_SPL}
SW_R32 = {_X.X86_REG_ESP, _X.X86_REG_EBP, _X.X86_REG_EAX, _X.X86_REG_EBX, _X.X86_REG_ECX, _X.X86_REG_EDX,
          _X.X86_REG_ESI, _X.X86_REG_EDI}
NOFALL = {"jmp", "ret", "int3", "ud2"} | STOP_MN


def sweep_why_bad(i, size, exec_ranges):
    """None when the instruction passes, else the test it fails."""
    m = i.mnemonic
    if m.startswith("rep") or m.startswith("lock"):
        m = m.split(" ", 1)[-1] if " " in m else m
    if m in SW_BAD and m not in SW_SOFT:
        if m == "int" and i.op_str in ("0x29", "0x2c", "3"):
            return None
        return "opcode " + m
    if m.startswith("f") and m not in ("fxsave", "fxrstor", "fnstcw", "fldcw", "fnclex", "femms"):
        return "x87"
    b = bytes(i.bytes)
    if len(b) >= 2 and 0x40 <= b[0] <= 0x4F and b[1] in (0xE8, 0xE9):
        return "rex branch"
    for p in i.prefix:
        if p in (0x26, 0x2E, 0x36, 0x3E, 0x64) and m not in ("jmp",) and not m.startswith("j"):
            return "segment prefix"
    try:
        ops = i.operands
    except capstone.CsError:
        return None
    for o in ops:
        if o.type == _X.X86_OP_REG:
            if o.reg in SW_SEG_BAD:
                return "segment register"
            if o.reg in SW_SP32:
                return "32-bit stack pointer"
        elif o.type == _X.X86_OP_MEM:
            base, disp = o.mem.base, o.mem.disp
            if o.mem.segment in SW_SEG_BAD:
                return "segment override"
            if base == _X.X86_REG_RIP:
                t = i.address + i.size + disp
                if not (0 <= t < size):
                    return "rip operand outside the image"
            elif base == _X.X86_REG_RSP:
                if disp < 0 and disp != -8:
                    return "below rsp"
            elif base in SW_R32:
                return "32-bit address"
            else:
                if disp < -0x8000000 or disp >= size:
                    return "displacement"
        elif o.type == _X.X86_OP_IMM and (m.startswith("j") or m == "call"):
            t = o.imm
            if not any(lo <= t < hi for lo, hi in exec_ranges):
                return "branch outside code"
    return None


# direct branches, and the push-and-return spelling, at every byte offset
# (a lookahead, so that matches overlap like a byte-by-byte scan)
HIDDEN_BRANCH = re.compile(rb"(?=([\xE8\xE9]....|\x0F[\x80-\x8F]....))", re.S)
HIDDEN_ANY = re.compile(rb"(?=([\xE8\xE9]....|\x0F[\x80-\x8F]....|\x48\x8D\x2D....\x48\x87\x2C\x24))", re.S)


class Sweeper:
    """Block decoding for the sweep and for the plausible-block invariant."""

    def __init__(self, im: Image, code: Code):
        self.mem = im.mem
        self.size = len(im.mem)
        self.ex = list(code.ex)
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.md.detail = True
        self.cache = {}
        self.runs = {}

    def insn(self, a):
        for i in self.md.disasm(bytes(self.mem[a:a + 16]), a, 1):
            return i
        return None

    @staticmethod
    def refs_of(i):
        """[(target, 'branch' | 'rip')] direct branch targets and RIP-relative operands."""
        out = []
        m = i.mnemonic
        if (m.startswith("j") or m == "call") and i.op_str.startswith("0x"):
            out.append((int(i.op_str, 16), "branch"))
            return out
        try:
            for o in i.operands:
                if o.type == _X.X86_OP_MEM and o.mem.base == _X.X86_REG_RIP:
                    out.append((i.address + i.size + o.mem.disp, "rip"))
        except capstone.CsError:
            pass
        return out

    def block(self, c, stop, rec_end, joins, region_end):
        """Decode from c to its terminator.

        stop: the first walked byte after c (or the region end). Accepted:
        the block ends at a terminator before `stop`, or runs exactly onto
        a walked instruction start at `stop`. Returns (ok, why, insns, refs)."""
        key = (c, stop, rec_end)
        r = self.cache.get(key)
        if r is not None:
            return r
        pc, ins, refs, why, ok = c, [], [], None, False
        while True:
            if pc >= stop:
                if pc == stop and stop < region_end and joins(pc):
                    ok, why = True, "runs onto a walked instruction start"
                elif stop >= region_end:
                    why = "runs to the end of the code region"
                else:
                    why = "runs into the middle of a walked instruction"
                break
            if pc >= rec_end:
                why = "runs past the end of its record"
                break
            i = self.insn(pc)
            if i is None:
                why = "undecodable"
                break
            if pc + i.size > stop:
                why = "decodes across a walked instruction boundary"
                break
            w = sweep_why_bad(i, self.size, self.ex)
            if w:
                why = w
                break
            ins.append((pc, i.size, i.mnemonic))
            for t, k in self.refs_of(i):
                refs.append((pc, t, k))
            if len(ins) > 4096:
                why = "longer than 4096 instructions"
                break
            if i.mnemonic in SW_TERM:
                ok, why = True, "ends at a terminator"
                break
            pc += i.size
        if ok and ins and not any(self.mem[c:ins[-1][0] + ins[-1][1]]):
            ok, why = False, "zero bytes"
        r = (ok, why, ins, refs)
        if len(self.cache) > 2_000_000:
            self.cache.clear()
        self.cache[key] = r
        return r

    def run_blocks(self, lo, hi):
        """Linear decode of [lo, hi) (leading int3 padding skipped), cut into
        blocks at terminators: [(start, plausible, refs)]."""
        key = (lo, hi)
        r = self.runs.get(key)
        if r is not None:
            return r
        seg = bytes(self.mem[lo:hi])
        st = seg.lstrip(b"\xCC")
        a0 = lo + len(seg) - len(st)
        out = []
        if not st.rstrip(b"\xCC").strip(b"\x00"):
            self.runs[key] = out
            return out
        blk_start, bad, refs = a0, None, []
        pos = a0
        for i in self.md.disasm(st, a0):
            w = sweep_why_bad(i, self.size, self.ex)
            if w and not bad:
                bad = w
            refs.extend(self.refs_of(i))
            pos = i.address + i.size
            if i.mnemonic in SW_TERM:
                out.append((blk_start, bad is None, refs))
                blk_start, bad, refs = pos, None, []
        if pos < hi and pos < a0 + len(st):
            # undecodable tail: the open block is filler
            pass
        elif pos > blk_start:
            out.append((blk_start, bad is None, refs))
        self.runs[key] = out
        return out


class Pipeline:
    def __init__(self, path: str, log=print, routines: str | None = None, keep_plans=(),
                 bake_json: str | None = None, routines_extra: str | None = None, stub_plans=(),
                 treat_proven=()):
        self.log = log
        t0 = time.time()
        self.t0 = t0
        self.im = Image(path)
        im = self.im
        # other plans: their baked values go into the image first (a check
        # on a published value is then a constant), and every byte they
        # patch or wipe is theirs
        self.keep_plans = [planfile.Plan.load(p) for p in keep_plans]
        self.baked = []
        for kp in self.keep_plans:
            for rva, kind, data in kp.patches:
                if kind == planfile.KIND_BAKE:
                    im.mem[rva:rva + len(data)] = data
                    self.baked.append((rva, len(data)))
        self.bake_source = "keep plans" if self.baked else None
        if not self.baked and bake_json:
            # no routine plan yet: take the values from its source table
            for e in json.load(open(bake_json)).get("bake", []):
                if e.get("needed"):
                    data = bytes.fromhex(e["bytes"])
                    im.mem[e["rva"]:e["rva"] + len(data)] = data
                    self.baked.append((e["rva"], len(data)))
            self.bake_source = bake_json
        self.extra = extra_code_regions(im)
        self.model = RoutineModel(routines, im.image_base)
        for rx in ([routines_extra] if isinstance(routines_extra, str) else (routines_extra or [])):
            self.model.add_extra(rx, im.image_base)
        # routines whose chain proof passed after the table was written
        self.treat_proven = list(treat_proven)
        for g in self.treat_proven:
            if g in self.model.r:
                self.model.r[g]["proven"] = True
        self.code = Code(im, self.extra, self.model)
        self.keep = ByteMap(im, self.extra)
        for rva, n in self.baked:
            self.keep.set(rva, n, 1)
        # keep: no patch of ours goes there. keep_wipe: no wipe of ours goes
        # there, except routine stubs, which may go once nothing calls them
        self.keep_wipe = ByteMap(im, self.extra)
        for rva, n in self.baked:
            self.keep_wipe.set(rva, n, 1)
        self.stub_ranges = []
        for kp in self.keep_plans:
            for rva, kind, data in kp.patches:
                self.keep.set(rva, len(data), 1)
                if kind == planfile.KIND_STUB:
                    self.stub_ranges.append((rva, len(data)))
                else:
                    self.keep_wipe.set(rva, len(data), 1)
            for rva, n in kp.wipes:
                self.keep.set(rva, n, 1)
                self.keep_wipe.set(rva, n, 1)
        # routine plans: their stubs are applied to the walk of the patched
        # image that decides the dead plan, and the reachable ones become
        # the stubs plan
        # one patch per address: a later plan's stub replaces an earlier one
        sp = {}
        self.stub_dupes = []
        for p in stub_plans:
            for rva, kind, data in planfile.Plan.load(p).patches:
                if kind == planfile.KIND_STUB:
                    if rva in sp:
                        self.stub_dupes.append({"rva": "%08X" % rva, "replaced": sp[rva].hex(), "by": data.hex(),
                                                "plan": os.path.basename(p)})
                    sp[rva] = data
        self.stub_patches = sorted(sp.items())
        for rva, data in self.stub_patches:
            self.stub_ranges.append((rva, len(data)))
        log("routine table: %d routines; keep plans: %d (%d baked values)" % (
            len(self.model.r), len(self.keep_plans), len(self.baked)))
        self.xr = RawXrefs(im, self.extra)
        log("image: %d code regions (+%d in data sections) %.0fs" % (
            len(self.code.ex), len(self.extra), time.time() - t0))
        self.census, self.cfail = census_chains(im, self.code, self.xr)
        log("census: %d chains, %d long sub sites without one" % (len(self.census), len(self.cfail)))
        # code reachable from the routine entries alone (the protection's own
        # code, plus whatever game functions it calls)
        wa0 = Walker(im, self.code, bypass=False)
        wa0.walk([(ch.G, "routine") for ch in self.census.values()])
        self.wa0 = wa0
        # what the routines write: recorded by an emulated census, or, for a
        # table read from the code, every location that code stores to or
        # takes the address of (for the checks only; nothing is kept from
        # the wipe on that account)
        check_writes = self.model.writes
        self.static_writes = None
        if not check_writes and any(m.get("clobbers") is not None for m in self.model.r.values()):
            self.static_writes = static_writes(im, self.code, wa0.bm)
            check_writes = self.static_writes
            log("routine table read from the code: %d locations its code may write (from %d instructions)" % (
                len(check_writes), int((wa0.bm.f & ISTART != 0).sum())))
        # a dword a guard publishes when it runs is written by a routine
        # whatever the walk above saw: a check that reads one has no single
        # outcome (before the guard ran, after it ran) and stays as shipped
        pubs = sorted({int(x[0], 16) for m in self.model.r.values() for x in (m.get("publishes") or [])})
        if pubs:
            check_writes = list(check_writes) + [(p, 4) for p in pubs]
        self.checks = find_checks(im, self.code, self.xr, self.cfail, check_writes, self.baked)
        log("checks: %d of %d sites have one outcome on the baked image (%s)" % (
            sum(1 for c in self.checks.values() if c.why is None), len(self.checks),
            dict(collections.Counter(c.why for c in self.checks.values() if c.why))))
        roots = collect_roots(im, self.code)
        self.roots, self.dropped_roots = filter_roots(roots, self.census)
        # exception records whose first byte is protection code reached only
        # through the routines: the protection laid code over the space of
        # some records; such a record is not a game function entry.  A record
        # is kept when anything outside the protection's code branches to it.
        # The same goes for a relocated pointer that the protection keeps in
        # its own space: the padding at the end of a data section that holds
        # its code (build 1.20 has a pointer there to a label inside a
        # routine; walked as a root, it led into ten routines and to a patch
        # on the first instruction of one, where the routine's stub also
        # goes). A code pointer counts as the protection's when every
        # relocated qword that holds it lies in such a region.
        ptr_out = set()
        ptr_in = set()
        if self.extra:
            rel = im.relocations()
            for s in im.sections:
                if s.executable:
                    continue
                for r in rel[(rel >= s.rva) & (rel < s.rva + s.vsize)].tolist():
                    v = im.u64(r) - im.image_base
                    if self.code.in_code(v):
                        (ptr_in if any(lo <= r < hi for lo, hi in self.extra) else ptr_out).add(v)
        own_ptr = ptr_in - ptr_out
        keep, drop2 = [], []
        self.dropped_own_pointers = []
        for r, why in self.roots:
            prot_rec = why == "pdata"
            prot_ptr = why.startswith("reloc:") and r in own_ptr
            if (prot_rec or prot_ptr) and wa0.bm.get(r) & (START | ISTART | CODE | IDIOM | CHAIN) \
                    and r not in wa0.call_targets:
                outside_ref = False
                for src, m, size in confirmed_branches_to(self.code, self.xr, r):
                    if not (wa0.bm.get(src) & (CODE | IDIOM | CHAIN)):
                        outside_ref = True
                        break
                if not outside_ref:
                    if prot_ptr:
                        self.dropped_own_pointers.append(r)
                    else:
                        drop2.append(r)
                    continue
            keep.append((r, why))
        self.roots = keep
        self.dropped_prot = drop2
        if self.dropped_own_pointers:
            log("roots: %d code pointers kept in the protection's own padding point into routine code and are "
                "not used as roots" % len(set(self.dropped_own_pointers)))
        log("roots: %d (dropped %d inside chains, %d on protection code)" % (
            len(self.roots), len(self.dropped_roots), len(drop2)))
        secs = im.exec_sections()
        arx = max(secs, key=lambda s: s.rva)          # the appended code section
        self.arxan_sec = (arx.rva, arx.rva + arx.vsize)
        self.track = set()          # instruction starts whose provenance is wanted
        self.sweep_on = True
        self.b_roots = []           # targets of plausible unwalked blocks (invariant B)
        self.b_data = []
        self.b_seen = set()
        self._asz = {}
        self.sweep_compare = True
        self.b_raw = []
        self.u_roots = []           # direct-branch targets in wipes that live code refers to
        self.u_data = []            # other references into wipes from live code
        self.u_refs = {}            # target -> (source, instruction, kind)
        self._ref_src = {}
        self._reasons = {}
        self._bounds = None
        self.code3 = None

    # -- sweep: unwalked code in live records --------------------------------
    def _rec_arrays(self, bm, exclude_prot=True, only_prot=False):
        """Exception records as byte-map index ranges, sorted: (fb, fe, bi, ei)."""
        rf = self.im.runtime_functions()
        fb = rf[:, 0].astype(np.int64)
        fe = rf[:, 1].astype(np.int64)
        lo, hi = self.arxan_sec
        inp = (fb >= lo) & (fb < hi)
        sel = fe > fb
        if exclude_prot:
            sel &= ~inp
        if only_prot:
            sel &= inp
        fb, fe = fb[sel], fe[sel]
        bi = np.full(len(fb), -1, np.int64)
        for slo, shi, off in bm.secs:
            m = (fb >= slo) & (fb < shi) & (fe <= shi)
            bi[m] = fb[m] - slo + off
        ok = bi >= 0
        fb, fe, bi = fb[ok], fe[ok], bi[ok]
        o = np.argsort(bi, kind="stable")
        fb, fe, bi = fb[o], fe[o], bi[o]
        return fb, fe, bi, bi + (fe - fb)

    @staticmethod
    def _region_of(bm, i):
        for lo, hi, off in bm.secs:
            if off <= i < off + hi - lo:
                return lo, hi, off
        return None

    def _sweep(self, w, ws, code, tag="sweep", exclude_prot=True, only_prot=False, rec_ok=None):
        """Accept block starts in unwalked bytes of the records whose begin
        the walk `w` reached; walk them with the keep-only walker `ws`;
        repeat until nothing new. The walked set is that of `w` and `ws`
        together. Returns (roots, stats)."""
        im, bm = self.im, w.bm
        bms = ws.bm
        mem = im.mem
        fb, fe, bi, ei = self._rec_arrays(bm, exclude_prot, only_prot)
        if rec_ok is not None:
            sel = rec_ok(fb, fe)
            fb, fe, bi, ei = fb[sel], fe[sel], bi[sel], ei[sel]
        sw = Sweeper(im, code)
        roots = []
        rounds = 0
        evaluated = set()
        accepted_why = collections.Counter()
        reasons = {}
        t0 = time.time()

        def joins(p):
            return bool((bm.get(p) | bms.get(p)) & (START | ISTART))
        while True:
            rounds += 1
            f = bm.f | bms.f
            walked = (f & (CODE | IDIOM | CHAIN)) != 0
            live_rec = (f[bi] & (START | ISTART)) != 0
            lb, le = bi[live_rec], ei[live_rec]
            edge = walked[:-1] & ~walked[1:]
            js = np.flatnonzero(edge) + 1
            del edge
            k = np.searchsorted(lb, js, "right") - 1
            k0 = np.maximum(k, 0)
            inr = (k >= 0) & (js < le[k0])
            js, rend = js[inr], le[k0][inr]
            back = np.flatnonzero(~walked[:-1] & walked[1:]) + 1
            del walked
            ri = np.searchsorted(back, js, "left")
            stop_i = np.where(ri < len(back), back[np.minimum(ri, len(back) - 1)], len(f))
            del back
            new = []
            reasons = {}
            for j, se, re_ in zip(js.tolist(), stop_i.tolist(), rend.tolist()):
                reg = self._region_of(bm, j)
                if reg is None:
                    continue
                slo, shi, off = reg
                cj = slo + j - off
                kk = j - 1
                while kk > j - 16 and kk > off and not (f[kk] & (START | ISTART)):
                    kk -= 1
                if kk < off or not (f[kk] & (START | ISTART)):
                    reasons[cj] = "not a candidate: no walked instruction ends here"
                    continue
                a = slo + kk - off
                d = code.insn(a)
                if d is None or a + d[0] != cj:
                    reasons[cj] = "not a candidate: no walked instruction ends here"
                    continue
                if not (d[1] in NOFALL or (d[1] == "int" and d[2] == "0x29")):
                    reasons[cj] = "not a candidate: after an instruction that falls through"
                    continue
                region_end = shi
                stop = slo + min(se, off + shi - slo) - off
                rec_end = slo + min(re_, off + shi - slo) - off
                c = cj
                while c < stop and mem[c] == 0xCC:
                    c += 1
                if c >= stop:
                    reasons[cj] = "int3 padding only"
                    continue
                evaluated.add(c)
                ok, why, ins, refs = sw.block(c, stop, rec_end, joins, region_end)
                if ok:
                    new.append((c, tag))
                    accepted_why[why] += 1
                else:
                    reasons[cj] = why
            if not new:
                break
            roots += new
            ws.walk(new)
            del f
            self.log("%s round %d: %d accepted (%d in all) %.0fs" % (tag, rounds, len(new), len(roots),
                                                                     time.time() - t0))
        rej = collections.Counter(reasons.values())
        stats = {
            "rounds": rounds,
            "records_considered": int(len(fb)),
            "gaps_seen_last_round": len(reasons),
            "candidates_evaluated": len(evaluated),
            "accepted": len(roots),
            "accepted_how": dict(accepted_why),
            "left_by_reason": dict(rej.most_common()),
            "left_samples": {r: ["%08X" % a for a, rr in sorted(reasons.items()) if rr == r][:40] for r in rej},
        }
        self._sweep_left = reasons
        return roots, stats

    def _new_ws(self, code):
        ws = Walker(self.im, code, bypass=False)
        ws.atomic = False
        ws.stop_f = self.w1.bm.f
        ws.track = self.track
        return ws

    def _stubs_on(self, check_claimed=True):
        """Write the routine plans' stubs into the image; returns what to restore."""
        im = self.im
        saved = []
        for rva, data in self.stub_patches:
            if check_claimed and getattr(self, "pl", None) is not None and self.pl.claimed.any_in(rva, len(data), 1):
                continue
            saved.append((rva, bytes(im.mem[rva:rva + len(data)])))
            im.mem[rva:rva + len(data)] = data
        return saved

    def _stubs_off(self, saved):
        for rva, b in reversed(saved):
            self.im.mem[rva:rva + len(b)] = b

    SLOTS = (0x2326626C, 0x23266274)

    def _slot_loads(self, w):
        lo, hi = min(self.SLOTS), max(self.SLOTS) + 8
        return sorted(set(pc for pc, t in w.datarefs if lo <= t < hi))

    def _sweep_summary(self, w1, ws, roots, st):
        new = ((ws.bm.f & (CODE | IDIOM | CHAIN)) != 0) & ((w1.bm.f & (CODE | IDIOM | CHAIN)) == 0)
        t_end = w1.bm.secs[0][1] - w1.bm.secs[0][0]
        out = dict(st)
        stub_starts = [rva for rva, d in self.stub_patches if ws.bm.get(rva) & START]
        loads = self._slot_loads(ws)
        out.update({
            "bytes_kept_only": int(new.sum()),
            "bytes_kept_only_in_text": int(new[:t_end].sum()),
            "insns_kept_only": ws.insns,
            "routine_stubs_reached": len(stub_starts),
            "protection_slot_loads": len(loads),
            "protection_slot_load_sites": ["%08X" % x for x in loads[:60]]})
        out.update(self.kept_only_content(ws, roots))
        return out

    def analyse(self):
        im, code, log = self.im, self.code, self.log
        w1 = Walker(im, code, bypass=True)
        w1.checks = self.checks
        w1.track = self.track
        w1.walk(self.roots)
        self.w1 = w1
        self.sweep_roots, self.sweep_stats = [], {}
        self.sweep_before = None
        if self.sweep_on and self.sweep_compare and self.stub_patches:
            # the same sweep on the image without the routine stubs, for the
            # before/after comparison only
            ws0 = self._new_ws(code)
            r0, st0 = self._sweep(w1, ws0, code)
            self.sweep_before = self._sweep_summary(w1, ws0, r0, st0)
            self._ws0_mask = np.packbits((ws0.bm.f & (CODE | IDIOM | CHAIN)) != 0)
            log("sweep without stubs: %s" % {k: v for k, v in self.sweep_before.items() if not isinstance(v, (dict, list))})
            del ws0
        # keep-only walk from the sweep's blocks: original image with the
        # routine plans' stubs in place (a routine reached from kept-only
        # code ends at its stub); it stops where it meets the planning
        # walk's instruction starts; nothing in it is rewritten, and no
        # patch may cover a byte it walks
        # closure of the routine entries under direct control flow only
        # (branches, resolved idioms, direct calls; no code addresses taken,
        # no jump tables), image without stubs: report only
        wr = Walker(im, code, bypass=False)
        wr.atomic = False
        wr.follow_refs = False
        wr.tables = False
        wr.walk([(g, "routine") for g in sorted(self._gset())])
        self.wr_f = (wr.bm.f & (CODE | IDIOM | CHAIN)) != 0
        self.wr_insns = wr.insns
        del wr
        saved = self._stubs_on(check_claimed=False)
        code_s = Code(im, self.extra, self.model) if saved else code
        ws = self._new_ws(code_s)
        self.ws = ws
        if self.sweep_on:
            self.sweep_roots, st = self._sweep(w1, ws, code_s)
            self.sweep_stats = self._sweep_summary(w1, ws, self.sweep_roots, st)
            log("sweep: %s" % {k: v for k, v in self.sweep_stats.items() if not isinstance(v, (dict, list))})
        self._stubs_off(saved)
        self.dropped_reached = [r for r in self.dropped_prot if w1.bm.get(r) & (START | ISTART)]
        log("walk 1: %d insns, %d idioms, %d chains; dropped records reached anyway: %d %.0fs" % (
            w1.insns, len(w1.idioms), len(w1.chains), len(self.dropped_reached), time.time() - self.t0))
        pl = Planner(im, code, self.xr, w1, self.roots + self.sweep_roots, keep=self.keep)
        # guards that publish a value when they run: their constructs stay
        pl.publishers = frozenset(g for g, m in self.model.r.items() if m.get("publishes"))
        pl.plan_chains()
        pl.plan_checks(self.checks)
        log("checks folded: %s" % dict(collections.Counter(r[0] if r[0] == "ok" else r[1]
                                                           for r in pl.check_res.values())))
        pl.plan_idioms()
        pl.plan_peephole()
        log("peephole: seen %s, folded %s, skipped %s" % (
            dict(pl.peep_count), dict(pl.peep_done), dict(pl.peep_skip)))
        self.pl = pl
        fl = FlagLiveness(code, w1.chains)
        for S, ch in w1.chains.items():
            ch.flags = "preserved" if "flags" in ch.push_order else fl.at(ch.final if ch.final is not None else ch.E)
        log("planned: %d patches, %d relocation drops %.0fs" % (
            len(pl.patches), len(pl.drops), time.time() - self.t0))

    def apply_and_rewalk(self):
        """Patch the mapped image in place (originals kept) and walk it again."""
        im = self.im
        self.orig = {}
        for rva, (data, kind, tag) in self.pl.patches.items():
            self.orig[rva] = bytes(im.mem[rva:rva + len(data)])
            im.mem[rva:rva + len(data)] = data
        code2 = Code(im, self.extra, self.model)
        self.code2 = code2
        w2 = Walker(im, code2, bypass=False)
        w2.atomic = False
        w2.track = self.track
        w2.walk(self.roots)
        self.w2 = w2
        self.log("walk 2 (patched): %d insns, %d idioms left %.0fs" % (
            w2.insns, len(w2.idioms), time.time() - self.t0))
        groots = [(ch.G, "routine") for ch in self.census.values()] + \
                 [(ch.S, "chain") for ch in self.census.values()]
        wa = Walker(im, code2, bypass=False)
        wa.atomic = False
        wa.walk(groots)
        self.wa = wa
        # exception records dropped as roots that nothing else reaches: if one
        # of them were a real function after all, what it reaches must stay
        lost = [r for r in self.dropped_prot if not (w2.bm.get(r) & (START | ISTART))]
        wk = Walker(im, code2, bypass=False)
        wk.atomic = False
        wk.track = self.track
        wk.walk([(r, "dropped-record") for r in lost])
        self.wk = wk
        self.lost_records = lost
        self.log("walk A (protection): %d insns %.0fs" % (wa.insns, time.time() - self.t0))
        # the same image with the routine plans' stubs in place: a routine
        # still called ends at its stub, so its body is no longer reached
        self.w2s = w2
        self.code3 = code2
        sorig = self._stubs_on()
        if sorig:
            code3 = Code(im, self.extra, self.model)
            w2s = Walker(im, code3, bypass=False)
            w2s.atomic = False
            w2s.track = self.track
            w2s.walk(self.roots)
            self.w2s = w2s
            self.code3 = code3
            self.log("walk 2s (patched, routines stubbed): %d insns %.0fs" % (
                w2s.insns, time.time() - self.t0))
        # targets of plausible unwalked blocks that branch into what would be
        # wiped (invariant B): kept, with everything they reach (stubs in
        # place, as for the keep-only sweep walk)
        wb = Walker(im, self.code3, bypass=False)
        wb.atomic = False
        wb.track = self.track
        wb.walk([(r, "plausible-block target") for r in self.b_roots])
        self.wb = wb
        # targets of direct branches from live code into a would-be wipe:
        # what a keep-only walk from them reaches stays
        wu = Walker(im, self.code3, bypass=False)
        wu.atomic = False
        wu.track = self.track
        wu.walk([(r, "referenced by live code") for r in self.u_roots])
        self.wu = wu
        self._stubs_off(sorig)

    def restore(self):
        for rva, b in self.orig.items():
            self.im.mem[rva:rva + len(b)] = b

    def dead_bytes(self, arxan_sec, cap=0x10000):
        """Wipe list: [(rva, len)]. The main plan's keep set comes from the
        walk of the patched image as it is; the dead plan's from the walk
        with the routine plans' stubs in place (self.w2s)."""
        bm2, bma, bm1 = self.w2.bm, self.wa.bm, self.w1.bm
        self._bounds = None
        self._reasons = {}
        anyc = ((bm2.f | bma.f | bm1.f) & (CODE | IDIOM | CHAIN)) != 0
        code_idx = np.flatnonzero(anyc)
        del anyc
        # the stubbed walk reaches the continuations (T2) of the constructs
        # left in place, which the real routines also reach at run time but
        # the unstubbed walk cannot follow: its live code is live for the
        # main plan too
        if self.w2s is not self.w2:
            keep_s, _, _, live_stubs = self._keep_for(self.w2s, code_idx, cap)
        keep, live, keep_lost, _ = self._keep_for(self.w2, code_idx, cap)
        if self.w2s is not self.w2:
            keep |= keep_s
            live |= (self.w2s.bm.f & (CODE | IDIOM | CHAIN | DREAD)) != 0
        else:
            keep_s, live_stubs = keep, self._live_stubs
        out = self._wipes(arxan_sec, keep, live, keep_lost, code_idx)
        del keep
        self.stubs_reachable = live_stubs
        self.stubs_live = len(live_stubs)
        bma = self.wa.bm
        prot_only = ((bma.f & (CODE | IDIOM | CHAIN)) != 0)
        sec_mask = self._sec_mask
        dead = (sec_mask & ~keep_s & ~self.wipe_mask) | (~sec_mask & prot_only & ~keep_s & ~self.wipe_mask)
        self.dead_mask = dead
        self.dead_wipes = [(bm2.rva(a), b - a) for a, b in ranges_of(dead)]
        return out

    def _keep_for(self, wl, code_idx, cap):
        """Bytes no wipe may touch, given the walk `wl` as the live code."""
        im = self.im
        bm2 = wl.bm
        live = (bm2.f & (CODE | IDIOM | CHAIN | DREAD)) != 0
        patched = self.pl.claimed.f != 0
        keep_lost = ((self.wk.bm.f & (CODE | IDIOM | CHAIN | DREAD)) != 0) |             ((self.ws.bm.f & (CODE | IDIOM | CHAIN | DREAD)) != 0)
        keep = live | patched | keep_lost | (self.keep_wipe.f != 0)
        # a routine stub (from another plan) stays while its routine is still
        # reached by live code: some byte of the stub is then live
        live_stubs = []
        for rva, n in self.stub_ranges:
            i = bm2.idx(rva)
            if i >= 0 and (live[i:i + n].any() or keep_lost[i:i + n].any()):
                keep[i:i + n] = True
                live_stubs.append((rva, n))
        self._live_stubs = live_stubs
        # bytes a routine writes (code a writer produces, state, digests):
        # whatever reads them later, they are not ours to wipe
        for rva, n in self.model.writes:
            i = bm2.idx(rva)
            if i >= 0:
                keep[i:i + n] = True
        # code reached from the targets of plausible unwalked blocks
        keep_b = (self.wb.bm.f & (CODE | IDIOM | CHAIN | DREAD)) != 0
        keep |= keep_b
        keep |= (self.wu.bm.f & (CODE | IDIOM | CHAIN | DREAD)) != 0
        # a target the walk could not start at (undecodable bytes): the bytes
        # an instruction there could span stay as they are
        self.b_raw = []
        for w_, rs_ in ((self.wb, self.b_roots), (self.wu, self.u_roots)):
            for t in rs_:
                i = bm2.idx(t)
                if i >= 0 and not (w_.bm.f[i] & (CODE | IDIOM | CHAIN)):
                    keep[i:i + 15] = True
                    self.b_raw.append(t)
        # data read by live code, and pointed to by relocated data. An
        # instruction that states its operand size (not lea) reads that many
        # bytes; anything else (an address taken, a relocated pointer) keeps
        # the bytes up to the next referenced address, the next code byte or
        # `cap` bytes on, whichever comes first.
        asz = self._asz
        sized, unsized = {}, set()
        nref_live = nref_rel = 0
        for w in (wl, self.wk, self.wb, self.wu, self.ws):
            code = w.code
            if w.datarefs:
                arr = np.array(w.datarefs, dtype=np.int64)
                ii = idx_np(bm2, arr[:, 1])
                sel = np.flatnonzero(ii >= 0)
                nref_live += len(sel)
                for pc, i in zip(arr[sel, 0].tolist(), ii[sel].tolist()):
                    n = asz.get(pc, -1)
                    if n == -1:
                        n = asz[pc] = access_size(code, pc)
                    if n is None:
                        unsized.add(i)
                    else:
                        sized[i] = max(sized.get(i, 0), n)
            if w.coderefs:
                arr = np.array(w.coderefs, dtype=np.int64)
                ii = idx_np(bm2, arr[:, 1])
                ii = ii[ii >= 0]
                nref_live += len(ii)
                unsized.update(ii.tolist())
        for t in list(self.b_data) + list(self.u_data):
            i = bm2.idx(t)
            if i >= 0:
                unsized.add(i)
        rel_idx = set()
        rel = im.relocations()
        for s in im.sections:
            if s.executable:
                continue
            sel = rel[(rel >= s.rva) & (rel < s.rva + s.vsize)]
            for r in sel:
                v = im.u64(int(r)) - im.image_base
                if 0 <= v < len(im.mem):
                    i = bm2.idx(v)
                    if i >= 0:
                        nref_rel += 1
                        rel_idx.add(i)
        bounds = self._ref_bounds(bm2)
        sec_lo, sec_hi = bm2.idx(self.arxan_sec[0]), bm2.idx(self.arxan_sec[1] - 1) + 1
        old = np.zeros(sec_hi - sec_lo, dtype=bool)
        r_live = np.zeros(sec_hi - sec_lo, dtype=bool)
        r_rel = np.zeros(sec_hi - sec_lo, dtype=bool)

        def put(idx, ends, rmask):
            for a, b in zip(idx.tolist(), ends.tolist()):
                keep[a:b] = True
                a2, b2 = max(a, sec_lo), min(b, sec_hi)
                if a2 < b2:
                    rmask[a2 - sec_lo:b2 - sec_lo] = True
        un = np.array(sorted(unsized), dtype=np.int64)
        put(un, data_extent_to(un, bounds, code_idx, cap), r_live)
        # the round-3 rule (blocks also ended at sized reads), report only
        r3 = np.zeros(sec_hi - sec_lo, dtype=bool)
        for st_, en_ in ((un, data_extent_to(un, self._bounds_r3, code_idx, cap)),):
            for a, b in zip(st_.tolist(), en_.tolist()):
                a2, b2 = max(a, sec_lo), min(b, sec_hi)
                if a2 < b2:
                    r3[a2 - sec_lo:b2 - sec_lo] = True
        si = np.array(sorted(sized), dtype=np.int64)
        put(si, si + np.array([sized[i] for i in si.tolist()], dtype=np.int64), r_live)
        ri = np.array(sorted(rel_idx), dtype=np.int64)
        put(ri, data_extent_to(ri, bounds, code_idx, cap), r_rel)
        for a, b in zip(ri.tolist(), data_extent_to(ri, self._bounds_r3, code_idx, cap).tolist()):
            a2, b2 = max(a, sec_lo), min(b, sec_hi)
            if a2 < b2:
                r3[a2 - sec_lo:b2 - sec_lo] = True
        # the old rule (every start to the next code byte or `cap`), for the
        # saving the tighter extents make in the protection's section
        allst = np.array(sorted(unsized | set(sized) | rel_idx), dtype=np.int64)
        for a, b in zip(allst.tolist(), data_extent(allst, code_idx, cap).tolist()):
            a2, b2 = max(a, sec_lo), min(b, sec_hi)
            if a2 < b2:
                old[a2 - sec_lo:b2 - sec_lo] = True
        # PE structures inside code regions
        pe = np.zeros(sec_hi - sec_lo, dtype=bool)
        pe_names = {}
        for k, (d_rva, d_sz) in enumerate(im.dirs):
            if d_rva and d_sz:
                i = bm2.idx(d_rva)
                if i >= 0:
                    keep[i:i + d_sz] = True
                    a2, b2 = max(i, sec_lo), min(i + d_sz, sec_hi)
                    if a2 < b2:
                        pe[a2 - sec_lo:b2 - sec_lo] = True
                        pe_names[PE_DIR_NAMES[k] if k < len(PE_DIR_NAMES) else str(k)] = b2 - a2
        rs = self._reasons
        si_ = np.array(sorted(sized), dtype=np.int64)
        for a in si_.tolist():
            if sec_lo <= a < sec_hi:
                r3[a - sec_lo:min(a + sized[a], sec_hi) - sec_lo] = True
        for name, m in (("data_live", r_live), ("data_reloc", r_rel), ("data_old_rule", old), ("pe", pe),
                        ("data_round3_rule", r3)):
            rs[name] = m if name not in rs else (rs[name] | m)
        rs.setdefault("pe_names", {}).update(pe_names)
        rs["refs_live"] = max(rs.get("refs_live", 0), nref_live)
        rs["refs_reloc"] = max(rs.get("refs_reloc", 0), nref_rel)
        rs["sec"] = (sec_lo, sec_hi)
        return keep, live, keep_lost, live_stubs

    def _ref_bounds(self, bm):
        """Ends of address-taken data blocks: every address any walk takes
        (lea, movabs, a RIP-relative operand without a stated size) and
        every relocated pointer. A sized read inside a block does not end
        it: code holding the block's address can index past it.
        Also (for the report) the round-3 bounds, which included sized reads."""
        if getattr(self, "_bounds", None) is not None:
            return self._bounds
        s, s_all = set(), set()
        asz = self._asz
        for w in (self.w1, self.w2, self.w2s, self.wa, self.wk, self.wb, self.wu, self.ws):
            code = w.code
            for pc, t in w.datarefs:
                s_all.add(t)
                n = asz.get(pc, -1)
                if n == -1:
                    n = asz[pc] = access_size(code, pc)
                if n is None:
                    s.add(t)
            for _, t in w.coderefs:
                s.add(t)
                s_all.add(t)
        im = self.im
        rel = im.relocations()
        for sec in im.sections:
            if sec.executable:
                continue
            for r in rel[(rel >= sec.rva) & (rel < sec.rva + sec.vsize)]:
                v = im.u64(int(r)) - im.image_base
                s.add(v)
                s_all.add(v)
        n = len(im.mem)
        ii = idx_np(bm, np.array(sorted(t for t in s if 0 <= t < n), dtype=np.int64))
        self._bounds = np.unique(ii[ii >= 0])
        ii = idx_np(bm, np.array(sorted(t for t in s_all if 0 <= t < n), dtype=np.int64))
        self._bounds_r3 = np.unique(ii[ii >= 0])
        return self._bounds

    def _wipes(self, arxan_sec, keep, live, keep_lost, code_idx):
        im = self.im
        bm2, bma, bm1 = self.w2.bm, self.wa.bm, self.w1.bm
        lo_s, hi_s = arxan_sec
        patched = self.pl.claimed.f != 0
        # what belongs to the protection
        prot = ((bma.f & (CODE | IDIOM | CHAIN)) != 0) | ((bm1.f & (IDIOM | CHAIN)) != 0)
        astarts = [t for _, t in self.wa.datarefs]
        aidx = np.array(sorted(set(bm2.idx(t) for t in astarts if bm2.idx(t) >= 0)), dtype=np.int64)
        aends = data_extent(aidx, code_idx, 0x1000)
        protd = np.zeros_like(prot)
        for a, b in zip(aidx.tolist(), aends.tolist()):
            protd[a:b] = True
        sec_mask = np.zeros_like(prot)
        i0, i1 = bm2.idx(lo_s), bm2.idx(hi_s - 1) + 1
        sec_mask[i0:i1] = True
        wipe = sec_mask & (prot | protd) & ~keep
        # game code: only the bodies of bypassed chains and idiom leftovers
        own = np.zeros_like(prot)
        for ch in self.w1.chains.values():
            if ch.bypass:
                for a, n in ch.insns:
                    i = bm2.idx(a)
                    own[i:i + n] = True
        for s, res in self.pl.idiom_res.items():
            if res[0] == "ok":
                for a, n in self.w1.idioms[s].insns:
                    i = bm2.idx(a)
                    own[i:i + n] = True
        for lo, hi in self.extra:            # code in data sections: never wiped
            own[bm2.idx(lo):bm2.idx(hi - 1) + 1] = False
        wipe |= ~sec_mask & own & ~keep
        out = []
        for a, b in ranges_of(wipe):
            out.append((bm2.rva(a), b - a))
        self.wipe_mask = wipe
        self._sec_mask = sec_mask
        sm = sec_mask

        def n(m):
            return int((m & sm).sum())
        zero_pad = np.zeros_like(sm)
        segb = np.frombuffer(im.mem, dtype=np.uint8, count=hi_s - lo_s, offset=lo_s)
        zero_pad[i0:i1] = (segb == 0) | (segb == 0xCC)
        self.wipe_stats = {
            "section_bytes": n(np.ones_like(sm)),
            "live_code": n(live & ~((bm2.f & DREAD) != 0)),
            "patched": n(patched),
            "kept_as_live_data_or_pe": n(keep & ~live & ~patched & ~keep_lost),
            "kept_reached_from_dropped_records": n(keep_lost & ~live & ~patched),
            "protection_code": n(prot),
            "protection_data": n(protd & ~prot),
            "wiped": n(wipe),
            "unclassified_kept": n(~keep & ~prot & ~protd),
            "unclassified_kept_zero_or_cc": n(~keep & ~prot & ~protd & zero_pad),
        }
        self.log("arxan section: %s" % self.wipe_stats)
        return out

    # -- invariant B: plausible unwalked blocks into wiped bytes ------------
    def _b_violations(self, mask):
        """[(src, target, kind)]: a block of unwalked, unwiped bytes of .text
        or an extra code region, inside a record whose begin is live, that
        passes the compiler-output tests and has a direct branch or a
        RIP-relative operand into a wiped byte."""
        bm = self.w2.bm
        f2, fs = self.w2.bm.f, self.w2s.bm.f
        live = ((f2 | fs | self.wk.bm.f | self.wb.bm.f | self.wu.bm.f | self.ws.bm.f) & (CODE | IDIOM | CHAIN)) != 0
        live |= self.pl.claimed.f != 0
        free = ~live & ~mask
        del live
        lo_a = bm.idx(self.arxan_sec[0])
        hi_a = bm.idx(self.arxan_sec[1] - 1) + 1
        free[lo_a:hi_a] = False
        fb, fe, bi, ei = self._rec_arrays(bm, exclude_prot=True)
        livebeg = ((f2[bi] | fs[bi]) & (START | ISTART)) != 0
        lb, le = bi[livebeg], ei[livebeg]
        sw = getattr(self, "_bsweeper", None)
        if sw is None:
            sw = self._bsweeper = Sweeper(self.im, self.code2)
        out = []
        nblk = nplaus = 0
        for a, b in ranges_of(free):
            k = int(np.searchsorted(lb, a, "right")) - 1
            if k < 0 or a >= le[k]:
                # the run may still start before a record and reach into one
                k2 = int(np.searchsorted(lb, a, "left"))
                if k2 >= len(lb) or lb[k2] >= b:
                    continue
                a = int(lb[k2])
                k = k2
            b = min(b, int(le[k]))
            reg = self._region_of(bm, a)
            if reg is None:
                continue
            slo, shi, off = reg
            for st, plaus, refs in sw.run_blocks(slo + a - off, slo + b - off):
                nblk += 1
                if not plaus:
                    continue
                nplaus += 1
                for t, kind in refs:
                    i = bm.idx(t) if 0 <= t < len(self.im.mem) else -1
                    if i >= 0 and mask[i]:
                        out.append((st, t, kind))
        # Hidden branches. A block that only a computed jump reaches can
        # start behind junk bytes, where a linear decode never reads it as an
        # instruction. The protection moves the blocks of such a function
        # into its own section and leaves `jmp block` at each block's old
        # address, so the computed jump lands on a 5-byte jump with junk on
        # both sides (1.20: `90 66 2B 16 76 | E9 rel32` at 0x3DD532, reached
        # by `push rax ; ret`). So: a direct jmp, call or jcc encoded at ANY
        # byte offset, whose target is a wiped byte of the protection's
        # section, keeps that target. The bytes searched are the ones the
        # walks from real roots did not read: what the layout sweep and the
        # plausible blocks decoded there is a guess (1.20: 0xD4A4C0, junk
        # decoded straight over such a jump), and a function the walk never
        # entered can hold one too (0xF5D2D4).
        mem = self.im.mem
        size = len(mem)
        a_lo, a_hi = self.arxan_sec
        nhidden = nptr = 0
        main = ((f2 | fs) & (CODE | IDIOM | CHAIN)) != 0
        main |= self.pl.claimed.f != 0
        fk = ~main & ~mask
        fh = fk.copy()
        fh[lo_a:hi_a] = False

        def pieces(bits):
            # a run of bits can cross from one code region into the next in
            # index order, which is not address order: cut at region ends
            for a0, b0 in ranges_of(bits):
                a = a0
                while a < b0:
                    reg = self._region_of(bm, a)
                    if reg is None:
                        break
                    slo, shi, off = reg
                    b = min(b0, off + shi - slo)
                    if b <= a:
                        break
                    yield slo + a - off, slo + b - off
                    a = b

        for lo, hi in pieces(fh):
            seg = bytes(mem[lo:hi])
            for m in HIDDEN_BRANCH.finditer(seg):
                g = m.group(1)
                p = lo + m.start()
                if g[0] == 0x0F:
                    t = p + 6 + int.from_bytes(g[2:6], "little", signed=True)
                else:
                    t = p + 5 + int.from_bytes(g[1:5], "little", signed=True)
                if not (a_lo <= t < a_hi):
                    continue
                i = bm.idx(t)
                if i >= 0 and mask[i]:
                    out.append((p, t, "branch"))
                    nhidden += 1
        # The same from the other side: a wiped byte of the GAME's code that
        # a kept, unwalked byte anywhere still jumps to, by a direct branch
        # or by the push-and-return spelling `lea rbp,[rip+X] ; xchg
        # [rsp],rbp`. 1.20: the 5-byte `jmp` at 0x1B8A407 was wiped once the
        # rewritten idioms stopped passing through it, and fourteen blocks
        # kept as shipped still end in a push-and-return to it. Targets in
        # the protection's section are left to the rule above: its dead code
        # is full of jumps into itself.
        del fh
        for lo, hi in pieces(fk):
            seg = bytes(mem[lo:hi])
            for m in HIDDEN_ANY.finditer(seg):
                g = m.group(1)
                p = lo + m.start()
                if g[0] == 0x0F:
                    t = p + 6 + int.from_bytes(g[2:6], "little", signed=True)
                elif g[0] == 0x48:
                    t = p + 7 + int.from_bytes(g[3:7], "little", signed=True)
                else:
                    t = p + 5 + int.from_bytes(g[1:5], "little", signed=True)
                if t < 0 or t >= size or a_lo <= t < a_hi:
                    continue
                i = bm.idx(t)
                if i >= 0 and mask[i]:
                    out.append((p, t, "branch"))
                    nhidden += 1
        del fk
        # Kept pointers. A relocated qword in a code region that is not
        # wiped and points at a wiped byte: a table of block addresses for a
        # computed jump can sit next to the code that uses it, in the code
        # section, where the roots taken from the data sections do not see
        # it (1.20: 0xD42EE3 holds 0x1B8A407). What it names is kept like a
        # branch target.
        base = self.im.image_base
        drops = self.pl.drops
        for r in self.im.relocations():
            r = int(r)
            i = bm.idx(r)
            if i < 0 or mask[i] or r in drops:
                continue
            v = struct.unpack_from("<Q", mem, r)[0]
            if not (base <= v < base + size):
                continue
            t = v - base
            j = bm.idx(t)
            if j >= 0 and mask[j]:
                out.append((r, t, "branch"))
                nptr += 1
        self._b_counts = (nblk, nplaus)
        self._b_hidden, self._b_ptrs = nhidden, nptr
        return out

    def _apply_unwipes(self):
        """Withdraw the wipe ranges around bytes that live code refers to
        (found by an earlier check); recomputed wipes keep the withdrawal."""
        bm2 = self.w2.bm
        self.unwiped = 0
        if not self.unwipe_targets:
            return
        for t in sorted(self.unwipe_targets):
            i = bm2.idx(t)
            for m in (self.wipe_mask, self.dead_mask):
                if i >= 0 and m[i]:
                    lo_, hi_ = i, i
                    while lo_ > 0 and m[lo_ - 1]:
                        lo_ -= 1
                    while hi_ < len(m) and m[hi_]:
                        hi_ += 1
                    m[lo_:hi_] = False
                    self.unwiped += hi_ - lo_
        self.wipes = [(bm2.rva(a), b - a) for a, b in ranges_of(self.wipe_mask)]
        self.dead_wipes = [(bm2.rva(a), b - a) for a, b in ranges_of(self.dead_mask)]

    def _ws_drops(self):
        """Patches that cover a byte the keep-only sweep walk reaches."""
        f = self.ws.bm.f
        out = set()
        for rva, (data, kind, tag) in self.pl.patches.items():
            i = self.ws.bm.idx(rva)
            if i >= 0 and f[i:i + len(data)].any():
                out.add(rva)
        return out

    def _settle_b(self):
        """Keep what plausible unwalked blocks branch to or read, until no
        such block reaches a wiped byte. Returns rounds made."""
        rounds = 0
        while True:
            v = self._b_violations(self.wipe_mask | self.dead_mask)
            br = sorted(set(t for _, t, k in v if k == "branch") - self.b_seen)
            dr = sorted(set(t for _, t, k in v if k == "rip") - self.b_seen)
            self.log("invariant B: %d violations (%d blocks, %d plausible); new branch targets %d, data %d" % (
                len(v), self._b_counts[0], self._b_counts[1], len(br), len(dr)))
            self.log("hidden branches into wiped bytes: %d; kept pointers into wiped bytes: %d" % (
                self._b_hidden, self._b_ptrs))
            if not br and not dr:
                return rounds
            rounds += 1
            self.b_seen |= set(br) | set(dr)
            self.b_roots += br
            self.b_data += dr
            saved = self._stubs_on()
            self.wb.walk([(r, "plausible-block target") for r in br])
            self._stubs_off(saved)
            self.wipes = self.dead_bytes(self.arxan_sec)
            self._apply_unwipes()

    # -- static invariants on the patched image ---------------------------
    def invariants(self, wipes, mask=None, drops_extra=None, wl=None):
        mask = self.wipe_mask if mask is None else mask
        drops_extra = self.wipe_drops if drops_extra is None else drops_extra
        im, code2, bm2 = self.im, self.code2, (wl or self.w2).bm
        res = {}
        live = (bm2.f & (START | CODE | IDIOM | CHAIN)) != 0
        # 1. long-form stub sites reached by live code
        hit = []
        for x in long_sub_sites(im, code2):
            if bm2.get(x) & (START | CODE):
                hit.append(x)
        res["live_long_sub_sites_of_chains"] = ["%08X" % x for x in hit if x in self.census]
        res["live_long_sub_sites_not_chains"] = ["%08X" % x for x in hit if x not in self.census]
        # 2. live bytes inside wiped ranges
        res["live_bytes_in_wipes"] = int((live & mask).sum())
        # 3. every patch decodes to the intended instructions
        bad = []
        md = code2.md
        for rva, (data, kind, tag) in self.pl.patches.items():
            got = []
            for a, size, m, op in md.disasm_lite(bytes(data), rva):
                got.append((a, size, m, op))
            if tag.startswith("peep "):
                # one stack instruction, then nop filler / a jmp past the
                # second half / int3 filler
                form = tag.split()[1]
                want = {"ret": "ret", "pop": "pop", "push": "push", "jmp": "jmp"}[form]
                rest = got[1:]
                ok = bool(got) and got[0][2] == want and sum(g[1] for g in got) == len(data) and \
                    (form != "jmp" or not got[0][3].startswith("0x")) and \
                    all(g[2] in ("nop", "int3") or (g[2] == "jmp" and g[3].startswith("0x")) for g in rest)
                # and the register is the one the original pair moved
                if ok and form != "ret" and got[0][3] != self.pl.peep_reg.get(rva):
                    ok = False
                if not ok:
                    bad.append(rva)
                continue
            # the patch must decode to branches then int3 filler only
            body = [g for g in got if g[2] != "int3"]
            filler_ok = all(g[2] == "int3" for g in got[len(body):])
            ok = filler_ok and sum(g[1] for g in got) == len(data) and \
                all(((g[2] in ("jmp", "call") or g[2] in JCC_MN) and g[3].startswith("0x"))
                    or (g[2] == "lea" and k == 0 and (lea_rsp_disp(g[3]) or 0) > 0
                        and len(body) == 2 and body[1][2] == "jmp")
                    for k, g in enumerate(body))
            if not ok:
                bad.append(rva)
        res["patch_decode_bad"] = bad
        # 4. branches/refs from live code into the interior of a patch or wipe
        interior = np.zeros(len(bm2.f), dtype=bool)
        for rva, (data, kind, tag) in self.pl.patches.items():
            i = bm2.idx(rva)
            # the jcc/call/jmp starts inside a patch are entry points only for
            # the patch's own decoding; outside entries must hit rva itself
            interior[i + 1:i + len(data)] = True
        interior |= mask
        xr2 = RawXrefs(im, self.extra)
        sel = np.zeros(len(xr2.tgt), dtype=bool)
        viol = []
        # map targets to byte-map indices in bulk
        tidx = np.full(len(xr2.tgt), -1, dtype=np.int64)
        for lo, hi, off in bm2.secs:
            m = (xr2.tgt >= lo) & (xr2.tgt < hi)
            tidx[m] = xr2.tgt[m] - lo + off
        sidx = np.full(len(xr2.src), -1, dtype=np.int64)
        for lo, hi, off in bm2.secs:
            m = (xr2.src >= lo) & (xr2.src < hi)
            sidx[m] = xr2.src[m] - lo + off
        cand = (tidx >= 0) & (sidx >= 0)
        cand[cand] = interior[tidx[cand]] & ((bm2.f[sidx[cand]] & (START | ISTART)) != 0)
        for i in np.flatnonzero(cand):
            src, k, t = int(xr2.src[i]), int(xr2.kind[i]), int(xr2.tgt[i])
            d = code2.insn(src)
            if d is None or d[0] != KIND_ENC[k][1]:
                continue
            if k < 5:
                if not (d[2].startswith("0x") and int(d[2], 16) == t):
                    continue
                if not (d[1] == "jmp" or d[1] == "call" or d[1] in JCC_MN):
                    continue
            elif d[1] != KIND_ENC[k][0]:
                continue
            # a patch's own internal decoding is fine
            if src in self.pl.patches or self.pl.claimed.get(src):
                continue
            viol.append((src, t))
        res["refs_into_interior"] = viol
        for r, why in self.roots:
            i = bm2.idx(r)
            if i >= 0 and interior[i]:
                viol.append((why, r))
        # 5. remaining relocation sites hold an in-image VA
        drops = self.pl.drops | drops_extra
        rel = im.relocations()
        badr = []
        wipe_rvas = mask
        for r in rel:
            r = int(r)
            if r in drops:
                continue
            v = im.u64(r)
            i = bm2.idx(r)
            if i >= 0 and wipe_rvas[i]:
                badr.append((r, "in wipe"))
                continue
            if not (im.image_base <= v < im.image_base + len(im.mem)):
                badr.append((r, "%x" % v))
        res["bad_relocs"] = badr
        # 6. (B) no plausible unwalked block in a live record branches or
        # refers into a wiped byte
        res["plausible_blocks_into_wipes"] = [("%08X" % a, "%08X" % t, k) for a, t, k in self._b_violations(mask)]
        res["plausible_blocks_scanned"] = {"blocks": self._b_counts[0], "plausible": self._b_counts[1]}
        return res

    def _check_all(self):
        rel = self.im.relocations()
        self.wipe_drops = set()
        bm = self.w2.bm
        for r in rel:
            r = int(r)
            i = bm.idx(r)
            if i >= 0 and self.wipe_mask[i:i + 8].any():
                self.wipe_drops.add(r)
        self.inv = self.invariants(self.wipes)
        self.dead_drops = set()
        for r in rel:
            r = int(r)
            i = bm.idx(r)
            if i >= 0 and self.dead_mask[i:i + 8].any() and r not in self.wipe_drops:
                self.dead_drops.add(r)
        union = self.wipe_mask | self.dead_mask
        # the dead plan assumes the stubs plan: check the union against the
        # walk with the stubs in place
        self.inv_union = self.invariants(self.wipes + self.dead_wipes, union,
                                         self.wipe_drops | self.dead_drops, wl=self.w2s)

    def _targets(self, inv):
        out = []
        for v in inv["refs_into_interior"]:
            out.append(v[1])
            self._ref_src.setdefault(v[1], v[0])
        return out

    def _recompute_drops(self):
        pl = self.pl
        pl.drops = set()
        rel = pl.rel
        for rva, (data, kind, tag) in pl.patches.items():
            lo = np.searchsorted(rel, rva - 7, "left")
            hi = np.searchsorted(rel, rva + len(data), "left")
            for r in rel[lo:hi]:
                pl.drops.add(int(r))

    def _rollback(self, drop, reason, restore=True):
        """Roll back the patches in `drop`, with their partners."""
        wsd = self._ws_drops()
        # roll back the patches live code enters, with their partners
        tags = {self.pl.patches[r][2] for r in drop}
        keys = set()
        for t in tags:
            parts = t.split()
            keys.add(" ".join(parts[:2]) if not t.startswith("peep") else t)
        gone = [r for r, (d, k, t) in self.pl.patches.items()
                if t in tags or " ".join(t.split()[:2]) in keys]
        if restore:
            self.restore()
        for r in gone:
            tag = self.pl.patches[r][2]
            self.rolled_back.append((r, tag))
            del self.pl.patches[r]
            parts = tag.split()
            try:
                s = int(parts[-1] if parts[-1] != "hop" and parts[-1] != "pred" else parts[-2], 16)
            except ValueError:
                s = None
            why = ("skip", "rolled back: " + (reason if r not in wsd else "the kept-only sweep walk enters it"))
            if parts[0] in ("jmp", "jcc", "call", "popjmp") and s in self.pl.idiom_res:
                self.pl.idiom_res[s] = why
            elif parts[0] == "check" and s in self.pl.check_res:
                self.pl.check_res[s] = why
            elif parts[0] == "chain" and s in self.w1.chains:
                self.w1.chains[s].bypass = False
                self.w1.chains[s].why = why[1]
            elif parts[0] == "peep":
                self.pl.peep_done[parts[1] if parts[1] != "jmp" else "jmp r"] -= 1
                ps = self.pl.peep_seen.get(int(parts[-1], 16))
                if ps is not None:
                    ps[1] = why[1]
                self.pl.peep_skip[why[1]] += 1
        self.pl.claimed = ByteMap(self.im, self.code.extra)
        for r, (d, k, t) in self.pl.patches.items():
            self.pl.claimed.set(r, len(d), 1)
        self._recompute_drops()
        self.log("rolled back %d patches (%s)" % (len(gone), reason))

    def run(self):
        """Everything up to the plan. Leaves the image patched (not wiped).

        The plan is made on the first walk; the second walk (of the patched
        image, with every construct that stays in place walked through) can
        find live code that enters a patch or a wiped byte. Such patches are
        rolled back and such wipes withdrawn, then everything is checked
        again."""
        self.analyse()
        self.rolled_back = []
        self.unwiped = 0
        self.unwipe_targets = set()
        self.b_rounds = 0
        # patches over bytes the keep-only sweep walk reaches: rolled back
        # before anything is applied
        wsd = self._ws_drops()
        if wsd:
            self._rollback(wsd, "the kept-only sweep walk enters it", restore=False)
        self.ws_rolled_back = len(self.rolled_back)
        # A guard publishes its digest when it runs, and a check that reads
        # the dword can run before the guard does: build 1.20's WinMain tests
        # one, takes the "not equal" branch, which sets the flag WinMain needs
        # to go on, and only then calls the guard. So a published value is
        # not a constant of the image, and a construct whose routine publishes
        # one is not folded into a jump: it stays as shipped and calls the
        # routine's replacement, which stores the value (find_routines.py).
        pub = {g for g, m in self.model.r.items() if m.get("publishes")}
        self.publish_kept = 0
        if pub:
            sites = {s for s, i in self.w1.idioms.items() if any(ch.G in pub for ch in i.inner)}
            drop = set()
            for r, (d, k, t) in self.pl.patches.items():
                parts = t.split()
                if parts and parts[0] in ("jmp", "jcc", "call", "popjmp"):
                    try:
                        s = int(parts[-1] if parts[-1] not in ("hop", "pred") else parts[-2], 16)
                    except ValueError:
                        continue
                    if s in sites:
                        drop.add(r)
            before = len(self.rolled_back)
            if drop:
                self._rollback(drop, "a routine inside publishes a value", restore=False)
            self.publish_kept = len(sites)
            self.log("publishing routines: %d; constructs left in place for them: %d (%d patches withdrawn)" % (
                len(pub), len(sites), len(self.rolled_back) - before))
            # such a construct returns through the three addresses its
            # routine's replacement writes: two `ret` gadgets and the
            # continuation. The walk steps over the construct by the table
            # and never passes the gadgets, so they are kept as roots.
            gad = sorted({t for g in pub for _, t in self.model.r[g]["cont"]} - self.b_seen)
            self.b_seen |= set(gad)
            self.b_roots += gad
        for it in range(4):
            self.apply_and_rewalk()
            drop = set()
            for it2 in range(8):
                self.wipes = self.dead_bytes(self.arxan_sec)
                self._apply_unwipes()
                self.b_rounds += self._settle_b()
                self._check_all()
                pstart = sorted(self.pl.patches)
                drop = set()
                unwipe = set()
                for t in self._targets(self.inv) + self._targets(self.inv_union):
                    k = bisect.bisect_right(pstart, t) - 1
                    if k >= 0:
                        r = pstart[k]
                        if r < t < r + len(self.pl.patches[r][0]):
                            drop.add(r)
                            continue
                    unwipe.add(t)
                unwipe -= set(self.u_refs)
                drop |= self._ws_drops()
                if drop or not unwipe:
                    break
                # wipes live code refers to: a direct branch keeps what a
                # keep-only walk from its target reaches; any other
                # reference keeps a data extent (to the next address-taken
                # reference, the next code byte, or the cap)
                br, dr = [], []
                for t in sorted(unwipe):
                    src = self._ref_src.get(t)
                    d = self.code2.insn(src) if isinstance(src, int) else None
                    is_br = d is not None and (d[1] in ("jmp", "call") or d[1] in JCC_MN) and d[2].startswith("0x")
                    self.u_refs[t] = (src, ("%s %s" % (d[1], d[2])) if d else str(src), "branch" if is_br else "other")
                    (br if is_br else dr).append(t)
                self.u_roots += br
                self.u_data += dr
                saved = self._stubs_on()
                self.wu.walk([(r, "referenced by live code") for r in br])
                self._stubs_off(saved)
                self.log("live code refers into %d wiped bytes (%d branches): kept by walk / extent; checking again" % (
                    len(unwipe), len(br)))
            if not drop:
                break
            self._rollback(drop, "live code enters the patch in the patched walk")
        self.log("dead plan: %d ranges %d bytes; union invariants: %s" % (
            len(self.dead_wipes), sum(n for _, n in self.dead_wipes),
            {k: (len(v) if isinstance(v, list) else v) for k, v in self.inv_union.items()}))
        self.log("wipes: %d ranges %d bytes; invariants: %s" % (
            len(self.wipes), sum(n for _, n in self.wipes),
            {k: (len(v) if isinstance(v, list) else v) for k, v in self.inv.items()}))

    def plan(self) -> planfile.Plan:
        p = planfile.Plan()
        for rva, n in self.wipes:
            p.wipe(rva, n)
        for rva in sorted(self.pl.patches):
            data, kind, tag = self.pl.patches[rva]
            p.patch(rva, data, kind)
        for r in sorted(self.pl.drops | self.wipe_drops):
            p.drop(r)
        return p

    def dead_plan(self) -> planfile.Plan:
        p = planfile.Plan()
        for rva, n in self.dead_wipes:
            p.wipe(rva, n)
        for r in sorted(self.dead_drops):
            p.drop(r)
        return p

    def stubs_plan(self) -> planfile.Plan:
        """The routine plans' stub patches that the image's own roots still
        reach once the flow plan and the stubs are applied."""
        p = planfile.Plan()
        live = set(self.stubs_reachable)
        # A construct that stays in place inside rewritten code (its routine
        # publishes a value) is stepped over by the table, so no walk enters
        # the routine: its replacement is needed all the same. The pieces of
        # one replacement are linked by a trailing `jmp rel32`.
        by_rva = dict(self.stub_patches)
        need = set()
        for s, i in self.w1.idioms.items():
            if i.inner and self.pl.idiom_res.get(s, ("",))[0] != "ok":
                need.update(ch.G for ch in i.inner)
        self.stubs_for_kept_constructs = 0
        for g in sorted(need):
            rva = g
            for _ in range(64):
                data = by_rva.get(rva)
                if data is None:
                    break
                if (rva, len(data)) not in live:
                    live.add((rva, len(data)))
                    self.stubs_for_kept_constructs += 1
                if len(data) >= 5 and data[-5] == 0xE9 and data[-1:] != b"\xC3":
                    rva = rva + len(data) + struct.unpack("<i", data[-4:])[0]
                else:
                    break
        for rva, data in self.stub_patches:
            if (rva, len(data)) in live:
                p.patch(rva, data, planfile.KIND_STUB)
        return p

    def function_for(self, starts):
        """For each construct start, a .pdata function entry in .text from
        which the walk reached it without passing through a call (following
        the walk's first-found provenance), or None."""
        w = self.w1
        fn = set(int(b) for b in self.im.runtime_functions()[:, 0])
        text_hi = self.im.exec_sections()[0].rva + self.im.exec_sections()[0].vsize
        out = {}
        for s in starts:
            x = w.found_in.get(s, s)
            res = None
            for _ in range(4000):
                if x in fn and x < text_hi:
                    res = x
                    break
                if x in w.call_targets:
                    break
                nx = w.src.get(x)
                if nx is None or isinstance(nx, str):
                    break
                x = nx
            out[s] = res
        return out

    def _skipped_plain(self):
        out = collections.defaultdict(list)
        for s, r in self.pl.idiom_res.items():
            if r[0] != "ok" and not self.w1.idioms[s].inner:
                out[r[1]].append(s)
        return out

    def reachable_routines(self):
        """Routine entries the stubbed patched walk reaches, with provenance."""
        out = []
        w = self.w2s
        for g in sorted(set(ch.G for ch in self.census.values()) | set(self.model.r)):
            if w.bm.get(g) & (START | ISTART):
                o = w.origin(g, 3000)
                out.append({"G": "%08X" % g, "path_len": len(o),
                            "first_hops": [("%08X" % x) if isinstance(x, int) else x for x in o[1:6]],
                            "root": o[-1] if isinstance(o[-1], str) else None,
                            "root_addr": ("%08X" % o[-2]) if len(o) > 1 and isinstance(o[-2], int) else None})
        return out

    # -- provenance of tracked instructions (item C) -------------------------
    def _gset(self):
        return set(ch.G for ch in self.census.values()) | set(self.model.r)

    def _path(self, w, code, start, goal, limit=50000):
        """The walk's straight-line path from a work item to `goal` (same
        rules as Walker._run): [(pc, mnemonic, op)], reached?"""
        pc, seq, seen = start, [], set()
        while len(seq) < limit:
            if pc == goal:
                return seq, True
            if pc in seen:
                return seq, False
            seen.add(pc)
            idm = w.idioms.get(pc)
            if idm is not None:
                if idm.kind == "jmp" and not idm.inner:
                    seq.append((pc, "idiom jmp", "0x%x" % idm.target))
                    pc = idm.target
                    continue
                if idm.kind == "jcc" and not idm.inner:
                    seq.append((pc, "idiom j%s (not taken)" % idm.cc, "0x%x" % idm.target))
                    pc = idm.fall
                    continue
                seq.append((pc, "idiom " + idm.kind, ""))
                return seq, False
            if pc in w.chains:
                seq.append((pc, "chain (stepped over)", ""))
                return seq, False
            d = code.insn(pc)
            if d is None:
                return seq, False
            size, m, op = d
            seq.append((pc, m, op))
            if m == "jmp" and op.startswith("0x"):
                pc = int(op, 16)
                continue
            if m in STOP_MN or m == "jmp":
                return seq, False
            pc += size
        return seq, False

    def provenance(self, x, w, code):
        hit = w.track_hit.get(x)
        if hit is None:
            return {"reached": False}
        run0 = hit[0]
        chain = w.origin(run0, 1_000_000)
        items = [c for c in chain if isinstance(c, int)]
        root_why = chain[-1] if isinstance(chain[-1], str) else None
        G = self._gset()
        lo_a, hi_a = self.arxan_sec
        fn = getattr(self, "_fnset", None)
        if fn is None:
            fn = self._fnset = set(int(b) for b in self.im.runtime_functions()[:, 0])
        text_hi = self.im.exec_sections()[0].rva + self.im.exec_sections()[0].vsize
        hops, flags = [], []
        goal = x
        for k, it in enumerate(items):
            seq, ok = self._path(w, code, it, goal)
            for pc, m, op in seq:
                if m == "call" and op.startswith("0x"):
                    t = int(op, 16)
                    if t in G or lo_a <= t < hi_a:
                        flags.append("passes the fall-through of `call 0x%X` at 0x%X (a call into the "
                                     "protection, which the planner treats as one-way when it is a chain)" % (t, pc))
                if pc in self.census:
                    flags.append("passes through the chain at 0x%X walked as plain code" % pc)
                if pc in w.unknowns:
                    flags.append("passes through the construct at 0x%X left in place (no continuation)" % pc)
            via = w.src_pc.get(it)
            vd = code.insn(via) if via is not None else None
            hops.append({"item": "%08X" % it, "path_insns": len(seq), "path_found": ok,
                         "via": ("%08X %s %s" % (via, vd[1], vd[2])) if vd else None})
            goal = via
        root = items[-1] if items else None
        real = (root_why in ("pdata", "entry", "tls", "export") and root is not None and root < text_hi
                and (root_why != "pdata" or root in fn))
        return {"reached": True, "root": "%08X" % root if root is not None else None, "root_kind": root_why,
                "root_in_protection_section": root is not None and lo_a <= root < hi_a,
                "root_is_pdata_begin_in_text": bool(real),
                "root_first_insns": ["%08X %s %s" % (a_, m_, o_) for a_, _, m_, o_ in
                                     (list(code.run(root, 64))[:6] if root is not None else [])],
                "hops": len(items),
                "first_hops": hops[:8], "last_hops": hops[-4:] if len(hops) > 8 else [],
                "one_way_flags": sorted(set(flags))[:20], "one_way_flag_count": len(set(flags))}

    def provenance_report(self, addrs):
        out = {}
        for x in addrs:
            e = {}
            for name, w, code in (("planning walk", self.w1, self.code), ("patched walk", self.w2, self.code2),
                                  ("patched walk, routines stubbed", self.w2s, self.code3 or self.code2),
                                  ("kept-only sweep walk", self.ws, self.code),
                                  ("dropped-record walk", self.wk, self.code2),
                                  ("plausible-block target walk", self.wb, self.code2)):
                p = self.provenance(x, w, code)
                if p["reached"]:
                    e[name] = p
            out["%08X" % x] = e
        return out

    # -- 3,645 sites, sweep content -----------------------------------------
    def site_status(self, sites):
        w1, ws = self.w1, self.ws
        S = set(sites)
        in_idiom = {}
        for wname, w in (("planning", w1), ("kept-only", ws)):
            for st, idm in w.idioms.items():
                for a, n in idm.insns:
                    for b in range(a, a + n):
                        if b in S and (b not in in_idiom):
                            in_idiom[b] = (wname, st)
        left = sorted(getattr(self, "_sweep_left", {}).items())
        lk = [a for a, _ in left]
        fb, fe, bi, ei = self._rec_arrays(w1.bm, exclude_prot=False)
        o = np.argsort(fb)
        fbs, fes = fb[o], fe[o]
        res = collections.Counter()
        samples = collections.defaultdict(list)
        per = {}
        for s in sites:
            f1 = w1.bm.get(s)
            if s in in_idiom and in_idiom[s][0] == "planning":
                st = in_idiom[s][1]
                r = self.pl.idiom_res.get(st, ("?", "?"))
                why = "planning walk: idiom rewritten" if r[0] == "ok" else "planning walk: idiom left: %s" % r[1]
            elif f1 & (CODE | IDIOM | CHAIN):
                why = "planning walk: walked as plain code (inside a construct left in place)" \
                    if s in w1.frozen else "planning walk: walked as plain code"
            elif s in in_idiom:
                why = "kept-only sweep walk: idiom found, not rewritten"
            elif ws.bm.get(s) & (CODE | IDIOM | CHAIN):
                why = "kept-only sweep walk: plain code"
            elif self.wk.bm.get(s) & (CODE | IDIOM | CHAIN):
                why = "kept: reached from dropped records only"
            elif self.wb.bm.get(s) & (CODE | IDIOM | CHAIN):
                why = "kept: reached from plausible-block targets only"
            else:
                k = int(np.searchsorted(fbs, s, "right")) - 1
                if k < 0 or s >= fes[k]:
                    why = "not reached: outside every exception record"
                elif not ((w1.bm.get(int(fbs[k])) | ws.bm.get(int(fbs[k]))) & (START | ISTART)):
                    why = "not reached: its record's begin is not live"
                else:
                    j = bisect.bisect_right(lk, s) - 1
                    if j >= 0 and lk[j] >= fbs[k]:
                        why = "not reached: sweep left the gap before it: " + left[j][1]
                    else:
                        why = "not reached: no sweep candidate before it in its record"
            i = w1.bm.idx(s)
            wiped = bool(i >= 0 and (self.wipe_mask[i] or self.dead_mask[i]))
            key = why + (" [wiped]" if wiped else "")
            res[key] += 1
            if len(samples[key]) < 20:
                samples[key].append("%08X" % s)
            per["%08X" % s] = key
        return {"count": len(sites), "by_status": dict(res.most_common()), "samples": samples}

    def kept_only_content(self, ws=None, roots=None):
        ws = ws or self.ws
        roots = self.sweep_roots if roots is None else roots
        f = ws.bm.f
        lo_t = ws.bm.secs[0]
        mem = np.frombuffer(self.im.mem, dtype=np.uint8)
        nj = 0
        for lo, hi, off in ws.bm.secs:
            seg = mem[lo:hi]
            fl = f[off:off + hi - lo]
            n = len(seg) - 3
            m = (seg[:n] == 0xFF) & (seg[1:n + 1] == 0x64) & (seg[2:n + 2] == 0x24) & (seg[3:n + 3] == 0xF8)
            m &= ((fl[:n] & (CODE | IDIOM | CHAIN)) != 0)
            nj += int(m.sum())
        longs = [x for x in long_sub_sites(self.im, self.code) if f[ws.bm.idx(x)] & (CODE | START)]
        pl = Planner(self.im, self.code, self.xr, ws, roots, keep=None)
        pl.plan_peephole()
        return {"jmp_rsp8_bytes_in_kept_only_code": nj,
                "idioms": len(ws.idioms),
                "idioms_by_kind": dict(collections.Counter(i.kind for i in ws.idioms.values())),
                "constructs_with_a_routine_inside": sum(1 for i in ws.idioms.values() if i.inner),
                "constructs_without_continuation": len(ws.unknowns),
                "constructs_without_continuation_first": ["%08X" % a for a in sorted(ws.unknowns)[:50]],
                "chains_walked_as_plain_code": sum(1 for S in self.census if f[ws.bm.idx(S)] & START),
                "long_form_sites": len(longs),
                "long_form_sites_list": ["%08X" % x for x in longs[:100]],
                "pairs_by_form": dict(pl.peep_count),
                "idiom_sample": ["%08X" % a for a in sorted(ws.idioms)[:40]]}

    # -- E: what stays in the protection's section ---------------------------
    def protection_breakdown(self):
        rs = self._reasons
        sec_lo, sec_hi = rs["sec"]
        sl = slice(sec_lo, sec_hi)
        kept = ~(self.wipe_mask[sl] | self.dead_mask[sl])
        C = CODE | IDIOM | CHAIN
        live = ((self.w2.bm.f[sl] | self.w2s.bm.f[sl]) & (C | DREAD)) != 0
        patched = self.pl.claimed.f[sl] != 0
        lost = (self.wk.bm.f[sl] & (C | DREAD)) != 0
        swept = (self.ws.bm.f[sl] & (C | DREAD)) != 0
        btarg = (self.wb.bm.f[sl] & (C | DREAD)) != 0
        utarg = (self.wu.bm.f[sl] & (C | DREAD)) != 0
        writes = np.zeros_like(kept)
        bm = self.w2.bm
        for rva, n in self.model.writes:
            i = bm.idx(rva)
            if sec_lo <= i < sec_hi:
                writes[i - sec_lo:i - sec_lo + n] = True
        stubs = np.zeros_like(kept)
        for rva, n in self.stubs_reachable:
            i = bm.idx(rva)
            if sec_lo <= i < sec_hi:
                stubs[i - sec_lo:i - sec_lo + n] = True
        other_plans = self.keep_wipe.f[sl] != 0
        mem = np.frombuffer(self.im.mem, dtype=np.uint8, count=self.arxan_sec[1] - self.arxan_sec[0],
                            offset=self.arxan_sec[0])
        order = [("live code", live), ("patched", patched), ("PE structure", rs["pe"]),
                 ("data read by a live instruction", rs["data_live"]),
                 ("data pointed at by a relocated pointer", rs["data_reloc"]),
                 ("reached only from dropped records", lost),
                 ("kept-only sweep walk (code and data)", swept),
                 ("reached from targets of plausible unwalked blocks", btarg),
                 ("reached from branch targets live code has into would-be wipes", utarg),
                 ("bytes a routine writes", writes), ("routine stub still reached", stubs),
                 ("other plans' bytes", other_plans)]
        taken = np.zeros_like(kept)
        out = {"section_bytes": int(sec_hi - sec_lo), "kept_bytes": int(kept.sum())}
        # page entropy
        npg = (len(mem) + 4095) // 4096
        ent = np.zeros(npg)
        for p in range(npg):
            pg = mem[p * 4096:(p + 1) * 4096]
            c = np.bincount(pg, minlength=256)
            q = c[c > 0] / len(pg)
            ent[p] = -(q * np.log2(q)).sum()
        rows = {}

        def page_any(m):
            pad = np.zeros(npg * 4096, dtype=bool)
            pad[:len(m)] = m
            return pad.reshape(npg, 4096).any(axis=1)
        for name, m in order:
            mine = kept & m & ~taken
            taken |= mine
            pages = np.flatnonzero(page_any(mine))
            rows[name] = {"bytes": int(mine.sum()), "pages": int(len(pages)),
                          "pages_above_7.2_bits": int((ent[pages] > 7.2).sum()) if len(pages) else 0}
        rest = kept & ~taken
        zero = (mem == 0) | (mem == 0xCC)
        rows["other"] = {"bytes": int(rest.sum()), "zero_or_int3_bytes": int((rest & zero).sum()),
                         "protection_code_bytes": int((rest & (((self.wa.bm.f[sl] & C) != 0))).sum())}
        out["by_reason"] = rows
        out["pe_structures"] = rs.get("pe_names", {})
        out["referencing_sites_live_insns"] = rs.get("refs_live")
        out["referencing_sites_relocated_pointers"] = rs.get("refs_reloc")
        refs_in = 0
        for w in (self.w2, self.w2s, self.wk, self.wb, self.ws):
            for _, t in w.datarefs:
                if self.arxan_sec[0] <= t < self.arxan_sec[1]:
                    refs_in += 1
        rel = self.im.relocations()
        rel_in = 0
        for sec in self.im.sections:
            if sec.executable:
                continue
            for r in rel[(rel >= sec.rva) & (rel < sec.rva + sec.vsize)]:
                v = self.im.u64(int(r)) - self.im.image_base
                if self.arxan_sec[0] <= v < self.arxan_sec[1]:
                    rel_in += 1
        out["live_data_refs_into_section"] = refs_in
        out["relocated_pointers_into_section"] = rel_in
        old = rs["data_old_rule"]
        newd = rs["data_live"] | rs["data_reloc"]
        out["extent_rule"] = {
            "old_rule_bytes_in_section": int(old.sum()), "new_rule_bytes_in_section": int(newd.sum()),
            "saved_by_tighter_extents": int((old & ~newd).sum()),
            "saved_and_now_wiped": int((old & ~newd & ~kept).sum()),
            "round3_rule_bytes_in_section": int(rs["data_round3_rule"].sum()),
            "given_back_vs_round3_rule": int((newd & ~rs["data_round3_rule"]).sum())}
        out["high_entropy_pages_kept"] = int(((ent > 7.2) & page_any(kept)).sum())
        out["high_entropy_pages_in_section"] = int((ent > 7.2).sum())
        return out

    # -- G: symptoms of non-code in the live set -----------------------------
    def junk_symptoms(self):
        """Report only. Live instruction starts (patched walk) that overlap
        another, RIP-relative operands outside the image, direct branches
        to non-code; and the protection-section bytes reached only through
        a path holding one of them."""
        w2, code2 = self.w2, self.code2
        C = CODE | IDIOM | CHAIN
        ex = self.code.ex
        size = len(self.im.mem)
        res = {}
        for name, w, code in (("patched walk", w2, code2),
                              ("patched walk, routines stubbed", self.w2s, self.code3 or code2)):
            f = w.bm.f
            idx = np.flatnonzero((f & (START | ISTART)) != 0)
            # rva of every start
            rv = np.empty(len(idx), dtype=np.int64)
            for lo, hi, off in w.bm.secs:
                m = (idx >= off) & (idx < off + hi - lo)
                rv[m] = idx[m] - off + lo
            sizes = np.zeros(len(idx), dtype=np.int64)
            ripout, brout = [], []
            md = code.md
            mem = self.im.mem
            for k, a in enumerate(rv.tolist()):
                for _, sz, m, op in md.disasm_lite(bytes(mem[a:a + 16]), a, 1):
                    sizes[k] = sz
                    if "rip" in op:
                        t = rip_target(op, a + sz)
                        if t is not None and not (0 <= t < size):
                            ripout.append(a)
                    elif op.startswith("0x") and (m == "jmp" or m == "call" or m in JCC_MN):
                        t = int(op, 16)
                        if not any(lo <= t < hi for lo, hi in ex):
                            brout.append(a)
            o = np.argsort(rv)
            rv_s, sz_s = rv[o], sizes[o]
            ends = rv_s + np.maximum(sz_s, 1)
            # an instruction overlaps the next start inside it
            ov = np.flatnonzero(rv_s[1:] < ends[:-1])
            overl = set(rv_s[ov].tolist()) | set(rv_s[ov + 1].tolist())
            res[name] = {"instruction_starts": int(len(rv)),
                         "starts_overlapping_another": len(overl),
                         "rip_operand_outside_image": len(ripout),
                         "direct_branch_to_non_code": len(brout),
                         "samples": {"overlap": ["%08X" % x for x in sorted(overl)[:20]],
                                     "rip_outside": ["%08X" % x for x in ripout[:20]],
                                     "branch_non_code": ["%08X" % x for x in brout[:20]]}}
            if w is w2:
                strong = set(ripout) | set(brout)
                allp = strong | overl
        # clean walks of the patched image that never execute a symptomatic
        # instruction; live protection-section bytes they miss are reached
        # only through a path holding one
        lo_i, hi_i = w2.bm.idx(self.arxan_sec[0]), w2.bm.idx(self.arxan_sec[1] - 1) + 1
        base = (w2.bm.f[lo_i:hi_i] & C) != 0
        base_all = ((w2.bm.f & C) != 0)
        for label, poison in (("rip outside image or branch to non-code", strong),
                              ("those, or an overlapping start", allp)):
            wc = Walker(self.im, code2, bypass=False)
            wc.atomic = False
            wc.poison = poison
            wc.walk(self.roots)
            got = (wc.bm.f[lo_i:hi_i] & C) != 0
            got_all = (wc.bm.f & C) != 0
            if poison is strong:
                self._wc_f = (wc.bm.f & C) != 0
            res["only through a path with: " + label] = {
                "live_bytes_in_protection_section": int(base.sum()),
                "reached_only_through_such_a_path": int((base & ~got).sum()),
                "live_bytes_everywhere": int(base_all.sum()),
                "everywhere_only_through_such_a_path": int((base_all & ~got_all).sum())}
            del wc
        return res

    def routine_closure_report(self):
        """Report only: the routine entries' direct-flow closure, its overlap
        with the clean game walk (item G), and the kept-only bytes in it."""
        wr = self.wr_f
        bm = self.w2.bm
        out = {"routine_entries": len(self._gset()), "closure_bytes": int(wr.sum()),
               "closure_insns": self.wr_insns}
        wc = getattr(self, "_wc_f", None)
        if wc is not None:
            ov = wr & wc
            out["overlap_with_clean_game_walk_bytes"] = int(ov.sum())
            G = self._gset()
            rng = ranges_of(ov)
            lst = []
            n_entry_only = 0
            for a, b in rng:
                ra = bm.rva(a)
                if ra in G and b - a <= 32:
                    n_entry_only += 1
                    continue
                lst.append((ra, b - a))
            out["overlap_ranges"] = len(rng)
            out["overlap_ranges_at_routine_entries_32_bytes_or_less"] = n_entry_only
            out["overlap_ranges_other"] = len(lst)
            out["overlap_other_bytes"] = int(sum(n for _, n in lst))
            out["overlap_other_largest"] = ["%08X+%d" % x for x in sorted(lst, key=lambda x: -x[1])[:50]]
        ko = (self.ws.bm.f & (CODE | IDIOM | CHAIN)) != 0
        ko &= (self.w1.bm.f & (CODE | IDIOM | CHAIN)) == 0
        out["kept_only_bytes"] = int(ko.sum())
        out["kept_only_bytes_inside_closure"] = int((ko & wr).sum())
        m0 = getattr(self, "_ws0_mask", None)
        if m0 is not None:
            k0 = np.unpackbits(m0)[:len(wr)].astype(bool) & ((self.w1.bm.f & (CODE | IDIOM | CHAIN)) == 0)
            out["kept_only_bytes_without_stubs"] = int(k0.sum())
            out["kept_only_bytes_without_stubs_inside_closure"] = int((k0 & wr).sum())
        lo_i, hi_i = bm.idx(self.arxan_sec[0]), bm.idx(self.arxan_sec[1] - 1) + 1
        out["kept_only_bytes_in_protection_section"] = int(ko[lo_i:hi_i].sum())
        out["kept_only_bytes_in_protection_section_inside_closure"] = int((ko & wr)[lo_i:hi_i].sum())
        return out

    def fold_report(self) -> dict:
        w1, pl, model = self.w1, self.pl, self.model
        folded = {s: i for s, i in w1.idioms.items() if any(e[0] == "cont" for e in i.effects)}
        ok = [s for s in folded if pl.idiom_res[s][0] == "ok"]
        skip = collections.Counter(pl.idiom_res[s][1] for s in folded if pl.idiom_res[s][0] != "ok")
        unk = []
        for s, u in sorted(w1.unknowns.items()):
            m = model.get(u.chain.G) or {}
            unk.append({"outermost_start": "%08X" % s, "S": "%08X" % u.chain.S, "G": "%08X" % u.chain.G,
                        "class": m.get("class"), "why": u.why})
        return {
            "constructs_with_a_continuation_routine": len(folded),
            "folded": len(ok),
            "folded_by_kind": dict(collections.Counter(w1.idioms[s].kind for s in ok)),
            "folded_popjmp_entries": [{"start": "%08X" % s, "pop": w1.idioms[s].pop,
                                       "target": "%08X" % w1.idioms[s].target} for s in ok
                                      if w1.idioms[s].kind == "popjmp"],
            "skipped_by_reason": dict(skip),
            "skipped_sites": {r: ["%08X" % s for s in folded if pl.idiom_res[s][0] != "ok"
                                  and pl.idiom_res[s][1] == r][:100] for r in skip},
            "register_liveness": dict(collections.Counter(pl.inner_regs.values())),
            "flag_liveness": dict(collections.Counter(pl.inner_flags.values())),
            "unknown_continuation_constructs": len(unk),
            "unknown_continuation_routines": sorted(set(x["G"] for x in unk)),
            "unknown_continuation_list": unk,
            "keep_plan_overlaps": [(k, "%08X" % a) for k, a in pl.keep_overlaps],
            "checks": {"bake_source": self.bake_source, "baked_values": len(self.baked),
                       "sites": len(self.checks),
                       "folded": sum(1 for r in pl.check_res.values() if r[0] == "ok"),
                       "by_result": dict(collections.Counter(r[0] if r[0] == "ok" else r[1]
                                                            for r in pl.check_res.values())),
                       "list": [ck.as_json() | {"result": list(map(str, pl.check_res.get(c, ("?",))))}
                                for c, ck in sorted(self.checks.items())]},
            "peephole_forms_in_live_code": dict(pl.peep_count),
            "peephole_folded": dict(pl.peep_done),
            "peephole_skipped": dict(pl.peep_skip),
            "peephole_sample_sites": {k: ["%08X" % x for x in v[:50]] for k, v in pl.peep_sites.items()},
            "baked_values_applied": len(self.baked),
            "routine_stub_patches_total": len(self.stub_ranges),
            "routine_stub_patches_still_reachable": self.stubs_live,
            "table_entries_that_are_not_routines": len(model.not_routines),
            "routines_from_extra_file": sorted("%08X" % g for g in model.extra_given),
            "folded_on_extra_file_alone": [
                {"start": "%08X" % s, "routines": ["%08X" % c.G for c in w1.idioms[s].inner
                                                   if c.G in model.extra_given]}
                for s in ok if any(c.G in model.extra_given for c in w1.idioms[s].inner)],
            "table_routines_without_continuation": sorted(
                "%08X" % g for g, m in model.r.items() if m["form"] != "call" and len(m["cont"]) != 3),
        }

    def report(self) -> dict:
        w1, pl = self.w1, self.pl
        chains = list(w1.chains.values())
        why = collections.Counter(ch.why for ch in chains if not ch.bypass)
        flags = collections.Counter(ch.flags for ch in chains)
        census_unreached = [ch.S for ch in self.census.values() if ch.S not in w1.chains]
        kinds = collections.Counter(i.kind for i in w1.idioms.values())
        ok = collections.Counter(w1.idioms[s].kind for s, r in pl.idiom_res.items() if r[0] == "ok")
        how = collections.Counter(r[1] for r in pl.idiom_res.values() if r[0] == "ok")
        skip = collections.Counter(r[1] for r in pl.idiom_res.values() if r[0] != "ok")
        skip_sites = collections.defaultdict(list)
        for s, r in sorted(pl.idiom_res.items()):
            if r[0] != "ok":
                skip_sites[r[1]].append("%08X" % s)
        call_empty = sum(1 for s, r in pl.idiom_res.items()
                         if r[0] == "ok" and w1.idioms[s].kind == "call" and r[2][0][0] == "jmp")
        bm2, bm1 = self.w2.bm, self.w1.bm
        sec = {}
        for lo, hi, off in bm2.secs:
            seg = bm2.f[off:off + hi - lo]
            sec["%08X-%08X" % (lo, hi)] = {
                "live_code_bytes": int(((seg & (CODE | IDIOM | CHAIN)) != 0).sum()),
                "wiped_bytes": int(self.wipe_mask[off:off + hi - lo].sum()),
                "dead_plan_bytes": int(self.dead_mask[off:off + hi - lo].sum())}
        return {
            "image": os.path.basename(self.im.path),
            "extra_code_regions": ["%08X-%08X" % r for r in self.extra],
            "roots": dict(collections.Counter(w for _, w in self.roots)),
            "roots_dropped_inside_chains": ["%08X" % r for r in self.dropped_roots],
            "roots_dropped_on_protection_code": {"count": len(self.dropped_prot),
                                                 "reached_anyway": len(self.dropped_reached),
                                                 "not_reached_otherwise": ["%08X" % r for r in self.lost_records],
                                                 "first": ["%08X" % r for r in self.dropped_prot[:100]]},
            "routine_entries_reached_from_game_roots": ["%08X" % g for g in sorted(set(
                ch.G for ch in self.census.values()))
                if self.w2.bm.get(g) & (START | CODE | IDIOM)],
            "long_sub_sites": len(self.census) + len(self.cfail),
            "chains_matched": len(self.census),
            "long_sub_sites_without_chain": ["%08X" % x for x in self.cfail],
            "chains_reached_from_game_roots": len(chains),
            "chains_not_reached": len(census_unreached),
            "chains_bypassed": sum(1 for c in chains if c.bypass),
            "chains_bypass_method": dict(collections.Counter(c.S_patch for c in chains if c.bypass)),
            "chains_not_bypassed_by_reason": {str(k): v for k, v in why.items()},
            "chains_flags_at_E": dict(flags),
            "chains": [c.as_json() | {"push_order": c.push_order} for c in sorted(chains, key=lambda c: c.S)],
            "census_unreached_S": ["%08X" % s for s in census_unreached],
            "chains_inside_idioms": len(set(c.S for i in w1.idioms.values() for c in i.inner)),
            "chains_inside_rewritten_idioms": len(set(c.S for s, i in w1.idioms.items() for c in i.inner
                                                      if pl.idiom_res[s][0] == "ok")),
            "chains_inside_idioms_list": [{"S": c.S, "idiom": s, "E_raw": c.E_raw, "G": c.G,
                                           "flags_after": pl.inner_flags.get(s, "preserved"),
                                           "rewritten": pl.idiom_res[s][0] == "ok"}
                                          for s, i in sorted(w1.idioms.items()) for c in i.inner],
            "inner_chain_flags": dict(collections.Counter(pl.inner_flags.values())),
            "idioms_found": dict(kinds),
            "idioms_rewritten": dict(ok),
            "idioms_rewritten_how": dict(how),
            "idiom_calls_of_empty_routines_as_jmp": call_empty,
            "idioms_skipped_by_reason": dict(skip),
            "idioms_skipped_sites": {k: v[:200] for k, v in skip_sites.items()},
            "patches": len(pl.patches),
            "patch_bytes": sum(len(d) for d, _, _ in pl.patches.values()),
            "reloc_drops_patches": len(pl.drops),
            "reloc_drops_wipes": len(self.wipe_drops),
            "wipe_ranges": len(self.wipes),
            "wipe_bytes": sum(n for _, n in self.wipes),
            "arxan_section_composition": self.wipe_stats,
            "sections": sec,
            "walk1": {"insns": w1.insns, "overlaps": len(w1.overlaps), "undecodable": len(w1.undecodable),
                      "outside": len(w1.outside), "jump_tables": len(w1.jtables)},
            "walk2_idioms_left": len(self.w2.idioms),
            "plain_idioms_left_in_place": {
                r: {"count": len(v), "reached_in_patched_walk": sum(
                    1 for x in v if self.w2s.bm.get(x) & (START | ISTART))}
                for r, v in self._skipped_plain().items()},
            "stubs_plan_patches": len(self.stubs_reachable),
            "stub_patches_total": len(self.stub_patches),
            "routine_entries_reachable_with_stubs": self.reachable_routines(),
            "walk2_stubbed_insns": self.w2s.insns,
            "rolled_back_patches": {"count": len(self.rolled_back),
                                    "list": ["%08X %s" % (r, t) for r, t in self.rolled_back[:300]]},
            "wipe_bytes_withdrawn_after_check": self.unwiped,
            "folds": self.fold_report(),
            "dead_plan": {"ranges": len(self.dead_wipes), "bytes": sum(n for _, n in self.dead_wipes),
                          "reloc_drops": len(self.dead_drops)},
            "invariants_union_with_dead_plan": {
                k: (v if not isinstance(v, list) else {"count": len(v), "first": [str(x) for x in v[:50]]})
                for k, v in self.inv_union.items()},
            "invariants": {k: (v if not isinstance(v, list) else {"count": len(v), "first": [str(x) for x in v[:50]]})
                           for k, v in self.inv.items()},
        }


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("exe", help="executable decrypted by `mwdec decrypt`")
    ap.add_argument("-o", "--out", required=True, help="plan file to write")
    ap.add_argument("--report", help="JSON report to write")
    ap.add_argument("--live", help="write the live-byte bitmap of the code regions (.npy)")
    ap.add_argument("--routines", help="routine table JSON (per routine entry: form, cont, regs_changed)")
    ap.add_argument("--keep-plan", action="append", default=[],
                    help="another plan whose bytes are left alone (its KIND_BAKE values are applied "
                         "before analysis); may repeat")
    ap.add_argument("--dead-plan", help="second plan: the wipes held back from the main plan")
    ap.add_argument("--routines-extra", action="append", default=[],
                    help="continuations for routines the main table lacks: "
                         "{\"0x<G>\": {\"cont_rva\": [T0, T1, T2], \"offset_measured\": o}}; may repeat")
    ap.add_argument("--bake-json", help="baked values as a JSON list `bake` of {rva, bytes, needed}, "
                                        "used only when no --keep-plan carries KIND_BAKE patches")
    ap.add_argument("--stub-plan", action="append", default=[],
                    help="a plan of routine stubs (the routine census writes two); the walks that decide "
                         "what stays run with these in place; may repeat, a later plan wins")
    ap.add_argument("--stubs-out", help="third plan: the stub patches that code left in the image still reaches")
    ap.add_argument("--starts-out", help="write the entries of the functions that reach a folded construct or check")
    ap.add_argument("--proven", action="append", default=[], metavar="RVA",
                    help="hex entry of a routine to plan as proven although the table has no passed "
                         "chain proof for it; may repeat")
    a = ap.parse_args()
    pp = Pipeline(a.exe, log=lambda s: print(s, flush=True), routines=a.routines,
                  keep_plans=a.keep_plan, bake_json=a.bake_json, routines_extra=a.routines_extra,
                  stub_plans=a.stub_plan, treat_proven=[int(x, 16) for x in a.proven])
    pp.run()
    plan = pp.plan()
    plan.save(a.out)
    print(plan.summary())
    if a.dead_plan:
        dp = pp.dead_plan()
        dp.save(a.dead_plan)
        print("dead plan:", dp.summary())
    if a.stubs_out:
        sp = pp.stubs_plan()
        sp.save(a.stubs_out)
        print("stubs plan:", sp.summary())
    if a.report:
        rep = pp.report()
        json.dump(rep, open(a.report, "w"), indent=1, default=lambda o: int(o) if isinstance(o, np.integer) else str(o))
    if a.starts_out:
        # function entries from which a folded construct or a folded check is
        # reached without a call: where a comparison of this export with the
        # protected image should start (MWHook, d9_e2e.py --starts)
        folds = sorted(s for s, r in pp.pl.idiom_res.items()
                       if r[0] == "ok" and any(e[0] == "cont" for e in pp.w1.idioms[s].effects))
        checks = sorted(c for c, r in pp.pl.check_res.items() if r[0] == "ok")
        ent = set(v for v in pp.function_for(folds).values() if v) | \
            set(v for v in pp.function_for(checks).values() if v)
        with open(a.starts_out, "w") as f:
            f.write("".join("%X\n" % v for v in sorted(ent)))
        print("starts: %d function entries reach %d folds and %d folded checks" % (len(ent), len(folds), len(checks)))
    if a.live:
        # live: what the image's own roots reach in the patched image, with
        # or without the stubs plan, plus every byte the plan patches
        bm = pp.w2.bm
        live = np.packbits(((bm.f & (CODE | IDIOM | CHAIN)) != 0) | ((pp.w2s.bm.f & (CODE | IDIOM | CHAIN)) != 0)
                           | (pp.pl.claimed.f != 0))
        np.save(a.live, live)
        json.dump({"regions": [[lo, hi, off] for lo, hi, off in bm.secs], "packbits": True},
                  open(os.path.splitext(a.live)[0] + ".json", "w"))


if __name__ == "__main__":
    main()
