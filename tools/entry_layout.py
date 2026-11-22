"""Lay out the protected executable's entry points as straight-line code.

Input: an executable already decrypted by `mwdec decrypt`. Nothing is run.

The protection scatters each entry path over the image, one or two
instructions at a time, joined by `jmp`, and writes jumps and calls as
stack tricks:

    lea rsp,[rsp-8] ; mov [rsp],rbp ; lea rbp,[rip+X] ; xchg [rsp],rbp   = push X
    push X ; lea rsp,[rsp+8] ; jmp [rsp-8]                               = jmp X
    push R ; push G ; ret                                                = call G, return to R

This tool follows the path from each TLS callback and from the entry point,
resolves those tricks with a small symbolic stack, drops the joining jumps,
and folds the context save/restore blocks into one line each.

    py -3 entry_layout.py modernwarfare.dec.exe [-o entry.md] [--raw] [--names names.json]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

import capstone
from capstone import x86_const as X

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from mwdec.pe import Image  # noqa: E402

MAX_STEPS = 4000


class Walker:
    def __init__(self, image: Image, names: dict[int, str]):
        self.im = image
        self.names = names
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self.md.detail = True

    def one(self, rva: int):
        code = bytes(self.im.mem[rva:rva + 16])
        for insn in self.md.disasm(code, rva):
            return insn
        return None

    def name(self, rva: int) -> str:
        n = self.names.get(rva)
        return "%08X" % rva + (" <%s>" % n if n else "")

    def walk(self, start: int):
        """Returns a list of rows: (rva, text, kind, extra)."""
        rows = []
        stack: list[int | None] = []      # symbolic: known constants or None
        below: int | None = None          # value just popped (at [rsp-8])
        regval: dict = {}                 # reg -> RVA constant, or ("cc", cond, A, B)
        prepush = [None]                  # value written to [rsp-8] before a push
        seen: set[int] = set()
        pc = start

        def pop():
            return stack.pop() if stack else None

        for _ in range(MAX_STEPS):
            if pc in seen:
                rows.append((pc, "(loops back to %08X)" % pc, "end", None))
                break
            seen.add(pc)
            i = self.one(pc)
            if i is None:
                rows.append((pc, "(undecodable: still encrypted?)", "end", None))
                break
            ops = i.operands
            m = i.mnemonic
            nxt = pc + i.size
            text = ("%s %s" % (m, i.op_str)).strip()

            def is_rsp_mem(op, disp):
                return (op.type == X.X86_OP_MEM and op.mem.base == X.X86_REG_RSP
                        and op.mem.index == 0 and op.mem.disp == disp)

            if m == "jmp" and ops[0].type == X.X86_OP_IMM:
                rows.append((pc, text, "flow", ops[0].imm))
                pc = ops[0].imm
                continue
            if (m == "jmp" and is_rsp_mem(ops[0], -8)) or m == "ret":
                tgt = below if m == "jmp" else pop()
                below = None
                if isinstance(tgt, tuple):          # push A ; cmovcc -> B ; ret
                    _, cc, a_, b_ = tgt
                    rows.append((pc, "j%s %s" % (cc, self.name(b_)), "cjcc", b_))
                    pc = a_
                    continue
                if tgt is None:
                    rows.append((pc, text, "end", None))
                    break
                ret_to = stack[-1] if (m == "ret" and stack) else None
                if isinstance(ret_to, int):
                    rows.append((pc, "call %s" % self.name(tgt), "ccall", (tgt, ret_to)))
                    stack.pop()
                    pc = ret_to
                else:
                    rows.append((pc, "jmp %s" % self.name(tgt), "cjmp", tgt))
                    pc = tgt
                continue
            if m == "jmp":
                rows.append((pc, text, "end", None))
                break
            if m == "call" and ops[0].type == X.X86_OP_IMM:
                rows.append((pc, "call %s" % self.name(ops[0].imm), "call", ops[0].imm))
                pc = nxt
                continue
            if m.startswith("j") and ops and ops[0].type == X.X86_OP_IMM:
                rows.append((pc, text, "jcc", ops[0].imm))
                pc = nxt
                continue

            # ---- symbolic stack and registers ---------------------------
            below_next = None

            def slot(disp):
                k = disp // 8
                return -1 - k if 0 <= k < len(stack) and disp % 8 == 0 else None

            r0 = ops[0].reg if ops and ops[0].type == X.X86_OP_REG else None
            keep = False
            if m == "push":
                stack.append(None)
            elif m == "pushfq":
                stack.append(None)
            elif m in ("pop", "popfq"):
                below_next = pop()
            elif m == "lea" and r0 == X.X86_REG_RSP and                     ops[1].mem.base == X.X86_REG_RSP and ops[1].mem.index == 0:
                d = ops[1].mem.disp
                if d < 0:
                    stack.extend([prepush[0]] + [None] * (-d // 8 - 1))
                else:
                    for _k in range(d // 8):
                        below_next = pop()
            elif m in ("sub", "add") and r0 == X.X86_REG_RSP:
                if ops[1].type == X.X86_OP_IMM:
                    n = ops[1].imm // 8
                    if m == "sub":
                        stack.extend([None] * n)
                    else:
                        for _k in range(n):
                            pop()
                else:
                    stack.clear()
            elif m == "lea" and r0 and ops[1].mem.base == X.X86_REG_RIP:
                regval[r0] = nxt + ops[1].mem.disp
                keep = True
            elif m in ("mov", "movabs") and r0 and ops[1].type == X.X86_OP_IMM and                     self.im.image_base <= ops[1].imm < self.im.image_base + len(self.im.mem):
                regval[r0] = ops[1].imm - self.im.image_base
                keep = True
            elif m == "mov" and r0 and ops[1].type == X.X86_OP_MEM and                     ops[1].mem.base == X.X86_REG_RSP and ops[1].mem.index == 0 and                     slot(ops[1].mem.disp) is not None:
                regval[r0] = stack[slot(ops[1].mem.disp)]
                keep = True
            elif m.startswith("cmov") and r0 and ops[1].type == X.X86_OP_REG:
                a_, b_ = regval.get(r0), regval.get(ops[1].reg)
                if isinstance(a_, int) and isinstance(b_, int):
                    regval[r0] = ("cc", m[4:], a_, b_)
                    keep = True
            elif m == "xchg" and is_rsp_mem(ops[0], 0) and ops[1].type == X.X86_OP_REG:
                v = regval.get(ops[1].reg)
                old = stack[-1] if stack else None
                if stack:
                    stack[-1] = v
                else:
                    stack.append(v)
                regval[ops[1].reg] = old
            elif m == "mov" and ops[0].type == X.X86_OP_MEM and ops[0].mem.base == X.X86_REG_RSP                     and ops[0].mem.index == 0 and ops[1].type == X.X86_OP_REG:
                v = regval.get(ops[1].reg)
                if ops[0].mem.disp == -8:
                    prepush[0] = v
                    below = None
                    rows.append((pc, text, "insn", None))
                    pc = nxt
                    continue
                if slot(ops[0].mem.disp) is not None:
                    stack[slot(ops[0].mem.disp)] = v
            if r0 and not keep and m not in ("cmp", "test", "push", "xchg"):
                regval.pop(r0, None)
            prepush[0] = None
            below = below_next
            rows.append((pc, text, "insn", None))
            pc = nxt
        else:
            rows.append((pc, "(stopped after %d steps)" % MAX_STEPS, "end", None))
        return rows


GLUE = re.compile(
    r"lea rsp, \[rsp [-+] 8\]|mov qword ptr \[rsp( [-+] (8|0x10))?\], r\w+$|"
    r"xchg qword ptr \[rsp\], r\w+$|push r\w+$|pop r\w+$|movabs r\w+, 0x1[4-6]\w{7}$|"
    r"lea r\w+, \[rip [-+] 0x\w+\]$|mov r\w+, qword ptr \[rsp( [-+] (8|0x10))?\]$|cmov\w+ r\w+, r\w+$")

GPR = {"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "r8", "r9", "r10",
       "r11", "r12", "r13", "r14", "r15"}


def fold(rows):
    """Collapse the protection's boilerplate. Returns printable lines."""
    out = []
    n = len(rows)
    k = 0

    def txt(j):
        return rows[j][1] if j < n else ""

    while k < n:
        rva, text, kind, extra = rows[k]
        if kind == "flow":
            k += 1
            continue
        # A computed jmp/call/jcc: drop the stack glue that built its target.
        if kind in ("cjmp", "ccall", "cjcc"):
            removed = 0
            while out and removed < 24 and out[-1][2] == "insn" and GLUE.match(out[-1][1]):
                out.pop()
                removed += 1
            out.append((rva, text, kind))
            k += 1
            continue
        # context save
        if text.startswith("push ") and text[5:] in GPR | {"rsp"}:
            j, regs = k, []
            while j < n and (rows[j][2] == "flow" or (txt(j).startswith("push ") and txt(j)[5:] in GPR)
                             or txt(j) == "pushfq"):
                if rows[j][2] != "flow":
                    regs.append(txt(j)[5:] if txt(j) != "pushfq" else "flags")
                j += 1
            xm = 0
            if len(regs) >= 8:
                jj = j
                while jj < n and (rows[jj][2] == "flow" or txt(jj).startswith("lea rsp, [rsp - 0x")
                                  or (txt(jj).startswith("mov") and "xmm" in txt(jj)
                                      and "[rsp" in txt(jj).split(",")[0])):
                    xm += "xmm" in txt(jj)
                    jj += 1
                out.append((rva, "; save context: %d registers%s" % (
                    len(regs), ", %d XMM" % xm if xm else ""), "fold"))
                k = jj
                continue
        # context restore
        if ("xmm" in text and text.startswith("mov") and "[rsp" in text.split(",")[-1]):
            j, xm = k, 0
            while j < n and (rows[j][2] == "flow" or (txt(j).startswith("mov") and "xmm" in txt(j))
                             or txt(j).startswith("lea rsp, [rsp + 0x")):
                xm += "xmm" in txt(j)
                j += 1
            regs = 0
            while j < n and (rows[j][2] == "flow" or txt(j).startswith("pop ") or txt(j) == "popfq"):
                regs += rows[j][2] != "flow"
                j += 1
            if xm >= 8:
                out.append((rva, "; restore context: %d XMM, %d registers" % (xm, regs), "fold"))
                k = j
                continue
        # stack alignment: push 0x10 ; test rsp,0xf ; jne L ; push 0x18 ; L: sub rsp,8
        if text == "push 0x10" and "test rsp, 0xf" in txt(k + 1):
            j = k + 2
            while j < n and (rows[j][2] in ("flow", "jcc") or txt(j) in ("push 0x18", "sub rsp, 8")):
                j += 1
            out.append((rva, "; align stack to 16 (pushes 0x10 or 0x18, then sub rsp,8)", "fold"))
            k = j
            continue
        if text == "add rsp, qword ptr [rsp + 8]":
            out.append((rva, "; undo stack alignment", "fold"))
            k += 1
            continue
        out.append((rva, text, kind))
        k += 1
    return out


def trim(lines, body):
    """Keep everything up to the last protection line, then `body` more."""
    last = max((i for i, l in enumerate(lines) if l[2] == "fold" or "<arxan" in l[1]),
               default=-1)
    if len(lines) > last + 1 + body:
        lines = lines[:last + 1 + body] + [(0, "; ... the original function continues", "fold")]
    return lines


def render(title, start, lines):
    s = ["### %s: `%08X`" % (title, start), "", "```asm"]
    for rva, text, kind in lines:
        if kind == "fold":
            s.append("            %s" % text)
        else:
            s.append("  %08X  %s" % (rva, text))
    s += ["```", ""]
    return "\n".join(s)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("exe", help="executable decrypted by `mwdec decrypt`")
    ap.add_argument("-o", "--out", help="write Markdown here instead of stdout")
    ap.add_argument("--raw", action="store_true", help="do not fold boilerplate")
    ap.add_argument("--body", type=int, default=14,
                    help="instructions of original code to show after the protection's part")
    ap.add_argument("--names", help="JSON object {\"<hex rva>\": \"name\"}")
    ap.add_argument("--at", action="append", default=[],
                    help="extra start RVA (hex) to lay out; may repeat")
    a = ap.parse_args()

    im = Image(a.exe)
    names = {}
    if a.names:
        names = {int(k, 16): v for k, v in json.load(open(a.names)).items()}
    w = Walker(im, names)
    starts = [("TLS callback %d" % i, r) for i, r in enumerate(im.tls_callbacks())]
    starts.append(("Entry point", im.entry_rva))
    starts += [("Path", int(x, 16)) for x in a.at]

    doc = ["# Entry paths of %s" % os.path.basename(a.exe), "",
           "Image base `%X`. Loader order: TLS callbacks first, then the entry point." % im.image_base,
           ""]
    done = set()
    while starts:
        title, start = starts.pop(0)
        if start in done:
            continue
        done.add(start)
        rows = w.walk(start)
        if a.raw:
            lines = [(r, t, k) for r, t, k, _ in rows if k != "flow"]
        else:
            lines = trim(fold(rows), a.body)
        doc.append(render(title, start, lines))
        # A called target that itself opens with a context save is a thunk
        # the protection injected: lay it out too, right after its caller.
        nested = []
        for r, t, k, extra in rows:
            tgt = extra if k == "call" else extra[0] if k == "ccall" else None
            if tgt is None or tgt in done:
                continue
            head = fold(w.walk(tgt))[:1]
            if head and head[0][1].startswith("; save context"):
                nested.append(("Injected thunk (called from %08X)" % r, tgt))
        starts = nested + starts
    text = "\n".join(doc)
    if a.out:
        open(a.out, "w", encoding="utf-8").write(text)
        print("wrote", a.out)
    else:
        sys.stdout.reconfigure(encoding="utf-8")
        print(text)


if __name__ == "__main__":
    main()
