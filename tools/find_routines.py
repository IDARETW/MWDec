"""The routine table of a build, read from the routines' own code.

    py -3 tools\\find_routines.py decrypted.exe -o routines.json [--check 011_routines.json]

Input: an image with both layers off (`mwdec decrypt`). Nothing is run.

A routine called from game code through a `push R ; push G ; ret` chain
does not come back to the address the calling code pushed. Before it
returns it writes three qwords on its caller's stack: the addresses of two
`ret` gadgets and the address where the game function continues. The
calling code names none of them. The routine does, and always the same way,
because every routine ends in the same compiled epilogue:

    mov rax, [rip+I]         ; a qword: which slot, counted in qwords
    mov rdx, [rbp+D]         ; the caller's frame
    mov rcx, [rip+Q]         ; a qword with a relocation: the address
    mov [rdx+rax*8], rcx

three times, highest slot first. So the three addresses are constants in
the file, and the table that `devirt_flow.py` needs can be read instead of
measured:

 1. every routine-call chain in the image (devirt_flow.census_chains) gives
    a routine entry G and says whether it is called or jumped to;
 2. every instance of the four instructions above gives (slot, address);
 3. the code of each routine is walked from G, through joining and
    disguised jumps and both ways through branches, and the instances it
    reaches are that routine's. A routine has several exit paths; they must
    agree.
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import re
import struct
import sys
import time

import os as _os
_os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")    # numpy's math library reserves 31 MB a core when loaded; nothing here uses it
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, ".."))
import devirt_flow as F  # noqa: E402
import find_writers as FW  # noqa: E402
from mwdec.pe import Image  # noqa: E402


def form_of(chains) -> str:
    """'call' when every chain reaches the routine with a call (it returns
    to its caller: the start-up routines), 'pushret' when it is jumped to
    with a planted return address, 'mixed' otherwise."""
    f = {("call" if c.call_form == "call" else "pushret") for c in chains}
    return f.pop() if len(f) == 1 else "mixed"


# what a routine leaves in registers its chain does not restore. The exit
# code loads rax (slot index), rdx (caller's frame) and rcx (the address).
# The rest of the volatile set is not excluded by anything read here, so a
# fold is planned only where all of them are dead afterwards.
CLOBBERS = ["rax", "rcx", "rdx", "r8", "r9", "r10", "r11"]


def stub_insns(cont_rva, o0, publishes=()):
    """The 53-byte replacement (MWHook d1_stubgen.py, version 2), as
    (kind, bytes | target rva, length). `o0` is the offset of the lowest
    slot from the routine's entry rsp when the alignment step pushed 10h;
    the stub reads the push at run time and adds it.

    `publishes`: (rva, value) of each dword the routine publishes. A guard
    writes its digest when it runs, and code can read the dword before
    that: the replacement stores the value at the same moment
    (`mov dword ptr [rip+P], value`, which changes no register and no flag)."""
    idx = (o0 - 0x18) // 8
    assert (o0 - 0x18) % 8 == 0 and 0 <= idx < 0x80
    out = [("store", (p, v), 10) for p, v in publishes]
    out += [("raw", bytes.fromhex("488D542408"), 5),            # lea rdx, [rsp+8]
           ("raw", bytes.fromhex("488B4208"), 4),               # mov rax, [rdx+8]
           ("raw", bytes.fromhex("48C1E803"), 4),               # shr rax, 3
           ("raw", bytes.fromhex("4883C0") + bytes([idx]), 4)]  # add rax, idx
    for k in (2, 1, 0):
        out.append(("lea", cont_rva[k], 7))                     # lea rcx, [rip+T]
        out.append(("raw", bytes.fromhex("48890CC2"), 4) if k == 0 else
                   ("raw", bytes.fromhex("48894CC2") + struct.pack("<b", 8 * k), 5))
    out.append(("raw", b"\xC3", 1))
    return out


def owned_runs(code, g, max_runs=40, through=False):
    """Runs of straight-line bytes from g, each up to and including its
    joining `jmp rel32`: the routine's own first instructions. A run ends
    at the first branch or call. With `through`, it goes on past a
    conditional branch or a call to the bytes that follow, which are the
    same routine's: used only when the stub does not fit otherwise."""
    runs = []
    x = g
    for _ in range(max_runs):
        start = x
        nxt = None
        while True:
            d = code.insn(x) if code.in_code(x) else None
            if d is None:
                if x > start:
                    runs.append((start, x))
                return runs
            size, m, op = d
            x += size
            if m == "jmp" and op.startswith("0x"):
                nxt = int(op, 16)
                break
            if through and (m == "call" or (m.startswith("j") and m != "jmp")):
                continue
            if m in ("ret", "jmp", "int3", "ud2", "call") or m.startswith("j"):
                break
        runs.append((start, x))
        if nxt is None:
            break
        x = nxt
    return runs


def build_stub(code, g, cont_rva, o0, through=False, publishes=()):
    """{rva: bytes} placing the stub in the routine's own runs, or (None, why)."""
    ins = stub_insns(cont_rva, o0, publishes)
    runs = owned_runs(code, g, through=through)
    patches = {}
    k = 0
    for ri, (lo, hi) in enumerate(runs):
        cap = hi - lo
        buf = bytearray()
        if sum(n for _, _, n in ins[k:]) <= cap:
            take, link = len(ins) - k, False
        else:
            take, room = 0, cap - 5
            while k + take < len(ins) and ins[k + take][2] <= room:
                room -= ins[k + take][2]
                take += 1
            link = True
            if ri + 1 >= len(runs):
                return None, "out of room after %d runs" % len(runs)
        for kind, val, n in ins[k:k + take]:
            if kind == "raw":
                buf += val
            elif kind == "store":
                # mov dword ptr [rip+rel32], imm32
                buf += b"\xC7\x05" + struct.pack("<i", val[0] - (lo + len(buf) + 10)) + struct.pack("<I", val[1])
            else:
                buf += b"\x48\x8D\x0D" + struct.pack("<i", val - (lo + len(buf) + 7))
        k += take
        if link:
            buf += b"\xE9" + struct.pack("<i", runs[ri + 1][0] - (lo + len(buf) + 5))
        patches[lo] = bytes(buf)
        if k >= len(ins) and not link:
            break
    if k < len(ins):
        return None, "did not fit"
    return patches, None


class Finder:
    def __init__(self, path: str, log=print):
        self.log = log
        self.t0 = time.time()
        self.im = Image(path)
        self.st = FW.Stream(self.im)            # every read-only section may hold code
        self.code = self.st.code
        self.base = self.im.image_base
        self.size = self.im.size_of_image
        self.rel = None
        self.published = {}                     # rva of a published dword -> the value its checks need

    def load_checks(self, path):
        """The published dwords and the values the checks need (find_checks.py --json)."""
        d = json.load(open(path))
        for c in d["checks"]:
            self.published[int(c["P"], 16)] = int(c["need"], 16)
        self.say("published dwords: %d" % len(self.published))

    def say(self, s):
        self.log("[%6.1fs] %s" % (time.time() - self.t0, s))

    # 1. the chains
    def chains(self):
        xr = F.RawXrefs(self.im, self.code.extra)
        self.census, self.cfail = F.census_chains(self.im, self.code, xr)
        by = collections.defaultdict(list)
        for site, ch in self.census.items():
            by[ch.G].append(ch)
        self.by_routine = by
        forms = collections.Counter(form_of(c) for c in by.values())
        self.say("chains: %d, at %d long-form sites without one; routines: %d (%s)" % (
            len(self.census), len(self.cfail), len(by), dict(forms)))

    # 2. the slot writes, and which routine reaches which
    STORE2 = re.compile(r"^qword ptr \[(\w+) \+ (\w+)\*8(?: \+ (?:0x[0-9a-f]+|\d+))?\], (\w+)$")

    def slot_write(self, window):
        """If the last instruction of `window` (instructions in stream
        order) is a routine's slot store, (index constant, address, shape).

        The store is `mov [base + R*8 (+ d)], V`. Just before it V was
        loaded from a qword of the image that holds an address in the image,
        and R was loaded from, or had added to it, a qword that holds a
        small number. Which registers, and whether the base is the routine's
        own frame or a pointer into the caller's, differs between builds and
        between the kinds of routine in one build:

            mov rax,[rip+I] ; mov rdx,[rbp+D] ; mov rcx,[rip+Q] ; mov [rdx+rax*8],rcx        19936
            mov rax,[rbp+D] ; add rax,[rip+I] ; mov rdx,[rip+Q] ; mov [rbp+rax*8+d],rdx      1.20
            mov rax,[rip+Q] ; mov rdx,[rbp+D] ; add rdx,[rip+I] ; mov [rbp+rdx*8+d],rax      1.20
        """
        pc, size, m, op = window[-1]
        if m != "mov":
            return None
        mt = self.STORE2.match(op)
        if not mt:
            return None
        base, idx_reg, val_reg = mt.group(1), mt.group(2), mt.group(3)
        mem = self.im.mem
        q = i = None
        shape = []
        for ins in reversed(window[-5:-1]):
            _, _, m2, op2 = ins
            if q is None and m2 == "mov" and op2.startswith(val_reg + ", qword ptr [rip"):
                q = FW.rip_target(ins)
                shape.append("value")
            elif i is None and m2 in ("mov", "add") and op2.startswith(idx_reg + ", qword ptr [rip"):
                i = FW.rip_target(ins)
                shape.append("index " + m2)
        if q is None or i is None or not (0 <= q <= self.size - 8) or not (0 <= i <= self.size - 8):
            return None
        index = struct.unpack_from("<Q", mem, i)[0]
        val = struct.unpack_from("<Q", mem, q)[0]
        if index >= 0x200 or not (self.base <= val < self.base + self.size):
            return None
        return index, val - self.base, "[%s+%s*8] <- %s; %s" % (base, idx_reg, val_reg, ", ".join(reversed(shape)))

    def walk(self, limit=400000):
        """Every routine's code from its entry: joining and disguised jumps
        followed, both ways through branches, calls stepped over. The slot
        stores met on the way are the routine's."""
        out = {}
        st = self.st
        steps = 0
        shapes = collections.Counter()
        for g, chs in sorted(self.by_routine.items()):
            got = collections.defaultdict(set)      # index constant -> addresses
            sites = []
            pubs = {}                               # published dword -> the store's address
            seen = set()
            todo = collections.deque([g])
            n = 0
            while todo and n < limit:
                pc = todo.popleft()
                window = []
                while pc not in seen and n < limit:
                    seen.add(pc)
                    n += 1
                    kind, ins, succ = st.step(pc)
                    if kind == "insn":
                        window.append(ins)
                        if len(window) > 6:
                            del window[0]
                        r = self.slot_write(window)
                        if r is not None:
                            got[r[0]].add(r[1])
                            sites.append(ins[0])
                            shapes[r[2]] += 1
                        if self.published and ins[2] == "mov" and ins[3].startswith("dword ptr [rip"):
                            # the guard's publish: `mov [rip+P], r32`
                            t = FW.rip_target(ins)
                            if t in self.published:
                                pubs.setdefault(t, ins[0])
                        pc = succ[0]
                    elif kind in ("jmp", "call"):
                        if kind == "call":
                            window = []
                        pc = succ[0]
                    elif kind == "jcc":
                        todo.append(succ[0])
                        window = []
                        pc = succ[1]
                    else:
                        break
            steps += n
            out[g] = {"form": form_of(chs), "got": got, "sites": sites, "steps": n,
                      "chains": [c.S for c in chs], "returns": [c.R for c in chs],
                      "push": sorted({len(c.push_order) for c in chs}), "pubs": pubs}
        self.routines = out
        self.shapes = shapes
        self.say("walked %d routines, %d instructions; slot stores met: %d" % (len(out), steps, sum(shapes.values())))
        if self.published:
            by = collections.defaultdict(list)
            for g, r in out.items():
                for p in r["pubs"]:
                    by[p].append(g)
            forms = collections.Counter()
            for p in self.published:
                fs = {out[g]["form"] for g in by.get(p, [])}
                forms["no routine stores it" if not fs else "/".join(sorted(fs))] += 1
            self.pub_by = by
            self.say("published dwords by who stores them: %s; routines that publish: %d" % (
                dict(forms), sum(1 for r in out.values() if r["pubs"])))
        for k, v in shapes.most_common():
            self.say("   %5d  %s" % (v, k))

    def table(self):
        """{G: record} in the form devirt_flow.RoutineModel reads."""
        tab = {}
        kinds = collections.Counter()
        for g, r in self.routines.items():
            got = r["got"]
            idxs = sorted(got)
            one = all(len(v) == 1 for v in got.values())
            e = {"form": r["form"], "class": None, "chains": ["%08X" % s for s in r["chains"]],
                 "returns": ["%08X" % x for x in r["returns"]],     # one per chain, same order
                 "exit_sites": len(r["sites"]), "instructions_walked": r["steps"]}
            if r.get("pubs"):
                # [dword, value, address of the store]. A routine that is
                # called and returns (the start-up) has published before
                # anything else runs: those values are baked into the image.
                # A guard publishes when its construct runs: its replacement
                # stores the value, and devirt_flow leaves the construct.
                e["publishes" if r["form"] == "pushret" else "publishes_at_start"] = [
                    ["0x%x" % p, "0x%08x" % self.published[p], "0x%x" % at] for p, at in sorted(r["pubs"].items())]
            if len(idxs) == 3 and idxs[1] == idxs[0] + 1 and idxs[2] == idxs[0] + 2 and one \
                    and r["form"] == "pushret":
                t = [next(iter(got[i])) for i in idxs]
                e["cont_rva"] = ["0x%x" % x for x in t]
                e["index_constant"] = idxs[0]
                # Where the slots are: just above the chain's register save,
                # 118h + 8 x (registers the chain pushed) from the routine's
                # entry rsp when the alignment step pushed 10h. The routine's
                # own index constant has to agree with that count, up to a
                # constant that depends only on how the build spells the
                # store (checked over all routines in check_offsets).
                if len(r["push"]) == 1:
                    o0 = 0x118 + 8 * r["push"][0]
                    e["slot_offset"] = o0
                    # what devirt_flow reads: (offset, address) x 3
                    e["cont"] = [[o0 + 8 * k, "0x%x" % (self.base + t[k])] for k in range(3)]
                    e["clobbers"] = CLOBBERS
                    kinds["three slots"] += 1
                else:
                    e["why"] = "its chains save different numbers of registers: %s" % r["push"]
                    kinds["three slots, chains disagree"] += 1
            elif not idxs:
                kinds["no slot write reached (%s)" % r["form"]] += 1
            else:
                e["ambiguous"] = {str(i): ["0x%x" % t for t in sorted(v)] for i, v in got.items()}
                kinds["ambiguous (%s)" % r["form"]] += 1
            tab["0x%x" % g] = e
        self.kinds = kinds
        # the index constant against the chain's push count: one difference
        # for the whole build, or the two readings do not describe the same slots
        rel = collections.Counter(e["index_constant"] - e["slot_offset"] // 8 for e in tab.values()
                                  if "slot_offset" in e)
        self.index_relation = dict(rel)
        if len(rel) > 1:
            common = rel.most_common(1)[0][0]
            for k, e in tab.items():
                if "slot_offset" in e and e["index_constant"] - e["slot_offset"] // 8 != common:
                    e["why"] = "index constant %d does not fit the chain's %d saved registers" % (
                        e["index_constant"], (e["slot_offset"] - 0x118) // 8)
                    for f in ("cont", "clobbers"):
                        e.pop(f, None)
                    kinds["three slots"] -= 1
                    kinds["index and chain disagree"] += 1
        return tab

    def stub_plan(self, tab):
        """A `ret` at every routine that is called and returns, the 53-byte
        replacement at every routine with three slots."""
        import planfile
        plan = planfile.Plan()
        n_ret = n_stub = 0
        fail = []
        claimed = {}
        for k, e in sorted(tab.items(), key=lambda kv: int(kv[0], 16)):
            g = int(k, 16)
            if e["form"] == "call" and "ambiguous" not in e:
                plan.patch(g, b"\xC3", planfile.KIND_STUB)
                n_ret += 1
            elif "cont" in e:
                pubs = [(int(x[0], 16), int(x[1], 16)) for x in e.get("publishes", [])]
                p, why = build_stub(self.code, g, [int(x, 16) for x in e["cont_rva"]], e["slot_offset"],
                                    publishes=pubs)
                if p is None:
                    p, why = build_stub(self.code, g, [int(x, 16) for x in e["cont_rva"]], e["slot_offset"],
                                        through=True, publishes=pubs)
                    if p is not None:
                        e["stub_note"] = "placed past the routine's first branch"
                if p is not None:
                    # two routines must not be given the same bytes
                    hit = next((claimed[b] for rva, data in p.items() for b in range(rva, rva + len(data))
                                if b in claimed), None)
                    if hit is not None:
                        p, why = None, "its first instructions are also routine %s's" % hit
                if p is None:
                    fail.append((k, why))
                    e["why"] = "no room for the replacement: " + why
                    for f_ in ("cont", "clobbers", "publishes"):
                        e.pop(f_, None)
                    continue
                for rva, data in sorted(p.items()):
                    plan.patch(rva, data, planfile.KIND_STUB)
                    for b in range(rva, rva + len(data)):
                        claimed[b] = k
                n_stub += 1
        self.say("stubs: %d `ret`, %d replacements in %d pieces; %d did not fit %s" % (
            n_ret, n_stub, len(plan.patches) - n_ret, len(fail), fail[:4]))
        return plan


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("exe")
    ap.add_argument("-o", "--out")
    ap.add_argument("--stubs-out", help="plan with the replacement of every routine (for devirt_flow --stub-plan)")
    ap.add_argument("--compare-stubs", action="append", default=[],
                    help="stub plans to compare the replacements with (later ones win, as in an export)")
    ap.add_argument("--limit", type=int, default=400000, help="instructions to walk per routine at most")
    ap.add_argument("--check", help="a measured table (011_routines.json) to compare with")
    ap.add_argument("--checks", help="find_checks.py --json: the published dwords; each routine's publishes are then "
                                     "recorded, and its replacement stores them")
    ap.add_argument("--bake-out", help="plan with the published values that hold from the start: those the start-up "
                                       "routines store and those no routine was seen to store (for devirt_flow "
                                       "--keep-plan, in place of find_checks.py's plan)")
    a = ap.parse_args()
    f = Finder(a.exe)
    if a.checks:
        f.load_checks(a.checks)
    f.chains()
    f.walk(a.limit)
    tab = f.table()
    if a.bake_out:
        import planfile
        guards = {int(x[0], 16) for e in tab.values() for x in e.get("publishes", [])}
        bake = planfile.Plan()
        for p, need in sorted(f.published.items()):
            if p not in guards:
                bake.patch(p, struct.pack("<I", need), planfile.KIND_BAKE)
        bake.save(a.bake_out)
        f.say("values that hold from the start: %d of %d published dwords baked (%s); %d are stored by guards when they run" % (
            len(bake.patches), len(f.published), a.bake_out, len(guards)))
    f.say("routines: %s" % dict(f.kinds))
    f.say("index constant minus slot offset in qwords, over the routines: %s" % f.index_relation)
    # the stubs first: a routine whose replacement cannot be placed loses
    # its entry in the table (it then stays as shipped, with its construct)
    sp = f.stub_plan(tab)
    if a.out:
        with open(a.out, "w") as fh:
            json.dump({"meta": {"image": os.path.basename(a.exe), "made_by": "tools/find_routines.py",
                                "addresses": "RVA", "slot_stores": dict(f.shapes),
                                "index_minus_offset": f.index_relation,
                                "kinds": dict(f.kinds)}, "routines": tab}, fh, indent=1)
        f.say("wrote %s" % a.out)
    if a.stubs_out:
        sp.save(a.stubs_out)
        f.say("wrote %s" % a.stubs_out)
        if a.compare_stubs:
            import planfile
            mine = {rva: data for rva, kind, data in sp.patches}
            other = {}
            for p in a.compare_stubs:
                for rva, kind, data in planfile.Plan.load(p).patches:
                    if kind == planfile.KIND_STUB:
                        other[rva] = data
            same = sum(1 for r in mine if other.get(r) == mine[r])
            f.say("stub pieces against %s: %d equal, %d at the same place with other bytes, %d of mine it lacks, "
                  "%d of its I lack" % ([os.path.basename(p) for p in a.compare_stubs], same,
                                        sum(1 for r in mine if r in other and other[r] != mine[r]),
                                        sum(1 for r in mine if r not in other), sum(1 for r in other if r not in mine)))
    if a.check:
        known = json.load(open(a.check))["routines"]
        base = f.base
        same = diff = missing = extra = 0
        shown = 0
        for k, v in known.items():
            stub = v.get("stub") or {}
            c = stub.get("cont") if stub.get("stub") == "continuation" else None
            if not c or len(c) != 3:
                continue
            want = ["0x%x" % (int(t, 16) - base) for _, t in c]
            mine = tab.get(k)
            if mine is None:
                missing += 1
                if shown < 12:
                    shown += 1
                    print("   measured routine %s is in no chain found" % k)
            elif mine.get("cont_rva") == want:
                same += 1
                if mine.get("slot_offset") != c[0][0] and shown < 12:
                    shown += 1
                    print("   %s: slot offset %s from the chain, measured %d" % (k, mine.get("slot_offset"), c[0][0]))
            else:
                diff += 1
                if shown < 12:
                    shown += 1
                    print("   %s: measured %s, read %s %s" % (k, want, mine.get("cont_rva"), mine.get("ambiguous", "")))
        for k, v in tab.items():
            if "cont_rva" in v and k not in known:
                extra += 1
        f.say("against the measured table: %d equal, %d different, %d measured routines not found, "
              "%d read that the table lacks" % (same, diff, missing, extra))
    return 0


if __name__ == "__main__":
    sys.exit(main())
