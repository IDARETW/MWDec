"""Rebuild the writer table of a build from its image, without running it.

    py -3 tools\\find_writers.py layer1.exe -o writers.tsv [--check src\\writers_19936.inc]

Input: an image whose bootstrap layer is off (`mwdec decrypt --layer1-only
--keep-strings`). Output: one row per writer, in the order they have to be
applied, for `mwdec decrypt --writers`.

A writer overwrites ranges of the image from an encoded copy it keeps
somewhere else (its stash), with one dword of key and one of four
encodings (src/writers.h). Every writer is an instance of the same
compiled routine, so its code names its three things in fixed ways:

    lea rax, [rip+STASH] ; mov [rbp+68h], rax          the encoded copy
    lea rax, [rip+LIST]  ; mov [rbp+48h], rax          where it goes
    xor eax, [rip+KEY]   ; mov rdx, [rbp+78h] ; mov [rdx], eax      Xor
    add eax, [rip+KEY]   ; mov rdx, [rbp+78h] ; mov [rdx], eax      Sub
    mov eax, [rip+KEY]   ; mov [rbp+8Ch], eax ; lea rax, [rbp+0B0h] XorAuto
    mov eax, [rip+KEY]   ; mov [rbp+88h], eax                       MulRol

The protection cuts that code into pieces joined by jumps, some of them
disguised, so the tool reads instructions as a stream: joining jumps are
followed and disguised ones resolved (devirt_flow.resolve_idiom). The steps:

 1. every range list in the image (find_lists);
 2. every instruction that names a list's first byte (riprefs), kept when
    the stream goes on with the store into the frame;
 3. from there, back along the stream for the stash and forward for the
    key, through conditional branches both ways;
 4. each candidate row is decoded. A writer whose output is code is a
    decryptor. Its twin, which hides the same ranges again, has a stash of
    noise and is dropped. A writer whose ranges cover another writer's
    stash is applied first, and kept when that makes the other one work.
"""
from __future__ import annotations

import argparse
import collections
import os
import re
import struct
import sys
import time
import zlib

import os as _os
_os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")    # numpy's math library reserves 31 MB a core when loaded; nothing here uses it
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, ".."))
import devirt_flow as F  # noqa: E402
import find_bootstrap as fb  # noqa: E402
import find_lists  # noqa: E402
import riprefs  # noqa: E402
from mwdec.pe import Image  # noqa: E402

M = 0xFFFFFFFF
VARIANTS = ("Xor", "Sub", "XorAuto", "MulRol")


# ------------------------------------------------------------ the stream --
class Stream:
    """Instructions in execution order across the protection's pieces."""

    def __init__(self, im: Image):
        self.im = im
        # The protection keeps pieces of its code in the slack at the end of
        # read-only data sections: the tail of .rdata on build 19936, and on
        # 0.01.2 the last page of .pdata, where the set-up of that build's
        # largest writer sits. Nothing is decoded here unless a reference or
        # a jump leads to it, so every read-only section is taken whole.
        ro = [(s.rva, s.rva + min(s.vsize, s.rsize)) for s in im.sections
              if not s.executable and not (s.chars & 0x80000000) and min(s.vsize, s.rsize)]
        self.code = F.Code(im, ro)

    def step(self, pc):
        """One step from pc. Returns (kind, insn, successors):
        kind 'insn': an ordinary instruction, one successor;
             'jmp' : a joining or disguised jump, one successor, no insn;
             'jcc' : a conditional branch (plain or disguised), two successors;
             'call': a call; the successor is the return address;
             'end' : ret, an indirect jump, or something that does not decode."""
        code = self.code
        if not code.in_code(pc):
            return "end", None, []
        try:
            idm = F.resolve_idiom(code, pc, chains=False)
        except Exception:
            idm = None
        if idm is not None:
            if idm.kind == "jmp":
                return "jmp", None, [idm.target]
            if idm.kind == "jcc":
                return "jcc", None, [idm.target, idm.fall]
            if idm.kind == "call":
                return "call", None, [idm.ret]
        i = code.insn(pc)
        if i is None:
            return "end", None, []
        size, m, op = i
        nxt = pc + size
        if m == "jmp":
            if op.startswith("0x"):
                return "jmp", None, [int(op, 16)]
            return "end", (pc, size, m, op), []
        if m in ("ret", "retf", "int3", "ud2", "hlt"):
            return "end", (pc, size, m, op), []
        if m == "call":
            return "call", (pc, size, m, op), [nxt]
        if m[0] == "j" and op.startswith("0x"):
            return "jcc", (pc, size, m, op), [int(op, 16), nxt]
        return "insn", (pc, size, m, op), [nxt]

    def straight(self, pc, n):
        """The next n ordinary instructions on the straight path from pc
        (the instruction at pc included). Stops early at a branch."""
        out = []
        guard = 0
        while len(out) < n and guard < 4 * n + 64:
            guard += 1
            kind, ins, succ = self.step(pc)
            if kind == "insn":
                out.append(ins)
                pc = succ[0]
            elif kind == "jmp":
                pc = succ[0]
            else:
                break
        return out

    def reach(self, start, limit=6000):
        """Every instruction reachable from start within `limit` steps,
        both ways through conditional branches, calls stepped over.
        Yields (pc, size, mnem, op) in breadth-first order."""
        seen = set()
        todo = collections.deque([start])
        n = 0
        while todo and n < limit:
            pc = todo.popleft()
            while pc not in seen and n < limit:
                seen.add(pc)
                n += 1
                kind, ins, succ = self.step(pc)
                if ins is not None and kind in ("insn", "call", "jcc"):
                    yield ins
                if kind in ("insn", "jmp", "call"):
                    pc = succ[0]
                elif kind == "jcc":
                    todo.append(succ[0])
                    pc = succ[1]
                else:
                    break


def rip_target(ins):
    """Target of the RIP-relative operand of (pc, size, mnem, op), or None."""
    pc, size, m, op = ins
    mm = re.search(r"\[rip ([+-]) (0x[0-9a-f]+)\]", op)
    if not mm:
        return None
    d = int(mm.group(2), 16)
    return pc + size + (d if mm.group(1) == "+" else -d)


# -------------------------------------------------------------- decoding --
def decode(e, variant, K):
    """Plaintext words for stash words e (a uint32 array) under key K."""
    if variant == "Xor":
        return e ^ np.uint32(K)
    if variant == "Sub":
        return (np.uint32(K) - e).astype(np.uint32)
    out = np.empty(len(e), dtype=np.uint32)
    ev = e.tolist()
    if variant == "XorAuto":
        k = K
        for i, w in enumerate(ev):
            p = w ^ k
            out[i] = p
            k = (k + p) & M
        return out
    a, b = K, K & 31
    for i, w in enumerate(ev):
        s = b & 31
        if s:
            a = ((a << s) | (a >> (32 - s))) & M
        p = (w - a * b) & M
        out[i] = p
        b = (~p ^ b) & M
    return out


def entropy(b: bytes) -> float:
    if not b:
        return 8.0
    c = np.bincount(np.frombuffer(b, dtype=np.uint8), minlength=256).astype(float)
    p = c[c > 0] / len(b)
    return float(-(p * np.log2(p)).sum())


def common_share(b: bytes) -> float:
    return float(fb.COMMON[np.frombuffer(b, dtype=np.uint8)].mean()) if b else 0.0


# ------------------------------------------------------------- the sites --
def code_arrays(im: Image, st: Stream):
    """(rva, uint8 view) for every executable region."""
    out = []
    for lo, hi in st.code.ex:
        out.append((lo, np.frombuffer(im.mem, dtype=np.uint8, count=hi - lo, offset=lo)))
    return out


def sites_of(arrs, prefix: bytes):
    """Every (rva of the instruction, target of its RIP-relative operand)
    for instructions that are `prefix` followed by a 32-bit displacement."""
    n = len(prefix)
    out_s, out_t = [], []
    for lo, a in arrs:
        if len(a) < n + 4:
            continue
        m = np.ones(len(a) - n - 3, dtype=bool)
        for k, b in enumerate(prefix):
            m &= a[k:len(a) - n - 3 + k] == b
        at = np.nonzero(m)[0]
        d = (a[at + n].astype(np.uint32) | (a[at + n + 1].astype(np.uint32) << 8) |
             (a[at + n + 2].astype(np.uint32) << 16) | (a[at + n + 3].astype(np.uint32) << 24)).view(np.int32)
        out_s.append(at.astype(np.int64) + lo)
        out_t.append(at.astype(np.int64) + lo + n + 4 + d.astype(np.int64))
    return np.concatenate(out_s), np.concatenate(out_t)


FRAME_STORE = re.compile(r"^(?:qword|dword) ptr \[rbp \+ (0x[0-9a-f]+|\d+)\], (rax|eax)$")
FRAME_USE = re.compile(r"dword ptr \[rbp \+ (0x[0-9a-f]+|\d+)\]")


def frame_store(ins):
    """The frame offset D of `mov [rbp+D], rax/eax`, or None."""
    if ins[2] != "mov":
        return None
    m = FRAME_STORE.match(ins[3])
    return int(m.group(1), 0) if m else None


class Finder:
    def __init__(self, path: str, log=print):
        self.log = log
        self.t0 = time.time()
        self.path = path
        self.im = Image(path)
        self.st = Stream(self.im)
        self.arrs = code_arrays(self.im, self.st)
        self.size = self.im.size_of_image
        self.applied = set()

    def say(self, s):
        if os.environ.get("MWDEC_MEM"):        # what the process holds at this point
            import lowmem
            s = "[%d MB held, %d committed] %s" % (lowmem.now_mb() + (s,))
        self.log("[%5.1fs] %s" % (time.time() - self.t0, s))

    # 1. lists
    def lists(self):
        # find_lists reads a file; give it the image as it stands in memory
        # (a later round looks at what the first round's writers uncovered)
        im = self.im

        class Mapped:
            b = np.frombuffer(im.mem, dtype=np.uint8)
            size_of_image = im.size_of_image
            secs = [{"name": s.name, "rva": s.rva, "vsize": s.vsize, "rsize": min(s.vsize, s.rsize) or s.vsize,
                     "raw": s.rva, "exec": s.executable} for s in im.sections]

        found = find_lists.find_lists(Mapped)
        self.list_at = {x["rva"]: x for x in found}
        self.say("range lists: %d" % len(found))

    # 2. writer set-up sites: lea rax,[rip+LIST] ; mov [rbp+D],rax ; mov eax,1 ; test eax,eax
    def setups(self):
        s, t = sites_of(self.arrs, bytes.fromhex("488d05"))
        self.lea_sites = dict(zip(s.tolist(), t.tolist()))
        want = np.array(sorted(self.list_at), dtype=np.int64)
        hit = np.isin(t, want)
        self.setup = {}         # list site -> {list, slot}
        other = collections.Counter()
        for site, lst in zip(s[hit].tolist(), t[hit].tolist()):
            ins = self.st.straight(site, 4)
            if len(ins) == 4 and frame_store(ins[1]) is not None and \
                    ins[2][2:] == ("mov", "eax, 1") and ins[3][2:] == ("test", "eax, eax"):
                self.setup[site] = {"list": lst, "slot": frame_store(ins[1])}
            else:
                other[" ; ".join("%s %s" % i[2:] for i in ins[1:3])] += 1
        self.say("instructions that load a list's address into rax: %d; of them writer set-ups: %d (list slots %s)" % (
            int(hit.sum()), len(self.setup), dict(collections.Counter(hex(v["slot"]) for v in self.setup.values()))))
        self.other_list_users = other

    # 3. the stash: the lea rax,[rip+S] ; mov [rbp+D],rax the stream passes just before the set-up
    def stashes(self):
        st = self.st

        def try_from(a):
            """If a is `lea rax,[rip+S]` + frame store and the straight stream from it reaches a
            set-up site within 32 instructions (18 on build 19936): (that site, S, slot)."""
            ins = st.straight(a, 32)
            if len(ins) < 3 or ins[0][2] != "lea" or not ins[0][3].startswith("rax, [rip") or \
                    frame_store(ins[1]) is None:
                return None
            for k in range(2, len(ins)):
                if ins[k][0] in self.setup:
                    # The stash is the last address put into the frame
                    # before the list's. Starting further back, the stream
                    # passes other `lea rax ; mov [rbp+D],rax` pairs first
                    # (a base pointer in [rbp+48h] on 1.20), and taking the
                    # first of them gave 28 of 82 writers the wrong stash.
                    for i in range(k - 2, -1, -1):
                        if ins[i][2] == "lea" and ins[i][3].startswith("rax, [rip") and \
                                frame_store(ins[i + 1]) is not None:
                            return ins[k][0], rip_target(ins[i]), frame_store(ins[i + 1]), ins[i][0]
                    return None
            return None

        # the usual case: the same piece of code, a fixed distance before
        for site in sorted(self.setup):
            for back in range(0x30, 0x80):
                a = site - back
                if a in self.lea_sites:
                    r = try_from(a)
                    if r and r[0] == site:
                        self.setup[site].update(stash=r[1], stash_slot=r[2], stash_site=r[3])
                        break
        left = [s for s in self.setup if "stash" not in self.setup[s]]
        self.say("stash named a fixed distance before the list: %d; still to find: %d" % (
            len(self.setup) - len(left), len(left)))
        if left:
            # the code was cut between the two: try every lea rax that is followed by a frame store or a jump
            cand = []
            for site, tgt in self.lea_sites.items():
                if not (0 <= tgt < self.size):
                    continue
                nb = bytes(self.im.mem[site + 7:site + 10])
                if nb[:1] == bytes([0xE9]) or nb[:2] == bytes([0x48, 0x89]):
                    cand.append(site)
            self.say("  candidates for a cut set-up: %d" % len(cand))
            leftset = set(left)
            for a in cand:
                r = try_from(a)
                if r and r[0] in leftset and "stash" not in self.setup[r[0]]:
                    self.setup[r[0]].update(stash=r[1], stash_slot=r[2], stash_site=r[3])
            left = [s for s in self.setup if "stash" not in self.setup[s]]
            self.say("  after the wider search, without a stash: %d" % len(left))
        self.no_stash = left
        for s in left:
            del self.setup[s]
        self.say("stash slots: %s" % dict(collections.Counter(hex(w["stash_slot"]) for w in self.setup.values())))

    # 4. the encoding, and the key where the loop names it
    def loops(self):
        st = self.st
        kinds = collections.Counter()
        for site, w in self.setup.items():
            variant = key = slot = None
            seq = []
            for ins in st.reach(site, 900):
                seq.append(ins)
                pc, size, m, op = ins
                if m == "imul":
                    variant = "MulRol"
                    break
                if m in ("xor", "add") and op.startswith("eax, dword ptr [rip"):
                    nx = st.straight(pc, 3)
                    if len(nx) == 3 and nx[1][2] == "mov" and nx[1][3].startswith("rdx, qword ptr [rbp") and \
                            nx[2][2:] == ("mov", "dword ptr [rdx], eax"):
                        variant = "Xor" if m == "xor" else "Sub"
                        key = rip_target(ins)
                        break
                if m == "xor" and op.startswith("eax, dword ptr [rbp"):
                    # MulRol's imul comes before its xor of a frame slot, so this is XorAuto
                    mm = FRAME_USE.search(op)
                    slot = int(mm.group(1), 0) if mm else None
                    variant = "XorAuto"
                    break
            if variant == "MulRol":
                for ins in seq[::-1]:
                    if ins[2] == "rol":
                        mm = FRAME_USE.search(ins[3])
                        slot = int(mm.group(1), 0) if mm else None
                        break
            w.update(variant=variant, key=key, key_slot=slot)
            kinds[variant] += 1
        self.say("encodings read from the loops: %s" % dict(kinds))

    # 5. the key of XorAuto and MulRol: mov eax,[rip+K] ; mov [rbp+slot],eax, before the set-up
    def inits(self):
        st = self.st
        need = {s: w for s, w in self.setup.items() if w["variant"] in ("XorAuto", "MulRol") and w["key"] is None}
        if not need:
            return
        s, t = sites_of(self.arrs, bytes.fromhex("8b05"))
        cand = []
        for site, tgt in zip(s.tolist(), t.tolist()):
            if not (0 <= tgt < self.size - 4):
                continue
            nb = bytes(self.im.mem[site + 6:site + 8])
            if nb[:1] == bytes([0xE9]) or nb == bytes([0x89, 0x85]) or nb == bytes([0x89, 0x45]):
                cand.append((site, tgt))
        self.say("instructions that load a dword into eax and then store or jump: %d" % len(cand))
        # the frame slot the loop keeps its running key in says which store is the key's
        slots = {w["key_slot"] for w in need.values() if w["key_slot"] is not None}
        inits = []
        for site, tgt in cand:
            ins = st.straight(site, 2)
            if len(ins) < 2 or ins[0][2] != "mov" or not ins[0][3].startswith("eax, dword ptr [rip"):
                continue
            d = frame_store(ins[1])
            if d is not None and d in slots and ins[1][3].startswith("dword"):
                inits.append((site, tgt, d))
        self.say("of them stores into a key slot (%s): %d" % (", ".join(hex(s) for s in sorted(slots)), len(inits)))
        linked = 0
        for site, tgt, d in inits:
            for ins in st.reach(site, 500):
                w = need.get(ins[0])
                if w is not None:
                    if w["key_slot"] == d and w["key"] is None:
                        w.update(key=tgt, key_site=site)
                        linked += 1
                    break
        self.say("key set-ups that lead to a writer set-up with that slot: %d of %d wanted" % (linked, len(need)))

    # 6. which rows are decryptors, and in what order
    def judge(self):
        """Decode every row. Sets self.rows: accepted rows in the order to
        apply them, each with `writes_stash`; self.dropped: the rest."""
        # Judged in place. A row that is kept is laid into the image for
        # good, a row that is only tried is laid in and taken out again
        # (leads_to_code), so the image needs no second copy of 500 MB.
        mem = self.im.mem
        rows = []
        for site, w in sorted(self.setup.items()):
            if w.get("key") is None or w.get("variant") is None:
                continue
            lst = self.list_at[w["list"]]["list"]
            n = lst.total()
            if not (0 <= w["stash"] and w["stash"] + n <= self.size and 0 <= w["key"] <= self.size - 4):
                continue
            rows.append(dict(w, site=site, ranges=lst, bytes=n))

        cache = {}
        cached = [0]

        def out_of(r, m, limit=None):
            """What r writes, decoded from the image as m has it; with a
            limit, only that many bytes (judging needs the first 64 KB, and
            every encoding decodes front to back). Remembered by the bytes
            it was decoded from: trials ask the same question many times."""
            n = r["bytes"] if limit is None else min(r["bytes"], limit)
            raw = bytes(m[r["stash"]:r["stash"] + (n + 3) // 4 * 4])
            key = struct.unpack_from("<I", m, r["key"])[0]
            ck = (r["site"], n, key, zlib.crc32(raw))
            hit = cache.get(ck)
            if hit is None:
                hit = decode(np.frombuffer(raw, dtype="<u4"), r["variant"], key).tobytes()[:n]
                if cached[0] > 150_000_000:
                    cache.clear()
                    cached[0] = 0
                cache[ck] = hit
                cached[0] += len(hit)
            return hit

        HEAD = 65536

        MIN = 32      # bytes below which statistics say nothing

        BIG = 4096    # bytes from which entropy says something too

        def kind_of(b: bytes, r=None) -> str:
            """'flat' (one value over and over: an eraser), 'structured'
            (code, tables, text), 'noise', or 'short'. Judged on the first
            64 KB, which is all a short writer has."""
            if len(b) < MIN:
                return "short"
            b = b[:65536]
            if entropy(b) < 1.0:
                return "flat"
            # The share of common code bytes separates cleanly: on build
            # 19936 every decryptor's output has 58% or more, every repair
            # writer's 37% or more, and nothing else above 24%. Entropy does
            # not: a twin may write the code back weakly encoded, which
            # measures well under 8 bits without being code.
            if common_share(b) > 0.35:
                return "structured"
            # Not all code reaches 35%. Build 1.30.0 has a writer for 48,843
            # bytes of functions that do nothing but register strings
            # (`lea rcx, [rip+..] ; call .. ; mov [rip+..], eax`, three
            # displacements to every opcode) and the 51,128 bytes of those
            # strings in .rdata: 34% in the functions and in the strings
            # alike, at 5.96 bits a byte. Noise has 20% and 8.00 bits, and a
            # weakly encoded twin stays under 24%, so on an output large
            # enough for the entropy to mean something the two measures
            # together leave a wide gap.
            if len(b) >= BIG and common_share(b) > 0.28 and entropy(b) < 7.0:
                return "structured"
            return "noise"

        def lay(r, out, m):
            o = 0
            for rva, ln in r["ranges"]:
                m[rva:rva + ln] = out[o:o + ln]
                o += ln

        def now_at(r, m):
            return b"".join(bytes(m[rva:rva + ln]) for rva, ln in r["ranges"])

        def feeds(a, b):
            """Does a's output land on b's stash?"""
            lo, hi = b["stash"], b["stash"] + b["bytes"]
            return a["ranges"].touches(lo, hi)

        # a row kept in an earlier round has done its work
        pending = [r for r in rows if r["site"] not in self.applied]
        accepted = []
        self.repairs, self.erasers, self.short = [], [], []
        progress = True
        while progress:
            progress = False
            # rows whose stash decodes to something structured as the image now stands
            for r in list(pending):
                head = out_of(r, mem, HEAD)
                k = kind_of(head, r)
                if k == "structured":
                    r.update(entropy_out=entropy(head), share_out=common_share(head))
                    pending.remove(r)
                    progress = True
                    out = out_of(r, mem)
                    cur = now_at(r, mem)
                    if out == cur:
                        self.repairs.append(r)      # writes what is there already
                    else:
                        r["changed"] = int((np.frombuffer(out, dtype=np.uint8) !=
                                            np.frombuffer(cur, dtype=np.uint8)).sum())
                        lay(r, out, mem)
                        accepted.append(r)
                elif k == "flat":
                    pending.remove(r)
                    self.erasers.append(r)
                elif k == "short":
                    pending.remove(r)
                    self.short.append(r)
            # a row that decodes to noise may be preparing another row's stash:
            # apply it on a copy and see whether that row then decodes. The
            # row it feeds may itself only prepare a third one, so follow the
            # chain a few levels.
            # Trials are made in place and undone: the image is hundreds of
            # megabytes, a writer's ranges are not.
            def leads_to_code(a, depth, used):
                saved = now_at(a, mem)
                lay(a, out_of(a, mem), mem)
                try:
                    for b in fed.get(a["site"], ()):
                        if b["site"] in used or b["site"] not in live:
                            continue
                        k = kind_of(out_of(b, mem, HEAD), b)
                        if k == "structured":
                            return True
                        if k == "noise" and depth < 4 and leads_to_code(b, depth + 1, used | {b["site"]}):
                            return True
                    return False
                finally:
                    lay(a, saved, mem)

            live = {r["site"] for r in pending}
            fed = {a["site"]: [b for b in pending if b is not a and feeds(a, b)] for a in pending}
            for a in list(pending):
                if not fed[a["site"]]:
                    continue
                if leads_to_code(a, 0, {a["site"]}):
                    lay(a, out_of(a, mem), mem)
                    accepted.append(a)
                    pending.remove(a)
                    progress = True
                    break               # the image changed: judge everything again
        # The rows stay in the order they were laid down: each was decoded
        # from the image as the rows before it had left it, so replaying them
        # in that order gives the same bytes.
        for r in accepted:
            r["writes_stash"] = any(feeds(r, b) for b in accepted if b is not r)
        order = accepted
        self.rows = order
        self.dropped = pending
        self.say("rows judged: %d kept (%d prepare another row's stash); dropped: %d decode to noise, %d write what is "
                 "already there, %d write one value over and over, %d are too short to judge" % (
                     len(order), sum(1 for r in order if r["writes_stash"]), len(pending), len(self.repairs),
                     len(self.erasers), len(self.short)))
        # A decryptor and the writer that hides the same bytes again name the
        # same ranges. Ranges that hold noise at the end, and for which only
        # noise was decoded, have nobody who decrypts them here: what they
        # hold stays as the file has it. (Ranges that are another row's stash
        # hold noise by design, and a row that would write noise over
        # readable bytes hides nothing that is not already in the open.)
        settled = {r["ranges"] for r in accepted} | {r["ranges"] for r in self.repairs} | \
            self.settled_ranges
        self.settled_ranges = settled
        left = {}
        for r in pending:
            left.setdefault(r["ranges"], []).append(r)
        self.unsettled = []
        for k, rs in left.items():
            if k in settled or any(feeds(rs[0], b) for b in rows if b is not rs[0]):
                continue
            if kind_of(now_at(rs[0], mem)[:HEAD]) == "noise":
                self.unsettled.append(rs)
        return mem

    def run(self, max_rounds=8):
        """Rounds: find the writers visible in the image, apply the ones
        that decode, look again. A writer can uncover the code, the list or
        the stash of another."""
        all_rows = []
        self.rounds = []
        self.applied = set()
        self.settled_ranges = set()
        self.unsettled = []
        for n in range(1, max_rounds + 1):
            self.say("round %d" % n)
            self.st = Stream(self.im)           # the image changed: decode afresh
            self.arrs = code_arrays(self.im, self.st)
            self.lists()
            if n == 1:
                self.list_at0 = dict(self.list_at)
            self.setups()
            self.stashes()
            self.loops()
            self.inits()
            mem = self.judge()
            self.rounds.append({"set_ups": len(self.setup), "kept": len(self.rows), "noise": len(self.dropped),
                                "repairs": len(self.repairs), "short": len(self.short)})
            if not self.rows:
                break
            for r in self.rows:
                r["round"] = n
                self.applied.add(r["site"])
            all_rows += self.rows
            self.im.mem[:] = mem
        self.rows = all_rows
        return self.im.mem


def write_table(rows, path, image_name):
    with open(path, "w", newline="\n") as f:
        f.write("# writer table for %s, made by tools/find_writers.py; rows in the order to apply them\n" % image_name)
        f.write("site\twrites_stash\tvariant\tlist\tstash\tkey\tbytes\tranges\tround\n")
        for r in rows:
            f.write("%08X\t%d\t%s\t%08X\t%08X\t%08X\t%d\t%d\t%d\n" % (
                r["site"], int(r["writes_stash"]), r["variant"], r["list"], r["stash"], r["key"], r["bytes"],
                len(r["ranges"]), r.get("round", 1)))


def read_inc(path):
    rows = []
    for ln in open(path):
        m = re.match(r"\{0x([0-9A-F]+), (true|false), WriterVariant::(\w+), 0x([0-9A-F]+), 0x([0-9A-F]+), "
                     r"0x([0-9A-F]+)\}", ln.strip())
        if m:
            rows.append({"routine": int(m[1], 16), "writes_stash": m[2] == "true", "variant": m[3],
                         "list": int(m[4], 16), "stash": int(m[5], 16), "key": int(m[6], 16)})
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("exe", help="image with the bootstrap layer off")
    ap.add_argument("-o", "--out", help="writer table to write (TSV)")
    ap.add_argument("--check", help="a known table (src/writers_NNNNN.inc) to compare with")
    a = ap.parse_args()
    f = Finder(a.exe)
    f.run()
    f.say("sets of ranges that only noise was decoded for: %d (%d bytes)" % (
        len(f.unsettled), sum(rs[0]["bytes"] for rs in f.unsettled)))
    for rs in f.unsettled[:40]:
        r = rs[0]
        secs = collections.Counter()
        for rva, ln in r["ranges"]:
            secs[next((s.name for s in f.im.sections if s.rva <= rva < s.rva + max(s.vsize, s.rsize)), "-")] += ln
        print("  no decryptor: %d bytes in %d ranges, first %08X, by section %s; writers %s" % (
            r["bytes"], len(r["ranges"]), r["ranges"][0][0], dict(secs),
            ", ".join("%08X %s" % (x["site"], x["variant"]) for x in rs)))
    if a.out:
        write_table(f.rows, a.out, os.path.basename(a.exe))
        f.say("wrote %s: %d rows" % (a.out, len(f.rows)))
    if a.check:
        known = read_inc(a.check)
        mine = {r["stash"]: r for r in f.rows}
        same = 0
        for k in known:
            r = mine.get(k["stash"])
            if r is not None and r["variant"] == k["variant"] and r["key"] == k["key"] and \
                    (k["list"] not in f.list_at0 or r["ranges"] == f.list_at0[k["list"]]["list"]):
                same += 1
            else:
                print("  known row not reproduced: stash %08X %s key %08X stash-writer %s; found: %s" % (
                    k["stash"], k["variant"], k["key"], k["writes_stash"],
                    None if r is None else (r["variant"], "%08X" % r["key"], r["writes_stash"])))
        extra = [r for r in f.rows if r["stash"] not in {k["stash"] for k in known}]
        f.say("known rows reproduced: %d of %d; rows found that the known table lacks: %d" % (
            same, len(known), len(extra)))
        for r in extra[:40]:
            print("  extra: site %08X %s list %08X stash %08X key %08X, %d bytes in %d ranges, first %08X, "
                  "entropy %.2f, stash-writer %s" % (r["site"], r["variant"], r["list"], r["stash"], r["key"],
                                                      r["bytes"], len(r["ranges"]), r["ranges"][0][0],
                                                      r.get("entropy_out", 0), r["writes_stash"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
