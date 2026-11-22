"""Find the bootstrap layer's three parameters in a shipped executable,
without running or emulating anything.

    py -3 tools\\find_bootstrap.py modernwarfare.exe [--rounds N] [--json out.json]

Prints `--bootstrap KEY,IV,RANGES,ROUNDS` for `mwdec`.

How:

1. The range list. The bootstrap cipher steps around every relocated
   qword, so between two relocation sites that are close together the list
   must hold `gap 8, length (distance - 8)`. A run of such pairs, taken
   from the file's own relocation table and encoded as LEB128, is searched
   for in the file. The list's beginning is then the place before the match
   from which decoding arrives at the match with the right cursor and runs
   on to the terminator (a gap that takes the 32-bit cursor to 0xFFFFFFFF).

2. The key and the starting block. Both have to be readable before
   anything is decrypted, so the cipher skips them, and no relocation
   explains the skip. In the protection's section the list leaves about a
   thousand such islands, and only a handful are exactly 16 or exactly 8
   bytes long. Every (16-byte island, 8-byte island) pair is tried as (key,
   starting block): the first 512 bytes of the stream are deciphered and
   the share of bytes that are common in compiled code is counted. Noise
   gives about one in five. The right pair gives more than half.
"""
import argparse
import json
import struct
import sys
import time

import os as _os
_os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")    # numpy's math library reserves 31 MB a core when loaded; nothing here uses it
import numpy as np

MASK = 0xFFFFFFFF
DELTA = 0x9E3779B9


class PE:
    def __init__(self, path):
        self.b = np.fromfile(path, dtype=np.uint8)
        raw = self.b[:0x1000].tobytes()
        pe = struct.unpack_from("<I", raw, 0x3C)[0]
        n = struct.unpack_from("<H", raw, pe + 6)[0]
        opt = struct.unpack_from("<H", raw, pe + 20)[0]
        self.timestamp = struct.unpack_from("<I", raw, pe + 8)[0]
        self.base = struct.unpack_from("<Q", raw, pe + 24 + 24)[0]
        self.size_of_image = struct.unpack_from("<I", raw, pe + 24 + 56)[0]
        self.entry = struct.unpack_from("<I", raw, pe + 24 + 16)[0]
        self.dirs = [struct.unpack_from("<II", raw, pe + 24 + 112 + 8 * i) for i in range(16)]
        o = pe + 24 + opt
        self.secs = []
        for i in range(n):
            h = raw[o + 40 * i:o + 40 * i + 40]
            vs, va, rs, ro = struct.unpack_from("<IIII", h, 8)
            ch = struct.unpack_from("<I", h, 36)[0]
            self.secs.append({"name": h[:8].rstrip(b"\0").decode("latin1"), "rva": va, "vsize": vs, "rsize": rs,
                              "raw": ro, "exec": bool(ch & 0x20000000)})

    def off(self, rva):
        for s in self.secs:
            if s["rva"] <= rva < s["rva"] + min(s["vsize"], s["rsize"]):
                return s["raw"] + rva - s["rva"]
        return None

    def rva_of(self, off):
        for s in self.secs:
            if s["raw"] <= off < s["raw"] + s["rsize"]:
                return s["rva"] + off - s["raw"]
        return None

    def relocs(self):
        """RVAs of every DIR64 relocation, sorted."""
        rva, size = self.dirs[5]
        o = self.off(rva)
        raw = self.b[o:o + size].tobytes()
        out = []
        i = 0
        while i + 8 <= len(raw):
            page, blk = struct.unpack_from("<II", raw, i)
            if blk < 8:
                break
            ents = np.frombuffer(raw, dtype="<u2", count=(blk - 8) // 2, offset=i + 8)
            out.append(page + (ents[(ents >> 12) == 10] & 0xFFF).astype(np.int64))
            i += blk
        return np.sort(np.concatenate(out))


def uleb(v):
    out = bytearray()
    while True:
        c = v & 0x7F
        v >>= 7
        if v:
            out.append(c | 0x80)
        else:
            out.append(c)
            return bytes(out)


def decode(p, i=0, cursor=0, limit=None):
    """Decode a range list from p[i:]. Returns (ranges as an int64 array of
    (rva, length), index after the terminator) or None if it does not end
    in a terminator."""
    out = []
    n = len(p)
    while True:
        v = 0
        sh = 0
        while True:
            if i >= n:
                return None
            c = p[i]
            i += 1
            v |= (c & 0x7F) << sh
            sh += 7
            if not c & 0x80:
                break
            if sh > 35:
                return None
        cursor += v
        if cursor == 0xFFFFFFFF:
            return np.array(out, dtype=np.int64).reshape(-1, 2), i
        if cursor > 0xFFFFFFFF:
            return None
        v = 0
        sh = 0
        while True:
            if i >= n:
                return None
            c = p[i]
            i += 1
            v |= (c & 0x7F) << sh
            sh += 7
            if not c & 0x80:
                break
            if sh > 35:
                return None
        out.append((cursor, v))
        cursor += v
        if limit is not None and len(out) > limit:
            return None


def find_list(pe, log):
    rel = pe.relocs()
    code = [s for s in pe.secs if s["exec"]]
    data = pe.b.tobytes()
    hit = None
    # the section with the most relocations first: its needles are the
    # likeliest to exist
    code.sort(key=lambda s: -int(((rel >= s["rva"]) & (rel < s["rva"] + s["vsize"])).sum()))
    for sec in code:
        r = rel[(rel >= sec["rva"]) & (rel < sec["rva"] + sec["vsize"])]
        d = np.diff(r)
        # stretches of 6 relocations, each 9..120 bytes after the one
        # before: nothing but relocations interrupts the cipher there
        ok = (d > 8) & (d < 128)
        run = np.convolve(ok.astype(np.int32), np.ones(6, dtype=np.int32), "valid") == 6
        starts = np.nonzero(run)[0]
        found = dup = 0
        for k in starts[::max(1, len(starts) // 400)]:
            needle = b"".join(uleb(8) + uleb(int(d[k + j]) - 8) for j in range(6))
            at = data.find(needle)
            if at < 0:
                continue
            found += 1
            if data.find(needle, at + 1) >= 0:
                dup += 1
                continue                # not unique: take another stretch
            hit = (at, int(r[k]))
            break
        log("%s at %#x: %d relocations, %d candidate stretches, %d needles found (%d not unique)" % (
            sec["name"], sec["rva"], len(r), len(starts), found, dup))
        if hit:
            break
    if hit is None:
        return None
    at, r0 = hit
    log("needle for the relocations after RVA %#x found at file offset %#x (RVA %#x)" % (r0, at, pe.rva_of(at)))
    # The needle begins with the gap over the relocation at r0, so the
    # cursor there is r0. LEB128 can be read backwards (a value ends at a
    # byte with the top bit clear and owns the top-bit-set bytes before
    # it), so walk back value by value, length then gap, taking each off
    # the cursor. The list begins where the cursor is back at 0.
    p = at
    cursor = r0
    want_len = True
    values = 0
    while cursor > 0:
        if not want_len:
            # the list's first value is a gap equal to the whole cursor,
            # and whatever lies before the list may end in bytes with the
            # top bit set, which the backward rule would take for part of it
            first = uleb(cursor)
            if data[p - len(first):p] == first:
                p -= len(first)
                cursor = 0
                want_len = True
                break
        e = p - 1                       # last byte of the value before p
        if e < 0 or data[e] & 0x80:
            return None
        s = e
        while s > 0 and data[s - 1] & 0x80 and e - s < 5:
            s -= 1
        v = 0
        for k in range(e, s - 1, -1):
            v = (v << 7) | (data[k] & 0x7F)
        cursor -= v
        p = s
        want_len = not want_len
        values += 1
    if cursor != 0 or not want_len:
        # ended on a length, or overshot: not a list that starts at RVA 0
        return None
    res = decode(data, p)
    if res is None:
        return None
    ranges, end = res
    log("list begins at file offset %#x (RVA %#x): %d ranges, %d bytes, %d encoded" % (
        p, pe.rva_of(p), len(ranges), int(ranges[:, 1].sum()), end - p))
    return p, ranges, end - p


def islands(pe, ranges, rel, sec):
    """Runs of bytes in a section that the cipher skips and no relocation
    explains: [(rva, length)]."""
    lo, n = sec["rva"], min(sec["vsize"], sec["rsize"])
    d = np.zeros(n + 1, dtype=np.int32)
    r = ranges[(ranges[:, 0] + ranges[:, 1] > lo) & (ranges[:, 0] < lo + n)]
    a = np.clip(r[:, 0] - lo, 0, n)
    b = np.clip(r[:, 0] + r[:, 1] - lo, 0, n)
    np.add.at(d, a, 1)
    np.add.at(d, b, -1)
    q = rel[(rel >= lo) & (rel + 8 <= lo + n)] - lo
    np.add.at(d, q, 1)
    np.add.at(d, q + 8, -1)
    free = np.cumsum(d[:-1]) == 0
    e = np.diff(np.concatenate(([0], free.astype(np.int8), [0])))
    s = np.nonzero(e == 1)[0]
    t = np.nonzero(e == -1)[0]
    return [(int(lo + x), int(y - x)) for x, y in zip(s, t)]


def xtea_enc(v0, v1, key, rounds):
    """Vectorised over keys: key is (n, 4) uint32, v0/v1 scalars or arrays."""
    a = np.full(key.shape[0], v0, dtype=np.uint32) if np.isscalar(v0) else v0.copy()
    b = np.full(key.shape[0], v1, dtype=np.uint32) if np.isscalar(v1) else v1.copy()
    s = 0
    rows = np.arange(key.shape[0])
    for _ in range(rounds):
        a += (((b << np.uint32(4)) ^ (b >> np.uint32(5))) + b) ^ (np.uint32(s) + key[:, s & 3])
        s = (s + DELTA) & MASK
        b += (((a << np.uint32(4)) ^ (a >> np.uint32(5))) + a) ^ (np.uint32(s) + key[:, (s >> 11) & 3])
    return a, b


# Bytes that make up most of compiled x64 code: REX prefixes, mov / lea /
# call / jmp opcodes, common ModRM and SIB bytes, small displacements,
# padding. A block of noise holds about one in six of them.
COMMON = np.zeros(256, dtype=bool)
COMMON[list(bytes.fromhex("00 01 02 04 08 0f 10 18 20 24 28 30 33 38 3b 40 41 44 45 48 49 4c 4d 54 5c 66 74 75 83 84 85 "
                          "89 8b 8d 90 c0 c1 c3 c7 c8 c9 cc d0 d2 e8 e9 eb f8 fe ff"))] = True


def stream_head(pe, ranges, n):
    """The first n bytes the keystream is applied to, in keystream order."""
    out = bytearray()
    for rva, ln in ranges:
        o = pe.off(int(rva))
        out += pe.b[o:o + int(ln)].tobytes()
        if len(out) >= n:
            break
    return bytes(out[:n])


def search_pairs(head, keys, ivs, rounds, log, chunk=1 << 22):
    """Every (key, starting block) pair: decipher the first block of the
    stream and keep the pairs whose 8 plaintext bytes are all common code
    bytes. keys: (nk, 4) uint32; ivs: (ni, 2) uint32. Returns a list of
    (key index, iv index)."""
    c0, c1 = struct.unpack_from("<II", head, 0)
    nk, ni = len(keys), len(ivs)
    per = max(1, chunk // max(1, ni))
    out = []
    for k0 in range(0, nk, per):
        kk = keys[k0:k0 + per]
        K = np.repeat(kk, ni, axis=0)
        v0 = np.tile(ivs[:, 0], len(kk))
        v1 = np.tile(ivs[:, 1], len(kk))
        a, b = xtea_enc(v0, v1, K, rounds)
        p = np.stack([a ^ np.uint32(c0), b ^ np.uint32(c1)], axis=1).view(np.uint8).reshape(-1, 8)
        good = COMMON[p].sum(axis=1) == 8
        for j in np.nonzero(good)[0]:
            out.append((k0 + int(j) // ni, int(j) % ni))
    return out


def confirm(head, key, iv, rounds):
    """Fraction of common code bytes in the first len(head) plaintext bytes."""
    v0, v1 = iv
    ks = bytearray()
    while len(ks) < len(head):
        v0, v1 = enc1(v0, v1, key, rounds)
        ks += struct.pack("<II", v0, v1)
    p = np.frombuffer(bytes(x ^ y for x, y in zip(head, ks)), dtype=np.uint8)
    return float(COMMON[p].mean())


def enc1(v0, v1, k, rounds):
    s = 0
    for _ in range(rounds):
        v0 = (v0 + ((((v1 << 4) ^ (v1 >> 5)) + v1 & MASK) ^ (s + k[s & 3] & MASK))) & MASK
        s = (s + DELTA) & MASK
        v1 = (v1 + ((((v0 << 4) ^ (v0 >> 5)) + v0 & MASK) ^ (s + k[(s >> 11) & 3] & MASK))) & MASK
    return v0, v1


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("exe")
    ap.add_argument("--rounds", type=int, action="append",
                    help="XTEA cycles to try (two Feistel rounds each); default 64, then 32")
    ap.add_argument("--json")
    ap.add_argument("--list-only", action="store_true")
    ap.add_argument("--islands", action="store_true",
                    help="also run the search by position (islands) when the set-up code already gave the answer")
    ap.add_argument("--widest", type=int, default=64,
                    help="when no island has exactly the size of a key or a starting block, try every "
                         "window of islands up to this many bytes")
    ap.add_argument("--where", action="append", type=lambda s: int(s, 16), default=[],
                    help="report which island holds this RVA (to check a known key or starting block)")
    a = ap.parse_args()
    t0 = time.time()

    def log(s):
        print("[%5.1fs] %s" % (time.time() - t0, s), flush=True)

    pe = PE(a.exe)
    for s in pe.secs:
        log("%-8s rva %08X vsize %08X %s" % (s["name"], s["rva"], s["vsize"], "x" if s["exec"] else ""))
    res = find_list(pe, log)
    if res is None:
        log("no range list found")
        return 1
    lp, ranges, enc = res
    out = {"ranges_rva": pe.rva_of(lp), "ranges": int(len(ranges)), "bytes": int(ranges[:, 1].sum()), "encoded": enc}
    rel = pe.relocs()
    prot = [s for s in pe.secs if s["exec"]][-1]
    isl = islands(pe, ranges, rel, prot)
    import collections
    hist = collections.Counter(n for _, n in isl)
    log("islands in %s at %#x: %d, %d bytes; lengths (most common): %s" % (
        prot["name"], prot["rva"], len(isl), sum(n for _, n in isl), hist.most_common(12)))
    log("islands of 8 bytes: %d; of 16 bytes: %d; largest: %s" % (
        hist.get(8, 0), hist.get(16, 0), ["%#x+%d" % x for x in sorted(isl, key=lambda x: -x[1])[:6]]))
    out["islands"] = len(isl)
    if a.where:
        for w in a.where:
            hit = [x for x in isl if x[0] <= w < x[0] + x[1]]
            log("RVA %#x is in island %s" % (w, ["%#x+%d" % x for x in hit]))
    if a.list_only:
        print(json.dumps(out))
        return 0
    # The cipher's own set-up code names the key and the starting block, and
    # it is plain compiled code in every build looked at:
    #     mov dword ptr [rbp+10h], CYCLES ; mov dword ptr [rbp+14h], 9E3779B9h
    #     lea rax, [rip+KEY] ; mov [rbp], rax ; lea rax, [rip+BLOCK] ; mov [rbp+8], rax
    head = stream_head(pe, ranges, 512)
    data = pe.b.tobytes()
    at = data.find(bytes.fromhex("c74514b979379e"))
    while at >= 0:
        s = data[at - 7:at + 29]
        if s[:3] == bytes.fromhex("c74510") and s[14:17] == bytes.fromhex("488d05") and \
                s[21:25] == bytes.fromhex("48894500") and s[25:28] == bytes.fromhex("488d05") and \
                data[at + 25:at + 29] == bytes.fromhex("48894508"):
            cycles = struct.unpack_from("<I", s, 3)[0]
            site = pe.rva_of(at)
            key = site + 7 + 7 + struct.unpack_from("<i", s, 17)[0]
            blk = site + 7 + 11 + 7 + struct.unpack_from("<i", s, 28)[0]
            log("cipher set-up at %#x: %d cycles, key @ %#x, starting block @ %#x" % (site, cycles, key, blk))
            if pe.off(key) is not None and pe.off(blk) is not None:
                kw = [int(x) for x in np.frombuffer(pe.b[pe.off(key):pe.off(key) + 16].tobytes(), dtype="<u4")]
                vw = [int(x) for x in np.frombuffer(pe.b[pe.off(blk):pe.off(blk) + 8].tobytes(), dtype="<u4")]
                frac = confirm(head, kw, (vw[0], vw[1]), cycles)
                log("  common code bytes in the first %d with those: %.1f%%" % (len(head), 100 * frac))
                if frac > 0.45:
                    out.update(key_rva=key, iv_rva=blk, rounds=cycles, score=frac, from_code=True)
                    print("--bootstrap 0x%X,0x%X,0x%X,%d" % (key, blk, out["ranges_rva"], cycles))
                    if a.json:
                        json.dump(out, open(a.json, "w"), indent=1)
                    if not a.islands:
                        return 0
        at = data.find(bytes.fromhex("c74514b979379e"), at + 1)
    # key and starting block by position: small islands, tried as pairs
    def cands(size, widest):
        c = [r for r, n in isl if n == size]
        if not c:
            c = [r + k for r, n in isl if size < n <= widest for k in range(n - size + 1)]
        return c
    kc = cands(16, a.widest)
    ic = cands(8, a.widest)
    log("key candidates: %d; starting-block candidates: %d; pairs: %d" % (len(kc), len(ic), len(kc) * len(ic)))
    keys = np.array([np.frombuffer(pe.b[pe.off(r):pe.off(r) + 16].tobytes(), dtype="<u4") for r in kc], dtype=np.uint32)
    ivs = np.array([np.frombuffer(pe.b[pe.off(r):pe.off(r) + 8].tobytes(), dtype="<u4") for r in ic], dtype=np.uint32)
    for rounds in (a.rounds or [64, 32]):
        if len(kc) * len(ic) <= 4096:
            hits = [(i, j) for i in range(len(kc)) for j in range(len(ic))]     # few enough to try in full
        else:
            hits = search_pairs(head, keys, ivs, rounds, log)
            log("%d cycles: pairs whose first block deciphers to common code bytes: %d" % (rounds, len(hits)))
        best = []
        for ki, ii in hits:
            frac = confirm(head, [int(x) for x in keys[ki]], (int(ivs[ii][0]), int(ivs[ii][1])), rounds)
            best.append((frac, kc[ki], ic[ii]))
        best.sort(reverse=True)
        for frac, k, v in best[:5]:
            log("key @ %#x  starting block @ %#x  common code bytes in the first %d: %.1f%%" % (
                k, v, len(head), 100 * frac))
        if best and best[0][0] > 0.45 and (len(best) == 1 or best[1][0] < 0.3):
            frac, k, v = best[0]
            out.update(key_rva=k, iv_rva=v, rounds=rounds, score=frac)
            print("--bootstrap 0x%X,0x%X,0x%X,%d" % (k, v, out["ranges_rva"], rounds))
            break
    else:
        log("no pair stands out")
    if a.json:
        json.dump(out, open(a.json, "w"), indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
