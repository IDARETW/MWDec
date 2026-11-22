"""Every range list in an image, found from the file alone.

    py -3 tools\\find_lists.py image.exe [-o lists.tsv] [--json lists.json]

The protection writes every "these bytes, then skip, then these bytes"
table in one encoding: unsigned LEB128 pairs (gap, length) walked with a
32-bit cursor that starts at RVA 0, ended by a gap that takes the cursor
to exactly 0xFFFFFFFF (src/ranges.h). That ending is a signature. The last
range ends inside the image, so the final gap is at least 0xFFFFFFFF minus
the image size: always five bytes, the last of them 0x0D to 0x0F.

LEB128 can be read backwards without ambiguity (a value ends at a byte
with the top bit clear and owns the top-bit-set bytes before it). So from
each candidate ending the tool walks back, length then gap, taking each
value off the cursor. A list is accepted when a gap equals the whole
remaining cursor, which only its first gap can.

Works on the shipped file for the lists the bootstrap cipher skips, and on
a decrypted image for all of them.
"""
import argparse
import collections
import json
import os
import sys
import time

import os as _os
_os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")    # numpy's math library reserves 31 MB a core when loaded; nothing here uses it
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from find_bootstrap import PE, uleb  # noqa: E402


def candidates(a, size_of_image):
    """Offsets in the byte array a where a five-byte LEB128 value starts
    whose value v leaves 0xFFFFFFFF - v inside the image."""
    hi = (a & 0x80) != 0
    last = (a >= 0x0D) & (a <= 0x0F)
    m = hi[:-4] & hi[1:-3] & hi[2:-2] & hi[3:-1] & last[4:]
    at = np.nonzero(m)[0]
    v = ((a[at].astype(np.int64) & 0x7F) | ((a[at + 1].astype(np.int64) & 0x7F) << 7) |
         ((a[at + 2].astype(np.int64) & 0x7F) << 14) | ((a[at + 3].astype(np.int64) & 0x7F) << 21) |
         (a[at + 4].astype(np.int64) << 28))
    end = 0xFFFFFFFF - v
    ok = (end > 0) & (end <= size_of_image)
    return at[ok], end[ok]


class Ranges:
    """A list of (rva, length) pairs, kept as two arrays.

    It reads like the list of tuples it replaces (iteration, len, indexing,
    slices, ==), and it can be a dictionary key. A build's lists hold 1.3
    million ranges between them, the bootstrap's alone a million: as tuples
    that is 150 MB a time, made again on every round of find_writers.py,
    and the walk below used to build and throw away millions more while
    testing terminators that are not one. Small objects freed in that
    number do not go back to the system; a process that had been through
    two rounds held 3 GB. As arrays a list is 16 bytes a range."""
    __slots__ = ("rva", "ln", "_h")

    def __init__(self, rva, ln):
        self.rva = np.asarray(rva, dtype=np.int64)
        self.ln = np.asarray(ln, dtype=np.int64)
        self._h = None

    def __len__(self):
        return len(self.rva)

    def __iter__(self):
        return zip(self.rva.tolist(), self.ln.tolist())

    def __getitem__(self, i):
        if isinstance(i, slice):
            return list(zip(self.rva[i].tolist(), self.ln[i].tolist()))
        return int(self.rva[i]), int(self.ln[i])

    def __eq__(self, o):
        if isinstance(o, Ranges):
            return np.array_equal(self.rva, o.rva) and np.array_equal(self.ln, o.ln)
        try:
            return len(o) == len(self) and all(a == tuple(b) for a, b in zip(self, o))
        except TypeError:
            return NotImplemented

    def __hash__(self):
        if self._h is None:
            self._h = hash((len(self), self.rva.tobytes(), self.ln.tobytes()))
        return self._h

    def total(self):
        return int(self.ln.sum())

    def touches(self, lo, hi):
        """Does any range overlap [lo, hi)?"""
        return bool(((self.rva < hi) & (self.rva + self.ln > lo)).any())


def _is_first(a, lo, p, cursor):
    """Do the bytes that end at p spell `cursor`? (a list's first value is
    the RVA its first range begins at). Returns the first byte or None."""
    first = uleb(cursor)
    s = p - len(first)
    if s >= lo and a[s:p].tobytes() == first:
        return s
    return None


def walk_back(a, lo, at, cursor, max_values=8_000_000):
    """From a terminator at a[at] (a uint8 array), with the cursor it
    implies, back to the list's first byte. Returns (start, the ranges in
    order as a Ranges) or None.

    walk_back_ref below is the definition, one value at a time; this reads
    the same stream a window at a time. Going backwards the values
    alternate: a range's length, then the gap to the range before it. After
    each length the bytes in front are tested for being the list's first
    value. The walk fails on a zero length, on a cursor that reaches zero,
    and on a value longer than five bytes."""
    p = at
    want_len = True
    n = 0
    parts_rva, parts_len = [], []
    W = 512

    def done(start):
        rv = np.concatenate(parts_rva)[::-1] if parts_rva else np.zeros(0, dtype=np.int64)
        ln = np.concatenate(parts_len)[::-1] if parts_len else np.zeros(0, dtype=np.int64)
        return start, Ranges(rv, ln)

    while True:
        if p - 1 < lo or a[p - 1] >= 0x80:
            # nothing in front that ends a value: only the first-value test is left
            if not want_len:
                s = _is_first(a, lo, p, cursor)
                if s is not None:
                    return done(s)
            return None
        w0 = max(lo, p - W)
        if w0 > lo:
            # move to where a value begins: after a byte without the continuation bit
            k = np.nonzero(a[w0 - 1:p - 1] < 0x80)[0]
            if len(k) == 0:
                # the value in front is longer than the window: longer than five bytes
                if not want_len:
                    s = _is_first(a, lo, p, cursor)
                    if s is not None:
                        return done(s)
                return None
            w0 += int(k[0])
        b = a[w0:p]
        ends = np.nonzero(b < 0x80)[0]
        starts = np.empty(len(ends), dtype=np.int64)
        starts[0] = 0
        starts[1:] = ends[:-1] + 1
        nb = ends - starts + 1
        s5 = np.maximum(starts, ends - 4)           # a value is read from its last five bytes at most
        v = np.zeros(len(ends), dtype=np.int64)
        for k in range(5):
            idx = s5 + k
            m = idx <= ends
            v[m] |= (b[idx[m]].astype(np.int64) & 0x7F) << (7 * k)
        # in the order the walk meets them: last value of the window first
        v, nb, s5, ends = v[::-1], nb[::-1], s5[::-1] + w0, ends[::-1] + w0
        cnt = len(v)
        after = cursor - np.cumsum(v)               # the cursor once value i is taken
        before = after + v
        i = np.arange(cnt)
        is_len = ((i & 1) == 0) if want_len else ((i & 1) == 1)
        # what can end the walk at value i: the first-value test (at a gap
        # position, before the value is taken), then the failures.
        # The test asks whether the bytes in front spell the cursor, however
        # many continuation bytes precede them (junk before a list often has
        # the high bit set, and runs into the list's first value): so it is
        # the last k bytes of the value that have to spell the cursor, k
        # being the bytes the cursor takes. A value's first byte is its
        # least significant, so those are the value's high bits.
        k7 = 7 * (1 + (before >= 1 << 7) + (before >= 1 << 14) + (before >= 1 << 21) + (before >= 1 << 28))
        n7 = 7 * np.minimum(nb, 5)                  # bits the value was read from
        high = v >> np.maximum(n7 - k7, 0)
        maybe_first = ~is_len & (before > 0) & (((high == before) & (n7 >= k7)) | (nb > 5))
        fail = (is_len & (v == 0)) | (after <= 0) | (nb > 5)
        stop = None
        for e in np.nonzero(maybe_first | fail)[0].tolist():
            if maybe_first[e]:
                s = _is_first(a, lo, int(ends[e]) + 1, int(before[e]))
                if s is not None:
                    stop = ("first", e, s)
                    break
            if fail[e]:
                stop = ("fail", e, None)
                break
        if stop is not None and stop[0] == "fail":
            return None
        upto = cnt if stop is None else stop[1]     # values taken in this window
        if n + upto > max_values:
            return None
        sel = is_len[:upto]
        parts_rva.append(after[:upto][sel])
        parts_len.append(v[:upto][sel])
        if stop is not None:
            return done(stop[2])
        n += cnt
        cursor = int(after[-1])
        if cnt & 1:
            want_len = not want_len
        p = int(s5[-1])                             # first byte of the earliest value taken
        if nb[-1] > 5:                              # (cannot happen: a long value is a failure)
            return None
        W = min(W * 8, 1 << 22)


def walk_back_ref(data, lo, at, cursor, max_values=8_000_000):
    """The definition of walk_back, one value at a time, on bytes. Kept to
    check the windowed version against (MWDEC_LISTS_CHECK=1)."""
    from array import array
    p = at
    rv, lv = array("q"), array("q")

    class out:                  # the two arrays, written like the list they replace
        @staticmethod
        def append(t):
            rv.append(t[0])
            lv.append(t[1])
    want_len = True
    length = 0
    n = 0
    while True:
        if not want_len:
            first = uleb(cursor)
            if p - len(first) >= lo and data[p - len(first):p] == first:
                rv.append(cursor)
                lv.append(length)
                rv.reverse()
                lv.reverse()
                return p - len(first), Ranges(np.array(rv, dtype=np.int64), np.array(lv, dtype=np.int64))
        e = p - 1
        if e < lo or data[e] & 0x80:
            return None
        s = e
        while s > lo and data[s - 1] & 0x80 and e - s < 4:
            s -= 1
        v = 0
        for k in range(e, s - 1, -1):
            v = (v << 7) | (data[k] & 0x7F)
        if want_len:
            if v == 0:
                return None             # no list has an empty range
            length = v
            cursor -= v
        else:
            out.append((cursor, length))
            cursor -= v
        if cursor <= 0:
            return None
        p = s
        want_len = not want_len
        n += 1
        if n > max_values:
            return None


def find_lists(pe, log=lambda s: None):
    """All lists in the file's sections. Returns a list of dicts."""
    found = []
    seen_ends = set()
    for sec in pe.secs:
        n = min(sec["vsize"], sec["rsize"])
        if n < 16:
            continue
        a = pe.b[sec["raw"]:sec["raw"] + n]
        at, end = candidates(a, pe.size_of_image)
        # The windowed walk equals the definition on every candidate of 1.30.0
        # (63,914 candidates, 196 lists, 12.5 million ranges) and of 1.51.2
        # (310 lists, 11.8 million ranges), in 9 s where the definition takes
        # 33. MWDEC_LISTS_CHECK=1 runs both and stops at a difference;
        # MWDEC_LISTS_REF=1 uses the definition alone.
        check = os.environ.get("MWDEC_LISTS_CHECK")
        fast = check or not os.environ.get("MWDEC_LISTS_REF")
        data = a.tobytes() if (check or not fast) else None
        got = 0
        for o, e in zip(at.tolist(), end.tolist()):
            if o == 0 or a[o - 1] & 0x80:
                continue                # the value before it does not end here
            res = walk_back(a, 0, o, e) if fast else walk_back_ref(data, 0, o, e)
            if check:
                ref = walk_back_ref(data, 0, o, e)
                if (res is None) != (ref is None) or (res is not None and (res[0] != ref[0] or res[1] != ref[1])):
                    raise AssertionError("walk_back differs from its definition at %s+%X: %s / %s" % (
                        sec["name"], o, None if res is None else (res[0], len(res[1])),
                        None if ref is None else (ref[0], len(ref[1]))))
            if res is None:
                continue
            start, ranges = res
            # every range must lie inside one section
            ok = True
            where = collections.Counter()
            for rva, ln in ranges[:4096]:
                s = next((x for x in pe.secs if x["rva"] <= rva and rva + ln <= x["rva"] + max(x["vsize"], x["rsize"])), None)
                if s is None:
                    ok = False
                    break
                where["%s@%X" % (s["name"], s["rva"])] += ln
            if not ok:
                continue
            got += 1
            found.append({"rva": sec["rva"] + start, "end_rva": sec["rva"] + o + 5, "encoded": o + 5 - start,
                          "ranges": len(ranges), "bytes": ranges.total(),
                          "first": ranges[0][0], "last_end": ranges[-1][0] + ranges[-1][1],
                          "where": dict(where), "list": ranges})
        log("%-8s %08X: %d terminator candidates, %d lists" % (sec["name"], sec["rva"], len(at), got))
    return found


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("exe")
    ap.add_argument("-o", "--out", help="TSV: one row per list")
    ap.add_argument("--json", help="JSON with every range of every list")
    ap.add_argument("--show", type=int, default=30)
    a = ap.parse_args()
    t0 = time.time()

    def log(s):
        print("[%5.1fs] %s" % (time.time() - t0, s), flush=True)

    pe = PE(a.exe)
    lists = find_lists(pe, log)
    lists.sort(key=lambda x: x["rva"])
    log("lists: %d; ranges %d; bytes covered %d" % (
        len(lists), sum(x["ranges"] for x in lists), sum(x["bytes"] for x in lists)))
    size = collections.Counter()
    for x in lists:
        size[min(x["ranges"], 10**9).bit_length()] += 1
    for x in sorted(lists, key=lambda x: -x["bytes"])[:a.show]:
        print("  list @ %08X  %8d ranges %10d bytes  %7d encoded  first %08X  %s" % (
            x["rva"], x["ranges"], x["bytes"], x["encoded"], x["first"],
            ", ".join("%s %d" % kv for kv in sorted(x["where"].items(), key=lambda kv: -kv[1])[:3])))
    if a.out:
        with open(a.out, "w") as f:
            f.write("rva\tend_rva\tencoded\tranges\tbytes\tfirst\tlast_end\twhere\n")
            for x in lists:
                f.write("%08X\t%08X\t%d\t%d\t%d\t%08X\t%08X\t%s\n" % (
                    x["rva"], x["end_rva"], x["encoded"], x["ranges"], x["bytes"], x["first"], x["last_end"],
                    ";".join("%s=%d" % kv for kv in sorted(x["where"].items()))))
    if a.json:
        json.dump([{k: (v if k != "list" else [[r, n] for r, n in v]) for k, v in x.items()} for x in lists],
                  open(a.json, "w"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
