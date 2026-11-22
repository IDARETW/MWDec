"""Is everything in an exported image at the address a memory dump of the same build has it at?

    py -3 tools\\check_dump.py EXPORT.exe DUMP.exe [--dec DEC.exe [--layer1 L1.exe]] [--json OUT.json]

A dump made from the running game (Scylla and the like) is the image as
Windows laid it out: its headers name the address it was loaded at, its
pointers were relocated to that address, and whoever works from it counts
from the start of the image, base 0. An export is a file for the loader,
linked at its preferred base. The two agree when the same RVA holds the
same thing in both. Read both by RVA, and compare:

 1. the layout: every section's RVA and its size in pages, and SizeOfImage;
 2. whether the dump file's offsets are its RVAs (what "base 0" assumes);
 3. pointers: at every relocation site of the export, the export's value
    minus its image base against the dump's value minus the base the dump
    was loaded at (read from the dump's header, and checked against the
    difference most sites show);
 4. the exception directory: one record per function piece, begin and end
    as RVAs;
 5. the game's code section byte for byte at the same RVA, and the first
    16 bytes of every function, in the pages the dump holds (a dumper
    writes zeros for a page it could not read);
 6. a control: the same byte count with the dump moved by 16 bytes and by
    a page either way. If the count at 0 is not far above those, equal
    bytes mean nothing.

With --dec (the decrypted image the export was made from) the code is also
compared three ways, which separates what the removal rewrote from what
the dump and the decryption disagree about; with --layer1 (the file with
only its outer layer off) it says how much of what writers decrypt the
dump still holds encrypted.

Reads files only, through memory maps and 16 MB at a time: four images of
300 to 700 MB are compared in about 150 MB of memory.
"""
from __future__ import annotations

import argparse
import json
import struct
import sys

import os as _os
_os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")    # numpy's math library reserves 31 MB a core when loaded; nothing here uses it
import numpy as np

STEP = 1 << 24      # bytes compared at a time; a multiple of the page size


class Img:
    """A PE file read by RVA through a memory map of the file."""

    def __init__(self, path):
        self.path = path
        self.fb = np.memmap(path, dtype=np.uint8, mode="r")
        self.file_size = len(self.fb)
        hd = self.fb[:0x1000].tobytes()
        pe = struct.unpack_from("<I", hd, 0x3C)[0]
        if hd[pe:pe + 4] != b"PE\0\0":
            raise ValueError("%s: not a PE file" % path)
        nsec = struct.unpack_from("<H", hd, pe + 6)[0]
        optsz = struct.unpack_from("<H", hd, pe + 20)[0]
        opt = pe + 24
        self.entry = struct.unpack_from("<I", hd, opt + 16)[0]
        self.base = struct.unpack_from("<Q", hd, opt + 24)[0]
        self.size = struct.unpack_from("<I", hd, opt + 56)[0]
        self.hsize = min(struct.unpack_from("<I", hd, opt + 60)[0], self.file_size)
        ndir = struct.unpack_from("<I", hd, opt + 108)[0]
        self.dirs = [struct.unpack_from("<II", hd, opt + 112 + 8 * i) for i in range(ndir)]
        self.secs = []
        so = opt + optsz
        need = so + 40 * nsec
        if need > len(hd):
            hd = self.fb[:need].tobytes()
        for i in range(nsec):
            name, vs, va, rs, ro = struct.unpack_from("<8sIIII", hd, so + 40 * i)
            ch = struct.unpack_from("<I", hd, so + 40 * i + 36)[0]
            have = min(rs, vs) if vs else rs
            have = max(0, min(have, self.file_size - ro))
            self.secs.append({"name": name.rstrip(b"\0").decode("latin1"), "rva": va, "vsize": vs, "raw": ro,
                              "rsize": rs, "have": have, "exec": bool(ch & 0x20000000),
                              "write": bool(ch & 0x80000000)})
        self.end = (max([self.size] + [s["rva"] + max(s["vsize"], 1) for s in self.secs]) + 0xFFF) & ~0xFFF
        self.raw_is_rva = all(s["raw"] == s["rva"] for s in self.secs if s["rsize"])

    def sec_of(self, rva):
        for s in self.secs:
            if s["rva"] <= rva < s["rva"] + max(s["vsize"], s["rsize"]):
                return s
        return None

    def span(self, rva, n):
        """n bytes at rva: a view of the file where one section backs the
        whole range, otherwise a copy with zeros where nothing does."""
        if n <= 0:
            return np.zeros(0, dtype=np.uint8)
        if rva >= 0 and rva + n <= self.hsize:
            return self.fb[rva:rva + n]
        s = self.sec_of(rva) if rva >= 0 else None
        if s is not None:
            rel = rva - s["rva"]
            if rel + n <= s["have"]:
                return self.fb[s["raw"] + rel:s["raw"] + rel + n]
        out = np.zeros(n, dtype=np.uint8)
        a = rva
        while a < rva + n:
            if a < 0:
                a = 0
                continue
            s = self.sec_of(a)
            if a < self.hsize:
                k = min(rva + n, self.hsize) - a
                out[a - rva:a - rva + k] = self.fb[a:a + k]
            elif s is None:
                nxt = min((x["rva"] for x in self.secs if x["rva"] > a), default=rva + n)
                k = min(rva + n, nxt) - a
            else:
                rel = a - s["rva"]
                k = min(rva + n, s["rva"] + max(s["vsize"], s["rsize"], 1)) - a
                h = max(0, min(k, s["have"] - rel))
                if h:
                    out[a - rva:a - rva + h] = self.fb[s["raw"] + rel:s["raw"] + rel + h]
            a += max(k, 1)
        return out

    def gather(self, at, width):
        """The `width` bytes at each RVA of `at` (an int64 array): an array of shape (len(at), width)."""
        out = np.zeros((len(at), width), dtype=np.uint8)
        for s in self.secs:
            m = (at >= s["rva"]) & (at + width <= s["rva"] + s["have"])
            if m.any():
                off = at[m] - s["rva"] + s["raw"]
                out[m] = self.fb[off[:, None] + np.arange(width)]
        return out

    def qwords(self, at):
        return self.gather(at, 8).view("<u8").reshape(-1)

    def relocs(self):
        rva, size = self.dirs[5]
        if not rva:
            return np.zeros(0, dtype=np.int64)
        raw = self.span(rva, size).tobytes()
        out = []
        off = 0
        while off + 8 <= len(raw):
            page, bs = struct.unpack_from("<II", raw, off)
            if bs < 8:
                break
            e = np.frombuffer(raw, dtype="<u2", count=(bs - 8) // 2, offset=off + 8)
            sel = e[(e >> 12) == 10]
            out.append(page + (sel & 0xFFF).astype(np.int64))
            off += bs
        return np.sort(np.concatenate(out)) if out else np.zeros(0, dtype=np.int64)

    def functions(self):
        rva, size = self.dirs[3]
        n = size // 12
        if not rva or not n:
            return np.zeros((0, 3), dtype="<u4")
        return np.frombuffer(self.span(rva, 12 * n).tobytes(), dtype="<u4").reshape(-1, 3)


def pct(a, b):
    return "%.3f%%" % (100.0 * a / b) if b else "-"


def bits(hist):
    n = hist.sum()
    if not n:
        return 0.0
    p = hist[hist > 0] / float(n)
    return float(-(p * np.log2(p)).sum())


def check(export, dump, dec=None, log=print, shipped=None):
    ex, du = Img(export), Img(dump)
    r = {"export": export, "dump": dump}
    # 1. layout
    by = {(s["name"], s["rva"]): s for s in du.secs}
    same = []
    other = []
    # a dumper writes each section's size rounded up to a page, as it is in memory
    page = lambda v: (v + 0xFFF) & ~0xFFF      # noqa: E731
    for s in ex.secs:
        d = by.pop((s["name"], s["rva"]), None)
        if d is not None and page(d["vsize"]) == page(s["vsize"]):
            same.append(s["name"])
        else:
            other.append("%s at %X+%X (dump: %s)" % (s["name"], s["rva"], s["vsize"],
                                                      "none" if d is None else "%X+%X" % (d["rva"], d["vsize"])))
    extra = ["%s at %X+%X" % (s["name"], s["rva"], s["vsize"]) for s in by.values()]
    r["sections_same_rva_and_size"] = len(same)
    r["sections_of_the_export"] = len(ex.secs)
    r["sections_that_differ"] = other
    r["sections_only_in_the_dump"] = extra
    r["size_of_image"] = ["%X" % ex.size, "%X" % du.size]
    r["entry_point"] = ["%X" % ex.entry, "%X" % du.entry]
    r["image_base_in_header"] = ["%X" % ex.base, "%X" % du.base]
    r["dump_file_offsets_are_rvas"] = du.raw_is_rva
    offs = sorted({s["rva"] - s["raw"] for s in du.secs if s["rsize"]})
    r["dump_rva_minus_file_offset"] = ["%X" % o for o in offs]
    r["size_of_image_same_pages"] = page(ex.size) == page(du.size)
    log("sections with the same RVA and size in pages: %d of %d%s%s" % (
        len(same), len(ex.secs), ("; differ: " + "; ".join(other)) if other else "",
        ("; only in the dump: " + "; ".join(extra)) if extra else ""))
    log("SizeOfImage %X / %X; entry point %X / %X; image base in the header %X / %X (export / dump)" % (
        ex.size, du.size, ex.entry, du.entry, ex.base, du.base))
    log("the dump file's offsets are its RVAs: %s (RVA minus file offset, per section: %s)" % (
        du.raw_is_rva, ", ".join("%X" % o for o in offs)))
    n = min(ex.end, du.end)

    # 3. pointers
    rel = ex.relocs()
    rel = rel[rel + 8 <= n]
    e, d = ex.qwords(rel), du.qwords(rel)
    delta = (d - e).astype(np.uint64)
    vals, counts = np.unique(delta, return_counts=True)
    top = int(vals[np.argmax(counts)]) if len(vals) else 0
    loaded_at = (ex.base + top) & 0xFFFFFFFFFFFFFFFF
    ok = delta == np.uint64(top)
    r["relocation_sites"] = int(len(rel))
    r["dump_loaded_at"] = "%X" % loaded_at
    r["dump_loaded_at_equals_header"] = loaded_at == du.base
    r["pointers_same_rva"] = int(ok.sum())
    by_sec = {}
    const = [0, 0]      # in sections nobody writes: neither the game at run time nor the removal
    for s in ex.secs:
        m = (rel >= s["rva"]) & (rel < s["rva"] + max(s["vsize"], s["rsize"]))
        if m.any():
            by_sec["%s@%X" % (s["name"], s["rva"])] = [int(ok[m].sum()), int(m.sum())]
            if not s["exec"] and not s["write"]:
                const[0] += int(ok[m].sum())
                const[1] += int(m.sum())
    r["pointers_by_section"] = by_sec
    r["pointers_in_read_only_data_same_rva"] = const
    log("pointers: %d relocation sites in the export; the dump was loaded at %X (its header says %X); "
        "same RVA in both: %d (%s); in read-only data: %d of %d" % (
            len(rel), loaded_at, du.base, int(ok.sum()), pct(int(ok.sum()), len(rel)), const[0], const[1]))
    for k, (a, b) in by_sec.items():
        log("    %-16s %8d of %8d %s" % (k, a, b, pct(a, b)))
    del e, d, delta, ok

    # 4. exception directory
    # A record is a function piece: where it begins, where it ends, where
    # its unwind data is, all RVAs. The export's records are looked for in
    # the dump's directory wherever they sit there: the export drops the
    # record of a piece of protection code it removed, and every record
    # after that one is a slot earlier than in the dump (1.59.1: one record
    # of 126,534 dropped, at slot 111,309).
    fe = ex.functions()
    rva, size = ex.dirs[3]
    nd = max(len(fe), du.dirs[3][1] // 12 if du.dirs[3][0] == rva else 0)
    fd = np.frombuffer(du.span(rva, 12 * nd).tobytes(), dtype="<u4").reshape(-1, 3) if len(fe) else fe
    eq = slot = 0
    if len(fe):
        kd = (fd[:, 0].astype(np.uint64) << np.uint64(32)) | fd[:, 1].astype(np.uint64)
        order = np.argsort(kd, kind="stable")
        ke = (fe[:, 0].astype(np.uint64) << np.uint64(32)) | fe[:, 1].astype(np.uint64)
        at = np.minimum(np.searchsorted(kd[order], ke), len(kd) - 1)
        hit = order[at]
        eq = int(((kd[hit] == ke) & (fd[hit, 2] == fe[:, 2])).sum())
        slot = int((fe == fd[:len(fe)]).all(axis=1).sum())
        del kd, ke, order, at, hit
    r["function_records"] = int(len(fe))
    r["function_records_same"] = eq
    r["function_records_same_slot"] = slot
    r["function_records_in_dump"] = int(nd)
    r["exception_directory"] = ["%X+%X" % ex.dirs[3], "%X+%X" % du.dirs[3]]
    log("exception directory %X+%X / %X+%X: %d records in the export, %d of them in the dump's directory with the "
        "same RVAs (%s); %d in the same slot; the dump has %d" % (
            ex.dirs[3] + du.dirs[3] + (len(fe), eq, pct(eq, len(fe)), slot, nd)))

    # 5. the game's code, 6. the control, and the three- and four-way counts, a stretch at a time
    code = next(s for s in ex.secs if s["exec"])
    lo, hi = code["rva"], min(code["rva"] + code["have"], n)
    de = Img(dec) if dec else None
    l1 = Img(shipped) if (dec and shipped) else None
    shifts = (-0x1000, -0x10, 0x10, 0x1000)
    c = collections_counter()
    ctl = dict.fromkeys(shifts, 0)
    npg = (hi - lo) // 0x1000
    held_pg = np.ones(npg + 1, dtype=bool)
    hist_dump = np.zeros(256, dtype=np.int64)
    hist_exp = np.zeros(256, dtype=np.int64)
    for c0 in range(lo, hi, STEP):
        k = min(STEP, hi - c0)
        a, b = ex.span(c0, k), du.span(c0, k)
        # A dump does not have to hold every page. A dumper writes zeros for
        # a page it could not read, and the archive's dump of 1.51.2 has
        # 16,484 such pages in the game's code, more than half of it. A page
        # that is all zero in the dump and not in the export is a page the
        # dump does not hold, and says nothing about addresses.
        full = k // 0x1000
        held = np.ones(k, dtype=bool)
        if full:
            dz = ~b[:full * 0x1000].reshape(full, 0x1000).any(axis=1)
            ez = ~a[:full * 0x1000].reshape(full, 0x1000).any(axis=1)
            hp = ~(dz & ~ez)
            held_pg[(c0 - lo) // 0x1000:(c0 - lo) // 0x1000 + full] = hp
            held[:full * 0x1000] = np.repeat(hp, 0x1000)
        c["held"] += int(held.sum())
        eqab = a == b
        c["same"] += int((eqab & held).sum())
        diff = ~eqab & held
        cc = a == 0xCC
        c["diff_cc"] += int((diff & cc).sum())
        c["diff_other"] += int((diff & ~cc).sum())
        for sh in shifts:
            if c0 + sh >= 0:
                ctl[sh] += int(((a == du.span(c0 + sh, k)) & held).sum())
        if de is not None:
            x = de.span(c0, k)
            eqxb = x == b
            eqax = a == x
            c["dec_same"] += int((eqxb & held).sum())
            c["rewritten"] += int((~eqax & held).sum())
            m = ~eqxb & eqax & held
            c["left_alone_differ"] += int(m.sum())
            hist_dump += np.bincount(b[m], minlength=256)
            hist_exp += np.bincount(a[m], minlength=256)
            if l1 is not None:
                y = l1.span(c0, k)
                inner = (y != x) & held             # bytes a writer decrypts
                first = b == y
                c["inner"] += int(inner.sum())
                c["inner_still"] += int((inner & first).sum())
                c["left_alone_first_state"] += int((m & first).sum())
    nheld = c["held"]
    r["code_pages"] = int(npg)
    r["code_pages_the_dump_does_not_hold"] = int(npg - held_pg[:npg].sum())
    r["code_section"] = "%s %X-%X" % (code["name"], lo, hi)
    r["code_bytes"] = nheld
    r["code_bytes_same"] = c["same"]
    r["code_bytes_differ_export_cc"] = c["diff_cc"]
    r["code_bytes_differ_other"] = c["diff_other"]
    log("code %s %X-%X: %d pages, %d of them not in the dump (all zero there). In the rest: %d bytes, the same at "
        "the same RVA: %d (%s); different: %d where the export has 0xCC, %d elsewhere" % (
            code["name"], lo, hi, npg, r["code_pages_the_dump_does_not_hold"], nheld, c["same"],
            pct(c["same"], nheld), c["diff_cc"], c["diff_other"]))
    starts = np.unique(fe[:, 0].astype(np.int64)) if len(fe) else np.zeros(0, dtype=np.int64)
    starts = starts[(starts >= lo) & (starts + 16 <= hi)]
    starts = starts[held_pg[(starts - lo) >> 12] & held_pg[(starts - lo + 15) >> 12]]
    feq = (ex.gather(starts, 16) == du.gather(starts, 16)).all(axis=1)
    r["function_starts"] = int(len(starts))
    r["function_starts_same_16_bytes"] = int(feq.sum())
    log("function starts in pages the dump holds: %d; first 16 bytes the same in the dump: %d (%s)" % (
        len(starts), int(feq.sum()), pct(int(feq.sum()), len(starts))))
    r["control_same_bytes_with_the_dump_moved"] = {"%+d" % k: v for k, v in ctl.items()}
    log("control, same bytes with the dump moved: %s" % ", ".join(
        "%+d: %s" % (k, pct(v, nheld)) for k, v in ctl.items()))

    # other sections, for the record
    per = {}
    for s in ex.secs:
        l2, h2 = s["rva"], min(s["rva"] + s["have"], n)
        if h2 > l2:
            t = 0
            for c0 in range(l2, h2, STEP):
                k = min(STEP, h2 - c0)
                t += int((ex.span(c0, k) == du.span(c0, k)).sum())
            per["%s@%X" % (s["name"], l2)] = [t, int(h2 - l2)]
    r["same_bytes_by_section"] = per
    log("same bytes by section: %s" % ", ".join("%s %s" % (k, pct(a2, b2)) for k, (a2, b2) in per.items()))

    if de is not None:
        r["dec_vs_dump_same"] = c["dec_same"]
        r["rewritten_by_the_removal"] = c["rewritten"]
        r["dec_differs_from_dump_where_export_equals_dec"] = c["left_alone_differ"]
        log("three ways, code in pages the dump holds: decrypted image against the dump %s the same; the removal "
            "changed %d bytes; bytes the removal left alone that differ from the dump: %d" % (
                pct(c["dec_same"], nheld), c["rewritten"], c["left_alone_differ"]))
        # What are those? A dump is one moment of a running game: functions
        # the protection decrypts for one use and hides again are noise in it
        # unless it was taken while they ran. Noise has 8 bits a byte.
        if c["left_alone_differ"]:
            r["those_bytes_entropy"] = {"dump": round(bits(hist_dump), 2), "export": round(bits(hist_exp), 2)}
            log("    those bytes have %.2f bits of entropy a byte in the dump and %.2f in the export "
                "(8.00 is noise: still encrypted)" % (r["those_bytes_entropy"]["dump"],
                                                      r["those_bytes_entropy"]["export"]))
        if l1 is not None:
            # The plainest answer: is the dump holding there what the game
            # holds before a writer has run? That state is the file with its
            # outer layer off (`mwdec decrypt --layer1-only`): the start-up
            # decrypts the outer layer everywhere, and what the writers
            # decrypt on demand is still encrypted underneath.
            r["bytes_writers_decrypt"] = c["inner"]
            r["of_them_still_encrypted_in_dump"] = c["inner_still"]
            r["those_bytes_still_encrypted_in_dump"] = c["left_alone_first_state"]
            log("    %d of them are, in the dump, what the game holds before a writer has run: functions the "
                "protection had not decrypted yet, or had hidden again, when the dump was taken" %
                c["left_alone_first_state"])
            log("    of the %d code bytes that writers decrypt, the dump holds %d still encrypted (%s)" % (
                c["inner"], c["inner_still"], pct(c["inner_still"], c["inner"])))

    best_other = max(ctl.values()) if ctl else 0
    # Pointers are judged where nothing changes them: writable data moves as
    # the game runs, and the removal rewrites code that held some.
    r["addresses_match"] = bool(
        not other and const[1] and const[0] >= 0.999 * const[1] and len(fe) and eq >= 0.99 * len(fe) and
        nheld >= 0x100000 and c["same"] > 4 * best_other and c["same"] >= 0.5 * nheld)
    log("addresses match: %s" % ("yes" if r["addresses_match"] else "NO"))
    return r


def collections_counter():
    import collections
    return collections.Counter()


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("export")
    ap.add_argument("dump")
    ap.add_argument("--dec", help="the decrypted image the export was made from")
    ap.add_argument("--layer1", dest="shipped",
                    help="the file with its outer layer off (with --dec): says how much of what writers decrypt "
                         "the dump still holds encrypted")
    ap.add_argument("--json")
    a = ap.parse_args()
    r = check(a.export, a.dump, a.dec, shipped=a.shipped)
    if a.json:
        json.dump(r, open(a.json, "w"), indent=1)
    return 0 if r["addresses_match"] else 1


if __name__ == "__main__":
    sys.exit(main())
