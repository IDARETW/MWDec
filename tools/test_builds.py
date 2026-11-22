"""Decrypt every build in a folder from its file alone, measure, and delete.

    py -3 tools\\test_builds.py O:\\Builds\\odin -o out\\builds\\test.tsv [--jobs 3] [--only REGEX]
                                [--builds manifest.tsv] [--resume]
    py -3 tools\\test_builds.py --summary out\\builds\\test.tsv

For each <root>\\<build>\\ModernWarfare.exe (read only; nothing is run):

  0. the file is copied here (the archive is a network share);
  1. `mwdec decrypt --layer1-only`, with no profile: the key, the starting
     block and the range list are found in the file;
  2. `find_writers.py` on that image: the writer table, from the code;
  3. `mwdec decrypt --writers` with that table: both layers and the strings;
  4. count the unreadable 4 KB code pages in the shipped file, after layer
     1 and after both layers, and look at the entry point;
  5. `check_functions.py` on the result: the function pieces that still
     neither disassemble nor have the byte statistics of code.

The copy and the two executables each attempt writes are deleted as soon as
they have been measured. What stays is one row per build in the result
table and the build's writer table (a few kilobytes) next to it. A build
the share does not serve is recorded as "not read"; `--resume` tries those
again and keeps the rest.
"""
import argparse
import concurrent.futures
import datetime
import os
import re
import shutil
import struct
import subprocess
import sys
import threading
import time

import os as _os
_os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")    # numpy's math library reserves 31 MB a core when loaded; nothing here uses it
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from find_bootstrap import COMMON  # noqa: E402  (256 flags: the byte values code is mostly made of)

MWDEC = os.path.join(HERE, "..", "build", "Release", "mwdec.exe")
COLS = ["build", "size", "linked", "sections", "status", "key", "block", "list", "cycles", "pairs", "best", "next",
        "ranges", "layer1_bytes", "set_ups", "rounds", "rows", "rows_feeding", "noise_rows_last_round",
        "string_blobs", "game_pages", "noisy_shipped", "noisy_layer1", "noisy_final", "prot_pages",
        "prot_noisy_shipped", "prot_noisy_layer1", "prot_noisy_final", "entry", "seconds", "note", "over72_final",
        "fn_pieces", "fn_encrypted", "fn_encrypted_bytes"]


def sections(path):
    with open(path, "rb") as f:
        raw = f.read(0x1000)
    pe = struct.unpack_from("<I", raw, 0x3C)[0]
    nsec = struct.unpack_from("<H", raw, pe + 6)[0]
    ts = struct.unpack_from("<I", raw, pe + 8)[0]
    opt = struct.unpack_from("<H", raw, pe + 20)[0]
    entry = struct.unpack_from("<I", raw, pe + 24 + 16)[0]
    o = pe + 24 + opt
    secs = []
    for i in range(nsec):
        h = raw[o + 40 * i:o + 40 * i + 40]
        vs, va, rs, ro = struct.unpack_from("<IIII", h, 8)
        ch = struct.unpack_from("<I", h, 36)[0]
        secs.append({"name": h[:8].rstrip(b"\0").decode("latin1"), "rva": va, "vsize": vs, "rsize": rs, "raw": ro,
                     "exec": bool(ch & 0x20000000)})
    return ts, entry, secs


def noisy_pages(path, secs):
    """[(pages, unreadable pages, pages above 7.2 bits)] for the first and the last executable section.

    Unreadable: above 7.2 bits per byte and under 30% common code bytes.
    Entropy alone is not enough: a page of hashing code, all 64-bit
    constants, reaches 7.2 bits and still disassembles from its first byte
    to its last (four such pages in 0.01.2 and 1.03.0, at 40% to 42%
    common code bytes; an encrypted page has 19% to 22%)."""
    ex = [s for s in secs if s["exec"]]
    out = []
    for s in (ex[0], ex[-1]):
        n = min(s["vsize"], s["rsize"]) & ~0xFFF
        a = np.fromfile(path, dtype=np.uint8, count=n, offset=s["raw"]).reshape(-1, 4096)
        cnt = np.zeros((a.shape[0], 256), dtype=np.int32)
        np.add.at(cnt, (np.repeat(np.arange(a.shape[0]), 4096), a.reshape(-1)), 1)
        p = cnt / 4096.0
        with np.errstate(divide="ignore", invalid="ignore"):
            e = -(np.where(p > 0, p * np.log2(p), 0)).sum(axis=1)
        common = cnt[:, COMMON].sum(axis=1) / 4096.0
        out.append((a.shape[0], int(((e > 7.2) & (common < 0.30)).sum()), int((e > 7.2).sum())))
    return out


def entry_shape(path, secs, entry):
    """'compiler entry, call redirected' when the entry point is sub rsp,28h ; call X ; add rsp,28h ; jmp Y."""
    for s in secs:
        if s["rva"] <= entry < s["rva"] + s["rsize"]:
            with open(path, "rb") as f:
                f.seek(s["raw"] + entry - s["rva"])
                b = f.read(18)
            if b[:4] == bytes.fromhex("4883ec28") and b[4] == 0xE8 and b[9:13] == bytes.fromhex("4883c428") and \
                    b[13] == 0xE9:
                tgt = entry + 9 + struct.unpack_from("<i", b, 5)[0]
                last = [x for x in secs if x["exec"]][-1]
                return "compiler entry, call into the appended section" if tgt >= last["rva"] else "compiler entry"
            return "other: " + b[:8].hex()
    return "outside the sections"


NOT_READ = "not read"


def fetch(src, dst, stall=30, first=None):
    """Copy a build's executable here; everything else works on the copy.

    The archive is a network share, and a read from it can hang for six
    minutes before the system gives up. A thread stuck in such a read cannot
    be stopped, a process can: the copy is made by a child, and when the
    file here has not grown for `stall` seconds the child is killed and the
    build is recorded as not read.

    `first` is the allowance before the first byte, when it is longer: the
    archive extracts a file from a larger blob before it can send any of it
    (14 s when it is idle, more than 30 s when it is short of memory, which
    it is after a few reads in a row)."""
    first = max(stall, first or 0)
    if os.path.exists(dst):
        os.remove(dst)
    size = os.path.getsize(src)
    code = "import shutil, sys; shutil.copyfile(sys.argv[1], sys.argv[2])"
    p = subprocess.Popen([sys.executable, "-I", "-c", code, src, dst], stdout=subprocess.DEVNULL,
                         stderr=subprocess.PIPE, text=True)
    seen, when = -1, time.time()
    while True:
        try:
            p.wait(timeout=2)
            break
        except subprocess.TimeoutExpired:
            n = os.path.getsize(dst) if os.path.exists(dst) else 0
            if n != seen:
                seen, when = n, time.time()
            elif time.time() - when > (stall if n else first):
                p.kill()
                p.wait()
                raise OSError("no data from the archive for %d s, after %d of %d bytes" % (
                    stall if n else first, n, size))
    if p.returncode != 0:
        err = (p.stderr.read() or "").strip().splitlines()
        raise OSError(err[-1] if err else "the copy failed")
    if os.path.getsize(dst) != size:
        raise OSError("the copy has %d bytes, the file %d" % (os.path.getsize(dst), size))


def one(root, build, exe, outdir, tmproot):
    row = dict.fromkeys(COLS, "")
    row["build"] = build
    tmp = os.path.join(tmproot, re.sub(r"[^0-9A-Za-z._-]", "_", build))
    os.makedirs(tmp, exist_ok=True)
    src = os.path.join(tmp, "shipped.exe")
    l1 = os.path.join(tmp, "layer1.exe")
    dec = os.path.join(tmp, "dec.exe")
    t0 = time.time()
    try:
        try:
            fetch(os.path.join(root, build, exe), src)
        except OSError as e:
            row["status"] = NOT_READ
            row["note"] = ("%s: %s" % (type(e).__name__, e)).replace("\t", " ")[:300]
            return row
        ts, entry, secs = sections(src)
        row.update(size=os.path.getsize(src), sections=len(secs),
                   linked=datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%d"))
        if sum(1 for s in secs if s["exec"]) < 2:
            row["status"] = "one code section: not protected"
            return row
        r = subprocess.run([MWDEC, "decrypt", src, "-o", l1, "--no-profile", "--layer1-only", "--keep-strings"],
                           capture_output=True, text=True)
        txt = r.stdout + r.stderr
        m = re.search(r"key ([0-9A-F]{8}), starting block ([0-9A-F]{8}), range list ([0-9A-F]{8}), (\d+) cycles\s+"
                      r"\((\d+) islands, (\d+) x (\d+) pairs tried, best ([\d.]+)% common code bytes, next ([\d.]+)%",
                      txt)
        if not m or r.returncode != 0:
            mm = re.search(r"mwdec: (.*)", txt)
            row["status"] = "layer 1 not found"
            row["note"] = (mm[1] if mm else txt.strip()[-200:]).replace("\t", " ").replace(
                "no profile for this build, and no bootstrap layer found in the file: ", "")
            return row
        m2 = re.search(r"(\d+) bytes encoded, (\d+) ranges, (\d+) bytes covered", txt)
        row.update(key=m[1], block=m[2], list=m[3], cycles=m[4], pairs="%sx%s" % (m[6], m[7]), best=m[8], next=m[9],
                   ranges=m2[2] if m2 else "", layer1_bytes=m2[3] if m2 else "")
        shipped = noisy_pages(src, secs)
        after1 = noisy_pages(l1, secs)
        row.update(game_pages=shipped[0][0], noisy_shipped=shipped[0][1], noisy_layer1=after1[0][1],
                   prot_pages=shipped[1][0], prot_noisy_shipped=shipped[1][1], prot_noisy_layer1=after1[1][1],
                   entry=entry_shape(l1, secs, entry))
        table = os.path.join(outdir, re.sub(r"[^0-9A-Za-z._-]", "_", build) + ".writers.tsv")
        r = subprocess.run([sys.executable, "-I", os.path.join(HERE, "find_writers.py"), l1, "-o", table],
                           capture_output=True, text=True)
        txt = r.stdout + r.stderr
        if r.returncode != 0 or not os.path.exists(table):
            row["status"] = "layer 1 only"
            row["note"] = "writer search failed: " + txt.strip().splitlines()[-1][:200] if txt.strip() else "no output"
            return row
        rounds = re.findall(r"rows judged: (\d+) kept \((\d+) prepare another row's stash\); dropped: (\d+) decode to "
                            r"noise", txt)
        ups = re.findall(r"of them writer set-ups: (\d+)", txt)
        row.update(set_ups=ups[0] if ups else "", rounds=len(rounds), rows=sum(int(x[0]) for x in rounds),
                   rows_feeding=sum(int(x[1]) for x in rounds), noise_rows_last_round=rounds[-1][2] if rounds else "")
        r = subprocess.run([MWDEC, "decrypt", src, "-o", dec, "--no-profile", "--writers", table],
                           capture_output=True, text=True)
        txt = r.stdout + r.stderr
        if r.returncode != 0:
            row["status"] = "layer 1 only"
            row["note"] = "decrypt with the table failed: " + txt.strip().splitlines()[-1][:200]
            return row
        mm = re.search(r"string blobs: (\d+)", txt)
        row["string_blobs"] = mm[1] if mm else ""
        final = noisy_pages(dec, secs)
        row.update(noisy_final=final[0][1], prot_noisy_final=final[1][1], over72_final=final[0][2],
                   status="both layers")
        # the finer check: function pieces that neither disassemble nor have the byte statistics of code
        r = subprocess.run([sys.executable, "-I", os.path.join(HERE, "check_functions.py"), dec, "--json",
                            os.path.join(tmp, "fn.json")], capture_output=True, text=True)
        if r.returncode == 0:
            import json
            s = json.load(open(os.path.join(tmp, "fn.json")))["summary"]
            row.update(fn_pieces=s["pieces"], fn_encrypted=s["encrypted_pieces"],
                       fn_encrypted_bytes=s["encrypted_bytes"])
        return row
    except Exception as e:      # one build must not stop the run
        row["status"] = row["status"] or "error"
        row["note"] = ("%s: %s" % (type(e).__name__, e)).replace("\t", " ")[:300]
        return row
    finally:
        # the outputs of this attempt go, whatever happened
        shutil.rmtree(tmp, ignore_errors=True)
        row["seconds"] = "%.0f" % (time.time() - t0)


def read_rows(path):
    if not os.path.exists(path):
        return []
    return [dict(zip(COLS, ln.rstrip("\n").split("\t"))) for ln in open(path).read().splitlines()[1:] if ln.strip()]


def by_version(name):
    """Sort key: 1.9.0 before 1.10.0."""
    return [(0, int(p)) if p.isdigit() else (1, p) for p in re.split(r"[.\-_]", name)]


def summary(path):
    """Print what a result table says: counts by status, and one line per build."""
    rows = sorted(read_rows(path), key=lambda r: by_version(r["build"]))

    def num(r, k):
        try:
            return int(r.get(k) or 0)
        except ValueError:
            return 0

    import collections
    st = collections.Counter(r["status"] for r in rows)
    print("%d builds: %s" % (len(rows), ", ".join("%d %s" % (v, k) for k, v in st.most_common())))
    both = [r for r in rows if r["status"] == "both layers"]
    if both:
        print("with both layers: unreadable game code pages, summed over %d builds: shipped %d, after layer 1 %d, "
              "after both %d (pages above 7.2 bits whatever they hold, after both: %d)" % (
                  len(both), sum(num(r, "noisy_shipped") for r in both), sum(num(r, "noisy_layer1") for r in both),
                  sum(num(r, "noisy_final") for r in both), sum(num(r, "over72_final") for r in both)))
        left = [r for r in both if num(r, "noisy_final")]
        print("builds with unreadable game code left: %d%s" % (
            len(left), (": " + ", ".join("%s (%s)" % (r["build"], r["noisy_final"]) for r in left)) if left else ""))
        print("cycles: %s; string blobs found in %d builds" % (
            dict(collections.Counter(r["cycles"] for r in both)), sum(1 for r in both if num(r, "string_blobs"))))
    print("%-34s %-10s %6s %7s %7s %6s %5s %5s %5s %7s %13s  %s" % (
        "build", "linked", "pages", "shipped", "layer1", "final", ">7.2", "ups", "rows", "blobs", "fn enc/bytes",
        "status / note"))
    for r in rows:
        print("%-34s %-10s %6s %7s %7s %6s %5s %5s %5s %7s %13s  %s%s" % (
            r["build"][:34], r["linked"], r["game_pages"], r["noisy_shipped"], r["noisy_layer1"], r["noisy_final"],
            r.get("over72_final", ""), r["set_ups"], r["rows"], r["string_blobs"],
            ("%s/%s" % (r.get("fn_encrypted", ""), r.get("fn_encrypted_bytes", ""))) if r.get("fn_pieces") else "",
            r["status"], (" (" + r["note"][:60] + ")") if r["note"] else ""))


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--summary":
        summary(sys.argv[2])
        return 0
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("root")
    ap.add_argument("-o", "--out", required=True)
    ap.add_argument("--exe", default="ModernWarfare.exe")
    ap.add_argument("--only", help="regular expression a build folder's name must match")
    ap.add_argument("--jobs", type=int, default=3)
    ap.add_argument("--tmp", default=os.path.join(HERE, "..", "out", "tmp_test"))
    ap.add_argument("--builds", help="a table whose first column names the build folders (a third column, when "
                                     "there is one, must not be 0); saves listing the share")
    ap.add_argument("--resume", action="store_true",
                    help="keep the rows the result table already has, except the ones that could not be read, "
                         "and do the other builds")
    a = ap.parse_args()
    if a.builds:
        builds = []
        for ln in open(a.builds).read().splitlines()[1:]:
            c = [x.strip('"') for x in ln.split("\t")]
            if c and c[0] and (len(c) < 3 or c[2] not in ("0", "")):
                builds.append(c[0])
        builds.sort(key=by_version)
    else:
        builds = sorted((d for d in os.listdir(a.root) if os.path.isfile(os.path.join(a.root, d, a.exe))),
                        key=by_version)
    if a.only:
        builds = [b for b in builds if re.search(a.only, b)]
    kept = []
    if a.resume:
        kept = [r for r in read_rows(a.out) if r["status"] not in (NOT_READ, "error", "")]
        have = {r["build"] for r in kept}
        if a.only:
            # a build named again is done again
            kept = [r for r in kept if r["build"] not in set(builds)]
        else:
            builds = [b for b in builds if b not in have]
    outdir = os.path.join(os.path.dirname(os.path.abspath(a.out)), "writers")
    os.makedirs(outdir, exist_ok=True)
    os.makedirs(a.tmp, exist_ok=True)
    lock = threading.Lock()
    t0 = time.time()
    done = 0
    with open(a.out, "w", newline="\n") as f:
        f.write("\t".join(COLS) + "\n")
        for r in kept:
            f.write("\t".join(str(r.get(c, "")) for c in COLS) + "\n")
        f.flush()

        def run(b):
            nonlocal done
            row = one(a.root, b, a.exe, outdir, a.tmp)
            with lock:
                done += 1
                f.write("\t".join(str(row[c]) for c in COLS) + "\n")
                f.flush()
                print("%3d/%d %-44s %-18s layer1 %s->%s  final %s  rows %s  (%ss, total %.0fs) %s" % (
                    done, len(builds), b, row["status"], row["noisy_shipped"], row["noisy_layer1"], row["noisy_final"],
                    row["rows"], row["seconds"], time.time() - t0, row["note"][:80]), flush=True)

        with concurrent.futures.ThreadPoolExecutor(max_workers=a.jobs) as ex:
            list(ex.map(run, builds))
    shutil.rmtree(a.tmp, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
