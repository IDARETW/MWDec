"""Run `mwdec info` over a folder of builds and tabulate what it finds.

    py -3 tools\\survey_builds.py O:\\Builds\\odin -o out\\builds\\survey.tsv [--exe ModernWarfare.exe]

Reads each executable (nothing is run). One row per build: sections, sizes,
link time stamp, and the bootstrap layer's parameters as `mwdec` finds them
in the file, or why it found none.
"""
import argparse
import datetime
import os
import re
import struct
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
MWDEC = os.path.join(HERE, "..", "build", "Release", "mwdec.exe")


def header(path):
    with open(path, "rb") as f:
        raw = f.read(0x1000)
    pe = struct.unpack_from("<I", raw, 0x3C)[0]
    nsec = struct.unpack_from("<H", raw, pe + 6)[0]
    ts = struct.unpack_from("<I", raw, pe + 8)[0]
    opt = struct.unpack_from("<H", raw, pe + 20)[0]
    entry = struct.unpack_from("<I", raw, pe + 24 + 16)[0]
    soi = struct.unpack_from("<I", raw, pe + 24 + 56)[0]
    o = pe + 24 + opt
    secs = []
    for i in range(nsec):
        h = raw[o + 40 * i:o + 40 * i + 40]
        vs, va, rs, ro = struct.unpack_from("<IIII", h, 8)
        ch = struct.unpack_from("<I", h, 36)[0]
        secs.append((h[:8].rstrip(b"\0").decode("latin1"), va, vs, bool(ch & 0x20000000)))
    return ts, entry, soi, secs


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("root")
    ap.add_argument("-o", "--out", required=True)
    ap.add_argument("--exe", default="ModernWarfare.exe")
    ap.add_argument("--only", help="regular expression a build folder's name must match")
    a = ap.parse_args()
    builds = sorted(d for d in os.listdir(a.root) if os.path.isdir(os.path.join(a.root, d)))
    if a.only:
        builds = [b for b in builds if re.search(a.only, b)]
    t0 = time.time()
    with open(a.out, "w", newline="\n") as f:
        f.write("build\tsize\tlinked\tsections\tcode_sections\tentry\tsize_of_image\tstatus\tkey\tblock\tlist\tcycles\t"
                "islands\tpairs\tbest\tnext\tranges\tbytes\tseconds\n")
        for b in builds:
            p = os.path.join(a.root, b, a.exe)
            if not os.path.isfile(p):
                continue
            t = time.time()
            try:
                ts, entry, soi, secs = header(p)
            except Exception as e:
                f.write("%s\t\t\t\t\t\t\tnot a PE file: %s\n" % (b, e))
                continue
            r = subprocess.run([MWDEC, "info", p, "--no-profile"], capture_output=True, text=True)
            txt = r.stdout + r.stderr
            m = re.search(r"key ([0-9A-F]{8}), starting block ([0-9A-F]{8}), range list ([0-9A-F]{8}), (\d+) cycles\s+"
                          r"\((\d+) islands, (\d+) x (\d+) pairs tried, best ([\d.]+)% common code bytes, next ([\d.]+)%",
                          txt)
            m2 = re.search(r"(\d+) bytes encoded, (\d+) ranges, (\d+) bytes covered", txt)
            if m:
                status = "found"
                cols = [m[1], m[2], m[3], m[4], m[5], "%sx%s" % (m[6], m[7]), m[8], m[9],
                        m2[2] if m2 else "", m2[3] if m2 else ""]
            else:
                mm = re.search(r"mwdec: (.*)", txt)
                status = (mm[1] if mm else txt.strip()[:160]).replace("\t", " ")
                status = status.replace("no profile for this build, and no bootstrap layer found in the file: ", "")
                cols = [""] * 10
            row = [b, str(os.path.getsize(p)),
                   datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%d"),
                   str(len(secs)), str(sum(1 for s in secs if s[3])), "%08X" % entry, "%08X" % soi, status] + cols + \
                  ["%.0f" % (time.time() - t)]
            f.write("\t".join(row) + "\n")
            f.flush()
            print("%-46s %-9s %s  (%.0fs, total %.0fs)" % (b, status[:9], " ".join(cols[:4]), time.time() - t,
                                                           time.time() - t0), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
