"""Do the functions of an image read as code? A finer check than entropy.

    py -3 tools\\check_functions.py image.exe [--list N] [--json out.json] [--section N]

Every record of the exception directory names a piece of a function by its
first and last byte. Each piece that lies in the game's code section (the
first executable one) is disassembled from its first byte, straight
through. A piece counts as unreadable when

  * the disassembly meets bytes that are no instruction before the end, or
  * it contains an instruction compiled game code does not have: port
    I/O, `hlt`, `cli`, an interrupt return, a far transfer and the like.

Encrypted bytes fail one of the two within a few dozen bytes. So does
obfuscated code with junk bytes on dead paths, of which build 19936 has
megabytes, so the bytes are asked as well. A piece of 32 bytes or more
that fails the disassembly is

  * a table, when under 30% of its bytes are common code bytes but its
    entropy is low (a jump table the compiler put after a `ret`: about 4
    bits per byte);
  * encrypted, when it has between 13% and 30% common code bytes (an
    encrypted run has about 20%, code 40% and more) and at least nine
    tenths of the entropy a random run of its length would have.

A page of entropy cannot see a 300-byte function that is still encrypted
in the middle of readable code; this can. It is still a statistic: an
encrypted piece under 32 bytes is not judged at all, and a short piece of
dense hand-written code can pass for noise (eight pieces of 54 bytes do on
build 19936).
"""
from __future__ import annotations

import argparse
import json
import os
import sys

import capstone
import os as _os
_os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")    # numpy's math library reserves 31 MB a core when loaded; nothing here uses it
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, ".."))
from find_bootstrap import COMMON  # noqa: E402
from mwdec.pe import Image  # noqa: E402

MIN = 32            # bytes below which a piece is not judged
SHARE = 0.30        # common code bytes below which a piece that fails to decode counts as encrypted

# mnemonics a compiler does not emit into user-mode game code
RARE = frozenset("""in out insb insw insd outsb outsw outsd hlt cli sti iret iretd iretq retf retfq lcall ljmp
int1 into sysret sysretq sysexit sysenter rsm wrmsr rdmsr clts invd wbinvd lgdt lidt lldt ltr lmsw sgdt sidt
sldt str smsw salc xlatb loop loope loopne jrcxz jecxz enter leave bound arpl aaa aas aad aam daa das
fisttp ffree fdecstp fincstp fnsave frstor fnstenv fldenv fbld fbstp""".split()) - {"leave"}


def check(im: Image, section=None, progress=None):
    """Returns (rows, summary). rows: (begin, end, why, share) for the pieces counted as encrypted."""
    ex = [s for s in im.sections if s.executable]
    sec = ex[0] if section is None else im.sections[section]
    lo, hi = sec.rva, sec.rva + min(sec.vsize, sec.rsize)
    rf = im.runtime_functions()
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    mem = im.mem
    bad = []
    n = total = bad_bytes = undecoded = undecoded_bytes = small = tables = table_bytes = 0
    seen = set()
    for row in rf:
        b, e = int(row[0]), int(row[1])
        if not (lo <= b < e <= hi) or e - b > 4_000_000 or (b, e) in seen:
            continue
        seen.add((b, e))
        n += 1
        total += e - b
        if e - b < MIN:
            small += 1
            continue
        raw = bytes(mem[b:e])
        at = b
        why = None
        for addr, size, mnem, _ in md.disasm_lite(raw, b):
            at = addr + size
            if mnem in RARE:
                why = "has `%s` at %08X" % (mnem, addr)
                break
        if why is None and at < e:
            why = "no instruction at %08X" % at
        if why:
            undecoded += 1
            undecoded_bytes += e - b
            a = np.frombuffer(raw, dtype=np.uint8)
            share = float(COMMON[a].mean())
            if share < SHARE:
                c = np.bincount(a, minlength=256).astype(float)
                p = c[c > 0] / len(a)
                ent = float(-(p * np.log2(p)).sum())
                if share > 0.13 and ent > 0.9 * min(8.0, float(np.log2(len(a)))):
                    bad.append((b, e, why, share))
                    bad_bytes += e - b
                else:
                    tables += 1
                    table_bytes += e - b
        if progress and n % 20000 == 0:
            progress(n)
    return bad, {"section": sec.name, "pieces": n, "bytes": total, "not_judged_small": small,
                 "fail_disassembly": undecoded, "fail_disassembly_bytes": undecoded_bytes,
                 "tables": tables, "table_bytes": table_bytes,
                 "encrypted_pieces": len(bad), "encrypted_bytes": bad_bytes}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("exe")
    ap.add_argument("--list", type=int, default=0, help="print the first N unreadable pieces")
    ap.add_argument("--json", help="write the summary and all unreadable pieces here")
    ap.add_argument("--section", type=int, help="index of the section to check (default: the first executable one)")
    a = ap.parse_args()
    im = Image(a.exe)
    bad, s = check(im, a.section)
    print("%s: %d function pieces in %s, %d bytes (%d under %d bytes, not judged)\n"
          "   fail the disassembly: %d pieces, %d bytes\n"
          "   of them tables (under %d%% common code bytes, low entropy): %d pieces, %d bytes\n"
          "   of them counted as encrypted: %d pieces (%.3f%%), %d bytes (%.3f%%)" % (
              os.path.basename(a.exe), s["pieces"], s["section"], s["bytes"], s["not_judged_small"], MIN,
              s["fail_disassembly"], s["fail_disassembly_bytes"], int(SHARE * 100), s["tables"], s["table_bytes"],
              s["encrypted_pieces"], 100.0 * s["encrypted_pieces"] / max(1, s["pieces"]), s["encrypted_bytes"],
              100.0 * s["encrypted_bytes"] / max(1, s["bytes"])))
    for b, e, why, share in sorted(bad, key=lambda x: x[0] - x[1])[:a.list]:
        print("   %08X-%08X  %7d bytes  %4.1f%% common  %s" % (b, e, e - b, 100 * share, why))
    if a.json:
        with open(a.json, "w") as f:
            json.dump({"summary": s, "encrypted": [[b, e, why, round(share, 4)] for b, e, why, share in bad]}, f)
    return 0


if __name__ == "__main__":
    sys.exit(main())
