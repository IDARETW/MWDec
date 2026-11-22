"""Find a writer's key and encoding from its stash alone.

    py -3 tools\\find_writer_key.py image.exe --stash RVA [--variant Xor|Sub|XorAuto|MulRol]

A writer keeps an encoded copy of what it writes (the stash) and one dword
of key. There are four encodings (src/writers.h), and in all four the
first few plaintext words depend only on the key and the first few stash
words. So every one of the 2^32 keys is tried against each encoding: the
first 16 bytes are decoded, and a key is kept when most of them are bytes
that are common in compiled code. The few keys that survive decode 4 KB,
and the share of common bytes there picks the winner (noise gives about a
fifth, code more than half).

This only finds writers whose output is code. A writer that prepares
another writer's stash produces noise under every key.
"""
import argparse
import os
import struct
import sys
import time

import os as _os
_os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")    # numpy's math library reserves 31 MB a core when loaded; nothing here uses it
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from find_bootstrap import PE, COMMON  # noqa: E402

VARIANTS = ("Xor", "Sub", "XorAuto", "MulRol")
M = 0xFFFFFFFF


def decode_vec(e, variant, K):
    """First len(e) plaintext words for an array of keys K (uint32).
    Returns a (len(K), len(e)) uint32 array."""
    out = np.empty((len(K), len(e)), dtype=np.uint32)
    if variant == "Xor":
        for i, w in enumerate(e):
            out[:, i] = K ^ np.uint32(w)
    elif variant == "Sub":
        for i, w in enumerate(e):
            out[:, i] = K - np.uint32(w)
    elif variant == "XorAuto":
        k = K.copy()
        for i, w in enumerate(e):
            p = k ^ np.uint32(w)
            out[:, i] = p
            k += p
    else:
        a = K.copy()
        b = K & np.uint32(31)
        for i, w in enumerate(e):
            s = b & np.uint32(31)
            a = (a << s) | (a >> ((np.uint32(32) - s) & np.uint32(31)))
            p = np.uint32(w) - a * b
            out[:, i] = p
            b = ~p ^ b
    return out


def decode_one(e, variant, K):
    out = []
    if variant == "Xor":
        return [w ^ K for w in e]
    if variant == "Sub":
        return [(K - w) & M for w in e]
    if variant == "XorAuto":
        k = K
        for w in e:
            p = w ^ k
            out.append(p)
            k = (k + p) & M
        return out
    a, b = K, K & 31
    for w in e:
        s = b & 31
        a = ((a << s) | (a >> (32 - s))) & M if s else a
        p = (w - a * b) & M
        out.append(p)
        b = (~p ^ b) & M
    return out


def common_share(words):
    by = np.frombuffer(struct.pack("<%dI" % len(words), *words), dtype=np.uint8)
    return float(COMMON[by].mean())


def search(stash, variants=VARIANTS, log=lambda s: None, chunk=1 << 24, first=2, need=6):
    """stash: bytes (at least 4 KB). Returns [(share, variant, key)] best first."""
    e = struct.unpack("<%dI" % (len(stash) // 4), stash[:len(stash) // 4 * 4])
    head = np.array(e[:first], dtype=np.uint32)
    found = []
    for v in variants:
        t0 = time.time()
        keep = []
        for lo in range(0, 1 << 32, chunk):
            K = np.arange(lo, lo + chunk, dtype=np.uint64).astype(np.uint32)
            with np.errstate(over="ignore"):
                p = decode_vec(head, v, K)
            ok = COMMON[p.view(np.uint8)].sum(axis=1) >= need
            keep.append(K[ok])
        keep = np.concatenate(keep)
        # second stage: 80 bytes
        if len(keep):
            with np.errstate(over="ignore"):
                p = decode_vec(np.array(e[:20], dtype=np.uint32), v, keep)
            sh = COMMON[p.view(np.uint8)].mean(axis=1)
            keep = keep[sh >= 0.42]
        # the final score reads the whole stash (the caller cuts it to the
        # writer's byte count): past its end the decode is noise again
        best = sorted(((common_share(decode_one(e[:1024], v, int(k))), v, int(k)) for k in keep), reverse=True)
        log("%-7s %d keys pass the first two stages; best %s (%.0f s)" % (
            v, len(keep), ["%08X %.1f%%" % (k, 100 * s) for s, _, k in best[:3]], time.time() - t0))
        found += best[:5]
    return sorted(found, reverse=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("exe")
    ap.add_argument("--stash", type=lambda s: int(s, 16), required=True, action="append")
    ap.add_argument("--variant", action="append", choices=VARIANTS)
    ap.add_argument("--bytes", type=int, default=4096,
                    help="how many bytes the writer writes (the total of its range list); at most 4096 are scored")
    a = ap.parse_args()
    pe = PE(a.exe)
    for st in a.stash:
        o = pe.off(st)
        stash = pe.b[o:o + max(80, min(a.bytes, 4096)) // 4 * 4].tobytes()
        print("stash %08X: %s" % (st, stash[:16].hex()), flush=True)
        res = search(stash, a.variant or VARIANTS, log=lambda s: print("  " + s, flush=True))
        for sh, v, k in res[:3]:
            print("  %-7s key %08X  common bytes %.1f%%" % (v, k, 100 * sh))
    return 0


if __name__ == "__main__":
    sys.exit(main())
