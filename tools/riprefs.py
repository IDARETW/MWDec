"""RIP-relative references to a set of addresses, found by scanning bytes.

No disassembly: every 4-byte field of the executable sections is read as a
signed displacement, and kept when the address it would name (the field's
end plus the displacement, with 0, 1 or 4 bytes of immediate after it) is
one of the wanted ones. A field that matches by accident is possible; the
caller decides what to do with a hit (decode around it, or count on
several independent hits agreeing).

    from riprefs import rip_refs
    refs = rip_refs(pe, [0x25A8CA90, ...])     # {target: [(rva of field, immediate bytes), ...]}
"""
import os as _os
_os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")    # numpy's math library reserves 31 MB a core when loaded; nothing here uses it
import numpy as np


def rip_refs(pe, targets, chunk=1 << 24, immediates=(0, 1, 4)):
    want = np.array(sorted(set(int(t) for t in targets)), dtype=np.int64)
    out = {int(t): [] for t in want}
    for s in pe.secs:
        if not s["exec"]:
            continue
        n = min(s["vsize"], s["rsize"])
        for lo in range(0, n - 4, chunk):
            a = pe.b[s["raw"] + lo:s["raw"] + min(n, lo + chunk + 3)]
            if len(a) < 4:
                continue
            d = (a[:-3].astype(np.uint32) | (a[1:-2].astype(np.uint32) << 8) | (a[2:-1].astype(np.uint32) << 16) |
                 (a[3:].astype(np.uint32) << 24)).view(np.int32).astype(np.int64)
            base = s["rva"] + lo + np.arange(len(d), dtype=np.int64) + 4
            for imm in immediates:
                t = base + imm + d
                hit = np.nonzero(np.isin(t, want))[0]
                for h in hit.tolist():
                    out[int(t[h])].append((s["rva"] + lo + h, imm))
    return out
