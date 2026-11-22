"""Patch plans: the output of the analysis tools, the input of `mwdec export`.

A plan is a list of byte patches against the *decrypted* image (both code
layers removed), a list of base-relocation entries to delete, and a list of
ranges to fill with int3. Nothing in a plan is executable by itself; it is
data that says "these bytes, at this RVA".

File layout (little-endian):

    "MWPLAN1\\0"
    u32 n_patches ; n x { u32 rva ; u32 len ; u8 kind ; u8 bytes[len] }
    u32 n_drop    ; n x u32 rva                 DIR64 entries to delete
    u32 n_wipe    ; n x { u32 rva ; u32 len }   ranges to fill with 0xCC

`mwdec export` applies, in this order: wipes, then patches in file order,
then relocation drops. Later plans on the command line win over earlier.
"""
from __future__ import annotations

import struct

MAGIC = b"MWPLAN1\0"

# patch kinds (informational; mwdec counts patches per kind in its report)
KIND_BOOT = 1      # start-up path: entry point call, TLS callback entry
KIND_IMPORT = 2    # an import reference retargeted to the loader's table
KIND_STUB = 3      # a protection routine's entry replaced by `ret`
KIND_BAKE = 4      # a value the routines would have published
KIND_BYPASS = 5    # a jump over a routine call chain
KIND_FLOW = 6      # a disguised jump / call / branch rewritten as a direct one
KIND_OTHER = 7

KIND_NAMES = {1: "boot", 2: "import", 3: "stub", 4: "bake", 5: "bypass", 6: "flow", 7: "other"}


class Plan:
    def __init__(self):
        self.patches: list[tuple[int, int, bytes]] = []   # (rva, kind, bytes)
        self.drop_relocs: list[int] = []
        self.wipes: list[tuple[int, int]] = []

    def patch(self, rva: int, data: bytes, kind: int = KIND_OTHER):
        if not data:
            raise ValueError("empty patch")
        self.patches.append((int(rva), int(kind), bytes(data)))

    def drop(self, rva: int):
        self.drop_relocs.append(int(rva))

    def wipe(self, rva: int, length: int):
        if length > 0:
            self.wipes.append((int(rva), int(length)))

    def save(self, path: str):
        with open(path, "wb") as f:
            f.write(MAGIC)
            f.write(struct.pack("<I", len(self.patches)))
            for rva, kind, data in self.patches:
                f.write(struct.pack("<IIB", rva, len(data), kind))
                f.write(data)
            f.write(struct.pack("<I", len(self.drop_relocs)))
            f.write(struct.pack("<%dI" % len(self.drop_relocs), *self.drop_relocs))
            f.write(struct.pack("<I", len(self.wipes)))
            for rva, n in self.wipes:
                f.write(struct.pack("<II", rva, n))

    @classmethod
    def load(cls, path: str) -> "Plan":
        p = cls()
        b = open(path, "rb").read()
        if b[:8] != MAGIC:
            raise ValueError("not a plan file: " + path)
        o = 8
        n, = struct.unpack_from("<I", b, o)
        o += 4
        for _ in range(n):
            rva, ln, kind = struct.unpack_from("<IIB", b, o)
            o += 9
            p.patches.append((rva, kind, b[o:o + ln]))
            o += ln
        n, = struct.unpack_from("<I", b, o)
        o += 4
        p.drop_relocs = list(struct.unpack_from("<%dI" % n, b, o))
        o += 4 * n
        n, = struct.unpack_from("<I", b, o)
        o += 4
        for _ in range(n):
            p.wipes.append(struct.unpack_from("<II", b, o))
            o += 8
        return p

    def summary(self) -> str:
        kinds: dict[int, list[int]] = {}
        for _, kind, data in self.patches:
            k = kinds.setdefault(kind, [0, 0])
            k[0] += 1
            k[1] += len(data)
        parts = ["%s %d (%d bytes)" % (KIND_NAMES.get(k, str(k)), v[0], v[1]) for k, v in sorted(kinds.items())]
        return "patches: %s; relocations dropped: %d; wiped: %d ranges, %d bytes" % (
            ", ".join(parts) or "none", len(self.drop_relocs), len(self.wipes), sum(n for _, n in self.wipes))


def keep_kinds(plan: "Plan", kinds) -> "Plan":
    """A copy of `plan` with only the patches of the given kinds (no wipes,
    no relocation drops): e.g. the published values of a routine plan
    without its stubs."""
    out = Plan()
    out.patches = [p for p in plan.patches if p[1] in kinds]
    return out


if __name__ == "__main__":
    import sys
    args = sys.argv[1:]
    if args and args[0] == "--kinds":
        # planfile.py --kinds bake[,stub...] in.plan out.plan
        names = {v: k for k, v in KIND_NAMES.items()}
        sub = keep_kinds(Plan.load(args[2]), {names[n] for n in args[1].split(",")})
        sub.save(args[3])
        print(args[3], "-", sub.summary())
    else:
        for path in args:
            print(path, "-", Plan.load(path).summary())
