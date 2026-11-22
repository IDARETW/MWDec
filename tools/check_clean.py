"""Static checks on an image written by `mwdec export`.

Nothing is run. Each check counts something that should be zero (or says
how much is left) once the protection has been removed:

  * PE: checksum, relocation entries that do not hold an image address,
    certificate directory.
  * Imports: references to the second import table.
  * Strings: engine string blobs still flagged as encrypted.
  * Start-up: does the entry point's first call lead into routine chains;
    do any TLS callbacks.
  * Routine calls: how many of the protection's call stubs are still
    present as code (the long-form `sub rsp,8` that every stub contains),
    and how many disguised jumps (`jmp [rsp-8]`).
  * Noise: 4 KB code pages above 7.2 bits per byte.

    py -3 check_clean.py clean.exe [--imports imports.tsv] [--json out.json]
"""
from __future__ import annotations

import argparse
import json
import os
import struct
import sys

import os as _os
_os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")    # numpy's math library reserves 31 MB a core when loaded; nothing here uses it
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, ".."))
from entry_layout import Walker, fold  # noqa: E402
from mwdec.pe import Image  # noqa: E402

STUB = bytes.fromhex("4881EC08000000")      # sub rsp, 8 (long encoding)
CJMP = bytes.fromhex("FF6424F8")            # jmp qword ptr [rsp-8]


def pe_checksum(fb: bytes, field: int) -> int:
    a = np.frombuffer(fb[:len(fb) & ~1], dtype="<u2").astype(np.uint64)
    total = int(a.sum()) - int(a[field // 2]) - int(a[field // 2 + 1])
    if len(fb) & 1:
        total += fb[-1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (total + len(fb)) & 0xFFFFFFFF


def count(buf: bytes, pat: bytes) -> int:
    n = 0
    i = buf.find(pat)
    while i >= 0:
        n += 1
        i = buf.find(pat, i + 1)
    return n


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("exe")
    ap.add_argument("--imports", help="TSV from `mwdec imports` (enables the import check)")
    ap.add_argument("--json")
    ap.add_argument("--live", help="live-byte bitmap from devirt_flow.py --live: also count what is left "
                                   "in code the game's own roots reach")
    a = ap.parse_args()
    im = Image(a.exe)
    fb = im.file
    rep: dict = {}

    opt = im.opt_offset
    stored, = struct.unpack_from("<I", fb, opt + 64)
    rep["checksum_ok"] = stored == pe_checksum(fb, opt + 64)
    rep["certificate_directory"] = im.dirs[4][0] if len(im.dirs) > 4 else 0
    rel = np.asarray(im.relocations(), dtype=np.int64)
    vals = np.array([im.u64(int(r)) for r in rel], dtype=np.uint64) if len(rel) else np.zeros(0, np.uint64)
    bad = int(((vals < im.image_base) | (vals >= im.image_base + len(im.mem))).sum())
    rep["relocations"] = int(len(rel))
    rep["relocations_not_an_image_address"] = bad

    if a.imports:
        alias = [int(f[1], 16) for f in (l.split("\t") for l in open(a.imports, encoding="utf-8").read().splitlines()[1:]) if f[1]]
        slots = np.array(sorted(alias), dtype=np.int64)
        refs = 0
        for s in im.exec_sections():
            size = min(s.rsize, s.vsize)
            b = np.frombuffer(im.mem, dtype=np.uint8, count=size, offset=s.rva)
            modrm = (b[1:-4] & 0xC7) == 0x05          # RIP-relative ModRM just before the field
            pos = np.nonzero(modrm)[0] + 2
            d = (b[pos].astype(np.int64) | (b[pos + 1].astype(np.int64) << 8)
                 | (b[pos + 2].astype(np.int64) << 16) | (b[pos + 3].astype(np.int64) << 24))
            d = np.where(d >= 1 << 31, d - (1 << 32), d)
            opc = b[pos - 2]
            tgt = s.rva + pos + 4 + d
            hit = np.isin(tgt, slots) & ((opc == 0xFF) | (opc == 0x8B))
            refs += int(hit.sum())
        rep["references_to_second_import_table"] = refs

    # engine string blobs still encrypted (.data, 8-aligned, flag byte 1, printable after XOR)
    left = 0
    for s in im.sections:
        if s.name != ".data":
            continue
        raw = bytes(im.mem[s.rva:s.rva + min(s.rsize, s.vsize)])
        hdr = np.frombuffer(raw[:len(raw) // 8 * 8], dtype="<u4")[2::2]
        for i in np.nonzero(((hdr >> 24) == 1) & ((hdr & 0xFFFFFF) >= 4) & ((hdr & 0xFFFFFF) <= 0x4000))[0]:
            o = int(i) * 8
            n = int(hdr[i]) & 0xFFFFFF
            if o + 0xC + n >= len(raw) or raw[o + 0xC + n] != 0:
                continue
            key = raw[o:o + 8]
            pt = bytes(v ^ key[j & 7] for j, v in enumerate(raw[o + 0xC:o + 0xC + n]))
            if all(32 <= c < 127 or c in (9, 10, 13, 0x1E, 0x1F) for c in pt):
                left += 1
    rep["string_blobs_still_encrypted"] = left

    w = Walker(im, {})
    md = w.md
    pc = im.entry_rva
    rep["entry_point_calls_a_thunk"] = False
    for _ in range(4):
        i = next(md.disasm(bytes(im.mem[pc:pc + 16]), pc), None)
        if i is None:
            break
        if i.mnemonic == "call" and i.size == 5:
            lines = fold(w.walk(i.operands[0].imm))
            rep["entry_point_calls_a_thunk"] = bool(lines and lines[0][1].startswith("; save context"))
            rep["entry_point_call_target"] = i.operands[0].imm
            break
        pc += i.size
    rep["tls_callbacks_with_chains"] = sum(
        1 for cb in im.tls_callbacks()
        if (lambda l: bool(l and l[0][1].startswith("; save context")))(fold(w.walk(cb))))

    live = None
    if a.live:
        bits = np.unpackbits(np.load(a.live))
        regions = json.load(open(os.path.splitext(a.live)[0] + ".json"))["regions"]

        def live(rva):
            for lo, hi, off in regions:
                if lo <= rva < hi:
                    return bool(bits[rva - lo + off])
            return False

    def positions(buf, pat):
        i = buf.find(pat)
        while i >= 0:
            yield i
            i = buf.find(pat, i + 1)

    rep["sections"] = []
    for s in im.exec_sections():
        buf = bytes(im.mem[s.rva:s.rva + min(s.rsize, s.vsize)])
        if live is not None:
            rep.setdefault("live", []).append({
                "rva": s.rva, "name": s.name,
                "routine_call_stubs": sum(1 for i in positions(buf, STUB) if live(s.rva + i)),
                "disguised_jumps": sum(1 for i in positions(buf, CJMP) if live(s.rva + i))})
        pages = np.frombuffer(buf[:len(buf) & ~0xFFF], dtype=np.uint8).reshape(-1, 4096)
        noisy = 0
        int3 = 0
        for row in pages:
            c = np.bincount(row, minlength=256)
            int3 += int(c[0xCC])
            p = c[c > 0] / 4096.0
            noisy += float(-(p * np.log2(p)).sum()) > 7.2
        rep["sections"].append({
            "rva": s.rva, "name": s.name, "bytes": len(buf),
            "routine_call_stubs": count(buf, STUB), "disguised_jumps": count(buf, CJMP),
            "pages": int(pages.shape[0]), "noisy_pages": int(noisy), "int3_bytes": int3})

    rep["exception_records"] = im.dirs[3][1] // 12 if len(im.dirs) > 3 else 0
    for k, v in rep.items():
        if k not in ("sections", "live"):
            print("%-40s %s" % (k, hex(v) if k.endswith("target") else v))
    for s in rep.get("live", []):
        print("in code the game reaches, %-6s %08X: %d call stubs, %d disguised jumps" % (
            s["name"], s["rva"], s["routine_call_stubs"], s["disguised_jumps"]))
    print("%-10s %-9s %12s %10s %12s %8s %12s" % ("section", "rva", "bytes", "call stubs", "disg. jumps", "noisy pg", "int3 bytes"))
    for s in rep["sections"]:
        print("%-10s %08X  %12d %10d %12d %8d %12d" % (s["name"], s["rva"], s["bytes"], s["routine_call_stubs"],
                                                      s["disguised_jumps"], s["noisy_pages"], s["int3_bytes"]))
    if a.json:
        json.dump(rep, open(a.json, "w"), indent=1)


if __name__ == "__main__":
    main()
