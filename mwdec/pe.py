"""Minimal PE32+ reader: just what a static decryptor needs.

The image is held as a flat `bytearray` laid out by RVA (the way the loader
maps it), so every address in this package is an RVA and an index at once.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

import os as _os
_os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")    # numpy's math library reserves 31 MB a core when loaded; nothing here uses it
import numpy as np

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_WRITE = 0x80000000

DIR_EXPORT, DIR_IMPORT, DIR_RESOURCE, DIR_EXCEPTION, DIR_SECURITY, \
    DIR_BASERELOC, DIR_DEBUG, _, _, DIR_TLS = range(10)


@dataclass(frozen=True)
class Section:
    index: int
    name: str
    rva: int
    vsize: int
    raw: int
    rsize: int
    chars: int

    @property
    def end(self) -> int:
        return self.rva + self.vsize

    @property
    def executable(self) -> bool:
        return bool(self.chars & IMAGE_SCN_MEM_EXECUTE)


class Image:
    """A PE file mapped by RVA."""

    @property
    def file(self) -> bytes:
        """The file's bytes, read when asked for. They used to be kept for
        the life of the object, 300 MB beside the mapped copy, though only
        check_clean.py and to_file_bytes() ever look at them."""
        with open(self.path, "rb") as f:
            return f.read()

    def __init__(self, path: str):
        self.path = path
        # the file is read through a map: its pages are the system's file
        # cache, not memory of this process, and are let go when it is done
        import mmap
        with open(path, "rb") as f:
            fb = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        pe = struct.unpack_from("<I", fb, 0x3C)[0]
        if fb[pe:pe + 4] != b"PE\0\0":
            raise ValueError("not a PE file")
        self.pe_offset = pe
        nsec, = struct.unpack_from("<H", fb, pe + 6)
        optsz, = struct.unpack_from("<H", fb, pe + 20)
        opt = pe + 24
        if struct.unpack_from("<H", fb, opt)[0] != 0x20B:
            raise ValueError("expected a PE32+ image")
        self.opt_offset = opt
        self.entry_rva, = struct.unpack_from("<I", fb, opt + 16)
        self.image_base, = struct.unpack_from("<Q", fb, opt + 24)
        self.size_of_image, = struct.unpack_from("<I", fb, opt + 56)
        self.size_of_headers, = struct.unpack_from("<I", fb, opt + 60)
        ndirs, = struct.unpack_from("<I", fb, opt + 108)
        self.dirs = [struct.unpack_from("<II", fb, opt + 112 + 8 * i)
                     for i in range(ndirs)]
        self.sections: list[Section] = []
        base = opt + optsz
        self.section_table_offset = base
        for i in range(nsec):
            o = base + 40 * i
            name = fb[o:o + 8].rstrip(b"\0").decode("latin1")
            vsize, rva, rsize, raw = struct.unpack_from("<IIII", fb, o + 8)
            chars, = struct.unpack_from("<I", fb, o + 36)
            self.sections.append(Section(i, name, rva, vsize, raw, rsize,
                                         chars))
        size = (self.size_of_image + 0xFFF) & ~0xFFF
        self.mem = bytearray(size)
        self.mem[:self.size_of_headers] = fb[:self.size_of_headers]
        for s in self.sections:
            n = min(s.rsize, s.vsize) if s.vsize else s.rsize
            self.mem[s.rva:s.rva + n] = fb[s.raw:s.raw + n]
        fb.close()
        self._relocs = None

    # ---- lookup ----------------------------------------------------------
    def section_of(self, rva: int) -> Section | None:
        for s in self.sections:
            if s.rva <= rva < s.rva + max(s.vsize, s.rsize):
                return s
        return None

    def exec_sections(self) -> list[Section]:
        return [s for s in self.sections if s.executable]

    def is_exec(self, rva: int) -> bool:
        s = self.section_of(rva)
        return bool(s and s.executable)

    def va(self, rva: int) -> int:
        return self.image_base + rva

    def rva_of(self, va: int) -> int | None:
        r = va - self.image_base
        return r if 0 <= r < len(self.mem) else None

    # ---- typed reads -----------------------------------------------------
    def u8(self, rva): return self.mem[rva]
    def u16(self, rva): return struct.unpack_from("<H", self.mem, rva)[0]
    def u32(self, rva): return struct.unpack_from("<I", self.mem, rva)[0]
    def i32(self, rva): return struct.unpack_from("<i", self.mem, rva)[0]
    def u64(self, rva): return struct.unpack_from("<Q", self.mem, rva)[0]
    def read(self, rva, n): return bytes(self.mem[rva:rva + n])

    def cstr(self, rva: int, limit: int = 256) -> str:
        end = self.mem.find(b"\0", rva, rva + limit)
        return self.mem[rva:end if end >= 0 else rva + limit].decode("latin1")

    def view(self, s: Section) -> np.ndarray:
        """Writable numpy view of a section's bytes inside the mapped image."""
        return np.frombuffer(self.mem, dtype=np.uint8, count=s.rsize,
                             offset=s.rva)

    # ---- directories -----------------------------------------------------
    def relocations(self) -> np.ndarray:
        """Sorted RVAs of every DIR64 base relocation."""
        if self._relocs is None:
            rva, size = self.dirs[DIR_BASERELOC]
            out = []
            off = rva
            end = rva + size
            while off + 8 <= end:
                page, bsz = struct.unpack_from("<II", self.mem, off)
                if bsz < 8:
                    break
                ents = np.frombuffer(self.mem, dtype="<u2",
                                     count=(bsz - 8) // 2, offset=off + 8)
                sel = ents[(ents >> 12) == 10]
                out.append(page + (sel & 0xFFF).astype(np.int64))
                off += bsz
            self._relocs = np.sort(np.concatenate(out)) if out else \
                np.zeros(0, dtype=np.int64)
        return self._relocs

    def tls_callbacks(self) -> list[int]:
        rva, size = self.dirs[DIR_TLS]
        if not rva:
            return []
        array_va = struct.unpack_from("<Q", self.mem, rva + 24)[0]
        arr = self.rva_of(array_va)
        out = []
        while arr is not None:
            v = self.u64(arr)
            if not v:
                break
            out.append(v - self.image_base)
            arr += 8
        return out

    def imports(self) -> list[tuple[int, str, str]]:
        """(IAT slot RVA, dll, name) for every import."""
        rva, _ = self.dirs[DIR_IMPORT]
        out = []
        i = 0
        while rva:
            oft, _, _, name_rva, ft = struct.unpack_from(
                "<IIIII", self.mem, rva + 20 * i)
            if not (oft or ft or name_rva):
                break
            dll = self.cstr(name_rva)
            j = 0
            while True:
                thunk = self.u64((oft or ft) + 8 * j)
                if not thunk:
                    break
                name = ("ord#%d" % (thunk & 0xFFFF)) if thunk >> 63 \
                    else self.cstr((thunk & 0x7FFFFFFF) + 2)
                out.append((ft + 8 * j, dll, name))
                j += 1
            i += 1
        return out

    def runtime_functions(self) -> np.ndarray:
        """(begin, end, unwind) rows of the exception directory."""
        rva, size = self.dirs[DIR_EXCEPTION]
        n = size // 12
        return np.frombuffer(self.mem, dtype="<u4", count=3 * n,
                             offset=rva).reshape(n, 3)

    # ---- writing a file back ---------------------------------------------
    def to_file_bytes(self) -> bytes:
        """Serialise with the original file layout (same offsets and sizes),
        taking section contents from the mapped image."""
        out = bytearray(self.file)
        for s in self.sections:
            n = min(s.rsize, s.vsize) if s.vsize else s.rsize
            out[s.raw:s.raw + n] = self.mem[s.rva:s.rva + n]
        return bytes(out)
