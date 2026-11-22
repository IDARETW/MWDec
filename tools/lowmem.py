"""Being a good neighbour: a long job that fits beside whatever else the machine is doing.

Used by remove_build.py and remove_all.py (and importable by anything else):

    lowmem.settle()               this process and its children: one BLAS thread, below-normal priority
    lowmem.available_gb()         physical memory free right now, and commit left
    lowmem.wait_for(gb, say)      wait until that much is free (somebody started a game), then go on
    lowmem.shards(per_gb, most)   how many emulator shards fit now
    lowmem.peak_mb()              this process's peak working set

Nothing here is needed for correctness. The pipeline's steps are sized to
run one after another in a few gigabytes; this keeps them from being
started into a machine that has none left, and from taking the processor
away from a foreground program.
"""
from __future__ import annotations

import ctypes
import os
import sys
import time


def settle(priority=True):
    # numpy's OpenBLAS reserves about 31 MB per core on import for a thread
    # pool nothing here uses: 620 MB of commit per Python process on 20 cores
    os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")
    os.environ.setdefault("OMP_NUM_THREADS", "1")
    if priority and sys.platform == "win32":
        try:        # BELOW_NORMAL_PRIORITY_CLASS; children inherit it
            ctypes.windll.kernel32.SetPriorityClass(ctypes.c_void_p(-1), 0x00004000)
        except Exception:
            pass


class _MEMSTAT(ctypes.Structure):
    _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]


def available_gb():
    """(physical memory available, commit charge still available), in GB."""
    if sys.platform != "win32":
        return 1e9, 1e9
    m = _MEMSTAT()
    m.dwLength = ctypes.sizeof(m)
    ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m))
    return m.ullAvailPhys / 2 ** 30, m.ullAvailPageFile / 2 ** 30


def wait_for(need_gb, say=None, what="", limit=3600, commit_gb=None):
    """Wait while less than need_gb of physical memory (and commit_gb of
    commit, default the same) is available. Returns the seconds waited.
    After `limit` seconds it goes on anyway: a slow step beats none."""
    commit_gb = need_gb if commit_gb is None else commit_gb
    t0 = time.time()
    told = 0.0
    while True:
        phys, commit = available_gb()
        if phys >= need_gb and commit >= commit_gb:
            break
        waited = time.time() - t0
        if waited > limit:
            if say:
                say("    still only %.1f GB free after %.0f min; going on with %s" % (phys, waited / 60, what))
            break
        if say and waited - told >= 300 or (say and told == 0.0):
            say("    %.1f GB of memory free (%.1f GB of commit), %s wants %.1f: waiting" % (phys, commit, what, need_gb))
            told = waited or 0.001
        time.sleep(20)
    return time.time() - t0


def shards(per_gb=0.45, most=8, least=1, reserve_gb=1.5):
    """How many emulator shards to run now: what fits in the memory that is
    free, leaving reserve_gb for everything else, and no more than there
    are cores to run them."""
    phys, commit = available_gb()
    n = int((min(phys, commit) - reserve_gb) / per_gb)
    return max(least, min(most, n, max(1, (os.cpu_count() or 2) - 2)))


class _PMC(ctypes.Structure):
    _fields_ = [("cb", ctypes.c_ulong), ("PageFaultCount", ctypes.c_ulong), ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t), ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t), ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t), ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t), ("PrivateUsage", ctypes.c_size_t)]


def now_mb():
    """(working set, commit) of this process right now, in MB."""
    if sys.platform != "win32":
        return 0, 0
    p = _PMC()
    p.cb = ctypes.sizeof(p)
    ctypes.windll.psapi.GetProcessMemoryInfo(ctypes.c_void_p(-1), ctypes.byref(p), p.cb)
    return p.WorkingSetSize >> 20, p.PrivateUsage >> 20


def peak_mb(handle=None):
    """(peak working set, peak commit) in MB of this process, or of the
    process whose handle is given (a subprocess.Popen's `_handle`)."""
    if sys.platform != "win32":
        return 0, 0
    p = _PMC()
    p.cb = ctypes.sizeof(p)
    h = ctypes.c_void_p(-1 if handle is None else int(handle))
    if not ctypes.windll.psapi.GetProcessMemoryInfo(h, ctypes.byref(p), p.cb):
        return 0, 0
    return p.PeakWorkingSetSize >> 20, p.PeakPagefileUsage >> 20
