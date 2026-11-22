"""Remove the protection from every build in a folder.

    py -3 tools\\remove_all.py O:\\Builds\\odin --results out\\removed --builds manifest.tsv
                             [--deliver DIR | --deliver-ssh user@host:/path] [--only REGEX] [--jobs 1]
                             [--resume] [--nas-guard user@host]

For each <root>\\<build>\\ModernWarfare.exe (read only; nothing is run):

  1. the file is copied here by a child process (the root may be a network
     share that stalls; one copy at a time);
  2. `remove_build.py` makes the cleaned executable from it;
  3. the cleaned executable is delivered: copied to <DIR>\\<build>\\ or, with
     `--deliver-ssh`, sent with scp to <path>/<build>/ and its size checked
     there;
  4. the local copy of the shipped file, the intermediate executables and,
     once delivered, the cleaned executable are deleted.

What stays per build, in <results>\\<build>\\: the writer table, the routine
table, the small plans, the reports and `summary.json`. The two large
plans (flow, dead) are deleted; they are remade by running the build again.
`<results>\\results.tsv` has one row per build; `--resume` skips the builds
whose row says `exported` (and `delivered`, when delivery was asked for).

`--nas-guard user@host` asks the archive server, before each copy, how the
service behind the share is doing (its memory against its limit, and how
much of the time it is stalled), and waits while it is under pressure.
"""
from __future__ import annotations

import argparse
import collections
import concurrent.futures
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import remove_build  # noqa: E402  (first: it settles this process: one BLAS thread, below-normal priority)
import lowmem  # noqa: E402
from test_builds import by_version, fetch  # noqa: E402

COLS = ["build", "size", "status", "delivered", "seconds", "writer_rows", "routines", "three_slots", "chains",
        "check_sequences", "published_dwords", "string_blobs", "fn_pieces", "fn_encrypted", "fn_encrypted_bytes",
        "export_bytes", "why", "startup_chains_skipped", "constructs", "constructs_folded", "branches_rewritten",
        "branches_left", "stubs_kept", "wiped_bytes", "verify_equal", "verify_different", "verify_no_verdict",
        "verify_note", "dump", "dump_code_same", "dump_function_records", "dump_function_starts", "dump_pointers",
        "dump_loaded_at", "dump_note", "start_stretches", "start_different", "start_end", "start_note",
        "export_seconds"]
SMALL = ("writers.tsv", "routines.json", "routine_stubs.plan", "checks.plan", "checks.json", "boot.plan",
         "boot.json", "stubs.plan", "imports.tsv", "flow.json", "clean.json", "functions.json", "summary.json",
         "log.txt", "starts_folds.txt", "verify.json", "verify.log", "dump_check.json", "dump_check.log",
         "start.json", "start.log", "junk.json")


def dump_check(a, res, clean, src, fetch_lock, say):
    """Compare the export with a memory dump of the same build, address for
    address (check_dump.py). Returns the row's dump_* fields."""
    W = lambda n: os.path.join(res, n)      # noqa: E731
    out = dict.fromkeys(("dump", "dump_code_same", "dump_function_records", "dump_function_starts",
                         "dump_pointers", "dump_loaded_at", "dump_note"), "")
    local = W("dump.exe")
    try:
        with fetch_lock:
            for attempt in (1, 2):
                if a.nas_guard:
                    nas_wait(a.nas_guard, say)
                try:
                    fetch(src, local, stall=a.fetch_stall, first=a.fetch_first)
                    break
                except OSError:
                    if attempt == 2:
                        raise
        cmd = [sys.executable, "-I", os.path.join(os.path.dirname(os.path.abspath(__file__)), "check_dump.py"),
               clean, local, "--json", W("dump_check.json")]
        if os.path.exists(W("dec.exe")):
            cmd += ["--dec", W("dec.exe")]
            if os.path.exists(W("layer1.exe")):
                cmd += ["--layer1", W("layer1.exe")]
        r = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
        with open(W("dump_check.log"), "w", encoding="utf-8") as f:
            f.write(r.stdout + r.stderr)
        d = json.load(open(W("dump_check.json")))
        out.update(dump="yes" if d["addresses_match"] else "NO",
                   dump_code_same="%.3f%%" % (100.0 * d["code_bytes_same"] / max(1, d["code_bytes"])),
                   dump_function_records="%d/%d" % (d["function_records_same"], d["function_records"]),
                   dump_function_starts="%d/%d" % (d["function_starts_same_16_bytes"], d["function_starts"]),
                   dump_pointers="%d/%d" % (d["pointers_same_rva"], d["relocation_sites"]),
                   dump_loaded_at=d["dump_loaded_at"])
        notes = []
        if d["sections_that_differ"]:
            notes.append("sections: " + "; ".join(d["sections_that_differ"]))
        if d.get("code_pages_the_dump_does_not_hold"):
            notes.append("the dump lacks %d of %d code pages" % (d["code_pages_the_dump_does_not_hold"],
                                                                d["code_pages"]))
        out["dump_note"] = "; ".join(notes)[:300]
    except Exception as e:      # a dump that could not be read is not a mismatch
        out.update(dump="?", dump_note=("%s: %s" % (type(e).__name__, e))[:300])
    finally:
        try:
            os.remove(local)
        except OSError:
            pass
    return out


NAS_BUSY = 25.0     # percent of the last 10 s the service stood still; reads are fine at 10 to 15


def nas_wait(host, say, limit=1800):
    """Wait while the share's service is stalled. Returns a note or ''."""
    cmd = ("d=/sys/fs/cgroup/system.slice/odin-archive-view.service; cat $d/memory.current $d/memory.high; "
           "grep ^full $d/memory.pressure")
    t0 = time.time()
    note = ""
    while True:
        try:
            r = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", host, cmd],
                               capture_output=True, text=True, timeout=40)
            ln = r.stdout.split("\n")
            cur, high = int(ln[0]), ln[1].strip()
            full = float(re.search(r"avg10=([\d.]+)", ln[2])[1])
            if full < NAS_BUSY:
                return note
            note = "waited %.0f s for the archive service (stalled %.0f%% of the time, %d MiB of %s)" % (
                time.time() - t0, full, cur >> 20, high)
        except Exception as e:      # the guard must not stop the run
            return "archive guard: %s" % e
        if time.time() - t0 > limit:
            return note + "; gave up waiting"
        say("    archive service stalled %.0f%% of the time; waiting" % full)
        time.sleep(30)


def deliver_ssh(local, target, build):
    """Copy the export to the server. Each call has a time limit and is tried
    a second time: a connection that died without closing (seen once, an
    `ssh mkdir` that never returned) must not hold up the run."""
    host, path = target.split(":", 1)
    rdir = "%s/%s" % (path.rstrip("/"), build)
    opts = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "-o", "ServerAliveInterval=15",
            "-o", "ServerAliveCountMax=4"]

    def call(cmd, limit):
        for attempt in (1, 2):
            try:
                return subprocess.run(cmd, capture_output=True, text=True, timeout=limit)
            except subprocess.TimeoutExpired:
                if attempt == 2:
                    raise OSError("%s did not finish in %d s, twice" % (cmd[0], limit))

    r = call(["ssh"] + opts + [host, "mkdir -p '%s'" % rdir], 60)
    if r.returncode != 0:
        raise OSError("mkdir on the server failed: " + (r.stderr or r.stdout).strip()[:200])
    r = call(["scp", "-q"] + opts + [local, "%s:%s/ModernWarfare.exe" % (host, rdir)], 600)
    if r.returncode != 0:
        raise OSError("scp failed: " + (r.stderr or r.stdout).strip()[:200])
    r = call(["ssh"] + opts + [host, "stat -c %%s '%s/ModernWarfare.exe'" % rdir], 60)
    if r.returncode != 0 or int(r.stdout.strip() or 0) != os.path.getsize(local):
        raise OSError("size on the server is %s, here %d" % (r.stdout.strip(), os.path.getsize(local)))
    return "%s:%s/ModernWarfare.exe" % (host, rdir)


def withdraw_ssh(target, build):
    """Remove what an earlier run delivered for this build: an export that
    this run would not deliver must not stay on the server under its name."""
    host, path = target.split(":", 1)
    f = "%s/%s/ModernWarfare.exe" % (path.rstrip("/"), build)
    try:
        r = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", host,
                            "if [ -f '%s' ]; then rm -f '%s' && echo removed; fi" % (f, f)],
                           capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        return False
    return "removed" in (r.stdout or "")


def start_begin(a, res, clean):
    """The build's start-up in the emulator, protected image and export side
    by side (MWHook\\tools\\arxan\\d10_init.py): entry point, TLS callbacks, C
    runtime, every static initialiser, into main, until the program only
    waits. Two processes, begun here and collected by start_end() while the
    function comparison runs. Nothing is started as a process of the game."""
    W = lambda n: os.path.join(res, n)      # noqa: E731
    cfg = W("cfg")
    env = dict(os.environ, D9_CFG=cfg, D9_NO_STARTUP="1", OPENBLAS_NUM_THREADS="1")
    common = ["--game-dir", a.start_game_dir or res, "--wall", str(a.start_wall), "--idle", str(a.start_idle),
              "--tail", "8"]
    plans = ["--ref-plan", W("checks.plan")]
    if os.path.exists(os.path.join(cfg, "ref_startup.plan")):
        plans += ["--ref-plan", os.path.join(cfg, "ref_startup.plan")]
    procs = []
    for side, image, extra in (("reference", W("dec.exe"), plans), ("export", clean, [])):
        log = open(W("start_%s.log" % side), "w", encoding="utf-8")
        p = subprocess.Popen([sys.executable, "-I", os.path.join(a.verify, "d10_init.py"), image, "--side", side,
                              "-o", W("start_%s.json" % side)] + common + extra,
                             stdout=log, stderr=subprocess.STDOUT, env=env)
        procs.append((p, log))
    return procs


def start_end(a, res, procs):
    """Wait for the two emulated starts and compare them, initialiser by
    initialiser. Returns the row's start_* fields."""
    W = lambda n: os.path.join(res, n)      # noqa: E731
    out = dict.fromkeys(("start_stretches", "start_different", "start_end", "start_note"), "")
    try:
        late = False
        for p, log in procs:
            try:
                p.wait(timeout=2 * a.start_wall + 900)
            except subprocess.TimeoutExpired:
                p.kill()
                late = True
            finally:
                log.close()
        if late:
            raise OSError("an emulated start did not end in time")
        r = subprocess.run([sys.executable, "-I", os.path.join(a.verify, "d10_init.py"), "--compare",
                            W("start_reference.json"), W("start_export.json"), "--json", W("start.json")],
                           capture_output=True, text=True, errors="replace")
        with open(W("start.log"), "w", encoding="utf-8") as f:
            for side in ("reference", "export"):
                f.write(open(W("start_%s.log" % side), encoding="utf-8", errors="replace").read())
            f.write(r.stdout + r.stderr)
        d = json.load(open(W("start.json")))
        out.update(start_stretches=d["compared"], start_different=d["different"], start_end=d["end"][:160])
    except Exception as e:      # a start that could not be compared is said so; the function comparison decides
        out["start_note"] = ("%s: %s" % (type(e).__name__, e))[:300]
    finally:
        for n in ("start_reference.json", "start_export.json", "start_reference.log", "start_export.log"):
            try:
                os.remove(W(n))
            except OSError:
                pass
    return out


def verify(a, res, clean):
    """Compare the export with the decrypted image, protection running, in
    the emulator (MWHook\\tools\\arxan\\d10_cfg.py and d10_verify.py). Returns
    the row's verify_* fields. Nothing is started as a process."""
    W = lambda n: os.path.join(res, n)      # noqa: E731
    cfg = W("cfg")
    py = [sys.executable, "-I"]
    out = {"verify_equal": "", "verify_different": "", "verify_no_verdict": "", "verify_note": ""}
    starting = None
    try:
        r = subprocess.run(py + [os.path.join(a.verify, "d10_cfg.py"), W("dec.exe"), W("routines.json"),
                                 W("imports.tsv"), cfg, "--starts-sample", str(a.verify_sample), "--walk", "50"],
                           capture_output=True, text=True, errors="replace")
        if r.returncode != 0:
            raise OSError("d10_cfg: " + (r.stdout + r.stderr).strip().splitlines()[-1][:200])
        shutil.copyfile(W("starts_folds.txt"), os.path.join(cfg, "starts_folds.txt"))
        # the checks and the code regions: with them the comparison can tell a
        # path the program cannot take (a check met before its guard) and the
        # protection's own bytes from the game's data
        for n in ("checks.json", "flow.json"):
            if os.path.exists(W(n)):
                shutil.copyfile(W(n), os.path.join(cfg, n))
        if a.start_wall > 0:
            # the emulated start runs beside the function comparison: two more processes
            try:
                starting = start_begin(a, res, clean)
            except Exception as e:
                out["start_note"] = ("%s: %s" % (type(e).__name__, e))[:300]
        r = subprocess.run(py + [os.path.join(a.verify, "d10_verify.py"), W("dec.exe"), clean, cfg,
                                 "--checks", W("checks.plan"), "--tag", "v", "--shards", str(a.verify_shards),
                                 "--wall", str(a.verify_wall)], capture_output=True, text=True, errors="replace")
        with open(W("verify.log"), "w", encoding="utf-8") as f:
            f.write(r.stdout + r.stderr)
        d = json.load(open(os.path.join(cfg, "verify_v.json")))
        eq = df = nv = 0
        where = []
        cold = collections.Counter()
        for name, t in d["tests"].items():
            if t.get("shards_that_failed"):
                raise OSError("a shard of the comparison failed: %s" % str(t["shards_that_failed"])[:200])
            for k, n in t["verdicts"].items():
                if k.startswith("equal"):
                    eq += n
                elif k == "DIFFERENT":
                    df += n
                else:
                    nv += n
                    # the three ways a function entered cold says nothing
                    # (d9_e2e._one): each is decided there from what the path
                    # did, not from how the difference looks
                    if not k.startswith(("no verdict (time", "no verdict (reference stopped")):
                        cold[k[len("no verdict ("):-1]] += n
            for x in t["different"]:
                where.append("%s (%s)" % (x["function"], name))
        where = where[:6]
        for k, n in cold.items():
            where.append("%d: %s" % (n, k))
        if eq == 0:
            # nothing compared equal: the comparison did not really run
            raise OSError("the comparison gave no equal verdict at all (%d different, %d without)" % (df, nv))
        shutil.copyfile(os.path.join(cfg, "verify_v.json"), W("verify.json"))
        out.update(verify_equal=eq, verify_different=df, verify_no_verdict=nv, verify_note="; ".join(where)[:300])
    except Exception as e:      # a comparison that could not be made is not a pass
        out.update(verify_different="?", verify_note=("%s: %s" % (type(e).__name__, e))[:300])
    if starting:
        out.update(start_end(a, res, starting))
    return out          # the caller removes cfg, or keeps it with the rest of a build that differs


def one(a, build, fetch_lock, say):
    row = dict.fromkeys(COLS, "")
    row["build"] = build
    res = os.path.join(a.results, re.sub(r"[^0-9A-Za-z._-]", "_", build))
    os.makedirs(res, exist_ok=True)
    shipped = os.path.join(res, "shipped.exe")
    clean = os.path.join(res, "ModernWarfare.clean.exe")
    t0 = time.time()
    try:
        with fetch_lock:
            if a.nas_guard:
                note = nas_wait(a.nas_guard, say)
                if note:
                    row["why"] = note
            # The first byte can take minutes when the archive is short of
            # memory (34 of 79 builds gave none within 30 s in one run, and
            # every one of them read in 15 s on a quiet server afterwards).
            # One more try after the server has had time to settle.
            for attempt in (1, 2):
                try:
                    fetch(os.path.join(a.root, build, a.exe), shipped, stall=a.fetch_stall, first=a.fetch_first)
                    break
                except OSError as e:
                    if attempt == 2:
                        row["status"] = "not read"
                        row["why"] = ("%s" % e)[:300]
                        return row
                    say("    %s: %s; trying once more" % (build, e))
                    if a.nas_guard:
                        nas_wait(a.nas_guard, say)
        s = remove_build.remove(shipped, clean, res, unlock=a.unlock_sections, say=lambda m: None,
                                flow_exe=a.flow_exe, flow_script=a.flow_script, keep_work=bool(a.verify),
                                full=a.full)
        row["export_seconds"] = (s.get("seconds") or {}).get("all", "")
        if a.verify and s["status"] == "exported" and not isinstance(s.get("functions"), dict):
            # the fast removal leaves the self-checks out; a verified run still wants the function pieces
            try:
                fj = os.path.join(res, "functions.json")
                remove_build.run(remove_build.py_cmd() + [os.path.join(remove_build.HERE, "check_functions.py"),
                                                          clean, "--json", fj], os.path.join(res, "log.txt"), "functions")
                s["functions"] = json.load(open(fj))["summary"]
            except Exception as e:      # a report: the row says it is missing
                s["functions"] = "no report: %s" % e
        row.update(size=s.get("size", ""), status=s["status"], writer_rows=s.get("writer_rows", ""),
                   chains=s.get("chains", ""), check_sequences=s.get("check_sequences", ""),
                   published_dwords=s.get("published_dwords", ""), string_blobs=s.get("string_blobs", ""),
                   export_bytes=s.get("export_bytes", ""))
        k = s.get("routines") or {}
        row["routines"] = s.get("routine_entries", "")
        row["three_slots"] = k.get("three slots", "")
        fl = s.get("flow")
        if isinstance(fl, dict):
            row.update(startup_chains_skipped=fl.get("start_up_chains_skipped", ""),
                       constructs=fl.get("constructs_with_a_routine", ""),
                       constructs_folded=fl.get("constructs_folded", ""),
                       branches_rewritten=fl.get("branches_rewritten", ""), branches_left=fl.get("branches_left", ""),
                       stubs_kept=fl.get("stubs_kept", ""),
                       wiped_bytes=(fl.get("wiped_bytes") or 0) + (fl.get("dead_plan_bytes") or 0))
        fn = s.get("functions")
        if isinstance(fn, dict):
            row.update(fn_pieces=fn["pieces"], fn_encrypted=fn["encrypted_pieces"],
                       fn_encrypted_bytes=fn["encrypted_bytes"])
        if s["status"] != "exported":
            row["why"] = (row["why"] + "; " if row["why"] else "") + s.get("why", "")
            return row
        # A memory dump of the build, where the archive has one: everything
        # in the export has to be at the address the dump has it at. It is
        # asked of every export, whatever the comparison below says.
        if build in a.dumps:
            lowmem.wait_for(1.0, say, "the dump check")
            row.update(dump_check(a, res, clean, a.dumps[build], fetch_lock, say))
        if a.verify:
            lowmem.wait_for(3.5 if a.start_wall > 0 else 2.0, say, "the comparison")
            v = verify(a, res, clean)
            row.update(v)
            if v.get("verify_different") not in (0, "0"):
                # an export that behaves differently from the protected image
                # somewhere is not delivered; the row says where to look
                row["status"] = "differs in emulation"
                return row
            if v.get("start_different") not in (0, "0", "", None):
                # the two starts made different calls in some initialiser, or got different answers
                row["status"] = "differs in emulation"
                row["why"] = (row["why"] + "; " if row["why"] else "") + "the emulated starts differ"
                return row
        if row["dump"] == "NO":
            row["status"] = "addresses differ from the dump"
            return row
        # what is delivered: with --unlock-sections the twin whose sections
        # are all writable and executable (the comparison was made on the
        # other, the same bytes with the section flags left alone)
        final = s.get("unlocked") or clean
        if a.deliver_ssh:
            row["delivered"] = deliver_ssh(final, a.deliver_ssh, build)
        elif a.deliver:
            d = os.path.join(a.deliver, build)
            os.makedirs(d, exist_ok=True)
            shutil.copyfile(final, os.path.join(d, "ModernWarfare.exe"))
            row["delivered"] = os.path.join(d, "ModernWarfare.exe")
        return row
    except Exception as e:      # one build must not stop the run
        row["status"] = row["status"] or "error"
        row["why"] = ("%s: %s" % (type(e).__name__, e)).replace("\t", " ")[:300]
        return row
    finally:
        if a.deliver_ssh and not row["delivered"] and row["status"] != "not read":
            try:
                if withdraw_ssh(a.deliver_ssh, build):
                    row["why"] = (row["why"] + "; " if row["why"] else "") + "an earlier delivery was withdrawn"
            except Exception:       # the server not answering must not stop the run
                pass
        # A build that differs is worth looking at, and making its images
        # again takes ten minutes: the first few keep the decrypted image, the
        # export and the comparison's tables (run_compare.ps1 works on them).
        keep = ()
        if row["status"] == "differs in emulation" and a.keep_differing > 0:
            a.keep_differing -= 1
            keep = ("dec.exe", "ModernWarfare.clean.exe", "cfg")
            row["why"] = (row["why"] + "; " if row["why"] else "") + "work folder kept"
        else:
            shutil.rmtree(os.path.join(res, "cfg"), ignore_errors=True)
        # everything large goes; the cleaned executable too once it has been delivered
        for n in os.listdir(res):
            p = os.path.join(res, n)
            if n in SMALL or n in keep:
                continue
            if n == "ModernWarfare.clean.exe" and not row["delivered"] and (a.deliver or a.deliver_ssh) is None:
                continue                # nowhere to deliver to: it stays here
            try:
                os.remove(p)
            except OSError:
                pass
        row["seconds"] = "%.0f" % (time.time() - t0)


def read_rows(path):
    if not os.path.exists(path):
        return []
    return [dict(zip(COLS, ln.split("\t"))) for ln in open(path).read().splitlines()[1:] if ln.strip()]


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("root")
    ap.add_argument("--results", required=True)
    ap.add_argument("--exe", default="ModernWarfare.exe")
    ap.add_argument("--builds", help="a table whose first column names the build folders")
    ap.add_argument("--only")
    ap.add_argument("--jobs", type=int, default=1)
    ap.add_argument("--resume", action="store_true")
    ap.add_argument("--deliver", help="folder that gets <build>\\ModernWarfare.exe")
    ap.add_argument("--deliver-ssh", help="user@host:/path that gets <build>/ModernWarfare.exe by scp")
    ap.add_argument("--nas-guard", help="user@host of the archive server, to wait while its share service is stalled")
    ap.add_argument("--fetch-stall", type=float, default=120, help="seconds a read from the archive may stand still")
    ap.add_argument("--fetch-first", type=float, default=400, help="seconds the archive may take to its first byte")
    ap.add_argument("--keep-differing", type=int, default=0,
                    help="keep the work folder (decrypted image, export, comparison tables) of this many builds "
                         "that differ in emulation")
    ap.add_argument("--dumps-first", action="store_true", help="take the builds that have a memory dump first")
    ap.add_argument("--dump-index", help="dump-index.json of a folder of memory dumps (entries with `version` and "
                                         "`archive_path`): each export is compared with its build's dump by address")
    ap.add_argument("--unlock-sections", action="store_true")
    ap.add_argument("--flow-exe", help="an mwdec.exe with the `flow` command, used instead of devirt_flow.py")
    ap.add_argument("--flow-script", default="devirt_flow.py", help="the Python flow tool, when no --flow-exe")
    ap.add_argument("--full", action="store_true",
                    help="each removal also does what only feeds a report or a proof, and the self-checks")
    ap.add_argument("--verify", metavar="DIR",
                    help="folder with d10_cfg.py and d10_verify.py (MWHook\\tools\\arxan): compare every export "
                         "with its protected image in the emulator, and deliver only the ones with no difference")
    ap.add_argument("--verify-sample", type=int, default=300, help="random function entries besides the folded ones")
    ap.add_argument("--verify-shards", default="auto",
                    help="processes for the comparison; 'auto' takes what the free memory and the cores allow")
    ap.add_argument("--verify-wall", type=float, default=8.0, help="seconds one function may run in the emulator")
    ap.add_argument("--start-wall", type=float, default=0,
                    help="with --verify: also start each build in the emulator from its entry point, protected "
                         "image and export, for at most this many seconds a side, and compare the two starts "
                         "initialiser by initialiser (0: not done)")
    ap.add_argument("--start-idle", type=int, default=400,
                    help="end an emulated start when this many API calls in a row only wait")
    ap.add_argument("--start-game-dir", help="a folder with the DLLs that ship beside the game's executable")
    a = ap.parse_args()
    a.dumps = {}
    if a.dump_index:
        root = os.path.dirname(os.path.abspath(a.dump_index))
        for e in json.load(open(a.dump_index)):
            a.dumps[e["version"]] = os.path.join(root, e["archive_path"].replace("/", os.sep))
    # the comparison's shards run from another folder: no relative paths
    a.results = os.path.abspath(a.results)
    if a.verify:
        a.verify = os.path.abspath(a.verify)
    if a.builds:
        builds = []
        for ln in open(a.builds).read().splitlines()[1:]:
            c = [x.strip('"') for x in ln.split("\t")]
            if c and c[0] and (len(c) < 3 or c[2] not in ("0", "")):
                builds.append(c[0])
    else:
        builds = [d for d in os.listdir(a.root) if os.path.isfile(os.path.join(a.root, d, a.exe))]
    builds.sort(key=by_version)
    if a.dumps_first:
        builds.sort(key=lambda b: b not in a.dumps)     # stable: version order within each half
    if a.only:
        builds = [b for b in builds if re.search(a.only, b)]
    os.makedirs(a.results, exist_ok=True)
    tsv = os.path.join(a.results, "results.tsv")
    kept = []
    if a.resume:
        want_delivery = bool(a.deliver or a.deliver_ssh)
        kept = [r for r in read_rows(tsv) if r["status"] == "exported" and (r["delivered"] or not want_delivery)]
        if a.only:
            kept = [r for r in read_rows(tsv) if r["build"] not in set(builds)]
        else:
            done = {r["build"] for r in kept}
            # rows of builds that are tried again are dropped; the others stay
            kept += [r for r in read_rows(tsv) if r["build"] not in done and r["build"] not in set(builds)]
            builds = [b for b in builds if b not in done]
    lock = threading.Lock()
    fetch_lock = threading.Lock()
    t0 = time.time()
    n = 0

    def say(m):
        print(m, flush=True)

    with open(tsv, "w", newline="\n") as f:
        f.write("\t".join(COLS) + "\n")
        for r in kept:
            f.write("\t".join(str(r.get(c, "")) for c in COLS) + "\n")
        f.flush()

        def run(b):
            nonlocal n
            row = one(a, b, fetch_lock, say)
            with lock:
                n += 1
                f.write("\t".join(str(row[c]).replace("\t", " ").replace("\n", " ") for c in COLS) + "\n")
                f.flush()
                say("%3d/%d %-30s %-9s routines %s/%s checks %s fn-encrypted %s  %ss (total %.0f min) %s%s%s" % (
                    n, len(builds), b, row["status"], row["three_slots"], row["routines"], row["published_dwords"],
                    row["fn_encrypted"], row["seconds"], (time.time() - t0) / 60, row["why"][:100],
                    (" dump: %s, code %s" % (row["dump"], row["dump_code_same"])) if row["dump"] else "",
                    (" start: %s stretches, %s different, %s" % (
                        row["start_stretches"], row["start_different"], str(row["start_end"])[:60]))
                    if row["start_stretches"] != "" else (" start: " + str(row["start_note"])[:80]
                                                         if row["start_note"] else "")))

        with concurrent.futures.ThreadPoolExecutor(max_workers=a.jobs) as ex:
            list(ex.map(run, builds))
    return 0


if __name__ == "__main__":
    sys.exit(main())
