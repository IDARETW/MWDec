"""Remove the protection from one build, from its shipped file alone.

    py -3 tools\\remove_build.py ModernWarfare.exe -o clean.exe --work DIR --flow-exe MWDEC.exe
                                 [--keep-work] [--unlock-sections] [--full] [--steps]

Nothing is run and nothing is taken from a profile. With --flow-exe (an
mwdec.exe built with src\\flow), `mwdec remove` does every step below in one
process: the shipped file is read once and each step hands its image and
tables to the next in memory; the C++ steps write the same files as the
tools listed, byte for byte. The default leaves out what only feeds a report
or a proof; --full puts back the flow pass's report-only walks, the live map,
the junk constructs' emulator proof, and the two self-checks of the export
(step 10). --steps, or no --flow-exe, runs the tools one by one instead:

The steps, each also a tool that can be run by itself:

  1. mwdec decrypt --layer1-only      bootstrap layer; key, block, list found in the file
  2. find_writers.py                  the writer table, from the writers' code
  3. mwdec decrypt --writers          both layers and the string blobs
  4. mwdec imports                    the two import tables
  5. find_routines.py                 the routine table and the replacement stubs, from the routines' code
  6. find_checks.py                   the values the guards publish, from the checks that read them
  7. devirt_boot.py                   plan: start-up calls restored, one import table
  8. devirt_flow.py                   plans: nests folded, branches rewritten, dead bytes wiped
  9. mwdec export                     the plans applied to the shipped file
 10. check_clean.py, check_functions.py   what is left

`--work` gets every intermediate file. Unless `--keep-work`, the two
intermediate executables are deleted when the export is written, and what
stays in the folder is small: the tables, the plans and the reports.
A one-line summary goes to `summary.json` there.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
# MWDEC_EXE names the executable when the tools are run from a copy (a batch
# runs from a snapshot, so that work on the tools does not reach into it)
MWDEC = os.environ.get("MWDEC_EXE") or os.path.join(HERE, "..", "build", "Release", "mwdec.exe")
sys.path.insert(0, HERE)
import lowmem  # noqa: E402

lowmem.settle()     # one BLAS thread and below-normal priority, for this process and every step it starts

# Physical memory a step is given before it starts, in GB: a little over what
# the largest build has needed. When less is free (a game was started), the
# step waits instead of pushing the machine into its page file.
NEEDS = {"writers": 2.0, "flow plans": 4.5, "routines": 1.5, "boot plan": 1.5, "check": 1.0, "functions": 1.0}
PEAKS = {}          # step -> (peak working set MB, peak commit MB) of the last run() of that name


class Failed(Exception):
    pass


def run(cmd, log, what, ok=(0,)):
    t0 = time.time()
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace")
    out = p.communicate()[0] or ""
    PEAKS[what] = lowmem.peak_mb(getattr(p, "_handle", None)) if sys.platform == "win32" else (0, 0)
    with open(log, "a", encoding="utf-8") as f:
        f.write("\n===== %s\n%s\n%s\npeak working set %d MB, peak commit %d MB\n" % (
            what, " ".join('"%s"' % c if " " in c else c for c in cmd), out, PEAKS[what][0], PEAKS[what][1]))
    if p.returncode not in ok:
        tail = out.strip().splitlines()[-1][:300] if out.strip() else "no output"
        raise Failed("%s failed: %s" % (what, tail))
    return out, time.time() - t0


def remove(src, out, work, unlock=False, keep_work=False, say=print, flow_exe=None, flow_script="devirt_flow.py",
           full=False, steps=False):
    """The whole removal. With an mwdec.exe that has the flow pass (flow_exe),
    `mwdec remove` does every step in one process, the image held in memory;
    with `steps`, or without one, the tools run one by one (the reference).
    `full` adds what only feeds a report or a proof, and the self-checks."""
    if flow_exe and not steps:
        return remove_one(src, out, work, unlock, keep_work, say, flow_exe, full)
    return remove_steps(src, out, work, unlock, keep_work, say, flow_exe, flow_script, full)


def summarize(s, o, W):
    """What the step outputs and the work folder say, into the summary s."""
    m = re.search(r"key ([0-9A-F]{8}), starting block ([0-9A-F]{8}), range list ([0-9A-F]{8}), (\d+) cycles", o)
    if m:
        s["bootstrap"] = {"key": m[1], "block": m[2], "list": m[3], "cycles": int(m[4])}
    m = re.findall(r"rows judged: (\d+) kept", o)
    s["writer_rows"] = sum(int(x) for x in m)
    m = re.search(r"sets of ranges that only noise was decoded for: (\d+) \((\d+) bytes\)", o)
    if m:
        s["ranges_without_a_decryptor"] = {"sets": int(m[1]), "bytes": int(m[2])}
    m = re.search(r"string blobs: (\d+)", o)
    s["string_blobs"] = int(m[1]) if m else None
    m = re.search(r"imports: (\d+) descriptors, (\d+) slots", o)
    s["imports"] = {"descriptors": int(m[1]), "slots": int(m[2])} if m else None
    m = re.search(r"checks: (\d+) sequences on (\d+) published dwords", o)
    if m:
        s["check_sequences"], s["published_dwords"] = int(m[1]), int(m[2])
    try:
        meta = json.load(open(W("routines.json")))["meta"]
        s["routines"] = meta["kinds"]
        s["slot_store_shapes"] = meta["slot_stores"]
        s["index_minus_offset"] = meta["index_minus_offset"]
    except (OSError, ValueError, KeyError) as e:
        s["routines"] = "no table: %s" % e
    m = re.search(r"chains: (\d+), at (\d+) long-form sites without one; routines: (\d+)", o)
    if m:
        s["chains"], s["sites_without_chain"], s["routine_entries"] = int(m[1]), int(m[2]), int(m[3])
    m = re.search(r"published dwords by who stores them: (\{.*?\}); routines that publish: (\d+)", o)
    if m:
        s["published_by"], s["publishing_routines"] = m[1], int(m[2])
    m = re.search(r"values that hold from the start: (\d+) of (\d+) published dwords baked", o)
    if m:
        s["published_baked"] = int(m[1])
    try:
        tls = json.load(open(W("boot.json"))).get("tls") or []
        s["tls_callbacks"] = len(tls)
        s["tls_callbacks_with_start_up_calls"] = [t["index"] for t in tls if t.get("routines_called")]
    except Exception as e:      # the report is optional
        s["tls_callbacks"] = "no report: %s" % e
    for pat, key in ((r"checks folded: (\{.*\})", "checks_folded"), (r"^planned: (.*)$", "planned"),
                     (r"^(walk 1: .*)$", "walk")):
        m = re.search(pat, o, re.M)
        if m:
            s[key] = m[1][:300]
    try:
        rep = json.load(open(W("flow.json")))
        fo = rep.get("folds") or {}
        s["flow"] = {
            "code_regions_in_data_sections": rep.get("extra_code_regions"),
            "chains": rep.get("chains_matched"),
            "start_up_chains_skipped": rep.get("chains_bypassed"),
            "constructs_with_a_routine": fo.get("constructs_with_a_continuation_routine"),
            "constructs_folded": fo.get("folded"),
            "branches_rewritten": sum((rep.get("idioms_rewritten") or {}).values()),
            "branches_left": rep.get("walk2_idioms_left"),
            "routines_without_a_continuation": len(rep.get("unknown_continuation_routines") or []),
            "stubs_kept": rep.get("stubs_plan_patches"),
            "patches": rep.get("patches"), "wiped_bytes": rep.get("wipe_bytes"),
            "dead_plan_bytes": (rep.get("dead_plan") or {}).get("bytes"),
        }
    except Exception as e:      # the report is optional
        s["flow"] = "no report: %s" % e
    try:
        jr = json.load(open(W("junk.json")))
        s["junk"] = {k: jr.get(k) for k in ("constructs", "replaced", "wiped_bytes", "bytes_kept", "shapes",
                                             "proved", "proved_wrong", "not_counted")}
    except (OSError, ValueError) as e:
        s["junk"] = "no report: %s" % e
    m = re.search(r"WARNING: (\d+) bytes are patched to different values by two plans", o)
    s["bytes_patched_twice_differently"] = int(m[1]) if m else 0
    m = re.search(r"wiped\s+(\d+) ranges\s+(\d+) bytes", o)
    if m:
        s["export_wiped_bytes"] = int(m[2])
    m = re.search(r"relocations: (\d+) dropped by plan.*?(\d+) left", o)
    if m:
        s["relocations_left"] = int(m[2])


def self_checks(s, out, W, step):
    """check_clean.py and check_functions.py on the export (the full form only)."""
    step("check", py_cmd() + [os.path.join(HERE, "check_clean.py"), out, "--imports", W("imports.tsv"),
                              "--json", W("clean.json")] + (["--live", W("live.npy")] if os.path.exists(W("live.npy")) else []),
         ok=(0, 1))
    try:
        s["check_clean"] = {k: v for k, v in json.load(open(W("clean.json"))).items()
                            if isinstance(v, (int, str, float, bool))}
    except Exception as e:      # the report is optional
        s["check_clean"] = "no report: %s" % e
    step("functions", py_cmd() + [os.path.join(HERE, "check_functions.py"), out, "--json", W("functions.json")])
    try:
        s["functions"] = json.load(open(W("functions.json")))["summary"]
    except Exception as e:
        s["functions"] = "no report: %s" % e


def py_cmd():
    return [sys.executable, "-I"]


def remove_one(src, out, work, unlock, keep_work, say, exe, full):
    """`mwdec remove`: every step in one process; then, in the full form, the self-checks."""
    os.makedirs(work, exist_ok=True)
    log = os.path.join(work, "log.txt")
    open(log, "w").close()
    W = lambda name: os.path.join(work, name)   # noqa: E731
    s = {"source": src, "size": os.path.getsize(src), "status": "started", "seconds": {}, "peak_mb": {},
         "waited_for_memory": 0, "mode": "full" if full else "fast", "flow_implementation": "mwdec remove"}
    t_all = time.time()

    def step(name, cmd, **kw):
        say("  %s" % name)
        if name in NEEDS:
            s["waited_for_memory"] += round(lowmem.wait_for(NEEDS[name], say, name))
        o, dt = run(cmd, log, name, **kw)
        s["seconds"][name] = round(dt)
        s["peak_mb"][name] = list(PEAKS.get(name, (0, 0)))
        return o

    try:
        cmd = [exe, "remove", src, "-o", out, "--work", work]
        if unlock:
            cmd.append("--unlock-sections")
        if keep_work:
            cmd.append("--keep-work")
        if full:
            cmd.append("--full")
        o = step("remove", cmd)
        for name, secs in re.findall(r"^step (.+) ([\d.]+)$", o, re.M):
            s["seconds"][name] = round(float(secs), 1)
        summarize(s, o, W)
        if unlock:
            s["unlocked"] = os.path.splitext(out)[0] + ".unlocked.exe"
        s["export_bytes"] = os.path.getsize(out)
        if full:
            self_checks(s, out, W, step)
        s["status"] = "exported"
    except Failed as e:
        s["status"] = "failed"
        s["why"] = str(e)
    except Exception as e:          # never leave the caller without a summary
        s["status"] = "failed"
        s["why"] = "%s: %s" % (type(e).__name__, e)
    finally:
        if not keep_work:
            for n in ("layer1.exe", "dec.exe", "live.npy"):
                if os.path.exists(W(n)):
                    os.remove(W(n))
        s["seconds"]["all"] = round(time.time() - t_all)
        with open(W("summary.json"), "w") as f:
            json.dump(s, f, indent=1)
    return s


def remove_steps(src, out, work, unlock=False, keep_work=False, say=print, flow_exe=None, flow_script="devirt_flow.py",
                 full=True):
    os.makedirs(work, exist_ok=True)
    log = os.path.join(work, "log.txt")
    open(log, "w").close()
    W = lambda name: os.path.join(work, name)   # noqa: E731
    py = [sys.executable, "-I"]
    T = lambda name: os.path.join(HERE, name)   # noqa: E731
    s = {"source": src, "size": os.path.getsize(src), "status": "started", "seconds": {}, "peak_mb": {},
         "waited_for_memory": 0}
    t_all = time.time()

    def step(name, cmd, **kw):
        say("  %s" % name)
        if name in NEEDS:
            s["waited_for_memory"] += round(lowmem.wait_for(NEEDS[name], say, name))
        o, dt = run(cmd, log, name, **kw)
        s["seconds"][name] = round(dt)
        s["peak_mb"][name] = list(PEAKS.get(name, (0, 0)))
        return o

    try:
        o = step("layer 1", [MWDEC, "decrypt", src, "-o", W("layer1.exe"), "--no-profile", "--layer1-only",
                             "--keep-strings"])
        m = re.search(r"key ([0-9A-F]{8}), starting block ([0-9A-F]{8}), range list ([0-9A-F]{8}), (\d+) cycles", o)
        if not m:
            raise Failed("layer 1: bootstrap parameters not found")
        s["bootstrap"] = {"key": m[1], "block": m[2], "list": m[3], "cycles": int(m[4])}
        o = step("writers", py + [T("find_writers.py"), W("layer1.exe"), "-o", W("writers.tsv")])
        m = re.findall(r"rows judged: (\d+) kept", o)
        s["writer_rows"] = sum(int(x) for x in m)
        m = re.search(r"sets of ranges that only noise was decoded for: (\d+) \((\d+) bytes\)", o)
        if m:
            s["ranges_without_a_decryptor"] = {"sets": int(m[1]), "bytes": int(m[2])}
        o = step("layer 2", [MWDEC, "decrypt", src, "-o", W("dec.exe"), "--no-profile", "--writers", W("writers.tsv")])
        m = re.search(r"string blobs: (\d+)", o)
        s["string_blobs"] = int(m[1]) if m else None
        if not keep_work:
            os.remove(W("layer1.exe"))
        o = step("imports", [MWDEC, "imports", src, "-o", W("imports.tsv"), "--no-profile"])
        m = re.search(r"imports: (\d+) descriptors, (\d+) slots", o)
        s["imports"] = {"descriptors": int(m[1]), "slots": int(m[2])} if m else None
        # the checks first: the routine walk needs to know which dwords are
        # published, to record which routine stores each
        o = step("checks", py + [T("find_checks.py"), W("dec.exe"), "-o", W("checks_all.plan"),
                                 "--json", W("checks.json")])
        m = re.search(r"checks: (\d+) sequences on (\d+) published dwords", o)
        if m:
            s["check_sequences"], s["published_dwords"] = int(m[1]), int(m[2])
        # A published value is written when its guard runs, and code can be
        # placed before that on purpose (1.20's WinMain). So only the values
        # that hold from the start are baked (`checks.plan`): the ones a
        # start-up routine stores, and the ones no routine was seen to store.
        # A guard's replacement stores its value when it is called.
        o = step("routines", py + [T("find_routines.py"), W("dec.exe"), "-o", W("routines.json"),
                                   "--stubs-out", W("routine_stubs.plan"), "--checks", W("checks.json"),
                                   "--bake-out", W("checks.plan")])
        meta = json.load(open(W("routines.json")))["meta"]
        s["routines"] = meta["kinds"]
        s["slot_store_shapes"] = meta["slot_stores"]
        s["index_minus_offset"] = meta["index_minus_offset"]
        m = re.search(r"chains: (\d+), at (\d+) long-form sites without one; routines: (\d+)", o)
        if m:
            s["chains"], s["sites_without_chain"], s["routine_entries"] = int(m[1]), int(m[2]), int(m[3])
        m = re.search(r"published dwords by who stores them: (\{.*?\}); routines that publish: (\d+)", o)
        if m:
            s["published_by"], s["publishing_routines"] = m[1], int(m[2])
        m = re.search(r"values that hold from the start: (\d+) of (\d+) published dwords baked", o)
        if m:
            s["published_baked"] = int(m[1])
        step("boot plan", py + [T("devirt_boot.py"), W("dec.exe"), "--imports", W("imports.tsv"), "-o", W("boot.plan"),
                                "--report", W("boot.json")])
        # The TLS callbacks: the protection puts its three start-up calls in
        # front of the first one (they run on every call, for every reason)
        # and nowhere else, behind a plain `jmp`. That is what devirt_boot.py
        # patches, and what every build seen so far has; a build that has it
        # otherwise is not one this pipeline has been checked on.
        try:
            tls = json.load(open(W("boot.json"))).get("tls") or []
            s["tls_callbacks"] = len(tls)
            s["tls_callbacks_with_start_up_calls"] = [t["index"] for t in tls if t.get("routines_called")]
            left = [t["index"] for t in tls if t.get("routines_called") and not t.get("patched")]
        except Exception as e:      # the report is optional
            s["tls_callbacks"] = "no report: %s" % e
            left = []
        if left:
            raise Failed("TLS callback %s begins with start-up calls that could not be taken off" % left)
        # the flow pass: the C++ implementation (`mwdec flow`, same arguments
        # and the same output files byte for byte) when one is given, else
        # the Python reference
        flow = [flow_exe, "flow", "--regions", "v2"] if flow_exe else py + [T(flow_script)]
        s["flow_implementation"] = "mwdec flow" if flow_exe else flow_script
        o = step("flow plans", flow + [W("dec.exe"), "-o", W("flow.plan"),
                                       "--dead-plan", W("dead.plan"), "--stubs-out", W("stubs.plan"),
                                       "--routines", W("routines.json"), "--keep-plan", W("checks.plan"),
                                       "--keep-plan", W("boot.plan"), "--stub-plan", W("routine_stubs.plan"),
                                       "--report", W("flow.json"), "--live", W("live.npy"),
                                       "--starts-out", W("starts_folds.txt")])
        for pat, key in ((r"checks folded: (\{.*\})", "checks_folded"), (r"^planned: (.*)$", "planned"),
                         (r"^(walk 1: .*)$", "walk")):
            m = re.search(pat, o, re.M)
            if m:
                s[key] = m[1][:300]
        try:
            rep = json.load(open(W("flow.json")))
            fo = rep.get("folds") or {}
            s["flow"] = {
                "code_regions_in_data_sections": rep.get("extra_code_regions"),
                "chains": rep.get("chains_matched"),
                "start_up_chains_skipped": rep.get("chains_bypassed"),
                "constructs_with_a_routine": fo.get("constructs_with_a_continuation_routine"),
                "constructs_folded": fo.get("folded"),
                "branches_rewritten": sum((rep.get("idioms_rewritten") or {}).values()),
                "branches_left": rep.get("walk2_idioms_left"),
                "routines_without_a_continuation": len(rep.get("unknown_continuation_routines") or []),
                "stubs_kept": rep.get("stubs_plan_patches"),
                "patches": rep.get("patches"), "wiped_bytes": rep.get("wipe_bytes"),
                "dead_plan_bytes": (rep.get("dead_plan") or {}).get("bytes"),
            }
        except Exception as e:      # the report is optional
            s["flow"] = "no report: %s" % e
        plans = []
        for p in ("boot.plan", "checks.plan", "flow.plan", "dead.plan", "stubs.plan"):
            plans += ["--plan", W(p)]
        # The protection's junk constructs (a call back into its own bytes,
        # around which nothing changes): each becomes a jump over itself. Made
        # after the other plans, which it reads so as not to write over them,
        # and applied last.
        step("junk plan", py + [T("find_junk.py"), W("dec.exe"), "-o", W("junk.plan"), "--report", W("junk.json"),
                                "--prove", "300"] + plans)
        try:
            jr = json.load(open(W("junk.json")))
            s["junk"] = {k: jr.get(k) for k in ("constructs", "replaced", "wiped_bytes", "bytes_kept", "shapes",
                                                 "proved", "proved_wrong", "not_counted")}
            if jr.get("proved_wrong"):
                raise Failed("%d junk constructs are not a no-op in the emulator" % jr["proved_wrong"])
        except (OSError, ValueError) as e:
            s["junk"] = "no report: %s" % e
        plans += ["--plan", W("junk.plan")]
        cmd = [MWDEC, "export", src, "-o", out, "--no-profile", "--writers", W("writers.tsv")] + plans
        o = step("export", cmd)
        if unlock:
            # The same image with every section writable and executable, for
            # running as a process. The checks and the emulated comparison
            # are made on the image above, whose sections say what they
            # hold: they tell code from data by the section flags.
            s["unlocked"] = os.path.splitext(out)[0] + ".unlocked.exe"
            step("export, sections unlocked",
                 [MWDEC, "export", src, "-o", s["unlocked"], "--no-profile", "--writers", W("writers.tsv")] + plans
                 + ["--unlock-sections"])
        s["export_bytes"] = os.path.getsize(out)
        m = re.search(r"WARNING: (\d+) bytes are patched to different values by two plans", o)
        s["bytes_patched_twice_differently"] = int(m[1]) if m else 0
        m = re.search(r"wiped\s+(\d+) ranges\s+(\d+) bytes", o)
        if m:
            s["export_wiped_bytes"] = int(m[2])
        m = re.search(r"relocations: (\d+) dropped by plan.*?(\d+) left", o)
        if m:
            s["relocations_left"] = int(m[2])
        o = step("check", py + [T("check_clean.py"), out, "--imports", W("imports.tsv"), "--json", W("clean.json"),
                                "--live", W("live.npy")], ok=(0, 1))
        try:
            s["check_clean"] = {k: v for k, v in json.load(open(W("clean.json"))).items()
                                if isinstance(v, (int, str, float, bool))}
        except Exception as e:      # the report is optional
            s["check_clean"] = "no report: %s" % e
        o = step("functions", py + [T("check_functions.py"), out, "--json", W("functions.json")])
        try:
            s["functions"] = json.load(open(W("functions.json")))["summary"]
        except Exception as e:
            s["functions"] = "no report: %s" % e
        s["status"] = "exported"
    except Failed as e:
        s["status"] = "failed"
        s["why"] = str(e)
    except Exception as e:          # never leave the caller without a summary
        s["status"] = "failed"
        s["why"] = "%s: %s" % (type(e).__name__, e)
    finally:
        if not keep_work:
            for n in ("layer1.exe", "dec.exe", "live.npy"):
                if os.path.exists(W(n)):
                    os.remove(W(n))
        s["seconds"]["all"] = round(time.time() - t_all)
        with open(W("summary.json"), "w") as f:
            json.dump(s, f, indent=1)
    return s


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("exe")
    ap.add_argument("-o", "--out", required=True)
    ap.add_argument("--work", required=True, help="folder for the tables, plans, reports and intermediate files")
    ap.add_argument("--keep-work", action="store_true", help="keep the intermediate executables too")
    ap.add_argument("--unlock-sections", action="store_true", help="passed to mwdec export")
    ap.add_argument("--flow-exe", help="an mwdec.exe with the `flow` and `remove` commands: every step in one process")
    ap.add_argument("--flow-script", default="devirt_flow.py", help="the Python flow tool to run (in tools\\)")
    ap.add_argument("--full", action="store_true",
                    help="also what only feeds a report or a proof (report-only walks, the live map, the junk "
                         "constructs' emulator proof) and the self-checks of the export")
    ap.add_argument("--steps", action="store_true", help="run the tools one by one (the reference) instead of `mwdec remove`")
    a = ap.parse_args()
    s = remove(a.exe, a.out, a.work, a.unlock_sections, a.keep_work, flow_exe=a.flow_exe, flow_script=a.flow_script,
               full=a.full, steps=a.steps)
    print(json.dumps({k: v for k, v in s.items() if k not in ("seconds",)}, indent=1))
    print("seconds:", s["seconds"])
    return 0 if s["status"] == "exported" else 1


if __name__ == "__main__":
    sys.exit(main())
