// mwdec flow: the C++ port of tools/devirt_flow.py.
#include <windows.h>
#include <psapi.h>

#include <cstdio>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "flow/pipeline.h"

namespace flow {

int cmd_flow(int argc, char** argv) {
    std::string exe, out, dead, stubs, routines, report, live, starts;
    std::vector<std::string> keep, stub;
    bool fast = false;
    static bool mem = false;  // --mem: every log line says what the process holds at that moment
    if (argc >= 3 && std::string(argv[2]) == "--rng-test") {
        // the draws find_checks makes, for comparison with random.Random(1400)
        PyRandom r(1400);
        for (int k = 0; k < 3; ++k) std::printf("%llu\n", static_cast<unsigned long long>(r.getrandbits(64)));
        std::printf("%lld\n", static_cast<long long>(r.randbelow(32)));
        std::printf("%llu\n", static_cast<unsigned long long>(r.getrandbits(12)));
        uint8_t b[8];
        r.randbytes(b, 8);
        for (uint8_t x : b) std::printf("%02x", x);
        std::printf("\n");
        return 0;
    }
    for (int i = 2; i < argc; ++i) {
        const std::string a = argv[i];
        auto val = [&]() -> std::string {
            if (i + 1 >= argc) throw std::runtime_error("missing value for " + a);
            return argv[++i];
        };
        if (a == "-o" || a == "--out") out = val();
        else if (a == "--dead-plan") dead = val();
        else if (a == "--stubs-out") stubs = val();
        else if (a == "--routines") routines = val();
        else if (a == "--keep-plan") keep.push_back(val());
        else if (a == "--stub-plan") stub.push_back(val());
        else if (a == "--report") report = val();
        else if (a == "--live") live = val();
        else if (a == "--starts-out") starts = val();
        else if (a == "--check-cache") g_cache_check = true;
        else if (a == "--cache-infinite") g_cache_infinite = true;
        else if (a == "--fast") fast = true;
        else if (a == "--mem") mem = true;
        else if (a == "--regions") {
            const std::string v = val();
            if (v != "v1" && v != "v2") throw std::runtime_error("--regions wants v1 or v2");
            g_regions_v2 = v == "v2";
        }
        else if (!a.empty() && a[0] == '-') throw std::runtime_error("unknown option " + a);
        else if (exe.empty()) exe = a;
        else throw std::runtime_error("unexpected argument " + a);
    }
    if (exe.empty() || out.empty())
        throw std::runtime_error(
            "usage: mwdec flow <decrypted.exe> -o flow.plan [--dead-plan P] [--stubs-out P] [--routines R.json]\n"
            "       [--keep-plan P ...] [--stub-plan P ...] [--report R.json] [--live L.npy] [--starts-out S.txt]");
    const ULONGLONG t0 = GetTickCount64();
    Pipeline pp(exe,
                [](const std::string& s) {
                    if (mem) {
                        PROCESS_MEMORY_COUNTERS_EX m{};
                        GetProcessMemoryInfo(GetCurrentProcess(), reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&m),
                                             sizeof m);
                        std::printf("[%5.2f GB held, %5.2f GB committed] ", m.WorkingSetSize / 1073741824.0,
                                    m.PrivateUsage / 1073741824.0);
                    }
                    std::printf("%s\n", s.c_str());
                    std::fflush(stdout);
                },
                routines, keep, stub);
    pp.skip_report_only = fast;
    pp.run();
    ULONGLONG tl = GetTickCount64();
    auto lap = [&tl](const char* what) {
        const ULONGLONG t = GetTickCount64();
        std::printf("  timing: %s %.1fs\n", what, (t - tl) / 1000.0);
        tl = t;
    };
    lap("run");
    const PlanF p = pp.plan();
    p.save(out);
    std::printf("%s\n", p.summary().c_str());
    if (!dead.empty()) {
        const PlanF d = pp.dead_plan();
        d.save(dead);
        std::printf("dead plan: %s\n", d.summary().c_str());
    }
    if (!stubs.empty()) {
        const PlanF s = pp.stubs_plan();
        s.save(stubs);
        std::printf("stubs plan: %s\n", s.summary().c_str());
    }
    lap("plans");
    if (!report.empty()) {
        const Json r = pp.report();
        std::ofstream f(report, std::ios::binary | std::ios::trunc);
        f << r.dump(1);
        lap("report");
    }
    if (!starts.empty()) {
        const auto ent = pp.starts_out();
        // the Python writes it in text mode: CRLF on Windows
        std::ofstream f(starts, std::ios::binary | std::ios::trunc);
        for (int64_t v : ent) {
            char b[32];
            std::snprintf(b, sizeof b, "%llX\r\n", static_cast<unsigned long long>(v));
            f << b;
        }
    }
    if (!live.empty()) {
        const auto bits = pp.live_bits();
        save_npy_u8(live, bits.data(), bits.size());
        std::string js = "{\"regions\": [";
        const auto& secs = pp.regions().secs;
        for (size_t k = 0; k < secs.size(); ++k) {
            if (k) js += ", ";
            js += "[" + std::to_string(secs[k].lo) + ", " + std::to_string(secs[k].hi) + ", " +
                  std::to_string(secs[k].off) + "]";
        }
        js += "], \"packbits\": true}";
        std::string jp = live;
        const size_t dot = jp.find_last_of('.');
        const size_t sl = jp.find_last_of("\\/");
        if (dot != std::string::npos && (sl == std::string::npos || dot > sl)) jp = jp.substr(0, dot);
        std::ofstream f(jp + ".json", std::ios::binary | std::ios::trunc);
        f << js;
    }
    lap("starts and live map");
    PROCESS_MEMORY_COUNTERS pmc{};
    GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof pmc);
    std::printf("flow: %.1f s, peak working set %.2f GB, peak commit %.2f GB", (GetTickCount64() - t0) / 1000.0,
                pmc.PeakWorkingSetSize / 1073741824.0, pmc.PeakPagefileUsage / 1073741824.0);
    if (g_cache_check) std::printf(", stale decode-cache hits %lld", static_cast<long long>(g_stale_hits));
    std::printf("\n");
    return 0;
}

}  // namespace flow
