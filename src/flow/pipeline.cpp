#include "flow/pipeline.h"

#include <emmintrin.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstring>
#include <deque>
#include <exception>
#include <execution>
#include <functional>
#include <stdexcept>
#include <thread>

#include "flow/pyutil.h"

namespace flow {

namespace {

const uint8_t LONG_SUB8[7] = {0x48, 0x81, 0xEC, 0x08, 0x00, 0x00, 0x00};

double now_s() {
    using namespace std::chrono;
    return duration<double>(steady_clock::now().time_since_epoch()).count();
}

// Run the jobs on threads of their own and wait for all; the first exception
// any of them throws is thrown here.
void run_parallel(const std::vector<std::function<void()>>& jobs) {
    std::vector<std::exception_ptr> err(jobs.size());
    std::vector<std::thread> th;
    for (size_t i = 1; i < jobs.size(); ++i)
        th.emplace_back([&, i] {
            try {
                jobs[i]();
            } catch (...) {
                err[i] = std::current_exception();
            }
        });
    if (!jobs.empty()) {
        try {
            jobs[0]();
        } catch (...) {
            err[0] = std::current_exception();
        }
    }
    for (std::thread& t : th) t.join();
    for (auto& e : err)
        if (e) std::rethrow_exception(e);
}

// f(lo, hi) over [0, n) in chunks, on as many threads as there are cores
void parallel_for(size_t n, const std::function<void(size_t, size_t)>& f, size_t min_n = 2048) {
    const unsigned nt = std::max(1u, std::min<unsigned>(std::thread::hardware_concurrency(), 16));
    if (n < min_n || nt == 1) {
        f(0, n);
        return;
    }
    const size_t chunk = (n + nt * 4 - 1) / (nt * 4);
    std::atomic<size_t> next{0};
    std::vector<std::function<void()>> jobs(nt, [&] {
        for (size_t a; (a = next.fetch_add(chunk)) < n;) f(a, std::min(n, a + chunk));
    });
    run_parallel(jobs);
}

std::string fmt0(double v) {
    char b[32];
    std::snprintf(b, sizeof b, "%.0f", v);
    return b;
}

// time spent in named parts of the passes after the plan (printed at the end
// of run with --profile)
std::map<std::string, double>& prof() {
    static std::map<std::string, double> m;
    return m;
}
struct ProfT {
    const char* k;
    double t;
    explicit ProfT(const char* k_) : k(k_), t(now_s()) {}
    ~ProfT() { prof()[k] += now_s() - t; }
};

// a walker's own account of where its time went
std::string wstat(const Walker& w) {
    char b[200];
    std::snprintf(b, sizeof b, "%lld insns; constructs %lld in %.1fs, chains %lld in %.1fs",
                  static_cast<long long>(w.insns), static_cast<long long>(w.n_construct), w.t_construct,
                  static_cast<long long>(w.n_chain), w.t_chain);
    return b;
}

bool page_has_cjmp(const FImage& im, int64_t p) {
    static const uint8_t pat[4] = {0xFF, 0x64, 0x24, 0xF8};
    const int64_t e = std::min<int64_t>(p + 0x1000, im.len);
    for (int64_t k = p; k + 4 <= e; ++k)
        if (std::memcmp(im.mem.data() + k, pat, 4) == 0) return true;
    return false;
}

// Python dict repr of a {str: int-or-dict} Json object (for log lines)
std::string py_dict(const Json& j) {
    std::string o = "{";
    for (size_t k = 0; k < j.keys().size(); ++k) {
        if (k) o += ", ";
        o += py_repr_str(j.keys()[k]) + ": ";
        const Json& v = j.at(k);
        if (v.is_obj())
            o += py_dict(v);
        else if (v.is_str())
            o += py_repr_str(v.as_str());
        else if (v.type() == Json::BOOL)
            o += v.as_bool() ? "True" : "False";
        else
            o += v.dump();
    }
    return o + "}";
}

Json counter_json(const Counter& c) {
    Json j = Json::object();
    for (const auto& [k, v] : c.v) j[k] = Json(v);
    return j;
}

}  // namespace

// ------------------------------------------------------ extra regions --

// The rule of tools/devirt_flow.py: pushed and called addresses also count as
// landings in a section's tail. `--regions v1` leaves them out.
bool g_regions_v2 = true;

RangeV extra_code_regions(const FImage& im, int min_hits, bool tails) {
    RawXrefs xr(im, {});
    std::vector<int64_t> page_order;
    std::unordered_map<int64_t, int64_t> pages;
    std::unordered_map<int64_t, std::vector<int64_t>> lands;
    std::vector<const PSection*> data;
    for (const PSection& s : im.sections)
        if (!s.executable()) data.push_back(&s);
    Lite d;
    for (size_t i = 0; i < xr.tgt.size(); ++i) {
        const int k = xr.kind[i];
        if (k != 0 && k != 2) continue;
        const int64_t t = xr.tgt[i];
        bool sel = false;
        for (const PSection* s : data)
            if (t >= s->rva && t < static_cast<int64_t>(s->rva) + s->vsize) sel = true;
        if (!sel) continue;
        const int64_t src = xr.src[i];
        if (!fresh_lite(im, src, d)) continue;
        int64_t v;
        if (starts(d.ops(), "0x") && hex_op(d.ops(), v) && v == t && (d.mid == M_JMP || mf(d.mid, F_JCC))) {
            const int64_t p = t & ~int64_t(0xFFF);
            if (!pages.count(p)) page_order.push_back(p);
            pages[p] += 1;
            lands[p].push_back(t);
        }
    }
    // addresses in data sections that are pushed as a return
    // or jump address, or called; they only move where a tail region starts
    std::unordered_map<int64_t, std::vector<int64_t>> more;
    if (g_regions_v2) {
        const uint8_t* m = im.mem.data();
        const int64_t size = im.len;
        auto rel = [m](int64_t p) {
            int32_t v;
            std::memcpy(&v, m + p, 4);
            return static_cast<int64_t>(v);
        };
        static const uint8_t XCHG[4] = {0x48, 0x87, 0x2C, 0x24};
        for (const PSection* s : im.exec_sections()) {
            const int64_t lo = s->rva, hi = static_cast<int64_t>(s->rva) + s->vsize;
            int64_t p = lo;
            while (p + 7 <= hi) {
                // re.finditer: leftmost match, then continue after it
                int64_t len = 0;
                bool viaj = false;
                if (m[p] == 0x48 && m[p + 1] == 0x8D && m[p + 2] == 0x2D) {
                    if (p + 11 <= hi && std::memcmp(m + p + 7, XCHG, 4) == 0) {
                        len = 11;
                    } else if (p + 12 <= hi && m[p + 7] == 0xE9) {
                        len = 12;
                        viaj = true;
                    }
                }
                if (!len) {
                    ++p;
                    continue;
                }
                const int64_t a = p;
                p += len;
                const int64_t t = a + 7 + rel(a + 3);
                if (viaj) {
                    const int64_t j = a + 12 + rel(a + 8);
                    if (!(0 <= j && j <= size - 4 && std::memcmp(m + j, XCHG, 4) == 0)) continue;
                }
                if (0 <= t && t < size) {
                    const PSection* ts = im.section_of(t);
                    if (ts && !ts->executable()) more[t & ~int64_t(0xFFF)].push_back(t);
                }
            }
        }
        for (size_t i = 0; i < xr.tgt.size(); ++i) {
            if (xr.kind[i] != 1) continue;
            const int64_t t = xr.tgt[i];
            bool sel = false;
            for (const PSection* s : data)
                if (t >= s->rva && t < static_cast<int64_t>(s->rva) + s->vsize) sel = true;
            if (!sel) continue;
            const int64_t src = xr.src[i];
            if (!fresh_lite(im, src, d)) continue;
            int64_t v;
            if (starts(d.ops(), "0x") && hex_op(d.ops(), v) && v == t && d.mid == M_CALL)
                more[t & ~int64_t(0xFFF)].push_back(t);
        }
    }
    auto pget = [&pages](int64_t p) -> int64_t {
        auto it = pages.find(p);
        return it == pages.end() ? 0 : it->second;
    };
    std::vector<int64_t> good;
    for (int64_t p : page_order) {
        const PSection* s = im.section_of(p);
        if (pages[p] < min_hits || (s->chars & 0x80000000u)) continue;
        if (!page_has_cjmp(im, p)) continue;
        good.push_back(p);
    }
    std::sort(good.begin(), good.end());
    std::vector<std::pair<int64_t, int64_t>> out;
    for (int64_t p : good) {
        if (!out.empty() && out.back().second >= p)
            out.back().second = p + 0x1000;
        else
            out.emplace_back(p, p + 0x1000);
    }
    RangeV res;
    for (const auto& [lo, hi] : out) {
        const PSection* s = im.section_of(lo);
        res.emplace_back(lo, std::min<int64_t>(hi, static_cast<int64_t>(s->rva) + s->vsize));
    }
    if (!tails) return res;
    RangeV regs;
    for (const PSection* s : data) {
        const int64_t end = s->rsize ? static_cast<int64_t>(s->rva) + std::min(s->vsize, s->rsize) : 0;
        if (end <= s->rva) continue;
        RangeV mine;
        for (const auto& r : res)
            if (s->rva <= r.first && r.first < end) mine.push_back(r);
        bool have = false;
        int64_t lo_reg = 0;
        if (!mine.empty()) {
            lo_reg = mine[0].first;
            for (const auto& r : mine) lo_reg = std::min(lo_reg, r.first);
            have = true;
            while (lo_reg - 0x1000 >= s->rva && pget(lo_reg - 0x1000) && page_has_cjmp(im, lo_reg - 0x1000))
                lo_reg -= 0x1000;
        }
        bool have_dir = false;
        int64_t dir_end = 0;
        for (size_t k = 0; k < im.dirs.size(); ++k) {
            const auto [rva, sz] = im.dirs[k];
            if (k != 4 && sz && s->rva <= rva && rva < end) {
                const int64_t v = static_cast<int64_t>(rva) + sz;
                if (!have_dir || v > dir_end) dir_end = v;
                have_dir = true;
            }
        }
        if (have_dir && dir_end < end && !(!mine.empty() && lo_reg <= dir_end)) {
            bool hf = false;
            int64_t first = 0;
            for (const auto* dm : {&lands, &more})
                for (const auto& [p, ts] : *dm)
                    for (int64_t t : ts)
                        if (dir_end <= t && t < end && (!hf || t < first)) {
                            first = t;
                            hf = true;
                        }
            if (hf) {
                lo_reg = have ? std::min(lo_reg, first) : first;
                have = true;
            }
        } else if (!have_dir && mine.empty() && !(s->chars & 0x80000000u) && s->vsize <= 0x4000000) {
            const int64_t last = (end - 1) & ~int64_t(0xFFF);
            if (pget(last) && (page_has_cjmp(im, last) || pget(last) >= 3)) {
                std::vector<int64_t> v = lands[last];
                if (auto it = more.find(last); it != more.end()) v.insert(v.end(), it->second.begin(), it->second.end());
                lo_reg = *std::min_element(v.begin(), v.end());
                have = true;
            }
        }
        if (have) regs.emplace_back(lo_reg, end);
    }
    std::sort(regs.begin(), regs.end());
    return regs;
}

std::vector<int64_t> long_sub_sites(const FImage& im, const Code& code) {
    // every 48 81 EC 08 00 00 00, region by region in order (memchr finds the
    // first byte; the regions are searched on threads and joined in order)
    std::vector<std::vector<int64_t>> part(code.ex.size());
    const uint8_t* m = im.mem.data();
    std::vector<std::function<void()>> jobs;
    for (size_t r = 0; r < code.ex.size(); ++r)
        jobs.push_back([&, r] {
            const int64_t lo = code.ex[r].first, hi = code.ex[r].second;
            int64_t k = lo;
            while (k + 7 <= hi) {
                const void* q = std::memchr(m + k, 0x48, static_cast<size_t>(hi - 6 - k));
                if (!q) break;
                k = static_cast<const uint8_t*>(q) - m;
                if (std::memcmp(m + k, LONG_SUB8, 7) == 0) part[r].push_back(k);
                ++k;
            }
        });
    run_parallel(jobs);
    std::vector<int64_t> out;
    for (const auto& p : part) out.insert(out.end(), p.begin(), p.end());
    return out;
}

void census_chains(FImage& im, Code& code, const RawXrefs& xr, OrderedMap<ChainP>& res, std::vector<int64_t>& fail,
                   int depth) {
    for (int64_t x : long_sub_sites(im, code)) {
        std::unordered_set<int64_t> seen{x};
        std::deque<std::pair<int64_t, int>> q{{x, 0}};
        ChainP found;
        Lite d;
        while (!q.empty()) {
            const auto [a, dep] = q.front();
            q.pop_front();
            if (code.insn(a, d) && ((d.mid == M_PUSH && gpr_index(d.ops()) >= 0) || d.mid == M_PUSHFQ)) {
                ChainP ch = match_chain(code, a);
                if (ch && ch->sub_site == x)
                    if (!found || ch->push_order.size() > found->push_order.size()) found = ch;
            }
            if (dep >= depth) continue;
            for (int64_t p : back_preds(code, xr, a))
                if (seen.insert(p).second) q.emplace_back(p, dep + 1);
        }
        if (!found)
            fail.push_back(x);
        else
            res.set(x, found);
    }
}

// ---------------------------------------------------------------- roots --

static std::vector<std::pair<int64_t, int64_t>> collect_roots(FImage& im, Code& code) {
    std::vector<std::pair<int64_t, int64_t>> roots;
    const auto rf = im.runtime_functions();
    const int64_t w_pdata = why_val("pdata");
    for (const auto& r : rf) roots.emplace_back(r[0], w_pdata);
    roots.emplace_back(im.entry_rva, why_val("entry"));
    for (int64_t t : im.tls_callbacks()) roots.emplace_back(t, why_val("tls"));
    if (!im.dirs.empty() && im.dirs[0].first) {
        const uint32_t erva = im.dirs[0].first;
        const uint32_t nfun = im.u32(erva + 20), afun = im.u32(erva + 28);
        for (uint32_t k = 0; k < nfun; ++k) {
            const uint32_t r = im.u32(afun + 4 * static_cast<int64_t>(k));
            if (r && code.in_code(r)) roots.emplace_back(r, why_val("export"));
        }
    }
    const auto& rel = im.relocations();
    for (const PSection& s : im.sections) {
        if (s.executable()) continue;
        const int64_t w = why_val("reloc:" + s.name);
        auto lo = std::lower_bound(rel.begin(), rel.end(), static_cast<int64_t>(s.rva));
        auto hi = std::lower_bound(rel.begin(), rel.end(), static_cast<int64_t>(s.rva) + s.vsize);
        for (auto it = lo; it < hi; ++it) {
            const int64_t v = static_cast<int64_t>(im.u64(*it) - im.image_base);
            if (code.in_code(v)) roots.emplace_back(v, w);
        }
    }
    std::vector<int64_t> h_order;
    std::unordered_map<int64_t, int64_t> handlers;
    struct Sc {
        int64_t b, e, h, d;
    };
    std::vector<Sc> scope;
    for (const auto& r : rf) {
        const int64_t b = r[0], e = r[1], u = r[2];
        if (u & 1) continue;
        const int flags = im.mem[static_cast<size_t>(u)] >> 3;
        const int ncodes = im.mem[static_cast<size_t>(u + 2)];
        const int64_t p = u + 4 + 2 * ((ncodes + 1) & ~1);
        if (flags & 4) continue;
        if (flags & 3) {
            const int64_t h = im.u32(p);
            if (!handlers.count(h)) h_order.push_back(h);
            handlers[h] += 1;
            scope.push_back({b, e, h, p + 4});
        }
    }
    for (int64_t h : h_order)
        if (code.in_code(h)) roots.emplace_back(h, why_val("handler"));
    std::vector<int64_t> g_order;
    std::unordered_map<int64_t, int64_t> good;
    std::unordered_map<int64_t, std::vector<std::vector<std::pair<int64_t, int64_t>>>> parsed;
    for (const Sc& sc : scope) {
        const int64_t n = im.u32(sc.d);
        bool ok = 0 < n && n < 256;
        std::vector<std::pair<int64_t, int64_t>> recs;
        if (ok) {
            for (int64_t k = 0; k < n; ++k) {
                const int64_t o = sc.d + 4 + 16 * k;
                const int64_t sb = im.u32(o), se = im.u32(o + 4), sh = im.u32(o + 8), st = im.u32(o + 12);
                if (!(sc.b <= sb && sb < sc.e && sc.b < se && se <= sc.e + 1)) {
                    ok = false;
                    break;
                }
                recs.emplace_back(sh, st);
            }
        }
        if (ok) {
            if (!good.count(sc.h)) g_order.push_back(sc.h);
            good[sc.h] += 1;
            parsed[sc.h].push_back(std::move(recs));
        }
    }
    for (int64_t h : g_order) {
        const int64_t cnt = good[h];
        if (static_cast<double>(cnt) >= 0.9 * static_cast<double>(handlers[h]) && cnt >= 3)
            for (const auto& recs : parsed[h])
                for (const auto& [sh, st] : recs) {
                    if (sh > 1 && code.in_code(sh)) roots.emplace_back(sh, why_val("scope-handler"));
                    if (st && code.in_code(st)) roots.emplace_back(st, why_val("scope-target"));
                }
    }
    return roots;
}

// ------------------------------------------------------------- Pipeline --

double Pipeline::secs() const { return now_s() - t0_; }

Pipeline::~Pipeline() = default;

static FImage load_fimage(const std::string& path) {
    FImage im;
    im.load(path);
    return im;
}
static std::vector<PlanF> load_plans(const std::vector<std::string>& paths) {
    std::vector<PlanF> v;
    for (const std::string& p : paths) v.push_back(PlanF::load(p));
    return v;
}
static Json load_routines(const std::string& path) { return path.empty() ? Json() : load_json(path); }

Pipeline::Pipeline(const std::string& path, Log logfn, const std::string& routines,
                   const std::vector<std::string>& keep_plans, const std::vector<std::string>& stub_plans)
    : Pipeline(load_fimage(path), std::move(logfn), load_routines(routines), load_plans(keep_plans),
               load_plans(stub_plans)) {}

Pipeline::Pipeline(FImage im, Log logfn, const Json& routines, std::vector<PlanF> keep_plans,
                   const std::vector<PlanF>& stub_plans)
    : log_(std::move(logfn)), im_(std::move(im)) {
    t0_ = now_s();
    keep_plans_ = std::move(keep_plans);
    for (const PlanF& kp : keep_plans_)
        for (const PlanPatchF& p : kp.patches)
            if (p.kind == KIND_BAKE) {
                std::memcpy(im_.mem.data() + p.rva, p.data.data(), p.data.size());
                baked_.emplace_back(p.rva, static_cast<int64_t>(p.data.size()));
            }
    {
        ProfT pt_("start: code regions in data sections");
        extra_ = extra_code_regions(im_);
    }
    if (!routines.is_null()) model_.load_from(routines, im_.image_base);
    reg_ = Regions(im_, extra_);
    code_ = std::make_unique<Code>(im_, extra_, &model_);
    keep_ = std::make_unique<BitMap>(reg_);
    keep_wipe_ = std::make_unique<BitMap>(reg_);
    for (const auto& [rva, n] : baked_) {
        keep_->set(rva, n);
        keep_wipe_->set(rva, n);
    }
    for (const PlanF& kp : keep_plans_) {
        for (const PlanPatchF& p : kp.patches) {
            keep_->set(p.rva, static_cast<int64_t>(p.data.size()));
            if (p.kind == KIND_STUB)
                stub_ranges_.emplace_back(p.rva, static_cast<int64_t>(p.data.size()));
            else
                keep_wipe_->set(p.rva, static_cast<int64_t>(p.data.size()));
        }
        for (const auto& [rva, n] : kp.wipes) {
            keep_->set(rva, n);
            keep_wipe_->set(rva, n);
        }
    }
    std::map<int64_t, std::vector<uint8_t>> sp;
    for (const PlanF& p : stub_plans)
        for (const PlanPatchF& x : p.patches)
            if (x.kind == KIND_STUB) sp[x.rva] = x.data;
    for (auto& [rva, data] : sp) stub_patches_.emplace_back(rva, data);
    for (const auto& [rva, data] : stub_patches_) stub_ranges_.emplace_back(rva, static_cast<int64_t>(data.size()));
    log("routine table: " + std::to_string(model_.r.size()) + " routines; keep plans: " +
        std::to_string(keep_plans_.size()) + " (" + std::to_string(baked_.size()) + " baked values)");
    {
        ProfT pt_("start: raw references");
        xr_ = std::make_unique<RawXrefs>(im_, extra_);
    }
    log("image: " + std::to_string(code_->ex.size()) + " code regions (+" + std::to_string(extra_.size()) +
        " in data sections) " + fmt0(secs()) + "s");

    g_phase = "census";
    Code& code = *code_;
    {
        ProfT pt_("start: census");
        census_chains(im_, code, *xr_, census_, cfail_);
    }
    log("census: " + std::to_string(census_.size()) + " chains, " + std::to_string(cfail_.size()) +
        " long sub sites without one " + fmt0(secs()) + "s");

    g_phase = "wa0";
    auto wa0 = std::make_unique<Walker>(im_, code, reg_, false);
    {
        ProfT pt_("start: walk of the routines");
        Roots r;
        const int64_t w = why_val("routine");
        for (const auto& [x, ch] : census_.items()) r.emplace_back(ch->G, w);
        wa0->walk(r);
    }
    log("  walk of the routines: " + wstat(*wa0));
    std::vector<std::pair<int64_t, int64_t>> check_writes = model_.writes;
    bool any_clob = false;
    for (const auto& [g, m] : model_.r)
        if (m.has_clobbers) any_clob = true;
    if (check_writes.empty() && any_clob) {
        g_phase = "static_writes";
        ProfT pt_("start: static writes");
        check_writes = static_writes(im_, code, wa0->bm);
        have_static_writes_ = true;
        static_writes_n_ = check_writes.size();
        int64_t n = 0;
        for (int64_t i = 0; i < reg_.total; ++i)
            if (wa0->bm.f[static_cast<size_t>(i)] & ISTART) ++n;
        wa0_istarts_ = n;
        log("routine table read from the code: " + std::to_string(check_writes.size()) +
            " locations its code may write (from " + std::to_string(n) + " instructions)");
    }
    // a dword a guard publishes when it runs is written by a routine whatever
    // the walk above saw: a check that reads one has no single outcome
    {
        std::set<int64_t> pubs;
        for (const auto& [g, m] : model_.r)
            for (int64_t p : m.publish_rvas) pubs.insert(p);
        for (int64_t p : pubs) check_writes.emplace_back(p, 4);
    }
    g_phase = "find_checks";
    {
        ProfT pt_("start: checks");
        checks_ = find_checks(im_, code, *xr_, cfail_, check_writes, baked_);
    }
    {
        int64_t one = 0;
        Counter why;
        // Python: Counter over the dict's values (insertion order of out)
        std::vector<std::pair<int64_t, const CheckFold*>> v;
        for (const auto& [c, ck] : checks_) v.emplace_back(c, &ck);
        for (const auto& [c, ck] : checks_)
            if (!ck.why) ++one;
        std::string w = "{";
        std::map<std::string, int64_t> cnt;
        for (const auto& [c, ck] : checks_)
            if (ck.why) cnt[*ck.why]++;
        bool first = true;
        for (const auto& [k, n] : cnt) {
            w += (first ? "" : ", ") + py_repr_str(k) + ": " + std::to_string(n);
            first = false;
        }
        w += "}";
        log("checks: " + std::to_string(one) + " of " + std::to_string(checks_.size()) +
            " sites have one outcome on the baked image (" + w + ") " + fmt0(secs()) + "s");
    }

    g_phase = "roots";
    Roots roots = collect_roots(im_, code);
    // filter_roots
    {
        std::unordered_set<int64_t> inside, starts_;
        for (const auto& [x, ch] : census_.items()) {
            starts_.insert(ch->S);
            for (const auto& [a, n] : ch->insns)
                for (int64_t b = a; b < a + n; ++b) inside.insert(b);
        }
        const int64_t w_pdata = why_val("pdata");
        Roots keep;
        for (const auto& [r, why] : roots) {
            if (why == w_pdata && inside.count(r) && !starts_.count(r))
                dropped_roots_.push_back(r);
            else
                keep.emplace_back(r, why);
        }
        roots_ = std::move(keep);
    }
    std::unordered_set<int64_t> ptr_out, ptr_in;
    if (!extra_.empty()) {
        const auto& rel = im_.relocations();
        for (const PSection& s : im_.sections) {
            if (s.executable()) continue;
            auto lo = std::lower_bound(rel.begin(), rel.end(), static_cast<int64_t>(s.rva));
            auto hi = std::lower_bound(rel.begin(), rel.end(), static_cast<int64_t>(s.rva) + s.vsize);
            for (auto it = lo; it < hi; ++it) {
                const int64_t r = *it;
                const int64_t v = static_cast<int64_t>(im_.u64(r) - im_.image_base);
                if (code.in_code(v)) {
                    bool in = false;
                    for (const auto& [elo, ehi] : extra_)
                        if (elo <= r && r < ehi) in = true;
                    (in ? ptr_in : ptr_out).insert(v);
                }
            }
        }
    }
    {
        Roots keep;
        const int64_t w_pdata = why_val("pdata");
        for (const auto& [r, why] : roots_) {
            const bool prot_rec = why == w_pdata;
            const bool prot_ptr = why < 0 && starts(why_str(static_cast<int>(-1 - why)), "reloc:") && ptr_in.count(r) &&
                                  !ptr_out.count(r);
            if ((prot_rec || prot_ptr) && (wa0->bm.get(r) & (START | ISTART | CODE | IDIOM | CHAIN)) &&
                !wa0->call_targets.count(r)) {
                bool outside_ref = false;
                for (const BranchRef& b : confirmed_branches_to(code, *xr_, r))
                    if (!(wa0->bm.get(b.src) & (CODE | IDIOM | CHAIN))) {
                        outside_ref = true;
                        break;
                    }
                if (!outside_ref) {
                    if (prot_ptr)
                        dropped_own_pointers_.push_back(r);
                    else
                        dropped_prot_.push_back(r);
                    continue;
                }
            }
            keep.emplace_back(r, why);
        }
        roots_ = std::move(keep);
    }
    if (!dropped_own_pointers_.empty()) {
        std::unordered_set<int64_t> u(dropped_own_pointers_.begin(), dropped_own_pointers_.end());
        log("roots: " + std::to_string(u.size()) +
            " code pointers kept in the protection's own padding point into routine code and are not used as roots");
    }
    log("roots: " + std::to_string(roots_.size()) + " (dropped " + std::to_string(dropped_roots_.size()) +
        " inside chains, " + std::to_string(dropped_prot_.size()) + " on protection code) " + fmt0(secs()) + "s");
    {
        const auto secs_ = im_.exec_sections();
        const PSection* arx = secs_[0];
        for (const PSection* s : secs_)
            if (s->rva > arx->rva) arx = s;
        arxan_sec_ = {arx->rva, static_cast<int64_t>(arx->rva) + arx->vsize};
    }
}

std::vector<std::pair<int64_t, int64_t>> Pipeline::roots_with(const std::vector<int64_t>& rs,
                                                              const std::string& why) const {
    std::vector<std::pair<int64_t, int64_t>> o;
    const int64_t w = why_val(why);
    for (int64_t r : rs) o.emplace_back(r, w);
    return o;
}

std::set<int64_t> Pipeline::gset() const {
    std::set<int64_t> s;
    for (const auto& [x, ch] : census_.items()) s.insert(ch->G);
    for (const auto& [g, m] : model_.r) s.insert(g);
    return s;
}

// ------------------------------------------------------------ the sweep --

Pipeline::Recs Pipeline::rec_arrays(bool exclude_prot, bool only_prot) const {
    const auto rf = im_.runtime_functions();
    const auto [lo, hi] = arxan_sec_;
    std::vector<int64_t> fb, fe, bi;
    for (const auto& r : rf) {
        const int64_t b = r[0], e = r[1];
        const bool inp = b >= lo && b < hi;
        bool sel = e > b;
        if (exclude_prot) sel = sel && !inp;
        if (only_prot) sel = sel && inp;
        if (!sel) continue;
        int64_t idx = -1;
        for (const auto& s : reg_.secs)
            if (b >= s.lo && b < s.hi && e <= s.hi) idx = b - s.lo + s.off;
        if (idx < 0) continue;
        fb.push_back(b);
        fe.push_back(e);
        bi.push_back(idx);
    }
    std::vector<size_t> o(fb.size());
    for (size_t i = 0; i < o.size(); ++i) o[i] = i;
    std::stable_sort(o.begin(), o.end(), [&bi](size_t a, size_t b) { return bi[a] < bi[b]; });
    Recs r;
    for (size_t i : o) {
        r.fb.push_back(fb[i]);
        r.fe.push_back(fe[i]);
        r.bi.push_back(bi[i]);
        r.ei.push_back(bi[i] + (fe[i] - fb[i]));
    }
    return r;
}

std::unique_ptr<Walker> Pipeline::new_ws(Code& code) {
    auto ws = std::make_unique<Walker>(im_, code, reg_, false);
    ws->atomic = false;
    ws->stop_f = &w1_->bm;
    ws->keep_src = true;
    return ws;
}

std::pair<Pipeline::Roots, Json> Pipeline::sweep(Walker& w, Walker& ws, Code& code, const std::string& tag) {
    const ByteMap& bm = w.bm;
    const ByteMap& bms = ws.bm;
    const uint8_t* mem = im_.mem.data();
    const Recs recs = rec_arrays(true, false);
    Sweeper sw(im_, code);
    Roots roots;
    int rounds = 0;
    std::unordered_set<int64_t> evaluated;
    Counter accepted_why;
    std::vector<std::pair<int64_t, std::string>> reasons;
    const double ts = now_s();
    auto joins = [&](int64_t p) { return ((bm.get(p) | bms.get(p)) & (START | ISTART)) != 0; };
    const int64_t total = reg_.total;
    const int64_t wtag = why_val(tag);
    // A gap is the unwalked bytes after a walked run; its verdict reads the
    // flags from 16 bytes before it to the next walked byte, and the record
    // its start lies in. A round walks from the gaps it accepted, so in the
    // next round only the gaps within reach of a byte that walk changed, or
    // under a record start that became live, can come out differently: the
    // others keep the verdict they had (the block memo answers them the
    // same, and nothing else they read has changed). Every round's accepted
    // list, its order and the memo's contents are those of a full pass.
    // Nothing outlives the pass.
    struct GapRes {
        int64_t j;
        int64_t pos;    // cj for a rejected gap, c for an accepted one
        int32_t why;    // index into why_tab
        uint8_t state;  // 0 not a gap that counts, 1 rejected, 2 accepted
    };
    std::vector<std::string> why_tab;
    std::unordered_map<std::string, int32_t> why_idx;
    auto why_id = [&](const std::string& s) {
        auto it = why_idx.find(s);
        if (it != why_idx.end()) return it->second;
        const int32_t k = static_cast<int32_t>(why_tab.size());
        why_tab.push_back(s);
        why_idx.emplace(s, k);
        return k;
    };
    const int32_t W_NOEND = why_id("not a candidate: no walked instruction ends here");
    const int32_t W_FALL = why_id("not a candidate: after an instruction that falls through");
    const int32_t W_CC = why_id("int3 padding only");
    std::vector<GapRes> gaps;   // every gap start's verdict, by j
    std::vector<std::pair<int64_t, int64_t>> touched;  // index ranges the last walk set flags in
    std::vector<int64_t> lb_prev;
    Bits walked;
    std::vector<int64_t> lb, le;
    Lite d;
    auto eval = [&](int64_t j, GapRes& g) {
        g.j = j;
        g.state = 0;
        const int64_t k = static_cast<int64_t>(std::upper_bound(lb.begin(), lb.end(), j) - lb.begin()) - 1;
        if (k < 0 || !(j < le[static_cast<size_t>(k)])) return;
        int64_t se = walked.next_set(j);
        if (se < 0) se = total;
        const int64_t re_ = le[static_cast<size_t>(k)];
        const Regions::Sec* rg = reg_.region_of(j);
        if (!rg) return;
        const int64_t slo = rg->lo, shi = rg->hi, off = rg->off;
        const int64_t cj = slo + j - off;
        auto fcomb = [&](int64_t i) {
            return static_cast<uint8_t>(bm.f[static_cast<size_t>(i)] | bms.f[static_cast<size_t>(i)]);
        };
        g.state = 1;
        g.pos = cj;
        int64_t kk = j - 1;
        while (kk > j - 16 && kk > off && !(fcomb(kk) & (START | ISTART))) --kk;
        if (kk < off || !(fcomb(kk) & (START | ISTART))) {
            g.why = W_NOEND;
            return;
        }
        const int64_t a = slo + kk - off;
        if (!code.insn(a, d) || a + d.size != cj) {
            g.why = W_NOEND;
            return;
        }
        if (!(mf(d.mid, F_NOFALL) || (d.mid == M_INT && d.ops() == "0x29"))) {
            g.why = W_FALL;
            return;
        }
        const int64_t region_end = shi;
        const int64_t stop = slo + std::min(se, off + shi - slo) - off;
        const int64_t rec_end = slo + std::min(re_, off + shi - slo) - off;
        int64_t c = cj;
        while (c < stop && mem[c] == 0xCC) ++c;
        if (c >= stop) {
            g.why = W_CC;
            return;
        }
        evaluated.insert(c);
        const auto [ok, why] = sw.block(c, stop, rec_end, joins, region_end);
        g.why = why_id(why);
        if (ok) {
            g.state = 2;
            g.pos = c;
            accepted_why[why] += 1;
        }
    };
    // The same verdicts for many gaps at once: on threads, each gap is taken
    // as far as it goes from the flags as they stand (they do not change
    // during a round) with a decoder of the thread's own, the block verdict
    // worked out unless the block memo already has it. Then, in gap order,
    // what eval() leaves behind is recorded as eval() would: the decode in
    // the code's cache, the block verdict in the memo, the candidate, the
    // accepted count. A gap whose decode the cache already holds differently,
    // or whose block verdict the memo already holds, takes the cache's or
    // memo's answer (eval() itself is run for it), so the result is that of
    // eval() gap by gap.
    struct Pre {
        int64_t j = 0;
        uint8_t stage = 0;  // 0 not a gap that counts, 1 rejected before the decode, 2 decoded
        int64_t cj = 0, a = 0, stop = 0, rec_end = 0, c = 0, region_end = 0;
        Lite d;
        bool dec_ok = false;
        bool has_block = false;
        std::pair<bool, std::string> block;
    };
    auto pre_eval = [&](int64_t j, Pre& p) {
        p.j = j;
        p.stage = 0;
        const int64_t k = static_cast<int64_t>(std::upper_bound(lb.begin(), lb.end(), j) - lb.begin()) - 1;
        if (k < 0 || !(j < le[static_cast<size_t>(k)])) return;
        int64_t se = walked.next_set(j);
        if (se < 0) se = total;
        const int64_t re_ = le[static_cast<size_t>(k)];
        const Regions::Sec* rg = reg_.region_of(j);
        if (!rg) return;
        const int64_t slo = rg->lo, shi = rg->hi, off = rg->off;
        p.cj = slo + j - off;
        auto fcomb = [&](int64_t i) {
            return static_cast<uint8_t>(bm.f[static_cast<size_t>(i)] | bms.f[static_cast<size_t>(i)]);
        };
        p.stage = 1;
        int64_t kk = j - 1;
        while (kk > j - 16 && kk > off && !(fcomb(kk) & (START | ISTART))) --kk;
        if (kk < off || !(fcomb(kk) & (START | ISTART))) return;
        p.stage = 2;
        p.a = slo + kk - off;
        p.dec_ok = fresh_lite(code.image(), p.a, p.d);
        if (!p.dec_ok || p.a + p.d.size != p.cj) return;
        if (!(mf(p.d.mid, F_NOFALL) || (p.d.mid == M_INT && p.d.ops() == "0x29"))) return;
        p.region_end = shi;
        p.stop = slo + std::min(se, off + shi - slo) - off;
        p.rec_end = slo + std::min(re_, off + shi - slo) - off;
        int64_t c = p.cj;
        while (c < p.stop && mem[c] == 0xCC) ++c;
        p.c = c;
        if (c >= p.stop) return;
        if (sw.remembered(c, p.stop, p.rec_end)) return;
        p.block = sw.evaluate(c, p.stop, p.rec_end, joins, p.region_end);
        p.has_block = true;
    };
    auto replay = [&](const Pre& p, GapRes& g) {
        g.j = p.j;
        g.state = 0;
        if (p.stage == 0) return;
        g.state = 1;
        g.pos = p.cj;
        if (p.stage == 1) {
            g.why = W_NOEND;
            return;
        }
        if (code.contains(p.a)) {
            // the cache answers this decode: eval() as it stands
            eval(p.j, g);
            return;
        }
        code.put(p.a, p.d);
        if (!p.dec_ok || p.a + p.d.size != p.cj) {
            g.why = W_NOEND;
            return;
        }
        if (!(mf(p.d.mid, F_NOFALL) || (p.d.mid == M_INT && p.d.ops() == "0x29"))) {
            g.why = W_FALL;
            return;
        }
        if (p.c >= p.stop) {
            g.why = W_CC;
            return;
        }
        evaluated.insert(p.c);
        const std::pair<bool, std::string>* r = sw.remembered(p.c, p.stop, p.rec_end);
        if (!r) {
            if (!p.has_block) throw std::logic_error("sweep: a block verdict was not worked out");
            r = &sw.remember(p.c, p.stop, p.rec_end, p.block);
        }
        g.why = why_id(r->second);
        if (r->first) {
            g.state = 2;
            g.pos = p.c;
            accepted_why[r->second] += 1;
        }
    };
    auto eval_many = [&](const std::vector<int64_t>& js, std::vector<GapRes>& out) {
        out.resize(js.size());
        if (js.size() < 4096) {
            for (size_t i = 0; i < js.size(); ++i) eval(js[i], out[i]);
            return;
        }
        // in slices, so that the per-gap state stays small
        const size_t SL = size_t(1) << 16;
        std::vector<Pre> pre;
        for (size_t s = 0; s < js.size(); s += SL) {
            const size_t n = std::min(SL, js.size() - s);
            pre.assign(n, Pre());
            parallel_for(n, [&](size_t i0, size_t i1) {
                for (size_t i = i0; i < i1; ++i) pre_eval(js[s + i], pre[i]);
            });
            for (size_t i = 0; i < n; ++i) replay(pre[i], out[s + i]);
        }
    };
    auto is_gap = [&](int64_t j) { return j >= 1 && j < total && walked.test(j - 1) && !walked.test(j); };
    while (true) {
        ++rounds;
        const double tr = now_s();
        if (rounds == 1) {
            walked = bm.mask_or(bms, CODE | IDIOM | CHAIN);
        } else {
            // only where the last walk set a flag can a byte have become walked
            for (const auto& [lo, hi] : touched)
                for (int64_t i = lo; i < hi; ++i)
                    if ((bm.f[static_cast<size_t>(i)] | bms.f[static_cast<size_t>(i)]) & (CODE | IDIOM | CHAIN))
                        walked.set(i);
        }
        lb.clear();
        le.clear();
        for (size_t k = 0; k < recs.bi.size(); ++k) {
            const size_t i = static_cast<size_t>(recs.bi[k]);
            if ((bm.f[i] | bms.f[i]) & (START | ISTART)) {
                lb.push_back(recs.bi[k]);
                le.push_back(recs.ei[k]);
            }
        }
        Roots nw;
        if (rounds == 1) {
            std::vector<int64_t> js;
            for (const auto& [rs, re] : walked.runs())
                if (re < total) js.push_back(re);
            eval_many(js, gaps);
            for (const GapRes& g : gaps)
                if (g.state == 2) nw.emplace_back(g.pos, wtag);
        } else {
            // where the last walk set flags (the walker's own log of it)
            std::vector<std::pair<int64_t, int64_t>> dirty;
            dirty.reserve(touched.size() + 64);
            for (const auto& [lo, hi] : touched)
                dirty.emplace_back(std::max<int64_t>(0, lo - 17), std::min<int64_t>(total, hi + 17));
            // record starts that became live: every gap up to the next live start
            {
                size_t q = 0;
                for (size_t k = 0; k < lb.size(); ++k) {
                    while (q < lb_prev.size() && lb_prev[q] < lb[k]) ++q;
                    if (q < lb_prev.size() && lb_prev[q] == lb[k]) continue;
                    int64_t nxt = total;
                    for (size_t k2 = k + 1; k2 < lb.size(); ++k2)
                        if (lb[k2] > lb[k]) {
                            nxt = lb[k2];
                            break;
                        }
                    dirty.emplace_back(lb[k], nxt);
                }
            }
            std::sort(dirty.begin(), dirty.end());
            std::vector<std::pair<int64_t, int64_t>> merged;
            for (auto [a, b] : dirty) {
                // a gap whose bytes run into a: from that gap's start
                if (a > 0 && !walked.test(a)) {
                    int64_t p = a - 1;
                    while (p >= 0 && !walked.test(p)) --p;
                    a = p + 1;
                }
                if (!merged.empty() && a <= merged.back().second)
                    merged.back().second = std::max(merged.back().second, b);
                else
                    merged.emplace_back(a, b);
            }
            // the gap starts of every dirty range, in order, judged together
            std::vector<int64_t> js;
            std::vector<size_t> upto;  // js index where each range's gaps end
            for (const auto& [a, b] : merged) {
                for (int64_t j = walked.next_zero(std::max<int64_t>(a, 1)); j >= 0 && j < b && j < total;) {
                    if (is_gap(j)) js.push_back(j);
                    const int64_t s = walked.next_set(j);
                    if (s < 0) break;
                    j = walked.next_zero(s);
                }
                upto.push_back(js.size());
            }
            std::vector<GapRes> res;
            eval_many(js, res);
            std::vector<GapRes> next;
            next.reserve(gaps.size() + 1024);
            size_t gi = 0, ri = 0;
            for (size_t m = 0; m < merged.size(); ++m) {
                const auto [a, b] = merged[m];
                while (gi < gaps.size() && gaps[gi].j < a) next.push_back(gaps[gi++]);
                while (gi < gaps.size() && gaps[gi].j < b) ++gi;  // their verdicts are made again
                for (; ri < upto[m]; ++ri) {
                    next.push_back(res[ri]);
                    if (res[ri].state == 2) nw.emplace_back(res[ri].pos, wtag);
                }
            }
            while (gi < gaps.size()) next.push_back(gaps[gi++]);
            gaps.swap(next);
        }
        lb_prev = lb;
        const double tj = now_s();
        if (nw.empty()) break;
        roots.insert(roots.end(), nw.begin(), nw.end());
        touched.clear();
        ws.touch_log = &touched;
        ws.walk(nw);
        ws.touch_log = nullptr;
        char tb[64];
        std::snprintf(tb, sizeof tb, " (judged in %.1fs, walked in %.1fs)", tj - tr, now_s() - tj);
        log(tag + " round " + std::to_string(rounds) + ": " + std::to_string(nw.size()) + " accepted (" +
            std::to_string(roots.size()) + " in all) " + fmt0(now_s() - ts) + "s" + tb);
    }
    reasons.clear();
    for (const GapRes& g : gaps)
        if (g.state == 1) reasons.emplace_back(g.pos, why_tab[static_cast<size_t>(g.why)]);
    Counter rej;
    for (const auto& [a, r] : reasons) rej[r] += 1;
    Json st = Json::object();
    st["rounds"] = Json(rounds);
    st["records_considered"] = Json(static_cast<int64_t>(recs.fb.size()));
    st["gaps_seen_last_round"] = Json(static_cast<int64_t>(reasons.size()));
    st["candidates_evaluated"] = Json(static_cast<int64_t>(evaluated.size()));
    st["accepted"] = Json(static_cast<int64_t>(roots.size()));
    st["accepted_how"] = counter_json(accepted_why);
    {
        auto v = rej.v;
        std::stable_sort(v.begin(), v.end(), [](const auto& x, const auto& y) { return x.second > y.second; });
        Json j = Json::object();
        for (const auto& [k, n] : v) j[k] = Json(n);
        st["left_by_reason"] = j;
        Json s = Json::object();
        auto sr = reasons;
        std::sort(sr.begin(), sr.end());
        for (const auto& [k, n] : rej.v) {
            Json l = Json::array();
            for (const auto& [a, r] : sr)
                if (r == k && l.size() < 40) l.push(Json(hex8(a)));
            s[k] = l;
        }
        st["left_samples"] = s;
    }
    return {roots, st};
}

Json Pipeline::kept_only_content(Walker& ws, const Roots& roots) {
    const uint8_t* mem = im_.mem.data();
    int64_t nj = 0;
    for (const auto& s : reg_.secs) {
        const int64_t n = (s.hi - s.lo) - 3;
        for (int64_t i = 0; i < n; ++i) {
            const uint8_t* p = mem + s.lo + i;
            if (p[0] == 0xFF && p[1] == 0x64 && p[2] == 0x24 && p[3] == 0xF8 &&
                (ws.bm.f[static_cast<size_t>(s.off + i)] & (CODE | IDIOM | CHAIN)))
                ++nj;
        }
    }
    std::vector<int64_t> longs;
    for (int64_t x : long_sub_sites(im_, *code_))
        if (ws.bm.f[static_cast<size_t>(ws.bm.idx(x))] & (CODE | START)) longs.push_back(x);
    std::vector<int64_t> rr;
    for (const auto& [r, w] : roots) rr.push_back(r);
    Planner pl(im_, *code_, *xr_, ws, rr, nullptr, reg_);
    pl.plan_peephole();
    Json o = Json::object();
    o["jmp_rsp8_bytes_in_kept_only_code"] = Json(nj);
    o["idioms"] = Json(static_cast<int64_t>(ws.idioms.size()));
    Counter kinds;
    int64_t with_inner = 0;
    for (const auto& [s, i] : ws.idioms.items()) {
        kinds[ikind_name(i->kind)] += 1;
        if (!i->inner.empty()) ++with_inner;
    }
    o["idioms_by_kind"] = counter_json(kinds);
    o["constructs_with_a_routine_inside"] = Json(with_inner);
    o["constructs_without_continuation"] = Json(static_cast<int64_t>(ws.unknowns.size()));
    {
        Json l = Json::array();
        for (const auto& [a, u] : ws.unknowns)
            if (l.size() < 50) l.push(Json(hex8(a)));
        o["constructs_without_continuation_first"] = l;
    }
    int64_t cw = 0;
    for (const auto& [x, ch] : census_.items())
        if (ws.bm.f[static_cast<size_t>(ws.bm.idx(x))] & START) ++cw;
    o["chains_walked_as_plain_code"] = Json(cw);
    o["long_form_sites"] = Json(static_cast<int64_t>(longs.size()));
    {
        Json l = Json::array();
        for (size_t k = 0; k < longs.size() && k < 100; ++k) l.push(Json(hex8(longs[k])));
        o["long_form_sites_list"] = l;
    }
    o["pairs_by_form"] = counter_json(pl.peep_count);
    {
        std::vector<int64_t> ks;
        for (const auto& [s, i] : ws.idioms.items()) ks.push_back(s);
        std::sort(ks.begin(), ks.end());
        Json l = Json::array();
        for (size_t k = 0; k < ks.size() && k < 40; ++k) l.push(Json(hex8(ks[k])));
        o["idiom_sample"] = l;
    }
    return o;
}

Json Pipeline::sweep_summary(Walker& w1, Walker& ws, const Roots& roots, const Json& st) {
    int64_t kept = 0, kept_text = 0;
    const int64_t t_end = reg_.secs[0].hi - reg_.secs[0].lo;
    for (int64_t i = 0; i < reg_.total; ++i) {
        if ((ws.bm.f[static_cast<size_t>(i)] & (CODE | IDIOM | CHAIN)) &&
            !(w1.bm.f[static_cast<size_t>(i)] & (CODE | IDIOM | CHAIN))) {
            ++kept;
            if (i < t_end) ++kept_text;
        }
    }
    Json out = st;
    int64_t stub_starts = 0;
    for (const auto& [rva, d] : stub_patches_)
        if (ws.bm.get(rva) & START) ++stub_starts;
    std::set<int64_t> loads;
    const int64_t lo = 0x2326626C, hi = 0x23266274 + 8;
    for (const DataRef& r : ws.datarefs)
        if (lo <= r.t && r.t < hi) loads.insert(r.pc);
    out["bytes_kept_only"] = Json(kept);
    out["bytes_kept_only_in_text"] = Json(kept_text);
    out["insns_kept_only"] = Json(ws.insns);
    out["routine_stubs_reached"] = Json(stub_starts);
    out["protection_slot_loads"] = Json(static_cast<int64_t>(loads.size()));
    {
        Json l = Json::array();
        for (int64_t x : loads)
            if (l.size() < 60) l.push(Json(hex8(x)));
        out["protection_slot_load_sites"] = l;
    }
    Json k = kept_only_content(ws, roots);
    for (size_t i = 0; i < k.keys().size(); ++i) out[k.keys()[i]] = k.at(i);
    return out;
}

static std::string scalars_dict(const Json& j) {
    Json s = Json::object();
    for (size_t i = 0; i < j.keys().size(); ++i)
        if (!j.at(i).is_obj() && !j.at(i).is_arr()) s[j.keys()[i]] = j.at(i);
    return py_dict(s);
}

Pipeline::Saved Pipeline::stubs_on(bool check_claimed) {
    Saved saved;
    for (const auto& [rva, data] : stub_patches_) {
        if (check_claimed && pl_ && pl_->claimed.any_in(rva, static_cast<int64_t>(data.size()))) continue;
        saved.emplace_back(rva, std::vector<uint8_t>(im_.mem.data() + rva, im_.mem.data() + rva + data.size()));
        std::memcpy(im_.mem.data() + rva, data.data(), data.size());
    }
    return saved;
}

void Pipeline::stubs_off(const Saved& saved) {
    for (auto it = saved.rbegin(); it != saved.rend(); ++it)
        std::memcpy(im_.mem.data() + it->first, it->second.data(), it->second.size());
}

void Pipeline::analyse() {
    Code& code = *code_;
    g_phase = "walk1";
    w1_ = std::make_unique<Walker>(im_, code, reg_, true);
    w1_->checks = &checks_;
    w1_->keep_src = true;
    w1_->keep_found_in = true;
    {
        ProfT pt_("walk 1");
        w1_->walk(roots_);
    }
    log("walk 1 walked: " + std::to_string(w1_->insns) + " insns " + fmt0(secs()) + "s");
    log("  walk 1: " + wstat(*w1_));
    // The sweep without the routines' stubs only feeds the report: the fast
    // form leaves it out (its root reason is interned all the same, so the
    // reasons keep their numbers)
    if (sweep_on_ && !stub_patches_.empty() && skip_report_only) why_val("sweep");
    if (sweep_on_ && !stub_patches_.empty() && !skip_report_only) {
        g_phase = "sweep0";
        auto ws0 = new_ws(code);
        auto [r0, st0] = sweep(*w1_, *ws0, code, "sweep");
        sweep_before_ = sweep_summary(*w1_, *ws0, r0, st0);
        log("sweep without stubs: " + scalars_dict(sweep_before_));
    }
    if (!skip_report_only) {
        g_phase = "wr";
        Walker wr(im_, code, reg_, false);
        wr.atomic = false;
        wr.follow_refs = false;
        wr.tables = false;
        const auto gs = gset();
        wr.walk(roots_with(std::vector<int64_t>(gs.begin(), gs.end()), "routine"));
    }
    g_phase = "sweep";
    const Saved saved = stubs_on(false);
    if (!saved.empty()) {
        code_s_own_ = std::make_unique<Code>(im_, extra_, &model_);
        code_s_ = code_s_own_.get();
    } else {
        code_s_ = &code;
    }
    ws_ = new_ws(*code_s_);
    if (sweep_on_) {
        ProfT pt_("sweep");
        auto [r, st] = sweep(*w1_, *ws_, *code_s_, "sweep");
        sweep_roots_ = r;
        // what the kept-only code holds is counted for the report alone
        sweep_stats_ = skip_report_only ? st : sweep_summary(*w1_, *ws_, sweep_roots_, st);
        log("sweep: " + scalars_dict(sweep_stats_));
    }
    stubs_off(saved);
    for (int64_t r : dropped_prot_)
        if (w1_->bm.get(r) & (START | ISTART)) dropped_reached_.push_back(r);
    log("walk 1: " + std::to_string(w1_->insns) + " insns, " + std::to_string(w1_->idioms.size()) + " idioms, " +
        std::to_string(w1_->chains.size()) + " chains; dropped records reached anyway: " +
        std::to_string(dropped_reached_.size()) + " " + fmt0(secs()) + "s");
    g_phase = "plan";
    std::vector<int64_t> rr;
    for (const auto& [r, w] : roots_) rr.push_back(r);
    for (const auto& [r, w] : sweep_roots_) rr.push_back(r);
    pl_ = std::make_unique<Planner>(im_, code, *xr_, *w1_, rr, keep_.get(), reg_);
    pl_->compute_fold_dead = !skip_report_only;
    for (const auto& [g, m] : model_.r)
        if (m.publishes) pl_->publishers.insert(g);
    const double tp0 = secs();
    pl_->plan_chains();
    const double tp1 = secs();
    pl_->plan_checks(checks_);
    {
        Counter c;
        for (const auto& [k, r] : pl_->check_res.items()) c[r.ok ? std::string("ok") : r.detail] += 1;
        log("checks folded: " + py_dict(counter_json(c)));
    }
    const double tp2 = secs();
    pl_->plan_idioms();
    const double tp3 = secs();
    pl_->plan_peephole();
    const double tp4 = secs();
    log("peephole: seen " + py_dict(counter_json(pl_->peep_count)) + ", folded " +
        py_dict(counter_json(pl_->peep_done)) + ", skipped " + py_dict(counter_json(pl_->peep_skip)));
    log("plan phases: chains " + fmt0(tp1 - tp0) + "s, checks " + fmt0(tp2 - tp1) + "s, idioms " + fmt0(tp3 - tp2) +
        "s (sorting " + fmt0(pl_->t_sort) + "s, in plan_idiom " + fmt0(pl_->t_calls) + "s: decoding " +
        fmt0(pl_->t_decode) + "s, liveness after constructs " + fmt0(pl_->t_live) +
        "s, liveness for the report " + fmt0(pl_->t_fold_dead) + "s, targets and other ways in " +
        fmt0(pl_->t_final) + "s of which other ways in " + fmt0(pl_->t_entered) + "s), peephole " +
        fmt0(tp4 - tp3) + "s");
    if (!skip_report_only) {
        g_phase = "chain flags";
        FlagLiveness fl(code, [this](int64_t pc) -> const Chain* {
            const ChainP* c = w1_->chains.get(pc);
            return c ? c->get() : nullptr;
        });
        for (auto& [S, ch] : w1_->chains.items())
            ch->flags = ch->saves_flags() ? "preserved" : verdict_name(fl.at(ch->final_ ? *ch->final_ : ch->E));
    }
    log("planned: " + std::to_string(pl_->patches.size()) + " patches, " + std::to_string(pl_->drops.size()) +
        " relocation drops " + fmt0(secs()) + "s");
}

void Pipeline::apply_and_rewalk() {
    orig_.clear();
    pl_->patches.each([this](int64_t rva, const Patch& p) {
        orig_.emplace_back(rva, std::vector<uint8_t>(im_.mem.data() + rva, im_.mem.data() + rva + p.data.size()));
        std::memcpy(im_.mem.data() + rva, p.data.data(), p.data.size());
    });
    g_phase = "walk2";
    w2s_own_.reset();
    wb_.reset();
    wu_.reset();
    w2_.reset();
    wa_.reset();
    wk_.reset();
    code3_own_.reset();
    code2_ = std::make_unique<Code>(im_, extra_, &model_);
    codeA_own_ = std::make_unique<Code>(im_, extra_, &model_);
    codeK_own_ = std::make_unique<Code>(im_, extra_, &model_);
    // The walks of the patched image do not depend on each other, except that
    // the dropped records walk 2 does not reach are the roots of walk K. They
    // read the image and write only to their own walker and decode cache, so
    // they run side by side: walk 2 then walk K on one thread, walk A on
    // another. The interning table of root reasons is filled before.
    Roots groots;
    const int64_t wr = why_val("routine"), wc = why_val("chain");
    for (const auto& [x, ch] : census_.items()) groots.emplace_back(ch->G, wr);
    for (const auto& [x, ch] : census_.items()) groots.emplace_back(ch->S, wc);
    const int64_t w_dropped = why_val("dropped-record");
    w2_ = std::make_unique<Walker>(im_, *code2_, reg_, false);
    w2_->atomic = false;
    w2_->keep_src = true;
    wa_ = std::make_unique<Walker>(im_, *codeA_own_, reg_, false);
    wa_->atomic = false;
    wk_ = std::make_unique<Walker>(im_, *codeK_own_, reg_, false);
    wk_->atomic = false;
    // The same with the routines' stubs in place (walk 2s, walk B and walk U)
    // at the same time, on a copy-on-write view of the image that has the
    // stubs written in: the image itself stays as the walks above read it.
    FImage cow = im_.cow_copy();
    size_t nstubs = 0;
    for (const auto& [rva, data] : stub_patches_) {
        if (pl_ && pl_->claimed.any_in(rva, static_cast<int64_t>(data.size()))) continue;
        std::memcpy(cow.mem.data() + rva, data.data(), data.size());
        ++nstubs;
    }
    w2s_ = w2_.get();
    code3_ = code2_.get();
    const Roots broots = roots_with(b_roots_, "plausible-block target");
    const Roots uroots = roots_with(u_roots_, "referenced by live code");
    if (nstubs) {
        code3_own_ = std::make_unique<Code>(cow, extra_, &model_);
        code3_ = code3_own_.get();
        w2s_own_ = std::make_unique<Walker>(cow, *code3_, reg_, false);
        w2s_own_->atomic = false;
        w2s_own_->keep_src = true;
    }
    codeB_own_ = std::make_unique<Code>(cow, extra_, &model_);
    codeU_own_ = std::make_unique<Code>(cow, extra_, &model_);
    wb_ = std::make_unique<Walker>(cow, *codeB_own_, reg_, false);
    wb_->atomic = false;
    wu_ = std::make_unique<Walker>(cow, *codeU_own_, reg_, false);
    wu_->atomic = false;
    std::vector<std::function<void()>> jobs = {[&] {
                                                   w2_->walk(roots_);
                                                   lost_records_.clear();
                                                   for (int64_t r : dropped_prot_)
                                                       if (!(w2_->bm.get(r) & (START | ISTART)))
                                                           lost_records_.push_back(r);
                                                   Roots kr;
                                                   for (int64_t r : lost_records_) kr.emplace_back(r, w_dropped);
                                                   wk_->walk(kr);
                                               },
                                               [&] { wa_->walk(groots); }, [&] { wb_->walk(broots); },
                                               [&] { wu_->walk(uroots); }};
    if (w2s_own_) jobs.push_back([&] { w2s_own_->walk(roots_); });
    run_parallel(jobs);
    log("walk 2 (patched): " + std::to_string(w2_->insns) + " insns, " + std::to_string(w2_->idioms.size()) +
        " idioms left " + fmt0(secs()) + "s");
    log("walk A (protection): " + std::to_string(wa_->insns) + " insns " + fmt0(secs()) + "s");
    log("  walk 2: " + wstat(*w2_) + " | walk K: " + wstat(*wk_) + " | walk A: " + wstat(*wa_));
    if (w2s_own_) log("  walk 2s: " + wstat(*w2s_own_));
    if (w2s_own_) {
        w2s_ = w2s_own_.get();
        log("walk 2s (patched, routines stubbed): " + std::to_string(w2s_->insns) + " insns " + fmt0(secs()) + "s");
    }
    // from here on they read the image itself, as they did when the stubs
    // were written into it and taken out again around these walks
    for (Code* c : {code3_own_.get(), codeB_own_.get(), codeU_own_.get()})
        if (c) c->rebind(im_);
    for (Walker* w : {w2s_own_.get(), wb_.get(), wu_.get()})
        if (w) w->rebind(im_);
}

void Pipeline::restore() {
    for (const auto& [rva, b] : orig_) std::memcpy(im_.mem.data() + rva, b.data(), b.size());
}

// ------------------------------------------------------------ the wipe --

int Pipeline::access_size_memo(Code& code, int64_t pc) {
    auto it = asz_.find(pc);
    if (it != asz_.end()) return it->second;
    int n = 0;
    Lite d;
    if (code.insn(pc, d) && d.mid != M_LEA) {
        auto m = ptr_rip_size(d.ops());
        const std::string_view mn = d.mn();
        if (m && !(starts(mn, "rep") || d.mid == M_FXSAVE || d.mid == M_FXRSTOR || d.mid == M_XSAVE ||
                   d.mid == M_XRSTOR || d.mid == M_FXSAVE64 || d.mid == M_FXRSTOR64))
            n = *m;
    }
    asz_[pc] = n;
    return n;
}

static int64_t data_extent(int64_t s, const Bits& code_idx, int64_t cap) {
    const int64_t k = code_idx.next_set(s + 1);
    const int64_t nxt = k < 0 ? s + cap : k;
    return std::min(nxt, s + cap);
}

static int64_t data_extent_to(int64_t s, const std::vector<int64_t>& bounds, const Bits& code_idx, int64_t cap) {
    int64_t e = data_extent(s, code_idx, cap);
    if (!bounds.empty()) {
        auto it = std::upper_bound(bounds.begin(), bounds.end(), s);
        const int64_t nb = it == bounds.end() ? e : *it;
        e = std::min(e, nb);
    }
    return e;
}

const std::vector<int64_t>& Pipeline::ref_bounds() {
    if (have_bounds_) return bounds_;
    // Collected in a vector, then sorted and made unique: the same sorted
    // set of indices a std::set gave, without a tree node of 40 bytes for
    // each of several million references.
    std::vector<int64_t> ii;
    auto add = [&](int64_t t) {
        if (0 <= t && t < im_.len) {
            const int64_t i = reg_.idx(t);
            if (i >= 0) ii.push_back(i);
        }
    };
    for (Walker* w : {w1_.get(), w2_.get(), w2s_, wa_.get(), wk_.get(), wb_.get(), wu_.get(), ws_.get()}) {
        for (const DataRef& r : w->datarefs)
            if (access_size_memo(*w->code, r.pc) == 0) add(r.t);
        for (const DataRef& r : w->coderefs) add(r.t);
    }
    const auto& rel = im_.relocations();
    for (const PSection& sec : im_.sections) {
        if (sec.executable()) continue;
        auto lo = std::lower_bound(rel.begin(), rel.end(), static_cast<int64_t>(sec.rva));
        auto hi = std::lower_bound(rel.begin(), rel.end(), static_cast<int64_t>(sec.rva) + sec.vsize);
        for (auto it = lo; it < hi; ++it) add(static_cast<int64_t>(im_.u64(*it) - im_.image_base));
    }
    std::sort(ii.begin(), ii.end());
    ii.erase(std::unique(ii.begin(), ii.end()), ii.end());
    bounds_ = std::move(ii);
    have_bounds_ = true;
    return bounds_;
}

Pipeline::KeepFor Pipeline::keep_for(Walker& wl, const Bits& code_idx, int64_t cap) {
    ProfT pt_("keep_for");
    const uint8_t L4 = CODE | IDIOM | CHAIN | DREAD, L3 = CODE | IDIOM | CHAIN;
    KeepFor r;
    r.live = wl.bm.mask(L4);
    r.keep_lost = wk_->bm.mask(L4);
    r.keep_lost |= ws_->bm.mask(L4);
    Bits& keep = r.keep;
    keep = r.live;
    keep |= pl_->claimed.b;
    keep |= r.keep_lost;
    keep |= keep_wipe_->b;
    for (const auto& [rva, n] : stub_ranges_) {
        const int64_t i = reg_.idx(rva);
        if (i >= 0 && (r.live.any_range(i, i + n) || r.keep_lost.any_range(i, i + n))) {
            keep.set_range(i, i + n);
            r.live_stubs.emplace_back(rva, n);
        }
    }
    for (const auto& [rva, n] : model_.writes) {
        const int64_t i = reg_.idx(rva);
        if (i >= 0) keep.set_range(i, i + n);
    }
    keep |= wb_->bm.mask(L4);
    keep |= wu_->bm.mask(L4);
    for (Walker* w : {wb_.get(), wu_.get()}) {
        const auto& rs = w == wb_.get() ? b_roots_ : u_roots_;
        for (int64_t t : rs) {
            const int64_t i = reg_.idx(t);
            if (i >= 0 && !(w->bm.f[static_cast<size_t>(i)] & L3)) keep.set_range(i, i + 15);
        }
    }
    // What live code refers to is kept: a sized read keeps its operand, an
    // address taken keeps up to the next reference. Setting a range twice
    // is setting it once, so a sized read is set as it is met (the union
    // over one address is its largest size), and the unsized ones are
    // gathered in a vector and made unique, where a std::set and a std::map
    // held a tree node for each of a few million references.
    std::vector<int64_t> unsized;
    ProfT pt2_("keep_for refs");
    for (Walker* w : {&wl, wk_.get(), wb_.get(), wu_.get(), ws_.get()}) {
        for (const DataRef& d : w->datarefs) {
            const int64_t i = reg_.idx(d.t);
            if (i < 0) continue;
            const int n = access_size_memo(*w->code, d.pc);
            if (n == 0)
                unsized.push_back(i);
            else
                keep.set_range(i, i + n);
        }
        for (const DataRef& d : w->coderefs) {
            const int64_t i = reg_.idx(d.t);
            if (i >= 0) unsized.push_back(i);
        }
    }
    for (const auto* v : {&b_data_, &u_data_})
        for (int64_t t : *v) {
            const int64_t i = reg_.idx(t);
            if (i >= 0) unsized.push_back(i);
        }
    const auto& rel = im_.relocations();
    for (const PSection& s : im_.sections) {
        if (s.executable()) continue;
        auto lo = std::lower_bound(rel.begin(), rel.end(), static_cast<int64_t>(s.rva));
        auto hi = std::lower_bound(rel.begin(), rel.end(), static_cast<int64_t>(s.rva) + s.vsize);
        for (auto it = lo; it < hi; ++it) {
            const int64_t v = static_cast<int64_t>(im_.u64(*it) - im_.image_base);
            if (0 <= v && v < im_.len) {
                const int64_t i = reg_.idx(v);
                if (i >= 0) unsized.push_back(i);
            }
        }
    }
    std::sort(std::execution::par, unsized.begin(), unsized.end());
    unsized.erase(std::unique(unsized.begin(), unsized.end()), unsized.end());
    const auto& bounds = ref_bounds();
    for (int64_t a : unsized) keep.set_range(a, data_extent_to(a, bounds, code_idx, cap));
    for (const auto& [d_rva, d_sz] : im_.dirs)
        if (d_rva && d_sz) {
            const int64_t i = reg_.idx(d_rva);
            if (i >= 0) keep.set_range(i, i + d_sz);
        }
    return r;
}

std::vector<std::pair<int64_t, int64_t>> Pipeline::wipes_(const Bits& keep, const Bits& live, const Bits& keep_lost,
                                                          const Bits& code_idx) {
    ProfT pt_("wipes");
    const auto [lo_s, hi_s] = arxan_sec_;
    const Bits& patched = pl_->claimed.b;
    Bits prot = wa_->bm.mask(CODE | IDIOM | CHAIN);
    prot |= w1_->bm.mask(IDIOM | CHAIN);
    std::vector<int64_t> aidx;  // ascending, each once (what a std::set gave)
    aidx.reserve(wa_->datarefs.size());
    for (const DataRef& d : wa_->datarefs) {
        const int64_t i = reg_.idx(d.t);
        if (i >= 0) aidx.push_back(i);
    }
    std::sort(std::execution::par, aidx.begin(), aidx.end());
    aidx.erase(std::unique(aidx.begin(), aidx.end()), aidx.end());
    Bits protd(reg_.total);
    for (int64_t a : aidx) protd.set_range(a, data_extent(a, code_idx, 0x1000));
    Bits sec(reg_.total);
    const int64_t i0 = reg_.idx(lo_s), i1 = reg_.idx(hi_s - 1) + 1;
    sec.set_range(i0, i1);
    Bits wipe = prot;
    wipe |= protd;
    wipe &= sec;
    wipe.andnot(keep);
    Bits own(reg_.total);
    for (const auto& [S, ch] : w1_->chains.items())
        if (ch->bypass == 1)
            for (const auto& [a, n] : ch->insns) {
                const int64_t i = reg_.idx(a);
                if (i >= 0) own.set_range(i, i + n);
            }
    for (const auto& [s, res] : pl_->idiom_res.items())
        if (res.ok)
            for (const auto& [a, n] : (*w1_->idioms.get(s))->insns) {
                const int64_t i = reg_.idx(a);
                if (i >= 0) own.set_range(i, i + n);
            }
    for (const auto& [lo, hi] : extra_) own.set_range(reg_.idx(lo), reg_.idx(hi - 1) + 1, false);
    {
        Bits t = own;
        t.andnot(sec);
        t.andnot(keep);
        wipe |= t;
    }
    std::vector<std::pair<int64_t, int64_t>> out;
    for (const auto& [a, b] : wipe.runs()) out.emplace_back(reg_.rva(a), b - a);
    // wipe_stats (report)
    if (!skip_report_only) {
        auto n = [&sec](const Bits& m) {
            Bits t = m;
            t &= sec;
            return t.count();
        };
        Bits zero(reg_.total);
        for (int64_t k = 0; k < hi_s - lo_s; ++k) {
            const uint8_t b = im_.mem[static_cast<size_t>(lo_s + k)];
            if (b == 0 || b == 0xCC) zero.set(i0 + k);
        }
        Bits dread = w2_->bm.mask(DREAD);
        Json st = Json::object();
        Bits ones(reg_.total);
        ones.set_range(0, reg_.total);
        st["section_bytes"] = Json(n(ones));
        {
            Bits t = live;
            t.andnot(dread);
            st["live_code"] = Json(n(t));
        }
        st["patched"] = Json(n(patched));
        {
            Bits t = keep;
            t.andnot(live);
            t.andnot(patched);
            t.andnot(keep_lost);
            st["kept_as_live_data_or_pe"] = Json(n(t));
        }
        {
            Bits t = keep_lost;
            t.andnot(live);
            t.andnot(patched);
            st["kept_reached_from_dropped_records"] = Json(n(t));
        }
        st["protection_code"] = Json(n(prot));
        {
            Bits t = protd;
            t.andnot(prot);
            st["protection_data"] = Json(n(t));
        }
        st["wiped"] = Json(n(wipe));
        Bits unc = ones;
        unc.andnot(keep);
        unc.andnot(prot);
        unc.andnot(protd);
        st["unclassified_kept"] = Json(n(unc));
        unc &= zero;
        st["unclassified_kept_zero_or_cc"] = Json(n(unc));
        wipe_stats_ = st;
        log("arxan section: " + py_dict(st));
    }
    wipe_mask_ = std::move(wipe);
    sec_mask_ = std::move(sec);
    return out;
}

std::vector<std::pair<int64_t, int64_t>> Pipeline::dead_bytes() {
    ProfT pt_("dead_bytes");
    g_phase = "dead_bytes";
    const int64_t cap = 0x10000;
    have_bounds_ = false;
    Bits code_idx = w2_->bm.mask(CODE | IDIOM | CHAIN);
    code_idx |= wa_->bm.mask(CODE | IDIOM | CHAIN);
    code_idx |= w1_->bm.mask(CODE | IDIOM | CHAIN);
    KeepFor ks;
    const bool two = w2s_ != w2_.get();
    if (two) ks = keep_for(*w2s_, code_idx, cap);
    KeepFor k = keep_for(*w2_, code_idx, cap);
    std::vector<std::pair<int64_t, int64_t>> live_stubs;
    if (two) {
        k.keep |= ks.keep;
        k.live |= w2s_->bm.mask(CODE | IDIOM | CHAIN | DREAD);
        live_stubs = ks.live_stubs;
    } else {
        ks.keep = k.keep;
        live_stubs = k.live_stubs;
    }
    auto out = wipes_(k.keep, k.live, k.keep_lost, code_idx);
    stubs_reachable_ = live_stubs;
    Bits prot_only = wa_->bm.mask(CODE | IDIOM | CHAIN);
    Bits a = sec_mask_;
    a.andnot(ks.keep);
    a.andnot(wipe_mask_);
    Bits b = sec_mask_;
    b.flip();
    b &= prot_only;
    b.andnot(ks.keep);
    b.andnot(wipe_mask_);
    a |= b;
    dead_mask_ = std::move(a);
    dead_wipes_.clear();
    for (const auto& [x, y] : dead_mask_.runs()) dead_wipes_.emplace_back(reg_.rva(x), y - x);
    return out;
}

// ---------------------------------------------------------- invariants --

std::vector<std::tuple<int64_t, int64_t, bool>> Pipeline::b_violations(const Bits& mask) {
    ProfT pt_("b_violations");
    const uint8_t L3 = CODE | IDIOM | CHAIN;
    Bits live = w2_->bm.mask(L3);
    for (Walker* w : {w2s_, wk_.get(), wb_.get(), wu_.get(), ws_.get()}) live |= w->bm.mask(L3);
    live |= pl_->claimed.b;
    Bits fr = live;
    fr.flip();
    fr.andnot(mask);
    const int64_t lo_a = reg_.idx(arxan_sec_.first), hi_a = reg_.idx(arxan_sec_.second - 1) + 1;
    fr.set_range(lo_a, hi_a, false);
    const Recs recs = rec_arrays(true, false);
    std::vector<int64_t> lb, le;
    for (size_t k = 0; k < recs.bi.size(); ++k) {
        const size_t i = static_cast<size_t>(recs.bi[k]);
        if ((w2_->bm.f[i] | w2s_->bm.f[i]) & (START | ISTART)) {
            lb.push_back(recs.bi[k]);
            le.push_back(recs.ei[k]);
        }
    }
    if (!bsweeper_) bsweeper_ = std::make_unique<Sweeper>(im_, *code2_);
    std::vector<std::tuple<int64_t, int64_t, bool>> out;
    int64_t nblk = 0, nplaus = 0, nhidden = 0;
    const uint8_t* mem = im_.mem.data();
    std::unique_ptr<ProfT> ptb_ = std::make_unique<ProfT>("b_violations blocks");
    for (auto [a, b] : fr.runs()) {
        int64_t k = static_cast<int64_t>(std::upper_bound(lb.begin(), lb.end(), a) - lb.begin()) - 1;
        if (k < 0 || a >= le[static_cast<size_t>(k)]) {
            const int64_t k2 = static_cast<int64_t>(std::lower_bound(lb.begin(), lb.end(), a) - lb.begin());
            if (k2 >= static_cast<int64_t>(lb.size()) || lb[static_cast<size_t>(k2)] >= b) continue;
            a = lb[static_cast<size_t>(k2)];
            k = k2;
        }
        b = std::min(b, le[static_cast<size_t>(k)]);
        const Regions::Sec* rg = reg_.region_of(a);
        if (!rg) continue;
        for (const RunBlock& rb : bsweeper_->run_blocks(rg->lo + a - rg->off, rg->lo + b - rg->off)) {
            ++nblk;
            if (!rb.plausible) continue;
            ++nplaus;
            for (const BlockRef& r : rb.refs) {
                const int64_t i = (0 <= r.t && r.t < im_.len) ? reg_.idx(r.t) : -1;
                if (i >= 0 && mask.test(i)) out.emplace_back(rb.start, r.t, r.branch);
            }
        }
    }
    // Hidden branches. A block that only a computed jump reaches can start
    // behind junk bytes, where a linear decode never reads it as an
    // instruction. The protection moves the blocks of such a function into
    // its own section and leaves `jmp block` at each block's old address, so
    // the computed jump lands on a 5-byte jump with junk on both sides (1.20:
    // `90 66 2B 16 76 | E9 rel32` at 0x3DD532, reached by `push rax ; ret`).
    // So: a direct jmp, call or jcc encoded at ANY byte offset, whose target
    // is a wiped byte of the protection's section, keeps that target.
    // The bytes searched are the ones the walks from real roots did not
    // read. What the layout sweep and the plausible blocks decoded there is a
    // guess, and a guess can decode junk straight over such a jump (1.20:
    // 0xD4A4C0 in the first TLS callback's function), so their bytes are
    // searched too.
    ptb_.reset();
    ProfT pth_("b_violations hidden and pointers");
    Bits fh = w2_->bm.mask(L3);
    fh |= w2s_->bm.mask(L3);
    fh |= pl_->claimed.b;
    fh.flip();
    fh.andnot(mask);
    fh.set_range(lo_a, hi_a, false);
    // (Not only inside functions the walk entered: 1.20 has such a jump at
    // 0xF5D2D4, in a function that is reached by computed jumps alone.)
    // A run of bits can cross from one code region into the next in index
    // order, which is not address order: each run is cut at region ends
    // (uncut, a run out of the last section read past the image on 1.03.0).
    // (each piece as (first start, last start + 1, the piece's end), cut into
    // stretches of 1 MB of starts so that the threads below share the work)
    struct Piece {
        int64_t lo, lo_end, hi;
    };
    auto pieces = [&](const Bits& bits) {
        std::vector<Piece> v;
        for (auto [a0, b0] : bits.runs()) {
            for (int64_t a = a0; a < b0;) {
                const Regions::Sec* rg = reg_.region_of(a);
                if (!rg) break;
                const int64_t b = std::min<int64_t>(b0, rg->off + (rg->hi - rg->lo));
                if (b <= a) break;
                const int64_t lo = rg->lo + a - rg->off, hi = rg->lo + b - rg->off;
                for (int64_t s = lo; s < hi; s += int64_t(1) << 20) v.push_back({s, std::min<int64_t>(hi, s + (int64_t(1) << 20)), hi});
                a = b;
            }
        }
        return v;
    };
    // (the pieces are scanned on threads, each into a list of its own, and
    // the lists joined in the pieces' order)
    using Hit3 = std::vector<std::tuple<int64_t, int64_t, bool>>;
    {
        const auto pc = pieces(fh);
        std::vector<Hit3> part(pc.size());
        parallel_for(pc.size(), [&](size_t i0, size_t i1) {
            for (size_t pi = i0; pi < i1; ++pi) {
                const int64_t lo = pc[pi].lo, lo_end = pc[pi].lo_end, hi = pc[pi].hi;
                for (int64_t p = lo; p < lo_end && p + 5 <= hi; ++p) {
                    const uint8_t c = mem[p];
                    int64_t t;
                    if (c == 0xE9 || c == 0xE8) {
                        int32_t rel;
                        std::memcpy(&rel, mem + p + 1, 4);
                        t = p + 5 + rel;
                    } else if (c == 0x0F && (mem[p + 1] & 0xF0) == 0x80 && p + 6 <= hi) {
                        int32_t rel;
                        std::memcpy(&rel, mem + p + 2, 4);
                        t = p + 6 + rel;
                    } else {
                        continue;
                    }
                    if (t < arxan_sec_.first || t >= arxan_sec_.second) continue;
                    const int64_t i = reg_.idx(t);
                    if (i >= 0 && mask.test(i)) part[pi].emplace_back(p, t, true);
                }
            }
        }, 2);
        for (const Hit3& h : part) {
            out.insert(out.end(), h.begin(), h.end());
            nhidden += static_cast<int64_t>(h.size());
        }
    }
    // The same from the other side: a wiped byte of the GAME's code that a
    // kept, unwalked byte anywhere still jumps to, by a direct branch or by
    // the push-and-return spelling `lea rbp,[rip+X] ; xchg [rsp],rbp` (the
    // `ret` follows). 1.20: the 5-byte `jmp` at 0x1B8A407 was wiped once the
    // rewritten idioms stopped passing through it, and fourteen blocks kept
    // as shipped, thirteen of them in the protection's section, still end in
    // a push-and-return to it. Targets in the protection's section are left
    // to the rules above: its dead code is full of jumps into itself.
    {
        Bits fk = w2_->bm.mask(L3);
        fk |= w2s_->bm.mask(L3);
        fk |= pl_->claimed.b;
        fk.flip();
        fk.andnot(mask);
        const auto pc = pieces(fk);
        std::vector<Hit3> part(pc.size());
        parallel_for(pc.size(), [&](size_t i0, size_t i1) {
            for (size_t pi = i0; pi < i1; ++pi) {
                const int64_t lo = pc[pi].lo, lo_end = pc[pi].lo_end, hi = pc[pi].hi;
                for (int64_t p = lo; p < lo_end && p + 5 <= hi; ++p) {
                    const uint8_t c = mem[p];
                    int64_t t;
                    if (c == 0xE9 || c == 0xE8) {
                        int32_t rel;
                        std::memcpy(&rel, mem + p + 1, 4);
                        t = p + 5 + rel;
                    } else if (c == 0x0F && (mem[p + 1] & 0xF0) == 0x80 && p + 6 <= hi) {
                        int32_t rel;
                        std::memcpy(&rel, mem + p + 2, 4);
                        t = p + 6 + rel;
                    } else if (c == 0x48 && p + 11 <= hi && mem[p + 1] == 0x8D && mem[p + 2] == 0x2D &&
                               mem[p + 7] == 0x48 && mem[p + 8] == 0x87 && mem[p + 9] == 0x2C && mem[p + 10] == 0x24) {
                        int32_t rel;
                        std::memcpy(&rel, mem + p + 3, 4);
                        t = p + 7 + rel;
                    } else {
                        continue;
                    }
                    if (t < 0 || t >= im_.len || (arxan_sec_.first <= t && t < arxan_sec_.second)) continue;
                    const int64_t j = reg_.idx(t);
                    if (j >= 0 && mask.test(j)) part[pi].emplace_back(p, t, true);
                }
            }
        }, 2);
        for (const Hit3& h : part) {
            out.insert(out.end(), h.begin(), h.end());
            nhidden += static_cast<int64_t>(h.size());
        }
    }
    // Kept pointers. A relocated qword in a code region that is not wiped and
    // points at a wiped byte. A table of block addresses for a computed jump
    // can sit next to the code that uses it, in the code section, where the
    // roots taken from the data sections do not see it (1.20: 0xD42EE3, in
    // the first TLS callback's function, holds 0x1B8A407, a 5-byte `jmp`
    // that the rewritten idioms no longer pass through). What such a pointer
    // names is kept like a branch target.
    int64_t nptr = 0;
    for (int64_t r : im_.relocations()) {
        const int64_t i = reg_.idx(r);
        if (i < 0 || mask.test(i) || pl_->drops.count(r)) continue;
        const uint64_t v = im_.u64(r);
        if (!(im_.image_base <= v && v < im_.image_base + static_cast<uint64_t>(im_.len))) continue;
        const int64_t t = static_cast<int64_t>(v - im_.image_base);
        const int64_t j = reg_.idx(t);
        if (j >= 0 && mask.test(j)) {
            out.emplace_back(r, t, true);
            ++nptr;
        }
    }
    b_counts_[0] = nblk;
    b_counts_[1] = nplaus;
    b_hidden_ = nhidden;
    b_ptrs_ = nptr;
    return out;
}

int Pipeline::settle_b() {
    int rounds = 0;
    while (true) {
        Bits m = wipe_mask_;
        m |= dead_mask_;
        const auto v = b_violations(m);
        std::set<int64_t> br, dr;
        for (const auto& [s, t, k] : v)
            if (!b_seen_.count(t)) (k ? br : dr).insert(t);
        log("invariant B: " + std::to_string(v.size()) + " violations (" + std::to_string(b_counts_[0]) + " blocks, " +
            std::to_string(b_counts_[1]) + " plausible); new branch targets " + std::to_string(br.size()) +
            ", data " + std::to_string(dr.size()));
        log("hidden branches into wiped bytes: " + std::to_string(b_hidden_) + "; kept pointers into wiped bytes: " +
            std::to_string(b_ptrs_));
        if (br.empty() && dr.empty()) return rounds;
        ++rounds;
        for (int64_t t : br) b_seen_.insert(t);
        for (int64_t t : dr) b_seen_.insert(t);
        b_roots_.insert(b_roots_.end(), br.begin(), br.end());
        b_data_.insert(b_data_.end(), dr.begin(), dr.end());
        {
            ProfT pt_("settle walks");
            const Saved saved = stubs_on(true);
            wb_->walk(roots_with(std::vector<int64_t>(br.begin(), br.end()), "plausible-block target"));
            stubs_off(saved);
        }
        wipes_v_ = dead_bytes();
    }
}

Inv Pipeline::invariants(const Bits& mask, const std::unordered_set<int64_t>& drops_extra, Walker& wl) {
    ProfT pt_("invariants");
    std::unique_ptr<ProfT> pp_ = std::make_unique<ProfT>("invariants patches");
    Inv res;
    const ByteMap& bm2 = wl.bm;
    Code& code2 = *code2_;
    for (int64_t x : long_sub_sites(im_, code2))
        if (bm2.get(x) & (START | CODE)) (census_.contains(x) ? res.sub_of_chains : res.sub_not_chains).push_back(hex8(x));
    {
        Bits live = bm2.mask(START | CODE | IDIOM | CHAIN);
        live &= mask;
        res.live_bytes_in_wipes = live.count();
    }
    // 3. patches decode to what was meant (on threads, each with its own
    // decoder; the bad ones are listed in the patches' order)
    std::vector<std::pair<int64_t, const Patch*>> plist;
    pl_->patches.each([&](int64_t rva, const Patch& p) { plist.emplace_back(rva, &p); });
    std::vector<uint8_t> pbad(plist.size(), 0);
    parallel_for(plist.size(), [&](size_t i0, size_t i1) {
      Decoder& ld = lite_dec();
      for (size_t pi = i0; pi < i1; ++pi) {
        const int64_t rva = plist[pi].first;
        const Patch& p = *plist[pi].second;
        struct G {
            int size;
            uint16_t m;
            std::string op;
        };
        std::vector<G> got;
        ld.run(p.data.data(), p.data.size(), static_cast<uint64_t>(rva),
               [&](const cs_insn* i) { got.push_back({i->size, ld.mid_of(i), i->op_str}); });
        int64_t tot = 0;
        for (const G& g : got) tot += g.size;
        bool ok;
        if (starts(p.tag, "peep ")) {
            auto sp = split_cs(p.tag);  // not used; split on whitespace below
            (void)sp;
            std::vector<std::string> parts;
            {
                size_t a = 0;
                const std::string& t = p.tag;
                while (a < t.size()) {
                    while (a < t.size() && t[a] == ' ') ++a;
                    size_t b = a;
                    while (b < t.size() && t[b] != ' ') ++b;
                    if (b > a) parts.push_back(t.substr(a, b - a));
                    a = b;
                }
            }
            const std::string form = parts[1];
            const uint16_t want = form == "ret" ? M_RET : form == "pop" ? M_POP : form == "push" ? M_PUSH : M_JMP;
            ok = !got.empty() && got[0].m == want && tot == static_cast<int64_t>(p.data.size()) &&
                 (form != "jmp" || !starts(got[0].op, "0x"));
            for (size_t k = 1; ok && k < got.size(); ++k)
                if (!(got[k].m == M_NOP || got[k].m == M_INT3 || (got[k].m == M_JMP && starts(got[k].op, "0x"))))
                    ok = false;
            if (ok && form != "ret") {
                auto it = pl_->peep_reg.find(rva);
                const int r = it == pl_->peep_reg.end() ? -1 : it->second;
                if (r < 0 || got[0].op != GPR64[r]) ok = false;
            }
        } else {
            std::vector<const G*> body;
            for (const G& g : got)
                if (g.m != M_INT3) body.push_back(&g);
            bool filler_ok = true;
            for (size_t k = body.size(); k < got.size(); ++k)
                if (got[k].m != M_INT3) filler_ok = false;
            ok = filler_ok && tot == static_cast<int64_t>(p.data.size());
            for (size_t k = 0; ok && k < body.size(); ++k) {
                const G& g = *body[k];
                const bool br = (g.m == M_JMP || g.m == M_CALL || mf(g.m, F_JCC)) && starts(g.op, "0x");
                const bool lea = g.m == M_LEA && k == 0 && lea_rsp_disp(g.op).value_or(0) > 0 && body.size() == 2 &&
                                 body[1]->m == M_JMP;
                if (!(br || lea)) ok = false;
            }
        }
        if (!ok) pbad[pi] = 1;
      }
    });
    for (size_t pi = 0; pi < plist.size(); ++pi)
        if (pbad[pi]) res.patch_decode_bad.push_back(plist[pi].first);
    // 4. references from live code into a patch's interior or a wipe
    pp_ = std::make_unique<ProfT>("invariants refs");
    Bits interior(reg_.total);
    pl_->patches.each([&](int64_t rva, const Patch& p) {
        const int64_t i = reg_.idx(rva);
        interior.set_range(i + 1, i + static_cast<int64_t>(p.data.size()));
    });
    interior |= mask;
    struct C {
        int64_t t, src;
        uint64_t seq;
        uint8_t k;
    };
    std::vector<C> cand;
    {
        std::vector<XHit> hits;
        scan_xrefs_par(im_, extra_, [&](int64_t t, int64_t s, uint8_t) {
            const int64_t ti = reg_.idx(t);
            if (ti < 0 || !interior.test(ti)) return false;
            const int64_t si = reg_.idx(s);
            return si >= 0 && (bm2.f[static_cast<size_t>(si)] & (START | ISTART)) != 0;
        }, hits);
        for (size_t i = 0; i < hits.size(); ++i) cand.push_back({hits[i].t, hits[i].s, i, hits[i].k});
    }
    std::sort(cand.begin(), cand.end(), [](const C& a, const C& b) { return a.t != b.t ? a.t < b.t : a.seq < b.seq; });
    Lite d;
    for (const C& c : cand) {
        if (!code2.insn(c.src, d) || d.size != KIND_ENC[c.k].size) continue;
        if (c.k < 5) {
            int64_t v;
            if (!(starts(d.ops(), "0x") && hex_op(d.ops(), v) && v == c.t)) continue;
            if (!(d.mid == M_JMP || d.mid == M_CALL || mf(d.mid, F_JCC))) continue;
        } else if (d.mid != KIND_ENC[c.k].mid) {
            continue;
        }
        if (pl_->patches.contains(c.src) || pl_->claimed.get(c.src)) continue;
        res.refs_into_interior.push_back({false, c.src, c.t});
    }
    for (const auto& [r, why] : roots_) {
        const int64_t i = reg_.idx(r);
        if (i >= 0 && interior.test(i)) res.refs_into_interior.push_back({true, why, r});
    }
    // 5. relocations
    pp_.reset();
    for (int64_t r : im_.relocations()) {
        if (pl_->drops.count(r) || drops_extra.count(r)) continue;
        const uint64_t v = im_.u64(r);
        const int64_t i = reg_.idx(r);
        if (i >= 0 && mask.test(i)) {
            res.bad_relocs.emplace_back(r, "in wipe");
            continue;
        }
        if (!(im_.image_base <= v && v < im_.image_base + static_cast<uint64_t>(im_.len)))
            res.bad_relocs.emplace_back(r, hexx(static_cast<int64_t>(v)));
    }
    res.plausible = b_violations(mask);
    res.blocks = b_counts_[0];
    res.plaus = b_counts_[1];
    return res;
}

static std::string tuple_ints(int64_t a, int64_t b) { return "(" + std::to_string(a) + ", " + std::to_string(b) + ")"; }

Json Inv::to_json(bool summary) const {
    Json o = Json::object();
    auto lst = [summary](const std::vector<std::string>& v) {
        if (summary) return Json(static_cast<int64_t>(v.size()));
        Json j = Json::object();
        j["count"] = Json(static_cast<int64_t>(v.size()));
        Json f = Json::array();
        for (size_t k = 0; k < v.size() && k < 50; ++k) f.push(Json(v[k]));
        j["first"] = f;
        return j;
    };
    o["live_long_sub_sites_of_chains"] = lst(sub_of_chains);
    o["live_long_sub_sites_not_chains"] = lst(sub_not_chains);
    o["live_bytes_in_wipes"] = Json(live_bytes_in_wipes);
    {
        std::vector<std::string> v;
        for (int64_t x : patch_decode_bad) v.push_back(std::to_string(x));
        o["patch_decode_bad"] = lst(v);
    }
    {
        std::vector<std::string> v;
        for (const Viol& x : refs_into_interior)
            v.push_back(x.is_root ? "(" + py_repr_str(why_str(static_cast<int>(-1 - x.src))) + ", " + std::to_string(x.t) + ")"
                                  : tuple_ints(x.src, x.t));
        o["refs_into_interior"] = lst(v);
    }
    {
        std::vector<std::string> v;
        for (const auto& [r, s] : bad_relocs) v.push_back("(" + std::to_string(r) + ", " + py_repr_str(s) + ")");
        o["bad_relocs"] = lst(v);
    }
    {
        std::vector<std::string> v;
        for (const auto& [a, t, k] : plausible)
            v.push_back("(" + py_repr_str(hex8(a)) + ", " + py_repr_str(hex8(t)) + ", " +
                        py_repr_str(k ? "branch" : "rip") + ")");
        o["plausible_blocks_into_wipes"] = lst(v);
    }
    Json s = Json::object();
    s["blocks"] = Json(blocks);
    s["plausible"] = Json(plaus);
    o["plausible_blocks_scanned"] = s;
    return o;
}

void Pipeline::check_all() {
    g_phase = "check_all";
    const auto& rel = im_.relocations();
    wipe_drops_.clear();
    for (int64_t r : rel) {
        const int64_t i = reg_.idx(r);
        if (i >= 0 && wipe_mask_.any_range(i, i + 8)) wipe_drops_.insert(r);
    }
    inv_ = invariants(wipe_mask_, wipe_drops_, *w2_);
    dead_drops_.clear();
    for (int64_t r : rel) {
        const int64_t i = reg_.idx(r);
        if (i >= 0 && dead_mask_.any_range(i, i + 8) && !wipe_drops_.count(r)) dead_drops_.insert(r);
    }
    Bits uni = wipe_mask_;
    uni |= dead_mask_;
    std::unordered_set<int64_t> dx = wipe_drops_;
    dx.insert(dead_drops_.begin(), dead_drops_.end());
    inv_union_ = invariants(uni, dx, *w2s_);
}

std::vector<int64_t> Pipeline::targets(const Inv& inv) {
    std::vector<int64_t> out;
    for (const Viol& v : inv.refs_into_interior) {
        out.push_back(v.t);
        if (!ref_src_.count(v.t)) ref_src_[v.t] = {v.is_root, v.src};
    }
    return out;
}

std::unordered_set<int64_t> Pipeline::ws_drops() {
    std::unordered_set<int64_t> out;
    pl_->patches.each([&](int64_t rva, const Patch& p) {
        const int64_t i = reg_.idx(rva);
        if (i < 0) return;
        const int64_t e = std::min<int64_t>(i + static_cast<int64_t>(p.data.size()), reg_.total);
        for (int64_t k = i; k < e; ++k)
            if (ws_->bm.f[static_cast<size_t>(k)]) {
                out.insert(rva);
                break;
            }
    });
    return out;
}

void Pipeline::recompute_drops() {
    pl_->drops.clear();
    const auto& rel = im_.relocations();
    pl_->patches.each([&](int64_t rva, const Patch& p) {
        auto lo = std::lower_bound(rel.begin(), rel.end(), rva - 7);
        auto hi = std::lower_bound(rel.begin(), rel.end(), rva + static_cast<int64_t>(p.data.size()));
        for (auto it = lo; it < hi; ++it) pl_->drops.insert(*it);
    });
}

static std::vector<std::string> wsplit(const std::string& t) {
    std::vector<std::string> parts;
    size_t a = 0;
    while (a < t.size()) {
        while (a < t.size() && t[a] == ' ') ++a;
        size_t b = a;
        while (b < t.size() && t[b] != ' ') ++b;
        if (b > a) parts.push_back(t.substr(a, b - a));
        a = b;
    }
    return parts;
}

void Pipeline::rollback(const std::unordered_set<int64_t>& drop, const std::string& reason, bool do_restore) {
    const auto wsd = ws_drops();
    std::unordered_set<std::string> tags, keys;
    for (int64_t r : drop) tags.insert(pl_->patches.get(r)->tag);
    for (const std::string& t : tags) {
        const auto parts = wsplit(t);
        if (!starts(t, "peep"))
            keys.insert(parts.size() >= 2 ? parts[0] + " " + parts[1] : (parts.empty() ? "" : parts[0]));
        else
            keys.insert(t);
    }
    std::vector<int64_t> gone;
    pl_->patches.each([&](int64_t r, const Patch& p) {
        const auto parts = wsplit(p.tag);
        std::string two;
        for (size_t k = 0; k < parts.size() && k < 2; ++k) two += (k ? " " : "") + parts[k];
        if (tags.count(p.tag) || keys.count(two)) gone.push_back(r);
    });
    if (do_restore) restore();
    for (int64_t r : gone) {
        const std::string tag = pl_->patches.get(r)->tag;
        rolled_back_.emplace_back(r, tag);
        pl_->patches.erase(r);
        const auto parts = wsplit(tag);
        const std::string& last = parts.back() != "hop" && parts.back() != "pred" ? parts.back() : parts[parts.size() - 2];
        bool have_s = true;
        int64_t s = 0;
        try {
            size_t pos = 0;
            s = static_cast<int64_t>(std::stoull(last, &pos, 16));
            if (pos != last.size()) have_s = false;
        } catch (...) {
            have_s = false;
        }
        const std::string why = "rolled back: " + (wsd.count(r) ? std::string("the kept-only sweep walk enters it") : reason);
        Res skip;
        skip.detail = why;
        const std::string& p0 = parts[0];
        if ((p0 == "jmp" || p0 == "jcc" || p0 == "call" || p0 == "popjmp") && have_s && pl_->idiom_res.contains(s)) {
            pl_->idiom_res.set(s, skip);
        } else if (p0 == "check" && have_s && pl_->check_res.contains(s)) {
            pl_->check_res.set(s, skip);
        } else if (p0 == "chain" && have_s && w1_->chains.contains(s)) {
            (*w1_->chains.get(s))->bypass = 0;
            (*w1_->chains.get(s))->why = why;
        } else if (p0 == "peep") {
            pl_->peep_done[parts[1] != "jmp" ? parts[1] : std::string("jmp r")] -= 1;
            auto it = pl_->peep_seen.find(static_cast<int64_t>(std::stoull(parts.back(), nullptr, 16)));
            if (it != pl_->peep_seen.end()) it->second.second = why;
            pl_->peep_skip[why] += 1;
        }
    }
    pl_->claimed = BitMap(reg_);
    pl_->patches.each([&](int64_t r, const Patch& p) { pl_->claimed.set(r, static_cast<int64_t>(p.data.size())); });
    recompute_drops();
    log("rolled back " + std::to_string(gone.size()) + " patches (" + reason + ")");
}

static std::string inv_summary(const Inv& inv) { return py_dict(inv.to_json(true)); }

void Pipeline::run() {
    analyse();
    const auto wsd = ws_drops();
    if (!wsd.empty()) rollback(wsd, "the kept-only sweep walk enters it", false);
    ws_rolled_back_ = static_cast<int64_t>(rolled_back_.size());
    // A guard publishes its digest when it runs, and a check that reads the
    // dword can run before the guard does (1.20's WinMain). A published value
    // is not a constant of the image, so a construct whose routine publishes
    // one is not folded into a jump: it stays as shipped and calls the
    // routine's replacement, which stores the value (find_routines.py).
    {
        std::unordered_set<int64_t> pub;
        for (const auto& [g, m] : model_.r)
            if (m.publishes) pub.insert(g);
        if (!pub.empty()) {
            std::unordered_set<int64_t> sites;
            for (const auto& [s, i] : w1_->idioms.items())
                for (const ChainP& ch : i->inner)
                    if (pub.count(ch->G)) {
                        sites.insert(s);
                        break;
                    }
            std::unordered_set<int64_t> drop;
            pl_->patches.each([&](int64_t r, const Patch& p) {
                const auto parts = wsplit(p.tag);
                if (parts.empty()) return;
                const std::string& p0 = parts[0];
                if (!(p0 == "jmp" || p0 == "jcc" || p0 == "call" || p0 == "popjmp")) return;
                const std::string& last =
                    parts.back() != "hop" && parts.back() != "pred" ? parts.back() : parts[parts.size() - 2];
                try {
                    size_t pos = 0;
                    const int64_t s = static_cast<int64_t>(std::stoull(last, &pos, 16));
                    if (pos == last.size() && sites.count(s)) drop.insert(r);
                } catch (...) {
                }
            });
            const size_t before = rolled_back_.size();
            if (!drop.empty()) rollback(drop, "a routine inside publishes a value", false);
            log("publishing routines: " + std::to_string(pub.size()) + "; constructs left in place for them: " +
                std::to_string(sites.size()) + " (" + std::to_string(rolled_back_.size() - before) +
                " patches withdrawn)");
            // such a construct returns through the three addresses its
            // routine's replacement writes: two `ret` gadgets and the
            // continuation. The walk steps over the construct by the table
            // and never passes the gadgets, so they are kept as roots.
            std::set<int64_t> gad;
            for (int64_t g : pub)
                for (const auto& [o, t] : model_.r[g].cont)
                    if (!b_seen_.count(t)) gad.insert(t);
            for (int64_t t : gad) {
                b_seen_.insert(t);
                b_roots_.push_back(t);
            }
        }
    }
    for (int it = 0; it < 4; ++it) {
        double tp = now_s();
        auto lap = [&tp](const char* what) {
            const double t = now_s();
            const std::string s = std::string("  timing: ") + what + " " + fmt0(t - tp) + "s";
            tp = t;
            return s;
        };
        apply_and_rewalk();
        log(lap("walks after applying the plan"));
        std::unordered_set<int64_t> drop;
        for (int it2 = 0; it2 < 8; ++it2) {
            wipes_v_ = dead_bytes();
            log(lap("dead bytes"));
            unwiped_ = 0;
            b_rounds_ += settle_b();
            log(lap("settle plausible blocks"));
            check_all();
            log(lap("invariant checks"));
            const std::vector<int64_t> pstart = pl_->patches.sorted_keys();
            drop.clear();
            std::set<int64_t> unwipe;
            std::vector<int64_t> ts = targets(inv_);
            const auto t2 = targets(inv_union_);
            ts.insert(ts.end(), t2.begin(), t2.end());
            for (int64_t t : ts) {
                const int64_t k = static_cast<int64_t>(std::upper_bound(pstart.begin(), pstart.end(), t) - pstart.begin()) - 1;
                if (k >= 0) {
                    const int64_t r = pstart[static_cast<size_t>(k)];
                    if (r < t && t < r + static_cast<int64_t>(pl_->patches.get(r)->data.size())) {
                        drop.insert(r);
                        continue;
                    }
                }
                unwipe.insert(t);
            }
            for (int64_t t : u_refs_) unwipe.erase(t);
            for (int64_t r : ws_drops()) drop.insert(r);
            if (!drop.empty() || unwipe.empty()) break;
            std::vector<int64_t> br, dr;
            Lite d;
            for (int64_t t : unwipe) {
                const RefSrc& src = ref_src_[t];
                bool is_br = false;
                int64_t v;
                if (!src.is_why && code2_->insn(src.v, d))
                    is_br = (d.mid == M_JMP || d.mid == M_CALL || mf(d.mid, F_JCC)) && starts(d.ops(), "0x") &&
                            hex_op(d.ops(), v);
                u_refs_.insert(t);
                (is_br ? br : dr).push_back(t);
            }
            u_roots_.insert(u_roots_.end(), br.begin(), br.end());
            u_data_.insert(u_data_.end(), dr.begin(), dr.end());
            ProfT pt_("walk U from wiped bytes live code refers to");
            const Saved saved = stubs_on(true);
            wu_->walk(roots_with(br, "referenced by live code"));
            stubs_off(saved);
            log("live code refers into " + std::to_string(unwipe.size()) + " wiped bytes (" + std::to_string(br.size()) +
                " branches): kept by walk / extent; checking again");
        }
        if (drop.empty()) break;
        rollback(drop, "live code enters the patch in the patched walk", true);
    }
    int64_t db = 0, wb = 0;
    for (const auto& [r, n] : dead_wipes_) db += n;
    for (const auto& [r, n] : wipes_v_) wb += n;
    log("dead plan: " + std::to_string(dead_wipes_.size()) + " ranges " + std::to_string(db) +
        " bytes; union invariants: " + inv_summary(inv_union_));
    log("wipes: " + std::to_string(wipes_v_.size()) + " ranges " + std::to_string(wb) + " bytes; invariants: " +
        inv_summary(inv_));
    for (const auto& [k, v] : prof()) {
        char b[96];
        std::snprintf(b, sizeof b, "  profile: %-34s %6.1fs", k.c_str(), v);
        log(b);
    }
}

PlanF Pipeline::plan() const {
    PlanF p;
    for (const auto& [rva, n] : wipes_v_)
        if (n > 0) p.wipes.emplace_back(static_cast<uint32_t>(rva), static_cast<uint32_t>(n));
    for (int64_t rva : pl_->patches.sorted_keys()) {
        const Patch* x = pl_->patches.get(rva);
        p.patches.push_back({static_cast<uint32_t>(rva), x->kind, x->data});
    }
    std::set<int64_t> d(pl_->drops.begin(), pl_->drops.end());
    d.insert(wipe_drops_.begin(), wipe_drops_.end());
    for (int64_t r : d) p.drops.push_back(static_cast<uint32_t>(r));
    return p;
}

PlanF Pipeline::dead_plan() const {
    PlanF p;
    for (const auto& [rva, n] : dead_wipes_)
        if (n > 0) p.wipes.emplace_back(static_cast<uint32_t>(rva), static_cast<uint32_t>(n));
    std::set<int64_t> d(dead_drops_.begin(), dead_drops_.end());
    for (int64_t r : d) p.drops.push_back(static_cast<uint32_t>(r));
    return p;
}

PlanF Pipeline::stubs_plan() const {
    PlanF p;
    std::set<std::pair<int64_t, int64_t>> live(stubs_reachable_.begin(), stubs_reachable_.end());
    // A construct that stays in place inside rewritten code (its routine
    // publishes a value) is stepped over by the table, so no walk enters the
    // routine: its replacement is needed all the same. The pieces of one
    // replacement are linked by a trailing `jmp rel32`.
    {
        std::map<int64_t, const std::vector<uint8_t>*> by_rva;
        for (const auto& [rva, data] : stub_patches_) by_rva[rva] = &data;
        std::set<int64_t> need;
        for (const auto& [s, i] : w1_->idioms.items()) {
            if (i->inner.empty()) continue;
            const Res* r = pl_->idiom_res.get(s);
            if (r && r->ok) continue;
            for (const ChainP& ch : i->inner) need.insert(ch->G);
        }
        for (int64_t g : need) {
            int64_t rva = g;
            for (int k = 0; k < 64; ++k) {
                auto it = by_rva.find(rva);
                if (it == by_rva.end()) break;
                const std::vector<uint8_t>& data = *it->second;
                live.insert({rva, static_cast<int64_t>(data.size())});
                if (data.size() >= 5 && data[data.size() - 5] == 0xE9 && data.back() != 0xC3) {
                    int32_t rel;
                    std::memcpy(&rel, data.data() + data.size() - 4, 4);
                    rva = rva + static_cast<int64_t>(data.size()) + rel;
                } else {
                    break;
                }
            }
        }
    }
    for (const auto& [rva, data] : stub_patches_)
        if (live.count({rva, static_cast<int64_t>(data.size())}))
            p.patches.push_back({static_cast<uint32_t>(rva), KIND_STUB, data});
    return p;
}

std::map<int64_t, int64_t> Pipeline::function_for(const std::vector<int64_t>& starts_) {
    std::unordered_set<int64_t> fn;
    for (const auto& r : im_.runtime_functions()) fn.insert(r[0]);
    const PSection* t = im_.exec_sections()[0];
    const int64_t text_hi = static_cast<int64_t>(t->rva) + t->vsize;
    std::map<int64_t, int64_t> out;
    for (int64_t s : starts_) {
        auto it = w1_->found_in.find(s);
        int64_t x = it == w1_->found_in.end() ? s : it->second;
        int64_t res = -1;
        for (int k = 0; k < 4000; ++k) {
            if (fn.count(x) && x < text_hi) {
                res = x;
                break;
            }
            if (w1_->call_targets.count(x)) break;
            const int64_t* nx = w1_->src.find(x);
            if (!nx || *nx < 0) break;
            x = *nx;
        }
        out[s] = res;
    }
    return out;
}

std::vector<int64_t> Pipeline::starts_out() {
    std::vector<int64_t> folds, cks;
    for (const auto& [s, r] : pl_->idiom_res.items())
        if (r.ok && (*w1_->idioms.get(s))->has_cont()) folds.push_back(s);
    for (const auto& [c, r] : pl_->check_res.items())
        if (r.ok) cks.push_back(c);
    std::sort(folds.begin(), folds.end());
    std::sort(cks.begin(), cks.end());
    std::set<int64_t> ent;
    for (const auto& [s, v] : function_for(folds))
        if (v > 0) ent.insert(v);
    for (const auto& [s, v] : function_for(cks))
        if (v > 0) ent.insert(v);
    log("starts: " + std::to_string(ent.size()) + " function entries reach " + std::to_string(folds.size()) +
        " folds and " + std::to_string(cks.size()) + " folded checks");
    return {ent.begin(), ent.end()};
}

std::vector<uint8_t> Pipeline::live_bits() const {
    const int64_t n = reg_.total;
    std::vector<uint8_t> out(static_cast<size_t>((n + 7) / 8), 0);
    const uint8_t L3 = CODE | IDIOM | CHAIN;
    for (int64_t i = 0; i < n; ++i) {
        const bool v = (w2_->bm.f[static_cast<size_t>(i)] & L3) || (w2s_->bm.f[static_cast<size_t>(i)] & L3) ||
                       pl_->claimed.b.test(i);
        if (v) out[static_cast<size_t>(i >> 3)] |= static_cast<uint8_t>(0x80 >> (i & 7));
    }
    return out;
}

}  // namespace flow
