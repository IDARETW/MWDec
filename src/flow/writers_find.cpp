// tools/find_writers.py (and find_lists.find_lists) in C++. Every step reads
// the image the way the Python does, in the same order, so that the table it
// writes is the same file byte for byte. The comments name the Python
// functions; the reasons for each rule are written there.
#include "flow/writers_find.h"

#include <windows.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <thread>
#include <cmath>
#include <cstdio>
#include <deque>
#include <fstream>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>

#include "flow/idiom.h"
#include "flow/pyutil.h"

namespace flow {

namespace {

// ------------------------------------------------------------ find_lists --

std::vector<uint8_t> uleb(uint64_t v) {
    std::vector<uint8_t> out;
    for (;;) {
        const uint8_t c = static_cast<uint8_t>(v & 0x7F);
        v >>= 7;
        if (v) {
            out.push_back(c | 0x80);
        } else {
            out.push_back(c);
            return out;
        }
    }
}

// find_lists.walk_back_ref: from a terminator at a[at], back to the list's
// first byte. Returns false when the walk fails.
bool walk_back(const uint8_t* a, int64_t lo, int64_t at, int64_t cursor, int64_t& start,
               std::vector<std::pair<int64_t, int64_t>>& out, int64_t max_values = 8000000) {
    int64_t p = at;
    bool want_len = true;
    int64_t length = 0, n = 0;
    out.clear();
    while (true) {
        if (!want_len) {
            const auto first = uleb(static_cast<uint64_t>(cursor));
            const int64_t k = static_cast<int64_t>(first.size());
            if (p - k >= lo && std::memcmp(a + p - k, first.data(), first.size()) == 0) {
                out.emplace_back(cursor, length);
                std::reverse(out.begin(), out.end());
                start = p - k;
                return true;
            }
        }
        const int64_t e = p - 1;
        if (e < lo || (a[e] & 0x80)) return false;
        int64_t s = e;
        while (s > lo && (a[s - 1] & 0x80) && e - s < 4) --s;
        int64_t v = 0;
        for (int64_t k = e; k >= s; --k) v = (v << 7) | (a[k] & 0x7F);
        if (want_len) {
            if (v == 0) return false;
            length = v;
            cursor -= v;
        } else {
            out.emplace_back(cursor, length);
            cursor -= v;
        }
        if (cursor <= 0) return false;
        p = s;
        want_len = !want_len;
        if (++n > max_values) return false;
    }
}

}  // namespace

std::vector<FoundRanges> find_lists_mapped(const FImage& im) {
    // the sections as find_writers.Finder.lists hands them to find_lists
    struct S {
        int64_t rva, vsize, rsize;
    };
    std::vector<S> secs;
    for (const PSection& s : im.sections) {
        int64_t rs = std::min(s.vsize, s.rsize);
        if (!rs) rs = s.vsize;
        secs.push_back({s.rva, s.vsize, rs});
    }
    // every candidate terminator in section order, then their walks on threads
    struct Cand {
        int64_t sec_rva, o, end;
        const uint8_t* a;
    };
    std::vector<Cand> cands;
    for (const S& sec : secs) {
        int64_t n = std::min(sec.vsize, sec.rsize);
        if (n < 16) continue;
        n = std::min<int64_t>(n, im.len - sec.rva);
        const uint8_t* a = im.mem.data() + sec.rva;
        for (int64_t o = 0; o + 5 <= n; ++o) {
            if (a[o + 4] < 0x0D || a[o + 4] > 0x0F) continue;
            if (!(a[o] & 0x80) || !(a[o + 1] & 0x80) || !(a[o + 2] & 0x80) || !(a[o + 3] & 0x80)) continue;
            const int64_t v = (a[o] & 0x7F) | (int64_t(a[o + 1] & 0x7F) << 7) | (int64_t(a[o + 2] & 0x7F) << 14) |
                              (int64_t(a[o + 3] & 0x7F) << 21) | (int64_t(a[o + 4]) << 28);
            const int64_t end = 0xFFFFFFFFll - v;
            if (!(end > 0 && end <= im.size_of_image)) continue;
            if (o == 0 || (a[o - 1] & 0x80)) continue;
            cands.push_back({sec.rva, o, end, a});
        }
    }
    std::vector<std::unique_ptr<FoundRanges>> res(cands.size());
    std::atomic<size_t> next{0};
    auto work = [&] {
        std::vector<std::pair<int64_t, int64_t>> rr;
        for (size_t i; (i = next.fetch_add(1)) < cands.size();) {
            const Cand& c = cands[i];
            int64_t start;
            if (!walk_back(c.a, 0, c.o, c.end, start, rr)) continue;
            bool ok = true;
            for (size_t k = 0; k < rr.size() && k < 4096; ++k) {
                const auto [rva, ln] = rr[k];
                bool in = false;
                for (const S& x : secs)
                    if (x.rva <= rva && rva + ln <= x.rva + std::max(x.vsize, x.rsize)) {
                        in = true;
                        break;
                    }
                if (!in) {
                    ok = false;
                    break;
                }
            }
            if (!ok) continue;
            auto f = std::make_unique<FoundRanges>();
            f->rva = c.sec_rva + start;
            f->r = rr;
            for (const auto& [x, ln] : rr) f->total += ln;
            res[i] = std::move(f);
        }
    };
    const unsigned nt = std::max(1u, std::min<unsigned>(std::thread::hardware_concurrency(), 16));
    std::vector<std::thread> th;
    for (unsigned t = 1; t < nt; ++t) th.emplace_back(work);
    work();
    for (std::thread& t : th) t.join();
    std::vector<FoundRanges> found;
    for (auto& f : res)
        if (f) found.push_back(std::move(*f));
    return found;
}

namespace {

// ------------------------------------------------------------ the stream --

struct SIns {
    int64_t pc = 0;
    int size = 0;
    std::string m, op;
};

enum { K_INSN, K_JMP, K_JCC, K_CALL, K_END };

struct SStep {
    int kind = K_END;
    bool has = false;
    SIns ins;
    int64_t s0 = 0, s1 = 0;
};

// find_writers.Stream
class Stream {
public:
    explicit Stream(FImage& im) : code_(im, ro_of(im), nullptr) {}
    Code& code() { return code_; }

    SStep step(int64_t pc) {
        SStep r;
        if (!code_.in_code(pc)) return r;
        std::optional<Idiom> idm;
        try {
            idm = resolve_idiom(code_, pc);
        } catch (...) {
            idm.reset();
        }
        if (idm) {
            if (idm->kind == IK_JMP) {
                r.kind = K_JMP;
                r.s0 = idm->target;
                return r;
            }
            if (idm->kind == IK_JCC) {
                r.kind = K_JCC;
                r.s0 = idm->target;
                r.s1 = idm->fall;
                return r;
            }
            if (idm->kind == IK_CALL) {
                r.kind = K_CALL;
                r.s0 = idm->ret;
                return r;
            }
        }
        Lite d;
        if (!code_.insn(pc, d)) return r;
        r.has = true;
        r.ins.pc = pc;
        r.ins.size = d.size;
        r.ins.m = std::string(d.mn());
        r.ins.op = std::string(d.ops());
        const int64_t nxt = pc + d.size;
        const std::string& m = r.ins.m;
        const std::string& op = r.ins.op;
        int64_t t;
        if (m == "jmp") {
            if (starts(op, "0x") && hex_op(op, t)) {
                r.has = false;
                r.kind = K_JMP;
                r.s0 = t;
                return r;
            }
            r.kind = K_END;
            return r;
        }
        if (m == "ret" || m == "retf" || m == "int3" || m == "ud2" || m == "hlt") {
            r.kind = K_END;
            return r;
        }
        if (m == "call") {
            r.kind = K_CALL;
            r.s0 = nxt;
            return r;
        }
        if (!m.empty() && m[0] == 'j' && starts(op, "0x") && hex_op(op, t)) {
            r.kind = K_JCC;
            r.s0 = t;
            r.s1 = nxt;
            return r;
        }
        r.kind = K_INSN;
        r.s0 = nxt;
        return r;
    }

    std::vector<SIns> straight(int64_t pc, size_t n) {
        std::vector<SIns> out;
        size_t guard = 0;
        while (out.size() < n && guard < 4 * n + 64) {
            ++guard;
            SStep s = step(pc);
            if (s.kind == K_INSN) {
                out.push_back(std::move(s.ins));
                pc = s.s0;
            } else if (s.kind == K_JMP) {
                pc = s.s0;
            } else {
                break;
            }
        }
        return out;
    }

    // reach(): calls f(ins) in the generator's order until f returns false
    template <class F> void reach(int64_t start, int64_t limit, F&& f) {
        std::unordered_set<int64_t> seen;
        std::deque<int64_t> todo{start};
        int64_t n = 0;
        while (!todo.empty() && n < limit) {
            int64_t pc = todo.front();
            todo.pop_front();
            while (!seen.count(pc) && n < limit) {
                seen.insert(pc);
                ++n;
                SStep s = step(pc);
                if (s.has && (s.kind == K_INSN || s.kind == K_CALL || s.kind == K_JCC))
                    if (!f(s.ins)) return;
                if (s.kind == K_INSN || s.kind == K_JMP || s.kind == K_CALL) {
                    pc = s.s0;
                } else if (s.kind == K_JCC) {
                    todo.push_back(s.s0);
                    pc = s.s1;
                } else {
                    break;
                }
            }
        }
    }

private:
    static RangeV ro_of(const FImage& im) {
        RangeV ro;
        for (const PSection& s : im.sections)
            if (!s.executable() && !(s.chars & 0x80000000u) && std::min(s.vsize, s.rsize))
                ro.emplace_back(s.rva, static_cast<int64_t>(s.rva) + std::min(s.vsize, s.rsize));
        return ro;
    }
    RangeV ro_;
    Code code_;
};

// find_writers.rip_target: "[rip +/- 0x..]", first match
std::optional<int64_t> rip_tgt(const SIns& i) {
    const std::string_view op = i.op;
    size_t p = 0;
    while (true) {
        const size_t k = op.find("[rip ", p);
        if (k == std::string_view::npos) return std::nullopt;
        const size_t q = k + 5;
        if (q + 4 <= op.size() && (op[q] == '+' || op[q] == '-') && op[q + 1] == ' ' && op[q + 2] == '0' &&
            op[q + 3] == 'x') {
            const bool plus = op[q] == '+';
            size_t e = q + 4;
            uint64_t v = 0;
            while (e < op.size() && ((op[e] >= '0' && op[e] <= '9') || (op[e] >= 'a' && op[e] <= 'f'))) {
                v = (v << 4) | static_cast<uint64_t>(op[e] <= '9' ? op[e] - '0' : op[e] - 'a' + 10);
                ++e;
            }
            if (e > q + 4 && e < op.size() && op[e] == ']') {
                const int64_t d = static_cast<int64_t>(v);
                return i.pc + i.size + (plus ? d : -d);
            }
        }
        p = k + 1;
    }
}

// FRAME_STORE: ^(?:qword|dword) ptr \[rbp \+ (0x[0-9a-f]+|\d+)\], (rax|eax)$  (on a mov)
std::optional<int64_t> frame_store(const SIns& i) {
    if (i.m != "mov") return std::nullopt;
    std::string_view s = i.op;
    size_t k;
    if (starts(s, "qword ptr [rbp + "))
        k = 17;
    else if (starts(s, "dword ptr [rbp + "))
        k = 17;
    else
        return std::nullopt;
    uint64_t v;
    size_t e;
    if (!parse_num(s, k, v, e)) return std::nullopt;
    const std::string_view rest = s.substr(e);
    if (rest != "], rax" && rest != "], eax") return std::nullopt;
    return static_cast<int64_t>(v);
}

// FRAME_USE search: dword ptr \[rbp \+ (0x[0-9a-f]+|\d+)\]
std::optional<int64_t> frame_use(std::string_view s) {
    size_t p = 0;
    while (true) {
        const size_t k = s.find("dword ptr [rbp + ", p);
        if (k == std::string_view::npos) return std::nullopt;
        uint64_t v;
        size_t e;
        if (parse_num(s, k + 17, v, e) && e < s.size() && s[e] == ']') return static_cast<int64_t>(v);
        p = k + 1;
    }
}

// sites_of: every (site, target) of `prefix` + rel32 over the stream's code regions
void sites_of(const FImage& im, const RangeV& ex, const std::vector<uint8_t>& prefix, std::vector<int64_t>& ss,
              std::vector<int64_t>& tt) {
    const int64_t n = static_cast<int64_t>(prefix.size());
    for (const auto& [lo, hi0] : ex) {
        const int64_t hi = std::min<int64_t>(hi0, im.len);
        const int64_t len = hi - lo;
        if (len < n + 4) continue;
        const uint8_t* a = im.mem.data() + lo;
        for (int64_t k = 0; k < len - n - 3; ++k) {
            if (a[k] != prefix[0]) continue;
            bool ok = true;
            for (int64_t j = 1; j < n; ++j)
                if (a[k + j] != prefix[static_cast<size_t>(j)]) {
                    ok = false;
                    break;
                }
            if (!ok) continue;
            int32_t d;
            std::memcpy(&d, a + k + n, 4);
            ss.push_back(lo + k);
            tt.push_back(lo + k + n + 4 + d);
        }
    }
}

// ------------------------------------------------------------- decoding --

const bool* common_table() {
    static bool t[256] = {};
    static bool init = false;
    if (!init) {
        for (int b : {0x00, 0x01, 0x02, 0x04, 0x08, 0x0F, 0x10, 0x18, 0x20, 0x24, 0x28, 0x30, 0x33, 0x38, 0x3B, 0x40, 0x41,
                      0x44, 0x45, 0x48, 0x49, 0x4C, 0x4D, 0x54, 0x5C, 0x66, 0x74, 0x75, 0x83, 0x84, 0x85, 0x89, 0x8B, 0x8D,
                      0x90, 0xC0, 0xC1, 0xC3, 0xC7, 0xC8, 0xC9, 0xCC, 0xD0, 0xD2, 0xE8, 0xE9, 0xEB, 0xF8, 0xFE, 0xFF})
            t[b] = true;
        init = true;
    }
    return t;
}

// numpy's pairwise summation of a float64 array (what .sum() does)
double pw_sum(const double* a, size_t n) {
    if (n < 8) {
        double r = 0.;
        for (size_t i = 0; i < n; ++i) r += a[i];
        return r;
    }
    if (n <= 128) {
        double r[8];
        for (int j = 0; j < 8; ++j) r[j] = a[j];
        size_t i;
        for (i = 8; i < n - (n % 8); i += 8)
            for (int j = 0; j < 8; ++j) r[j] += a[i + static_cast<size_t>(j)];
        double res = ((r[0] + r[1]) + (r[2] + r[3])) + ((r[4] + r[5]) + (r[6] + r[7]));
        for (; i < n; ++i) res += a[i];
        return res;
    }
    size_t n2 = n / 2;
    n2 -= n2 % 8;
    return pw_sum(a, n2) + pw_sum(a + n2, n - n2);
}

double entropy(const uint8_t* b, size_t n) {
    if (!n) return 8.0;
    int64_t c[256] = {};
    for (size_t i = 0; i < n; ++i) ++c[b[i]];
    std::vector<double> t;
    for (int k = 0; k < 256; ++k)
        if (c[k]) {
            const double p = static_cast<double>(c[k]) / static_cast<double>(n);
            t.push_back(p * std::log2(p));
        }
    // a reduction starts from the first element, then adds the rest
    const double s = t.size() > 1 ? t[0] + pw_sum(t.data() + 1, t.size() - 1) : t[0];
    return -s;
}

double common_share(const uint8_t* b, size_t n) {
    if (!n) return 0.0;
    const bool* t = common_table();
    int64_t k = 0;
    for (size_t i = 0; i < n; ++i) k += t[b[i]];
    return static_cast<double>(k) / static_cast<double>(n);
}

std::vector<uint8_t> decode(const uint8_t* raw, size_t nwords, const std::string& variant, uint32_t K) {
    std::vector<uint8_t> out(nwords * 4);
    uint32_t* o = reinterpret_cast<uint32_t*>(out.data());
    auto w = [raw](size_t i) {
        uint32_t x;
        std::memcpy(&x, raw + 4 * i, 4);
        return x;
    };
    if (variant == "Xor") {
        for (size_t i = 0; i < nwords; ++i) o[i] = w(i) ^ K;
    } else if (variant == "Sub") {
        for (size_t i = 0; i < nwords; ++i) o[i] = K - w(i);
    } else if (variant == "XorAuto") {
        uint32_t k = K;
        for (size_t i = 0; i < nwords; ++i) {
            const uint32_t p = w(i) ^ k;
            o[i] = p;
            k += p;
        }
    } else {
        uint32_t a = K, b = K & 31;
        for (size_t i = 0; i < nwords; ++i) {
            const uint32_t s = b & 31;
            if (s) a = (a << s) | (a >> (32 - s));
            const uint32_t p = w(i) - a * b;
            o[i] = p;
            b = ~p ^ b;
        }
    }
    return out;
}

enum Kind { KSHORT, KFLAT, KSTRUCT, KNOISE };

Kind kind_of(const uint8_t* b, size_t n) {
    if (n < 32) return KSHORT;
    n = std::min<size_t>(n, 65536);
    if (entropy(b, n) < 1.0) return KFLAT;
    const double cs = common_share(b, n);
    if (cs > 0.35) return KSTRUCT;
    if (n >= 4096 && cs > 0.28 && entropy(b, n) < 7.0) return KSTRUCT;
    return KNOISE;
}

using RangesP = std::shared_ptr<const std::vector<std::pair<int64_t, int64_t>>>;

struct Setup {
    int64_t list = 0, slot = 0;
    bool has_stash = false;
    std::optional<int64_t> stash;
    int64_t stash_slot = 0, stash_site = 0;
    std::optional<std::string> variant;
    std::optional<int64_t> key, key_slot;
};

struct Row {
    int64_t site = 0;
    Setup w;
    RangesP ranges;
    int64_t bytes = 0;
    bool writes_stash = false;
    int round = 1;
};

std::string counter_hex(const std::vector<std::pair<int64_t, int64_t>>& v) {
    std::string s = "{";
    for (size_t k = 0; k < v.size(); ++k) {
        char b[64];
        std::snprintf(b, sizeof b, "%s'0x%llx': %lld", k ? ", " : "", static_cast<unsigned long long>(v[k].first),
                      static_cast<long long>(v[k].second));
        s += b;
    }
    return s + "}";
}

// Counter in first-seen order
template <class K> struct OCounter {
    std::vector<std::pair<K, int64_t>> v;
    void add(const K& k) {
        for (auto& [x, n] : v)
            if (x == k) {
                ++n;
                return;
            }
        v.emplace_back(k, 1);
    }
};

class Finder {
public:
    Finder(FImage& im, std::function<void(const std::string&)> log) : im_(im), log_(std::move(log)) {
        t0_ = std::chrono::steady_clock::now();
        size_ = im.size_of_image;
    }

    WritersFound run(int max_rounds = 8) {
        std::vector<Row> all;
        for (int n = 1; n <= max_rounds; ++n) {
            say("round " + std::to_string(n));
            st_ = std::make_unique<Stream>(im_);
            lists();
            setups();
            stashes();
            loops();
            inits();
            judge();
            if (rows_.empty()) break;
            for (Row& r : rows_) {
                r.round = n;
                applied_.insert(r.site);
            }
            all.insert(all.end(), rows_.begin(), rows_.end());
        }
        WritersFound f;
        for (const Row& r : all) {
            WriterRow o;
            o.site = r.site;
            o.writes_stash = r.writes_stash;
            o.variant = *r.w.variant;
            o.list = r.w.list;
            o.stash = *r.w.stash;
            o.key = *r.w.key;
            o.bytes = r.bytes;
            o.nranges = r.ranges->size();
            o.round = r.round;
            f.rows.push_back(o);
        }
        f.unsettled_sets = static_cast<int64_t>(unsettled_.size());
        for (int64_t b : unsettled_) f.unsettled_bytes += b;
        return f;
    }

private:
    void say(const std::string& s) {
        const double t = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0_).count();
        char b[32];
        std::snprintf(b, sizeof b, "[%5.1fs] ", t);
        log_(b + s);
    }

    // 1. lists
    void lists() {
        list_at_.clear();
        for (FoundRanges& f : find_lists_mapped(im_)) {
            auto p = std::make_shared<std::vector<std::pair<int64_t, int64_t>>>(std::move(f.r));
            list_at_[f.rva] = {p, f.total};
        }
        say("range lists: " + std::to_string(list_at_.size()));
    }

    // 2. writer set-ups
    void setups() {
        lea_s_.clear();
        lea_t_.clear();
        sites_of(im_, st_->code().ex, {0x48, 0x8D, 0x05}, lea_s_, lea_t_);
        lea_map_.clear();
        for (size_t k = 0; k < lea_s_.size(); ++k) lea_map_[lea_s_[k]] = lea_t_[k];
        setup_.clear();
        order_.clear();
        int64_t hits = 0;
        for (size_t k = 0; k < lea_s_.size(); ++k) {
            if (!list_at_.count(lea_t_[k])) continue;
            ++hits;
            const int64_t site = lea_s_[k];
            const auto ins = st_->straight(site, 4);
            if (ins.size() == 4 && frame_store(ins[1]) && ins[2].m == "mov" && ins[2].op == "eax, 1" &&
                ins[3].m == "test" && ins[3].op == "eax, eax") {
                if (!setup_.count(site)) order_.push_back(site);
                Setup s;
                s.list = lea_t_[k];
                s.slot = *frame_store(ins[1]);
                setup_[site] = s;
            }
        }
        OCounter<int64_t> slots;
        for (int64_t s : order_) slots.add(setup_[s].slot);
        say("instructions that load a list's address into rax: " + std::to_string(hits) + "; of them writer set-ups: " +
            std::to_string(setup_.size()) + " (list slots " + counter_hex(slots.v) + ")");
    }

    struct TryRes {
        int64_t site;
        std::optional<int64_t> stash;
        int64_t slot, lea;
    };
    std::optional<TryRes> try_from(int64_t a) {
        const auto ins = st_->straight(a, 32);
        if (ins.size() < 3 || ins[0].m != "lea" || !starts(ins[0].op, "rax, [rip") || !frame_store(ins[1]))
            return std::nullopt;
        for (size_t k = 2; k < ins.size(); ++k) {
            if (setup_.count(ins[k].pc)) {
                for (int64_t i = static_cast<int64_t>(k) - 2; i >= 0; --i) {
                    const SIns& x = ins[static_cast<size_t>(i)];
                    if (x.m == "lea" && starts(x.op, "rax, [rip") && frame_store(ins[static_cast<size_t>(i) + 1]))
                        return TryRes{ins[k].pc, rip_tgt(x), *frame_store(ins[static_cast<size_t>(i) + 1]), x.pc};
                }
                return std::nullopt;
            }
        }
        return std::nullopt;
    }

    // 3. the stash
    void stashes() {
        std::vector<int64_t> sorted_sites = order_;
        std::sort(sorted_sites.begin(), sorted_sites.end());
        for (int64_t site : sorted_sites) {
            for (int64_t back = 0x30; back < 0x80; ++back) {
                const int64_t a = site - back;
                if (lea_map_.count(a)) {
                    const auto r = try_from(a);
                    if (r && r->site == site) {
                        Setup& w = setup_[site];
                        w.has_stash = true;
                        w.stash = r->stash;
                        w.stash_slot = r->slot;
                        w.stash_site = r->lea;
                        break;
                    }
                }
            }
        }
        std::vector<int64_t> left;
        for (int64_t s : order_)
            if (!setup_[s].has_stash) left.push_back(s);
        say("stash named a fixed distance before the list: " + std::to_string(setup_.size() - left.size()) +
            "; still to find: " + std::to_string(left.size()));
        if (!left.empty()) {
            std::vector<int64_t> cand;
            const uint8_t* m = im_.mem.data();
            for (size_t k = 0; k < lea_s_.size(); ++k) {
                const int64_t site = lea_s_[k], tgt = lea_t_[k];
                if (!(0 <= tgt && tgt < size_)) continue;
                if (lea_map_.at(site) != tgt) continue;  // a dict keeps the last target of a site (never two)
                if (site + 10 > im_.len) continue;
                if (m[site + 7] == 0xE9 || (m[site + 7] == 0x48 && m[site + 8] == 0x89)) cand.push_back(site);
            }
            say("  candidates for a cut set-up: " + std::to_string(cand.size()));
            const std::unordered_set<int64_t> leftset(left.begin(), left.end());
            for (int64_t a : cand) {
                const auto r = try_from(a);
                if (r && leftset.count(r->site) && !setup_[r->site].has_stash) {
                    Setup& w = setup_[r->site];
                    w.has_stash = true;
                    w.stash = r->stash;
                    w.stash_slot = r->slot;
                    w.stash_site = r->lea;
                }
            }
            left.clear();
            for (int64_t s : order_)
                if (!setup_[s].has_stash) left.push_back(s);
            say("  after the wider search, without a stash: " + std::to_string(left.size()));
        }
        for (int64_t s : left) setup_.erase(s);
        std::vector<int64_t> keep;
        for (int64_t s : order_)
            if (setup_.count(s)) keep.push_back(s);
        order_ = keep;
        OCounter<int64_t> slots;
        for (int64_t s : order_) slots.add(setup_[s].stash_slot);
        say("stash slots: " + counter_hex(slots.v));
    }

    // 4. the encoding, and the key where the loop names it
    void loops() {
        std::vector<std::pair<std::string, int64_t>> kinds;
        auto kadd = [&kinds](const std::string& k) {
            for (auto& [x, n] : kinds)
                if (x == k) {
                    ++n;
                    return;
                }
            kinds.emplace_back(k, 1);
        };
        for (int64_t site : order_) {
            Setup& w = setup_[site];
            std::optional<std::string> variant;
            std::optional<int64_t> key, slot;
            std::vector<SIns> seq;
            st_->reach(site, 900, [&](const SIns& ins) {
                seq.push_back(ins);
                const std::string& m = ins.m;
                const std::string& op = ins.op;
                if (m == "imul") {
                    variant = "MulRol";
                    return false;
                }
                if ((m == "xor" || m == "add") && starts(op, "eax, dword ptr [rip")) {
                    const auto nx = st_->straight(ins.pc, 3);
                    if (nx.size() == 3 && nx[1].m == "mov" && starts(nx[1].op, "rdx, qword ptr [rbp") &&
                        nx[2].m == "mov" && nx[2].op == "dword ptr [rdx], eax") {
                        variant = m == "xor" ? "Xor" : "Sub";
                        key = rip_tgt(ins);
                        return false;
                    }
                }
                if (m == "xor" && starts(op, "eax, dword ptr [rbp")) {
                    slot = frame_use(op);
                    variant = "XorAuto";
                    return false;
                }
                return true;
            });
            if (variant && *variant == "MulRol") {
                for (size_t k = seq.size(); k-- > 0;)
                    if (seq[k].m == "rol") {
                        slot = frame_use(seq[k].op);
                        break;
                    }
            }
            w.variant = variant;
            w.key = key;
            w.key_slot = slot;
            kadd(variant ? *variant : std::string("None"));
        }
        std::string s = "{";
        for (size_t k = 0; k < kinds.size(); ++k)
            s += (k ? ", " : "") + (kinds[k].first == "None" ? std::string("None") : "'" + kinds[k].first + "'") +
                 ": " + std::to_string(kinds[k].second);
        say("encodings read from the loops: " + s + "}");
    }

    // 5. the key of XorAuto and MulRol
    void inits() {
        std::vector<int64_t> need_order;
        for (int64_t s : order_) {
            const Setup& w = setup_[s];
            if (w.variant && (*w.variant == "XorAuto" || *w.variant == "MulRol") && !w.key) need_order.push_back(s);
        }
        if (need_order.empty()) return;
        const std::unordered_set<int64_t> need(need_order.begin(), need_order.end());
        std::vector<int64_t> ss, tt;
        sites_of(im_, st_->code().ex, {0x8B, 0x05}, ss, tt);
        std::vector<std::pair<int64_t, int64_t>> cand;
        const uint8_t* m = im_.mem.data();
        for (size_t k = 0; k < ss.size(); ++k) {
            const int64_t site = ss[k], tgt = tt[k];
            if (!(0 <= tgt && tgt < size_ - 4)) continue;
            if (site + 8 > im_.len) continue;
            const uint8_t a = m[site + 6], b = m[site + 7];
            if (a == 0xE9 || (a == 0x89 && (b == 0x85 || b == 0x45))) cand.emplace_back(site, tgt);
        }
        say("instructions that load a dword into eax and then store or jump: " + std::to_string(cand.size()));
        std::set<int64_t> slots;
        for (int64_t s : need_order)
            if (setup_[s].key_slot) slots.insert(*setup_[s].key_slot);
        struct Init {
            int64_t site, tgt, d;
        };
        std::vector<Init> inits;
        for (const auto& [site, tgt] : cand) {
            const auto ins = st_->straight(site, 2);
            if (ins.size() < 2 || ins[0].m != "mov" || !starts(ins[0].op, "eax, dword ptr [rip")) continue;
            const auto d = frame_store(ins[1]);
            if (d && slots.count(*d) && starts(ins[1].op, "dword")) inits.push_back({site, tgt, *d});
        }
        std::string sl;
        for (int64_t s : slots) {
            char b[32];
            std::snprintf(b, sizeof b, "%s0x%llx", sl.empty() ? "" : ", ", static_cast<unsigned long long>(s));
            sl += b;
        }
        say("of them stores into a key slot (" + sl + "): " + std::to_string(inits.size()));
        int64_t linked = 0;
        for (const Init& in : inits) {
            st_->reach(in.site, 500, [&](const SIns& ins) {
                if (!need.count(ins.pc)) return true;
                Setup& w = setup_[ins.pc];
                if (w.key_slot && *w.key_slot == in.d && !w.key) {
                    w.key = in.tgt;
                    ++linked;
                }
                return false;
            });
        }
        say("key set-ups that lead to a writer set-up with that slot: " + std::to_string(linked) + " of " +
            std::to_string(need.size()) + " wanted");
    }

    // 6. which rows are decryptors, and in what order
    std::vector<uint8_t> out_of(const Row& r, int64_t limit = -1) {
        const int64_t n = limit < 0 ? r.bytes : std::min(r.bytes, limit);
        const int64_t s = *r.w.stash;
        const int64_t e = std::min<int64_t>(s + (n + 3) / 4 * 4, im_.len);
        const size_t nw = static_cast<size_t>((e - s) / 4);
        uint32_t key;
        std::memcpy(&key, im_.mem.data() + *r.w.key, 4);
        std::vector<uint8_t> out = decode(im_.mem.data() + s, nw, *r.w.variant, key);
        out.resize(static_cast<size_t>(std::min<int64_t>(n, static_cast<int64_t>(out.size()))));
        return out;
    }
    void lay(const Row& r, const std::vector<uint8_t>& out) {
        int64_t o = 0;
        for (const auto& [rva, ln] : *r.ranges) {
            const int64_t k = std::max<int64_t>(0, std::min<int64_t>(ln, static_cast<int64_t>(out.size()) - o));
            std::memcpy(im_.mem.data() + rva, out.data() + o, static_cast<size_t>(k));
            o += ln;
        }
    }
    std::vector<uint8_t> now_at(const Row& r) {
        std::vector<uint8_t> v;
        for (const auto& [rva, ln] : *r.ranges) v.insert(v.end(), im_.mem.data() + rva, im_.mem.data() + rva + ln);
        return v;
    }
    static bool feeds(const Row& a, const Row& b) {
        const int64_t lo = *b.w.stash, hi = *b.w.stash + b.bytes;
        for (const auto& [rva, ln] : *a.ranges)
            if (rva < hi && rva + ln > lo) return true;
        return false;
    }

    void judge() {
        const int64_t HEAD = 65536;
        std::vector<Row> rows;
        std::vector<int64_t> sorted_sites = order_;
        std::sort(sorted_sites.begin(), sorted_sites.end());
        for (int64_t site : sorted_sites) {
            const Setup& w = setup_[site];
            if (!w.key || !w.variant || !w.stash) continue;
            const auto it = list_at_.find(w.list);
            const int64_t n = it->second.second;
            if (!(0 <= *w.stash && *w.stash + n <= size_ && 0 <= *w.key && *w.key <= size_ - 4)) continue;
            Row r;
            r.site = site;
            r.w = w;
            r.ranges = it->second.first;
            r.bytes = n;
            rows.push_back(r);
        }
        std::vector<size_t> pending, accepted, repairs;
        size_t erasers = 0, shorts = 0;
        for (size_t i = 0; i < rows.size(); ++i)
            if (!applied_.count(rows[i].site)) pending.push_back(i);
        auto premove = [&pending](size_t i) { pending.erase(std::find(pending.begin(), pending.end(), i)); };
        bool progress = true;
        while (progress) {
            progress = false;
            for (size_t i : std::vector<size_t>(pending)) {
                const auto head = out_of(rows[i], HEAD);
                const Kind k = kind_of(head.data(), head.size());
                if (k == KSTRUCT) {
                    premove(i);
                    progress = true;
                    const auto out = out_of(rows[i]);
                    const auto cur = now_at(rows[i]);
                    if (out == cur) {
                        repairs.push_back(i);
                    } else {
                        lay(rows[i], out);
                        accepted.push_back(i);
                    }
                } else if (k == KFLAT) {
                    premove(i);
                    ++erasers;
                } else if (k == KSHORT) {
                    premove(i);
                    ++shorts;
                }
            }
            std::unordered_set<int64_t> live;
            for (size_t i : pending) live.insert(rows[i].site);
            std::unordered_map<int64_t, std::vector<size_t>> fed;
            for (size_t a : pending) {
                auto& v = fed[rows[a].site];
                for (size_t b : pending)
                    if (b != a && feeds(rows[a], rows[b])) v.push_back(b);
            }
            std::function<bool(size_t, int, const std::set<int64_t>&)> leads = [&](size_t a, int depth,
                                                                                  const std::set<int64_t>& used) {
                const auto saved = now_at(rows[a]);
                lay(rows[a], out_of(rows[a]));
                bool res = false;
                auto it = fed.find(rows[a].site);
                if (it != fed.end()) {
                    for (size_t b : it->second) {
                        if (used.count(rows[b].site) || !live.count(rows[b].site)) continue;
                        const auto h = out_of(rows[b], HEAD);
                        const Kind k = kind_of(h.data(), h.size());
                        if (k == KSTRUCT) {
                            res = true;
                            break;
                        }
                        if (k == KNOISE && depth < 4) {
                            std::set<int64_t> u2 = used;
                            u2.insert(rows[b].site);
                            if (leads(b, depth + 1, u2)) {
                                res = true;
                                break;
                            }
                        }
                    }
                }
                lay(rows[a], saved);
                return res;
            };
            for (size_t a : std::vector<size_t>(pending)) {
                if (fed[rows[a].site].empty()) continue;
                if (leads(a, 0, {rows[a].site})) {
                    lay(rows[a], out_of(rows[a]));
                    accepted.push_back(a);
                    premove(a);
                    progress = true;
                    break;
                }
            }
        }
        int64_t ws = 0;
        for (size_t i : accepted) {
            bool f = false;
            for (size_t j : accepted)
                if (j != i && feeds(rows[i], rows[j])) {
                    f = true;
                    break;
                }
            rows[i].writes_stash = f;
            ws += f;
        }
        rows_.clear();
        for (size_t i : accepted) rows_.push_back(rows[i]);
        say("rows judged: " + std::to_string(accepted.size()) + " kept (" + std::to_string(ws) +
            " prepare another row's stash); dropped: " + std::to_string(pending.size()) + " decode to noise, " +
            std::to_string(repairs.size()) + " write what is already there, " + std::to_string(erasers) +
            " write one value over and over, " + std::to_string(shorts) + " are too short to judge");
        // ranges that only noise was decoded for (the last round's count is reported)
        for (size_t i : accepted) settled_.insert(*rows[i].ranges);
        for (size_t i : repairs) settled_.insert(*rows[i].ranges);
        std::vector<std::pair<const std::vector<std::pair<int64_t, int64_t>>*, size_t>> left;  // ranges -> first row
        for (size_t i : pending) {
            bool seen = false;
            for (const auto& [rg, j] : left)
                if (*rg == *rows[i].ranges) {
                    seen = true;
                    break;
                }
            if (!seen) left.emplace_back(rows[i].ranges.get(), i);
        }
        unsettled_.clear();
        for (const auto& [rg, i] : left) {
            if (settled_.count(*rg)) continue;
            bool f = false;
            for (size_t j = 0; j < rows.size(); ++j)
                if (j != i && feeds(rows[i], rows[j])) {
                    f = true;
                    break;
                }
            if (f) continue;
            auto cur = now_at(rows[i]);
            if (cur.size() > static_cast<size_t>(HEAD)) cur.resize(static_cast<size_t>(HEAD));
            if (kind_of(cur.data(), cur.size()) == KNOISE) unsettled_.push_back(rows[i].bytes);
        }
    }

    FImage& im_;
    std::function<void(const std::string&)> log_;
    std::chrono::steady_clock::time_point t0_;
    int64_t size_ = 0;
    std::unique_ptr<Stream> st_;
    std::map<int64_t, std::pair<RangesP, int64_t>> list_at_;
    std::vector<int64_t> lea_s_, lea_t_;
    std::unordered_map<int64_t, int64_t> lea_map_;
    std::unordered_map<int64_t, Setup> setup_;
    std::vector<int64_t> order_;  // setup_ in insertion order
    std::unordered_set<int64_t> applied_;
    std::set<std::vector<std::pair<int64_t, int64_t>>> settled_;
    std::vector<int64_t> unsettled_;
    std::vector<Row> rows_;
};

}  // namespace

WritersFound find_writers(FImage& im, const std::function<void(const std::string&)>& log) {
    Finder f(im, log);
    return f.run();
}

std::string writers_tsv(const std::vector<WriterRow>& rows, const std::string& image_name) {
    std::string s = "# writer table for " + image_name +
                    ", made by tools/find_writers.py; rows in the order to apply them\n"
                    "site\twrites_stash\tvariant\tlist\tstash\tkey\tbytes\tranges\tround\n";
    for (const WriterRow& r : rows) {
        char b[256];
        std::snprintf(b, sizeof b, "%08llX\t%d\t%s\t%08llX\t%08llX\t%08llX\t%lld\t%zu\t%d\n",
                      static_cast<unsigned long long>(r.site), r.writes_stash ? 1 : 0, r.variant.c_str(),
                      static_cast<unsigned long long>(r.list), static_cast<unsigned long long>(r.stash),
                      static_cast<unsigned long long>(r.key), static_cast<long long>(r.bytes), r.nranges, r.round);
        s += b;
    }
    return s;
}

int cmd_writers(int argc, char** argv) {
    std::string exe, out;
    for (int i = 2; i < argc; ++i) {
        const std::string a = argv[i];
        if ((a == "-o" || a == "--out") && i + 1 < argc)
            out = argv[++i];
        else if (!a.empty() && a[0] == '-')
            throw std::runtime_error("unknown option " + a);
        else
            exe = a;
    }
    if (exe.empty()) throw std::runtime_error("usage: mwdec writers <layer1.exe> -o writers.tsv");
    FImage im;
    im.load(exe);
    const WritersFound f = find_writers(im, [](const std::string& s) {
        std::printf("%s\n", s.c_str());
        std::fflush(stdout);
    });
    std::printf("sets of ranges that only noise was decoded for: %lld (%lld bytes)\n",
                static_cast<long long>(f.unsettled_sets), static_cast<long long>(f.unsettled_bytes));
    if (!out.empty()) {
        std::ofstream o(out, std::ios::binary | std::ios::trunc);
        o << writers_tsv(f.rows, basename_of(exe));
        std::printf("wrote %s: %zu rows\n", out.c_str(), f.rows.size());
    }
    return 0;
}

}  // namespace flow
