// tools/find_checks.py and tools/find_routines.py in C++ (see tables.h).
// Each step follows the Python line for line; the reasons for the rules are
// written there.
#include "flow/tables.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <deque>
#include <fstream>
#include <map>
#include <set>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>

#include "flow/pipeline.h"
#include "flow/pyutil.h"
#include "flow/stream.h"

namespace flow {

namespace {

std::string x0(int64_t v) {  // "0x%x"
    char b[32];
    std::snprintf(b, sizeof b, "0x%llx", static_cast<unsigned long long>(v));
    return b;
}
std::string x08(uint32_t v) {  // "0x%08x"
    char b[32];
    std::snprintf(b, sizeof b, "0x%08x", v);
    return b;
}
std::vector<uint8_t> le32(uint32_t v) {
    return {static_cast<uint8_t>(v), static_cast<uint8_t>(v >> 8), static_cast<uint8_t>(v >> 16),
            static_cast<uint8_t>(v >> 24)};
}
void put32(std::vector<uint8_t>& b, int64_t v) {
    const uint32_t x = static_cast<uint32_t>(static_cast<int32_t>(v));
    for (int i = 0; i < 4; ++i) b.push_back(static_cast<uint8_t>(x >> (8 * i)));
}

// Counter in first-seen order, printed as a Python dict of str keys
struct SCounter {
    std::vector<std::pair<std::string, int64_t>> v;
    void add(const std::string& k, int64_t n = 1) {
        for (auto& [x, c] : v)
            if (x == k) {
                c += n;
                return;
            }
        v.emplace_back(k, n);
    }
    std::string repr() const {
        std::string s = "{";
        for (size_t i = 0; i < v.size(); ++i)
            s += (i ? ", " : "") + py_repr_str(v[i].first) + ": " + std::to_string(v[i].second);
        return s + "}";
    }
};

// RIP_DWORD: ^(\w+), dword ptr \[rip ([+-]) (0x[0-9a-f]+|\d+)\]$
bool rip_dword(int64_t pc, const Lite& d, std::initializer_list<const char*> mnems, std::string& reg, int64_t& tgt) {
    bool ok = false;
    for (const char* m : mnems)
        if (d.mn() == m) ok = true;
    if (!ok) return false;
    const std::string_view s = d.ops();
    size_t j = 0;
    auto word = [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'; };
    while (j < s.size() && word(s[j])) ++j;
    if (j == 0) return false;
    const std::string_view r = s.substr(0, j);
    const std::string_view mid = ", dword ptr [rip ";
    if (s.substr(j, mid.size()) != mid) return false;
    size_t k = j + mid.size();
    if (k + 2 > s.size() || (s[k] != '+' && s[k] != '-') || s[k + 1] != ' ') return false;
    const bool plus = s[k] == '+';
    uint64_t v;
    size_t e;
    if (!parse_num(s, k + 2, v, e)) return false;
    if (e + 1 != s.size() || s[e] != ']') return false;
    reg = std::string(r);
    const int64_t disp = static_cast<int64_t>(v);
    tgt = pc + d.size + (plus ? disp : -disp);
    return true;
}

}  // namespace

ChecksOut find_slot_checks(FImage& im) {
    Stream st(im);
    Code& code = st.code();
    const int64_t size = im.size_of_image;
    const uint8_t* mem = im.mem.data();
    auto u32 = [&im](int64_t a) { return im.u32(a); };
    auto plain = [&code](int64_t pc, int64_t& at, Lite& d) {
        for (int k = 0; k < 8; ++k) {
            if (!code.in_code(pc) || !code.insn(pc, d)) return false;
            int64_t t;
            if (d.mn() == "jmp" && starts(d.ops(), "0x") && hex_op(d.ops(), t)) {
                pc = t;
                continue;
            }
            at = pc;
            return true;
        }
        return false;
    };
    static const char* const USES[] = {"add rsp", "j", "cmov", "push rbp", "lea rsp", "mov qword ptr [rsp - 8]"};
    ChecksOut out;
    for (const auto& [lo, hi0] : code.ex) {
        const int64_t hi = std::min<int64_t>(hi0, im.len);
        const uint8_t* buf = mem + lo;
        const int64_t n = hi - lo;
        for (int64_t o = 0; o + 1 < n; ++o) {
            if (buf[o] != 0x8B) continue;
            const uint8_t r1b = buf[o + 1];
            if (!(r1b == 0x05 || r1b == 0x0D || r1b == 0x15 || r1b == 0x1D || r1b == 0x25 || r1b == 0x2D || r1b == 0x35 ||
                  r1b == 0x3D))
                continue;
            if (o + 8 > n) continue;
            const uint8_t nb0 = buf[o + 6], nb1 = buf[o + 7];
            if (!(((nb0 == 0x03 || nb0 == 0x33 || nb0 == 0x2B) && nb1 == buf[o + 1]) || nb0 == 0xE9)) continue;
            const int64_t a = lo + o;
            Lite d1;
            if (!code.insn(a, d1)) continue;
            std::string reg;
            int64_t P;
            if (!rip_dword(a, d1, {"mov"}, reg, P)) continue;
            int64_t pc;
            Lite d;
            if (!plain(a + d1.size, pc, d)) continue;
            std::optional<int64_t> A;
            std::string r2;
            int64_t t2;
            if (rip_dword(pc, d, {"add"}, r2, t2) && r2 == reg) {
                A = t2;
                if (!plain(pc + d.size, pc, d)) continue;
            }
            std::string r3;
            int64_t B;
            if (!rip_dword(pc, d, {"xor", "sub"}, r3, B) || r3 != reg) continue;
            auto inimg = [size](int64_t x) { return 0 <= x && x <= size - 4; };
            if (!inimg(P) || !inimg(B) || (A && !inimg(*A))) continue;
            if (!code.in_code(P) || !code.in_code(B) || (A && !code.in_code(*A))) continue;
            int64_t upc;
            Lite du;
            std::string use;
            if (plain(pc + d.size, upc, du)) use = std::string(du.mn()) + " " + std::string(du.ops());
            bool ok = false;
            for (const char* u : USES)
                if (!use.empty() && starts(use, u)) ok = true;
            if (!ok) continue;
            SlotCheck c;
            c.at = a;
            c.P = P;
            c.A = A;
            c.B = B;
            c.op = std::string(d.mn());
            c.need = A ? static_cast<uint32_t>(u32(B) - u32(*A)) : u32(B);
            c.stat = u32(P);
            c.use = use;
            c.cut = pc != a + (A ? 12 : 6);
            out.checks.push_back(c);
        }
    }
    // values(): {P: need} in first-seen order, and the Ps two checks disagree about
    std::vector<int64_t> norder;
    std::unordered_map<int64_t, uint32_t> need;
    std::vector<int64_t> border;
    std::map<int64_t, std::set<uint32_t>> bad;
    for (const SlotCheck& c : out.checks) {
        auto it = need.find(c.P);
        if (it != need.end() && it->second != c.need) {
            if (!bad.count(c.P)) border.push_back(c.P);
            bad[c.P].insert(it->second);
            bad[c.P].insert(c.need);
            continue;
        }
        if (it == need.end()) norder.push_back(c.P);
        need[c.P] = c.need;
    }
    for (const auto& [p, vs] : bad) need.erase(p);
    SCounter uses;
    for (const SlotCheck& c : out.checks) {
        const size_t sp = c.use.find(' ');
        std::string k = c.use.substr(0, sp);
        if (c.use.find(" rsp") != std::string::npos) k += " rsp";
        uses.add(k);
    }
    std::vector<int64_t> ps;
    for (const auto& [p, v] : need) ps.push_back(p);
    std::sort(ps.begin(), ps.end());
    int64_t already = 0;
    for (int64_t P : ps) {
        already += im.u32(P) == need[P];
        out.plan.patches.push_back({static_cast<uint32_t>(P), KIND_BAKE, le32(need[P])});
    }
    int64_t cut = 0;
    for (const SlotCheck& c : out.checks) cut += c.cut;
    out.line = "checks: " + std::to_string(out.checks.size()) + " sequences on " +
               std::to_string(need.size() + bad.size()) + " published dwords (" + uses.repr() +
               "); already holding the needed value: " + std::to_string(already) + "; changed by the plan: " +
               std::to_string(static_cast<int64_t>(need.size()) - already) + "; two checks disagreeing: " +
               std::to_string(bad.size()) + "; sequences cut by a joining jump: " + std::to_string(cut);
    Json arr = Json::array();
    for (const SlotCheck& c : out.checks) {
        Json e = Json::object();
        e["at"] = Json(x0(c.at));
        e["P"] = Json(x0(c.P));
        e["A"] = c.A ? Json(x0(*c.A)) : Json();
        e["B"] = Json(x0(c.B));
        e["op"] = Json(c.op);
        e["need"] = Json(x08(c.need));
        e["static"] = Json(x08(c.stat));
        e["use"] = Json(c.use);
        e["cut"] = Json(c.cut);
        arr.push(e);
    }
    out.json = Json::object();
    out.json["checks"] = arr;
    Json dis = Json::object();
    for (int64_t p : border) {
        Json l = Json::array();
        for (uint32_t v : bad[p]) l.push(Json(x08(v)));
        dis[x0(p)] = l;
    }
    out.json["disagree"] = dis;
    return out;
}

namespace {

// STORE2: ^qword ptr \[(\w+) \+ (\w+)\*8(?: \+ (?:0x[0-9a-f]+|\d+))?\], (\w+)$
bool match_store2(std::string_view s, std::string& base, std::string& idx, std::string& val) {
    auto word = [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
    };
    if (!starts(s, "qword ptr [")) return false;
    size_t k = 11, j = k;
    while (j < s.size() && word(s[j])) ++j;
    if (j == k) return false;
    base = std::string(s.substr(k, j - k));
    if (s.substr(j, 3) != " + ") return false;
    k = j + 3;
    j = k;
    while (j < s.size() && word(s[j])) ++j;
    if (j == k) return false;
    idx = std::string(s.substr(k, j - k));
    if (s.substr(j, 2) != "*8") return false;
    k = j + 2;
    if (s.substr(k, 3) == " + ") {
        uint64_t v;
        size_t e;
        if (!parse_num(s, k + 3, v, e)) return false;
        k = e;
    }
    if (s.substr(k, 3) != "], ") return false;
    k += 3;
    j = k;
    while (j < s.size() && word(s[j])) ++j;
    if (j == k || j != s.size()) return false;
    val = std::string(s.substr(k, j - k));
    return true;
}

// stub_insns: (kind, bytes | target, length); kind 0 raw, 1 lea rcx,[rip+T], 2 store
struct StubIns {
    int kind;
    std::vector<uint8_t> raw;
    int64_t target = 0, value = 0;
    int n;
};

std::vector<StubIns> stub_insns(const std::vector<int64_t>& cont, int64_t o0,
                                const std::vector<std::pair<int64_t, int64_t>>& publishes) {
    const int64_t idx = (o0 - 0x18) / 8;
    if ((o0 - 0x18) % 8 || idx < 0 || idx >= 0x80) throw std::runtime_error("stub_insns: bad slot offset");
    std::vector<StubIns> out;
    for (const auto& [p, v] : publishes) out.push_back({2, {}, p, v, 10});
    out.push_back({0, {0x48, 0x8D, 0x54, 0x24, 0x08}, 0, 0, 5});
    out.push_back({0, {0x48, 0x8B, 0x42, 0x08}, 0, 0, 4});
    out.push_back({0, {0x48, 0xC1, 0xE8, 0x03}, 0, 0, 4});
    out.push_back({0, {0x48, 0x83, 0xC0, static_cast<uint8_t>(idx)}, 0, 0, 4});
    for (int k : {2, 1, 0}) {
        out.push_back({1, {}, cont[static_cast<size_t>(k)], 0, 7});
        if (k == 0)
            out.push_back({0, {0x48, 0x89, 0x0C, 0xC2}, 0, 0, 4});
        else
            out.push_back({0, {0x48, 0x89, 0x4C, 0xC2, static_cast<uint8_t>(8 * k)}, 0, 0, 5});
    }
    out.push_back({0, {0xC3}, 0, 0, 1});
    return out;
}

std::vector<std::pair<int64_t, int64_t>> owned_runs(Code& code, int64_t g, bool through, int max_runs = 40) {
    std::vector<std::pair<int64_t, int64_t>> runs;
    int64_t x = g;
    Lite d;
    for (int r = 0; r < max_runs; ++r) {
        const int64_t start = x;
        bool have_nxt = false;
        int64_t nxt = 0;
        while (true) {
            if (!code.in_code(x) || !code.insn(x, d)) {
                if (x > start) runs.emplace_back(start, x);
                return runs;
            }
            x += d.size;
            const std::string_view m = d.mn();
            int64_t t;
            if (m == "jmp" && starts(d.ops(), "0x") && hex_op(d.ops(), t)) {
                nxt = t;
                have_nxt = true;
                break;
            }
            const bool j = !m.empty() && m[0] == 'j';
            if (through && (m == "call" || (j && m != "jmp"))) continue;
            if (m == "ret" || m == "jmp" || m == "int3" || m == "ud2" || m == "call" || j) break;
        }
        runs.emplace_back(start, x);
        if (!have_nxt) break;
        x = nxt;
    }
    return runs;
}

// build_stub: the pieces in run order, or false with why
bool build_stub(Code& code, int64_t g, const std::vector<int64_t>& cont, int64_t o0, bool through,
                const std::vector<std::pair<int64_t, int64_t>>& publishes,
                std::vector<std::pair<int64_t, std::vector<uint8_t>>>& patches, std::string& why) {
    const auto ins = stub_insns(cont, o0, publishes);
    const auto runs = owned_runs(code, g, through);
    patches.clear();
    size_t k = 0;
    for (size_t ri = 0; ri < runs.size(); ++ri) {
        const auto [lo, hi] = runs[ri];
        const int64_t cap = hi - lo;
        std::vector<uint8_t> buf;
        int64_t rest = 0;
        for (size_t q = k; q < ins.size(); ++q) rest += ins[q].n;
        size_t take;
        bool link;
        if (rest <= cap) {
            take = ins.size() - k;
            link = false;
        } else {
            take = 0;
            int64_t room = cap - 5;
            while (k + take < ins.size() && ins[k + take].n <= room) {
                room -= ins[k + take].n;
                ++take;
            }
            link = true;
            if (ri + 1 >= runs.size()) {
                why = "out of room after " + std::to_string(runs.size()) + " runs";
                return false;
            }
        }
        for (size_t q = k; q < k + take; ++q) {
            const StubIns& s = ins[q];
            if (s.kind == 0) {
                buf.insert(buf.end(), s.raw.begin(), s.raw.end());
            } else if (s.kind == 2) {
                const int64_t at = lo + static_cast<int64_t>(buf.size());
                buf.insert(buf.end(), {0xC7, 0x05});
                put32(buf, s.target - (at + 10));
                const uint32_t v = static_cast<uint32_t>(s.value);
                for (int i = 0; i < 4; ++i) buf.push_back(static_cast<uint8_t>(v >> (8 * i)));
            } else {
                const int64_t at = lo + static_cast<int64_t>(buf.size());
                buf.insert(buf.end(), {0x48, 0x8D, 0x0D});
                put32(buf, s.target - (at + 7));
            }
        }
        k += take;
        if (link) {
            const int64_t at = lo + static_cast<int64_t>(buf.size());
            buf.push_back(0xE9);
            put32(buf, runs[ri + 1].first - (at + 5));
        }
        bool replaced = false;
        for (auto& p : patches)
            if (p.first == lo) {
                p.second = buf;
                replaced = true;
            }
        if (!replaced) patches.emplace_back(lo, buf);
        if (k >= ins.size() && !link) break;
    }
    if (k < ins.size()) {
        why = "did not fit";
        return false;
    }
    return true;
}

struct Rt {
    std::string form;
    std::vector<std::pair<int64_t, std::set<int64_t>>> got;  // index -> addresses, first-seen order
    std::vector<int64_t> sites;
    int64_t steps = 0;
    std::vector<int64_t> chains, returns;
    std::set<int64_t> push;
    std::vector<std::pair<int64_t, int64_t>> pubs;  // published dword -> the store's address, first-seen order
    std::set<int64_t>& at(int64_t ix) {
        for (auto& [k, v] : got)
            if (k == ix) return v;
        got.emplace_back(ix, std::set<int64_t>());
        return got.back().second;
    }
};

}  // namespace

RoutinesOut find_routines(FImage& im, const std::vector<SlotCheck>& checks, const std::string& image_name,
                          const std::function<void(const std::string&)>& log_, int64_t limit) {
    const auto t0 = std::chrono::steady_clock::now();
    auto say = [&](const std::string& s) {
        char b[32];
        std::snprintf(b, sizeof b, "[%6.1fs] ",
                      std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count());
        log_(b + s);
    };
    Stream st(im);
    Code& code = st.code();
    const int64_t base = static_cast<int64_t>(im.image_base);
    const int64_t size = im.size_of_image;
    // published dword -> need, first-seen order (the last check wins)
    std::vector<int64_t> porder;
    std::unordered_map<int64_t, uint32_t> published;
    for (const SlotCheck& c : checks) {
        if (!published.count(c.P)) porder.push_back(c.P);
        published[c.P] = c.need;
    }
    if (!checks.empty() || true) say("published dwords: " + std::to_string(published.size()));

    // 1. the chains
    RawXrefs xr(im, code.extra);
    OrderedMap<ChainP> census;
    std::vector<int64_t> cfail;
    census_chains(im, code, xr, census, cfail);
    std::map<int64_t, std::vector<ChainP>> by;
    std::vector<int64_t> by_order;
    for (const auto& [site, ch] : census.items()) {
        if (!by.count(ch->G)) by_order.push_back(ch->G);
        by[ch->G].push_back(ch);
    }
    auto form_of = [](const std::vector<ChainP>& v) {
        std::set<std::string> f;
        for (const ChainP& c : v) f.insert(std::string(c->call_form) == "call" ? "call" : "pushret");
        return f.size() == 1 ? *f.begin() : std::string("mixed");
    };
    {
        SCounter forms;
        for (int64_t g : by_order) forms.add(form_of(by[g]));
        say("chains: " + std::to_string(census.size()) + ", at " + std::to_string(cfail.size()) +
            " long-form sites without one; routines: " + std::to_string(by.size()) + " (" + forms.repr() + ")");
    }

    // 2. the walk
    SCounter shapes;
    std::map<int64_t, Rt> routines;
    auto slot_write = [&](const std::vector<SIns>& w, int64_t& index, int64_t& addr, std::string& shape) {
        const SIns& last = w.back();
        if (last.m != "mov") return false;
        std::string b, ir, vr;
        if (!match_store2(last.op, b, ir, vr)) return false;
        std::optional<int64_t> q, i;
        std::vector<std::string> sh;
        const size_t n = w.size();
        const size_t from = n >= 5 ? n - 5 : 0;
        for (size_t k = n - 1; k-- > from;) {
            const SIns& x = w[k];
            if (!q && x.m == "mov" && starts(x.op, vr + ", qword ptr [rip")) {
                q = rip_tgt(x);
                sh.push_back("value");
            } else if (!i && (x.m == "mov" || x.m == "add") && starts(x.op, ir + ", qword ptr [rip")) {
                i = rip_tgt(x);
                sh.push_back("index " + x.m);
            }
        }
        if (!q || !i || !(0 <= *q && *q <= size - 8) || !(0 <= *i && *i <= size - 8)) return false;
        const uint64_t idx = im.u64(*i), v = im.u64(*q);
        if (idx >= 0x200 || !(static_cast<uint64_t>(base) <= v && v < static_cast<uint64_t>(base + size))) return false;
        index = static_cast<int64_t>(idx);
        addr = static_cast<int64_t>(v) - base;
        std::string s;
        for (size_t k = sh.size(); k-- > 0;) s += (s.empty() ? "" : ", ") + sh[k];
        shape = "[" + b + "+" + ir + "*8] <- " + vr + "; " + s;
        return true;
    };
    int64_t steps = 0;
    for (const auto& [g, chs] : by) {
        Rt rt;
        std::unordered_set<int64_t> seen;
        std::deque<int64_t> todo{g};
        int64_t n = 0;
        while (!todo.empty() && n < limit) {
            int64_t pc = todo.front();
            todo.pop_front();
            std::vector<SIns> window;
            while (!seen.count(pc) && n < limit) {
                seen.insert(pc);
                ++n;
                SStep s = st.step(pc);
                if (s.kind == K_INSN) {
                    window.push_back(s.ins);
                    if (window.size() > 6) window.erase(window.begin());
                    int64_t ix, ad;
                    std::string sh;
                    if (slot_write(window, ix, ad, sh)) {
                        rt.at(ix).insert(ad);
                        rt.sites.push_back(s.ins.pc);
                        shapes.add(sh);
                    }
                    if (!published.empty() && s.ins.m == "mov" && starts(s.ins.op, "dword ptr [rip")) {
                        const auto t = rip_tgt(s.ins);
                        if (t && published.count(*t)) {
                            bool have = false;
                            for (const auto& [p, a] : rt.pubs)
                                if (p == *t) have = true;
                            if (!have) rt.pubs.emplace_back(*t, s.ins.pc);
                        }
                    }
                    pc = s.s0;
                } else if (s.kind == K_JMP || s.kind == K_CALL) {
                    if (s.kind == K_CALL) window.clear();
                    pc = s.s0;
                } else if (s.kind == K_JCC) {
                    todo.push_back(s.s0);
                    window.clear();
                    pc = s.s1;
                } else {
                    break;
                }
            }
        }
        steps += n;
        rt.form = form_of(chs);
        rt.steps = n;
        for (const ChainP& c : chs) {
            rt.chains.push_back(c->S);
            rt.returns.push_back(c->R);
            rt.push.insert(static_cast<int64_t>(c->push_order.size()));
        }
        routines[g] = std::move(rt);
    }
    int64_t nshape = 0;
    for (const auto& [k, v] : shapes.v) nshape += v;
    say("walked " + std::to_string(routines.size()) + " routines, " + std::to_string(steps) +
        " instructions; slot stores met: " + std::to_string(nshape));
    if (!published.empty()) {
        std::unordered_map<int64_t, std::vector<int64_t>> pby;
        int64_t npub = 0;
        for (const auto& [g, r] : routines) {
            for (const auto& [p, a] : r.pubs) pby[p].push_back(g);
            npub += !r.pubs.empty();
        }
        SCounter forms;
        for (int64_t p : porder) {
            std::set<std::string> fs;
            auto it = pby.find(p);
            if (it != pby.end())
                for (int64_t g : it->second) fs.insert(routines[g].form);
            std::string k;
            if (fs.empty()) {
                k = "no routine stores it";
            } else {
                for (const std::string& f : fs) k += (k.empty() ? "" : "/") + f;
            }
            forms.add(k);
        }
        say("published dwords by who stores them: " + forms.repr() + "; routines that publish: " +
            std::to_string(npub));
    }
    {
        auto v = shapes.v;
        std::stable_sort(v.begin(), v.end(), [](const auto& a, const auto& b) { return a.second > b.second; });
        for (const auto& [k, n] : v) {
            char b[32];
            std::snprintf(b, sizeof b, "   %5lld  ", static_cast<long long>(n));
            say(b + k);
        }
    }

    // 3. the table
    static const char* const CLOBBERS[] = {"rax", "rcx", "rdx", "r8", "r9", "r10", "r11"};
    Json tab = Json::object();
    SCounter kinds;
    for (auto& [g, r] : routines) {
        Json e = Json::object();
        e["form"] = Json(r.form);
        e["class"] = Json();
        Json ch = Json::array(), rs = Json::array();
        for (int64_t s : r.chains) ch.push(Json(hex8(s)));
        for (int64_t s : r.returns) rs.push(Json(hex8(s)));
        e["chains"] = ch;
        e["returns"] = rs;
        e["exit_sites"] = Json(static_cast<int64_t>(r.sites.size()));
        e["instructions_walked"] = Json(r.steps);
        if (!r.pubs.empty()) {
            auto pv = r.pubs;
            std::sort(pv.begin(), pv.end());
            Json l = Json::array();
            for (const auto& [p, at] : pv) {
                Json t = Json::array();
                t.push(Json(x0(p)));
                t.push(Json(x08(published[p])));
                t.push(Json(x0(at)));
                l.push(t);
            }
            e[r.form == "pushret" ? "publishes" : "publishes_at_start"] = l;
        }
        std::vector<int64_t> idxs;
        bool one = true;
        for (const auto& [ix, v] : r.got) {
            idxs.push_back(ix);
            if (v.size() != 1) one = false;
        }
        std::sort(idxs.begin(), idxs.end());
        if (idxs.size() == 3 && idxs[1] == idxs[0] + 1 && idxs[2] == idxs[0] + 2 && one && r.form == "pushret") {
            std::vector<int64_t> t;
            for (int64_t ix : idxs) t.push_back(*r.at(ix).begin());
            Json cr = Json::array();
            for (int64_t x : t) cr.push(Json(x0(x)));
            e["cont_rva"] = cr;
            e["index_constant"] = Json(idxs[0]);
            if (r.push.size() == 1) {
                const int64_t o0 = 0x118 + 8 * *r.push.begin();
                e["slot_offset"] = Json(o0);
                Json c = Json::array();
                for (int k = 0; k < 3; ++k) {
                    Json p = Json::array();
                    p.push(Json(o0 + 8 * k));
                    p.push(Json(x0(base + t[static_cast<size_t>(k)])));
                    c.push(p);
                }
                e["cont"] = c;
                Json cl = Json::array();
                for (const char* s : CLOBBERS) cl.push(Json(s));
                e["clobbers"] = cl;
                kinds.add("three slots");
            } else {
                std::string l = "[";
                bool f = true;
                for (int64_t p : r.push) {
                    l += (f ? "" : ", ") + std::to_string(p);
                    f = false;
                }
                e["why"] = Json("its chains save different numbers of registers: " + l + "]");
                kinds.add("three slots, chains disagree");
            }
        } else if (idxs.empty()) {
            kinds.add("no slot write reached (" + r.form + ")");
        } else {
            Json am = Json::object();
            for (const auto& [ix, v] : r.got) {
                Json l = Json::array();
                for (int64_t x : v) l.push(Json(x0(x)));
                am[std::to_string(ix)] = l;
            }
            e["ambiguous"] = am;
            kinds.add("ambiguous (" + r.form + ")");
        }
        tab[x0(g)] = e;
    }
    // the index constant against the chain's push count
    std::vector<std::pair<int64_t, int64_t>> rel;  // first-seen order
    for (size_t k = 0; k < tab.keys().size(); ++k) {
        const Json& e = tab.at(k);
        if (!e.has("slot_offset")) continue;
        const int64_t d = e.get("index_constant")->as_int() - e.get("slot_offset")->as_int() / 8;
        bool f = false;
        for (auto& x : rel)
            if (x.first == d) {
                ++x.second;
                f = true;
            }
        if (!f) rel.emplace_back(d, 1);
    }
    Json index_rel = Json::object();
    for (const auto& [d, n] : rel) index_rel[std::to_string(d)] = Json(n);
    std::string index_rel_repr = "{";
    for (size_t i = 0; i < rel.size(); ++i)
        index_rel_repr += (i ? ", " : "") + std::to_string(rel[i].first) + ": " + std::to_string(rel[i].second);
    index_rel_repr += "}";
    if (rel.size() > 1) {
        auto v = rel;
        std::stable_sort(v.begin(), v.end(), [](const auto& a, const auto& b) { return a.second > b.second; });
        const int64_t common = v[0].first;
        for (size_t k = 0; k < tab.keys().size(); ++k) {
            Json& e = tab[tab.keys()[k]];
            if (!e.has("slot_offset")) continue;
            const int64_t ic = e.get("index_constant")->as_int(), so = e.get("slot_offset")->as_int();
            if (ic - so / 8 != common) {
                e["why"] = Json("index constant " + std::to_string(ic) + " does not fit the chain's " +
                                std::to_string((so - 0x118) / 8) + " saved registers");
                e.erase("cont");
                e.erase("clobbers");
                kinds.add("three slots", -1);
                kinds.add("index and chain disagree");
            }
        }
    }

    RoutinesOut out;
    // the values that hold from the start
    {
        std::set<int64_t> guards;
        for (size_t k = 0; k < tab.keys().size(); ++k)
            if (const Json* p = tab.at(k).get("publishes"))
                for (const Json& x : p->items()) guards.insert(std::stoll(x.items()[0].as_str().substr(2), nullptr, 16));
        std::vector<int64_t> ps(porder);
        std::sort(ps.begin(), ps.end());
        for (int64_t p : ps)
            if (!guards.count(p)) out.bake.patches.push_back({static_cast<uint32_t>(p), KIND_BAKE, le32(published[p])});
        say("values that hold from the start: " + std::to_string(out.bake.patches.size()) + " of " +
            std::to_string(published.size()) + " published dwords baked; " + std::to_string(guards.size()) +
            " are stored by guards when they run");
    }
    say("routines: " + kinds.repr());
    say("index constant minus slot offset in qwords, over the routines: " + index_rel_repr);

    // 4. the stubs
    int64_t n_ret = 0, n_stub = 0;
    std::unordered_map<int64_t, std::string> claimed;
    std::vector<std::pair<std::string, std::string>> fail;
    for (size_t k = 0; k < tab.keys().size(); ++k) {  // keys are in ascending G already
        const std::string key = tab.keys()[k];
        Json& e = tab[key];
        const int64_t g = std::stoll(key.substr(2), nullptr, 16);
        if (e.get("form")->as_str() == "call" && !e.has("ambiguous")) {
            out.stubs.patches.push_back({static_cast<uint32_t>(g), KIND_STUB, {0xC3}});
            ++n_ret;
        } else if (e.has("cont")) {
            std::vector<int64_t> cont;
            for (const Json& x : e.get("cont_rva")->items()) cont.push_back(std::stoll(x.as_str().substr(2), nullptr, 16));
            std::vector<std::pair<int64_t, int64_t>> pubs;
            if (const Json* p = e.get("publishes"))
                for (const Json& x : p->items())
                    pubs.emplace_back(std::stoll(x.items()[0].as_str().substr(2), nullptr, 16),
                                      std::stoll(x.items()[1].as_str().substr(2), nullptr, 16));
            const int64_t o0 = e.get("slot_offset")->as_int();
            std::vector<std::pair<int64_t, std::vector<uint8_t>>> p;
            std::string why;
            bool ok = build_stub(code, g, cont, o0, false, pubs, p, why);
            if (!ok) {
                ok = build_stub(code, g, cont, o0, true, pubs, p, why);
                if (ok) e["stub_note"] = Json("placed past the routine's first branch");
            }
            if (ok) {
                std::string hit;
                for (const auto& [rva, data] : p) {
                    for (int64_t b = rva; b < rva + static_cast<int64_t>(data.size()); ++b) {
                        auto it = claimed.find(b);
                        if (it != claimed.end()) {
                            hit = it->second;
                            break;
                        }
                    }
                    if (!hit.empty()) break;
                }
                if (!hit.empty()) {
                    ok = false;
                    why = "its first instructions are also routine " + hit + "'s";
                }
            }
            if (!ok) {
                fail.emplace_back(key, why);
                e["why"] = Json("no room for the replacement: " + why);
                e.erase("cont");
                e.erase("clobbers");
                e.erase("publishes");
                continue;
            }
            std::sort(p.begin(), p.end());
            for (const auto& [rva, data] : p) {
                out.stubs.patches.push_back({static_cast<uint32_t>(rva), KIND_STUB, data});
                for (int64_t b = rva; b < rva + static_cast<int64_t>(data.size()); ++b) claimed[b] = key;
            }
            ++n_stub;
        }
    }
    {
        std::string f = "[";
        for (size_t i = 0; i < fail.size() && i < 4; ++i)
            f += (i ? ", " : "") + std::string("(") + py_repr_str(fail[i].first) + ", " + py_repr_str(fail[i].second) + ")";
        f += "]";
        say("stubs: " + std::to_string(n_ret) + " `ret`, " + std::to_string(n_stub) + " replacements in " +
            std::to_string(static_cast<int64_t>(out.stubs.patches.size()) - n_ret) + " pieces; " +
            std::to_string(fail.size()) + " did not fit " + f);
    }
    Json meta = Json::object();
    meta["image"] = Json(image_name);
    meta["made_by"] = Json("tools/find_routines.py");
    meta["addresses"] = Json("RVA");
    Json ss = Json::object();
    for (const auto& [k, v] : shapes.v) ss[k] = Json(v);
    meta["slot_stores"] = ss;
    meta["index_minus_offset"] = index_rel;
    Json kd = Json::object();
    for (const auto& [k, v] : kinds.v) kd[k] = Json(v);
    meta["kinds"] = kd;
    out.json = Json::object();
    out.json["meta"] = meta;
    out.json["routines"] = tab;
    return out;
}

// a file Python wrote in text mode: every \n is \r\n on Windows
void write_text_crlf(const std::string& path, const std::string& s) {
    std::string o;
    o.reserve(s.size() + s.size() / 16);
    for (char c : s) {
        if (c == '\n') o += '\r';
        o += c;
    }
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) throw std::runtime_error("cannot write " + path);
    f << o;
}

int cmd_tables(int argc, char** argv) {
    std::string exe, work;
    for (int i = 2; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--work" && i + 1 < argc)
            work = argv[++i];
        else if (!a.empty() && a[0] == '-')
            throw std::runtime_error("unknown option " + a);
        else
            exe = a;
    }
    if (exe.empty() || work.empty()) throw std::runtime_error("usage: mwdec tables <dec.exe> --work DIR");
    FImage im;
    im.load(exe);
    const auto t0 = std::chrono::steady_clock::now();
    const ChecksOut c = find_slot_checks(im);
    std::printf("%s\n", c.line.c_str());
    c.plan.save(work + "\\checks_all.plan");
    write_text_crlf(work + "\\checks.json", c.json.dump(1));
    std::printf("checks: %.1f s\n", std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count());
    const RoutinesOut r = find_routines(im, c.checks, basename_of(exe), [](const std::string& s) {
        std::printf("%s\n", s.c_str());
        std::fflush(stdout);
    });
    write_text_crlf(work + "\\routines.json", r.json.dump(1));
    r.stubs.save(work + "\\routine_stubs.plan");
    r.bake.save(work + "\\checks.plan");
    std::printf("tables: %.1f s\n", std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count());
    return 0;
}

}  // namespace flow
