// mwdec routines: the C++ port of tools/find_routines.py (the routine table
// read from the routines' own exit code, and the 53-byte stubs).
#include <algorithm>
#include <cstdio>
#include <deque>
#include <fstream>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "flow/pipeline.h"
#include "flow/pyutil.h"

namespace flow {

namespace {

struct Ins {
    int64_t pc;
    int size;
    uint16_t m;
    std::string op;
};

// find_writers.rip_target: "[rip +/- 0x..]" only
std::optional<int64_t> fw_rip_target(const Ins& i) {
    const std::string_view op = i.op;
    size_t p = 0;
    while (true) {
        const size_t k = op.find("[rip ", p);
        if (k == std::string_view::npos) return std::nullopt;
        size_t q = k + 5;
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

struct Step {
    int kind;  // 0 insn, 1 jmp, 2 jcc, 3 call, 4 end
    Ins ins;
    int64_t s0 = 0, s1 = 0;
};

Step stream_step(Code& code, int64_t pc) {
    Step r;
    r.kind = 4;
    if (!code.in_code(pc)) return r;
    std::optional<Idiom> idm;
    try {
        idm = resolve_idiom(code, pc);
    } catch (...) {
        idm.reset();
    }
    if (idm) {
        if (idm->kind == IK_JMP) return {1, {}, idm->target, 0};
        if (idm->kind == IK_JCC) return {2, {}, idm->target, idm->fall};
        if (idm->kind == IK_CALL) return {3, {}, idm->ret, 0};
    }
    Lite d;
    if (!code.insn(pc, d)) return r;
    Ins i{pc, d.size, d.mid, std::string(d.ops())};
    const int64_t nxt = pc + d.size;
    const std::string_view mn = d.mn();
    int64_t t;
    if (d.mid == M_JMP) {
        if (starts(i.op, "0x") && hex_op(i.op, t)) return {1, {}, t, 0};
        return {4, i, 0, 0};
    }
    if (d.mid == M_RET || mn == "retf" || d.mid == M_INT3 || d.mid == M_UD2 || mn == "hlt") return {4, i, 0, 0};
    if (d.mid == M_CALL) return {3, i, nxt, 0};
    if (!mn.empty() && mn[0] == 'j' && starts(i.op, "0x") && hex_op(i.op, t)) return {2, i, t, nxt};
    return {0, i, nxt, 0};
}

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

struct Rt {
    std::string form;
    std::map<int64_t, std::set<int64_t>> got;
    std::vector<int64_t> sites;
    int64_t steps = 0;
    std::vector<int64_t> chains, returns;
    std::set<int64_t> push;
};

struct StubIns {
    bool lea;
    std::vector<uint8_t> raw;
    int64_t target;
    int n;
};

std::vector<StubIns> stub_insns(const std::vector<int64_t>& cont, int64_t o0) {
    const int64_t idx = (o0 - 0x18) / 8;
    if ((o0 - 0x18) % 8 || idx < 0 || idx >= 0x80) throw std::runtime_error("stub_insns: bad slot offset");
    std::vector<StubIns> out;
    out.push_back({false, {0x48, 0x8D, 0x54, 0x24, 0x08}, 0, 5});
    out.push_back({false, {0x48, 0x8B, 0x42, 0x08}, 0, 4});
    out.push_back({false, {0x48, 0xC1, 0xE8, 0x03}, 0, 4});
    out.push_back({false, {0x48, 0x83, 0xC0, static_cast<uint8_t>(idx)}, 0, 4});
    for (int k : {2, 1, 0}) {
        out.push_back({true, {}, cont[static_cast<size_t>(k)], 7});
        if (k == 0)
            out.push_back({false, {0x48, 0x89, 0x0C, 0xC2}, 0, 4});
        else
            out.push_back({false, {0x48, 0x89, 0x4C, 0xC2, static_cast<uint8_t>(8 * k)}, 0, 5});
    }
    out.push_back({false, {0xC3}, 0, 1});
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
            const bool ok = code.in_code(x) && code.insn(x, d);
            if (!ok) {
                if (x > start) runs.emplace_back(start, x);
                return runs;
            }
            x += d.size;
            const std::string_view m = d.mn();
            int64_t t;
            if (d.mid == M_JMP && starts(d.ops(), "0x") && hex_op(d.ops(), t)) {
                nxt = t;
                have_nxt = true;
                break;
            }
            const bool j = !m.empty() && m[0] == 'j';
            if (through && (d.mid == M_CALL || (j && d.mid != M_JMP))) continue;
            if (d.mid == M_RET || d.mid == M_JMP || d.mid == M_INT3 || d.mid == M_UD2 || d.mid == M_CALL || j) break;
        }
        runs.emplace_back(start, x);
        if (!have_nxt) break;
        x = nxt;
    }
    return runs;
}

bool build_stub(Code& code, int64_t g, const std::vector<int64_t>& cont, int64_t o0, bool through,
                std::vector<std::pair<int64_t, std::vector<uint8_t>>>& patches, std::string& why) {
    const auto ins = stub_insns(cont, o0);
    const auto runs = owned_runs(code, g, through);
    patches.clear();
    size_t k = 0;
    auto put32 = [](std::vector<uint8_t>& b, int64_t v) {
        const int32_t x = static_cast<int32_t>(v);
        uint8_t q[4];
        std::memcpy(q, &x, 4);
        b.insert(b.end(), q, q + 4);
    };
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
            if (!ins[q].lea) {
                buf.insert(buf.end(), ins[q].raw.begin(), ins[q].raw.end());
            } else {
                const int64_t at = lo + static_cast<int64_t>(buf.size());
                buf.insert(buf.end(), {0x48, 0x8D, 0x0D});
                put32(buf, ins[q].target - (at + 7));
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

}  // namespace

int cmd_routines(int argc, char** argv) {
    std::string exe, out, stubs_out;
    int64_t limit = 400000;
    for (int i = 2; i < argc; ++i) {
        const std::string a = argv[i];
        auto val = [&]() -> std::string {
            if (i + 1 >= argc) throw std::runtime_error("missing value for " + a);
            return argv[++i];
        };
        if (a == "-o" || a == "--out") out = val();
        else if (a == "--stubs-out") stubs_out = val();
        else if (a == "--limit") limit = std::stoll(val());
        else if (!a.empty() && a[0] == '-') throw std::runtime_error("unknown option " + a);
        else exe = a;
    }
    if (exe.empty()) throw std::runtime_error("usage: mwdec routines <decrypted.exe> -o routines.json --stubs-out S.plan");
    FImage im;
    im.load(exe);
    RangeV ro;
    for (const PSection& s : im.sections)
        if (!s.executable() && !(s.chars & 0x80000000u) && std::min(s.vsize, s.rsize))
            ro.emplace_back(s.rva, static_cast<int64_t>(s.rva) + std::min(s.vsize, s.rsize));
    Code code(im, ro, nullptr);
    const int64_t base = static_cast<int64_t>(im.image_base);
    const int64_t size = im.size_of_image;
    RawXrefs xr(im, code.extra);
    OrderedMap<ChainP> census;
    std::vector<int64_t> cfail;
    census_chains(im, code, xr, census, cfail);
    std::map<int64_t, std::vector<ChainP>> by;
    for (const auto& [site, ch] : census.items()) by[ch->G].push_back(ch);
    auto form_of = [](const std::vector<ChainP>& v) {
        std::set<std::string> f;
        for (const ChainP& c : v) f.insert(std::string(c->call_form) == "call" ? "call" : "pushret");
        return f.size() == 1 ? *f.begin() : std::string("mixed");
    };
    std::printf("chains: %zu, at %zu long-form sites without one; routines: %zu\n", census.size(), cfail.size(),
                by.size());

    // walk
    Counter shapes;
    std::map<int64_t, Rt> routines;
    auto slot_write = [&](const std::vector<Ins>& w, int64_t& index, int64_t& addr, std::string& shape) {
        const Ins& last = w.back();
        if (last.m != M_MOV) return false;
        std::string b, ir, vr;
        if (!match_store2(last.op, b, ir, vr)) return false;
        std::optional<int64_t> q, i;
        bool hq = false, hi = false;
        std::vector<std::string> sh;
        const size_t n = w.size();
        const size_t from = n >= 5 ? n - 5 : 0;
        for (size_t k = n - 1; k-- > from;) {
            const Ins& x = w[k];
            if (!hq && x.m == M_MOV && starts(x.op, vr + ", qword ptr [rip")) {
                q = fw_rip_target(x);
                hq = q.has_value();
                sh.push_back("value");
            } else if (!hi && (x.m == M_MOV || x.m == M_ADD) && starts(x.op, ir + ", qword ptr [rip")) {
                i = fw_rip_target(x);
                hi = i.has_value();
                sh.push_back(std::string("index ") + std::string(mn_name(x.m)));
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
            std::vector<Ins> window;
            while (!seen.count(pc) && n < limit) {
                seen.insert(pc);
                ++n;
                Step s = stream_step(code, pc);
                if (s.kind == 0) {
                    window.push_back(s.ins);
                    if (window.size() > 6) window.erase(window.begin());
                    int64_t ix, ad;
                    std::string sh;
                    if (slot_write(window, ix, ad, sh)) {
                        rt.got[ix].insert(ad);
                        rt.sites.push_back(s.ins.pc);
                        shapes[sh] += 1;
                    }
                    pc = s.s0;
                } else if (s.kind == 1 || s.kind == 3) {
                    if (s.kind == 3) window.clear();
                    pc = s.s0;
                } else if (s.kind == 2) {
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
    std::printf("walked %zu routines, %lld instructions\n", routines.size(), static_cast<long long>(steps));

    // table
    Json tab = Json::object();
    Counter kinds;
    std::vector<int64_t> order;
    std::vector<std::pair<int64_t, int64_t>> rel_order;  // (key, count) insertion order
    for (const auto& [g, r] : routines) {
        const std::string key = "0x" + hexx(g);
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
        bool one = true;
        for (const auto& [ix, v] : r.got)
            if (v.size() != 1) one = false;
        std::vector<int64_t> idxs;
        for (const auto& [ix, v] : r.got) idxs.push_back(ix);
        if (idxs.size() == 3 && idxs[1] == idxs[0] + 1 && idxs[2] == idxs[0] + 2 && one && r.form == "pushret") {
            std::vector<int64_t> t;
            for (int64_t ix : idxs) t.push_back(*r.got.at(ix).begin());
            Json cr = Json::array();
            for (int64_t x : t) cr.push(Json("0x" + hexx(x)));
            e["cont_rva"] = cr;
            e["index_constant"] = Json(idxs[0]);
            if (r.push.size() == 1) {
                const int64_t o0 = 0x118 + 8 * *r.push.begin();
                e["slot_offset"] = Json(o0);
                Json c = Json::array();
                for (int k = 0; k < 3; ++k) {
                    Json p = Json::array();
                    p.push(Json(o0 + 8 * k));
                    p.push(Json("0x" + hexx(base + t[static_cast<size_t>(k)])));
                    c.push(p);
                }
                e["cont"] = c;
                Json cl = Json::array();
                for (const char* s : {"rax", "rcx", "rdx", "r8", "r9", "r10", "r11"}) cl.push(Json(s));
                e["clobbers"] = cl;
                kinds["three slots"] += 1;
            } else {
                std::string l = "[";
                bool f = true;
                for (int64_t p : r.push) {
                    l += (f ? "" : ", ") + std::to_string(p);
                    f = false;
                }
                e["why"] = Json("its chains save different numbers of registers: " + l + "]");
                kinds["three slots, chains disagree"] += 1;
            }
        } else if (idxs.empty()) {
            kinds["no slot write reached (" + r.form + ")"] += 1;
        } else {
            Json am = Json::object();
            for (const auto& [ix, v] : r.got) {
                Json l = Json::array();
                for (int64_t x : v) l.push(Json("0x" + hexx(x)));
                am[std::to_string(ix)] = l;
            }
            e["ambiguous"] = am;
            kinds["ambiguous (" + r.form + ")"] += 1;
        }
        tab[key] = e;
        order.push_back(g);
    }
    // index constant against the chain's push count
    std::vector<std::pair<int64_t, int64_t>> rel;
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
    if (rel.size() > 1) {
        auto v = rel;
        std::stable_sort(v.begin(), v.end(), [](const auto& a, const auto& b) { return a.second > b.second; });
        const int64_t common = v[0].first;
        for (size_t k = 0; k < tab.keys().size(); ++k) {
            Json& e = tab[tab.keys()[k]];
            if (!e.has("slot_offset")) continue;
            if (e.get("index_constant")->as_int() - e.get("slot_offset")->as_int() / 8 != common) {
                const int64_t ic = e.get("index_constant")->as_int();
                const int64_t so = e.get("slot_offset")->as_int();
                e["why"] = Json("index constant " + std::to_string(ic) + " does not fit the chain's " +
                                std::to_string((so - 0x118) / 8) + " saved registers");
                e.erase("cont");
                e.erase("clobbers");
                kinds["three slots"] -= 1;
                kinds["index and chain disagree"] += 1;
            }
        }
    }

    // stubs
    PlanF plan;
    int64_t n_ret = 0, n_stub = 0;
    std::unordered_map<int64_t, std::string> claimed;
    std::vector<std::pair<std::string, std::string>> fail;
    for (size_t k = 0; k < order.size(); ++k) {  // order is ascending G already
        const std::string key = tab.keys()[k];
        Json& e = tab[key];
        const int64_t g = order[k];
        if (e.get("form")->as_str() == "call" && !e.has("ambiguous")) {
            plan.patches.push_back({static_cast<uint32_t>(g), KIND_STUB, {0xC3}});
            ++n_ret;
        } else if (e.has("cont")) {
            std::vector<int64_t> cont;
            for (const Json& x : e.get("cont_rva")->items()) cont.push_back(std::stoll(x.as_str().substr(2), nullptr, 16));
            const int64_t o0 = e.get("slot_offset")->as_int();
            std::vector<std::pair<int64_t, std::vector<uint8_t>>> p;
            std::string why;
            bool ok = build_stub(code, g, cont, o0, false, p, why);
            if (!ok) {
                ok = build_stub(code, g, cont, o0, true, p, why);
                if (ok) e["stub_note"] = Json("placed past the routine's first branch");
            }
            if (ok) {
                std::string hit;
                for (const auto& [rva, data] : p) {
                    for (int64_t b = rva; b < rva + static_cast<int64_t>(data.size()); ++b)
                        if (claimed.count(b)) {
                            hit = claimed[b];
                            break;
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
                continue;
            }
            std::sort(p.begin(), p.end());
            for (const auto& [rva, data] : p) {
                plan.patches.push_back({static_cast<uint32_t>(rva), KIND_STUB, data});
                for (int64_t b = rva; b < rva + static_cast<int64_t>(data.size()); ++b) claimed[b] = key;
            }
            ++n_stub;
        }
    }
    std::printf("stubs: %lld `ret`, %lld replacements in %lld pieces; %zu did not fit\n", static_cast<long long>(n_ret),
                static_cast<long long>(n_stub), static_cast<long long>(plan.patches.size()) - n_ret, fail.size());
    if (!out.empty()) {
        Json top = Json::object();
        Json meta = Json::object();
        meta["image"] = Json(basename_of(exe));
        meta["made_by"] = Json("tools/find_routines.py");
        meta["addresses"] = Json("RVA");
        Json ss = Json::object();
        for (const auto& [k, v] : shapes.v) ss[k] = Json(v);
        meta["slot_stores"] = ss;
        Json ir = Json::object();
        for (const auto& [k, v] : rel) ir[std::to_string(k)] = Json(v);
        meta["index_minus_offset"] = ir;
        Json kd = Json::object();
        for (const auto& [k, v] : kinds.v) kd[k] = Json(v);
        meta["kinds"] = kd;
        top["meta"] = meta;
        top["routines"] = tab;
        std::ofstream f(out, std::ios::binary | std::ios::trunc);
        f << top.dump(1);
    }
    if (!stubs_out.empty()) plan.save(stubs_out);
    return 0;
}

}  // namespace flow
