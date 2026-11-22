#include "flow/planner.h"

#include <algorithm>
#include <chrono>
#include <stdexcept>

#include "flow/pyutil.h"

namespace flow {

// ------------------------------------------------------------ PatchMap --

void PatchMap::set(int64_t rva, Patch p) {
    auto it = idx_.find(rva);
    if (it != idx_.end()) {
        v_[it->second].p = std::move(p);
        return;
    }
    idx_.emplace(rva, v_.size());
    v_.push_back({rva, std::move(p), true});
}

bool PatchMap::erase(int64_t rva) {
    auto it = idx_.find(rva);
    if (it == idx_.end()) return false;
    v_[it->second].alive = false;
    v_[it->second].p = Patch{};
    idx_.erase(it);
    return true;
}

const Patch* PatchMap::get(int64_t rva) const {
    auto it = idx_.find(rva);
    return it == idx_.end() ? nullptr : &v_[it->second].p;
}

std::vector<int64_t> PatchMap::keys_in_order() const {
    std::vector<int64_t> k;
    for (const auto& e : v_)
        if (e.alive) k.push_back(e.rva);
    return k;
}

std::vector<int64_t> PatchMap::sorted_keys() const {
    auto k = keys_in_order();
    std::sort(k.begin(), k.end());
    return k;
}

// ------------------------------------------------------------- helpers --

std::vector<uint8_t> rel32(int64_t frm_next, int64_t to) {
    const int64_t d = to - frm_next;
    if (!(-(int64_t(1) << 31) <= d && d < (int64_t(1) << 31))) throw std::runtime_error("rel32 out of range");
    const int32_t v = static_cast<int32_t>(d);
    std::vector<uint8_t> o(4);
    std::memcpy(o.data(), &v, 4);
    return o;
}

struct Chunk {
    int64_t lo, hi;
};
static std::vector<Chunk> chunks_of(const InsnList& insns) {
    std::vector<Chunk> out;
    bool cur = false;
    Chunk c{};
    for (const auto& [a, n] : insns) {
        if (cur && a == c.hi) {
            c.hi = a + n;
        } else {
            if (cur) out.push_back(c);
            c = {a, a + n};
            cur = true;
        }
    }
    if (cur) out.push_back(c);
    return out;
}

static std::vector<uint8_t> cat(std::vector<uint8_t> a, const std::vector<uint8_t>& b) {
    a.insert(a.end(), b.begin(), b.end());
    return a;
}

// ------------------------------------------------------------- Planner --

Planner::Planner(FImage& im_, Code& code_, const RawXrefs& xr_, Walker& w_, const std::vector<int64_t>& roots,
                 const BitMap* keep_, const Regions& reg_)
    : im(im_), code(code_), xr(xr_), w(w_), bm(w_.bm), reg(reg_), keep(keep_), rel(im_.relocations()),
      claimed(reg_) {
    for (int64_t r : roots) rootset.insert(r);
    for (const auto& [k, v] : w.chains.items()) chain_by_S.set(k, v);
}

FlagLiveness& Planner::fl() {
    if (!fl_)
        fl_ = std::make_unique<FlagLiveness>(code, [this](int64_t pc) -> const Chain* {
            const ChainP* c = chain_by_S.get(pc);
            return c ? c->get() : nullptr;
        });
    return *fl_;
}

RegLiveness& Planner::rl() {
    if (!rl_) rl_ = std::make_unique<RegLiveness>(code);
    return *rl_;
}

std::vector<std::tuple<int, int64_t, int64_t>> Planner::entered(int64_t lo, int64_t hi,
                                                                const std::unordered_set<int64_t>& own,
                                                                bool lo_start_ok) {
    std::vector<std::tuple<int, int64_t, int64_t>> why;
    const int64_t first = lo_start_ok ? lo + 1 : lo;
    for (int64_t a = first; a < hi; ++a) {
        if (rootset.count(a)) why.emplace_back(0, a, 0);
        if (bm.get(a) & START) why.emplace_back(1, a, 0);
    }
    const size_t i0 = xr.lower(first), i1 = xr.lower(hi);
    Lite d;
    for (size_t i = i0; i < i1; ++i) {
        const int64_t src = xr.src[i];
        const int k = xr.kind[i];
        const int64_t t = xr.tgt[i];
        if (own.count(src)) continue;
        if (!(bm.get(src) & (START | ISTART))) continue;
        if (!code.insn(src, d) || d.size != KIND_ENC[k].size) continue;
        if (k < 5) {
            int64_t v;
            if (!(starts(d.ops(), "0x") && hex_op(d.ops(), v) && v == t)) continue;
        } else if (d.mid != KIND_ENC[k].mid) {
            continue;
        }
        why.emplace_back(2, src, t);
    }
    return why;
}

int64_t Planner::final(int64_t x) {
    std::unordered_set<int64_t> seen;
    Lite d;
    for (int k = 0; k < 64; ++k) {
        if (!seen.insert(x).second) break;
        const ChainP* ch = chain_by_S.get(x);
        if (ch && (*ch)->bypass == 1) {
            x = (*ch)->E;
            continue;
        }
        const IdiomP* idm = w.idioms.get(x);
        if (idm && (*idm)->kind == IK_JMP && !publishing(**idm)) {
            x = (*idm)->target;
            continue;
        }
        int64_t t;
        if (code.insn(x, d) && d.mid == M_JMP && starts(d.ops(), "0x") && d.size == 5 && hex_op(d.ops(), t)) {
            x = t;
            continue;
        }
        break;
    }
    return x;
}

void Planner::put(int64_t rva, std::vector<uint8_t> data, uint8_t kind, std::string tag, int64_t fill_to) {
    if (fill_to >= 0 && fill_to > rva + static_cast<int64_t>(data.size()))
        data.resize(static_cast<size_t>(fill_to - rva), 0xCC);
    const int64_t n = static_cast<int64_t>(data.size());
    claimed.set(rva, n);
    auto lo = std::lower_bound(rel.begin(), rel.end(), rva - 7);
    auto hi = std::lower_bound(rel.begin(), rel.end(), rva + n);
    for (auto it = lo; it < hi; ++it) drops.insert(*it);
    Patch p;
    p.data = std::move(data);
    p.kind = kind;
    p.tag = std::move(tag);
    patches.set(rva, std::move(p));
}

// -------------------------------------------------------------- chains --

void Planner::plan_chains() {
    auto items = chain_by_S.sorted();
    for (auto& [S, ch] : items) ch->bypass = decide_chain(S, *ch) ? 1 : 0;
    Lite d;
    for (auto& [S, ch] : items) {
        if (ch->bypass != 1) continue;
        ch->final_ = final(ch->E);
        if (ch->S_patch && std::string(ch->S_patch) == "jmp") {
            std::vector<uint8_t> b{0xE9};
            put(S, cat(b, rel32(S + 5, *ch->final_)), KIND_BYPASS, "chain " + hexX(S));
        } else {
            for (const auto& [kind, src] : ch->preds) {
                code.insn(src, d);
                const int n = d.size;
                std::vector<uint8_t> op(im.mem.data() + src, im.mem.data() + src + n - 4);
                put(src, cat(op, rel32(src + n, *ch->final_)), KIND_BYPASS, "chain " + hexX(S) + " pred");
            }
        }
    }
}

bool Planner::decide_chain(int64_t S, Chain& ch) {
    const auto first = chunks_of(ch.insns)[0];
    const int64_t lo = first.lo, hi = first.hi;
    if (lo != S) {
        ch.why = "first chunk does not start at S";
        return false;
    }
    ch.preds = preds_of(S);
    std::unordered_set<int64_t> own;
    for (const auto& [a, n] : ch.insns) own.insert(a);
    if (keep && keep->any_in(S, 5)) {
        keep_overlaps.emplace_back("chain", S);
        ch.why = "S overlaps a --keep-plan range";
        return false;
    }
    if (hi - S >= 5 && entered(S, S + 5, own).empty()) {
        ch.S_patch = "jmp";
        ch.why.reset();
        return true;
    }
    bool bad = ch.preds.empty();
    for (const auto& [kind, src] : ch.preds)
        if (std::string(kind) != "jmp" && std::string(kind) != "jcc") bad = true;
    if (bad) {
        ch.why = "S too short and a predecessor is not a rel32 branch";
        return false;
    }
    ch.S_patch = "preds";
    return true;
}

std::vector<std::pair<const char*, int64_t>> Planner::preds_of(int64_t S) {
    std::vector<std::pair<const char*, int64_t>> out;
    for (const BranchRef& b : confirmed_branches_to(code, xr, S)) {
        if (!(bm.get(b.src) & (START | CODE))) continue;
        if (b.size == 2)
            out.emplace_back("rel8", b.src);
        else if (b.mid == M_CALL)
            out.emplace_back("call", b.src);
        else
            out.emplace_back(b.mid == M_JMP ? "jmp" : "jcc", b.src);
    }
    for (int64_t src : confirmed_refs_to(code, xr, S))
        if (bm.get(src) & (IDIOM | CODE)) out.emplace_back("idiom-or-ref", src);
    Lite d;
    for (int k = 1; k < 16; ++k) {
        const int64_t a = S - k;
        if (bm.get(a) & START) {
            if (code.insn(a, d) && d.size == k && !mf(d.mid, F_STOP) && d.mid != M_JMP) out.emplace_back("fall", a);
        }
    }
    if (rootset.count(S)) out.emplace_back("root", S);
    return out;
}

// -------------------------------------------------------------- idioms --

namespace {
struct Timed {  // adds the time a scope takes to a counter
    double& acc;
    std::chrono::steady_clock::time_point t0 = std::chrono::steady_clock::now();
    explicit Timed(double& a) : acc(a) {}
    ~Timed() { acc += std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count(); }
};
}  // namespace

void Planner::plan_idioms() {
    std::vector<std::pair<int64_t, IdiomP>> order;
    {
        Timed tm(t_sort);
        order = w.idioms.sorted();
    }
    for (const auto& [s, idm] : order) {
        Res r;
        {
            Timed tm(t_calls);
            r = plan_idiom(s, *idm);
        }
        idiom_res.set(s, std::move(r));
    }
}

Res Planner::plan_idiom(int64_t s, const Idiom& idm) {
    auto skip = [](std::string why) {
        Res r;
        r.ok = false;
        r.detail = std::move(why);
        return r;
    };
    if (publishing(idm)) return skip("a routine inside publishes a value");
    const auto ch = chunks_of(idm.insns);
    const int64_t lo = ch[0].lo, hi = ch[0].hi;
    if (lo != s) return skip("first instruction not at chunk start");
    std::unordered_set<int64_t> in_chain;
    for (const ChainP& c : idm.inner)
        for (const auto& [a, n] : c->insns) in_chain.insert(a);
    Lite d;
    {
        Timed tm(t_decode);
        for (const auto& [a, n] : idm.insns) {
            if (in_chain.count(a)) continue;
            if (!code.insn(a, d)) throw std::runtime_error("an idiom instruction does not decode");
            const uint16_t m = d.mid;
            if (!(m == M_PUSH || m == M_POP || m == M_LEA || m == M_MOV || m == M_MOVABS || m == M_XCHG ||
                  m == M_JMP || m == M_RET || mf(m, F_CMOV)))
                return skip("non flag-neutral instruction " + std::string(mn_name(m)));
        }
    }
    std::unordered_set<int64_t> own;
    for (const auto& [a, n] : idm.insns) own.insert(a);
    for (int64_t a : own)
        if (w.frozen.count(a)) return skip("part of a construct whose routine has no known continuation");
    if (keep)
        for (const auto& [a, n] : idm.insns)
            if (keep->any_in(a, n)) {
                keep_overlaps.emplace_back("idiom", s);
                return skip("overlaps a --keep-plan range");
            }
    const int64_t t = idm.kind == IK_CALL ? idm.ret : idm.target;
    if (!idm.inner.empty() && idm.flags_clob) {
        Timed tm(t_live);
        inner_flags[s] = fl().at(t);
        if (inner_flags[s] != V_DEAD)
            return skip(std::string("flags ") + verdict_name(inner_flags[s]) + " after a chain inside the idiom");
    }
    if (!idm.clob.empty()) {
        Timed tm(t_live);
        RegSet cs = 0;
        for (int r : idm.clob) cs |= RegSet(1) << r;
        inner_regs[s] = rl().at(t, cs);
        if (inner_regs[s] != V_DEAD) {
            std::string names;
            for (size_t k = 0; k < idm.clob.size(); ++k) names += (k ? "," : "") + reg_str(idm.clob[k]);
            return skip("registers " + names + " " + verdict_name(inner_regs[s]) + " after the routine");
        }
    }
    if (idm.has_cont() && compute_fold_dead) {
        // fold_dead (report data the Python keeps): same liveness queries
        Timed tm(t_fold_dead);
        for (int r = 0; r < 16; ++r)
            if (r != REG_RSP) (void)rl().at(t, RegSet(1) << r);
        (void)fl().at(t);
    }
    Timed tm_final(t_final);        // the jump targets, then (below) the test for other ways in
    std::vector<BodyEl> body;
    if (idm.kind == IK_POPJMP) {
        body = {{'p', idm.pop}, {'j', final(idm.target)}};
    } else if (idm.kind == IK_JMP) {
        body = {{'j', final(idm.target)}};
    } else if (idm.kind == IK_JCC) {
        const int64_t b1 = final(idm.target);
        const int64_t b2 = final(idm.fall);
        body = {{'k', b1, idm.cc}, {'j', b2}};
    } else {
        const int64_t g = final(idm.target);
        if (code.insn(g, d) && d.mid == M_RET && d.olen == 0)
            body = {{'j', final(idm.ret)}};
        else {
            const int64_t r = final(idm.ret);
            body = {{'c', g}, {'j', r}};
        }
    }
    int64_t need = 0;
    for (const BodyEl& b : body) need += b.kind == 'k' ? 6 : ((b.kind != 'p' || 8 * b.a < 128) ? 5 : 8);
    auto enc = [&body](int64_t at) {
        std::vector<uint8_t> out;
        for (const BodyEl& b : body) {
            const int64_t nx = at + static_cast<int64_t>(out.size());
            if (b.kind == 'p') {
                const int64_t k8 = 8 * b.a;
                if (k8 < 128) {
                    out.insert(out.end(), {0x48, 0x8D, 0x64, 0x24, static_cast<uint8_t>(k8)});
                } else {
                    out.insert(out.end(), {0x48, 0x8D, 0xA4, 0x24});
                    const int32_t v = static_cast<int32_t>(k8);
                    uint8_t q[4];
                    std::memcpy(q, &v, 4);
                    out.insert(out.end(), q, q + 4);
                }
            } else if (b.kind == 'j') {
                out.push_back(0xE9);
                auto r = rel32(nx + 5, b.a);
                out.insert(out.end(), r.begin(), r.end());
            } else if (b.kind == 'c') {
                out.push_back(0xE8);
                auto r = rel32(nx + 5, b.a);
                out.insert(out.end(), r.begin(), r.end());
            } else {
                out.push_back(0x0F);
                out.push_back(static_cast<uint8_t>(0x80 + b.cc));
                auto r = rel32(nx + 6, b.a);
                out.insert(out.end(), r.begin(), r.end());
            }
        }
        return out;
    };
    {
        Timed tm(t_entered);
        if (!entered(lo, hi, own).empty()) return skip("first chunk entered from elsewhere");
    }
    if (!free_(lo, hi)) return skip("bytes already patched");
    const std::string tag = std::string(ikind_name(idm.kind)) + " " + hexX(s);
    if (hi - lo >= need) {
        put(lo, enc(lo), KIND_FLOW, tag, hi);
        Res r;
        r.ok = true;
        r.detail = "inline";
        r.body = body;
        return r;
    }
    if (hi - lo < 5) return skip("first chunk shorter than 5 bytes");
    for (size_t k = 1; k < ch.size(); ++k) {
        const int64_t clo = ch[k].lo, chi = ch[k].hi;
        if (chi - clo >= need && free_(clo, chi) && entered(clo, chi, own, false).empty()) {
            std::vector<uint8_t> b{0xE9};
            put(lo, cat(b, rel32(lo + 5, clo)), KIND_FLOW, tag + " hop", hi);
            put(clo, enc(clo), KIND_FLOW, tag, chi);
            Res r;
            r.ok = true;
            r.detail = "two-hop";
            r.body = body;
            return r;
        }
    }
    return skip("no chunk with " + std::to_string(need) + " free bytes");
}

// -------------------------------------------------------------- checks --

void Planner::plan_checks(const std::unordered_map<int64_t, CheckFold>& checks) {
    std::vector<int64_t> keys;
    for (const auto& [c, ck] : checks) keys.push_back(c);
    std::sort(keys.begin(), keys.end());
    auto skip = [this](int64_t c, std::string why) {
        Res r;
        r.detail = std::move(why);
        check_res.set(c, r);
    };
    for (int64_t c : keys) {
        const CheckFold& ck = checks.at(c);
        if (ck.why && !ck.why->empty()) {
            skip(c, *ck.why);
            continue;
        }
        if (!(bm.get(c) & START)) {
            skip(c, "not reached from game roots");
            continue;
        }
        if (keep && keep->any_in(c, 5)) {
            keep_overlaps.emplace_back("check", c);
            skip(c, "overlaps a --keep-plan range");
            continue;
        }
        const auto first = chunks_of(ck.insns)[0];
        if (first.lo != c || first.hi - c < 5) {
            skip(c, "first chunk shorter than 5 bytes");
            continue;
        }
        std::unordered_set<int64_t> own;
        for (const auto& [a, n] : ck.insns) own.insert(a);
        if (!entered(c, c + 5, own).empty() || !free_(c, c + 5)) {
            skip(c, "first bytes entered from elsewhere");
            continue;
        }
        if (ck.flags_changed) {
            const int v = fl().at(ck.E);
            if (v != V_DEAD) {
                skip(c, std::string("flags changed by the check are ") + verdict_name(v) + " at E");
                continue;
            }
        }
        if (!ck.regs_changed.empty()) {
            RegSet rs = 0;
            std::string names;
            for (size_t k = 0; k < ck.regs_changed.size(); ++k) {
                rs |= RegSet(1) << reg_id(ck.regs_changed[k]);
                names += (k ? "," : "") + ck.regs_changed[k];
            }
            const int v = rl().at(ck.E, rs);
            if (v != V_DEAD) {
                skip(c, "registers " + names + " changed by the check are " + verdict_name(v) + " at E");
                continue;
            }
        }
        const int64_t f = final(ck.E);
        std::vector<uint8_t> b{0xE9};
        put(c, cat(b, rel32(c + 5, f)), KIND_FLOW, "check " + hexX(c));
        Res r;
        r.ok = true;
        r.detail = "jmp";
        r.target = f;
        check_res.set(c, r);
    }
}

// ------------------------------------------------------------ peephole --

bool Planner::shape(int64_t a, Shape& s) {
    Lite d;
    if (!code.insn(a, d)) return false;
    const uint16_t m = d.mid;
    const std::string_view op = d.ops();
    s.size = d.size;
    s.reg = -1;
    if (m == M_LEA) {
        auto dd = lea_rsp_disp(op);
        if (dd == 8) {
            s.kind = 0;
            return true;
        }
        if (dd == -8) {
            s.kind = 1;
            return true;
        }
        return false;
    }
    if (m == M_JMP && rsp_disp(op) == -8) {
        s.kind = 2;
        return true;
    }
    if (m == M_MOV) {
        auto ops = split_cs(op);
        if (ops.size() != 2) return false;
        const int r0 = gpr_index(ops[0]), r1 = gpr_index(ops[1]);
        if (r0 >= 0 && r0 != REG_RSP && starts(ops[1], "qword ptr [rsp")) {
            auto dd = rsp_disp(ops[1]);
            if (dd == 0) {
                s.kind = 3;
                s.reg = r0;
                return true;
            }
            if (dd == -8) {
                s.kind = 4;
                s.reg = r0;
                return true;
            }
        }
        if (r1 >= 0 && r1 != REG_RSP && starts(ops[0], "qword ptr [rsp")) {
            auto dd = rsp_disp(ops[0]);
            if (dd == 0) {
                s.kind = 5;
                s.reg = r1;
                return true;
            }
            if (dd == -8) {
                s.kind = 6;
                s.reg = r1;
                return true;
            }
        }
    }
    return false;
}

std::pair<int64_t, int64_t> Planner::next(int64_t a, int size) {
    const int64_t n = a + size;
    Lite d;
    int64_t t;
    if (code.insn(n, d) && d.mid == M_JMP && starts(d.ops(), "0x") && d.size == 5 && hex_op(d.ops(), t)) return {t, n};
    return {n, -1};
}

bool Planner::other_way_in(int64_t a, int64_t own) {
    if (w.src.contains(a) || rootset.count(a)) return true;
    for (const BranchRef& b : confirmed_branches_to(code, xr, a)) {
        if (b.src == own) continue;
        if (bm.get(b.src) & (START | ISTART)) return true;
    }
    for (int64_t src : confirmed_refs_to(code, xr, a))
        if (bm.get(src) & (START | ISTART)) return true;
    return false;
}

static int rnum(int gpr) {
    // x86 register number (ModRM order) of a GPR64 index
    static const int map[16] = {0, 3, 1, 2, 6, 7, 5, 4, 8, 9, 10, 11, 12, 13, 14, 15};
    return map[gpr];
}

static std::vector<uint8_t> enc1(const std::string& form, int r) {
    if (form == "ret") return {0xC3};
    int k = rnum(r);
    std::vector<uint8_t> o;
    if (k >= 8) o.push_back(0x41);
    k &= 7;
    if (form == "pop") o.push_back(static_cast<uint8_t>(0x58 + k));
    else if (form == "push") o.push_back(static_cast<uint8_t>(0x50 + k));
    else {
        o.push_back(0xFF);
        o.push_back(static_cast<uint8_t>(0xE0 + k));
    }
    return o;
}

static std::vector<uint8_t> nopfill(int64_t n) {
    static const std::vector<uint8_t> nops[10] = {{},
                                                  {0x90},
                                                  {0x66, 0x90},
                                                  {0x0F, 0x1F, 0x00},
                                                  {0x0F, 0x1F, 0x40, 0x00},
                                                  {0x0F, 0x1F, 0x44, 0x00, 0x00},
                                                  {0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00},
                                                  {0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00},
                                                  {0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00},
                                                  {0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00}};
    std::vector<uint8_t> out;
    while (n > 0) {
        const int64_t k = std::min<int64_t>(n, 9);
        out.insert(out.end(), nops[k].begin(), nops[k].end());
        n -= k;
    }
    return out;
}

void Planner::plan_peephole() {
    const uint8_t* mem = im.mem.data();
    const uint8_t* f = bm.f.data();
    std::vector<int64_t> cands;
    for (const auto& sec : reg.secs) {
        const uint8_t* seg = mem + sec.lo;
        const uint8_t* fla = f + sec.off;
        const int64_t n = (sec.hi - sec.lo) - 6;
        for (int64_t i = 0; i < n; ++i) {
            if (!(fla[i] & START) || (fla[i] & (IDIOM | CHAIN))) continue;
            if ((seg[i] & 0xFB) != 0x48) continue;
            const bool lea = seg[i + 1] == 0x8D && seg[i + 2] == 0x64 && seg[i + 3] == 0x24 &&
                             (seg[i + 4] == 0x08 || seg[i + 4] == 0xF8);
            const bool mov = (seg[i + 1] == 0x8B || seg[i + 1] == 0x89) &&
                             ((seg[i + 2] & 0xC7) == 0x04 || (seg[i + 2] & 0xC7) == 0x44) && seg[i + 3] == 0x24;
            if (lea || mov) cands.push_back(sec.lo + i);
        }
    }
    for (int64_t a : cands) {
        if (claimed.get(a) || w.frozen.count(a)) continue;
        Shape s1{}, s2{}, s3{}, s4{};
        if (!shape(a, s1)) continue;
        const auto [a2, j1] = next(a, s1.size);
        if (!shape(a2, s2)) continue;
        std::string form;
        int r = -1;
        std::vector<std::pair<int64_t, int>> seq{{a, s1.size}};
        int64_t a4 = 0;
        if (s1.kind == 0 && s2.kind == 2) {
            form = "ret";
        } else if (s1.kind == 3 && s2.kind == 0) {
            form = "pop";
            r = s1.reg;
        } else if (s1.kind == 0 && s2.kind == 4) {
            form = "pop";
            r = s2.reg;
        } else if (s1.kind == 1 && s2.kind == 5) {
            form = "push";
            r = s2.reg;
        } else if (s1.kind == 6 && s2.kind == 1) {
            form = "push";
            r = s1.reg;
            const auto [a3, j2] = next(a2, s2.size);
            if (shape(a3, s3) && s3.kind == 0) {
                const auto [a4_, j3] = next(a3, s3.size);
                if (shape(a4_, s4) && s4.kind == 2 && j2 < 0 && j3 < 0 && j1 < 0) {
                    if (!other_way_in(a3) && !other_way_in(a4_)) {
                        form = "jmp r";
                        a4 = a4_;
                        seq.emplace_back(a2, s2.size);
                        seq.emplace_back(a3, s3.size);
                        seq.emplace_back(a4_, s4.size);
                    }
                }
            }
        }
        if (form.empty()) continue;
        if (form != "jmp r") seq.emplace_back(a2, s2.size);
        peep_count[form] += 1;
        peep_seen[a] = {form, ""};
        auto skipw = [&](const std::string& why) {
            peep_skip[why] += 1;
            peep_seen[a].second = why;
        };
        bool part = false;
        for (const auto& [x, n] : seq)
            if ((bm.get(x) & (IDIOM | CHAIN)) || claimed.get(x) || w.frozen.count(x)) part = true;
        if (part) {
            skipw("part of an idiom or chain");
            continue;
        }
        if (keep) {
            bool k = false;
            for (const auto& [x, n] : seq)
                if (keep->any_in(x, n)) k = true;
            if (k) {
                skipw("overlaps a --keep-plan range");
                continue;
            }
        }
        if (other_way_in(a2, j1 >= 0 ? j1 : -1)) {
            skipw(std::string("second half ") + (j1 >= 0 ? "(after a joining jmp) " : "") + "entered from elsewhere");
            continue;
        }
        const int64_t span_end = j1 >= 0 ? j1 + 5 : seq.back().first + seq.back().second;
        bool inside = false;
        for (int64_t b = a + 1; b < span_end; ++b)
            if (b != a2 && (rootset.count(b) || w.src.contains(b))) {
                inside = true;
                break;
            }
        if (inside || (j1 >= 0 && other_way_in(j1))) {
            skipw("a root or branch lands inside the pair");
            continue;
        }
        const std::vector<uint8_t> one = enc1(form == "ret" ? "ret" : (form == "jmp r" ? "jmp" : form), r);
        const bool stops = form == "ret" || form == "jmp r";
        if (j1 < 0) {
            int64_t end = seq.back().first + seq.back().second;
            if (form == "jmp r") end = a4 + s4.size;
            std::vector<uint8_t> body = one;
            const int64_t fill = end - a - static_cast<int64_t>(one.size());
            if (stops) {
                if (fill > 0) body.insert(body.end(), static_cast<size_t>(fill), 0xCC);
            } else {
                auto nf = nopfill(fill);
                body.insert(body.end(), nf.begin(), nf.end());
            }
            if (!free_(a, end)) {
                skipw("bytes already patched");
                continue;
            }
            put(a, body, KIND_FLOW, "peep " + form + " " + hexX(a));
            peep_reg[a] = r;
        } else {
            const int64_t end = j1 + 5;
            std::vector<uint8_t> body;
            if (stops) {
                body = one;
                const int64_t fill = end - a - static_cast<int64_t>(one.size());
                if (fill > 0) body.insert(body.end(), static_cast<size_t>(fill), 0xCC);
            } else {
                const int64_t nxt = a2 + s2.size;
                body = one;
                body.push_back(0xE9);
                auto rr = rel32(a + static_cast<int64_t>(one.size()) + 5, nxt);
                body.insert(body.end(), rr.begin(), rr.end());
                if (static_cast<int64_t>(body.size()) > end - a) {
                    skipw("no room after a joining jmp");
                    continue;
                }
                const int64_t fill = end - a - static_cast<int64_t>(body.size());
                if (fill > 0) body.insert(body.end(), static_cast<size_t>(fill), 0xCC);
            }
            if (!free_(a, end)) {
                skipw("bytes already patched");
                continue;
            }
            put(a, body, KIND_FLOW, "peep " + form + " " + hexX(a));
            peep_reg[a] = r;
            peep_done["joined by jmp"] += 0;
        }
        peep_done[form] += 1;
        peep_seen[a].second = "ok";
        if (peep_sites[form].size() < 200) peep_sites[form].push_back(a);
    }
}

}  // namespace flow
