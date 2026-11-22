#include "flow/walker.h"

#include <algorithm>
#include <chrono>
#include <stdexcept>

#include "flow/pyutil.h"

namespace flow {

namespace {
struct WhyTable {
    std::vector<std::string> s;
    std::unordered_map<std::string, int> id;
};
WhyTable& whys() {
    static WhyTable t;
    return t;
}
}  // namespace

int why_id(const std::string& s) {
    WhyTable& t = whys();
    auto it = t.id.find(s);
    if (it != t.id.end()) return it->second;
    const int k = static_cast<int>(t.s.size());
    t.s.push_back(s);
    t.id.emplace(s, k);
    return k;
}
const std::string& why_str(int id) { return whys().s[static_cast<size_t>(id)]; }

// -------------------------------------------------------------- I64Map --

static inline size_t h64(int64_t k) { return static_cast<size_t>(static_cast<uint64_t>(k) * 0x9E3779B97F4A7C15ull >> 20); }

const int64_t* I64Map::find(int64_t k) const {
    if (keys_.empty()) return nullptr;
    const size_t m = keys_.size() - 1;
    size_t i = h64(k) & m;
    while (keys_[i] != EMPTY) {
        if (keys_[i] == k) return &vals_[i];
        i = (i + 1) & m;
    }
    return nullptr;
}

void I64Map::grow() {
    std::vector<int64_t> ok, ov;
    ok.swap(keys_);
    ov.swap(vals_);
    const size_t ns = ok.empty() ? 1024 : ok.size() * 2;
    keys_.assign(ns, EMPTY);
    vals_.assign(ns, 0);
    n_ = 0;
    for (size_t i = 0; i < ok.size(); ++i)
        if (ok[i] != EMPTY) insert(ok[i], ov[i]);
}

bool I64Map::insert(int64_t k, int64_t v) {
    if ((n_ + 1) * 10 > keys_.size() * 7) grow();
    const size_t m = keys_.size() - 1;
    size_t i = h64(k) & m;
    while (keys_[i] != EMPTY) {
        if (keys_[i] == k) return false;
        i = (i + 1) & m;
    }
    keys_[i] = k;
    vals_[i] = v;
    ++n_;
    return true;
}

// -------------------------------------------------------------- Walker --

Walker::Walker(FImage& im_, Code& code_, const Regions& reg, bool bypass_)
    : imp(&im_), code(&code_), bm(reg), bypass(bypass_) {}

void Walker::push(int64_t rva, int64_t from) {
    work.push_back(rva);
    if (keep_src) src.insert(rva, from);
}

void Walker::walk(const std::vector<std::pair<int64_t, int64_t>>& roots) {
    for (const auto& [r, why] : roots) {
        work.push_back(r);
        if (keep_src) src.insert(r, why);
    }
    while (!work.empty()) {
        const int64_t pc = work.back();
        work.pop_back();
        run(pc);
    }
}

std::vector<int64_t> Walker::origin(int64_t rva, int depth) const {
    std::vector<int64_t> out{rva};
    for (int k = 0; k < depth; ++k) {
        const int64_t* s = src.find(out.back());
        if (!s || *s < 0) {
            if (s) out.push_back(*s);
            break;
        }
        out.push_back(*s);
    }
    return out;
}

void Walker::mark(const InsnList& ins, uint8_t bit) {
    for (const auto& [a, n] : ins) {
        bm.set(a, n, bit);
        bm.set(a, 1, ISTART);
        const int64_t i = bm.idx(a);
        touch(i, std::min<int64_t>(i + n, bm.total()));
    }
}

void Walker::run(int64_t pc) {
    FImage& im = *imp;
    const int64_t run0 = pc;
    run0_ = run0;
    have_run0_ = true;
    uint8_t* f = bm.f.data();
    std::vector<H> hist;  // deque(maxlen=24)
    hist.reserve(25);
    auto hpush = [&hist](H h) {
        if (hist.size() == 24) hist.erase(hist.begin());
        hist.push_back(h);
    };
    Lite d;
    while (true) {
        const int64_t i = bm.idx(pc);
        if (i < 0) {
            ++outside;
            return;
        }
        const uint8_t fl = f[i];
        if (fl & START) return;
        if (stop_f && (stop_f->f[static_cast<size_t>(i)] & START)) return;
        if (poison && poison->count(pc)) return;
        if (fl & (CODE | IDIOM | CHAIN)) ++overlaps;
        if (!fresh_lite(im, pc, d)) {
            ++undecodable;
            return;
        }
        const int size = d.size;
        const uint16_t m = d.mid;
        const std::string_view op = d.ops();
        const int64_t nxt = pc + size;
        const bool is_push = (m == M_PUSH && gpr_index(op) >= 0) || m == M_PUSHFQ;
        if (bypass && checks) {
            auto it = checks->find(pc);
            if (it != checks->end() && !it->second.why) {
                const CheckFold& ck = it->second;
                if (keep_found_in) found_in[pc] = run0;
                mark(ck.insns, CHAIN);
                {
                f[i] |= START;
                touch(i, i + 1);
            }
                push(ck.E, run0);
                return;
            }
        }
        if (bypass && is_push && !frozen.count(pc)) {
            ChainP ch;
            if (resolve) {
                const auto t0 = std::chrono::steady_clock::now();
                ch = match_chain(*code, pc);
                t_chain += std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
                ++n_chain;
            }
            RoutineModel* model = code->model;
            if (ch && (!model || model->effect(*ch).kind == Effect::NET)) {
                chains.set(pc, ch);
                mark(ch->insns, CHAIN);
                {
                f[i] |= START;
                touch(i, i + 1);
            }
                push(ch->E, run0);
                return;
            }
        }
        if (!frozen.count(pc) &&
            (is_push || (mf(m, F_IDIOM_FIRST) && ((m == M_LEA && starts(op, "rsp, [rsp - ")) ||
                                                  (m == M_MOV && starts(op, "qword ptr [rsp - ")))))) {
            Construct c;
            if (resolve) {
                const auto t0 = std::chrono::steady_clock::now();
                c = resolve_construct(*code, pc);
                t_construct += std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
                ++n_construct;
            }
            IdiomP idm = c.idm;
            if (idm && !idm->inner.empty() && !atomic) idm = nullptr;  // rewritten is always empty
            if (c.unk) {
                unknowns.emplace(pc, c.unk);
                for (const auto& [a_, n_] : c.unk->insns) frozen.insert(a_);
                idm = nullptr;
            }
            if (idm) {
                idioms.set(pc, idm);
                if (keep_found_in) found_in[pc] = run0;
                mark(idm->insns, IDIOM);
                {
                f[i] |= START;
                touch(i, i + 1);
            }
                if (idm->kind == IK_JMP && idm->inner.empty()) {
                    if (keep_src) src.insert(idm->target, run0);
                    pc = idm->target;
                    continue;
                }
                if (idm->kind == IK_JCC && idm->inner.empty()) {
                    push(idm->target, run0);
                    if (keep_src) src.insert(idm->fall, run0);
                    hpush({pc, 0, true});
                    pc = idm->fall;
                    continue;
                }
                if (idm->kind == IK_JMP || idm->kind == IK_POPJMP) {
                    push(idm->target, run0);
                } else if (idm->kind == IK_JCC) {
                    push(idm->target, run0);
                    push(idm->fall, run0);
                } else {
                    push(idm->target, run0);
                    push(idm->ret, run0);
                    call_targets.insert(idm->target);
                }
                return;
            }
        }
        {
                f[i] |= START;
                touch(i, i + 1);
            }
        {
            const int64_t e = std::min<int64_t>(i + size, bm.total());
            for (int64_t k = i; k < e; ++k) f[k] |= CODE;
            touch(i, e);
        }
        ++insns;
        if (contains(op, "rip")) {
            auto t = rip_target(op, nxt);
            if (t) {
                if (m == M_LEA && code->in_code(*t)) {
                    coderefs.push_back({pc, *t});
                    if (follow_refs) push(*t, run0);
                } else {
                    datarefs.push_back({pc, *t});
                    if (m == M_JMP || m == M_CALL) {
                        ++indirect;
                        if (m == M_JMP) return;
                    }
                }
            }
        } else if (m == M_MOVABS) {
            auto ops = split_cs(op);
            int64_t v;
            if (ops.size() == 2 && starts(ops[1], "0x") && hex_op(ops[1], v)) {
                v = static_cast<int64_t>(static_cast<uint64_t>(v) - im.image_base);
                // Python: int(ops[1], 16) - base, then 0 <= v < size
                const uint64_t raw = static_cast<uint64_t>(v) + im.image_base;
                const bool ok = raw >= im.image_base && v >= 0 && v < im.len;
                if (ok) {
                    if (code->in_code(v)) {
                        coderefs.push_back({pc, v});
                        if (follow_refs) push(v, run0);
                    } else {
                        datarefs.push_back({pc, v});
                    }
                }
            }
        }
        int64_t t;
        if (m == M_JMP) {
            if (starts(op, "0x") && hex_op(op, t)) {
                pc = t;
                continue;
            }
            ++indirect;
            if (gpr_index(op) >= 0 && tables) {
                jump_table(pc, op, hist);
            } else if (op == "qword ptr [rsp - 8]" && hist.size() >= 3 && tables) {
                const size_t n = hist.size();
                const H& h0 = hist[n - 3];
                const H& h1 = hist[n - 2];
                const H& h2 = hist[n - 1];
                Lite d0, d1, d2;
                const bool ok0 = !h0.synth && fresh_lite(im, h0.pc, d0);
                const bool ok1 = !h1.synth && fresh_lite(im, h1.pc, d1);
                const bool ok2 = !h2.synth && fresh_lite(im, h2.pc, d2);
                if (ok1 && ok2 && ok0 && d1.mid == M_LEA && d2.mid == M_LEA && lea_rsp_disp(d1.ops()) == -8 &&
                    lea_rsp_disp(d2.ops()) == 8 && d0.mid == M_MOV && starts(d0.ops(), "qword ptr [rsp - 8], ")) {
                    auto parts = split_cs(d0.ops());
                    const std::string r(parts[1]);
                    const int g = gpr_index(r);
                    if (g >= 0 && g != REG_RSP) {
                        std::vector<H> rest(hist.begin(), hist.end() - 3);
                        jump_table(pc, r, rest);
                    }
                }
            }
            return;
        }
        if (mf(m, F_JCC) || mf(m, F_COND8)) {
            if (starts(op, "0x") && hex_op(op, t)) push(t, run0);
        } else if (m == M_CALL) {
            if (starts(op, "0x") && hex_op(op, t)) {
                push(t, run0);
                call_targets.insert(t);
            } else {
                ++indirect;
            }
        } else if (mf(m, F_STOP) || m == M_INT) {
            return;
        }
        hpush({pc, size, false});
        pc = nxt;
    }
}

void Walker::jump_table(int64_t site, std::string_view reg, const std::vector<H>& h) {
    FImage& im = *imp;
    int64_t table = 0;
    bool have = false;
    int kk = -1;
    Lite d;
    for (int k = static_cast<int>(h.size()) - 1; k >= 0; --k) {
        if (h[static_cast<size_t>(k)].synth) continue;
        if (!fresh_lite(im, h[static_cast<size_t>(k)].pc, d)) continue;
        if (d.mid == M_MOV) {
            int64_t tb;
            if (match_jt(d.ops(), tb) && !have) {
                table = tb;
                have = true;
                kk = k;
                break;
            }
        }
    }
    (void)reg;
    if (!have) return;
    bool have_bound = false;
    int64_t bound = 0;
    for (int k = kk - 1; k > std::max(-1, kk - 16); --k) {
        if (h[static_cast<size_t>(k)].synth) continue;
        if (!fresh_lite(im, h[static_cast<size_t>(k)].pc, d)) continue;
        if (d.mid == M_CMP) {
            auto ops = split_cs(d.ops());
            uint64_t v;
            if (ops.size() == 2 && full_num(ops[1], v)) {
                bound = static_cast<int64_t>(v) + 1;
                have_bound = true;
                break;
            }
        }
    }
    bool have_sec = false;
    int64_t slo = 0, shi = 0;
    for (const auto& [lo, hi] : code->ex)
        if (lo <= site && site < hi) {
            have_sec = true;
            slo = lo;
            shi = hi;
        }
    int64_t n = 0;
    std::vector<int64_t> tg;
    const int64_t cap = have_bound && bound <= 4096 ? bound : 512;
    while (n < cap) {
        if (!(0 <= table + 4 * n + 4 && table + 4 * n + 4 <= im.len)) break;
        const int64_t t = im.u32(table + 4 * n);
        if (!have_bound && !(have_sec && slo <= t && t < shi)) break;
        if (!code->in_code(t)) break;
        tg.push_back(t);
        ++n;
    }
    ++jtables;
    datarefs.push_back({site, table});
    bm.set(table, 4 * n, DREAD);
    {
        const int64_t i = bm.idx(table);
        touch(i, std::min<int64_t>(i + 4 * n, bm.total()));
    }
    for (int64_t t : tg) push(t, have_run0_ ? run0_ : site);
}

}  // namespace flow
