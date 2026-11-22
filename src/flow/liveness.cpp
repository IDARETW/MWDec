#include "flow/liveness.h"

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "flow/pyutil.h"

namespace flow {

const char* verdict_name(int v) {
    static const char* const n[] = {"dead", "live", "unknown"};
    return n[v];
}

namespace {

struct R64Table {
    std::vector<int> of, full;
    R64Table() {
        std::unordered_map<std::string, std::string> m;
        for (int i = 0; i < 16; ++i) m[GPR64[i]] = GPR64[i];
        const char* const pairs[][2] = {{"eax", "rax"}, {"ax", "rax"}, {"al", "rax"}, {"ah", "rax"},
                                        {"ebx", "rbx"}, {"bx", "rbx"}, {"bl", "rbx"}, {"bh", "rbx"},
                                        {"ecx", "rcx"}, {"cx", "rcx"}, {"cl", "rcx"}, {"ch", "rcx"},
                                        {"edx", "rdx"}, {"dx", "rdx"}, {"dl", "rdx"}, {"dh", "rdx"},
                                        {"esi", "rsi"}, {"si", "rsi"}, {"sil", "rsi"}, {"edi", "rdi"},
                                        {"di", "rdi"},  {"dil", "rdi"}, {"ebp", "rbp"}, {"bp", "rbp"},
                                        {"bpl", "rbp"}};
        for (const auto& p : pairs) m[p[0]] = p[1];
        for (int k = 8; k < 16; ++k)
            for (const char* s : {"d", "w", "b"}) m["r" + std::to_string(k) + s] = "r" + std::to_string(k);
        Decoder& d = full_dec();
        of.assign(X86_REG_ENDING + 1, -1);
        full.assign(X86_REG_ENDING + 1, -1);
        for (unsigned r = 0; r <= X86_REG_ENDING; ++r) {
            const char* nm = d.reg_name(r);
            if (!nm) continue;
            const std::string n = nm;
            auto it = m.find(n);
            if (it == m.end()) continue;
            const int p = gpr_index(it->second);
            of[r] = p;
            if (n == it->second || (!n.empty() && n[0] == 'e') || (!n.empty() && n.back() == 'd')) full[r] = p;
        }
    }
};

R64Table& r64() {
    static R64Table t;
    return t;
}

struct PairHash {
    size_t operator()(const std::pair<int64_t, uint64_t>& p) const {
        return static_cast<size_t>(static_cast<uint64_t>(p.first) * 0x9E3779B97F4A7C15ull ^ (p.second * 0xC2B2AE3D27D4EB4Full));
    }
};

constexpr RegSet VOL = (RegSet(1) << 0) | (RegSet(1) << 2) | (RegSet(1) << 3) | (RegSet(1) << 8) |
                       (RegSet(1) << 9) | (RegSet(1) << 10) | (RegSet(1) << 11);  // rax rcx rdx r8-r11

}  // namespace

int r64_of(unsigned r) { return r < r64().of.size() ? r64().of[r] : -1; }
int r64_full_write(unsigned r) { return r < r64().full.size() ? r64().full[r] : -1; }

int RegLiveness::through_call(bool has_target, int64_t target, RegSet& pend, int depth, int cdepth) {
    const RegSet vp = pend & VOL;
    if (vp) {
        if (!has_target || cdepth >= 3) return V_LIVE;
        const int r = at(target, vp, depth, true, cdepth + 1);
        if (r != V_DEAD) return r;
    }
    pend &= ~VOL;
    return -1;
}

int RegLiveness::at(int64_t a, RegSet regs, int depth, bool callee, int cdepth) {
    if (!regs) return V_DEAD;
    struct W {
        int64_t pc;
        RegSet pend;
        int n;
    };
    std::vector<W> work{{a, regs, 0}};
    std::unordered_set<std::pair<int64_t, uint64_t>, PairHash> seen;
    Lite d;
    const FImage& im = code_.image();
    while (!work.empty()) {
        W w = work.back();
        work.pop_back();
        int64_t pc = w.pc;
        RegSet pend = w.pend;
        int n = w.n;
        while (true) {
            if (!seen.insert({pc, pend}).second) break;
            if (n > depth) return V_UNKNOWN;
            n += 1;
            if (!code_.insn(pc, d)) return V_UNKNOWN;
            if (mf(d.mid, F_IDIOM_FIRST) || d.mid == M_PUSHFQ) {
                Construct c = resolve_construct(code_, pc);
                if (c.unk) return V_UNKNOWN;
                if (c.idm) {
                    const Idiom& idm = *c.idm;
                    RegSet cl = 0;
                    for (int r : idm.clob) cl |= RegSet(1) << r;
                    if (!idm.clob.empty() && (pend & cl)) pend &= ~cl;
                    if (idm.kind == IK_JMP || idm.kind == IK_POPJMP) {
                        pc = idm.target;
                        continue;
                    }
                    if (idm.kind == IK_JCC) {
                        work.push_back({idm.target, pend, n});
                        pc = idm.fall;
                        continue;
                    }
                    const int v = through_call(true, idm.target, pend, depth, cdepth);
                    if (v >= 0) return v;
                    if (!pend) break;
                    pc = idm.ret;
                    continue;
                }
            }
            const cs_insn* i = fresh_full(im, pc);
            if (!i) return V_UNKNOWN;
            Decoder& dec = full_dec();
            const uint16_t m = dec.mid_of(i);
            const int64_t size = i->size;
            const std::string_view op = i->op_str;
            if (m == M_NOP) {
                pc += size;
                continue;
            }
            if (m == M_CALL) {
                int64_t t = 0;
                const bool ht = starts(op, "0x") && hex_op(op, t);
                const int v = through_call(ht, t, pend, depth, cdepth);
                if (v >= 0) return v;
                if (!pend) break;
                pc += size;
                continue;
            }
            if (m == M_RET) {
                if ((pend & 1) && !callee) return V_LIVE;
                break;
            }
            cs_regs rr, ww;
            uint8_t nr = 0, nw = 0;
            if (cs().regs_access(dec.handle(), i, rr, &nr, ww, &nw) != CS_ERR_OK) return V_UNKNOWN;
            RegSet rd = 0;
            for (uint8_t k = 0; k < nr; ++k) {
                const int p = r64_of(rr[k]);
                if (p >= 0) rd |= RegSet(1) << p;
            }
            if (pend & rd) {
                bool same = false;
                if ((m == M_XOR || m == M_SUB) && i->detail->x86.op_count == 2) {
                    auto ops = split_cs(op);
                    // Python indexes [0] and [1] of the split; a single part would raise
                    if (ops.size() >= 2) same = ops[0] == ops[1];
                }
                if (!same) return V_LIVE;
            }
            RegSet full = 0;
            for (uint8_t k = 0; k < nw; ++k) {
                const int p = r64_full_write(ww[k]);
                if (p >= 0) full |= RegSet(1) << p;
            }
            pend &= ~full;
            if (!pend) break;
            if (mf(m, F_STOP)) break;
            int64_t t;
            if (m == M_JMP) {
                if (starts(op, "0x") && hex_op(op, t)) {
                    pc = t;
                    continue;
                }
                return V_UNKNOWN;
            }
            if ((mf(m, F_JCC) || mf(m, F_COND8)) && starts(op, "0x") && hex_op(op, t)) work.push_back({t, pend, n});
            pc += size;
        }
    }
    return V_DEAD;
}

int FlagLiveness::at(int64_t a, int depth) {
    struct S {
        uint64_t test, mod;
    };
    static const S status[6] = {
        {X86_EFLAGS_TEST_CF, X86_EFLAGS_MODIFY_CF | X86_EFLAGS_RESET_CF | X86_EFLAGS_SET_CF | X86_EFLAGS_UNDEFINED_CF},
        {X86_EFLAGS_TEST_PF, X86_EFLAGS_MODIFY_PF | X86_EFLAGS_RESET_PF | X86_EFLAGS_SET_PF | X86_EFLAGS_UNDEFINED_PF},
        {X86_EFLAGS_TEST_AF, X86_EFLAGS_MODIFY_AF | X86_EFLAGS_RESET_AF | X86_EFLAGS_SET_AF | X86_EFLAGS_UNDEFINED_AF},
        {X86_EFLAGS_TEST_ZF, X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_RESET_ZF | X86_EFLAGS_SET_ZF | X86_EFLAGS_UNDEFINED_ZF},
        {X86_EFLAGS_TEST_SF, X86_EFLAGS_MODIFY_SF | X86_EFLAGS_RESET_SF | X86_EFLAGS_SET_SF | X86_EFLAGS_UNDEFINED_SF},
        {X86_EFLAGS_TEST_OF, X86_EFLAGS_MODIFY_OF | X86_EFLAGS_RESET_OF | X86_EFLAGS_SET_OF | X86_EFLAGS_UNDEFINED_OF}};
    struct W {
        int64_t pc;
        uint64_t pend;
        int n;
    };
    std::vector<W> work{{a, 0x3F, 0}};
    std::unordered_set<std::pair<int64_t, uint64_t>, PairHash> seen;
    Lite d;
    while (!work.empty()) {
        W w = work.back();
        work.pop_back();
        int64_t pc = w.pc;
        uint64_t pend = w.pend;
        int n = w.n;
        while (true) {
            if (!seen.insert({pc, pend}).second) break;
            if (n > depth) return V_UNKNOWN;
            n += 1;
            const Chain* ch = chains_ ? chains_(pc) : nullptr;
            if (ch && ch->E != pc) {
                if (ch->saves_flags()) {
                    pc = ch->E;
                    continue;
                }
                break;
            }
            Construct c;
            if (code_.insn(pc, d) && code_.insn(pc, d) && mf(d.mid, F_IDIOM_FIRST)) c = resolve_construct(code_, pc);
            if (c.unk) return V_UNKNOWN;
            if (c.idm) {
                const Idiom& idm = *c.idm;
                if (idm.kind == IK_JCC) return V_LIVE;
                if (idm.flags_clob) break;
                if (idm.kind == IK_JMP || idm.kind == IK_POPJMP) {
                    pc = idm.target;
                    continue;
                }
                break;
            }
            const cs_insn* i = fresh_full(code_.image(), pc);
            if (!i) return V_UNKNOWN;
            Decoder& dec = full_dec();
            const uint16_t m = dec.mid_of(i);
            const uint64_t ef = i->detail->x86.eflags;
            for (int k = 0; k < 6; ++k)
                if ((pend >> k & 1) && (ef & status[k].test)) return V_LIVE;
            if (m == M_PUSHFQ || m == M_PUSHF || m == M_LAHF) return V_LIVE;
            uint64_t wr = 0;
            for (int k = 0; k < 6; ++k)
                if (ef & status[k].mod) wr |= uint64_t(1) << k;
            pend &= ~wr;
            if (m == M_POPFQ || m == M_POPF || m == M_SAHF) pend = 0;
            if (!pend) break;
            if (m == M_RET || m == M_CALL || mf(m, F_STOP)) break;
            const std::string_view op = i->op_str;
            int64_t t;
            if (m == M_JMP) {
                if (starts(op, "0x") && hex_op(op, t)) {
                    pc = t;
                    continue;
                }
                return V_UNKNOWN;
            }
            if ((mf(m, F_JCC) || mf(m, F_COND8)) && starts(op, "0x") && hex_op(op, t)) work.push_back({t, pend, n});
            pc += i->size;
        }
    }
    return V_DEAD;
}

}  // namespace flow
