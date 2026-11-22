// find_writers.Stream: instructions in execution order across the
// protection's pieces (joining and disguised jumps followed), over the code
// sections and every read-only section. Shared by the ports of
// find_writers.py, find_checks.py and find_routines.py.
#pragma once

#include <algorithm>
#include <cstdint>
#include <deque>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

#include "flow/code.h"
#include "flow/idiom.h"
#include "flow/pyutil.h"

namespace flow {

struct SIns {
    int64_t pc = 0;
    int size = 0;
    std::string m, op;
};

enum { K_INSN, K_JMP, K_JCC, K_CALL, K_END };

struct SStep {
    int kind = K_END;
    bool has = false;  // ins is set
    SIns ins;
    int64_t s0 = 0, s1 = 0;
};

class Stream {
public:
    explicit Stream(FImage& im) : code_(im, ro_of(im), nullptr) {}
    Code& code() { return code_; }

    static RangeV ro_of(const FImage& im) {
        RangeV ro;
        for (const PSection& s : im.sections)
            if (!s.executable() && !(s.chars & 0x80000000u) && std::min(s.vsize, s.rsize))
                ro.emplace_back(s.rva, static_cast<int64_t>(s.rva) + std::min(s.vsize, s.rsize));
        return ro;
    }

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

    // the next n ordinary instructions on the straight path from pc
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

    // reach(): f(ins) in the generator's order until f returns false
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
    Code code_;
};

// find_writers.rip_target: "[rip +/- 0x..]", first match
inline std::optional<int64_t> rip_tgt(const SIns& i) {
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

}  // namespace flow
