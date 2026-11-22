// tools/find_junk.py in C++: the finder, the references into constructs and
// the plan follow the Python line for line (the reasons are written there).
// The emulator proof draws its own random samples, so its counts are not the
// Python's; what it proves is the same.
#include "flow/junk.h"

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <map>
#include <random>
#include <regex>
#include <set>
#include <stdexcept>
#include <unordered_map>

#include "flow/code.h"
#include "flow/pyutil.h"
#include "flow/tables.h"

namespace flow {

namespace {

struct JOp {
    int type = 0;
    unsigned reg = 0;
    std::string rname;
};

struct JI {
    bool ok = false;
    unsigned id = 0;
    int size = 0;
    std::string mn, op;
    std::vector<JOp> ops;
    uint64_t eflags = 0;
};

JI one(const FImage& im, int64_t rva, int64_t n = 15) {
    JI r;
    const cs_insn* i = fresh_full(im, rva, n);
    if (!i) return r;
    r.ok = true;
    r.id = i->id;
    r.size = i->size;
    r.mn = i->mnemonic;
    r.op = i->op_str;
    const cs_x86& x = i->detail->x86;
    r.eflags = x.eflags;
    Decoder& d = full_dec();
    for (int k = 0; k < x.op_count; ++k) {
        JOp o;
        o.type = x.operands[k].type;
        if (o.type == X86_OP_REG) {
            o.reg = x.operands[k].reg;
            const char* nm = d.reg_name(o.reg);
            o.rname = nm ? nm : "";
        }
        r.ops.push_back(o);
    }
    return r;
}

// the 64-bit register a register name is part of ("" for none)
std::string family(const std::string& n) {
    static const std::regex a(R"(r(\d+)[dwb]?)"), b(R"([re]?([abcd])x|([abcd])[lh])"), c(R"([re]?(si|di|bp|sp)l?)");
    std::smatch m;
    if (std::regex_match(n, m, a)) return "r" + m[1].str();
    if (std::regex_match(n, m, b)) return "r" + (m[1].matched ? m[1].str() : m[2].str()) + "x";
    if (std::regex_match(n, m, c)) return "r" + m[1].str();
    return "";
}

bool is_arith(unsigned id) {
    switch (id) {
        case X86_INS_MOV: case X86_INS_MOVABS: case X86_INS_ADD: case X86_INS_SUB: case X86_INS_XOR: case X86_INS_OR:
        case X86_INS_AND: case X86_INS_ADC: case X86_INS_SBB: case X86_INS_ROL: case X86_INS_ROR: case X86_INS_SHL:
        case X86_INS_SHR: case X86_INS_SAR: case X86_INS_NOT: case X86_INS_NEG: case X86_INS_INC: case X86_INS_DEC:
        case X86_INS_BSWAP: case X86_INS_IMUL:
            return true;
        default:
            return false;
    }
}
bool no_flags(unsigned id) {
    return id == X86_INS_MOV || id == X86_INS_MOVABS || id == X86_INS_NOT || id == X86_INS_BSWAP;
}

bool scratch(const JI& ins, const std::string& reg) {
    if (!is_arith(ins.id) || ins.ops.empty() || ins.ops[0].type != X86_OP_REG) return false;
    for (const JOp& o : ins.ops) {
        if (o.type == X86_OP_REG) {
            if (family(o.rname) != reg) return false;
        } else if (o.type != X86_OP_IMM) {
            return false;
        }
    }
    return true;
}

// An instruction that changes nothing at all (no register, no flag, no
// memory): a nop of any length; xchg or mov of a register with itself, at 64
// or 16 bits (at 32 bits either clears the register's upper half); lea of a
// 64-bit register from itself. Builds from 1.69 put one between the pops.
bool filler(const JI& i, const FImage& im, int64_t rva) {
    if (i.id == X86_INS_NOP) return true;
    auto is32 = [](const std::string& r) {
        static const std::regex e(R"(e(ax|bx|cx|dx|si|di|bp|sp)|r(8|9|1[0-5])d)");
        return std::regex_match(r, e);
    };
    if ((i.id == X86_INS_XCHG || i.id == X86_INS_MOV) && i.ops.size() == 2 && i.ops[0].type == X86_OP_REG &&
        i.ops[1].type == X86_OP_REG && i.ops[0].reg == i.ops[1].reg && !is32(i.ops[0].rname))
        return true;
    if (i.id == X86_INS_LEA && i.ops.size() == 2 && i.ops[0].type == X86_OP_REG && family(i.ops[0].rname) == i.ops[0].rname) {
        const cs_insn* d = fresh_full(im, rva, i.size);
        if (!d) return false;
        const cs_x86_op& m = d->detail->x86.operands[1];
        return m.type == X86_OP_MEM && static_cast<unsigned>(m.mem.base) == i.ops[0].reg &&
               m.mem.index == X86_REG_INVALID && m.mem.disp == 0 &&
               m.mem.segment == X86_REG_INVALID;
    }
    return false;
}

// "flags", a 64-bit register name, or "" (None)
std::string push_of(const JI& i) {
    if (i.id == X86_INS_PUSHFQ) return "flags";
    if (i.id == X86_INS_PUSH && i.ops.size() == 1 && i.ops[0].type == X86_OP_REG) {
        const std::string& n = i.ops[0].rname;
        return family(n) == n && n != "rsp" ? n : "";
    }
    return "";
}
std::string pop_of(const JI& i) {
    if (i.id == X86_INS_POPFQ) return "flags";
    if (i.id == X86_INS_POP && i.ops.size() == 1 && i.ops[0].type == X86_OP_REG) return i.ops[0].rname;
    return "";
}

struct Found {
    int64_t start, end;
    std::string reg, shape;
    bool operator<(const Found& o) const {
        if (start != o.start) return start < o.start;
        if (end != o.end) return end < o.end;
        if (reg != o.reg) return reg < o.reg;
        return shape < o.shape;
    }
};

// Counter in first-seen order
struct OC {
    std::vector<std::pair<std::string, int64_t>> v;
    void add(const std::string& k, int64_t n = 1) {
        for (auto& [x, c] : v)
            if (x == k) {
                c += n;
                return;
            }
        v.emplace_back(k, n);
    }
};

struct STATUSF {
    const char* name;
    uint64_t test;
    uint64_t w[4];
};
const STATUSF STATUS[6] = {
    {"CF", X86_EFLAGS_TEST_CF, {X86_EFLAGS_MODIFY_CF, X86_EFLAGS_RESET_CF, X86_EFLAGS_SET_CF, X86_EFLAGS_UNDEFINED_CF}},
    {"PF", X86_EFLAGS_TEST_PF, {X86_EFLAGS_MODIFY_PF, X86_EFLAGS_RESET_PF, X86_EFLAGS_SET_PF, X86_EFLAGS_UNDEFINED_PF}},
    {"AF", X86_EFLAGS_TEST_AF, {X86_EFLAGS_MODIFY_AF, X86_EFLAGS_RESET_AF, X86_EFLAGS_SET_AF, X86_EFLAGS_UNDEFINED_AF}},
    {"ZF", X86_EFLAGS_TEST_ZF, {X86_EFLAGS_MODIFY_ZF, X86_EFLAGS_RESET_ZF, X86_EFLAGS_SET_ZF, X86_EFLAGS_UNDEFINED_ZF}},
    {"SF", X86_EFLAGS_TEST_SF, {X86_EFLAGS_MODIFY_SF, X86_EFLAGS_RESET_SF, X86_EFLAGS_SET_SF, X86_EFLAGS_UNDEFINED_SF}},
    {"OF", X86_EFLAGS_TEST_OF, {X86_EFLAGS_MODIFY_OF, X86_EFLAGS_RESET_OF, X86_EFLAGS_SET_OF, X86_EFLAGS_UNDEFINED_OF}},
};

class Finder {
public:
    Finder(const FImage& im, bool older) : im_(im), older_(older) {}
    const FImage& im_;
    bool older_;
    OC why;
    OC flags;
    int64_t lim_ = 0;  // end of the current section's bytes: find_junk.py decodes from them alone

    JI seg(int64_t rva) { return one(im_, rva, std::min<int64_t>(15, lim_ - rva)); }

    // tail(): after the short jump, the return address goes, then the pushes
    // are undone in reverse order; fails with the reason in `fail`
    bool tail(int64_t start, const JI& op, int64_t cont, const std::vector<JI>& pushed,
              const std::vector<std::string>& pushes, const std::string& reg, Found& out, std::string& fail) {
        int64_t pc = cont;
        JI ins = seg(pc);
        if (!ins.ok || pop_of(ins) != reg) {
            fail = "no pop of the return address into the scratch register";
            return false;
        }
        std::vector<std::string> shape;
        for (const JI& p : pushed) shape.push_back(p.mn);
        shape.insert(shape.end(), {op.mn, "call", "|", "pop"});
        pc += ins.size;
        std::vector<std::string> need(pushes.rbegin(), pushes.rend());
        bool reg_back = false, flags_back = false;
        for (int k = 0; k < 10; ++k) {
            ins = seg(pc);
            if (!ins.ok) break;
            const std::string got = pop_of(ins);
            if (!got.empty() && !need.empty() && got == need[0]) {
                need.erase(need.begin());
                reg_back |= got == reg;
                flags_back |= got == "flags";
                shape.push_back(got == "flags" ? "popfq" : "pop");
                pc += ins.size;
                if (need.empty()) {
                    std::string s;
                    for (const std::string& x : shape) s += (s.empty() ? "" : " ") + x;
                    out = {start, pc, reg, s};
                    return true;
                }
                continue;
            }
            if (scratch(ins, reg) && !reg_back && !(flags_back && !no_flags(ins.id))) {
                shape.push_back(ins.mn);
                pc += ins.size;
                continue;
            }
            if (filler(ins, im_, pc)) {
                shape.push_back(ins.mn);
                pc += ins.size;
                continue;
            }
            break;
        }
        fail = "what follows does not put the register and the flags back";
        return false;
    }

    // at_call: the construct whose call is at c (an RVA); sec_lo/sec_hi bound the section's bytes
    bool at_call(int64_t c, Found& out) {
        const uint8_t* m = im_.mem.data();
        int32_t rel;
        std::memcpy(&rel, m + c + 1, 4);
        const int64_t t = c + 5 + rel;
        if (m[t] != 0xEB || !(0 < m[t + 1] && m[t + 1] < 0x80)) {
            why.add("the call does not land on a short jump");
            return false;
        }
        const int64_t cont = t + 2 + m[t + 1];
        if (cont <= c + 5) {
            why.add("the short jump does not pass the call");
            return false;
        }
        for (int64_t s_op = c - 2; s_op > c - 11; --s_op) {
            const JI op = seg(s_op);
            if (!op.ok || op.size != c - s_op || !(s_op < t)) continue;
            for (int k : {2, 3}) {
                const JI p1 = seg(s_op - k);
                if (!p1.ok || p1.size >= k) continue;
                const JI p2 = seg(s_op - k + p1.size);
                if (!p2.ok || p1.size + p2.size != k) continue;
                const std::string a = push_of(p1), b = push_of(p2);
                if ((a != "flags" && b != "flags") || a.empty() || b.empty() || a == b) continue;
                const std::string reg = b == "flags" ? a : b;
                if (!scratch(op, reg)) continue;
                std::string fail;
                if (tail(s_op - k, op, cont, {p1, p2}, {a, b}, reg, out, fail)) return true;
                // a flags push in front that is not the construct's: the older form may still be there
                if (!older_) {
                    why.add(fail);
                    return false;
                }
                return older(c, t, cont, out, fail);
            }
        }
        return older(c, t, cont, out, "no flags-and-register pushes with arithmetic in front of the call");
    }

    // the older form: one register pushed and the flags not saved (only when
    // older_; such a construct is kept only where the flags are proved unused
    // after it); `fail` is the reason recorded when it is not there either
    bool older(int64_t c, int64_t t, int64_t cont, Found& out, const std::string& fail0) {
        if (older_) {
            for (int64_t s_op = c - 2; s_op > c - 11; --s_op) {
                const JI op = seg(s_op);
                if (!op.ok || op.size != c - s_op || !(s_op < t)) continue;
                for (int k : {1, 2}) {
                    const JI p1 = seg(s_op - k);
                    const std::string reg = p1.ok && p1.size == k ? push_of(p1) : "";
                    if (reg.empty() || reg == "flags" || !scratch(op, reg)) continue;
                    std::string fail;
                    if (tail(s_op - k, op, cont, {p1}, {reg}, reg, out, fail)) return true;
                    why.add(fail);
                    return false;
                }
            }
        }
        why.add(fail0);
        return false;
    }

    // flags_after: "dead", "live" or "unknown"
    std::string flags_after(int64_t rva, int depth = 64) {
        struct W {
            int64_t pc;
            unsigned pend;
            int n;
        };
        std::vector<W> work{{rva, 0x3F, 0}};
        std::set<std::pair<int64_t, unsigned>> seen;
        const uint8_t* m = im_.mem.data();
        bool at_call = false;  // some path ended at a call or ret with flags not yet written
        while (!work.empty()) {
            W w = work.back();
            work.pop_back();
            int64_t pc = w.pc;
            unsigned pend = w.pend;
            int n = w.n;
            while (true) {
                if (!seen.insert({pc, pend}).second) break;
                if (++n > depth) return "unknown";
                const JI i = one(im_, pc, 16);
                if (!i.ok) return "unknown";
                const std::string& mn = i.mn;
                if (mn == "pushfq" || mn == "pushf" || mn == "lahf") return "live";
                for (int k = 0; k < 6; ++k)
                    if ((pend >> k & 1) && (i.eflags & STATUS[k].test)) return "live";
                for (int k = 0; k < 6; ++k)
                    for (uint64_t x : STATUS[k].w)
                        if (i.eflags & x) pend &= ~(1u << k);
                if (mn == "popfq" || mn == "popf" || mn == "sahf") pend = 0;
                if (!pend) break;
                if (mn == "int3" || mn == "ud2" || mn == "hlt" || mn == "int1" || mn == "iretq" || mn == "sysret" ||
                    mn == "retf")
                    return "unknown";
                if (mn == "ret") {
                    at_call = true;
                    break;
                }
                const bool direct = starts(i.op, "0x");
                int64_t t = 0;
                if (direct) hex_op(i.op, t);
                if (mn == "call") {
                    if (m[pc] == 0xE8) {
                        if (pc >= 0 && t >= 0 && t + 2 <= im_.len && m[t] == 0xEB && m[t + 1] < 0x80 &&
                            t + 2 + m[t + 1] > pc + 5) {
                            pc = t + 2 + m[t + 1];
                            continue;
                        }
                    }
                    at_call = true;
                    break;
                }
                if (mn == "jmp") {
                    if (!direct) return "unknown";
                    pc = t;
                    continue;
                }
                if (mn[0] == 'j' || starts(mn, "loop")) {
                    if (!direct) return "unknown";
                    work.push_back({t, pend, n});
                }
                pc += i.size;
            }
        }
        return at_call ? "dead at a call or ret" : "dead";
    }

    std::vector<Found> find() {
        std::vector<Found> out;
        const uint8_t* m = im_.mem.data();
        for (const PSection& s : im_.sections) {
            if (!s.executable()) continue;
            const int64_t have = s.vsize ? std::min(s.rsize, s.vsize) : s.rsize;
            lim_ = s.rva + have;
            for (int64_t p = 0; p + 5 <= have; ++p) {
                const uint8_t* q = m + s.rva + p;
                if (q[0] != 0xE8 || q[1] < 0xF0 || q[1] > 0xFB || q[2] != 0xFF || q[3] != 0xFF || q[4] != 0xFF) continue;
                const int64_t at = p;
                p += 4;  // finditer goes on after the match
                if (at < 16 || at + 160 > have) continue;
                Found f;
                if (at_call(s.rva + at, f)) out.push_back(f);
            }
        }
        std::sort(out.begin(), out.end());
        std::vector<Found> keep;
        int64_t last = -1;
        for (const Found& r : out) {
            if (r.start >= last) {
                keep.push_back(r);
                last = r.end;
            } else {
                why.add("inside another construct");
            }
        }
        std::vector<Found> res;
        for (const Found& r : keep) {
            if (r.shape.find("popfq") != std::string::npos) {
                res.push_back(r);
                continue;
            }
            const std::string v = flags_after(r.end);
            flags.add(v);
            if (v == "dead" || v == "dead at a call or ret")
                res.push_back(r);
            else
                why.add("the flags are left changed and may be read after (" + v + ")");
        }
        return res;
    }
};

}  // namespace

JunkOut find_junk(const FImage& im, const std::vector<const PlanF*>& plans, const std::vector<std::string>& names,
                  int prove, bool older, const std::function<void(const std::string&)>& log) {
    Finder f(im, older);
    const std::vector<Found> found = f.find();
    JunkOut out;
    log("call-back constructs that restore everything they touch: " + std::to_string(found.size()));
    {
        auto v = f.why.v;
        std::stable_sort(v.begin(), v.end(), [](const auto& a, const auto& b) { return a.second > b.second; });
        for (const auto& [k, n] : v) log("   not counted, " + k + ": " + std::to_string(n));
    }
    Json rep = Json::object();
    rep["constructs"] = Json(static_cast<int64_t>(found.size()));
    {
        Json nc = Json::object();
        for (const auto& [k, n] : f.why.v) nc[k] = Json(n);
        rep["not_counted"] = nc;
    }
    if (!found.empty()) {
        // foreign_references
        const int64_t lo = found.front().start;
        int64_t hi = 0;
        for (const Found& r : found) hi = std::max(hi, r.end);
        std::vector<int32_t> owner(static_cast<size_t>(hi - lo + 1), -1);
        for (size_t i = 0; i < found.size(); ++i)
            for (int64_t b = found[i].start + 1; b < found[i].end; ++b) owner[static_cast<size_t>(b - lo)] = static_cast<int32_t>(i);
        std::map<size_t, std::string> bad, overlap;  // index -> first reason
        auto hit = [&](int64_t t, int64_t src, const char* reason) {
            if (!(t > lo && t < hi)) return;
            const int32_t o = owner[static_cast<size_t>(t - lo)];
            if (o < 0) return;
            const Found& r = found[static_cast<size_t>(o)];
            if (!(r.start <= src && src < r.end) && !bad.count(static_cast<size_t>(o)))
                bad[static_cast<size_t>(o)] = std::string(reason) + " at " + hex8(src);
        };
        const uint8_t* m = im.mem.data();
        for (const PSection& s : im.sections) {
            const int64_t n = s.vsize ? std::min(s.rsize, s.vsize) : s.rsize;
            const uint8_t* raw = m + s.rva;
            const int64_t CH = int64_t(1) << 24;
            for (int64_t off = 0; off < n - 5; off += CH) {
                const int64_t k = std::min(n, off + CH + 6) - off - 6;
                if (k <= 0) break;
                for (int64_t p = off; p < off + k; ++p)
                    if (raw[p] == 0xE8 || raw[p] == 0xE9) {
                        int32_t rel;
                        std::memcpy(&rel, raw + p + 1, 4);
                        hit(s.rva + p + 5 + rel, s.rva + p, "a branch");
                    }
                for (int64_t p = off; p < off + k; ++p)
                    if (raw[p] == 0x0F && (raw[p + 1] & 0xF0) == 0x80) {
                        int32_t rel;
                        std::memcpy(&rel, raw + p + 2, 4);
                        hit(s.rva + p + 6 + rel, s.rva + p, "a branch");
                    }
            }
        }
        for (int64_t r : im.relocations()) hit(static_cast<int64_t>(im.u64(r) - im.image_base), r, "a relocated pointer");
        for (const auto& fn : im.runtime_functions()) hit(fn[0], static_cast<int64_t>(fn[0]) - 1, "an exception record begins");
        Decoder& ld = lite_dec();
        for (size_t pi = 0; pi < plans.size(); ++pi) {
            const PlanF* p = plans[pi];
            const std::string pname = pi < names.size() ? names[pi] : std::string("a plan");
            for (const PlanPatchF& x : p->patches) {
                const int64_t rva = x.rva, len = static_cast<int64_t>(x.data.size());
                // the last construct that starts at or before the patch's last byte
                auto it = std::upper_bound(found.begin(), found.end(), rva + len - 1,
                                           [](int64_t v, const Found& r) { return v < r.start; });
                if (it != found.begin()) {
                    const size_t i = static_cast<size_t>(it - found.begin()) - 1;
                    if (rva < found[i].end && rva + len > found[i].start && !overlap.count(i))
                        overlap[i] = "a patch of " + pname + " at " + hex8(rva);
                }
                const uint8_t d0 = x.data[0];
                if (d0 == 0xE9 || d0 == 0xE8 || d0 == 0x0F || d0 == 0xEB || (0x70 <= d0 && d0 < 0x80)) {
                    ld.run(x.data.data(), x.data.size(), static_cast<uint64_t>(rva), [&](const cs_insn* i) {
                        const std::string mnem = i->mnemonic;
                        const std::string_view ops = i->op_str;
                        int64_t t;
                        if (starts(ops, "0x") && (mnem[0] == 'j' || mnem[0] == 'c') && hex_op(ops, t))
                            if (lo < t && t < hi && owner[static_cast<size_t>(t - lo)] >= 0) {
                                const size_t o = static_cast<size_t>(owner[static_cast<size_t>(t - lo)]);
                                if (!bad.count(o))
                                    bad[o] = "a branch written by " + pname + " at " + hex8(static_cast<int64_t>(i->address));
                            }
                    });
                }
            }
        }
        int64_t wiped = 0, jumped = 0;
        for (size_t i = 0; i < found.size(); ++i) {
            if (overlap.count(i)) continue;
            const Found& r = found[i];
            const int64_t d = r.end - (r.start + 2);
            std::vector<uint8_t> data;
            if (d < 0x80) {
                data = {0xEB, static_cast<uint8_t>(d)};
            } else {
                const int32_t rel = static_cast<int32_t>(r.end - (r.start + 5));
                data = {0xE9};
                for (int k = 0; k < 4; ++k) data.push_back(static_cast<uint8_t>(static_cast<uint32_t>(rel) >> (8 * k)));
            }
            out.plan.patches.push_back({static_cast<uint32_t>(r.start), KIND_FLOW, data});
            ++jumped;
            if (!bad.count(i) && d < 0x80 && r.end - r.start - 2 > 0) {
                out.plan.wipes.emplace_back(static_cast<uint32_t>(r.start + 2), static_cast<uint32_t>(r.end - r.start - 2));
                wiped += r.end - r.start - 2;
            }
        }
        OC reasons;
        for (const auto& [i, v] : bad) reasons.add(v.substr(0, v.find(" at ")));
        log("replaced by a jump over themselves: " + std::to_string(jumped) + "; bytes filled with int3: " +
            std::to_string(wiped));
        log("left untouched because an earlier plan writes there: " + std::to_string(overlap.size()));
        log("jump written but bytes kept, because something refers into them: " + std::to_string(bad.size()));
        rep["replaced"] = Json(jumped);
        rep["wiped_bytes"] = Json(wiped);
        rep["left_for_an_earlier_plan"] = Json(static_cast<int64_t>(overlap.size()));
        rep["bytes_kept"] = Json(static_cast<int64_t>(bad.size()));
        Json bk = Json::object();
        for (const auto& [k, n] : reasons.v) bk[k] = Json(n);
        rep["bytes_kept_why"] = bk;
        int64_t total = 0, mn = INT64_MAX, mx = 0;
        std::set<std::string> shapes;
        OC regs;
        for (const Found& r : found) {
            total += r.end - r.start;
            mn = std::min(mn, r.end - r.start);
            mx = std::max(mx, r.end - r.start);
            shapes.insert(r.shape);
            regs.add(r.reg);
        }
        rep["total_bytes"] = Json(total);
        rep["shapes"] = Json(static_cast<int64_t>(shapes.size()));
        Json rg = Json::object();
        for (const auto& [k, n] : regs.v) rg[k] = Json(n);
        rep["registers"] = rg;
        Json lr = Json::array();
        lr.push(Json(mn));
        lr.push(Json(mx));
        rep["length_range"] = lr;
        Json ex = Json::array();
        for (size_t i = 0; i < found.size() && i < 6; ++i)
            ex.push(Json(hex8(found[i].start) + "-" + hex8(found[i].end) + " " + found[i].shape));
        rep["examples"] = ex;
        if (!f.flags.v.empty()) {
            Json fl = Json::object();
            for (const auto& [k, n] : f.flags.v) fl[k] = Json(n);
            rep["older_form_flags_after"] = fl;
        }
        if (prove > 0) {
            // one construct of every shape, then a random sample, run from random registers and flags
            std::mt19937_64 rnd(1);
            std::map<std::string, size_t> by_shape;
            for (size_t i = 0; i < found.size(); ++i) by_shape.emplace(found[i].shape, i);
            std::vector<size_t> todo;
            std::set<size_t> firsts;
            for (const auto& [s, i] : by_shape) {
                todo.push_back(i);
                firsts.insert(i);
            }
            std::vector<size_t> rest;
            for (size_t i = 0; i < found.size(); ++i)
                if (!firsts.count(i)) rest.push_back(i);
            std::shuffle(rest.begin(), rest.end(), rnd);
            for (size_t i = 0; i < rest.size() && static_cast<int>(todo.size()) < prove; ++i) todo.push_back(rest[i]);
            const UcApi& U = uc();
            static const int REGS[15] = {UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RSI,
                                         UC_X86_REG_RDI, UC_X86_REG_RBP, UC_X86_REG_R8,  UC_X86_REG_R9,  UC_X86_REG_R10,
                                         UC_X86_REG_R11, UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15};
            int64_t wrong = 0;
            std::vector<std::string> wrong_at;
            for (size_t i : todo) {
                const Found& r = found[i];
                uc_engine* u = nullptr;
                if (U.open(UC_ARCH_X86, UC_MODE_64, &u) != UC_ERR_OK) throw std::runtime_error("uc_open failed");
                const uint64_t B = 0x140000000ull;
                const int64_t page = r.start & ~int64_t(0xFFF);
                U.mem_map(u, B + page, 0x2000, UC_PROT_ALL);
                U.mem_write(u, B + page, im.mem.data() + page, static_cast<uint64_t>(std::min<int64_t>(0x2000, im.len - page)));
                U.mem_map(u, 0x7000000, 0x10000, UC_PROT_ALL);
                uint64_t vals[15];
                for (int k = 0; k < 15; ++k) {
                    vals[k] = rnd();
                    U.reg_write(u, REGS[k], &vals[k]);
                }
                const uint64_t flags = 0x202 | (rnd() & 0x8D5);
                U.reg_write(u, UC_X86_REG_EFLAGS, &flags);
                const uint64_t sp = 0x7008000;
                uint8_t above[64];
                for (uint8_t& b : above) b = static_cast<uint8_t>(rnd());
                U.mem_write(u, sp, above, 64);
                U.reg_write(u, UC_X86_REG_RSP, &sp);
                const uc_err e = U.emu_start(u, B + r.start, B + r.end, 0, 64);
                bool same = e == UC_ERR_OK;
                if (same) {
                    uint64_t rip = 0, rsp = 0, fl = 0;
                    U.reg_read(u, UC_X86_REG_RIP, &rip);
                    U.reg_read(u, UC_X86_REG_RSP, &rsp);
                    U.reg_read(u, UC_X86_REG_EFLAGS, &fl);
                    const uint64_t mask = r.shape.find("popfq") != std::string::npos ? ~uint64_t(0) : ~uint64_t(0x8D5);
                    uint8_t now[64];
                    U.mem_read(u, sp, now, 64);
                    same = rip == B + r.end && rsp == sp && (fl & mask) == (flags & mask) && std::memcmp(now, above, 64) == 0;
                    for (int k = 0; k < 15 && same; ++k) {
                        uint64_t v = 0;
                        U.reg_read(u, REGS[k], &v);
                        same = v == vals[k];
                    }
                }
                U.close(u);
                if (!same) {
                    ++wrong;
                    if (wrong_at.size() < 5) wrong_at.push_back(hex8(r.start));
                }
            }
            std::string wa;
            for (const std::string& s : wrong_at) wa += (wa.empty() ? "" : ", ") + s;
            log("run in the emulator: " + std::to_string(todo.size()) + " constructs covering all " +
                std::to_string(by_shape.size()) + " shapes; not a no-op: " + std::to_string(wrong) + " [" + wa + "]");
            rep["proved"] = Json(static_cast<int64_t>(todo.size()));
            rep["proved_shapes"] = Json(static_cast<int64_t>(by_shape.size()));
            rep["proved_wrong"] = Json(wrong);
            out.proved_wrong = wrong;
        }
    }
    out.report = rep;
    return out;
}

int cmd_junk(int argc, char** argv) {
    std::string exe, outp, report;
    std::vector<std::string> plans;
    int prove = 0;
    bool older = true;
    for (int i = 2; i < argc; ++i) {
        const std::string a = argv[i];
        auto val = [&]() -> std::string {
            if (i + 1 >= argc) throw std::runtime_error("missing value for " + a);
            return argv[++i];
        };
        if (a == "-o") outp = val();
        else if (a == "--report") report = val();
        else if (a == "--plan") plans.push_back(val());
        else if (a == "--prove") prove = std::stoi(val());
        else if (a == "--no-older") older = false;
        else if (!a.empty() && a[0] == '-') throw std::runtime_error("unknown option " + a);
        else exe = a;
    }
    if (exe.empty() || outp.empty())
        throw std::runtime_error("usage: mwdec junk <dec.exe> -o junk.plan [--report J] [--plan P ...] [--prove N] [--no-older]");
    FImage im;
    im.load(exe);
    std::vector<PlanF> loaded;
    for (const std::string& p : plans) loaded.push_back(PlanF::load(p));
    std::vector<const PlanF*> ptrs;
    std::vector<std::string> names;
    for (size_t i = 0; i < loaded.size(); ++i) {
        ptrs.push_back(&loaded[i]);
        names.push_back(basename_of(plans[i]));
    }
    const JunkOut j = find_junk(im, ptrs, names, prove, older, [](const std::string& s) {
        std::printf("%s\n", s.c_str());
        std::fflush(stdout);
    });
    j.plan.save(outp);
    if (!report.empty()) write_text_crlf(report, j.report.dump(1));
    return j.proved_wrong ? 1 : 0;
}

}  // namespace flow
