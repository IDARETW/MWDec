#include "flow/sweep.h"

#include "flow/pyutil.h"

namespace flow {

static bool seg_bad(unsigned r) {
    return r == X86_REG_ES || r == X86_REG_CS || r == X86_REG_SS || r == X86_REG_DS || r == X86_REG_FS;
}
static bool sp32(unsigned r) { return r == X86_REG_ESP || r == X86_REG_SP || r == X86_REG_SPL; }
static bool r32(unsigned r) {
    return r == X86_REG_ESP || r == X86_REG_EBP || r == X86_REG_EAX || r == X86_REG_EBX || r == X86_REG_ECX ||
           r == X86_REG_EDX || r == X86_REG_ESI || r == X86_REG_EDI;
}

const char* sweep_why_bad(const cs_insn* i, uint16_t mid, int64_t size, const RangeV& ex, std::string& buf) {
    std::string_view m = mn_name(mid);
    if (mf(mid, F_REP)) {
        const size_t k = m.find(' ');
        if (k != std::string_view::npos) m = m.substr(k + 1);
    }
    const std::string_view op = i->op_str;
    if (mf(mid, F_SWBAD)) {
        if (mf(mid, F_SWINT) && (op == "0x29" || op == "0x2c" || op == "3")) return nullptr;
        buf = "opcode " + std::string(m);
        return buf.c_str();
    }
    if (mf(mid, F_X87)) return "x87";
    if (i->size >= 2 && i->bytes[0] >= 0x40 && i->bytes[0] <= 0x4F && (i->bytes[1] == 0xE8 || i->bytes[1] == 0xE9))
        return "rex branch";
    const cs_x86& x = i->detail->x86;
    for (int k = 0; k < 4; ++k) {
        const uint8_t p = x.prefix[k];
        if ((p == 0x26 || p == 0x2E || p == 0x36 || p == 0x3E || p == 0x64) && m != "jmp" && !(m.size() && m[0] == 'j'))
            return "segment prefix";
    }
    const bool jlike = (!m.empty() && m[0] == 'j') || m == "call";
    for (int k = 0; k < x.op_count; ++k) {
        const cs_x86_op& o = x.operands[k];
        if (o.type == X86_OP_REG) {
            if (seg_bad(o.reg)) return "segment register";
            if (sp32(o.reg)) return "32-bit stack pointer";
        } else if (o.type == X86_OP_MEM) {
            const unsigned base = o.mem.base;
            const int64_t disp = o.mem.disp;
            if (seg_bad(o.mem.segment)) return "segment override";
            if (base == X86_REG_RIP) {
                const int64_t t = static_cast<int64_t>(i->address) + i->size + disp;
                if (!(0 <= t && t < size)) return "rip operand outside the image";
            } else if (base == X86_REG_RSP) {
                if (disp < 0 && disp != -8) return "below rsp";
            } else if (r32(base)) {
                return "32-bit address";
            } else {
                if (disp < -0x8000000 || disp >= size) return "displacement";
            }
        } else if (o.type == X86_OP_IMM && jlike) {
            const int64_t t = o.imm;
            bool in = false;
            for (const auto& [lo, hi] : ex)
                if (lo <= t && t < hi) in = true;
            if (!in) return "branch outside code";
        }
    }
    return nullptr;
}

static void refs_of(const cs_insn* i, uint16_t mid, std::vector<BlockRef>& out) {
    const std::string_view op = i->op_str;
    int64_t t;
    if ((mf(mid, F_J) || mid == M_CALL) && starts(op, "0x")) {
        if (hex_op(op, t)) out.push_back({t, true});
        return;
    }
    const cs_x86& x = i->detail->x86;
    for (int k = 0; k < x.op_count; ++k) {
        const cs_x86_op& o = x.operands[k];
        if (o.type == X86_OP_MEM && o.mem.base == X86_REG_RIP)
            out.push_back({static_cast<int64_t>(i->address) + i->size + o.mem.disp, false});
    }
}

std::pair<bool, std::string> Sweeper::block(int64_t c, int64_t stop, int64_t rec_end,
                                            const std::function<bool(int64_t)>& joins, int64_t region_end) {
    if (const auto* r = remembered(c, stop, rec_end)) return *r;
    return remember(c, stop, rec_end, evaluate(c, stop, rec_end, joins, region_end));
}

const std::pair<bool, std::string>* Sweeper::remembered(int64_t c, int64_t stop, int64_t rec_end) const {
    auto it = cache_.find(Key{c, stop, rec_end});
    return it == cache_.end() ? nullptr : &it->second;
}

const std::pair<bool, std::string>& Sweeper::remember(int64_t c, int64_t stop, int64_t rec_end,
                                                      std::pair<bool, std::string> v) {
    if (cache_.size() > 2000000) cache_.clear();
    auto& slot = cache_[Key{c, stop, rec_end}];
    slot = std::move(v);
    return slot;
}

std::pair<bool, std::string> Sweeper::evaluate(int64_t c, int64_t stop, int64_t rec_end,
                                               const std::function<bool(int64_t)>& joins, int64_t region_end) const {
    int64_t pc = c;
    std::string why;
    bool ok = false;
    int64_t nins = 0, last_end = c;
    std::string buf;
    Decoder& dec = full_dec();
    while (true) {
        if (pc >= stop) {
            if (pc == stop && stop < region_end && joins(pc)) {
                ok = true;
                why = "runs onto a walked instruction start";
            } else if (stop >= region_end) {
                why = "runs to the end of the code region";
            } else {
                why = "runs into the middle of a walked instruction";
            }
            break;
        }
        if (pc >= rec_end) {
            why = "runs past the end of its record";
            break;
        }
        const cs_insn* i = fresh_full(im_, pc);
        if (!i) {
            why = "undecodable";
            break;
        }
        if (pc + i->size > stop) {
            why = "decodes across a walked instruction boundary";
            break;
        }
        const uint16_t mid = dec.mid_of(i);
        if (const char* w = sweep_why_bad(i, mid, im_.len, ex_, buf)) {
            why = w;
            break;
        }
        ++nins;
        last_end = pc + i->size;
        if (nins > 4096) {
            why = "longer than 4096 instructions";
            break;
        }
        if (mf(mid, F_SWTERM)) {
            ok = true;
            why = "ends at a terminator";
            break;
        }
        pc += i->size;
    }
    if (ok && nins) {
        bool any = false;
        for (int64_t b = c; b < last_end; ++b)
            if (im_.mem[static_cast<size_t>(b)]) {
                any = true;
                break;
            }
        if (!any) {
            ok = false;
            why = "zero bytes";
        }
    }
    return {ok, why};
}

const std::vector<RunBlock>& Sweeper::run_blocks(int64_t lo, int64_t hi) {
    const auto key = std::make_pair(lo, hi);
    auto it = runs_.find(key);
    if (it != runs_.end()) return it->second;
    auto& out = runs_[key];
    const uint8_t* mem = im_.mem.data();
    int64_t s = lo, e = hi;
    while (s < e && mem[s] == 0xCC) ++s;  // lstrip CC
    const int64_t a0 = s;
    {
        int64_t q = e;
        while (q > s && mem[q - 1] == 0xCC) --q;  // rstrip CC
        int64_t p = s;
        while (p < q && mem[p] == 0) ++p;
        while (q > p && mem[q - 1] == 0) --q;
        if (p >= q) return out;
    }
    int64_t blk = a0;
    bool bad = false;
    std::vector<BlockRef> refs;
    int64_t pos = a0;
    std::string buf;
    Decoder& dec = full_dec();
    dec.run(mem + a0, static_cast<size_t>(e - a0), static_cast<uint64_t>(a0), [&](const cs_insn* i) {
        const uint16_t mid = dec.mid_of(i);
        if (sweep_why_bad(i, mid, im_.len, ex_, buf)) bad = true;
        refs_of(i, mid, refs);
        pos = static_cast<int64_t>(i->address) + i->size;
        if (mf(mid, F_SWTERM)) {
            out.push_back({blk, !bad, std::move(refs)});
            refs.clear();
            blk = pos;
            bad = false;
        }
    });
    if (pos < hi && pos < e) {
        // undecodable tail: the open block is filler
    } else if (pos > blk) {
        out.push_back({blk, !bad, std::move(refs)});
    }
    return out;
}

}  // namespace flow
