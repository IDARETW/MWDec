#include "flow/checks.h"

#include <algorithm>
#include <deque>
#include <set>
#include <stdexcept>
#include <unordered_set>

#include "flow/pyutil.h"

namespace flow {

// ------------------------------------------------------------ PyRandom --

PyRandom::PyRandom(uint32_t seed) {
    // init_by_array with key [seed] (CPython seeds an int by its 32-bit words)
    auto init_genrand = [this](uint32_t s) {
        mt_[0] = s;
        for (mti_ = 1; mti_ < 624; ++mti_)
            mt_[mti_] = 1812433253u * (mt_[mti_ - 1] ^ (mt_[mti_ - 1] >> 30)) + static_cast<uint32_t>(mti_);
    };
    init_genrand(19650218u);
    const uint32_t key[1] = {seed};
    const int key_length = 1;
    int i = 1, j = 0;
    int k = 624 > key_length ? 624 : key_length;
    for (; k; --k) {
        mt_[i] = (mt_[i] ^ ((mt_[i - 1] ^ (mt_[i - 1] >> 30)) * 1664525u)) + key[j] + static_cast<uint32_t>(j);
        ++i;
        ++j;
        if (i >= 624) {
            mt_[0] = mt_[623];
            i = 1;
        }
        if (j >= key_length) j = 0;
    }
    for (k = 623; k; --k) {
        mt_[i] = (mt_[i] ^ ((mt_[i - 1] ^ (mt_[i - 1] >> 30)) * 1566083941u)) - static_cast<uint32_t>(i);
        ++i;
        if (i >= 624) {
            mt_[0] = mt_[623];
            i = 1;
        }
    }
    mt_[0] = 0x80000000u;
    mti_ = 624;
}

uint32_t PyRandom::genrand() {
    static const uint32_t mag01[2] = {0x0u, 0x9908b0dfu};
    uint32_t y;
    if (mti_ >= 624) {
        int kk;
        for (kk = 0; kk < 624 - 397; ++kk) {
            y = (mt_[kk] & 0x80000000u) | (mt_[kk + 1] & 0x7fffffffu);
            mt_[kk] = mt_[kk + 397] ^ (y >> 1) ^ mag01[y & 1u];
        }
        for (; kk < 623; ++kk) {
            y = (mt_[kk] & 0x80000000u) | (mt_[kk + 1] & 0x7fffffffu);
            mt_[kk] = mt_[kk + (397 - 624)] ^ (y >> 1) ^ mag01[y & 1u];
        }
        y = (mt_[623] & 0x80000000u) | (mt_[0] & 0x7fffffffu);
        mt_[623] = mt_[396] ^ (y >> 1) ^ mag01[y & 1u];
        mti_ = 0;
    }
    y = mt_[mti_++];
    y ^= (y >> 11);
    y ^= (y << 7) & 0x9d2c5680u;
    y ^= (y << 15) & 0xefc60000u;
    y ^= (y >> 18);
    return y;
}

uint64_t PyRandom::getrandbits(int k) {
    if (k <= 32) return genrand() >> (32 - k);
    uint64_t v = 0;
    int shift = 0;
    while (k > 0) {
        uint32_t r = genrand();
        if (k < 32) r >>= (32 - k);
        v |= static_cast<uint64_t>(r) << shift;
        shift += 32;
        k -= 32;
    }
    return v;
}

int64_t PyRandom::randbelow(int64_t n) {
    int k = 0;
    while ((int64_t(1) << k) <= n) ++k;  // n.bit_length()
    int64_t r = static_cast<int64_t>(getrandbits(k));
    while (r >= n) r = static_cast<int64_t>(getrandbits(k));
    return r;
}

void PyRandom::randbytes(uint8_t* out, size_t n) {
    for (size_t i = 0; i < n; i += 4) {
        const uint32_t w = genrand();
        std::memcpy(out + i, &w, 4);
    }
}

// --------------------------------------------------------------- preds --

std::vector<int64_t> back_preds(Code& code, const RawXrefs& xr, int64_t a) {
    std::vector<int64_t> out;
    for (const BranchRef& b : confirmed_branches_to(code, xr, a))
        if (b.mid != M_CALL) out.push_back(b.src);
    for (int64_t s : confirmed_refs_to(code, xr, a)) out.push_back(s);
    Lite d;
    for (int k = 1; k < 16; ++k)
        if (code.insn(a - k, d) && d.size == k && !mf(d.mid, F_STOP) && d.mid != M_JMP) out.push_back(a - k);
    return out;
}

// ------------------------------------------------------------- MiniEmu --

namespace {

constexpr uint64_t STACK = 0x000000E000000000ull;
const int REGS[15] = {UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RSI,
                      UC_X86_REG_RDI, UC_X86_REG_RBP, UC_X86_REG_R8,  UC_X86_REG_R9,  UC_X86_REG_R10,
                      UC_X86_REG_R11, UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15};
const char* const REGN[15] = {"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "r8",
                              "r9",  "r10", "r11", "r12", "r13", "r14", "r15"};

struct EmuState {
    uint64_t r[15];
    uint64_t rsp;
    uint64_t flags;
};

struct MiniEmu {
    FImage& im;
    uint64_t base;
    uc_engine* uc = nullptr;
    std::unordered_set<uint64_t> mapped;
    uc_hook miss_h{};

    explicit MiniEmu(FImage& i) : im(i), base(i.image_base) {
        const UcApi& a = flow::uc();
        if (a.open(UC_ARCH_X86, UC_MODE_64, &uc) != UC_ERR_OK) throw std::runtime_error("uc_open failed");
        a.mem_map(uc, STACK, 0x100000, UC_PROT_ALL);
        a.hook_add(uc, &miss_h, UC_HOOK_MEM_UNMAPPED, reinterpret_cast<void*>(&MiniEmu::miss), this, 1, 0);
    }
    ~MiniEmu() {
        if (uc) flow::uc().close(uc);
    }

    static bool miss(uc_engine* u, uc_mem_type, uint64_t addr, int size, int64_t, void* ud) {
        MiniEmu* e = static_cast<MiniEmu*>(ud);
        bool ok = true;
        const uint64_t lo = addr & ~uint64_t(0xFFF);
        const uint64_t hi = (addr + static_cast<uint64_t>(std::max(size, 1)) + 0xFFF) & ~uint64_t(0xFFF);
        for (uint64_t a = lo; a < hi; a += 0x1000) {
            const int64_t r = static_cast<int64_t>(a - e->base);
            const bool in = a >= e->base && r >= 0 && r < e->im.len;
            if (in && !e->mapped.count(a)) {
                flow::uc().mem_map(u, a, 0x1000, UC_PROT_ALL);
                const int64_t n = std::min<int64_t>(0x1000, e->im.len - r);
                flow::uc().mem_write(u, a, e->im.mem.data() + r, static_cast<uint64_t>(n));
                e->mapped.insert(a);
            } else if (!in) {
                ok = false;
            }
        }
        return ok;
    }

    EmuState state() const {
        EmuState s{};
        for (int k = 0; k < 15; ++k) flow::uc().reg_read(uc, REGS[k], &s.r[k]);
        flow::uc().reg_read(uc, UC_X86_REG_RSP, &s.rsp);
        uint64_t f = 0;
        flow::uc().reg_read(uc, UC_X86_REG_EFLAGS, &f);
        s.flags = f & 0x8D5;
        return s;
    }
    void set(const EmuState& s, const std::vector<uint8_t>& stack) {
        for (int k = 0; k < 15; ++k) flow::uc().reg_write(uc, REGS[k], &s.r[k]);
        flow::uc().reg_write(uc, UC_X86_REG_RSP, &s.rsp);
        const uint64_t f = 0x202 | s.flags;
        flow::uc().reg_write(uc, UC_X86_REG_EFLAGS, &f);
        flow::uc().mem_write(uc, STACK, stack.data(), stack.size());
    }
};

struct Hit {
    bool x = false, undo = false, has_E = false;
    int64_t E = 0;
    bool flags = false;
    std::vector<std::string> regs;
};

struct RunCtx {
    MiniEmu* em;
    FImage* im;
    int64_t c, x;
    uint64_t base;
    EmuState st0;
    const std::vector<uint8_t>* stack;
    Hit hit;
    std::vector<int64_t> trace;
    std::vector<std::pair<int64_t, int64_t>> reads;
};

const uint8_t ADD_RSP_RSP8[5] = {0x48, 0x03, 0x64, 0x24, 0x08};

void code_h(uc_engine* u, uint64_t a, uint32_t, void* ud) {
    RunCtx* c = static_cast<RunCtx*>(ud);
    const int64_t r = static_cast<int64_t>(a - c->base);
    if (c->hit.undo && !c->hit.has_E && r != c->c) {
        const EmuState s = c->em->state();
        const uint64_t rsp0 = c->st0.rsp;
        if (s.rsp == rsp0) {
            uint8_t buf[0x200];
            flow::uc().mem_read(u, rsp0, buf, 0x200);
            if (std::memcmp(buf, c->stack->data() + (rsp0 - STACK), 0x200) == 0) {
                c->hit.has_E = true;
                c->hit.E = r;
                c->hit.flags = s.flags != c->st0.flags;
                for (int k = 0; k < 15; ++k)
                    if (s.r[k] != c->st0.r[k]) c->hit.regs.push_back(REGN[k]);
                std::sort(c->hit.regs.begin(), c->hit.regs.end());
                flow::uc().emu_stop(u);
                return;
            }
        }
    }
    c->trace.push_back(r);
    if (r == c->x) c->hit.x = true;
    if (c->hit.x && r >= 0 && r + 5 <= c->im->len && std::memcmp(c->im->mem.data() + r, ADD_RSP_RSP8, 5) == 0)
        c->hit.undo = true;
}

void read_h(uc_engine*, uc_mem_type, uint64_t addr, int size, int64_t, void* ud) {
    RunCtx* c = static_cast<RunCtx*>(ud);
    if (addr >= c->base && addr < c->base + static_cast<uint64_t>(c->im->len))
        c->reads.emplace_back(static_cast<int64_t>(addr - c->base), size);
}

}  // namespace

std::unordered_map<int64_t, CheckFold> find_checks(FImage& im, Code& code, const RawXrefs& xr,
                                                   const std::vector<int64_t>& sites,
                                                   const std::vector<std::pair<int64_t, int64_t>>& routine_writes,
                                                   const std::vector<std::pair<int64_t, int64_t>>& baked, int depth) {
    PyRandom rng(1400);
    MiniEmu em(im);
    const uint64_t base = im.image_base;
    std::unordered_set<int64_t> written, baked_set;
    for (const auto& [rva, n] : routine_writes)
        for (int64_t b = rva; b < rva + n; ++b) written.insert(b);
    for (const auto& [rva, n] : baked)
        for (int64_t b = rva; b < rva + n; ++b) baked_set.insert(b);
    std::unordered_map<int64_t, CheckFold> out;
    Lite d;

    auto path_ok = [&](int64_t c, int64_t x) {
        int64_t pc = c;
        for (int k = 0; k < 64; ++k) {
            if (pc == x) return true;
            if (!code.insn(pc, d)) return false;
            const uint16_t m = d.mid;
            int64_t t;
            if (m == M_JMP && starts(d.ops(), "0x") && hex_op(d.ops(), t)) {
                pc = t;
                continue;
            }
            if (m == M_JNE && starts(d.ops(), "0x")) {
                pc += d.size;
                continue;
            }
            const bool save = m == M_PUSH || m == M_PUSHFQ || m == M_TEST || m == M_JNE || m == M_JMP ||
                              m == M_LEA || m == M_SUB;
            if (!save || (m == M_LEA && !lea_rsp_disp(d.ops())) || (m == M_SUB && d.ops() != "rsp, 8")) return false;
            pc += d.size;
        }
        return false;
    };

    std::vector<uint8_t> stack(0x100000);
    auto run = [&](int64_t c, int64_t x, RunCtx& ctx) {
        EmuState st0{};
        for (int k = 0; k < 15; ++k) st0.r[k] = rng.getrandbits(64);
        st0.rsp = STACK + 0x80000 + static_cast<uint64_t>(8 * rng.randbelow(32));
        st0.flags = rng.getrandbits(12) & 0x8D5;
        rng.randbytes(stack.data(), stack.size());
        em.set(st0, stack);
        ctx.em = &em;
        ctx.im = &im;
        ctx.c = c;
        ctx.x = x;
        ctx.base = base;
        ctx.st0 = st0;
        ctx.stack = &stack;
        uc_hook h1, h2;
        const UcApi& a = flow::uc();
        a.hook_add(em.uc, &h1, UC_HOOK_CODE, reinterpret_cast<void*>(&code_h), &ctx, 1, 0);
        a.hook_add(em.uc, &h2, UC_HOOK_MEM_READ, reinterpret_cast<void*>(&read_h), &ctx, 1, 0);
        a.emu_start(em.uc, base + static_cast<uint64_t>(c), 0, 0, 600);
        a.hook_del(em.uc, h1);
        a.hook_del(em.uc, h2);
    };

    for (int64_t x : sites) {
        std::unordered_set<int64_t> seen{x};
        std::deque<std::pair<int64_t, int>> q{{x, 0}};
        std::vector<std::pair<int, int64_t>> cands;
        while (!q.empty()) {
            const auto [a, dep] = q.front();
            q.pop_front();
            if (code.insn(a, d) && ((d.mid == M_PUSH && gpr_index(d.ops()) >= 0) || d.mid == M_PUSHFQ) &&
                path_ok(a, x))
                cands.emplace_back(dep, a);
            if (dep >= depth) continue;
            for (int64_t p : back_preds(code, xr, a))
                if (seen.insert(p).second) q.emplace_back(p, dep + 1);
        }
        std::optional<CheckFold> ck;
        auto sorted = cands;
        std::sort(sorted.begin(), sorted.end(), [](const auto& l, const auto& r) { return l > r; });
        for (const auto& [dep, c] : sorted) {
            RunCtx r1;
            run(c, x, r1);
            if (!r1.hit.has_E) continue;
            RunCtx r2;
            run(c, x, r2);
            CheckFold k;
            k.c = c;
            k.site = x;
            std::set<std::pair<int64_t, int64_t>> s1(r1.reads.begin(), r1.reads.end());
            std::set<std::pair<int64_t, int64_t>> s2(r2.reads.begin(), r2.reads.end());
            if (!r2.hit.has_E || r2.hit.E != r1.hit.E || s1 != s2) k.why = "outcome depends on the state (two runs differ)";
            k.has_E = true;
            k.E = r1.hit.E;
            k.flags_changed = r1.hit.flags || r2.hit.flags;
            std::set<std::string> rs(r1.hit.regs.begin(), r1.hit.regs.end());
            rs.insert(r2.hit.regs.begin(), r2.hit.regs.end());
            k.regs_changed.assign(rs.begin(), rs.end());
            for (int64_t a : r1.trace)
                if (code.insn(a, d)) k.insns.emplace_back(a, d.size);
            k.reads.assign(s1.begin(), s1.end());
            for (const auto& [a, n] : k.reads)
                for (int64_t b = a; b < a + n; ++b)
                    if (written.count(b) && !baked_set.count(b)) {
                        if (!k.why) k.why = "reads " + hex8(a) + ", which a routine writes (not a baked value)";
                        break;
                    }
            ck = std::move(k);
            break;
        }
        if (!ck) {
            CheckFold k;
            k.c = cands.empty() ? x : cands.back().second;
            k.site = x;
            k.why = "no start found whose run comes back to the same state";
            ck = std::move(k);
        }
        const int64_t key = ck->c;
        out[key] = std::move(*ck);
    }
    return out;
}

std::vector<std::pair<int64_t, int64_t>> static_writes(FImage& im, Code& code, const ByteMap& bm) {
    std::set<std::pair<int64_t, int64_t>> out;
    Lite d;
    for (const auto& sec : bm.reg->secs) {
        const int64_t n = sec.hi - sec.lo;
        for (int64_t k = 0; k < n; ++k) {
            if (!(bm.f[static_cast<size_t>(sec.off + k)] & ISTART)) continue;
            const int64_t a = sec.lo + k;
            if (!code.insn(a, d) || !contains(d.ops(), "rip")) continue;
            const cs_insn* ins = fresh_full(im, a, d.size);
            if (!ins) continue;
            const cs_x86& x = ins->detail->x86;
            const uint16_t m = full_dec().mid_of(ins);
            for (int o = 0; o < x.op_count; ++o) {
                const cs_x86_op& op = x.operands[o];
                if (op.type == X86_OP_MEM && op.mem.base == X86_REG_RIP) {
                    const int64_t t = a + ins->size + op.mem.disp;
                    if (!(0 <= t && t < im.len)) continue;
                    if (m == M_LEA)
                        out.emplace(t, 8);
                    else if (op.access & CS_AC_WRITE)
                        out.emplace(t, std::max<int64_t>(1, op.size));
                }
            }
        }
    }
    return {out.begin(), out.end()};
}

}  // namespace flow
