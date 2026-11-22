#include "flow/idiom.h"

#include <algorithm>
#include <stdexcept>

#include "flow/pyutil.h"

namespace flow {

// ------------------------------------------------------------ registers --

namespace {
struct RegNames {
    std::vector<std::string> names;
    std::unordered_map<std::string, int> ids;
    RegNames() {
        for (int i = 0; i < 16; ++i) add(GPR64[i]);
        add("flags");
    }
    int add(const std::string& s) {
        auto it = ids.find(s);
        if (it != ids.end()) return it->second;
        if (names.size() >= 64) throw std::runtime_error("too many register names");
        const int id = static_cast<int>(names.size());
        names.push_back(s);
        ids.emplace(s, id);
        return id;
    }
};
RegNames& regnames() {
    static RegNames r;
    return r;
}
}  // namespace

int reg_id(std::string_view name) { return regnames().add(std::string(name)); }
const std::string& reg_str(int id) { return regnames().names[static_cast<size_t>(id)]; }

std::vector<int> sorted_regs(RegSet s) {
    std::vector<int> v;
    for (int i = 0; i < 64; ++i)
        if (s >> i & 1) v.push_back(i);
    std::sort(v.begin(), v.end(), [](int a, int b) { return reg_str(a) < reg_str(b); });
    return v;
}

bool Chain::saves_flags() const {
    return std::find(push_order.begin(), push_order.end(), REG_FLAGS) != push_order.end();
}

const char* ikind_name(int k) {
    static const char* const n[] = {"jmp", "jcc", "call", "popjmp"};
    return n[k];
}

// ----------------------------------------------------- symbolic state --

namespace {

struct SmallSet {
    std::vector<int64_t> v;  // open addressing, 0 = empty (keys stored +1 shifted)
    size_t n = 0;
    static uint64_t h(int64_t k) { return static_cast<uint64_t>(k) * 0x9E3779B97F4A7C15ull; }
    bool insert(int64_t k) {  // false if present
        if (v.empty()) v.assign(64, INT64_MIN);
        if ((n + 1) * 2 > v.size()) {
            std::vector<int64_t> old;
            old.swap(v);
            v.assign(old.size() * 2, INT64_MIN);
            n = 0;
            for (int64_t x : old)
                if (x != INT64_MIN) insert(x);
        }
        const size_t m = v.size() - 1;
        size_t i = static_cast<size_t>(h(k) >> 40) & m;
        while (v[i] != INT64_MIN) {
            if (v[i] == k) return false;
            i = (i + 1) & m;
        }
        v[i] = k;
        ++n;
        return true;
    }
    bool has(int64_t k) const {
        if (v.empty()) return false;
        const size_t m = v.size() - 1;
        size_t i = static_cast<size_t>(h(k) >> 40) & m;
        while (v[i] != INT64_MIN) {
            if (v[i] == k) return true;
            i = (i + 1) & m;
        }
        return false;
    }
};

struct MemMap {
    std::vector<std::pair<int64_t, Val>> e;
    const Val* find(int64_t o) const {
        for (const auto& [k, v] : e)
            if (k == o) return &v;
        return nullptr;
    }
    Val get(int64_t o) const {
        const Val* p = find(o);
        return p ? *p : Val::M(o);
    }
    void set(int64_t o, const Val& v) {
        for (auto& [k, x] : e)
            if (k == o) {
                x = v;
                return;
            }
        e.emplace_back(o, v);
    }
};

struct RegMap {
    std::array<Val, 64> v{};
    RegSet present = 0;
    Val get(int r) const { return (present >> r & 1) ? v[static_cast<size_t>(r)] : Val::R(r); }
    void set(int r, const Val& x) {
        v[static_cast<size_t>(r)] = x;
        present |= RegSet(1) << r;
    }
};

// the instruction shapes both evaluators accept, applied to (regs, mem, sp)
// returns false for "return None"
bool step_plain(Code& code, uint16_t m, std::string_view op, int64_t nxt, RegMap& regs, MemMap& mem, int64_t& sp,
                bool flags_clobbered) {
    std::vector<std::string_view> ops;
    if (!op.empty()) ops = split_cs(op);
    const int64_t base = static_cast<int64_t>(code.image().image_base);
    if (m == M_PUSH) {
        if (ops.size() != 1) return false;
        const int r = gpr_index(ops[0]);
        if (r < 0 || r == REG_RSP) return false;
        sp -= 8;
        mem.set(sp, regs.get(r));
        return true;
    }
    if (m == M_POP) {
        if (ops.size() != 1) return false;
        const int r = gpr_index(ops[0]);
        if (r < 0 || r == REG_RSP) return false;
        regs.set(r, mem.get(sp));
        sp += 8;
        return true;
    }
    if (m == M_LEA) {
        if (auto dd = lea_rsp_disp(op)) {
            if (*dd % 8) return false;
            sp += *dd;
            return true;
        }
        if (ops.size() == 2) {
            const int r = gpr_index(ops[0]);
            if (r >= 0 && r != REG_RSP && starts(ops[1], "[rip")) {
                auto t = rip_target(ops[1], nxt);
                if (!t) throw std::runtime_error("lea [rip] without a target");
                regs.set(r, Val::C(*t));
                return true;
            }
        }
        return false;
    }
    if (m == M_MOV || m == M_MOVABS) {
        if (ops.size() != 2) return false;
        const std::string_view d0 = ops[0], d1 = ops[1];
        const int r0 = gpr_index(d0);
        if (r0 >= 0 && r0 != REG_RSP) {
            const int r1 = gpr_index(d1);
            if (r1 >= 0 && r1 != REG_RSP) {
                regs.set(r0, regs.get(r1));
                return true;
            }
            if (starts(d1, "qword ptr [rsp")) {
                auto dd = rsp_disp(d1);
                if (!dd) return false;
                regs.set(r0, mem.get(sp + *dd));
                return true;
            }
            uint64_t v;
            if (m == M_MOVABS && full_num(d1, v)) {
                const uint64_t b = static_cast<uint64_t>(base);
                if (!(b <= v && v < b + static_cast<uint64_t>(code.image().len))) return false;
                regs.set(r0, Val::C(static_cast<int64_t>(v - b)));
                return true;
            }
            return false;
        }
        const int r1 = gpr_index(d1);
        if (starts(d0, "qword ptr [rsp") && r1 >= 0 && r1 != REG_RSP) {
            auto dd = rsp_disp(d0);
            if (!dd) return false;
            mem.set(sp + *dd, regs.get(r1));
            return true;
        }
        return false;
    }
    if (m == M_XCHG) {
        if (ops.size() != 2) return false;
        std::string_view x0 = ops[0], x1 = ops[1];
        if (starts(x1, "qword ptr [rsp")) std::swap(x0, x1);
        const int r1 = gpr_index(x1);
        if (starts(x0, "qword ptr [rsp") && r1 >= 0 && r1 != REG_RSP) {
            auto dd = rsp_disp(x0);
            if (!dd) return false;
            const Val old = mem.get(sp + *dd);
            mem.set(sp + *dd, regs.get(r1));
            regs.set(r1, old);
            return true;
        }
        const int r0 = gpr_index(x0);
        if (r0 >= 0 && r1 >= 0 && r0 != REG_RSP && r1 != REG_RSP) {
            const Val v0 = regs.get(r0);
            regs.set(r0, regs.get(r1));
            regs.set(r1, v0);
            return true;
        }
        return false;
    }
    if (mf(m, F_CMOV)) {
        const int cc = mn_cmov_cc(m);
        if (flags_clobbered) return false;
        if (cc < 0 || ops.size() != 2) return false;
        const int r0 = gpr_index(ops[0]), r1 = gpr_index(ops[1]);
        if (r0 < 0 || r1 < 0) return false;
        const Val v0 = regs.get(r0), v1 = regs.get(r1);
        if (v0.k != VC || v1.k != VC) return false;
        regs.set(r0, Val::Sel(cc, v1.a, v0.a));
        return true;
    }
    return false;
}

}  // namespace

// ------------------------------------------------------- resolve_idiom --

std::optional<Idiom> resolve_idiom(Code& code, int64_t a, int max_insns) {
    Lite d;
    if (!code.insn(a, d) || !mf(d.mid, F_IDIOM_FIRST)) return std::nullopt;
    RegMap regs;
    MemMap mem;
    int64_t sp = 0;
    int64_t pc = a;
    InsnList insns;
    SmallSet seen;
    auto finish = [&](const Val& tgt, int64_t endpc) -> std::optional<Idiom> {
        for (int r = 0; r < 64; ++r)
            if ((regs.present >> r & 1) && regs.v[static_cast<size_t>(r)] != Val::R(r)) return std::nullopt;
        int kind;
        if (sp == 0) {
            kind = IK_JMP;
        } else if (sp == -8) {
            const Val* rv = mem.find(-8);
            if (!rv || rv->k != VC) return std::nullopt;
            kind = IK_CALL;
        } else {
            return std::nullopt;
        }
        for (const auto& [off, v] : mem.e)
            if (off >= sp && !(kind == IK_CALL && off == -8))
                if (v != Val::M(off)) return std::nullopt;
        Idiom i;
        i.start = a;
        i.insns = insns;
        i.end = endpc;
        if (tgt.k == VC) {
            if (!code.in_code(tgt.a)) return std::nullopt;
            if (kind == IK_CALL) {
                const int64_t r = mem.find(-8)->a;
                if (!code.in_code(r)) return std::nullopt;
                i.kind = IK_CALL;
                i.target = tgt.a;
                i.ret = r;
                return i;
            }
            i.kind = IK_JMP;
            i.target = tgt.a;
            return i;
        }
        if (tgt.k == VSEL && kind == IK_JMP) {
            if (!(code.in_code(tgt.a) && code.in_code(tgt.b))) return std::nullopt;
            i.kind = IK_JCC;
            i.cc = tgt.cc;
            i.target = tgt.a;
            i.fall = tgt.b;
            return i;
        }
        return std::nullopt;
    };
    for (int it = 0; it < max_insns; ++it) {
        if (!seen.insert(pc)) return std::nullopt;
        if (!code.insn(pc, d)) return std::nullopt;
        const uint16_t m = d.mid;
        const std::string_view op = d.ops();
        insns.emplace_back(pc, d.size);
        const int64_t nxt = pc + d.size;
        if (m == M_JMP) {
            int64_t t;
            if (hex_op(op, t)) {
                pc = t;
                continue;
            }
            auto dd = rsp_disp(op);
            if (!dd) return std::nullopt;
            return finish(mem.get(sp + *dd), pc);
        }
        if (m == M_RET) {
            if (!op.empty()) return std::nullopt;
            const Val tgt = mem.get(sp);
            sp += 8;
            return finish(tgt, pc);
        }
        if (!step_plain(code, m, op, nxt, regs, mem, sp, false)) return std::nullopt;
        pc = nxt;
    }
    return std::nullopt;
}

// --------------------------------------------------------- match_chain --

ChainP match_chain(Code& code, int64_t s) {
    InsnList insns;
    int64_t pc = s;
    int budget = 400;
    struct X {
        int64_t a;
        int size;
        uint16_t m;
        std::string op;
    };
    auto step = [&](X& x) -> bool {
        Lite d;
        while (budget > 0) {
            --budget;
            if (!code.insn(pc, d)) return false;
            int64_t t;
            if (d.mid == M_JMP && hex_op(d.ops(), t)) {
                insns.emplace_back(pc, d.size);
                pc = t;
                continue;
            }
            if (d.mid == M_LEA || d.mid == M_MOV || d.mid == M_PUSH) {
                auto idm = resolve_idiom(code, pc);
                if (idm && idm->kind == IK_JMP) {
                    insns.insert(insns.end(), idm->insns.begin(), idm->insns.end());
                    pc = idm->target;
                    continue;
                }
            }
            x.a = pc;
            x.size = d.size;
            x.m = d.mid;
            x.op.assign(d.ops());
            return true;
        }
        return false;
    };
    std::vector<int> pushes;
    X x;
    while (true) {
        if (!step(x)) return nullptr;
        int r = -1;
        if (x.m == M_PUSH) {
            const int g = gpr_index(x.op);
            if (g >= 0 && g != REG_RSP) r = g;
        } else if (x.m == M_PUSHFQ) {
            r = REG_FLAGS;
        }
        if (r >= 0) {
            if (std::find(pushes.begin(), pushes.end(), r) != pushes.end()) return nullptr;
            pushes.push_back(r);
            insns.emplace_back(x.a, x.size);
            pc = x.a + x.size;
            continue;
        }
        break;
    }
    if (pushes.empty()) return nullptr;
    if (!(x.m == M_LEA && lea_rsp_disp(x.op) == -0x100)) return nullptr;
    insns.emplace_back(x.a, x.size);
    pc = x.a + x.size;
    std::vector<std::pair<int64_t, std::string>> xsave;  // dict: offset -> xmm (insertion order)
    auto xs_set = [&xsave](int64_t off, std::string v) {
        for (auto& e : xsave)
            if (e.first == off) {
                e.second = std::move(v);
                return;
            }
        xsave.emplace_back(off, std::move(v));
    };
    for (int k = 0; k < 16; ++k) {
        if (!step(x)) return nullptr;
        auto ops = split_cs(x.op);
        if (!mf(x.m, F_XMM) || ops.size() != 2 || !starts(ops[1], "xmm")) return nullptr;
        auto off = xmm_rsp(ops[0]);
        if (!off) return nullptr;
        xs_set(*off, std::string(ops[1]));
        insns.emplace_back(x.a, x.size);
        pc = x.a + x.size;
    }
    {
        std::vector<int64_t> offs;
        for (auto& e : xsave) offs.push_back(e.first);
        std::sort(offs.begin(), offs.end());
        if (offs.size() != 16) return nullptr;
        for (int k = 0; k < 16; ++k)
            if (offs[static_cast<size_t>(k)] != 0x10 * k) return nullptr;
        std::vector<std::string> vals;
        for (auto& e : xsave) vals.push_back(e.second);
        std::sort(vals.begin(), vals.end());
        if (std::unique(vals.begin(), vals.end()) != vals.end()) return nullptr;
    }
    auto xs_get = [&xsave](int64_t off) -> const std::string* {
        for (auto& e : xsave)
            if (e.first == off) return &e.second;
        return nullptr;
    };
    if (!step(x) || !(x.m == M_PUSH && x.op == "0x10")) return nullptr;
    insns.emplace_back(x.a, x.size);
    pc = x.a + x.size;
    if (!step(x) || !(x.m == M_TEST && x.op == "rsp, 0xf")) return nullptr;
    insns.emplace_back(x.a, x.size);
    pc = x.a + x.size;
    int64_t L;
    if (!step(x) || x.m != M_JNE || !hex_op(x.op, L)) return nullptr;
    insns.emplace_back(x.a, x.size);
    pc = x.a + x.size;
    if (!step(x) || !(x.m == M_PUSH && x.op == "0x18")) return nullptr;
    insns.emplace_back(x.a, x.size);
    pc = x.a + x.size;
    if (!step(x) || x.a != L) return nullptr;
    static const uint8_t LONG_SUB8[7] = {0x48, 0x81, 0xEC, 0x08, 0x00, 0x00, 0x00};
    if (L < 0 || L + 7 > code.image().len || std::memcmp(code.image().mem.data() + L, LONG_SUB8, 7) != 0) return nullptr;
    insns.emplace_back(L, 7);
    pc = L + 7;
    if (!step(x)) return nullptr;
    auto ch = std::make_shared<Chain>();
    int64_t t;
    if (x.m == M_CALL && hex_op(x.op, t)) {
        ch->G = t;
        ch->R = x.a + x.size;
        ch->call_form = "call";
        insns.emplace_back(x.a, x.size);
    } else {
        auto idm = resolve_idiom(code, x.a);
        if (!idm || idm->kind != IK_CALL) return nullptr;
        ch->G = idm->target;
        ch->R = idm->ret;
        ch->call_form = "push-ret";
        insns.insert(insns.end(), idm->insns.begin(), idm->insns.end());
    }
    pc = ch->R;
    static const uint8_t ADD_RSP_RSP8[5] = {0x48, 0x03, 0x64, 0x24, 0x08};
    if (!step(x)) return nullptr;
    if (x.a < 0 || x.a + 5 > code.image().len || std::memcmp(code.image().mem.data() + x.a, ADD_RSP_RSP8, 5) != 0) {
        // Python compares bytes(mem[a:a+5]); a shorter slice never equals
        return nullptr;
    }
    insns.emplace_back(x.a, x.size);
    pc = x.a + x.size;
    for (int k = 0; k < 16; ++k) {
        if (!step(x)) return nullptr;
        auto ops = split_cs(x.op);
        if (!mf(x.m, F_XMM) || ops.size() != 2) return nullptr;
        auto off = xmm_rsp(ops[1]);
        if (!off) return nullptr;
        const std::string* sv = xs_get(*off);
        if (!sv || *sv != ops[0]) return nullptr;
        insns.emplace_back(x.a, x.size);
        pc = x.a + x.size;
    }
    if (!step(x) || !(x.m == M_LEA && lea_rsp_disp(x.op) == 0x100)) return nullptr;
    insns.emplace_back(x.a, x.size);
    pc = x.a + x.size;
    for (auto it = pushes.rbegin(); it != pushes.rend(); ++it) {
        if (!step(x)) return nullptr;
        if (*it == REG_FLAGS) {
            if (!(x.m == M_POPFQ && x.op.empty())) return nullptr;
        } else {
            if (!(x.m == M_POP && x.op == GPR64[*it])) return nullptr;
        }
        insns.emplace_back(x.a, x.size);
        pc = x.a + x.size;
    }
    ch->S = s;
    ch->E_raw = pc;
    ch->sub_site = L;
    ch->push_order = pushes;
    // E: skip plain joining jumps / jmp idioms after the restore (they are
    // appended to the same instruction list, as in the Python)
    const bool got = step(x);
    ch->E = got ? x.a : pc;
    ch->insns = std::move(insns);
    return ch;
}

// ------------------------------------------------------- RoutineModel --

static int64_t parse_hex_key(const std::string& k) {
    std::string_view s = k;
    if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s.remove_prefix(2);
    uint64_t v = 0;
    for (char c : s) {
        v <<= 4;
        if (c >= '0' && c <= '9') v |= static_cast<uint64_t>(c - '0');
        else if (c >= 'a' && c <= 'f') v |= static_cast<uint64_t>(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') v |= static_cast<uint64_t>(c - 'A' + 10);
        else throw std::runtime_error("bad hex " + k);
    }
    return static_cast<int64_t>(v);
}

static int64_t as_int_any(const Json& j) {
    if (j.is_str()) return std::stoll(j.as_str());
    return j.as_int();
}

void RoutineModel::load(const std::string& path, uint64_t image_base) { load_from(load_json(path), image_base); }

void RoutineModel::load_from(const Json& top, uint64_t image_base) {
    const Json* tabp = top.get("routines");
    const Json& tab = tabp ? *tabp : top;
    for (size_t i = 0; i < tab.keys().size(); ++i) {
        const std::string& k = tab.keys()[i];
        const Json& v = tab.at(i);
        const int64_t g = parse_hex_key(k);
        const Json* stub = v.get("stub");
        const Json* cont = nullptr;
        Json empty = Json::array();
        bool stub_dict = stub && stub->is_obj();
        if (stub_dict) {
            const Json* sk = stub->get("stub");
            if (sk && sk->is_str() && sk->as_str() == "none") {
                not_routines.push_back(g);
                continue;
            }
            if (sk && sk->is_str() && sk->as_str() == "continuation")
                cont = stub->get("cont");
            else
                cont = &empty;
        } else {
            cont = v.get("cont");
        }
        RoutineInfo m;
        if (const Json* f = v.get("form"); f && f->is_str()) m.form = f->as_str();
        if (const Json* c = v.get("class")) m.klass = *c;
        if (cont && cont->truthy())
            for (const Json& e : cont->items())
                m.cont.emplace_back(as_int_any(e.items()[0]),
                                    parse_hex_key(e.items()[1].as_str()) - static_cast<int64_t>(image_base));
        if (const Json* rc = v.get("regs_changed"); rc && rc->truthy())
            for (const Json& e : rc->items()) m.regs_changed.push_back(e.as_str());
        if (const Json* pr = v.get("proof")) {
            bool any = false;
            if (pr->truthy())
                for (const Json& x : pr->items()) {
                    if (!x.is_obj()) continue;
                    const Json* kd = x.get("kind");
                    const Json* ps = x.get("pass");
                    if (kd && kd->is_str() && kd->as_str() == "chain" && ps && ps->truthy()) {
                        any = true;
                        break;
                    }
                }
            m.proven = any ? 1 : 0;
        }
        if (stub_dict) {
            const Json* r8 = stub->get("r8");
            m.stub_r8 = r8 && !r8->is_null();
        }
        if (const Json* cl = v.get("clobbers"); cl && !cl->is_null()) {
            m.has_clobbers = true;
            for (const Json& e : cl->items()) m.clobbers.push_back(e.as_str());
        }
        if (const Json* pb = v.get("publishes"); pb && pb->truthy()) {
            m.publishes = true;
            for (const Json& e : pb->items()) m.publish_rvas.push_back(parse_hex_key(e.items()[0].as_str()));
        }
        if (r.find(g) == r.end()) order.push_back(g);
        r[g] = std::move(m);
        const Json* w = v.get("success_writes");
        if (!w || !w->truthy()) w = v.get("writes");
        if (w && w->truthy())
            for (const Json& e : w->items()) writes.emplace_back(as_int_any(*e.get("rva")), as_int_any(*e.get("size")));
    }
}

Effect RoutineModel::effect(const Chain& ch) {
    Effect e;
    auto it = r.find(ch.G);
    if (it == r.end()) {
        e.kind = Effect::UNKNOWN;
        e.why = "routine not in table";
        return e;
    }
    const RoutineInfo& m = it->second;
    if (m.form && *m.form == "call") {
        e.kind = Effect::NET;
        return e;
    }
    const auto& c = m.cont;
    if (c.size() != 3) {
        e.kind = Effect::UNKNOWN;
        e.why = "continuation has " + std::to_string(c.size()) + " slots";
        return e;
    }
    const int64_t o = 0x118 + 8 * static_cast<int64_t>(ch.push_order.size());
    const bool ok1 = c[0].first == o && c[1].first == o + 8 && c[2].first == o + 16;
    const bool ok2 = c[0].first == o + 8 && c[1].first == o + 16 && c[2].first == o + 24;
    if (!ok1 && !ok2) {
        e.kind = Effect::UNKNOWN;
        e.why = "continuation offsets [" + std::to_string(c[0].first) + ", " + std::to_string(c[1].first) + ", " +
                std::to_string(c[2].first) + "], expected " + std::to_string(o);
        return e;
    }
    auto saved = [&ch](int rid) {
        return std::find(ch.push_order.begin(), ch.push_order.end(), rid) != ch.push_order.end();
    };
    if (m.has_clobbers && m.proven != 1) {
        for (const std::string& s : m.clobbers) {
            const int rid = reg_id(s);
            if (!saved(rid)) e.clob.push_back(rid);
        }
    } else if (m.proven == 1) {
        std::vector<std::string> l = {"rax", "rcx", "rdx"};
        if (m.stub_r8) l.push_back("r8");
        for (const std::string& s : l) {
            const int rid = reg_id(s);
            if (!saved(rid)) e.clob.push_back(rid);
        }
    } else if (m.proven == 0) {
        e.kind = Effect::UNKNOWN;
        e.why = "the routine's chain proof did not pass";
        return e;
    } else {
        std::vector<std::string> l = {"rax", "rcx", "rdx", "r8", "r9", "r10", "r11"};
        for (const std::string& s : m.regs_changed) l.push_back(s);
        std::vector<std::string> keep;
        for (const std::string& s : l)
            if (gpr_index(s) >= 0 && s != "rsp") keep.push_back(s);
        std::sort(keep.begin(), keep.end());
        keep.erase(std::unique(keep.begin(), keep.end()), keep.end());
        for (const std::string& s : keep) e.clob.push_back(reg_id(s));
    }
    if (m.extra) extra_used.insert(ch.G);
    e.kind = Effect::CONT;
    for (int k = 0; k < 3; ++k) e.t[static_cast<size_t>(k)] = c[static_cast<size_t>(k)].second;
    return e;
}

// --------------------------------------------------- resolve_construct --

namespace {

struct St {
    RegMap regs;
    MemMap mem;
    int64_t sp = 0;
    InsnList insns;
    std::vector<std::pair<ChainP, Effect>> inner;
    bool flags_clob = false;
    RegSet clob = 0;
    SmallSet seen;
    int n = 0;
};

bool continuable(Code& code, int64_t t) {
    Lite d;
    if (!code.insn(t, d)) return false;
    const uint16_t m = d.mid;
    if (mf(m, F_IDIOM_FIRST) || (m == M_RET && d.olen == 0) || m == M_PUSHFQ) return true;
    if (m == M_JMP) {
        int64_t v;
        return starts(d.ops(), "0x") || rsp_disp(d.ops()).has_value() || hex_op(d.ops(), v);
    }
    return false;
}

Construct finish2(Code& code, int64_t a, St& st, const Val& tgt, int64_t endpc) {
    for (int r = 0; r < 64; ++r)
        if (st.regs.present >> r & 1) {
            const Val& v = st.regs.v[static_cast<size_t>(r)];
            if (v != Val::R(r) && v != Val::Clob(r)) return {};
        }
    const int64_t sp = st.sp;
    int kind;
    if (sp == -8) {
        const Val* rv = st.mem.find(-8);
        if (!rv || rv->k != VC) return {};
        kind = IK_CALL;
    } else if (sp >= 0 && sp % 8 == 0) {
        kind = sp == 0 ? IK_JMP : IK_POPJMP;
    } else {
        return {};
    }
    for (const auto& [off, v] : st.mem.e)
        if (off >= sp && !(kind == IK_CALL && off == -8))
            if (v != Val::M(off)) return {};
    auto i = std::make_shared<Idiom>();
    i->start = a;
    i->insns = st.insns;
    i->end = endpc;
    for (auto& [c, e] : st.inner) i->inner.push_back(c);
    if (tgt.k == VC) {
        if (!code.in_code(tgt.a)) return {};
        if (kind == IK_CALL) {
            const int64_t r = st.mem.find(-8)->a;
            if (!code.in_code(r)) return {};
            i->kind = IK_CALL;
            i->target = tgt.a;
            i->ret = r;
        } else {
            i->kind = static_cast<uint8_t>(kind);
            i->target = tgt.a;
        }
    } else if (tgt.k == VSEL && kind == IK_JMP) {
        if (!(code.in_code(tgt.a) && code.in_code(tgt.b))) return {};
        i->kind = IK_JCC;
        i->cc = tgt.cc;
        i->target = tgt.a;
        i->fall = tgt.b;
    } else {
        return {};
    }
    i->pop = kind == IK_POPJMP ? sp / 8 : 0;
    for (auto& [c, e] : st.inner) i->effects.push_back(e);
    i->flags_clob = st.flags_clob;
    i->clob = sorted_regs(st.clob);
    Construct r;
    r.idm = i;
    return r;
}

Construct eval(Code& code, int64_t a, int64_t pc, St& st, int depth, int max_insns, int max_depth) {
    RoutineModel* model = code.model;
    Lite d;
    while (st.n < max_insns) {
        st.n += 1;
        if (!st.seen.insert(pc)) return {};
        if (!code.insn(pc, d)) return {};
        const uint16_t m = d.mid;
        if ((m == M_PUSH && gpr_index(d.ops()) >= 0) || m == M_PUSHFQ) {
            ChainP ch = match_chain(code, pc);
            if (ch) {
                Effect eff;
                if (model) eff = model->effect(*ch);
                if (eff.kind == Effect::UNKNOWN) {
                    auto u = std::make_shared<Unknown>();
                    u->start = a;
                    u->chain = ch;
                    u->why = eff.why;
                    u->insns = st.insns;
                    u->insns.insert(u->insns.end(), ch->insns.begin(), ch->insns.end());
                    Construct r;
                    r.unk = u;
                    return r;
                }
                st.insns.insert(st.insns.end(), ch->insns.begin(), ch->insns.end());
                if (!ch->saves_flags()) st.flags_clob = true;
                if (eff.kind == Effect::CONT) {
                    st.mem.set(st.sp, Val::C(eff.t[0]));
                    st.mem.set(st.sp + 8, Val::C(eff.t[1]));
                    st.mem.set(st.sp + 16, Val::C(eff.t[2]));
                    for (int r : eff.clob) {
                        st.regs.set(r, Val::Clob(r));
                        st.clob |= RegSet(1) << r;
                    }
                }
                pc = ch->E_raw;
                st.inner.emplace_back(ch, std::move(eff));
                continue;
            }
        }
        st.insns.emplace_back(pc, d.size);
        const int64_t nxt = pc + d.size;
        const std::string_view op = d.ops();
        if (m == M_JMP || m == M_RET) {
            Val tgt;
            if (m == M_JMP) {
                int64_t t;
                if (hex_op(op, t)) {
                    pc = t;
                    continue;
                }
                auto dd = rsp_disp(op);
                if (!dd) return {};
                tgt = st.mem.get(st.sp + *dd);
            } else {
                if (!op.empty()) return {};
                tgt = st.mem.get(st.sp);
                st.sp += 8;
            }
            if (tgt.k == VC && depth < max_depth && continuable(code, tgt.a)) {
                St c = st;
                Construct r = eval(code, a, tgt.a, c, depth + 1, max_insns, max_depth);
                if (r.idm || r.unk) return r;
            }
            return finish2(code, a, st, tgt, pc);
        }
        if (!step_plain(code, m, op, nxt, st.regs, st.mem, st.sp, st.flags_clob)) return {};
        pc = nxt;
    }
    return {};
}

}  // namespace

Construct resolve_construct(Code& code, int64_t a, int max_insns, int max_depth) {
    Lite d;
    if (!code.insn(a, d) || !(mf(d.mid, F_IDIOM_FIRST) || d.mid == M_PUSHFQ)) return {};
    St st;
    return eval(code, a, a, st, 0, max_insns, max_depth);
}

}  // namespace flow
