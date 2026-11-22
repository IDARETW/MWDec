// tools/devirt_boot.py and the parts of tools/entry_layout.py it uses, in
// C++. The steps follow the Python line for line; the reasons are written
// there.
#include "flow/boot.h"

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <map>
#include <regex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>

#include "flow/code.h"
#include "flow/pyutil.h"
#include "flow/tables.h"

namespace flow {

namespace {

// a symbolic value: None, an RVA, or ("cc", cond, A, B)
struct SV {
    int t = 0;  // 0 None, 1 int, 2 cc
    int64_t v = 0;
    std::string cc;
    int64_t a = 0, b = 0;
    static SV I(int64_t x) {
        SV s;
        s.t = 1;
        s.v = x;
        return s;
    }
};

struct Row {
    int64_t rva;
    std::string text, kind;
    int et = 0;  // extra: 0 None, 1 int, 2 (tgt, ret_to)
    int64_t e1 = 0, e2 = 0;
};

struct Line {
    int64_t rva;
    std::string text, kind;
};

int64_t floordiv(int64_t a, int64_t b) {
    int64_t q = a / b;
    if ((a % b != 0) && ((a < 0) != (b < 0))) --q;
    return q;
}

std::string h8(int64_t v) {
    char b[32];
    std::snprintf(b, sizeof b, "%08llX", static_cast<unsigned long long>(v));
    return b;
}

// entry_layout.Walker.walk
std::vector<Row> walk(const FImage& im, int64_t start) {
    const int MAX_STEPS = 4000;
    std::vector<Row> rows;
    std::vector<SV> stack;
    SV below;
    std::unordered_map<unsigned, SV> regval;
    SV prepush;
    std::unordered_set<int64_t> seen;
    int64_t pc = start;
    auto pop = [&stack]() {
        if (stack.empty()) return SV();
        SV v = stack.back();
        stack.pop_back();
        return v;
    };
    auto get = [&regval](unsigned r) {
        auto it = regval.find(r);
        return it == regval.end() ? SV() : it->second;
    };
    bool broke = false;
    for (int step = 0; step < MAX_STEPS; ++step) {
        if (seen.count(pc)) {
            rows.push_back({pc, "(loops back to " + h8(pc) + ")", "end"});
            broke = true;
            break;
        }
        seen.insert(pc);
        const cs_insn* i = fresh_full(im, pc, 16);
        if (!i) {
            rows.push_back({pc, "(undecodable: still encrypted?)", "end"});
            broke = true;
            break;
        }
        const cs_x86& x = i->detail->x86;
        const cs_x86_op* ops = x.operands;
        const int nops = x.op_count;
        const std::string m = i->mnemonic;
        const int64_t nxt = pc + i->size;
        std::string text = m + " " + i->op_str;
        while (!text.empty() && text.back() == ' ') text.pop_back();
        while (!text.empty() && text.front() == ' ') text.erase(text.begin());
        auto is_rsp_mem = [](const cs_x86_op& op, int64_t disp) {
            return op.type == X86_OP_MEM && op.mem.base == X86_REG_RSP && op.mem.index == 0 && op.mem.disp == disp;
        };
        if (m == "jmp" && nops > 0 && ops[0].type == X86_OP_IMM) {
            rows.push_back({pc, text, "flow", 1, ops[0].imm});
            pc = ops[0].imm;
            continue;
        }
        if ((m == "jmp" && nops > 0 && is_rsp_mem(ops[0], -8)) || m == "ret") {
            SV tgt = m == "jmp" ? below : pop();
            below = SV();
            if (tgt.t == 2) {
                rows.push_back({pc, "j" + tgt.cc + " " + h8(tgt.b), "cjcc", 1, tgt.b});
                pc = tgt.a;
                continue;
            }
            if (tgt.t == 0) {
                rows.push_back({pc, text, "end"});
                broke = true;
                break;
            }
            SV ret_to = (m == "ret" && !stack.empty()) ? stack.back() : SV();
            if (ret_to.t == 1) {
                rows.push_back({pc, "call " + h8(tgt.v), "ccall", 2, tgt.v, ret_to.v});
                stack.pop_back();
                pc = ret_to.v;
            } else {
                rows.push_back({pc, "jmp " + h8(tgt.v), "cjmp", 1, tgt.v});
                pc = tgt.v;
            }
            continue;
        }
        if (m == "jmp") {
            rows.push_back({pc, text, "end"});
            broke = true;
            break;
        }
        if (m == "call" && nops > 0 && ops[0].type == X86_OP_IMM) {
            rows.push_back({pc, "call " + h8(ops[0].imm), "call", 1, ops[0].imm});
            pc = nxt;
            continue;
        }
        if (!m.empty() && m[0] == 'j' && nops > 0 && ops[0].type == X86_OP_IMM) {
            rows.push_back({pc, text, "jcc", 1, ops[0].imm});
            pc = nxt;
            continue;
        }
        // the symbolic stack and registers
        SV below_next;
        auto slot = [&stack](int64_t disp) -> int64_t {
            if (disp < 0 || disp % 8) return -1;
            const int64_t k = disp / 8;
            return k < static_cast<int64_t>(stack.size()) ? static_cast<int64_t>(stack.size()) - 1 - k : -1;
        };
        const unsigned r0 = (nops > 0 && ops[0].type == X86_OP_REG) ? ops[0].reg : 0;
        bool keep = false;
        if (m == "push" || m == "pushfq") {
            stack.push_back(SV());
        } else if (m == "pop" || m == "popfq") {
            below_next = pop();
        } else if (m == "lea" && r0 == X86_REG_RSP && ops[1].mem.base == X86_REG_RSP && ops[1].mem.index == 0) {
            const int64_t d = ops[1].mem.disp;
            if (d < 0) {
                stack.push_back(prepush);
                for (int64_t k = 0; k < floordiv(-d, 8) - 1; ++k) stack.push_back(SV());
            } else {
                for (int64_t k = 0; k < floordiv(d, 8); ++k) below_next = pop();
            }
        } else if ((m == "sub" || m == "add") && r0 == X86_REG_RSP) {
            if (ops[1].type == X86_OP_IMM) {
                const int64_t n = floordiv(ops[1].imm, 8);
                if (m == "sub")
                    for (int64_t k = 0; k < n; ++k) stack.push_back(SV());
                else
                    for (int64_t k = 0; k < n; ++k) pop();
            } else {
                stack.clear();
            }
        } else if (m == "lea" && r0 && ops[1].mem.base == X86_REG_RIP) {
            regval[r0] = SV::I(nxt + ops[1].mem.disp);
            keep = true;
        } else if ((m == "mov" || m == "movabs") && r0 && ops[1].type == X86_OP_IMM &&
                   static_cast<int64_t>(im.image_base) <= ops[1].imm &&
                   ops[1].imm < static_cast<int64_t>(im.image_base) + im.len) {
            regval[r0] = SV::I(ops[1].imm - static_cast<int64_t>(im.image_base));
            keep = true;
        } else if (m == "mov" && r0 && ops[1].type == X86_OP_MEM && ops[1].mem.base == X86_REG_RSP &&
                   ops[1].mem.index == 0 && slot(ops[1].mem.disp) >= 0) {
            regval[r0] = stack[static_cast<size_t>(slot(ops[1].mem.disp))];
            keep = true;
        } else if (m.rfind("cmov", 0) == 0 && r0 && ops[1].type == X86_OP_REG) {
            const SV a_ = get(r0), b_ = get(ops[1].reg);
            if (a_.t == 1 && b_.t == 1) {
                SV c;
                c.t = 2;
                c.cc = m.substr(4);
                c.a = a_.v;
                c.b = b_.v;
                regval[r0] = c;
                keep = true;
            }
        } else if (m == "xchg" && nops > 1 && is_rsp_mem(ops[0], 0) && ops[1].type == X86_OP_REG) {
            const SV v = get(ops[1].reg);
            const SV old = stack.empty() ? SV() : stack.back();
            if (!stack.empty())
                stack.back() = v;
            else
                stack.push_back(v);
            regval[ops[1].reg] = old;
        } else if (m == "mov" && nops > 1 && ops[0].type == X86_OP_MEM && ops[0].mem.base == X86_REG_RSP &&
                   ops[0].mem.index == 0 && ops[1].type == X86_OP_REG) {
            const SV v = get(ops[1].reg);
            if (ops[0].mem.disp == -8) {
                prepush = v;
                below = SV();
                rows.push_back({pc, text, "insn"});
                pc = nxt;
                continue;
            }
            if (slot(ops[0].mem.disp) >= 0) stack[static_cast<size_t>(slot(ops[0].mem.disp))] = v;
        }
        if (r0 && !keep && m != "cmp" && m != "test" && m != "push" && m != "xchg") regval.erase(r0);
        prepush = SV();
        below = below_next;
        rows.push_back({pc, text, "insn"});
        pc = nxt;
    }
    if (!broke) rows.push_back({pc, "(stopped after " + std::to_string(MAX_STEPS) + " steps)", "end"});
    return rows;
}

const std::regex& glue() {
    static const std::regex r(
        R"(lea rsp, \[rsp [-+] 8\]|mov qword ptr \[rsp( [-+] (8|0x10))?\], r\w+$|)"
        R"(xchg qword ptr \[rsp\], r\w+$|push r\w+$|pop r\w+$|movabs r\w+, 0x1[4-6]\w{7}$|)"
        R"(lea r\w+, \[rip [-+] 0x\w+\]$|mov r\w+, qword ptr \[rsp( [-+] (8|0x10))?\]$|cmov\w+ r\w+, r\w+$)");
    return r;
}

bool glue_match(const std::string& s) {
    return std::regex_search(s, glue(), std::regex_constants::match_continuous);
}

bool sw(const std::string& s, const char* p) { return s.rfind(p, 0) == 0; }

// entry_layout.fold
std::vector<Line> fold(const std::vector<Row>& rows) {
    static const std::set<std::string> GPR = {"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "r8",
                                              "r9",  "r10", "r11", "r12", "r13", "r14", "r15"};
    std::vector<Line> out;
    const size_t n = rows.size();
    size_t k = 0;
    auto txt = [&](size_t j) -> std::string { return j < n ? rows[j].text : std::string(); };
    auto first_part = [](const std::string& t) { return t.substr(0, t.find(',')); };
    auto last_part = [](const std::string& t) {
        const size_t c = t.rfind(',');
        return c == std::string::npos ? t : t.substr(c + 1);
    };
    while (k < n) {
        const Row& r = rows[k];
        const std::string& text = r.text;
        if (r.kind == "flow") {
            ++k;
            continue;
        }
        if (r.kind == "cjmp" || r.kind == "ccall" || r.kind == "cjcc") {
            int removed = 0;
            while (!out.empty() && removed < 24 && out.back().kind == "insn" && glue_match(out.back().text)) {
                out.pop_back();
                ++removed;
            }
            out.push_back({r.rva, text, r.kind});
            ++k;
            continue;
        }
        if (sw(text, "push ") && (GPR.count(text.substr(5)) || text.substr(5) == "rsp")) {
            size_t j = k;
            std::vector<std::string> regs;
            while (j < n && (rows[j].kind == "flow" || (sw(txt(j), "push ") && GPR.count(txt(j).substr(5))) ||
                             txt(j) == "pushfq")) {
                if (rows[j].kind != "flow") regs.push_back(txt(j) != "pushfq" ? txt(j).substr(5) : "flags");
                ++j;
            }
            int xm = 0;
            if (regs.size() >= 8) {
                size_t jj = j;
                while (jj < n && (rows[jj].kind == "flow" || sw(txt(jj), "lea rsp, [rsp - 0x") ||
                                  (sw(txt(jj), "mov") && txt(jj).find("xmm") != std::string::npos &&
                                   first_part(txt(jj)).find("[rsp") != std::string::npos))) {
                    xm += txt(jj).find("xmm") != std::string::npos;
                    ++jj;
                }
                out.push_back({r.rva, "; save context: " + std::to_string(regs.size()) + " registers" +
                                          (xm ? ", " + std::to_string(xm) + " XMM" : ""),
                               "fold"});
                k = jj;
                continue;
            }
        }
        if (text.find("xmm") != std::string::npos && sw(text, "mov") &&
            last_part(text).find("[rsp") != std::string::npos) {
            size_t j = k;
            int xm = 0;
            while (j < n && (rows[j].kind == "flow" || (sw(txt(j), "mov") && txt(j).find("xmm") != std::string::npos) ||
                             sw(txt(j), "lea rsp, [rsp + 0x"))) {
                xm += txt(j).find("xmm") != std::string::npos;
                ++j;
            }
            int regs = 0;
            while (j < n && (rows[j].kind == "flow" || sw(txt(j), "pop ") || txt(j) == "popfq")) {
                regs += rows[j].kind != "flow";
                ++j;
            }
            if (xm >= 8) {
                out.push_back({r.rva,
                               "; restore context: " + std::to_string(xm) + " XMM, " + std::to_string(regs) + " registers",
                               "fold"});
                k = j;
                continue;
            }
        }
        if (text == "push 0x10" && txt(k + 1).find("test rsp, 0xf") != std::string::npos) {
            size_t j = k + 2;
            while (j < n && (rows[j].kind == "flow" || rows[j].kind == "jcc" || txt(j) == "push 0x18" ||
                             txt(j) == "sub rsp, 8"))
                ++j;
            out.push_back({r.rva, "; align stack to 16 (pushes 0x10 or 0x18, then sub rsp,8)", "fold"});
            k = j;
            continue;
        }
        if (text == "add rsp, qword ptr [rsp + 8]") {
            out.push_back({r.rva, "; undo stack alignment", "fold"});
            ++k;
            continue;
        }
        out.push_back({r.rva, text, r.kind});
        ++k;
    }
    return out;
}

// devirt_boot.continuation: (address, set) and the routine calls counted
std::pair<std::optional<int64_t>, int64_t> continuation(const FImage& im, int64_t start) {
    const std::vector<Row> rows = walk(im, start);
    const std::vector<Line> lines = fold(rows);
    if (lines.empty() || !sw(lines[0].text, "; save context")) return {std::nullopt, 0};
    int64_t last = -1;
    for (size_t i = 0; i < lines.size(); ++i)
        if (sw(lines[i].text, "; restore context")) last = static_cast<int64_t>(i);
    if (last < 0) throw std::runtime_error("max() arg is an empty sequence (continuation)");
    int64_t calls = 0;
    for (int64_t i = 0; i < last; ++i)
        calls += lines[static_cast<size_t>(i)].kind == "call" || lines[static_cast<size_t>(i)].kind == "ccall";
    if (last + 1 >= static_cast<int64_t>(lines.size())) return {std::nullopt, calls};
    const Line& l = lines[static_cast<size_t>(last + 1)];
    if (l.kind == "cjmp")
        for (const Row& r : rows)
            if (r.rva == l.rva && r.kind == "cjmp") return {r.e1, calls};
    if (l.kind == "fold") return {std::nullopt, calls};
    return {l.rva, calls};
}

std::vector<uint8_t> le(int64_t v, int n) {
    std::vector<uint8_t> b;
    for (int i = 0; i < n; ++i) b.push_back(static_cast<uint8_t>(static_cast<uint64_t>(v) >> (8 * i)));
    return b;
}

}  // namespace

BootOut devirt_boot(const FImage& im, const std::string& imports_tsv) {
    BootOut out;
    out.report = Json::object();
    Json& rep = out.report;
    // ---- entry point: the first call within the first few instructions
    int64_t pc = im.entry_rva;
    for (int k = 0; k < 4; ++k) {
        const cs_insn* i = fresh_full(im, pc, 16);
        if (!i) break;
        const cs_x86& x = i->detail->x86;
        if (std::string(i->mnemonic) == "call" && x.op_count > 0 && x.operands[0].type == X86_OP_IMM && i->size == 5) {
            const int64_t thunk = x.operands[0].imm;
            const int64_t site = pc;
            const auto [callee, calls] = continuation(im, thunk);
            Json e = Json::object();
            e["call_site"] = Json(site);
            e["thunk"] = Json(thunk);
            if (callee) {
                out.plan.patches.push_back({static_cast<uint32_t>(site + 1), KIND_BOOT, le(*callee - (site + 5), 4)});
                e["routines_called"] = Json(calls);
                e["original_callee"] = Json(*callee);
            } else {
                e["note"] = Json("call target is not a thunk");
            }
            rep["entry_point"] = e;
            break;
        }
        pc += i->size;
    }
    // ---- TLS callbacks
    Json tls = Json::array();
    const auto cbs = im.tls_callbacks();
    for (size_t n = 0; n < cbs.size(); ++n) {
        const int64_t cb = cbs[n];
        const auto [body, calls] = continuation(im, cb);
        Json row = Json::object();
        row["index"] = Json(static_cast<int64_t>(n));
        row["callback"] = Json(cb);
        row["routines_called"] = Json(calls);
        row["body"] = body ? Json(*body) : Json();
        if (body) {
            if (im.mem[static_cast<size_t>(cb)] == 0xE9) {
                out.plan.patches.push_back({static_cast<uint32_t>(cb + 1), KIND_BOOT, le(*body - (cb + 5), 4)});
                row["patched"] = Json(true);
            } else {
                row["patched"] = Json(false);
                row["note"] = Json("callback does not begin with jmp rel32");
            }
        }
        tls.push(row);
    }
    rep["tls"] = tls;

    // ---- imports
    std::map<int64_t, int64_t> alias;  // slot of the second table -> slot of the loader's
    {
        std::istringstream in(imports_tsv);
        std::string line;
        bool first = true;
        while (std::getline(in, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (first) {
                first = false;
                continue;
            }
            std::vector<std::string> f;
            size_t a = 0;
            while (true) {
                const size_t t = line.find('\t', a);
                f.push_back(line.substr(a, t == std::string::npos ? std::string::npos : t - a));
                if (t == std::string::npos) break;
                a = t + 1;
            }
            if (f.size() >= 4 && !f[1].empty()) alias[std::stoll(f[1], nullptr, 16)] = std::stoll(f[0], nullptr, 16);
        }
    }
    if (alias.empty()) {
        Json e = Json::object();
        e["note"] = Json("no aliased slots");
        rep["imports"] = e;
        return out;
    }
    const int64_t lo = alias.begin()->first, hi = alias.rbegin()->first + 8;
    std::vector<uint8_t> is_slot(static_cast<size_t>(hi - lo), 0);
    for (const auto& [s, t] : alias) is_slot[static_cast<size_t>(s - lo)] = 1;
    auto slot_at = [&](int64_t t) { return t >= lo && t < hi && is_slot[static_cast<size_t>(t - lo)]; };
    std::vector<std::pair<std::string, int64_t>> by_mnem;
    int64_t rejected = 0;
    std::unordered_set<int64_t> patched_sites;
    const uint8_t* mem = im.mem.data();
    for (const PSection* s : im.exec_sections()) {
        const int64_t size = std::min(s->rsize, s->vsize);
        std::vector<int64_t> cand;
        for (int64_t p = s->rva; p < static_cast<int64_t>(s->rva) + size - 3; ++p) {
            int32_t d;
            std::memcpy(&d, mem + p, 4);
            const int64_t base = p + d;
            if (slot_at(base + 4) || slot_at(base + 5) || slot_at(base + 6) || slot_at(base + 8)) cand.push_back(p);
        }
        for (int64_t p : cand) {
            bool ok = false;
            for (int back = 1; back < 12; ++back) {
                const int64_t st = p - back;
                const cs_insn* i = fresh_full(im, st, 16);
                if (!i || i->detail->x86.encoding.disp_offset != back || i->detail->x86.encoding.disp_size != 4) continue;
                const cs_x86& x = i->detail->x86;
                bool have = false;
                int64_t tgt = 0;
                for (int k = 0; k < x.op_count; ++k)
                    if (x.operands[k].type == X86_OP_MEM && x.operands[k].mem.base == X86_REG_RIP) {
                        tgt = st + i->size + x.operands[k].mem.disp;
                        have = true;
                    }
                if (have && alias.count(tgt)) {
                    const int64_t nw = alias[tgt] - (st + i->size);
                    if (-(int64_t(1) << 31) <= nw && nw < (int64_t(1) << 31) && !patched_sites.count(p)) {
                        out.plan.patches.push_back({static_cast<uint32_t>(p), KIND_IMPORT, le(nw, 4)});
                        patched_sites.insert(p);
                        const std::string mn = i->mnemonic;
                        bool f = false;
                        for (auto& [k2, c] : by_mnem)
                            if (k2 == mn) {
                                ++c;
                                f = true;
                            }
                        if (!f) by_mnem.emplace_back(mn, 1);
                    }
                    ok = true;
                    break;
                }
            }
            rejected += !ok;
        }
    }
    // relocated data pointers that name a slot of the second table
    int64_t data_ptrs = 0;
    for (int64_t r : im.relocations()) {
        const int64_t v = static_cast<int64_t>(im.u64(r) - im.image_base);
        auto it = alias.find(v);
        if (it != alias.end()) {
            out.plan.patches.push_back({static_cast<uint32_t>(r), KIND_IMPORT,
                                        le(static_cast<int64_t>(im.image_base) + it->second, 8)});
            ++data_ptrs;
        }
    }
    // image-relative uses (report only)
    int64_t abs_hits = 0;
    for (const PSection* s : im.exec_sections()) {
        const int64_t size = std::min(s->rsize, s->vsize);
        for (int al = 0; al < 4; ++al) {
            const int64_t n = (size - al) / 4;
            for (int64_t k = 0; k < n; ++k) {
                uint32_t v;
                std::memcpy(&v, mem + s->rva + al + 4 * k, 4);
                if (slot_at(v)) ++abs_hits;
            }
        }
    }
    Json im_ = Json::object();
    im_["aliased_slots"] = Json(static_cast<int64_t>(alias.size()));
    im_["code_references_retargeted"] = Json(static_cast<int64_t>(patched_sites.size()));
    Json bm = Json::object();
    for (const auto& [k, c] : by_mnem) bm[k] = Json(c);
    im_["by_instruction"] = bm;
    im_["candidates_rejected_by_decode"] = Json(rejected);
    im_["data_pointers_retargeted"] = Json(data_ptrs);
    im_["image_relative_candidates_not_patched"] = Json(abs_hits);
    rep["imports"] = im_;
    return out;
}

int cmd_boot(int argc, char** argv) {
    std::string exe, imports, out, report;
    for (int i = 2; i < argc; ++i) {
        const std::string a = argv[i];
        auto val = [&]() -> std::string {
            if (i + 1 >= argc) throw std::runtime_error("missing value for " + a);
            return argv[++i];
        };
        if (a == "--imports") imports = val();
        else if (a == "-o") out = val();
        else if (a == "--report") report = val();
        else if (!a.empty() && a[0] == '-') throw std::runtime_error("unknown option " + a);
        else exe = a;
    }
    if (exe.empty() || imports.empty() || out.empty())
        throw std::runtime_error("usage: mwdec boot <dec.exe> --imports imports.tsv -o boot.plan [--report boot.json]");
    FImage im;
    im.load(exe);
    std::ifstream f(imports, std::ios::binary);
    std::stringstream ss;
    ss << f.rdbuf();
    const BootOut b = devirt_boot(im, ss.str());
    b.plan.save(out);
    std::printf("%s\n", b.plan.summary().c_str());
    if (!report.empty()) write_text_crlf(report, b.report.dump(1));
    return 0;
}

}  // namespace flow
