#include "flow/dec.h"

#include <array>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>

namespace flow {

const char* const CC_NAMES[16] = {"o", "no", "b", "ae", "e", "ne", "be", "a",
                                  "s", "ns", "p", "np", "l", "ge", "le", "g"};

int norm_cc(std::string_view c) {
    static const std::pair<const char*, const char*> alias[] = {
        {"c", "b"},   {"nae", "b"}, {"nc", "ae"}, {"nb", "ae"}, {"z", "e"},   {"nz", "ne"}, {"na", "be"},
        {"nbe", "a"}, {"pe", "p"},  {"po", "np"}, {"nge", "l"}, {"nl", "ge"}, {"ng", "le"}, {"nle", "g"}};
    for (const auto& [k, v] : alias)
        if (c == k) {
            c = v;
            break;
        }
    for (int i = 0; i < 16; ++i)
        if (c == CC_NAMES[i]) return i;
    return -1;
}

namespace {

constexpr size_t kMaxMn = 16384;

const char* const kKnown[M_KNOWN_END] = {
    "",       "push",   "pop",     "lea",   "mov",     "movabs", "xchg",      "jmp",       "call",   "ret",
    "pushfq", "popfq",  "test",    "jne",   "sub",     "add",    "cmp",       "nop",       "int",    "xor",
    "int3",   "pushf",  "lahf",    "popf",  "sahf",    "fxsave", "fxrstor",   "xsave",     "xrstor", "fxsave64",
    "fxrstor64", "ud2"};

struct Table {
    std::mutex mu;
    std::unordered_map<std::string, uint16_t> ids;
    std::unique_ptr<std::string[]> names{new std::string[kMaxMn]};
    std::unique_ptr<uint32_t[]> flags{new uint32_t[kMaxMn]()};
    std::unique_ptr<int8_t[]> cmovcc{new int8_t[kMaxMn]()};
    size_t n = 0;

    static uint32_t compute(const std::string& m, int8_t& cc) {
        static const std::unordered_set<std::string> stop = {"ret", "retf", "int3", "ud2", "hlt",
                                                             "iretq", "iretd", "int1", "sysret"};
        static const std::unordered_set<std::string> cond8 = {"loop", "loope", "loopne", "jrcxz", "jecxz", "jcxz"};
        static const std::unordered_set<std::string> xmm = {"movupd", "movups", "movdqu", "movaps", "movapd", "movdqa"};
        static const std::unordered_set<std::string> swbad = {
            "in",     "out",    "insb",    "insd",    "insw",    "outsb",    "outsd", "outsw", "hlt",   "cli",
            "sti",    "iretd",  "iretq",   "iret",    "retf",    "retfq",    "lcall", "ljmp",  "int",   "into",
            "bound",  "arpl",   "salc",    "getsec",  "sysenter", "sysexit", "sysret", "rsm",  "wrmsr", "rdmsr",
            "clts",   "lgdt",   "lidt",    "sgdt",    "sidt",    "lldt",     "sldt",  "ltr",   "str",   "xlatb",
            "loop",   "loope",  "loopne",  "jrcxz",   "jecxz",   "enter",    "int1",  "icebp", "lahf",  "sahf",
            "cmc",    "std",    "clc",     "stc",     "invd",    "wbinvd",   "lar",   "lsl",   "verr",  "verw",
            "smsw",   "lmsw",   "swapgs",  "rdpmc",   "wait",    "fwait",    "pushfq", "popfq", "vmcall", "vmlaunch",
            "vmresume", "vmxoff", "movsb", "movsd",   "movsw",   "movsq",    "cmpsb", "cmpsd", "cmpsw", "cmpsq",
            "scasb",  "scasd",  "scasw",   "scasq",   "lodsb",   "lodsd",    "lodsw", "lodsq", "stosb", "stosd",
            "stosw",  "stosq",  "xchg"};
        static const std::unordered_set<std::string> swsoft = {"movsb", "movsd", "movsw", "movsq", "cmpsb", "scasb",
                                                               "stosb", "stosd", "stosw", "stosq", "lodsb", "xchg",
                                                               "pushfq", "popfq", "clc", "stc", "cmc", "std",
                                                               "lahf", "sahf"};
        static const std::unordered_set<std::string> x87ok = {"fxsave", "fxrstor", "fnstcw", "fldcw", "fnclex", "femms"};
        uint32_t f = 0;
        cc = -1;
        if (m.size() > 1 && m[0] == 'j') {
            const int c = norm_cc(std::string_view(m).substr(1));
            if (c >= 0) f |= F_JCC;
        }
        if (cond8.count(m)) f |= F_COND8;
        if (stop.count(m)) f |= F_STOP | F_NOFALL;
        if (m == "push" || m == "lea" || m == "mov") f |= F_IDIOM_FIRST;
        if (xmm.count(m)) f |= F_XMM;
        if (m.rfind("cmov", 0) == 0) {
            f |= F_CMOV;
            cc = static_cast<int8_t>(norm_cc(std::string_view(m).substr(4)));
        }
        if (m == "jmp" || m == "ret" || m == "int3" || m == "ud2") f |= F_NOFALL | F_SWTERM;
        if (!m.empty() && m[0] == 'j') f |= F_J;
        std::string s = m;
        if (m.rfind("rep", 0) == 0 || m.rfind("lock", 0) == 0) {
            f |= F_REP;
            const size_t k = m.find(' ');
            if (k != std::string::npos) s = m.substr(k + 1);
        }
        if (swbad.count(s) && !swsoft.count(s)) f |= F_SWBAD;
        if (s == "int") f |= F_SWINT;
        if (!s.empty() && s[0] == 'f' && !x87ok.count(s)) f |= F_X87;
        return f;
    }

    uint16_t get(std::string_view m) {
        std::lock_guard<std::mutex> g(mu);
        auto it = ids.find(std::string(m));
        if (it != ids.end()) return it->second;
        if (n >= kMaxMn) throw std::runtime_error("too many mnemonics");
        const uint16_t id = static_cast<uint16_t>(n++);
        names[id] = std::string(m);
        int8_t cc;
        flags[id] = compute(names[id], cc);
        cmovcc[id] = cc;
        ids.emplace(names[id], id);
        return id;
    }

    Table() {
        for (int i = 0; i < M_KNOWN_END; ++i) {
            const uint16_t id = get(kKnown[i]);
            if (id != i) throw std::logic_error("mnemonic table order");
        }
    }
};

Table& table() {
    static Table t;
    return t;
}

}  // namespace

uint16_t intern(std::string_view m) { return table().get(m); }
std::string_view mn_name(uint16_t id) { return table().names[id]; }
uint32_t mn_flags(uint16_t id) { return table().flags[id]; }
int mn_cmov_cc(uint16_t id) { return table().cmovcc[id]; }

Decoder::Decoder(bool detail) {
    const CsApi& a = cs();
    if (a.open(CS_ARCH_X86, CS_MODE_64, &h_) != CS_ERR_OK) throw std::runtime_error("cs_open failed");
    if (detail) a.option(h_, CS_OPT_DETAIL, CS_OPT_ON);
    insn_ = a.malloc_(h_);
    by_id_.assign(X86_INS_ENDING + 1, 0xFFFF);
    table();
}

Decoder::~Decoder() {
    if (insn_) cs().free_(insn_, 1);
    if (h_) cs().close(&h_);
}

uint16_t Decoder::mid_of(const cs_insn* i) {
    const unsigned id = i->id;
    if (id < by_id_.size()) {
        const uint16_t c = by_id_[id];
        if (c != 0xFFFF && mn_name(c) == i->mnemonic) return c;
        const uint16_t m = intern(i->mnemonic);
        by_id_[id] = m;
        return m;
    }
    return intern(i->mnemonic);
}

bool Decoder::lite(const uint8_t* p, size_t n, uint64_t addr, Lite& out) {
    const uint8_t* q = p;
    size_t left = n;
    uint64_t a = addr;
    if (!n || !cs().disasm_iter(h_, &q, &left, &a, insn_)) {
        out.size = 0;
        return false;
    }
    out.size = static_cast<uint8_t>(insn_->size);
    out.mid = mid_of(insn_);
    const size_t ol = std::strlen(insn_->op_str);
    out.olen = static_cast<uint16_t>(ol);
    std::memcpy(out.op, insn_->op_str, ol + 1);
    return true;
}

const cs_insn* Decoder::full(const uint8_t* p, size_t n, uint64_t addr) {
    const uint8_t* q = p;
    size_t left = n;
    uint64_t a = addr;
    if (!n || !cs().disasm_iter(h_, &q, &left, &a, insn_)) return nullptr;
    return insn_;
}

}  // namespace flow
