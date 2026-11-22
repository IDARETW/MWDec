#include "flow/pyutil.h"

namespace flow {

const char* const GPR64[16] = {"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                               "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15"};

int gpr_index(std::string_view s) {
    if (s.size() < 2 || s.size() > 3 || s[0] != 'r') return -1;
    for (int i = 0; i < 16; ++i)
        if (s == GPR64[i]) return i;
    return -1;
}

std::vector<std::string_view> split_cs(std::string_view s) {
    std::vector<std::string_view> out;
    size_t p = 0;
    while (true) {
        const size_t k = s.find(", ", p);
        if (k == std::string_view::npos) {
            out.push_back(s.substr(p));
            break;
        }
        out.push_back(s.substr(p, k - p));
        p = k + 2;
    }
    return out;
}

static bool is_hex(char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); }
static bool is_dig(char c) { return c >= '0' && c <= '9'; }
static bool is_word(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}

// regex alternation (0x[0-9a-f]+|\d+): the first alternative wins when it
// matches at all; both are greedy
bool parse_num(std::string_view s, size_t pos, uint64_t& v, size_t& end) {
    if (pos + 2 < s.size() + 0 && s[pos] == '0' && pos + 1 < s.size() && s[pos + 1] == 'x' && pos + 2 < s.size() &&
        is_hex(s[pos + 2])) {
        size_t k = pos + 2;
        uint64_t x = 0;
        while (k < s.size() && is_hex(s[k])) {
            const char c = s[k];
            x = (x << 4) | static_cast<uint64_t>(c <= '9' ? c - '0' : c - 'a' + 10);
            ++k;
        }
        v = x;
        end = k;
        return true;
    }
    if (pos < s.size() && is_dig(s[pos])) {
        size_t k = pos;
        uint64_t x = 0;
        while (k < s.size() && is_dig(s[k])) {
            x = x * 10 + static_cast<uint64_t>(s[k] - '0');
            ++k;
        }
        v = x;
        end = k;
        return true;
    }
    return false;
}

bool full_num(std::string_view s, uint64_t& v) {
    // fullmatch tries both alternatives against the whole string
    if (s.size() > 2 && s[0] == '0' && s[1] == 'x') {
        uint64_t x = 0;
        for (size_t k = 2; k < s.size(); ++k) {
            if (!is_hex(s[k])) goto dec;
            const char c = s[k];
            x = (x << 4) | static_cast<uint64_t>(c <= '9' ? c - '0' : c - 'a' + 10);
        }
        v = x;
        return true;
    }
dec:
    if (s.empty()) return false;
    {
        uint64_t x = 0;
        for (char c : s) {
            if (!is_dig(c)) return false;
            x = x * 10 + static_cast<uint64_t>(c - '0');
        }
        v = x;
        return true;
    }
}

bool hex_op(std::string_view s, int64_t& v) {
    if (s.size() < 3 || s[0] != '0' || s[1] != 'x') return false;
    uint64_t x = 0;
    for (size_t k = 2; k < s.size(); ++k) {
        const char c = s[k];
        if (c >= '0' && c <= '9')
            x = (x << 4) | static_cast<uint64_t>(c - '0');
        else if (c >= 'a' && c <= 'f')
            x = (x << 4) | static_cast<uint64_t>(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F')
            x = (x << 4) | static_cast<uint64_t>(c - 'A' + 10);
        else
            return false;
    }
    v = static_cast<int64_t>(x);
    return true;
}

// prefix "[base" then "]" | " + N]" | " - N]" ; if anchored the "]" must end s
static bool bracket_disp(std::string_view s, size_t pos, bool allow_minus, int64_t& d, size_t& end) {
    if (pos < s.size() && s[pos] == ']') {
        d = 0;
        end = pos + 1;
        return true;
    }
    if (pos + 3 <= s.size() && s[pos] == ' ' && (s[pos + 1] == '+' || (allow_minus && s[pos + 1] == '-')) &&
        s[pos + 2] == ' ') {
        uint64_t v;
        size_t e;
        if (!parse_num(s, pos + 3, v, e)) return false;
        if (e >= s.size() || s[e] != ']') return false;
        d = s[pos + 1] == '+' ? static_cast<int64_t>(v) : -static_cast<int64_t>(v);
        end = e + 1;
        return true;
    }
    return false;
}

std::optional<int64_t> rsp_disp(std::string_view s) {
    static constexpr std::string_view p = "qword ptr [rsp";
    if (!starts(s, p)) return std::nullopt;
    int64_t d;
    size_t e;
    if (!bracket_disp(s, p.size(), true, d, e) || e != s.size()) return std::nullopt;
    return d;
}

std::optional<int64_t> lea_rsp_disp(std::string_view s) {
    static constexpr std::string_view p = "rsp, [rsp";
    if (!starts(s, p)) return std::nullopt;
    int64_t d;
    size_t e;
    if (!bracket_disp(s, p.size(), true, d, e) || e != s.size()) return std::nullopt;
    return d;
}

std::optional<int64_t> rip_target(std::string_view op, int64_t nxt) {
    size_t p = 0;
    while (true) {
        const size_t k = op.find("[rip", p);
        if (k == std::string_view::npos) return std::nullopt;
        int64_t d;
        size_t e;
        if (bracket_disp(op, k + 4, true, d, e)) return nxt + d;
        p = k + 1;
    }
}

std::optional<int64_t> xmm_rsp(std::string_view s) {
    static constexpr std::string_view p = "xmmword ptr [rsp";
    if (!starts(s, p)) return std::nullopt;
    int64_t d;
    size_t e;
    if (!bracket_disp(s, p.size(), false, d, e) || e != s.size()) return std::nullopt;
    return d;
}

std::optional<int> ptr_rip_size(std::string_view s) {
    static const std::pair<std::string_view, int> sizes[] = {{"byte", 1},    {"word", 2},     {"dword", 4},
                                                            {"qword", 8},   {"tbyte", 10},   {"xmmword", 16},
                                                            {"ymmword", 32}, {"zmmword", 64}};
    for (size_t i = 0; i < s.size(); ++i) {
        if (i > 0 && is_word(s[i - 1])) continue;
        for (const auto& [w, n] : sizes) {
            if (s.substr(i, w.size()) == w && s.substr(i + w.size(), 9) == " ptr [rip") return n;
        }
    }
    return std::nullopt;
}

bool match_jt(std::string_view s, int64_t& table) {
    size_t k = 0;
    // (e\w\w|r\d+d)
    bool ok = false;
    if (s.size() >= 3 && s[0] == 'e' && is_word(s[1]) && is_word(s[2]) && s.substr(3, 2) == ", ") {
        k = 3;
        ok = true;
    } else if (s.size() >= 3 && s[0] == 'r' && is_dig(s[1])) {
        size_t j = 1;
        while (j < s.size() && is_dig(s[j])) ++j;
        if (j < s.size() && s[j] == 'd') {
            k = j + 1;
            ok = true;
        }
    }
    if (!ok) return false;
    static constexpr std::string_view a = ", dword ptr [r";
    if (s.substr(k, a.size()) != a) return false;
    k += a.size();
    size_t j = k;
    while (j < s.size() && is_word(s[j])) ++j;
    if (j == k) return false;
    k = j;
    static constexpr std::string_view b = " + r";
    if (s.substr(k, b.size()) != b) return false;
    k += b.size();
    j = k;
    while (j < s.size() && is_word(s[j])) ++j;
    if (j == k) return false;
    k = j;
    static constexpr std::string_view c = "*4 + 0x";
    if (s.substr(k, c.size()) != c) return false;
    k += c.size();
    j = k;
    uint64_t v = 0;
    while (j < s.size() && is_hex(s[j])) {
        const char ch = s[j];
        v = (v << 4) | static_cast<uint64_t>(ch <= '9' ? ch - '0' : ch - 'a' + 10);
        ++j;
    }
    if (j == k) return false;
    if (j + 1 != s.size() || s[j] != ']') return false;
    table = static_cast<int64_t>(v);
    return true;
}

static std::string fmt_hex(int64_t v, int width, bool upper) {
    char buf[40];
    const bool neg = v < 0;
    const uint64_t u = neg ? static_cast<uint64_t>(-(v + 1)) + 1 : static_cast<uint64_t>(v);
    std::snprintf(buf, sizeof buf, upper ? "%llX" : "%llx", static_cast<unsigned long long>(u));
    std::string d = buf;
    const int w = neg ? width - 1 : width;
    if (static_cast<int>(d.size()) < w) d = std::string(static_cast<size_t>(w) - d.size(), '0') + d;
    return neg ? "-" + d : d;
}

std::string hex8(int64_t v) { return fmt_hex(v, 8, true); }
std::string hexX(int64_t v) { return fmt_hex(v, 0, true); }
std::string hexx(int64_t v) { return fmt_hex(v, 0, false); }

std::string py_repr_str(std::string_view s) {
    const bool dq = s.find('\'') != std::string_view::npos && s.find('"') == std::string_view::npos;
    const char q = dq ? '"' : '\'';
    std::string o(1, q);
    for (char c : s) {
        if (c == q || c == '\\') o += '\\';
        o += c;
    }
    o += q;
    return o;
}

}  // namespace flow
