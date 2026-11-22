// The string tests devirt_flow.py makes on capstone's op_str, written out
// by hand (same accepted language as its regular expressions), and small
// helpers that mimic Python formatting.
#pragma once

#include <cstdint>
#include <cstdio>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace flow {

extern const char* const GPR64[16];  // devirt_flow.GPR64 order
int gpr_index(std::string_view s);   // index into GPR64, or -1
constexpr int REG_RSP = 7;
constexpr int REG_FLAGS = 16;        // "flags" in a chain's push order

inline bool starts(std::string_view s, std::string_view p) { return s.substr(0, p.size()) == p; }
inline bool contains(std::string_view s, std::string_view p) { return s.find(p) != std::string_view::npos; }

// str.split(", ") (an empty string gives one empty part)
std::vector<std::string_view> split_cs(std::string_view s);

// (0x[0-9a-f]+|\d+) at s[pos..]: value and end position
bool parse_num(std::string_view s, size_t pos, uint64_t& v, size_t& end);
// re.fullmatch(r"0x[0-9a-f]+|\d+", s)
bool full_num(std::string_view s, uint64_t& v);
// int(s, 16) for an op_str that starts with "0x" (false on anything else)
bool hex_op(std::string_view s, int64_t& v);

// 'qword ptr [rsp + 0x10]' -> 16 (RE_RSPMEM)
std::optional<int64_t> rsp_disp(std::string_view s);
// 'rsp, [rsp - 8]' -> -8 (RE_LEA_RSP)
std::optional<int64_t> lea_rsp_disp(std::string_view s);
// RE_RIP search: [rip +/- d] -> nxt +/- d
std::optional<int64_t> rip_target(std::string_view op, int64_t nxt);
// RE_XMMMEM: 'xmmword ptr [rsp + 0x10]' -> 16
std::optional<int64_t> xmm_rsp(std::string_view s);
// RE_PTR search: operand size of the first '<size> ptr [rip'
std::optional<int> ptr_rip_size(std::string_view s);
// RE_JT: ^(e\w\w|r\d+d), dword ptr \[(r\w+) \+ (r\w+)\*4 \+ (0x[0-9a-f]+)\]$
bool match_jt(std::string_view s, int64_t& table);

std::string hex8(int64_t v);   // "%08X"
std::string hexX(int64_t v);   // "%X"
std::string hexx(int64_t v);   // "%x"
std::string py_repr_str(std::string_view s);  // repr() of a str

}  // namespace flow
