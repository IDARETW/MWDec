// Instruction decoding with capstone, giving the same strings the Python
// binding gives (mnemonic, op_str, size), plus interned mnemonic ids with
// the membership tests devirt_flow.py makes on them.
#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include "flow/dyn.h"

namespace flow {

// Mnemonics the analysis names, interned first so their ids are constants.
enum Mn : uint16_t {
    M_NONE = 0,
    M_PUSH, M_POP, M_LEA, M_MOV, M_MOVABS, M_XCHG, M_JMP, M_CALL, M_RET, M_PUSHFQ,
    M_POPFQ, M_TEST, M_JNE, M_SUB, M_ADD, M_CMP, M_NOP, M_INT, M_XOR, M_INT3,
    M_PUSHF, M_LAHF, M_POPF, M_SAHF, M_FXSAVE, M_FXRSTOR, M_XSAVE, M_XRSTOR, M_FXSAVE64,
    M_FXRSTOR64, M_UD2,
    M_KNOWN_END
};

enum MnFlag : uint32_t {
    F_JCC = 1,          // JCC_MN
    F_COND8 = 2,        // COND_REL8
    F_STOP = 4,         // STOP_MN
    F_IDIOM_FIRST = 8,  // push / lea / mov
    F_XMM = 16,         // XMM_MOV
    F_CMOV = 32,        // starts with "cmov"
    F_NOFALL = 64,      // NOFALL
    F_SWTERM = 128,     // SW_TERM
    F_J = 256,          // starts with "j"
    F_REP = 512,        // starts with "rep" or "lock"
    F_SWBAD = 1024,     // sweep: SW_BAD and not SW_SOFT (after prefix strip)
    F_X87 = 2048,       // sweep: starts with "f" and not one of the allowed six
    F_SWINT = 4096,     // sweep: stripped mnemonic is "int"
};

uint16_t intern(std::string_view m);
std::string_view mn_name(uint16_t id);
uint32_t mn_flags(uint16_t id);
inline bool mf(uint16_t id, uint32_t f) { return (mn_flags(id) & f) != 0; }
// cc suffix of a cmov mnemonic, normalised (CC index 0..15) or -1
int mn_cmov_cc(uint16_t id);

extern const char* const CC_NAMES[16];
int norm_cc(std::string_view c);  // CC index or -1

struct Lite {
    uint8_t size = 0;  // 0: no instruction (None)
    uint16_t mid = 0;
    uint16_t olen = 0;
    char op[162];
    std::string_view ops() const { return {op, olen}; }
    std::string_view mn() const { return mn_name(mid); }
    explicit operator bool() const { return size != 0; }
};

class Decoder {
public:
    explicit Decoder(bool detail);
    ~Decoder();
    Decoder(const Decoder&) = delete;
    Decoder& operator=(const Decoder&) = delete;

    // one instruction from p[0..n) at addr; false when it does not decode
    bool lite(const uint8_t* p, size_t n, uint64_t addr, Lite& out);
    // detailed decode; the result lives until the next call
    const cs_insn* full(const uint8_t* p, size_t n, uint64_t addr);
    uint16_t mid_of(const cs_insn* i);
    const char* reg_name(unsigned r) const { return cs().reg_name(h_, r); }
    csh handle() const { return h_; }

    // linear decode (Cs.disasm with count 0): calls f(insn) until it fails
    template <class F> void run(const uint8_t* p, size_t n, uint64_t addr, F&& f) {
        const uint8_t* q = p;
        size_t left = n;
        uint64_t a = addr;
        while (left && cs().disasm_iter(h_, &q, &left, &a, insn_)) f(insn_);
    }

private:
    csh h_ = 0;
    cs_insn* insn_ = nullptr;
    std::vector<uint16_t> by_id_;
};

// Python's bytes(mem[a:a+n]) (negative a counts from the end).
inline void py_window(const uint8_t* mem, int64_t len, int64_t a, int64_t n, const uint8_t*& p, size_t& cnt) {
    auto norm = [len](int64_t i) {
        if (i < 0) {
            i += len;
            if (i < 0) i = 0;
        } else if (i > len) {
            i = len;
        }
        return i;
    };
    const int64_t s = norm(a), e = norm(a + n);
    p = mem + s;
    cnt = e > s ? static_cast<size_t>(e - s) : 0;
}

}  // namespace flow
