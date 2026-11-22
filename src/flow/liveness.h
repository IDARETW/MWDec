// Register and flag liveness (devirt_flow.py: RegLiveness, FlagLiveness).
#pragma once

#include <functional>
#include <string>

#include "flow/idiom.h"

namespace flow {

enum Verdict { V_DEAD, V_LIVE, V_UNKNOWN };
const char* verdict_name(int v);

class RegLiveness {
public:
    explicit RegLiveness(Code& code) : code_(code) {}
    int at(int64_t a, RegSet regs, int depth = 160, bool callee = false, int cdepth = 0);

private:
    // returns -1 for "None"
    int through_call(bool has_target, int64_t target, RegSet& pend, int depth, int cdepth);
    Code& code_;
};

class FlagLiveness {
public:
    using ChainLookup = std::function<const Chain*(int64_t)>;
    FlagLiveness(Code& code, ChainLookup chains) : code_(code), chains_(std::move(chains)) {}
    int at(int64_t a, int depth = 96);

private:
    Code& code_;
    ChainLookup chains_;
};

// capstone register id -> devirt_flow._R64 id (GPR64 index), or -1
int r64_of(unsigned cs_reg);
// a write of this capstone register fully overwrites its 64-bit register
// (nm == p, or starts with "e", or ends with "d"): GPR64 index or -1
int r64_full_write(unsigned cs_reg);

}  // namespace flow
