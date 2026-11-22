// Checks on published values (devirt_flow.py: find_checks with MiniEmu and
// random.Random(1400)), and static_writes.
#pragma once

#include <unordered_map>
#include <vector>

#include "flow/walker.h"

namespace flow {

// CPython's random.Random (Mersenne Twister), the draws find_checks makes
class PyRandom {
public:
    explicit PyRandom(uint32_t seed);
    uint32_t genrand();
    uint64_t getrandbits(int k);  // k <= 64
    int64_t randbelow(int64_t n);
    void randbytes(uint8_t* out, size_t n);  // n a multiple of 4

private:
    uint32_t mt_[624];
    int mti_ = 625;
};

std::unordered_map<int64_t, CheckFold> find_checks(FImage& im, Code& code, const RawXrefs& xr,
                                                   const std::vector<int64_t>& sites,
                                                   const std::vector<std::pair<int64_t, int64_t>>& routine_writes,
                                                   const std::vector<std::pair<int64_t, int64_t>>& baked,
                                                   int depth = 60);

std::vector<std::pair<int64_t, int64_t>> static_writes(FImage& im, Code& code, const ByteMap& bm);

// the predecessor list census_chains and find_checks share
std::vector<int64_t> back_preds(Code& code, const RawXrefs& xr, int64_t a);

}  // namespace flow
