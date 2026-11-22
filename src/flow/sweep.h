// Block decoding for the sweep and for the plausible-block invariant
// (devirt_flow.py: sweep_why_bad, Sweeper).
#pragma once

#include <functional>
#include <map>
#include <string>
#include <tuple>
#include <unordered_map>
#include <vector>

#include "flow/code.h"

namespace flow {

// nullptr when the instruction passes
const char* sweep_why_bad(const cs_insn* i, uint16_t mid, int64_t size, const RangeV& ex, std::string& buf);

struct BlockRef {
    int64_t t;
    bool branch;  // "branch" or "rip"
};

struct RunBlock {
    int64_t start;
    bool plausible;
    std::vector<BlockRef> refs;
};

class Sweeper {
public:
    Sweeper(FImage& im, const Code& code) : im_(im), ex_(code.ex) {}
    // (ok, why), remembered by (c, stop, rec_end)
    std::pair<bool, std::string> block(int64_t c, int64_t stop, int64_t rec_end,
                                       const std::function<bool(int64_t)>& joins, int64_t region_end);
    // block() in its two halves, for callers that work out verdicts on
    // threads and record them in order: the verdict alone (safe to call from
    // several threads while nothing is stored), what is remembered, and the
    // storing exactly as block() stores
    std::pair<bool, std::string> evaluate(int64_t c, int64_t stop, int64_t rec_end,
                                          const std::function<bool(int64_t)>& joins, int64_t region_end) const;
    const std::pair<bool, std::string>* remembered(int64_t c, int64_t stop, int64_t rec_end) const;
    const std::pair<bool, std::string>& remember(int64_t c, int64_t stop, int64_t rec_end,
                                                 std::pair<bool, std::string> v);
    const std::vector<RunBlock>& run_blocks(int64_t lo, int64_t hi);

private:
    struct Key {
        int64_t a, b, c;
        bool operator==(const Key& o) const { return a == o.a && b == o.b && c == o.c; }
    };
    struct KH {
        size_t operator()(const Key& k) const {
            return static_cast<size_t>((static_cast<uint64_t>(k.a) * 0x9E3779B97F4A7C15ull) ^
                                       (static_cast<uint64_t>(k.b) * 0xC2B2AE3D27D4EB4Full) ^
                                       (static_cast<uint64_t>(k.c) * 0x165667B19E3779F9ull));
        }
    };
    FImage& im_;
    RangeV ex_;
    std::unordered_map<Key, std::pair<bool, std::string>, KH> cache_;
    std::map<std::pair<int64_t, int64_t>, std::vector<RunBlock>> runs_;
};

}  // namespace flow
