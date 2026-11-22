// Layer 1: the bulk encryption that the first TLS callback removes before a
// single game instruction runs.
#pragma once

#include <cstdint>

#include "pe.h"
#include "profile.h"
#include "ranges.h"

namespace mwdec {

struct BootstrapResult {
    RangeList list;
    uint32_t key[4]{};
    uint32_t iv[2]{};
    uint64_t blocks = 0;  // XTEA block operations performed
    uint32_t final_state[2]{};  // keystream state after the last block
};

// Decodes the range list and, if `apply`, XORs the keystream over it.
BootstrapResult run_bootstrap(Image& im, const BootstrapProfile& p, bool apply);

}  // namespace mwdec
