// A writer's key and encoding, found from its stash alone.
//
// A writer keeps an encoded copy of what it writes (the stash) and one
// dword of key; there are four encodings (writers.h). In all four the first
// plaintext words depend only on the key and the first stash words. So every
// one of the 2^32 keys is tried against each encoding. A key survives when
// enough of the first 24 bytes it decodes, and then of the first 80, are
// bytes that are common in compiled code; the survivors decode the whole
// stash (up to 4 KB) and are ranked by the share of such bytes there. Noise
// gives about a fifth, code more than half.
//
// One encoding defeats the ranking. XorAuto (p = e ^ k ; k += p) forgets
// its starting key within 32 words: bit 0 of the next k is bit 0 of e
// whatever k was, bit 1 then depends only on bit 0, and so on. Every key
// decodes the rest of such a stash alike, so millions tie.
//
// This finds writers whose output is code. A writer that prepares another
// writer's stash produces noise under every key.
#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "writers.h"

namespace mwdec {

struct KeyCandidate {
    uint32_t key = 0;
    WriterVariant variant = WriterVariant::Xor;
    double share = 0;      // common code bytes in the decoded stash
    size_t survivors = 0;  // keys of this encoding that passed the first 80 bytes
};

// stash: the encoded bytes; n: how many of them the writer uses (the total
// of its range list). Returns the best candidates over all four encodings,
// best first, at most `top` per encoding.
std::vector<KeyCandidate> find_writer_keys(const uint8_t* stash, size_t n, size_t top = 3);

const char* variant_name(WriterVariant v);

}  // namespace mwdec
