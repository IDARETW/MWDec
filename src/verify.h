// Comparison of a statically decrypted image with a memory dump of the same
// build taken from a running process. The dump is only ever a reference: it
// is how the decryptor is checked, never an input to it.
#pragma once

#include <cstdint>
#include <vector>

#include "pe.h"

namespace mwdec {

struct SectionDiff {
    Section section;
    uint64_t compared = 0;
    uint64_t differ = 0;
    uint64_t differ_in_mask = 0;  // differing bytes a decryption layer touched
};

struct DiffRun {
    uint32_t rva = 0, size = 0;  // extent; nearby differences are merged
    uint32_t differing = 0;      // bytes inside the extent that differ
    uint32_t in_mask = 0;        // of those, bytes a decryption layer touched
};

struct VerifyResult {
    int64_t delta = 0;  // dump load address minus the image's preferred base
    uint64_t reloc_sites = 0;
    std::vector<SectionDiff> sections;
    std::vector<DiffRun> runs;
};

// `touched` is a bitmap over RVAs (bit set = some layer rewrote the byte),
// or empty. The image is rebased to the dump's load address for the
// comparison and restored before returning.
VerifyResult verify_against_dump(Image& im, const Image& dump,
                                 const std::vector<uint8_t>& touched,
                                 uint32_t merge_gap = 32);

}  // namespace mwdec
