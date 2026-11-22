// Per-build parameters.
//
// Nothing here is derived at run time from executing the protected image.
// Each value is an RVA of data the protection ships in plaintext; how each
// one is located is described in README.md, so a profile for another build
// can be produced the same way. Every value can also be overridden on the
// command line.
#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include "pe.h"
#include "writers.h"

namespace mwdec {

struct BootstrapProfile {
    uint32_t key_rva = 0;     // 16 bytes: four little-endian key words
    uint32_t iv_rva = 0;      // 8 bytes: initial keystream state (v0, v1)
    uint32_t ranges_rva = 0;  // LEB128 (gap, length) list, see ranges.h
    unsigned rounds = 64;
    uint32_t delta = 0x9E3779B9u;
};

// Two range lists in the standard encoding, walked in step: run i of the
// first is copied to run i of the second by the third start-up routine.
struct ImportProfile {
    uint32_t src_ranges_rva = 0;  // runs of the table the loader fills
    uint32_t dst_ranges_rva = 0;  // runs of the table the code calls through
};

struct BuildProfile {
    std::string name;
    uint32_t time_date_stamp = 0;
    uint32_t size_of_image = 0;
    uint32_t entry_rva = 0;
    BootstrapProfile bootstrap;
    ImportProfile imports;
    std::vector<WriterProfile> writers;  // layer 2, in application order
};

// Returns the profile whose identity fields match the image, if any.
std::optional<BuildProfile> find_profile(const Image& im);

}  // namespace mwdec
