// Encrypted string blobs in .data.
//
// These belong to the game engine rather than to the protection, but they
// are part of what "the executable is encrypted" means in practice, and
// they are recoverable from the shipped file alone.
//
//     +0x0   8 bytes   key
//     +0x8   3 bytes   length (little-endian, 24 bits)
//     +0xB   1 byte    1 = encrypted, 0 = already decrypted
//     +0xC   length    text, each byte XORed with key[i & 7]
//     +0xC+length      a plain 0
//
// Blobs are 8-byte aligned. The game decrypts one in place the first time
// it is asked for and clears the byte at +0xB; patch() leaves a blob in
// exactly that state.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "pe.h"

namespace mwdec {

struct XorBlob {
    uint32_t rva = 0;
    uint32_t length = 0;
    uint8_t key[8]{};
    std::string text;       // decrypted bytes
    unsigned ref_offsets = 0;  // how many of +0, +8, +0xB, +0xC code refers to
    unsigned ref_sites = 0;
};

// Finds every encrypted blob. Code references are counted against whatever
// the executable sections currently hold, so run this after the code layers
// have been decrypted. A blob shorter than four characters is reported only
// if code refers to it.
std::vector<XorBlob> find_xor_blobs(const Image& im);

void patch_xor_blobs(Image& im, const std::vector<XorBlob>& blobs);

// Tab-separated listing with C-style escapes in the text column.
std::string xor_blobs_tsv(const std::vector<XorBlob>& blobs);

}  // namespace mwdec
