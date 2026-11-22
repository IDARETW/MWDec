// Layer 2: what the protection's writer routines produce.
//
// After the bootstrap, some functions are still not code. Each of them is
// owned by a writer routine that, when the game is about to need the
// function, overwrites it with the real bytes. A writer does not decrypt
// the bytes that are there; it never reads them. It carries its own copy of
// the plaintext, the stash, encoded as 32-bit words, and a range list that
// says where the decoded bytes go:
//
//     Xor       p = e ^ K
//     Sub       p = K - e
//     XorAuto   p = e ^ k ;  k += p                       (k starts as K)
//     MulRol    a = rol(a, b & 31) ; p = e - a*b ; b = ~p ^ b
//                                                (a starts as K, b as K & 31)
//
// K is one dword stored in filler bytes between instructions. The decoded
// words, little-endian, form one byte stream that is laid into the ranges
// in list order.
//
// Writers are layered: the target of some writers is another writer's
// stash. Applying them in profile order (stash writers first) reproduces
// what the routines would write if every one of them ran once.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "pe.h"

namespace mwdec {

enum class WriterVariant : uint8_t { Xor, Sub, XorAuto, MulRol };

struct WriterProfile {
    uint32_t routine = 0;   // identifies the writer (a site inside it)
    bool writes_stash = false;
    WriterVariant variant = WriterVariant::Xor;
    uint32_t ranges_rva = 0;
    uint32_t stash_rva = 0;
    uint32_t key_rva = 0;
};

struct WriterResult {
    uint32_t routine = 0;
    bool writes_stash = false;
    uint32_t key = 0;
    size_t ranges = 0;
    uint64_t bytes = 0;
    uint64_t changed = 0;  // bytes whose value actually changed
};

// Decodes `n` bytes of a stash. Exposed for the self-test.
std::vector<uint8_t> decode_stash(const uint8_t* stash, size_t n, WriterVariant v, uint32_t key);

// Reads a writer table made by tools/find_writers.py: tab-separated rows
// `site  writes_stash  variant  list  stash  key ...` (hex RVAs; further
// columns are ignored), in the order to apply them. Lines that begin with
// `#` and the header line are skipped.
std::vector<WriterProfile> load_writer_table(const std::string& path);

// Applies every writer in order. If `touched` is non-empty it is a bitmap
// over RVAs and receives the bytes written to code (not to stashes).
std::vector<WriterResult> apply_writers(Image& im, const std::vector<WriterProfile>& writers,
                                        std::vector<uint8_t>& touched);

}  // namespace mwdec
