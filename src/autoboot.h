// The bootstrap layer's parameters, found in the file.
//
// Nothing is executed or emulated. Three observations are enough:
//
//  1. The cipher steps around every relocated qword, so a run of nearby
//     relocations fixes a run of (gap 8, length) pairs in the range list.
//     Their LEB128 encoding is searched for in the image; the hit is inside
//     the list, with a known cursor.
//  2. LEB128 reads backwards without ambiguity (a value ends at a byte with
//     the top bit clear and owns the top-bit-set bytes before it), so the
//     list can be walked back from the hit to the gap that equals the whole
//     remaining cursor: its first value.
//  3. The key and the starting block must be readable before anything is
//     decrypted. The cipher skips them and no relocation explains the skip.
//     Such islands are few, and very few are exactly 16 or 8 bytes long.
//     Each (16, 8) pair is tried on the first bytes of the stream; the right
//     one turns them into code.
#pragma once

#include <optional>
#include <string>
#include <vector>

#include "pe.h"
#include "profile.h"
#include "ranges.h"

namespace mwdec {

struct AutoBootReport {
    bool from_code = false;     // key and block read from the cipher's own set-up code
    size_t islands = 0;         // in the executable sections (only counted when not from_code)
    size_t key_candidates = 0;
    size_t iv_candidates = 0;
    double best = 0, second = 0;  // share of common code bytes, best pair and runner-up
    std::string why;              // set when nothing was found
};

// The list is found as described above. The key and the starting block are
// read from the cipher's set-up code where that has its usual shape
//     mov dword ptr [rbp+10h], CYCLES ; mov dword ptr [rbp+14h], 9E3779B9h
//     lea rax, [rip+KEY] ; mov [rbp], rax ; lea rax, [rip+BLOCK] ; mov [rbp+8], rax
// and by the island search otherwise; either way they are accepted only if
// they turn the first bytes of the stream into code. `report`, if given,
// says what was seen.
std::optional<BootstrapProfile> find_bootstrap(const Image& im, AutoBootReport* report = nullptr);

// Every range list in the image with at most max_ranges ranges (ranges.h).
// A list ends with a gap that takes the cursor from inside the image to
// 0xFFFFFFFF, which is always five LEB128 bytes ending in 0x0D to 0x0F; from
// each such value the list is walked back to its first byte.
struct FoundList {
    uint32_t rva = 0;
    RangeList list;
};
std::vector<FoundList> find_range_lists(const Image& im, size_t max_ranges);

// The two lists the import copy is driven by (imports.h), recognised by
// where their ranges lie. Run on an image whose bootstrap layer is off.
std::optional<ImportProfile> find_import_lists(const Image& im);

}  // namespace mwdec
