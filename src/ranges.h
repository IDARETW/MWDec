// The protection's range lists.
//
// Every list of "these bytes, then skip, then these bytes" in the protected
// image -- what a checksum guard hashes, what the bootstrap decrypts -- uses
// one encoding: a stream of unsigned LEB128 pairs (gap, length) walked with
// a 32-bit cursor that starts at RVA 0:
//
//     cursor += gap;  range = [cursor, cursor + length);  cursor += length;
//
// The list ends with a gap that carries the cursor to exactly 0xFFFFFFFF.
#pragma once

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace mwdec {

struct Range {
    uint32_t rva = 0, size = 0;
};

struct RangeList {
    std::vector<Range> ranges;
    size_t encoded_size = 0;  // bytes of the stream, terminator included
    uint64_t total = 0;       // sum of the lengths
};

inline bool read_uleb(const uint8_t* p, size_t n, size_t& i, uint64_t& v) {
    v = 0;
    for (unsigned shift = 0; shift < 64 && i < n; shift += 7) {
        const uint8_t c = p[i++];
        v |= static_cast<uint64_t>(c & 0x7F) << shift;
        if (!(c & 0x80)) return true;
    }
    return false;
}

// max_ranges: stop after that many ranges without looking for a terminator
// (for a list that is walked in step with another and ends when that does).
inline RangeList decode_ranges(const uint8_t* p, size_t n, size_t max_ranges = SIZE_MAX) {
    RangeList out;
    uint32_t cursor = 0;
    size_t i = 0;
    while (out.ranges.size() < max_ranges) {
        uint64_t gap, len;
        if (!read_uleb(p, n, i, gap)) throw std::runtime_error("range list: truncated gap");
        cursor += static_cast<uint32_t>(gap);
        if (cursor == 0xFFFFFFFFu) break;
        if (!read_uleb(p, n, i, len)) throw std::runtime_error("range list: truncated length");
        out.ranges.push_back({cursor, static_cast<uint32_t>(len)});
        out.total += len;
        cursor += static_cast<uint32_t>(len);
    }
    out.encoded_size = i;
    return out;
}

}  // namespace mwdec
