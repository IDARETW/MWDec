#include "writers.h"

#include <cstring>
#include <fstream>
#include <stdexcept>
#include <string>

#include "ranges.h"

namespace mwdec {

namespace {
inline uint32_t rol32(uint32_t v, unsigned n) {
    n &= 31;
    return n ? (v << n) | (v >> (32 - n)) : v;
}
}  // namespace

std::vector<uint8_t> decode_stash(const uint8_t* stash, size_t n, WriterVariant v, uint32_t key) {
    const size_t words = (n + 3) / 4;
    std::vector<uint8_t> out(words * 4);
    uint32_t k = key;       // XorAuto running key
    uint32_t a = key;       // MulRol multiplier
    uint32_t b = key & 31;  // MulRol rotation / factor
    for (size_t i = 0; i < words; ++i) {
        uint32_t e, p = 0;
        std::memcpy(&e, stash + 4 * i, 4);
        switch (v) {
            case WriterVariant::Xor:
                p = e ^ key;
                break;
            case WriterVariant::Sub:
                p = key - e;
                break;
            case WriterVariant::XorAuto:
                p = e ^ k;
                k += p;
                break;
            case WriterVariant::MulRol:
                a = rol32(a, b);
                p = e - a * b;
                b = ~p ^ b;
                break;
        }
        std::memcpy(out.data() + 4 * i, &p, 4);
    }
    out.resize(n);
    return out;
}

std::vector<WriterProfile> load_writer_table(const std::string& path) {
    std::ifstream f(path);
    if (!f) throw std::runtime_error("cannot open writer table " + path);
    std::vector<WriterProfile> rows;
    std::string line;
    size_t n = 0;
    while (std::getline(f, line)) {
        ++n;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty() || line[0] == '#' || line.rfind("site", 0) == 0) continue;
        std::vector<std::string> col;
        size_t a = 0;
        for (;;) {
            const size_t b = line.find('\t', a);
            col.push_back(line.substr(a, b == std::string::npos ? b : b - a));
            if (b == std::string::npos) break;
            a = b + 1;
        }
        if (col.size() < 6) throw std::runtime_error("writer table line " + std::to_string(n) + ": six columns wanted");
        WriterProfile w;
        w.routine = static_cast<uint32_t>(std::stoul(col[0], nullptr, 16));
        w.writes_stash = col[1] == "1" || col[1] == "true";
        if (col[2] == "Xor") w.variant = WriterVariant::Xor;
        else if (col[2] == "Sub") w.variant = WriterVariant::Sub;
        else if (col[2] == "XorAuto") w.variant = WriterVariant::XorAuto;
        else if (col[2] == "MulRol") w.variant = WriterVariant::MulRol;
        else throw std::runtime_error("writer table line " + std::to_string(n) + ": unknown encoding " + col[2]);
        w.ranges_rva = static_cast<uint32_t>(std::stoul(col[3], nullptr, 16));
        w.stash_rva = static_cast<uint32_t>(std::stoul(col[4], nullptr, 16));
        w.key_rva = static_cast<uint32_t>(std::stoul(col[5], nullptr, 16));
        rows.push_back(w);
    }
    return rows;
}

std::vector<WriterResult> apply_writers(Image& im, const std::vector<WriterProfile>& writers,
                                        std::vector<uint8_t>& touched) {
    std::vector<WriterResult> results;
    results.reserve(writers.size());
    for (const WriterProfile& w : writers) {
        WriterResult r;
        r.routine = w.routine;
        r.writes_stash = w.writes_stash;
        if (!im.in_bounds(w.ranges_rva, 2) || !im.in_bounds(w.key_rva, 4))
            throw std::runtime_error("writer profile points outside the image");
        const RangeList list = decode_ranges(im.mem.data() + w.ranges_rva, im.mem.size() - w.ranges_rva);
        for (const Range& g : list.ranges)
            if (!im.in_bounds(g.rva, g.size)) throw std::runtime_error("writer range list leaves the image");
        const size_t padded = (static_cast<size_t>(list.total) + 3) & ~static_cast<size_t>(3);
        if (!im.in_bounds(w.stash_rva, padded)) throw std::runtime_error("writer stash leaves the image");
        r.key = im.rd<uint32_t>(w.key_rva);
        // Decode the whole stash before writing anything: a writer's ranges
        // may overlap its own stash, and the routine decodes ahead of them.
        const std::vector<uint8_t> plain =
            decode_stash(im.mem.data() + w.stash_rva, static_cast<size_t>(list.total), w.variant, r.key);
        size_t pos = 0;
        for (const Range& g : list.ranges) {
            uint8_t* dst = im.mem.data() + g.rva;
            for (uint32_t i = 0; i < g.size; ++i) {
                r.changed += dst[i] != plain[pos + i];
                dst[i] = plain[pos + i];
                if (!w.writes_stash && !touched.empty())
                    touched[(g.rva + i) >> 3] |= static_cast<uint8_t>(1u << ((g.rva + i) & 7));
            }
            pos += g.size;
        }
        r.ranges = list.ranges.size();
        r.bytes = list.total;
        results.push_back(r);
    }
    return results;
}

}  // namespace mwdec
