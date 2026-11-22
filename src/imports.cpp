#include "imports.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <map>

#include "ranges.h"

namespace mwdec {

namespace {
std::string cstr(const Image& im, uint32_t rva, size_t limit = 256) {
    std::string s;
    while (im.in_bounds(rva, 1) && im.mem[rva] && s.size() < limit) s += static_cast<char>(im.mem[rva++]);
    return s;
}
}  // namespace

ImportTables read_imports(const Image& im, const ImportProfile& p) {
    ImportTables out;
    if (!im.in_bounds(p.src_ranges_rva, 2) || !im.in_bounds(p.dst_ranges_rva, 2))
        throw std::runtime_error("import profile points outside the image");
    const RangeList src = decode_ranges(im.mem.data() + p.src_ranges_rva, im.mem.size() - p.src_ranges_rva);
    const RangeList dst = decode_ranges(im.mem.data() + p.dst_ranges_rva, im.mem.size() - p.dst_ranges_rva);
    // The protection's own imports have no place in the game's table. Build
    // 19936 gives them a descriptor of their own, so the source list is one
    // run longer and the copy ends with the shorter list. 1.20 appends them
    // to the game's KERNEL32 imports instead, so one source run is two slots
    // longer than its destination, and the copy takes the destination's
    // length.
    const size_t runs = std::min(src.ranges.size(), dst.ranges.size());
    if (!runs) throw std::runtime_error("import copy lists are empty");
    std::map<uint32_t, Range> to;  // loader table run -> original table run
    for (size_t i = 0; i < runs; ++i) {
        if (src.ranges[i].size < dst.ranges[i].size || (dst.ranges[i].size & 7) ||
            !im.in_bounds(dst.ranges[i].rva, dst.ranges[i].size))
            throw std::runtime_error("import copy lists disagree in a run");
        to[src.ranges[i].rva] = dst.ranges[i];
    }

    const DataDir dir = im.dirs[1];
    for (uint32_t d = dir.rva; im.in_bounds(d, 20); d += 20) {
        const uint32_t int_rva = im.rd<uint32_t>(d);
        const uint32_t name_rva = im.rd<uint32_t>(d + 12);
        const uint32_t iat_rva = im.rd<uint32_t>(d + 16);
        if (!int_rva && !name_rva && !iat_rva) break;
        ++out.descriptors;
        const std::string dll = cstr(im, name_rva);
        const uint32_t names = int_rva ? int_rva : iat_rva;
        uint32_t count = 0;
        while (im.in_bounds(names + 8ull * count, 8) && im.rd<uint64_t>(names + 8 * count)) ++count;

        const auto it = to.find(iat_rva);
        const bool aliased = it != to.end() && it->second.size <= 8ull * count;
        const uint32_t copied = aliased ? it->second.size / 8 : 0;  // slots that have a copy
        if (aliased) {
            ++out.aliased;
            out.aliased_tables.push_back(iat_rva);
        } else {
            out.unaliased.push_back(dll);
        }
        for (uint32_t i = 0; i < count; ++i) {
            const uint64_t thunk = im.rd<uint64_t>(names + 8 * i);
            ImportEntry e;
            e.loader_slot = iat_rva + 8 * i;
            e.alias_slot = i < copied ? it->second.rva + 8 * i : 0;
            e.dll = dll;
            if (thunk >> 63) {
                char buf[16];
                std::snprintf(buf, sizeof buf, "#%u", static_cast<unsigned>(thunk & 0xFFFF));
                e.name = buf;
            } else {
                e.name = cstr(im, static_cast<uint32_t>(thunk) + 2);
            }
            out.entries.push_back(std::move(e));
        }
    }
    return out;
}

unsigned drop_protection_imports(Image& im, const ImportTables& tables,
                                 const std::vector<uint8_t>& wiped_bits, uint64_t& refs_left) {
    refs_left = 0;
    struct Desc {
        uint32_t at, int_rva, name_rva, iat_rva, count;
        bool aliased;
    };
    std::vector<Desc> descs;
    const DataDir dir = im.dirs[1];
    for (uint32_t d = dir.rva; im.in_bounds(d, 20); d += 20) {
        Desc x{d, im.rd<uint32_t>(d), im.rd<uint32_t>(d + 12), im.rd<uint32_t>(d + 16), 0, false};
        if (!x.int_rva && !x.name_rva && !x.iat_rva) break;
        const uint32_t names = x.int_rva ? x.int_rva : x.iat_rva;
        while (im.in_bounds(names + 8ull * x.count, 8) && im.rd<uint64_t>(names + 8 * x.count)) ++x.count;
        x.aliased = std::find(tables.aliased_tables.begin(), tables.aliased_tables.end(), x.iat_rva) !=
                    tables.aliased_tables.end();
        descs.push_back(x);
    }
    size_t keep = descs.size();
    while (keep > 0 && !descs[keep - 1].aliased) --keep;
    if (keep == 0 || keep == descs.size()) return 0;

    // Any code left that still loads one of those slots?
    for (size_t i = keep; i < descs.size(); ++i) {
        const uint32_t lo = descs[i].iat_rva, hi = lo + 8 * descs[i].count;
        for (const Section& s : im.sections) {
            if (!s.executable()) continue;
            const size_t size = std::min<size_t>(s.rsize, s.vsize);
            const uint8_t* b = im.mem.data() + s.rva;
            for (size_t o = 1; o + 4 <= size; ++o) {
                if ((b[o - 1] & 0xC7) != 0x05) continue;  // ModRM of a RIP-relative operand
                int32_t disp;
                std::memcpy(&disp, b + o, 4);
                const int64_t tgt = static_cast<int64_t>(s.rva) + static_cast<int64_t>(o) + 4 + disp;
                if (tgt < lo || tgt >= hi) continue;
                const uint32_t a = s.rva + static_cast<uint32_t>(o);
                if (!wiped_bits.empty() && ((wiped_bits[a >> 3] >> (a & 7)) & 1)) continue;
                ++refs_left;
            }
        }
    }
    if (refs_left) return 0;

    for (size_t i = keep; i < descs.size(); ++i) {
        const Desc& x = descs[i];
        const uint32_t names = x.int_rva ? x.int_rva : x.iat_rva;
        for (uint32_t k = 0; k < x.count; ++k) {
            const uint64_t thunk = im.rd<uint64_t>(names + 8 * k);
            if (thunk >> 63) continue;
            uint32_t s = static_cast<uint32_t>(thunk);
            if (!im.in_bounds(s, 3)) continue;
            uint32_t e = s + 2;
            while (im.in_bounds(e, 1) && im.mem[e]) ++e;
            std::memset(im.mem.data() + s, 0, e - s);
        }
        if (x.int_rva) std::memset(im.mem.data() + x.int_rva, 0, 8ull * (x.count + 1));
        std::memset(im.mem.data() + x.iat_rva, 0, 8ull * (x.count + 1));
        for (uint32_t e = x.name_rva; im.in_bounds(e, 1) && im.mem[e]; ++e) im.mem[e] = 0;
        std::memset(im.mem.data() + x.at, 0, 20);
    }
    const unsigned dropped = static_cast<unsigned>(descs.size() - keep);
    im.set_dir(1, dir.rva, dir.size >= 20 * dropped ? dir.size - 20 * dropped : dir.size);
    return dropped;
}

std::string imports_tsv(const ImportTables& r) {
    std::string s = "loader_slot\talias_slot\tdll\tname\n";
    char buf[64];
    for (const ImportEntry& e : r.entries) {
        if (e.alias_slot) std::snprintf(buf, sizeof buf, "%08X\t%08X\t", e.loader_slot, e.alias_slot);
        else std::snprintf(buf, sizeof buf, "%08X\t\t", e.loader_slot);
        s += buf;
        s += e.dll + "\t" + e.name + "\n";
    }
    return s;
}

}  // namespace mwdec
