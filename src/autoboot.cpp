#include "autoboot.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <functional>

#include "ranges.h"
#include "xtea.h"

namespace mwdec {

namespace {

void put_uleb(std::vector<uint8_t>& out, uint64_t v) {
    for (;;) {
        const uint8_t c = static_cast<uint8_t>(v & 0x7F);
        v >>= 7;
        if (v) {
            out.push_back(c | 0x80);
        } else {
            out.push_back(c);
            return;
        }
    }
}

// Bytes that make up most of compiled x64 code: REX prefixes, mov / lea /
// call / jmp opcodes, common ModRM and SIB bytes, small displacements,
// padding. Noise holds about one in five of them.
const std::array<bool, 256>& common_bytes() {
    static const std::array<bool, 256> t = [] {
        std::array<bool, 256> a{};
        for (int b : {0x00, 0x01, 0x02, 0x04, 0x08, 0x0F, 0x10, 0x18, 0x20, 0x24, 0x28, 0x30, 0x33,
                      0x38, 0x3B, 0x40, 0x41, 0x44, 0x45, 0x48, 0x49, 0x4C, 0x4D, 0x54, 0x5C, 0x66,
                      0x74, 0x75, 0x83, 0x84, 0x85, 0x89, 0x8B, 0x8D, 0x90, 0xC0, 0xC1, 0xC3, 0xC7,
                      0xC8, 0xC9, 0xCC, 0xD0, 0xD2, 0xE8, 0xE9, 0xEB, 0xF8, 0xFE, 0xFF})
            a[static_cast<size_t>(b)] = true;
        return a;
    }();
    return t;
}

// Offset of the list's first byte, walking back from a hit at `at` where
// the cursor is `cursor`. Returns SIZE_MAX if the walk does not end in a
// gap equal to the remaining cursor.
size_t list_start(const std::vector<uint8_t>& m, size_t at, uint64_t cursor, size_t max_values = SIZE_MAX) {
    size_t p = at;
    bool want_len = true;  // the hit begins with a gap, so a length precedes it
    size_t values = 0;
    while (cursor > 0) {
        if (values++ > max_values) return SIZE_MAX;
        if (!want_len) {
            // The first value is a gap equal to the whole cursor. What lies
            // before the list may end in top-bit-set bytes, which the
            // backward rule would take for part of it, so test directly.
            std::vector<uint8_t> first;
            put_uleb(first, cursor);
            if (p >= first.size() && std::memcmp(m.data() + p - first.size(), first.data(), first.size()) == 0)
                return p - first.size();
        }
        if (p == 0 || (m[p - 1] & 0x80)) return SIZE_MAX;
        size_t s = p - 1;
        while (s > 0 && (m[s - 1] & 0x80) && p - s < 5) --s;
        uint64_t v = 0;
        for (size_t k = p; k-- > s;) v = (v << 7) | (m[k] & 0x7F);
        if (v > cursor) return SIZE_MAX;
        cursor -= v;
        p = s;
        want_len = !want_len;
    }
    return SIZE_MAX;
}

struct Island {
    uint32_t rva, size;
};

}  // namespace

std::vector<FoundList> find_range_lists(const Image& im, size_t max_ranges) {
    // Every list ends with a gap that takes the cursor from inside the image
    // to 0xFFFFFFFF: five LEB128 bytes, the last 0x0D to 0x0F. Each such
    // value is a possible ending, with a known cursor; walk back from it.
    std::vector<FoundList> out;
    const std::vector<uint8_t>& m = im.mem;
    if (m.size() < 8) return out;
    for (size_t i = 1; i + 5 <= m.size(); ++i) {
        if (m[i + 4] < 0x0D || m[i + 4] > 0x0F) continue;
        if (!(m[i] & 0x80) || !(m[i + 1] & 0x80) || !(m[i + 2] & 0x80) || !(m[i + 3] & 0x80)) continue;
        if (m[i - 1] & 0x80) continue;  // the value before it must end here
        const uint64_t v = (m[i] & 0x7Full) | ((m[i + 1] & 0x7Full) << 7) | ((m[i + 2] & 0x7Full) << 14) |
                           ((m[i + 3] & 0x7Full) << 21) | (static_cast<uint64_t>(m[i + 4]) << 28);
        if (v >= 0xFFFFFFFFull) continue;
        const uint64_t end = 0xFFFFFFFFull - v;
        if (end == 0 || end > im.size_of_image) continue;
        const size_t start = list_start(m, i, end, 2 * max_ranges + 2);
        if (start == SIZE_MAX) continue;
        FoundList f;
        f.rva = static_cast<uint32_t>(start);
        try {
            f.list = decode_ranges(m.data() + start, m.size() - start, max_ranges + 1);
        } catch (const std::exception&) {
            continue;
        }
        if (f.list.ranges.empty() || f.list.ranges.size() > max_ranges || start + f.list.encoded_size != i + 5)
            continue;
        bool ok = true;
        for (const Range& g : f.list.ranges)
            if (g.size == 0 || !im.in_bounds(g.rva, g.size)) {
                ok = false;
                break;
            }
        if (ok) out.push_back(std::move(f));
    }
    return out;
}

std::optional<ImportProfile> find_import_lists(const Image& im) {
    // The third start-up routine copies the loader's import table to the
    // original one, run by run, from two lists. The first has one range per
    // imported DLL, all inside the table the import directory describes. The
    // second has the same runs (less the protection's own) in another data
    // section, and begins at that section's first byte.
    const Section* loader = im.section_of(im.dirs[1].rva);
    if (!loader) return std::nullopt;
    const std::vector<FoundList> lists = find_range_lists(im, 2000);
    auto all_in = [&](const FoundList& f, const Section* s) {
        for (const Range& g : f.list.ranges)
            if (!(s->contains(g.rva) && static_cast<uint64_t>(g.rva) + g.size <= s->end())) return false;
        return true;
    };
    std::optional<ImportProfile> best;
    uint64_t best_gap = UINT64_MAX;
    for (const FoundList& src : lists) {
        if (!all_in(src, loader) || src.list.ranges.size() < 4) continue;
        for (const FoundList& dst : lists) {
            if (&dst == &src) continue;
            const Section* s = im.section_of(dst.list.ranges.front().rva);
            if (!s || s == loader || s->executable() || !all_in(dst, s)) continue;
            if (dst.list.ranges.front().rva != s->rva) continue;
            const size_t ns = src.list.ranges.size(), nd = dst.list.ranges.size();
            if (nd > ns || ns - nd > 2 || dst.list.total > src.list.total) continue;
            const uint64_t gap = src.list.total - dst.list.total;
            if (gap > 64 || gap >= best_gap) continue;
            best_gap = gap;
            best = ImportProfile{src.rva, dst.rva};
        }
    }
    return best;
}

std::optional<BootstrapProfile> find_bootstrap(const Image& im, AutoBootReport* report) {
    AutoBootReport local;
    AutoBootReport& rep = report ? *report : local;
    const std::vector<uint32_t> rel = im.relocations();
    std::vector<const Section*> code;
    for (const Section& s : im.sections)
        if (s.executable()) code.push_back(&s);
    if (code.size() < 2) {
        rep.why = "one code section only: no appended section, so nothing here looks protected";
        return std::nullopt;
    }
    auto relocs_in = [&](const Section& s) {
        return std::make_pair(std::lower_bound(rel.begin(), rel.end(), s.rva),
                              std::lower_bound(rel.begin(), rel.end(), s.end()));
    };
    std::vector<const Section*> order = code;
    std::stable_sort(order.begin(), order.end(), [&](const Section* a, const Section* b) {
        const auto ra = relocs_in(*a), rb = relocs_in(*b);
        return (ra.second - ra.first) > (rb.second - rb.first);
    });

    // 1. needles from the relocation table. Six relocations 9 to 127 bytes
    //    apart give twelve bytes, 08 L 08 L 08 L 08 L 08 L 08 L. Most such
    //    runs are not in the list (something else interrupts the cipher
    //    between them), so many are tried, and all in one pass over the
    //    image: a position is looked up only where bytes 0, 2 and 4 are 08.
    struct Needle {
        std::array<uint8_t, 12> bytes;
        uint32_t cursor;
        size_t first = SIZE_MAX;
        unsigned hits = 0;
    };
    std::vector<Needle> needles;
    for (const Section* s : order) {
        const auto [b, e] = relocs_in(*s);
        const size_t n = static_cast<size_t>(e - b);
        if (n < 8) continue;
        std::vector<size_t> starts;
        size_t run = 0;
        for (size_t i = 0; i + 1 < n; ++i) {
            const uint32_t d = b[i + 1] - b[i];
            run = (d > 8 && d < 128) ? run + 1 : 0;
            if (run >= 6) starts.push_back(i + 1 - 6);
        }
        const size_t step = std::max<size_t>(1, starts.size() / 8000);
        for (size_t k = 0; k < starts.size(); k += step) {
            Needle nd;
            for (size_t j = 0; j < 6; ++j) {
                nd.bytes[2 * j] = 8;
                nd.bytes[2 * j + 1] = static_cast<uint8_t>(b[starts[k] + j + 1] - b[starts[k] + j] - 8);
            }
            nd.cursor = b[starts[k]];
            needles.push_back(nd);
        }
    }
    {
        // needles by their six length bytes, packed into 48 bits
        auto pack = [](const uint8_t* p) {
            uint64_t v = 0;
            for (int j = 0; j < 6; ++j) v = (v << 8) | p[2 * j + 1];
            return v;
        };
        std::vector<std::pair<uint64_t, size_t>> index;
        index.reserve(needles.size());
        for (size_t i = 0; i < needles.size(); ++i) index.emplace_back(pack(needles[i].bytes.data()), i);
        std::sort(index.begin(), index.end());
        const uint8_t* m = im.mem.data();
        const size_t end = im.mem.size() >= 12 ? im.mem.size() - 12 : 0;
        for (size_t i = 0; i < end; ++i) {
            if (m[i] != 8 || m[i + 2] != 8 || m[i + 4] != 8 || m[i + 6] != 8 || m[i + 8] != 8 || m[i + 10] != 8)
                continue;
            const uint64_t v = pack(m + i);
            for (auto it = std::lower_bound(index.begin(), index.end(), std::make_pair(v, size_t{0}));
                 it != index.end() && it->first == v; ++it) {
                Needle& nd = needles[it->second];
                if (nd.hits++ == 0) nd.first = i;
            }
        }
    }
    size_t hit = SIZE_MAX;
    uint32_t hit_cursor = 0;
    for (const Needle& nd : needles)
        if (nd.hits == 1) {  // found, and in one place only
            hit = nd.first;
            hit_cursor = nd.cursor;
            // a needle is right only if the list really walks back from it
            if (list_start(im.mem, hit, hit_cursor) != SIZE_MAX) break;
            hit = SIZE_MAX;
        }
    if (hit == SIZE_MAX) {
        rep.why = "no run of relocations has its (gap, length) pairs anywhere in the image";
        return std::nullopt;
    }

    // 2. back to the list's first byte
    const size_t start = list_start(im.mem, hit, hit_cursor);
    if (start == SIZE_MAX) {
        rep.why = "the bytes before the relocation pairs do not walk back to a list that starts at RVA 0";
        return std::nullopt;
    }
    RangeList list;
    try {
        list = decode_ranges(im.mem.data() + start, im.mem.size() - start);
    } catch (const std::exception&) {
        rep.why = "the list found does not end in a terminator";
        return std::nullopt;
    }
    for (const Range& g : list.ranges)
        if (!im.in_bounds(g.rva, g.size)) {
            rep.why = "the list found has a range outside the image";
            return std::nullopt;
        }

    // the first bytes the keystream is applied to, and how much of them a
    // (key, starting block, cycles) guess turns into common code bytes
    std::vector<uint8_t> head;
    for (const Range& g : list.ranges) {
        for (uint32_t k = 0; k < g.size && head.size() < 512; ++k) head.push_back(im.mem[g.rva + k]);
        if (head.size() >= 512) break;
    }
    const auto& common = common_bytes();
    auto share_of = [&](uint32_t k, uint32_t v, unsigned rounds) {
        uint32_t key[4];
        std::memcpy(key, im.mem.data() + k, 16);
        XteaOfb ks(key, im.rd<uint32_t>(v), im.rd<uint32_t>(v + 4), rounds);
        std::vector<uint8_t> p = head;
        ks.apply(p.data(), p.size());
        size_t n = 0;
        for (uint8_t c : p) n += common[c];
        return p.empty() ? 0.0 : static_cast<double>(n) / static_cast<double>(p.size());
    };

    // 3a. The cipher's own set-up is plain compiled code and names all
    //     three things:
    //         mov dword ptr [rbp+10h], CYCLES
    //         mov dword ptr [rbp+14h], 9E3779B9h
    //         lea rax, [rip+KEY]   ; mov [rbp], rax
    //         lea rax, [rip+BLOCK] ; mov [rbp+8], rax
    //     The starting block is not always in the protection's section (the
    //     oldest build keeps it in the game's), so this is tried first.
    {
        static const uint8_t kDelta[] = {0xC7, 0x45, 0x14, 0xB9, 0x79, 0x37, 0x9E};
        static const uint8_t kLea[] = {0x48, 0x8D, 0x05};
        for (const Section* s : code) {
            const uint8_t* m = im.mem.data();
            const size_t lo = s->rva + 7, hi = static_cast<size_t>(s->end()) > 40 ? s->end() - 40 : 0;
            for (size_t i = lo; i < hi; ++i) {
                if (std::memcmp(m + i, kDelta, sizeof kDelta) != 0) continue;
                if (m[i - 7] != 0xC7 || m[i - 6] != 0x45 || m[i - 5] != 0x10) continue;
                const size_t a = i + 7, b = a + 11;
                if (std::memcmp(m + a, kLea, 3) != 0 || std::memcmp(m + a + 7, "\x48\x89\x45\x00", 4) != 0 ||
                    std::memcmp(m + b, kLea, 3) != 0 || std::memcmp(m + b + 7, "\x48\x89\x45\x08", 4) != 0)
                    continue;
                int32_t d1, d2;
                uint32_t cycles;
                std::memcpy(&cycles, m + i - 4, 4);
                std::memcpy(&d1, m + a + 3, 4);
                std::memcpy(&d2, m + b + 3, 4);
                const int64_t key = static_cast<int64_t>(a) + 7 + d1, blk = static_cast<int64_t>(b) + 7 + d2;
                if (key < 0 || blk < 0 || !im.in_bounds(static_cast<uint64_t>(key), 16) ||
                    !im.in_bounds(static_cast<uint64_t>(blk), 8) || cycles == 0 || cycles > 4096)
                    continue;
                const double sh = share_of(static_cast<uint32_t>(key), static_cast<uint32_t>(blk), cycles);
                if (sh > rep.best) rep.best = sh;
                if (sh > 0.45) {
                    rep.from_code = true;
                    rep.best = sh;
                    BootstrapProfile p;
                    p.key_rva = static_cast<uint32_t>(key);
                    p.iv_rva = static_cast<uint32_t>(blk);
                    p.ranges_rva = static_cast<uint32_t>(start);
                    p.rounds = cycles;
                    return p;
                }
            }
        }
    }

    // 3b. Otherwise by position: the key and the starting block are bytes
    //     the cipher skips and no relocation explains. Islands of every
    //     executable section.
    std::vector<Island> islands;
    for (const Section* sec : code) {
        std::vector<uint8_t> used(sec->vsize, 0);
        auto mark = [&](uint64_t rva, uint64_t n) {
            const uint64_t lo = std::max<uint64_t>(rva, sec->rva), hi = std::min<uint64_t>(rva + n, sec->end());
            for (uint64_t a = lo; a < hi; ++a) used[a - sec->rva] = 1;
        };
        for (const Range& g : list.ranges)
            if (g.rva < sec->end() && static_cast<uint64_t>(g.rva) + g.size > sec->rva) mark(g.rva, g.size);
        const auto [b, e] = relocs_in(*sec);
        for (auto it = b; it != e; ++it) mark(*it, 8);
        for (uint32_t i = 0; i < sec->vsize;) {
            if (used[i]) {
                ++i;
                continue;
            }
            uint32_t j = i;
            while (j < sec->vsize && !used[j]) ++j;
            islands.push_back({sec->rva + i, j - i});
            i = j;
        }
    }
    rep.islands = islands.size();
    auto candidates = [&](uint32_t size) {
        std::vector<uint32_t> c;
        for (const Island& x : islands)
            if (x.size == size) c.push_back(x.rva);
        if (c.empty())
            for (const Island& x : islands)
                if (x.size > size && x.size <= 64)
                    for (uint32_t k = 0; k + size <= x.size; ++k) c.push_back(x.rva + k);
        return c;
    };
    const std::vector<uint32_t> keys = candidates(16), ivs = candidates(8);
    rep.key_candidates = keys.size();
    rep.iv_candidates = ivs.size();
    if (keys.empty() || ivs.empty()) {
        rep.why = "the list leaves no island the size of a key or of a starting block";
        return std::nullopt;
    }

    for (unsigned rounds : {64u, 32u}) {
        double best = 0, second = 0;
        uint32_t bk = 0, bv = 0;
        for (uint32_t k : keys)
            for (uint32_t v : ivs) {
                const double share = share_of(k, v, rounds);
                if (share > best) {
                    second = best;
                    best = share;
                    bk = k;
                    bv = v;
                } else if (share > second) {
                    second = share;
                }
            }
        if (best > rep.best) {
            rep.best = best;
            rep.second = second;
        }
        if (best > 0.45 && second < 0.30) {
            rep.best = best;
            rep.second = second;
            BootstrapProfile p;
            p.key_rva = bk;
            p.iv_rva = bv;
            p.ranges_rva = static_cast<uint32_t>(start);
            p.rounds = rounds;
            return p;
        }
    }
    rep.why = "no (key, starting block) pair turns the first bytes of the stream into code";
    return std::nullopt;
}

}  // namespace mwdec
