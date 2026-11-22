#include "plan.h"

#include <cstring>
#include <unordered_map>

namespace mwdec {

namespace {
struct Reader {
    const std::vector<uint8_t>& b;
    size_t o = 0;
    template <class T> T get() {
        if (o + sizeof(T) > b.size()) throw std::runtime_error("truncated plan file");
        T v;
        std::memcpy(&v, b.data() + o, sizeof(T));
        o += sizeof(T);
        return v;
    }
};

bool touches_directory(const Image& im, uint32_t rva, uint32_t n) {
    if (rva < im.size_of_headers) return true;
    for (int i = 0; i < 16; ++i) {
        if (i == 4) continue;  // certificate table: a file offset, not an RVA
        const DataDir d = im.dirs[i];
        if (d.rva && rva < d.rva + d.size && d.rva < rva + n) return true;
    }
    return false;
}
}  // namespace

const char* plan_kind_name(unsigned kind) {
    static const char* const names[8] = {"other", "boot", "import", "stub", "bake", "bypass", "flow", "other"};
    return names[kind < 8 ? kind : 0];
}

Plan Plan::load(const std::filesystem::path& path) {
    const std::vector<uint8_t> b = read_file(path);
    if (b.size() < 8 || std::memcmp(b.data(), "MWPLAN1\0", 8) != 0)
        throw std::runtime_error("not a plan file: " + path.string());
    Reader r{b, 8};
    Plan p;
    const uint32_t np = r.get<uint32_t>();
    p.patches.reserve(np);
    for (uint32_t i = 0; i < np; ++i) {
        PlanPatch x;
        x.rva = r.get<uint32_t>();
        const uint32_t len = r.get<uint32_t>();
        x.kind = r.get<uint8_t>();
        if (r.o + len > b.size()) throw std::runtime_error("truncated plan file");
        x.bytes.assign(b.begin() + static_cast<std::ptrdiff_t>(r.o),
                       b.begin() + static_cast<std::ptrdiff_t>(r.o + len));
        r.o += len;
        p.patches.push_back(std::move(x));
    }
    const uint32_t nd = r.get<uint32_t>();
    p.drop_relocs.reserve(nd);
    for (uint32_t i = 0; i < nd; ++i) p.drop_relocs.push_back(r.get<uint32_t>());
    const uint32_t nw = r.get<uint32_t>();
    p.wipes.reserve(nw);
    for (uint32_t i = 0; i < nw; ++i) {
        Range g;
        g.rva = r.get<uint32_t>();
        g.size = r.get<uint32_t>();
        p.wipes.push_back(g);
    }
    return p;
}

void apply_plans(Image& im, const std::vector<Plan>& plans, PlanStats& stats,
                 std::vector<uint8_t>& wiped_bits) {
    if (wiped_bits.empty()) wiped_bits.assign(im.mem.size() / 8 + 1, 0);
    // 1. Every wipe of every plan. Bytes are counted once.
    for (const Plan& plan : plans)
        for (const Range& g : plan.wipes) {
            if (!im.in_bounds(g.rva, g.size) || touches_directory(im, g.rva, g.size)) {
                ++stats.wipes_refused;
                continue;
            }
            std::memset(im.mem.data() + g.rva, 0xCC, g.size);
            for (uint32_t a = g.rva; a < g.rva + g.size; ++a) {
                uint8_t& b = wiped_bits[a >> 3];
                const uint8_t m = static_cast<uint8_t>(1u << (a & 7));
                if (!(b & m)) ++stats.wiped_bytes;
                b |= m;
            }
            ++stats.wiped_ranges;
        }
    // 2. Every patch, so that no plan's wipe can land on another plan's
    //    patch. Two plans writing different values to one byte is an error
    //    in the plans; it is counted and the later plan wins.
    std::vector<uint8_t> patched(im.mem.size() / 8 + 1, 0);
    for (const Plan& plan : plans)
        for (const PlanPatch& x : plan.patches) {
            if (!im.in_bounds(x.rva, x.bytes.size()) || x.rva < im.size_of_headers)
                throw std::runtime_error("plan patch outside the image");
            for (uint32_t i = 0; i < x.bytes.size(); ++i) {
                const uint32_t a = x.rva + i;
                const uint8_t m = static_cast<uint8_t>(1u << (a & 7));
                if ((patched[a >> 3] & m) && im.mem[a] != x.bytes[i]) ++stats.patch_conflicts;
                patched[a >> 3] |= m;
                if (wiped_bits[a >> 3] & m) {       // a patch re-establishes a wiped byte
                    wiped_bits[a >> 3] &= static_cast<uint8_t>(~m);
                    --stats.wiped_bytes;
                    ++stats.patched_over_wipes;
                }
                im.mem[a] = x.bytes[i];
            }
            const unsigned k = x.kind < 8 ? x.kind : 0;
            ++stats.patches[k];
            stats.patch_bytes[k] += x.bytes.size();
        }
    // 3. Listed relocation drops.
    std::unordered_map<uint32_t, uint32_t> entry;
    bool loaded = false;
    for (const Plan& plan : plans) {
        if (plan.drop_relocs.empty()) continue;
        if (!loaded) {
            for (const auto& [site, at] : im.relocation_entries()) entry[site] = at;
            loaded = true;
        }
        for (uint32_t site : plan.drop_relocs) {
            const auto it = entry.find(site);
            if (it == entry.end()) continue;
            const uint16_t zero = 0;  // IMAGE_REL_BASED_ABSOLUTE: skipped by the loader
            std::memcpy(im.mem.data() + it->second, &zero, 2);
            entry.erase(it);
            ++stats.relocs_dropped_listed;
        }
    }
}

uint32_t prune_exception_directory(Image& im, const std::vector<uint8_t>& wiped_bits) {
    const uint32_t rva = im.dirs[3].rva, size = im.dirs[3].size;
    if (!rva || size < 12 || wiped_bits.empty() || !im.in_bounds(rva, size)) return 0;
    const uint32_t n = size / 12;
    uint8_t* t = im.mem.data() + rva;
    uint32_t kept = 0;
    for (uint32_t i = 0; i < n; ++i) {
        uint32_t begin, end;
        std::memcpy(&begin, t + 12 * i, 4);
        std::memcpy(&end, t + 12 * i + 4, 4);
        bool dead = end > begin && im.in_bounds(begin, end - begin);
        for (uint32_t a = begin; dead && a < end; ++a)
            dead = ((wiped_bits[a >> 3] >> (a & 7)) & 1) != 0;
        if (dead) continue;
        if (kept != i) std::memmove(t + 12 * kept, t + 12 * i, 12);
        ++kept;
    }
    if (kept == n) return 0;
    std::memset(t + 12 * kept, 0, 12 * static_cast<size_t>(n - kept));
    im.set_dir(3, rva, kept * 12);
    return n - kept;
}

void settle_relocations(Image& im, const std::vector<uint8_t>& wiped_bits, PlanStats& stats) {
    const uint16_t zero = 0;
    for (const auto& [site, at] : im.relocation_entries()) {
        if (!im.in_bounds(site, 8)) continue;
        bool wiped = false;
        if (!wiped_bits.empty())
            for (uint32_t a = site; a < site + 8; ++a) wiped |= ((wiped_bits[a >> 3] >> (a & 7)) & 1) != 0;
        const uint64_t v = im.rd<uint64_t>(site);
        const bool dangling = v < im.image_base || v - im.image_base >= im.mem.size();
        if (wiped) {
            std::memcpy(im.mem.data() + at, &zero, 2);
            ++stats.relocs_dropped_in_wipes;
        } else if (dangling) {
            std::memcpy(im.mem.data() + at, &zero, 2);
            ++stats.relocs_dropped_dangling;
        } else {
            ++stats.relocs_left;
        }
    }
}

}  // namespace mwdec
