#include "verify.h"

#include <algorithm>
#include <cstring>
#include <map>

namespace mwdec {

namespace {
void rebase(Image& im, const std::vector<uint32_t>& relocs, int64_t delta) {
    for (uint32_t r : relocs) {
        if (!im.in_bounds(r, 8)) continue;
        uint64_t v;
        std::memcpy(&v, im.mem.data() + r, 8);
        v += static_cast<uint64_t>(delta);
        std::memcpy(im.mem.data() + r, &v, 8);
    }
}
}  // namespace

VerifyResult verify_against_dump(Image& im, const Image& dump,
                                 const std::vector<uint8_t>& touched, uint32_t merge_gap) {
    VerifyResult out;
    const std::vector<uint32_t> relocs = im.relocations();
    out.reloc_sites = relocs.size();

    // The dump's load address: the most common displacement between the two
    // images at relocation sites.
    std::map<int64_t, unsigned> votes;
    unsigned sampled = 0;
    for (size_t i = 0; i < relocs.size() && sampled < 65536; i += 7) {
        const uint32_t r = relocs[i];
        if (!im.in_bounds(r, 8) || !dump.in_bounds(r, 8)) continue;
        ++votes[static_cast<int64_t>(dump.rd<uint64_t>(r) - im.rd<uint64_t>(r))];
        ++sampled;
    }
    unsigned best = 0;
    for (const auto& [d, n] : votes)
        if (n > best) best = n, out.delta = d;

    rebase(im, relocs, out.delta);
    const auto is_touched = [&](uint32_t a) {
        return !touched.empty() && (touched[a >> 3] >> (a & 7)) & 1;
    };

    for (const Section& s : im.sections) {
        SectionDiff sd;
        sd.section = s;
        const uint64_t lim = std::min<uint64_t>({s.end(), im.mem.size(), dump.mem.size()});
        DiffRun run;
        bool open = false;
        uint32_t last_diff = 0;
        const uint8_t* a = im.mem.data();
        const uint8_t* b = dump.mem.data();
        for (uint64_t p = s.rva; p < lim; ++p) {
            ++sd.compared;
            if (a[p] == b[p]) continue;
            const uint32_t rva = static_cast<uint32_t>(p);
            const bool t = is_touched(rva);
            ++sd.differ;
            sd.differ_in_mask += t;
            if (open && rva - last_diff > merge_gap) {
                run.size = last_diff - run.rva + 1;
                out.runs.push_back(run);
                open = false;
            }
            if (!open) {
                run = DiffRun{rva, 0, 0, 0};
                open = true;
            }
            ++run.differing;
            run.in_mask += t;
            last_diff = rva;
        }
        if (open) {
            run.size = last_diff - run.rva + 1;
            out.runs.push_back(run);
        }
        out.sections.push_back(sd);
    }

    rebase(im, relocs, -out.delta);
    return out;
}

}  // namespace mwdec
