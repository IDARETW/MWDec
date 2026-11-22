// Patch plans: what the analysis tools decided, applied to the decrypted
// image to remove the protection.
//
// A plan is data. It lists byte patches (by RVA), relocation entries to
// delete, and ranges to fill with int3. The analysis that produced it is in
// tools/ (devirt_boot.py and friends); this file only applies it and keeps
// the PE consistent afterwards. See tools/planfile.py for the file layout.
#pragma once

#include <cstdint>
#include <filesystem>
#include <vector>

#include "pe.h"
#include "ranges.h"

namespace mwdec {

struct PlanPatch {
    uint32_t rva = 0;
    uint8_t kind = 0;
    std::vector<uint8_t> bytes;
};

struct Plan {
    std::vector<PlanPatch> patches;
    std::vector<uint32_t> drop_relocs;
    std::vector<Range> wipes;

    static Plan load(const std::filesystem::path& path);
};

struct PlanStats {
    uint64_t patches[8]{};        // count by kind (index 0 = unknown kinds)
    uint64_t patch_bytes[8]{};
    uint64_t wiped_ranges = 0, wiped_bytes = 0;
    uint64_t wipes_refused = 0;   // ranges that touch a PE directory or leave the image
    uint64_t patched_over_wipes = 0;  // bytes one plan wipes and a plan patches
    uint64_t patch_conflicts = 0;     // bytes two patches set to different values
    uint64_t relocs_dropped_listed = 0;
    uint64_t relocs_dropped_in_wipes = 0;
    uint64_t relocs_dropped_dangling = 0;
    uint64_t relocs_left = 0;
};

const char* plan_kind_name(unsigned kind);

// All wipes of all plans, then all patches in plan order, then the listed
// relocation drops. The result does not depend on the order of the plans
// unless two of them patch the same byte differently (counted in stats).
void apply_plans(Image& im, const std::vector<Plan>& plans, PlanStats& stats,
                 std::vector<uint8_t>& wiped_bits);

// Removes exception-directory records whose whole range was wiped: no
// instruction pointer can be inside them any more. Returns how many.
uint32_t prune_exception_directory(Image& im, const std::vector<uint8_t>& wiped_bits);

// After every plan: deletes relocation entries whose site was wiped, and
// entries whose 8 bytes no longer hold an address inside the image (a
// patch replaced the pointer with code). Counts what is left.
void settle_relocations(Image& im, const std::vector<uint8_t>& wiped_bits, PlanStats& stats);

}  // namespace mwdec
