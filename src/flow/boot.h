// The start-up path and the import tables: the C++ port of
// tools/devirt_boot.py (with the walk and fold of tools/entry_layout.py it
// uses). Same plan, byte for byte.
#pragma once

#include <string>

#include "flow/image.h"
#include "flow/json.h"

namespace flow {

struct BootOut {
    PlanF plan;   // boot.plan
    Json report;  // boot.json
};

// imports_tsv: what `mwdec imports` writes
BootOut devirt_boot(const FImage& im, const std::string& imports_tsv);

int cmd_boot(int argc, char** argv);  // mwdec boot dec.exe --imports imports.tsv -o boot.plan [--report boot.json]

}  // namespace flow
