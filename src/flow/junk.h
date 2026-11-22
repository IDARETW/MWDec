// The protection's junk constructs: the C++ port of tools/find_junk.py.
// Same plan, byte for byte.
#pragma once

#include <functional>
#include <string>
#include <vector>

#include "flow/image.h"
#include "flow/json.h"

namespace flow {

struct JunkOut {
    PlanF plan;    // junk.plan
    Json report;   // junk.json
    int64_t proved_wrong = 0;
};

// plans: the earlier plans (their patches are not written over); prove: how
// many constructs to run in the emulator (0: none); older: also the older
// form that does not save the flags (kept only where they are proved unused)
JunkOut find_junk(const FImage& im, const std::vector<const PlanF*>& plans, const std::vector<std::string>& names,
                  int prove, bool older, const std::function<void(const std::string&)>& log);

int cmd_junk(int argc, char** argv);  // mwdec junk dec.exe -o junk.plan [--report J] [--plan P ...] [--prove N] [--older]

}  // namespace flow
