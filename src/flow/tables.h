// The checks and the routine table, read from a decrypted image: the C++
// ports of tools/find_checks.py and tools/find_routines.py. Same plans, same
// JSON, byte for byte.
#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "flow/image.h"
#include "flow/json.h"

namespace flow {

// find_checks.scan: one slot-check sequence
struct SlotCheck {
    int64_t at = 0, P = 0, B = 0;
    std::optional<int64_t> A;
    std::string op, use;
    uint32_t need = 0, stat = 0;
    bool cut = false;
};

struct ChecksOut {
    std::vector<SlotCheck> checks;
    PlanF plan;        // checks_all.plan
    Json json;         // checks.json
    std::string line;  // the summary line find_checks.py prints
};
ChecksOut find_slot_checks(FImage& im);

struct RoutinesOut {
    Json json;       // routines.json
    PlanF stubs;     // routine_stubs.plan
    PlanF bake;      // checks.plan (the values that hold from the start)
};
// log gets find_routines.py's lines; image_name is what routines.json's meta names
RoutinesOut find_routines(FImage& im, const std::vector<SlotCheck>& checks, const std::string& image_name,
                          const std::function<void(const std::string&)>& log, int64_t limit = 400000);

int cmd_tables(int argc, char** argv);  // mwdec tables dec.exe --work DIR (both, as the two tools write them)

// a file as Python writes it in text mode (\n becomes \r\n)
void write_text_crlf(const std::string& path, const std::string& s);

}  // namespace flow
