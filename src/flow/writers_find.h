// The writer table read from an image whose bootstrap layer is off: the C++
// port of tools/find_writers.py and the list finder it uses
// (tools/find_lists.py). Same rows, same order, same file.
#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "flow/image.h"

namespace flow {

struct WriterRow {
    int64_t site = 0;
    bool writes_stash = false;
    std::string variant;
    int64_t list = 0, stash = 0, key = 0, bytes = 0;
    size_t nranges = 0;
    int round = 1;
};

struct WritersFound {
    std::vector<WriterRow> rows;          // in the order to apply them
    int64_t unsettled_sets = 0, unsettled_bytes = 0;
};

// Every range list of the mapped image (find_lists.find_lists on the image
// as find_writers.py hands it over): list RVA -> its ranges, in list order.
struct FoundRanges {
    int64_t rva = 0;
    std::vector<std::pair<int64_t, int64_t>> r;  // (rva, length)
    int64_t total = 0;
};
std::vector<FoundRanges> find_lists_mapped(const FImage& im);

// Rounds of: find the writers visible in the image, lay in the ones that
// decode, look again. The accepted rows are left laid into im.
WritersFound find_writers(FImage& im, const std::function<void(const std::string&)>& log);

// writers.tsv as find_writers.write_table writes it
std::string writers_tsv(const std::vector<WriterRow>& rows, const std::string& image_name);

int cmd_writers(int argc, char** argv);

}  // namespace flow
