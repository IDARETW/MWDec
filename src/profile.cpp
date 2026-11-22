#include "profile.h"

namespace mwdec {

namespace {
const WriterProfile kWriters19936[] = {
#include "writers_19936.inc"
};

std::vector<BuildProfile> make_profiles() {
    std::vector<BuildProfile> v;
    BuildProfile p;
    p.name = "Modern Warfare (2019) 1.51.2 (build 19936)";
    p.time_date_stamp = 0x61E72FE0;
    p.size_of_image = 0x29589400;
    p.entry_rva = 0x070D9224;
    p.bootstrap = {0x23BF3897, 0x26D860DC, 0x25A8CA90, 64, 0x9E3779B9u};
    p.imports = {0x26D045AE, 0x23B163B3};
    p.writers.assign(std::begin(kWriters19936), std::end(kWriters19936));
    v.push_back(std::move(p));
    return v;
}
}  // namespace

std::optional<BuildProfile> find_profile(const Image& im) {
    static const std::vector<BuildProfile> profiles = make_profiles();
    for (const BuildProfile& p : profiles)
        if (p.time_date_stamp == im.time_date_stamp && p.size_of_image == im.size_of_image &&
            p.entry_rva == im.entry_rva)
            return p;
    return std::nullopt;
}

}  // namespace mwdec
