// Minimal PE32+ reader: just what a static decryptor needs.
//
// The image is held as one flat buffer laid out by RVA, the way the loader
// maps it, so every address in MWDec is an RVA and a buffer index at once.
#pragma once

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace mwdec {

struct Section {
    int index = 0;
    std::string name;
    uint32_t rva = 0, vsize = 0, raw = 0, rsize = 0, chars = 0;
    uint32_t header = 0;  // file offset (= RVA) of this section's header

    uint32_t end() const { return rva + vsize; }
    bool executable() const { return (chars & 0x20000000u) != 0; }
    bool writable() const { return (chars & 0x80000000u) != 0; }
    bool contains(uint32_t a) const { return a >= rva && a < end(); }
};

struct DataDir {
    uint32_t rva = 0, size = 0;
};

class Image {
public:
    // keep_file: retain the original file bytes so save() can write the
    // image back in file layout. Not needed for a reference dump.
    static Image load(const std::filesystem::path& path, bool keep_file = true);

    std::filesystem::path path;
    std::vector<uint8_t> mem;   // SizeOfImage bytes, indexed by RVA
    std::vector<uint8_t> file;  // original file (empty unless keep_file)
    std::vector<Section> sections;
    DataDir dirs[16]{};
    uint64_t image_base = 0;
    uint32_t entry_rva = 0, size_of_image = 0, size_of_headers = 0;
    uint32_t time_date_stamp = 0, checksum = 0;

    bool in_bounds(uint64_t rva, uint64_t n) const {
        return rva <= mem.size() && n <= mem.size() - rva;
    }
    template <class T> T rd(uint32_t rva) const {
        if (!in_bounds(rva, sizeof(T))) throw std::out_of_range("read outside image");
        T v;
        std::memcpy(&v, mem.data() + rva, sizeof(T));
        return v;
    }
    const Section* section_of(uint32_t rva) const;
    // VA -> RVA; returns false if the value is not inside the image.
    bool va_to_rva(uint64_t va, uint32_t& rva) const;

    // RVAs of every IMAGE_REL_BASED_DIR64 site, ascending.
    std::vector<uint32_t> relocations() const;
    // RVAs of the TLS callbacks, in loader order.
    std::vector<uint32_t> tls_callbacks() const;

    // (site RVA, RVA of its 16-bit entry in the relocation directory) for
    // every DIR64 relocation, in directory order.
    std::vector<std::pair<uint32_t, uint32_t>> relocation_entries() const;
    // Rewrites a data-directory entry, here and in the mapped headers.
    void set_dir(int index, uint32_t rva, uint32_t size);

    // Writes the (possibly modified) image back in the original file layout.
    // finalize: also write back edited headers, drop a certificate table
    // whose directory entry was cleared, and recompute the PE checksum.
    void save(const std::filesystem::path& out, bool finalize = false) const;
    // the bytes save() writes
    std::vector<uint8_t> file_bytes(bool finalize = false) const;

    uint32_t opt_offset = 0;  // file offset (= RVA) of the optional header
};

std::vector<uint8_t> read_file(const std::filesystem::path& p);

}  // namespace mwdec
