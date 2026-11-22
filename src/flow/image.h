// The image as mwdec/pe.py maps it (same sizes, same reads), plan files as
// tools/planfile.py writes them, and a few containers for large flag arrays.
#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

namespace flow {

// Zero-filled memory from the OS: pages nobody touches cost nothing.
class BigBuf {
public:
    BigBuf() = default;
    explicit BigBuf(size_t n) { alloc(n); }
    ~BigBuf() { release(); }
    BigBuf(const BigBuf&) = delete;
    BigBuf& operator=(const BigBuf&) = delete;
    BigBuf(BigBuf&& o) noexcept : p_(o.p_), n_(o.n_), h_(o.h_), kind_(o.kind_) {
        o.p_ = nullptr;
        o.n_ = 0;
        o.h_ = nullptr;
        o.kind_ = 0;
    }
    BigBuf& operator=(BigBuf&& o) noexcept {
        if (this != &o) {
            release();
            p_ = o.p_;
            n_ = o.n_;
            h_ = o.h_;
            kind_ = o.kind_;
            o.p_ = nullptr;
            o.n_ = 0;
            o.h_ = nullptr;
            o.kind_ = 0;
        }
        return *this;
    }
    void alloc(size_t n);
    // memory in a pagefile-backed section, of which cow_view() can make a
    // copy-on-write view: the same bytes, and writes to the view stay its own
    void alloc_shared(size_t n);
    BigBuf cow_view() const;
    void release();
    uint8_t* data() { return p_; }
    const uint8_t* data() const { return p_; }
    size_t size() const { return n_; }
    uint8_t& operator[](size_t i) { return p_[i]; }
    uint8_t operator[](size_t i) const { return p_[i]; }

private:
    uint8_t* p_ = nullptr;
    size_t n_ = 0;
    void* h_ = nullptr;  // the section (kind 1)
    int kind_ = 0;       // 0 VirtualAlloc, 1 a section's view (owns the section), 2 a copy-on-write view
};

struct PSection {
    int index = 0;
    std::string name;
    uint32_t rva = 0, vsize = 0, raw = 0, rsize = 0, chars = 0;
    bool executable() const { return (chars & 0x20000000u) != 0; }
};

struct FImage {
    std::string path;
    std::vector<uint8_t> file;
    BigBuf mem;
    int64_t len = 0;
    uint64_t image_base = 0;
    uint32_t entry_rva = 0, size_of_image = 0, size_of_headers = 0;
    std::vector<std::pair<uint32_t, uint32_t>> dirs;
    std::vector<PSection> sections;

    void load(const std::string& p);
    void load_bytes(std::vector<uint8_t> bytes, const std::string& name);  // the file's bytes, already read
    // the same image over a copy-on-write view of its memory: writes to the
    // copy stay the copy's; the copy must go before this one does
    FImage cow_copy() const;
    const PSection* section_of(int64_t rva) const;
    std::vector<const PSection*> exec_sections() const;
    uint32_t u32(int64_t rva) const;
    uint64_t u64(int64_t rva) const;
    const std::vector<int64_t>& relocations() const;
    std::vector<std::array<uint32_t, 3>> runtime_functions() const;
    std::vector<int64_t> tls_callbacks() const;

private:
    mutable std::vector<int64_t> relocs_;
    mutable bool have_relocs_ = false;
};

struct PlanPatchF {
    uint32_t rva;
    uint8_t kind;
    std::vector<uint8_t> data;
};

struct PlanF {
    std::vector<PlanPatchF> patches;
    std::vector<uint32_t> drops;
    std::vector<std::pair<uint32_t, uint32_t>> wipes;

    static PlanF load(const std::string& path);
    void save(const std::string& path) const;
    std::string summary() const;
};

enum : uint8_t { KIND_BOOT = 1, KIND_IMPORT = 2, KIND_STUB = 3, KIND_BAKE = 4, KIND_BYPASS = 5, KIND_FLOW = 6 };

// np.save of a 1-D uint8 array
void save_npy_u8(const std::string& path, const uint8_t* data, size_t n);

std::string basename_of(const std::string& p);

}  // namespace flow
