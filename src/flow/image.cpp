#include "flow/image.h"

#include <windows.h>

#include <algorithm>
#include <fstream>
#include <map>
#include <stdexcept>

namespace flow {

void BigBuf::alloc(size_t n) {
    release();
    if (!n) return;
    p_ = static_cast<uint8_t*>(VirtualAlloc(nullptr, n, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!p_) throw std::runtime_error("out of memory (" + std::to_string(n) + " bytes)");
    n_ = n;
}

void BigBuf::release() {
    if (p_) {
        if (kind_ == 0)
            VirtualFree(p_, 0, MEM_RELEASE);
        else
            UnmapViewOfFile(p_);
    }
    if (h_ && kind_ == 1) CloseHandle(h_);
    p_ = nullptr;
    n_ = 0;
    h_ = nullptr;
    kind_ = 0;
}

void BigBuf::alloc_shared(size_t n) {
    release();
    if (!n) return;
    HANDLE h = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, static_cast<DWORD>(uint64_t(n) >> 32),
                                  static_cast<DWORD>(n & 0xFFFFFFFFu), nullptr);
    if (!h) throw std::runtime_error("out of memory (section of " + std::to_string(n) + " bytes)");
    void* p = MapViewOfFile(h, FILE_MAP_ALL_ACCESS, 0, 0, n);
    if (!p) {
        CloseHandle(h);
        throw std::runtime_error("out of memory (view of " + std::to_string(n) + " bytes)");
    }
    p_ = static_cast<uint8_t*>(p);
    n_ = n;
    h_ = h;
    kind_ = 1;
}

BigBuf BigBuf::cow_view() const {
    if (kind_ != 1) throw std::runtime_error("cow_view of memory that is not a section");
    BigBuf b;
    void* p = MapViewOfFile(static_cast<HANDLE>(h_), FILE_MAP_COPY, 0, 0, n_);
    if (!p) throw std::runtime_error("out of memory (copy-on-write view of " + std::to_string(n_) + " bytes)");
    b.p_ = static_cast<uint8_t*>(p);
    b.n_ = n_;
    b.kind_ = 2;
    return b;
}

FImage FImage::cow_copy() const {
    FImage c;
    c.path = path;
    c.len = len;
    c.image_base = image_base;
    c.entry_rva = entry_rva;
    c.size_of_image = size_of_image;
    c.size_of_headers = size_of_headers;
    c.dirs = dirs;
    c.sections = sections;
    c.mem = mem.cow_view();
    return c;
}

static std::vector<uint8_t> slurp(const std::string& p) {
    std::ifstream f(p, std::ios::binary | std::ios::ate);
    if (!f) throw std::runtime_error("cannot open " + p);
    const std::streamoff n = f.tellg();
    std::vector<uint8_t> b(static_cast<size_t>(n));
    f.seekg(0);
    f.read(reinterpret_cast<char*>(b.data()), n);
    if (!f) throw std::runtime_error("short read on " + p);
    return b;
}

template <class T> static T rd(const std::vector<uint8_t>& b, size_t o) {
    if (o + sizeof(T) > b.size()) throw std::runtime_error("truncated PE file");
    T v;
    std::memcpy(&v, b.data() + o, sizeof(T));
    return v;
}

void FImage::load(const std::string& p) { load_bytes(slurp(p), p); }

void FImage::load_bytes(std::vector<uint8_t> bytes, const std::string& p) {
    path = p;
    file = std::move(bytes);
    const auto& fb = file;
    const uint32_t pe = rd<uint32_t>(fb, 0x3C);
    if (rd<uint32_t>(fb, pe) != 0x00004550) throw std::runtime_error("not a PE file");
    const uint16_t nsec = rd<uint16_t>(fb, pe + 6);
    const uint16_t optsz = rd<uint16_t>(fb, pe + 20);
    const size_t opt = pe + 24;
    if (rd<uint16_t>(fb, opt) != 0x20B) throw std::runtime_error("expected a PE32+ image");
    entry_rva = rd<uint32_t>(fb, opt + 16);
    image_base = rd<uint64_t>(fb, opt + 24);
    size_of_image = rd<uint32_t>(fb, opt + 56);
    size_of_headers = rd<uint32_t>(fb, opt + 60);
    const uint32_t ndirs = rd<uint32_t>(fb, opt + 108);
    for (uint32_t i = 0; i < ndirs; ++i)
        dirs.emplace_back(rd<uint32_t>(fb, opt + 112 + 8 * i), rd<uint32_t>(fb, opt + 116 + 8 * i));
    const size_t base = opt + optsz;
    for (int i = 0; i < nsec; ++i) {
        const size_t o = base + 40 * static_cast<size_t>(i);
        PSection s;
        s.index = i;
        size_t nl = 0;
        while (nl < 8 && fb[o + nl]) ++nl;
        s.name.assign(reinterpret_cast<const char*>(fb.data() + o), nl);
        // rstrip(b"\0") of the 8 bytes: a name with embedded zeros keeps them
        {
            size_t e = 8;
            while (e > 0 && fb[o + e - 1] == 0) --e;
            s.name.assign(reinterpret_cast<const char*>(fb.data() + o), e);
        }
        s.vsize = rd<uint32_t>(fb, o + 8);
        s.rva = rd<uint32_t>(fb, o + 12);
        s.rsize = rd<uint32_t>(fb, o + 16);
        s.raw = rd<uint32_t>(fb, o + 20);
        s.chars = rd<uint32_t>(fb, o + 36);
        sections.push_back(s);
    }
    len = (static_cast<int64_t>(size_of_image) + 0xFFF) & ~int64_t(0xFFF);
    mem.alloc_shared(static_cast<size_t>(len));
    const size_t h = std::min<size_t>(size_of_headers, fb.size());
    if (h > static_cast<size_t>(len)) throw std::runtime_error("headers beyond the image");
    std::memcpy(mem.data(), fb.data(), h);
    for (const PSection& s : sections) {
        const size_t n = s.vsize ? std::min(s.rsize, s.vsize) : s.rsize;
        if (static_cast<int64_t>(s.rva) + static_cast<int64_t>(n) > len || s.raw + n > fb.size())
            throw std::runtime_error("section " + s.name + " does not fit (the Python reader would resize)");
        std::memcpy(mem.data() + s.rva, fb.data() + s.raw, n);
    }
    // the file's bytes are not looked at again: everything works on the
    // mapped copy. Kept, they were 300 MB for the whole run.
    std::vector<uint8_t>().swap(file);
}

const PSection* FImage::section_of(int64_t rva) const {
    for (const PSection& s : sections)
        if (s.rva <= rva && rva < static_cast<int64_t>(s.rva) + std::max(s.vsize, s.rsize)) return &s;
    return nullptr;
}

std::vector<const PSection*> FImage::exec_sections() const {
    std::vector<const PSection*> o;
    for (const PSection& s : sections)
        if (s.executable()) o.push_back(&s);
    return o;
}

uint32_t FImage::u32(int64_t rva) const {
    if (rva < 0 || rva + 4 > len) throw std::runtime_error("u32 outside the image");
    uint32_t v;
    std::memcpy(&v, mem.data() + rva, 4);
    return v;
}

uint64_t FImage::u64(int64_t rva) const {
    if (rva < 0 || rva + 8 > len) throw std::runtime_error("u64 outside the image");
    uint64_t v;
    std::memcpy(&v, mem.data() + rva, 8);
    return v;
}

const std::vector<int64_t>& FImage::relocations() const {
    if (!have_relocs_) {
        have_relocs_ = true;
        const uint32_t rva = dirs.size() > 5 ? dirs[5].first : 0;
        const uint32_t size = dirs.size() > 5 ? dirs[5].second : 0;
        int64_t off = rva;
        const int64_t end = static_cast<int64_t>(rva) + size;
        while (off + 8 <= end) {
            const uint32_t page = u32(off), bsz = u32(off + 4);
            if (bsz < 8) break;
            const int64_t cnt = (bsz - 8) / 2;
            for (int64_t k = 0; k < cnt; ++k) {
                uint16_t e;
                std::memcpy(&e, mem.data() + off + 8 + 2 * k, 2);
                if ((e >> 12) == 10) relocs_.push_back(static_cast<int64_t>(page) + (e & 0xFFF));
            }
            off += bsz;
        }
        std::sort(relocs_.begin(), relocs_.end());
    }
    return relocs_;
}

std::vector<std::array<uint32_t, 3>> FImage::runtime_functions() const {
    const uint32_t rva = dirs.size() > 3 ? dirs[3].first : 0;
    const uint32_t size = dirs.size() > 3 ? dirs[3].second : 0;
    const size_t n = size / 12;
    std::vector<std::array<uint32_t, 3>> o(n);
    if (n) std::memcpy(o.data(), mem.data() + rva, n * 12);
    return o;
}

std::vector<int64_t> FImage::tls_callbacks() const {
    std::vector<int64_t> o;
    const uint32_t rva = dirs.size() > 9 ? dirs[9].first : 0;
    if (!rva) return o;
    const uint64_t array_va = u64(rva + 24);
    const int64_t r = static_cast<int64_t>(array_va - image_base);
    if (array_va < image_base || !(0 <= r && r < len)) return o;
    int64_t arr = r;
    while (true) {
        const uint64_t v = u64(arr);
        if (!v) break;
        o.push_back(static_cast<int64_t>(v - image_base));
        arr += 8;
    }
    return o;
}

PlanF PlanF::load(const std::string& path) {
    const std::vector<uint8_t> b = slurp(path);
    if (b.size() < 8 || std::memcmp(b.data(), "MWPLAN1\0", 8) != 0)
        throw std::runtime_error("not a plan file: " + path);
    size_t o = 8;
    PlanF p;
    const uint32_t n = rd<uint32_t>(b, o);
    o += 4;
    for (uint32_t i = 0; i < n; ++i) {
        PlanPatchF x;
        x.rva = rd<uint32_t>(b, o);
        const uint32_t ln = rd<uint32_t>(b, o + 4);
        x.kind = rd<uint8_t>(b, o + 8);
        o += 9;
        if (o + ln > b.size()) throw std::runtime_error("truncated plan " + path);
        x.data.assign(b.begin() + static_cast<std::ptrdiff_t>(o), b.begin() + static_cast<std::ptrdiff_t>(o + ln));
        o += ln;
        p.patches.push_back(std::move(x));
    }
    const uint32_t nd = rd<uint32_t>(b, o);
    o += 4;
    for (uint32_t i = 0; i < nd; ++i, o += 4) p.drops.push_back(rd<uint32_t>(b, o));
    const uint32_t nw = rd<uint32_t>(b, o);
    o += 4;
    for (uint32_t i = 0; i < nw; ++i, o += 8) p.wipes.emplace_back(rd<uint32_t>(b, o), rd<uint32_t>(b, o + 4));
    return p;
}

void PlanF::save(const std::string& path) const {
    std::vector<uint8_t> o;
    auto put32 = [&o](uint32_t v) {
        for (int i = 0; i < 4; ++i) o.push_back(static_cast<uint8_t>(v >> (8 * i)));
    };
    o.insert(o.end(), {'M', 'W', 'P', 'L', 'A', 'N', '1', 0});
    put32(static_cast<uint32_t>(patches.size()));
    for (const PlanPatchF& p : patches) {
        put32(p.rva);
        put32(static_cast<uint32_t>(p.data.size()));
        o.push_back(p.kind);
        o.insert(o.end(), p.data.begin(), p.data.end());
    }
    put32(static_cast<uint32_t>(drops.size()));
    for (uint32_t d : drops) put32(d);
    put32(static_cast<uint32_t>(wipes.size()));
    for (const auto& [r, n] : wipes) {
        put32(r);
        put32(n);
    }
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) throw std::runtime_error("cannot write " + path);
    f.write(reinterpret_cast<const char*>(o.data()), static_cast<std::streamsize>(o.size()));
}

std::string PlanF::summary() const {
    static const char* const names[] = {"0", "boot", "import", "stub", "bake", "bypass", "flow", "other"};
    std::map<int, std::pair<size_t, size_t>> k;
    for (const PlanPatchF& p : patches) {
        auto& e = k[p.kind];
        e.first++;
        e.second += p.data.size();
    }
    std::string parts;
    for (const auto& [kind, v] : k) {
        if (!parts.empty()) parts += ", ";
        parts += (kind >= 1 && kind <= 7 ? names[kind] : std::to_string(kind)) + std::string(" ") +
                 std::to_string(v.first) + " (" + std::to_string(v.second) + " bytes)";
    }
    size_t wb = 0;
    for (const auto& w : wipes) wb += w.second;
    return "patches: " + (parts.empty() ? std::string("none") : parts) + "; relocations dropped: " +
           std::to_string(drops.size()) + "; wiped: " + std::to_string(wipes.size()) + " ranges, " +
           std::to_string(wb) + " bytes";
}

void save_npy_u8(const std::string& path, const uint8_t* data, size_t n) {
    std::string h = "{'descr': '|u1', 'fortran_order': False, 'shape': (" + std::to_string(n) + ",), }";
    const size_t digits = std::to_string(n).size();
    if (digits < 21) h.append(21 - digits, ' ');
    const size_t pad = 64 - ((10 + h.size() + 1) % 64);
    h.append(pad, ' ');
    h += '\n';
    std::string o = "\x93NUMPY";
    o += '\x01';
    o += '\x00';
    o += static_cast<char>(h.size() & 0xFF);
    o += static_cast<char>(h.size() >> 8);
    o += h;
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) throw std::runtime_error("cannot write " + path);
    f.write(o.data(), static_cast<std::streamsize>(o.size()));
    f.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(n));
}

std::string basename_of(const std::string& p) {
    const size_t k = p.find_last_of("\\/");
    return k == std::string::npos ? p : p.substr(k + 1);
}

}  // namespace flow
