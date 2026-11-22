#include "pe.h"

#include <algorithm>
#include <fstream>

namespace mwdec {

std::vector<uint8_t> read_file(const std::filesystem::path& p) {
    std::ifstream f(p, std::ios::binary | std::ios::ate);
    if (!f) throw std::runtime_error("cannot open " + p.string());
    const std::streamoff n = f.tellg();
    std::vector<uint8_t> b(static_cast<size_t>(n));
    f.seekg(0);
    f.read(reinterpret_cast<char*>(b.data()), n);
    if (!f) throw std::runtime_error("short read on " + p.string());
    return b;
}

namespace {
template <class T> T at(const std::vector<uint8_t>& b, size_t off) {
    if (off > b.size() || sizeof(T) > b.size() - off)
        throw std::runtime_error("truncated PE file");
    T v;
    std::memcpy(&v, b.data() + off, sizeof(T));
    return v;
}
}  // namespace

Image Image::load(const std::filesystem::path& path, bool keep_file) {
    Image im;
    im.path = path;
    std::vector<uint8_t> fb = read_file(path);

    const uint32_t pe = at<uint32_t>(fb, 0x3C);
    if (at<uint32_t>(fb, pe) != 0x00004550) throw std::runtime_error("not a PE file");
    const uint16_t nsec = at<uint16_t>(fb, pe + 6);
    im.time_date_stamp = at<uint32_t>(fb, pe + 8);
    const uint16_t optsz = at<uint16_t>(fb, pe + 20);
    const size_t opt = pe + 24;
    if (at<uint16_t>(fb, opt) != 0x20B) throw std::runtime_error("expected a PE32+ image");
    im.entry_rva = at<uint32_t>(fb, opt + 16);
    im.image_base = at<uint64_t>(fb, opt + 24);
    im.size_of_image = at<uint32_t>(fb, opt + 56);
    im.size_of_headers = at<uint32_t>(fb, opt + 60);
    im.checksum = at<uint32_t>(fb, opt + 64);
    im.opt_offset = static_cast<uint32_t>(opt);
    const uint32_t ndirs = std::min<uint32_t>(at<uint32_t>(fb, opt + 108), 16);
    for (uint32_t i = 0; i < ndirs; ++i) {
        im.dirs[i].rva = at<uint32_t>(fb, opt + 112 + 8 * i);
        im.dirs[i].size = at<uint32_t>(fb, opt + 116 + 8 * i);
    }

    size_t top = im.size_of_image;
    const size_t sh = opt + optsz;
    for (int i = 0; i < nsec; ++i) {
        const size_t o = sh + 40 * static_cast<size_t>(i);
        Section s;
        s.index = i;
        char name[9]{};
        std::memcpy(name, fb.data() + o, 8);
        (void)at<uint32_t>(fb, o + 36);
        s.name = name;
        s.vsize = at<uint32_t>(fb, o + 8);
        s.rva = at<uint32_t>(fb, o + 12);
        s.rsize = at<uint32_t>(fb, o + 16);
        s.raw = at<uint32_t>(fb, o + 20);
        s.chars = at<uint32_t>(fb, o + 36);
        s.header = static_cast<uint32_t>(o);
        if (!s.vsize) s.vsize = s.rsize;
        top = std::max<size_t>(top, static_cast<size_t>(s.rva) + s.vsize);
        im.sections.push_back(s);
    }

    im.mem.assign(top, 0);
    std::memcpy(im.mem.data(), fb.data(),
                std::min<size_t>({im.size_of_headers, fb.size(), top}));
    for (const Section& s : im.sections) {
        size_t n = std::min<size_t>(s.rsize, s.vsize);
        if (s.raw >= fb.size()) continue;
        n = std::min(n, fb.size() - s.raw);
        std::memcpy(im.mem.data() + s.rva, fb.data() + s.raw, n);
    }
    if (keep_file) im.file = std::move(fb);
    return im;
}

const Section* Image::section_of(uint32_t rva) const {
    for (const Section& s : sections)
        if (s.contains(rva)) return &s;
    return nullptr;
}

bool Image::va_to_rva(uint64_t va, uint32_t& rva) const {
    if (va < image_base || va - image_base >= mem.size()) return false;
    rva = static_cast<uint32_t>(va - image_base);
    return true;
}

std::vector<uint32_t> Image::relocations() const {
    std::vector<uint32_t> out;
    const DataDir d = dirs[5];
    if (!d.rva || !in_bounds(d.rva, d.size)) return out;
    uint32_t p = d.rva;
    const uint32_t end = d.rva + d.size;
    while (p + 8 <= end) {
        const uint32_t page = rd<uint32_t>(p);
        const uint32_t size = rd<uint32_t>(p + 4);
        if (size < 8 || p + size > end) break;
        for (uint32_t q = p + 8; q + 2 <= p + size; q += 2) {
            const uint16_t e = rd<uint16_t>(q);
            if ((e >> 12) == 10) out.push_back(page + (e & 0xFFF));
        }
        p += size;
    }
    std::sort(out.begin(), out.end());
    return out;
}

std::vector<uint32_t> Image::tls_callbacks() const {
    std::vector<uint32_t> out;
    const DataDir d = dirs[9];
    if (!d.rva || !in_bounds(d.rva, 40)) return out;
    uint32_t arr;
    if (!va_to_rva(rd<uint64_t>(d.rva + 24), arr)) return out;
    for (; in_bounds(arr, 8); arr += 8) {
        const uint64_t va = rd<uint64_t>(arr);
        uint32_t rva;
        if (!va || !va_to_rva(va, rva)) break;
        out.push_back(rva);
    }
    return out;
}

std::vector<std::pair<uint32_t, uint32_t>> Image::relocation_entries() const {
    std::vector<std::pair<uint32_t, uint32_t>> out;
    const DataDir d = dirs[5];
    if (!d.rva || !in_bounds(d.rva, d.size)) return out;
    uint32_t p = d.rva;
    const uint32_t end = d.rva + d.size;
    while (p + 8 <= end) {
        const uint32_t page = rd<uint32_t>(p);
        const uint32_t size = rd<uint32_t>(p + 4);
        if (size < 8 || p + size > end) break;
        for (uint32_t q = p + 8; q + 2 <= p + size; q += 2) {
            const uint16_t e = rd<uint16_t>(q);
            if ((e >> 12) == 10) out.emplace_back(page + (e & 0xFFF), q);
        }
        p += size;
    }
    return out;
}

void Image::set_dir(int index, uint32_t rva, uint32_t size) {
    dirs[index] = {rva, size};
    std::memcpy(mem.data() + opt_offset + 112 + 8 * index, &rva, 4);
    std::memcpy(mem.data() + opt_offset + 116 + 8 * index, &size, 4);
}

// The standard PE checksum: 16-bit one's-complement sum of the file with
// the checksum field taken as zero, plus the file length.
static uint32_t pe_checksum(const std::vector<uint8_t>& fb, size_t field) {
    uint64_t sum = 0;
    const size_t n = fb.size() & ~static_cast<size_t>(1);
    for (size_t i = 0; i < n; i += 2) {
        if (i == field || i == field + 2) continue;
        sum += static_cast<uint32_t>(fb[i]) | (static_cast<uint32_t>(fb[i + 1]) << 8);
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    if (fb.size() & 1) sum += fb.back();
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    return static_cast<uint32_t>(sum + fb.size());
}

void Image::save(const std::filesystem::path& out, bool finalize) const {
    const std::vector<uint8_t> fb = file_bytes(finalize);
    std::ofstream f(out, std::ios::binary | std::ios::trunc);
    if (!f) throw std::runtime_error("cannot write " + out.string());
    f.write(reinterpret_cast<const char*>(fb.data()), static_cast<std::streamsize>(fb.size()));
    if (!f) throw std::runtime_error("short write on " + out.string());
}

std::vector<uint8_t> Image::file_bytes(bool finalize) const {
    if (file.empty()) throw std::runtime_error("image was loaded without its file bytes");
    std::vector<uint8_t> fb = file;
    if (finalize) {
        // Headers may have been edited in the mapped image (directories).
        std::memcpy(fb.data(), mem.data(), std::min<size_t>({size_of_headers, fb.size(), mem.size()}));
        // The certificate table is addressed by file offset; if its
        // directory entry was cleared and it sits at the end, drop it.
        uint32_t cert_off, cert_size;
        std::memcpy(&cert_off, file.data() + opt_offset + 112 + 8 * 4, 4);
        std::memcpy(&cert_size, file.data() + opt_offset + 116 + 8 * 4, 4);
        if (cert_off && !dirs[4].rva && static_cast<size_t>(cert_off) + cert_size == fb.size())
            fb.resize(cert_off);
    }
    for (const Section& s : sections) {
        size_t n = std::min<size_t>(s.rsize, s.vsize);
        if (s.raw >= fb.size()) continue;
        n = std::min(n, fb.size() - s.raw);
        std::memcpy(fb.data() + s.raw, mem.data() + s.rva, n);
    }
    if (finalize) {
        const uint32_t sum = pe_checksum(fb, opt_offset + 64);
        std::memcpy(fb.data() + opt_offset + 64, &sum, 4);
    }
    return fb;
}

}  // namespace mwdec
