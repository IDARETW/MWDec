#include "strings.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <unordered_map>

namespace mwdec {

namespace {

bool printable(uint32_t c) {
    // 0x1E and 0x1F are the engine's localisation markers.
    return (c >= 0x20 && c != 0x7F) || c == 9 || c == 10 || c == 13 || c == 0x1E || c == 0x1F;
}

// ASCII, or well-formed UTF-8, with no control characters.
bool looks_like_text(const uint8_t* p, size_t n) {
    if (!n) return false;
    size_t i = 0, chars = 0;
    bool ascii = true;
    while (i < n) {
        const uint8_t c = p[i];
        uint32_t cp;
        size_t len;
        if (c < 0x80) {
            cp = c, len = 1;
        } else if ((c & 0xE0) == 0xC0) {
            cp = c & 0x1F, len = 2;
        } else if ((c & 0xF0) == 0xE0) {
            cp = c & 0x0F, len = 3;
        } else if ((c & 0xF8) == 0xF0) {
            cp = c & 0x07, len = 4;
        } else {
            return false;
        }
        if (i + len > n) return false;
        for (size_t k = 1; k < len; ++k) {
            if ((p[i + k] & 0xC0) != 0x80) return false;
            cp = (cp << 6) | (p[i + k] & 0x3F);
        }
        if (len > 1) {
            static const uint32_t kMin[5] = {0, 0, 0x80, 0x800, 0x10000};
            if (cp < kMin[len] || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return false;
            if (cp < 0xA0) return false;  // C1 controls
            ascii = false;
        } else if (!printable(cp)) {
            return false;
        }
        i += len;
        ++chars;
    }
    return ascii || chars >= 2;
}

}  // namespace

std::vector<XorBlob> find_xor_blobs(const Image& im) {
    std::vector<XorBlob> out;
    for (const Section& s : im.sections) {
        if (s.executable() || !s.writable() || s.name != ".data") continue;
        const uint8_t* raw = im.mem.data() + s.rva;
        const size_t size = std::min<size_t>(s.rsize, s.vsize);
        for (size_t o = 0; o + 0x10 <= size; o += 8) {
            uint32_t hdr;
            std::memcpy(&hdr, raw + o + 8, 4);
            const uint32_t n = hdr & 0xFFFFFF;
            if ((hdr >> 24) != 1 || n < 1 || n > 0x4000) continue;
            if (o + 0xC + n >= size || raw[o + 0xC + n] != 0) continue;
            XorBlob b;
            b.rva = s.rva + static_cast<uint32_t>(o);
            b.length = n;
            std::memcpy(b.key, raw + o, 8);
            b.text.resize(n);
            for (uint32_t j = 0; j < n; ++j)
                b.text[j] = static_cast<char>(raw[o + 0xC + j] ^ b.key[j & 7]);
            if (!looks_like_text(reinterpret_cast<const uint8_t*>(b.text.data()), n)) continue;
            out.push_back(std::move(b));
        }
    }
    if (out.empty()) return out;

    // Code references: any 32-bit field in an executable section that names
    // one of a blob's four interesting offsets, either RIP-relative or as an
    // image-relative displacement.
    std::unordered_map<uint32_t, uint32_t> target;  // address -> blob index * 4 + which
    target.reserve(out.size() * 8);
    static const uint32_t kOff[4] = {0, 8, 0xB, 0xC};
    uint32_t lo = 0xFFFFFFFFu, hi = 0;
    for (uint32_t i = 0; i < out.size(); ++i)
        for (uint32_t k = 0; k < 4; ++k) {
            target[out[i].rva + kOff[k]] = i * 4 + k;
            lo = std::min(lo, out[i].rva);
            hi = std::max(hi, out[i].rva + 0xC);
        }
    std::vector<uint8_t> seen(out.size(), 0);
    for (const Section& s : im.sections) {
        if (!s.executable()) continue;
        const size_t size = std::min<size_t>(s.rsize, s.vsize);
        const uint8_t* p = im.mem.data() + s.rva;
        for (size_t o = 0; o + 4 <= size; ++o) {
            int32_t d;
            std::memcpy(&d, p + o, 4);
            const uint32_t cand[2] = {
                static_cast<uint32_t>(static_cast<int64_t>(s.rva) + static_cast<int64_t>(o) + 4 + d),
                static_cast<uint32_t>(d)};
            for (uint32_t t : cand) {
                if (t < lo || t > hi) continue;
                const auto it = target.find(t);
                if (it == target.end()) continue;
                seen[it->second / 4] |= static_cast<uint8_t>(1u << (it->second % 4));
                ++out[it->second / 4].ref_sites;
            }
        }
    }
    std::vector<XorBlob> kept;
    kept.reserve(out.size());
    for (size_t i = 0; i < out.size(); ++i) {
        unsigned n = 0;
        for (int k = 0; k < 4; ++k) n += (seen[i] >> k) & 1;
        out[i].ref_offsets = n;
        if (n == 0 && out[i].length < 4) continue;  // too short to trust unreferenced
        kept.push_back(std::move(out[i]));
    }
    return kept;
}

void patch_xor_blobs(Image& im, const std::vector<XorBlob>& blobs) {
    for (const XorBlob& b : blobs) {
        if (!im.in_bounds(b.rva, 0xC + static_cast<uint64_t>(b.length))) continue;
        std::memcpy(im.mem.data() + b.rva + 0xC, b.text.data(), b.length);
        im.mem[b.rva + 0xB] = 0;
    }
}

std::string xor_blobs_tsv(const std::vector<XorBlob>& blobs) {
    std::string s = "rva\tlength\tkey\tref_offsets\tref_sites\ttext\n";
    char buf[96];
    for (const XorBlob& b : blobs) {
        std::snprintf(buf, sizeof buf, "%08X\t%u\t%02X%02X%02X%02X%02X%02X%02X%02X\t%u\t%u\t", b.rva,
                      b.length, b.key[0], b.key[1], b.key[2], b.key[3], b.key[4], b.key[5],
                      b.key[6], b.key[7], b.ref_offsets, b.ref_sites);
        s += buf;
        for (unsigned char c : b.text) {
            if (c == '\t') s += "\\t";
            else if (c == '\n') s += "\\n";
            else if (c == '\r') s += "\\r";
            else if (c == '\\') s += "\\\\";
            else if (c < 0x20) {
                std::snprintf(buf, sizeof buf, "\\x%02X", c);
                s += buf;
            } else s += static_cast<char>(c);
        }
        s += '\n';
    }
    return s;
}

}  // namespace mwdec
