#include "writerkey.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <mutex>
#include <thread>

namespace mwdec {

namespace {

inline uint32_t rol32(uint32_t v, unsigned n) {
    n &= 31;
    return n ? (v << n) | (v >> (32 - n)) : v;
}

// The same fifty byte values autoboot.cpp scores with.
const std::array<uint8_t, 256>& common_bytes() {
    static const std::array<uint8_t, 256> t = [] {
        std::array<uint8_t, 256> a{};
        for (int b : {0x00, 0x01, 0x02, 0x04, 0x08, 0x0F, 0x10, 0x18, 0x20, 0x24, 0x28, 0x30, 0x33,
                      0x38, 0x3B, 0x40, 0x41, 0x44, 0x45, 0x48, 0x49, 0x4C, 0x4D, 0x54, 0x5C, 0x66,
                      0x74, 0x75, 0x83, 0x84, 0x85, 0x89, 0x8B, 0x8D, 0x90, 0xC0, 0xC1, 0xC3, 0xC7,
                      0xC8, 0xC9, 0xCC, 0xD0, 0xD2, 0xE8, 0xE9, 0xEB, 0xF8, 0xFE, 0xFF})
            a[static_cast<size_t>(b)] = 1;
        return a;
    }();
    return t;
}

inline unsigned common4(const std::array<uint8_t, 256>& c, uint32_t p) {
    return c[p & 0xFF] + c[(p >> 8) & 0xFF] + c[(p >> 16) & 0xFF] + c[p >> 24];
}

constexpr size_t kFirstWords = 6;  // 24 bytes decide whether a key is looked at again
constexpr unsigned kFirstNeed = 10;

// How many of the first 24 plaintext bytes under key K are common code
// bytes. Eight bytes were too few: a function can begin with bytes that
// are not on the list, and the right key was then dropped here.
inline unsigned first_common(const std::array<uint8_t, 256>& c, WriterVariant v, uint32_t K,
                             const uint32_t* e) {
    unsigned n = 0;
    switch (v) {
        case WriterVariant::Xor:
            for (size_t i = 0; i < kFirstWords; ++i) n += common4(c, e[i] ^ K);
            break;
        case WriterVariant::Sub:
            for (size_t i = 0; i < kFirstWords; ++i) n += common4(c, K - e[i]);
            break;
        case WriterVariant::XorAuto: {
            uint32_t k = K;
            for (size_t i = 0; i < kFirstWords; ++i) {
                const uint32_t p = e[i] ^ k;
                k += p;
                n += common4(c, p);
            }
            break;
        }
        case WriterVariant::MulRol: {
            uint32_t a = K, b = K & 31;
            for (size_t i = 0; i < kFirstWords; ++i) {
                a = rol32(a, b);
                const uint32_t p = e[i] - a * b;
                b = ~p ^ b;
                n += common4(c, p);
            }
            break;
        }
    }
    return n;
}

double share_of(const std::array<uint8_t, 256>& c, const std::vector<uint8_t>& p) {
    size_t n = 0;
    for (uint8_t x : p) n += c[x];
    return p.empty() ? 0.0 : static_cast<double>(n) / static_cast<double>(p.size());
}

}  // namespace

const char* variant_name(WriterVariant v) {
    switch (v) {
        case WriterVariant::Xor: return "Xor";
        case WriterVariant::Sub: return "Sub";
        case WriterVariant::XorAuto: return "XorAuto";
        case WriterVariant::MulRol: return "MulRol";
    }
    return "?";
}

std::vector<KeyCandidate> find_writer_keys(const uint8_t* stash, size_t n, size_t top) {
    std::vector<KeyCandidate> out;
    if (n < 4 * kFirstWords) return out;
    const auto& c = common_bytes();
    uint32_t e[kFirstWords];
    std::memcpy(e, stash, sizeof e);
    const size_t mid = std::min<size_t>(n, 80), full = std::min<size_t>(n, 4096);
    const unsigned threads = std::max(1u, std::thread::hardware_concurrency());
    for (WriterVariant v : {WriterVariant::Xor, WriterVariant::Sub, WriterVariant::XorAuto, WriterVariant::MulRol}) {
        // Survivors are counted, not kept: under XorAuto hundreds of millions
        // of keys pass, and only the best few of each thread matter.
        const auto better = [](const KeyCandidate& a, const KeyCandidate& b) {
            return a.share != b.share ? a.share > b.share : a.key < b.key;
        };
        std::vector<KeyCandidate> found;
        size_t survivors = 0;
        std::mutex mu;
        std::vector<std::thread> pool;
        const uint64_t span = (uint64_t{1} << 32) / threads + 1;
        for (unsigned t = 0; t < threads; ++t)
            pool.emplace_back([&, t] {
                std::vector<KeyCandidate> mine;
                size_t passed = 0;
                const uint64_t lo = span * t, hi = std::min<uint64_t>(lo + span, uint64_t{1} << 32);
                for (uint64_t k64 = lo; k64 < hi; ++k64) {
                    const uint32_t K = static_cast<uint32_t>(k64);
                    if (first_common(c, v, K, e) < kFirstNeed) continue;
                    if (share_of(c, decode_stash(stash, mid, v, K)) < 0.42) continue;
                    ++passed;
                    KeyCandidate kc;
                    kc.key = K;
                    kc.variant = v;
                    kc.share = share_of(c, decode_stash(stash, full, v, K));
                    mine.push_back(kc);
                    if (mine.size() > 4096) {
                        std::sort(mine.begin(), mine.end(), better);
                        mine.resize(top);
                    }
                }
                std::sort(mine.begin(), mine.end(), better);
                if (mine.size() > top) mine.resize(top);
                const std::lock_guard<std::mutex> lock(mu);
                found.insert(found.end(), mine.begin(), mine.end());
                survivors += passed;
            });
        for (std::thread& th : pool) th.join();
        std::sort(found.begin(), found.end(), better);
        for (size_t i = 0; i < found.size() && i < top; ++i) {
            found[i].survivors = survivors;
            out.push_back(found[i]);
        }
    }
    std::sort(out.begin(), out.end(), [](const KeyCandidate& a, const KeyCandidate& b) {
        return a.share != b.share ? a.share > b.share : a.key < b.key;
    });
    return out;
}

}  // namespace mwdec
