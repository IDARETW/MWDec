// XTEA, and the output-feedback keystream the protection builds from it.
//
// The block function is textbook XTEA in the encipher direction with a
// configurable round count:
//
//     v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
//     sum += delta;
//     v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
//
// The protection never runs it over the data. It enciphers an 8-byte state
// in place, over and over, and XORs the successive states into the data:
// output feedback. Decryption and encryption are therefore the same
// operation, and block n cannot be computed without blocks 0..n-1.
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace mwdec {

constexpr uint32_t kXteaDelta = 0x9E3779B9u;

inline void xtea_encipher(uint32_t& v0, uint32_t& v1, const uint32_t key[4],
                          unsigned rounds = 32, uint32_t delta = kXteaDelta,
                          uint32_t sum = 0) {
    uint32_t a = v0, b = v1;
    for (unsigned i = 0; i < rounds; ++i) {
        a += (((b << 4) ^ (b >> 5)) + b) ^ (sum + key[sum & 3]);
        sum += delta;
        b += (((a << 4) ^ (a >> 5)) + a) ^ (sum + key[(sum >> 11) & 3]);
    }
    v0 = a;
    v1 = b;
}

inline void xtea_decipher(uint32_t& v0, uint32_t& v1, const uint32_t key[4],
                          unsigned rounds = 32, uint32_t delta = kXteaDelta) {
    uint32_t a = v0, b = v1, sum = delta * rounds;
    for (unsigned i = 0; i < rounds; ++i) {
        b -= (((a << 4) ^ (a >> 5)) + a) ^ (sum + key[(sum >> 11) & 3]);
        sum -= delta;
        a -= (((b << 4) ^ (b >> 5)) + b) ^ (sum + key[sum & 3]);
    }
    v0 = a;
    v1 = b;
}

// Keystream: S(0) = IV, S(i+1) = E(S(i)); the stream is S(1) || S(2) || ...
// with each state emitted as v0 then v1, little-endian.
class XteaOfb {
public:
    XteaOfb(const uint32_t key[4], uint32_t iv0, uint32_t iv1, unsigned rounds,
            uint32_t delta = kXteaDelta)
        : v0_(iv0), v1_(iv1), rounds_(rounds), delta_(delta) {
        std::memcpy(key_, key, sizeof key_);
    }

    void apply(uint8_t* p, size_t n) {
        for (size_t i = 0; i < n; ++i) {
            if (used_ == 8) refill();
            p[i] ^= buf_[used_++];
        }
    }
    uint64_t blocks() const { return blocks_; }
    // The current state. The real routine enciphers its state in place, so
    // after a run this is what the image holds where the IV used to be.
    uint32_t state0() const { return v0_; }
    uint32_t state1() const { return v1_; }

private:
    void refill() {
        xtea_encipher(v0_, v1_, key_, rounds_, delta_);
        std::memcpy(buf_, &v0_, 4);
        std::memcpy(buf_ + 4, &v1_, 4);
        used_ = 0;
        ++blocks_;
    }
    uint32_t key_[4];
    uint32_t v0_, v1_;
    unsigned rounds_;
    uint32_t delta_;
    uint8_t buf_[8]{};
    unsigned used_ = 8;
    uint64_t blocks_ = 0;
};

}  // namespace mwdec
