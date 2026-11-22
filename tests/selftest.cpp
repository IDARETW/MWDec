// Self-test: needs no game files.
#include <cstdio>
#include <cstring>
#include <vector>

#include "ranges.h"
#include "writers.h"
#include "xtea.h"

using namespace mwdec;

static int failures = 0;
#define CHECK(c)                                                    \
    do {                                                            \
        if (!(c)) {                                                 \
            std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); \
            ++failures;                                             \
        }                                                           \
    } while (0)

int main() {
    // Published XTEA vector (32 rounds): key 00010203..0f, pt 41424344 45464748.
    const uint32_t key[4] = {0x00010203, 0x04050607, 0x08090A0B, 0x0C0D0E0F};
    uint32_t a = 0x41424344, b = 0x45464748;
    xtea_encipher(a, b, key);
    CHECK(a == 0x497DF3D0 && b == 0x72612CB5);
    xtea_decipher(a, b, key);
    CHECK(a == 0x41424344 && b == 0x45464748);

    // Output feedback: applying the stream twice restores the data, and a
    // split application equals a single one (the stream ignores range ends).
    std::vector<uint8_t> data(1000), ref;
    for (size_t i = 0; i < data.size(); ++i) data[i] = static_cast<uint8_t>(i * 7 + 3);
    ref = data;
    std::vector<uint8_t> one = data, two = data;
    XteaOfb(key, 1, 2, 64).apply(one.data(), one.size());
    XteaOfb s(key, 1, 2, 64);
    s.apply(two.data(), 13);
    s.apply(two.data() + 13, 500);
    s.apply(two.data() + 513, 487);
    CHECK(one == two);
    CHECK(one != ref);
    CHECK(s.blocks() == 125);
    XteaOfb(key, 1, 2, 64).apply(one.data(), one.size());
    CHECK(one == ref);
    // First block of the stream is E(IV), emitted v0 then v1.
    uint32_t e0 = 1, e1 = 2;
    xtea_encipher(e0, e1, key, 64);
    uint8_t z[8]{}, want[8];
    XteaOfb(key, 1, 2, 64).apply(z, 8);
    std::memcpy(want, &e0, 4);
    std::memcpy(want + 4, &e1, 4);
    CHECK(std::memcmp(z, want, 8) == 0);

    // Range list: (0x1000,16) (0x7004,28) then the terminating gap.
    // gap 0x1000 = 80 20; len 16 = 10; gap 0x5FF4 = F4 BF 01; len 28 = 1C;
    // terminator: gap = 0xFFFFFFFF - 0x7020 = 0xFFFF8FDF = DF 9F FE FF 0F.
    const uint8_t enc[] = {0x80, 0x20, 0x10, 0xF4, 0xBF, 0x01, 0x1C,
                           0xDF, 0x9F, 0xFE, 0xFF, 0x0F, 0xFF, 0xFF};
    const RangeList l = decode_ranges(enc, sizeof enc);
    CHECK(l.ranges.size() == 2);
    CHECK(l.ranges[0].rva == 0x1000 && l.ranges[0].size == 16);
    CHECK(l.ranges[1].rva == 0x7004 && l.ranges[1].size == 28);
    CHECK(l.total == 44 && l.encoded_size == 12);

    // Writer stash decoding, one hand-worked case per variant.
    auto dec = [](std::vector<uint32_t> e, WriterVariant v, uint32_t key) {
        std::vector<uint8_t> raw(e.size() * 4);
        std::memcpy(raw.data(), e.data(), raw.size());
        const std::vector<uint8_t> out = decode_stash(raw.data(), raw.size(), v, key);
        std::vector<uint32_t> p(e.size());
        std::memcpy(p.data(), out.data(), out.size());
        return p;
    };
    CHECK(dec({0x11223344}, WriterVariant::Xor, 0xFFFFFFFF) == std::vector<uint32_t>{0xEEDDCCBB});
    CHECK(dec({3, 11}, WriterVariant::Sub, 10) == (std::vector<uint32_t>{7, 0xFFFFFFFF}));
    // XorAuto, K = 1: p0 = 3^1 = 2, k = 3; p1 = 3^3 = 0.
    CHECK(dec({3, 3}, WriterVariant::XorAuto, 1) == (std::vector<uint32_t>{2, 0}));
    // MulRol, K = 0x23: a = rol(0x23, 3) = 0x118, p0 = e0 - 0x348, b = ~p0 ^ 3;
    // then a = rol(0x118, 25) = 0x30000002, p1 = e1 - a*b.
    CHECK(dec({0x34D, 0xAFFFFFFB}, WriterVariant::MulRol, 0x23) == (std::vector<uint32_t>{5, 9}));
    // A length that is not a multiple of four is cut after decoding.
    const uint8_t odd[8] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    CHECK(decode_stash(odd, 5, WriterVariant::Xor, 0xFFFFFFFF).size() == 5);

    std::printf(failures ? "FAILED\n" : "PASS: mwdec selftest\n");
    return failures != 0;
}
