// Decoding over the mapped image (Code), the flag maps over the code
// regions (ByteMap, BitMap), and the raw branch/reference index (RawXrefs).
#pragma once

#include <algorithm>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "flow/dec.h"
#include "flow/image.h"

namespace flow {

struct RoutineModel;

using RangeV = std::vector<std::pair<int64_t, int64_t>>;

// walker flag bits
enum : uint8_t { START = 1, CODE = 2, IDIOM = 4, CHAIN = 8, DREAD = 16, PATCHB = 32, WIPEB = 64, ISTART = 128 };

// code regions laid end to end (the ByteMap index space)
struct Regions {
    struct Sec {
        int64_t lo, hi, off;
    };
    std::vector<Sec> secs;
    int64_t total = 0;
    Regions() = default;
    Regions(const FImage& im, const RangeV& extra);
    int64_t idx(int64_t rva) const {
        for (const Sec& s : secs)
            if (s.lo <= rva && rva < s.hi) return s.off + rva - s.lo;
        return -1;
    }
    int64_t rva(int64_t i) const {
        for (const Sec& s : secs)
            if (s.off <= i && i < s.off + s.hi - s.lo) return s.lo + i - s.off;
        return -1;
    }
    const Sec* region_of(int64_t i) const {
        for (const Sec& s : secs)
            if (s.off <= i && i < s.off + s.hi - s.lo) return &s;
        return nullptr;
    }
};

class Bits {
public:
    Bits() = default;
    explicit Bits(int64_t n) { resize(n); }
    void resize(int64_t n) {
        n_ = n;
        w_.assign(static_cast<size_t>((n + 63) / 64), 0);
    }
    int64_t size() const { return n_; }
    bool test(int64_t i) const { return (w_[static_cast<size_t>(i >> 6)] >> (i & 63)) & 1; }
    void set(int64_t i) { w_[static_cast<size_t>(i >> 6)] |= uint64_t(1) << (i & 63); }
    void reset(int64_t i) { w_[static_cast<size_t>(i >> 6)] &= ~(uint64_t(1) << (i & 63)); }
    void set_range(int64_t a, int64_t b, bool v = true);  // [a, b) clipped to [0, n)
    bool any_range(int64_t a, int64_t b) const;
    int64_t count() const;
    int64_t count_range(int64_t a, int64_t b) const;
    int64_t next_set(int64_t i) const;   // first set bit >= i, or -1
    int64_t next_zero(int64_t i) const;  // first clear bit >= i, or size()
    Bits& operator|=(const Bits& o);
    Bits& operator&=(const Bits& o);
    Bits& andnot(const Bits& o);  // this &= ~o
    void flip();
    void clear() { std::fill(w_.begin(), w_.end(), 0); }
    std::vector<std::pair<int64_t, int64_t>> runs() const;  // ranges_of
    std::vector<uint64_t>& words() { return w_; }
    const std::vector<uint64_t>& words() const { return w_; }

private:
    void trim();
    int64_t n_ = 0;
    std::vector<uint64_t> w_;
};

class ByteMap {
public:
    explicit ByteMap(const Regions& r) : reg(&r), f(static_cast<size_t>(r.total)) {}
    const Regions* reg;
    BigBuf f;
    int64_t total() const { return reg->total; }
    int64_t idx(int64_t rva) const { return reg->idx(rva); }
    int64_t rva(int64_t i) const { return reg->rva(i); }
    void set(int64_t rva, int64_t n, uint8_t bit) {
        const int64_t i = idx(rva);
        if (i < 0) return;
        const int64_t e = std::min(i + n, reg->total);
        for (int64_t k = i; k < e; ++k) f[static_cast<size_t>(k)] |= bit;
    }
    uint8_t get(int64_t rva) const {
        const int64_t i = idx(rva);
        return i >= 0 ? f[static_cast<size_t>(i)] : 0;
    }
    bool any_in(int64_t rva, int64_t n, uint8_t bit) const {
        const int64_t i = idx(rva);
        if (i < 0) return false;
        const int64_t e = std::min(i + n, reg->total);
        for (int64_t k = i; k < e; ++k)
            if (f[static_cast<size_t>(k)] & bit) return true;
        return false;
    }
    Bits mask(uint8_t bits) const;  // (f & bits) != 0
    Bits mask_or(const ByteMap& o, uint8_t bits) const;  // ((f | o.f) & bits) != 0
};

// a ByteMap used only as a set of bytes (keep, keep_wipe, claimed)
class BitMap {
public:
    explicit BitMap(const Regions& r) : reg(&r), b(r.total) {}
    const Regions* reg;
    Bits b;
    void set(int64_t rva, int64_t n) {
        const int64_t i = reg->idx(rva);
        if (i >= 0) b.set_range(i, i + n);
    }
    bool get(int64_t rva) const {
        const int64_t i = reg->idx(rva);
        return i >= 0 && b.test(i);
    }
    bool any_in(int64_t rva, int64_t n) const {
        const int64_t i = reg->idx(rva);
        return i >= 0 && b.any_range(i, i + n);
    }
};

// global switches for the decode-cache diagnostics
extern bool g_cache_check;     // on each hit, re-decode and count stale results
extern bool g_cache_infinite;  // never clear (superset of what Python keeps)
extern int64_t g_stale_hits;
extern const char* g_phase;

class Code {
public:
    Code(FImage& im, const RangeV& extra, RoutineModel* model);
    FImage& image() const { return *im_; }
    // read another image from now on (a view of the same bytes; the cache is kept)
    void rebind(FImage& im) { im_ = &im; }
    RoutineModel* model;
    RangeV ex, extra;

    bool in_code(int64_t rva) const {
        for (const auto& [lo, hi] : ex)
            if (lo <= rva && rva < hi) return true;
        return false;
    }
    // Code.insn: decode once per address and keep the result (Python's
    // cache, cleared after 4,000,000 entries)
    bool insn(int64_t a, Lite& out);
    size_t cache_size() const { return ents_.size(); }
    // insn() in two halves, for callers that decode on threads and record in
    // order: is a in the cache, and the recording a miss makes after decoding
    bool contains(int64_t a) const;
    void put(int64_t a, const Lite& d);

private:
    struct Ent {
        int64_t key;
        uint32_t aoff;
        uint16_t olen;
        uint16_t mid;
        uint8_t size;
    };
    void clear_cache();
    void grow();
    FImage* im_;
    std::vector<Ent> ents_;
    std::vector<char> arena_;
    std::vector<uint32_t> slots_;
    uint64_t mask_ = 0;
};

// decode at a in the current image (Python: md.disasm_lite(mem[a:a+16], a, 1))
bool fresh_lite(const FImage& im, int64_t a, Lite& out);
Decoder& lite_dec();
Decoder& full_dec();
// detailed decode of mem[a:a+n]
const cs_insn* fresh_full(const FImage& im, int64_t a, int64_t n = 16);

// every candidate encoding in RawXrefs' concatenation order: add(target, source, kind)
void scan_xrefs(const FImage& im, const RangeV& extra, const std::function<void(int64_t, int64_t, uint8_t)>& add);
// the same on threads: the hits keep() accepts (it must be safe to call from
// several threads), in scan_xrefs' order
struct XHit {
    uint32_t t, s;
    uint8_t k;
};
void scan_xrefs_par(const FImage& im, const RangeV& extra,
                    const std::function<bool(int64_t, int64_t, uint8_t)>& keep, std::vector<XHit>& out);

struct RawXrefs {
    std::vector<uint32_t> tgt, src;
    std::vector<uint8_t> kind;
    RawXrefs(const FImage& im, const RangeV& extra);
    // index range of entries whose target is rva
    std::pair<size_t, size_t> to(int64_t rva) const;
    size_t lower(int64_t rva) const;  // searchsorted left
};

struct KindEnc {
    uint16_t mid;  // M_NONE for "any jcc"
    uint8_t size;
};
extern const KindEnc KIND_ENC[7];

struct BranchRef {
    int64_t src;
    uint16_t mid;
    uint8_t size;
};
std::vector<int64_t> confirmed_refs_to(Code& code, const RawXrefs& xr, int64_t rva);
std::vector<BranchRef> confirmed_branches_to(Code& code, const RawXrefs& xr, int64_t rva);

}  // namespace flow
