#include "flow/code.h"

#include <emmintrin.h>

#include <algorithm>
#include <atomic>
#include <bit>
#include <cstdio>
#include <execution>
#include <stdexcept>
#include <thread>

#include "flow/pyutil.h"

namespace flow {

bool g_cache_check = false;
bool g_cache_infinite = false;
int64_t g_stale_hits = 0;
const char* g_phase = "";

Regions::Regions(const FImage& im, const RangeV& extra) {
    int64_t off = 0;
    for (const PSection* s : im.exec_sections()) {
        secs.push_back({s->rva, static_cast<int64_t>(s->rva) + s->vsize, off});
        off += s->vsize;
    }
    for (const auto& [lo, hi] : extra) {
        secs.push_back({lo, hi, off});
        off += hi - lo;
    }
    total = off;
}

// ---------------------------------------------------------------- Bits --

void Bits::trim() {
    if (n_ & 63) w_.back() &= (uint64_t(1) << (n_ & 63)) - 1;
}

void Bits::set_range(int64_t a, int64_t b, bool v) {
    if (a < 0) a = 0;
    if (b > n_) b = n_;
    if (a >= b) return;
    int64_t i = a;
    while (i < b && (i & 63)) {
        v ? set(i) : reset(i);
        ++i;
    }
    while (i + 64 <= b) {
        w_[static_cast<size_t>(i >> 6)] = v ? ~uint64_t(0) : 0;
        i += 64;
    }
    while (i < b) {
        v ? set(i) : reset(i);
        ++i;
    }
}

bool Bits::any_range(int64_t a, int64_t b) const {
    if (a < 0) a = 0;
    if (b > n_) b = n_;
    if (a >= b) return false;
    // Only the words the range lies in. (This used to ask next_set(a) for
    // the next set bit anywhere and compare it with b: on a map with a few
    // set bits, the ranges a --keep-plan names, every question about 15
    // bytes walked megabytes of zeros. The planner asks it for every
    // instruction of every disguised branch: 22 s of build 1.20's flow
    // pass, and 400 s of a late build's.)
    const size_t wa = static_cast<size_t>(a >> 6), wb = static_cast<size_t>((b - 1) >> 6);
    const uint64_t first = ~uint64_t(0) << (a & 63);
    const uint64_t last = ~uint64_t(0) >> (63 - ((b - 1) & 63));
    if (wa == wb) return (w_[wa] & first & last) != 0;
    if (w_[wa] & first) return true;
    for (size_t w = wa + 1; w < wb; ++w)
        if (w_[w]) return true;
    return (w_[wb] & last) != 0;
}

int64_t Bits::count() const {
    int64_t c = 0;
    for (uint64_t w : w_) c += std::popcount(w);
    return c;
}

int64_t Bits::count_range(int64_t a, int64_t b) const {
    if (a < 0) a = 0;
    if (b > n_) b = n_;
    int64_t c = 0;
    int64_t i = a;
    while (i < b && (i & 63)) c += test(i++);
    while (i + 64 <= b) {
        c += std::popcount(w_[static_cast<size_t>(i >> 6)]);
        i += 64;
    }
    while (i < b) c += test(i++);
    return c;
}

int64_t Bits::next_set(int64_t i) const {
    if (i < 0) i = 0;
    if (i >= n_) return -1;
    size_t w = static_cast<size_t>(i >> 6);
    uint64_t x = w_[w] & (~uint64_t(0) << (i & 63));
    while (true) {
        if (x) {
            const int64_t r = static_cast<int64_t>(w) * 64 + std::countr_zero(x);
            return r < n_ ? r : -1;
        }
        if (++w >= w_.size()) return -1;
        x = w_[w];
    }
}

Bits& Bits::operator|=(const Bits& o) {
    for (size_t i = 0; i < w_.size(); ++i) w_[i] |= o.w_[i];
    return *this;
}
Bits& Bits::operator&=(const Bits& o) {
    for (size_t i = 0; i < w_.size(); ++i) w_[i] &= o.w_[i];
    return *this;
}
Bits& Bits::andnot(const Bits& o) {
    for (size_t i = 0; i < w_.size(); ++i) w_[i] &= ~o.w_[i];
    return *this;
}
void Bits::flip() {
    for (uint64_t& w : w_) w = ~w;
    trim();
}

int64_t Bits::next_zero(int64_t i) const {
    if (i < 0) i = 0;
    if (i >= n_) return n_;
    size_t w = static_cast<size_t>(i >> 6);
    uint64_t x = ~w_[w] & (~uint64_t(0) << (i & 63));
    while (true) {
        if (x) {
            const int64_t r = static_cast<int64_t>(w) * 64 + std::countr_zero(x);
            return r < n_ ? r : n_;
        }
        if (++w >= w_.size()) return n_;
        x = ~w_[w];
    }
}

std::vector<std::pair<int64_t, int64_t>> Bits::runs() const {
    std::vector<std::pair<int64_t, int64_t>> out;
    int64_t i = next_set(0);
    while (i >= 0) {
        const int64_t e = next_zero(i);
        out.emplace_back(i, e);
        if (e >= n_) break;
        i = next_set(e);
    }
    return out;
}

// bit k of the result: (p[k] | q[k]) & bits, for 64 bytes (q may be null)
static inline uint64_t mask64(const uint8_t* p, const uint8_t* q, __m128i b) {
    uint64_t x = 0;
    const __m128i z = _mm_setzero_si128();
    for (int j = 0; j < 4; ++j) {
        __m128i v = _mm_loadu_si128(reinterpret_cast<const __m128i*>(p + 16 * j));
        if (q) v = _mm_or_si128(v, _mm_loadu_si128(reinterpret_cast<const __m128i*>(q + 16 * j)));
        const int m = _mm_movemask_epi8(_mm_cmpeq_epi8(_mm_and_si128(v, b), z));
        x |= static_cast<uint64_t>(static_cast<uint16_t>(~m)) << (16 * j);
    }
    return x;
}

static Bits mask_of(const uint8_t* p, const uint8_t* q, int64_t n, uint8_t bits) {
    Bits m(n);
    auto& w = m.words();
    const __m128i b = _mm_set1_epi8(static_cast<char>(bits));
    int64_t i = 0;
    for (; i + 64 <= n; i += 64) w[static_cast<size_t>(i >> 6)] = mask64(p + i, q ? q + i : nullptr, b);
    if (i < n) {
        uint64_t x = 0;
        for (int64_t k = 0; i + k < n; ++k)
            if ((p[i + k] | (q ? q[i + k] : 0)) & bits) x |= uint64_t(1) << k;
        w[static_cast<size_t>(i >> 6)] = x;
    }
    return m;
}

Bits ByteMap::mask(uint8_t bits) const { return mask_of(f.data(), nullptr, reg->total, bits); }

Bits ByteMap::mask_or(const ByteMap& o, uint8_t bits) const {
    return mask_of(f.data(), o.f.data(), reg->total, bits);
}

// ---------------------------------------------------------------- Code --

Decoder& lite_dec() {
    thread_local Decoder d(false);
    return d;
}
Decoder& full_dec() {
    thread_local Decoder d(true);
    return d;
}

bool fresh_lite(const FImage& im, int64_t a, Lite& out) {
    const uint8_t* p;
    size_t n;
    py_window(im.mem.data(), im.len, a, 16, p, n);
    return lite_dec().lite(p, n, static_cast<uint64_t>(a), out);
}

const cs_insn* fresh_full(const FImage& im, int64_t a, int64_t n) {
    const uint8_t* p;
    size_t cnt;
    py_window(im.mem.data(), im.len, a, n, p, cnt);
    return full_dec().full(p, cnt, static_cast<uint64_t>(a));
}

Code::Code(FImage& im, const RangeV& extra_, RoutineModel* model_) : model(model_), extra(extra_), im_(&im) {
    for (const PSection* s : im.exec_sections()) ex.emplace_back(s->rva, static_cast<int64_t>(s->rva) + s->vsize);
    for (const auto& r : extra) ex.push_back(r);
}

static inline uint64_t hkey(int64_t k) { return static_cast<uint64_t>(k) * 0x9E3779B97F4A7C15ull; }

void Code::clear_cache() {
    ents_.clear();
    arena_.clear();
    std::fill(slots_.begin(), slots_.end(), 0u);
}

void Code::grow() {
    const size_t ns = slots_.empty() ? (1u << 16) : slots_.size() * 2;
    slots_.assign(ns, 0u);
    mask_ = ns - 1;
    const int sh = 64 - std::countr_zero(static_cast<uint64_t>(ns));
    for (size_t i = 0; i < ents_.size(); ++i) {
        uint64_t h = hkey(ents_[i].key) >> sh;
        while (slots_[h]) h = (h + 1) & mask_;
        slots_[h] = static_cast<uint32_t>(i + 1);
    }
}

bool Code::insn(int64_t a, Lite& out) {
    if (slots_.empty()) grow();
    const int sh = 64 - std::countr_zero(static_cast<uint64_t>(slots_.size()));
    uint64_t h = hkey(a) >> sh;
    while (uint32_t s = slots_[h]) {
        const Ent& e = ents_[s - 1];
        if (e.key == a) {
            out.size = e.size;
            out.mid = e.mid;
            out.olen = e.olen;
            std::memcpy(out.op, arena_.data() + e.aoff, e.olen);
            out.op[e.olen] = 0;
            if (g_cache_check) {
                Lite f;
                fresh_lite(*im_, a, f);
                if (f.size != out.size || (f.size && (f.mid != out.mid || f.ops() != out.ops()))) {
                    if (g_stale_hits < 50)
                        std::printf("  [cache] stale decode at %08llX in %s: cached '%s %s' (%u), now '%s %s' (%u)\n",
                                    static_cast<unsigned long long>(a), g_phase, std::string(out.mn()).c_str(),
                                    out.op, out.size, std::string(f.mn()).c_str(), f.op, f.size);
                    ++g_stale_hits;
                }
            }
            return out.size != 0;
        }
        h = (h + 1) & mask_;
    }
    // miss: Python clears the dict once it holds more than 4,000,000
    if (ents_.size() > 4000000 && !g_cache_infinite) {
        clear_cache();
        h = hkey(a) >> sh;
    }
    fresh_lite(*im_, a, out);
    if ((ents_.size() + 1) * 2 > slots_.size()) {
        grow();
        const int sh2 = 64 - std::countr_zero(static_cast<uint64_t>(slots_.size()));
        h = hkey(a) >> sh2;
    }
    while (slots_[h]) h = (h + 1) & mask_;
    Ent e;
    e.key = a;
    e.size = out.size;
    e.mid = out.size ? out.mid : 0;
    e.olen = out.size ? out.olen : 0;
    e.aoff = static_cast<uint32_t>(arena_.size());
    if (out.size) arena_.insert(arena_.end(), out.op, out.op + out.olen);
    ents_.push_back(e);
    slots_[h] = static_cast<uint32_t>(ents_.size());
    return out.size != 0;
}

bool Code::contains(int64_t a) const {
    if (slots_.empty()) return false;
    const int sh = 64 - std::countr_zero(static_cast<uint64_t>(slots_.size()));
    uint64_t h = hkey(a) >> sh;
    while (uint32_t s = slots_[h]) {
        if (ents_[s - 1].key == a) return true;
        h = (h + 1) & mask_;
    }
    return false;
}

void Code::put(int64_t a, const Lite& out) {
    // what insn() does on a miss once it has decoded (the same clearing, the
    // same growth, the first free slot of the probe)
    if (slots_.empty()) grow();
    if (ents_.size() > 4000000 && !g_cache_infinite) clear_cache();
    if ((ents_.size() + 1) * 2 > slots_.size()) grow();
    const int sh = 64 - std::countr_zero(static_cast<uint64_t>(slots_.size()));
    uint64_t h = hkey(a) >> sh;
    while (slots_[h]) h = (h + 1) & mask_;
    Ent e;
    e.key = a;
    e.size = out.size;
    e.mid = out.size ? out.mid : 0;
    e.olen = out.size ? out.olen : 0;
    e.aoff = static_cast<uint32_t>(arena_.size());
    if (out.size) arena_.insert(arena_.end(), out.op, out.op + out.olen);
    ents_.push_back(e);
    slots_[h] = static_cast<uint32_t>(ents_.size());
}

// ------------------------------------------------------------ RawXrefs --

void scan_xrefs(const FImage& im, const RangeV& extra, const std::function<void(int64_t, int64_t, uint8_t)>& add_) {
    struct R {
        int64_t rva, vsize;
    };
    std::vector<R> regs;
    for (const PSection* s : im.exec_sections()) regs.push_back({s->rva, s->vsize});
    for (const auto& [lo, hi] : extra) regs.push_back({lo, hi - lo});
    const uint8_t* mem = im.mem.data();
    const int64_t L = im.len;
    auto add = [&](int64_t t, int64_t s, uint8_t k) {
        if (t >= 0 && t < L) add_(t, s, k);
    };
    for (const R& r : regs) {
        const uint8_t* a = mem + r.rva;
        const int64_t len = r.vsize;
        const int64_t n = len - 8;
        if (n <= 0) continue;
        auto r32 = [a](int64_t p) {
            int32_t v;
            std::memcpy(&v, a + p, 4);
            return static_cast<int64_t>(v);
        };
        auto r8 = [a](int64_t p) { return static_cast<int64_t>(static_cast<int8_t>(a[p])); };
        for (int64_t p = 0; p < n; ++p)
            if (a[p] == 0xE9) add(r.rva + p + 5 + r32(p + 1), r.rva + p, 0);
        for (int64_t p = 0; p < n; ++p)
            if (a[p] == 0xE8) add(r.rva + p + 5 + r32(p + 1), r.rva + p, 1);
        for (int64_t p = 0; p < n; ++p)
            if (a[p] == 0x0F && (a[p + 1] & 0xF0) == 0x80) add(r.rva + p + 6 + r32(p + 2), r.rva + p, 2);
        for (int64_t p = 0; p < n; ++p)
            if (a[p] == 0xEB) add(r.rva + p + 2 + r8(p + 1), r.rva + p, 3);
        for (int64_t p = 0; p < n; ++p)
            if ((a[p] & 0xF0) == 0x70) add(r.rva + p + 2 + r8(p + 1), r.rva + p, 4);
        for (int64_t p = 0; p < n; ++p)
            if ((a[p] & 0xFB) == 0x48 && a[p + 1] == 0x8D && (a[p + 2] & 0xC7) == 0x05)
                add(r.rva + p + 7 + r32(p + 3), r.rva + p, 5);
        for (int64_t p = 0; p < n; ++p)
            if ((a[p] & 0xFE) == 0x48 && (a[p + 1] & 0xF8) == 0xB8 && p + 10 <= len) {
                uint64_t v;
                std::memcpy(&v, a + p + 2, 8);
                const int64_t t = static_cast<int64_t>(v - im.image_base);
                add(t, r.rva + p, 6);
            }
    }
}

void scan_xrefs_par(const FImage& im, const RangeV& extra,
                    const std::function<bool(int64_t, int64_t, uint8_t)>& keep, std::vector<XHit>& out) {
    // the passes of scan_xrefs, one (region, kind) pair per task, each kept
    // hit tagged with its place in scan_xrefs' order
    struct R {
        int64_t rva, vsize;
    };
    std::vector<R> regs;
    for (const PSection* s : im.exec_sections()) regs.push_back({s->rva, s->vsize});
    for (const auto& [lo, hi] : extra) regs.push_back({lo, hi - lo});
    const uint8_t* mem = im.mem.data();
    const int64_t L = im.len;
    const size_t ntask = regs.size() * 7;
    std::vector<std::vector<XHit>> part(ntask);
    std::atomic<size_t> next{0};
    auto work = [&] {
        for (size_t task; (task = next.fetch_add(1)) < ntask;) {
            const R& r = regs[task / 7];
            const uint8_t k = static_cast<uint8_t>(task % 7);
            const uint8_t* a = mem + r.rva;
            const int64_t len = r.vsize;
            const int64_t n = len - 8;
            if (n <= 0) continue;
            std::vector<XHit>& o = part[task];
            auto r32 = [a](int64_t p) {
                int32_t v;
                std::memcpy(&v, a + p, 4);
                return static_cast<int64_t>(v);
            };
            auto r8 = [a](int64_t p) { return static_cast<int64_t>(static_cast<int8_t>(a[p])); };
            auto add = [&](int64_t t, int64_t p) {
                if (t >= 0 && t < L && keep(t, r.rva + p, k))
                    o.push_back({static_cast<uint32_t>(t), static_cast<uint32_t>(r.rva + p), k});
            };
            switch (k) {
                case 0:
                    for (int64_t p = 0; p < n; ++p)
                        if (a[p] == 0xE9) add(r.rva + p + 5 + r32(p + 1), p);
                    break;
                case 1:
                    for (int64_t p = 0; p < n; ++p)
                        if (a[p] == 0xE8) add(r.rva + p + 5 + r32(p + 1), p);
                    break;
                case 2:
                    for (int64_t p = 0; p < n; ++p)
                        if (a[p] == 0x0F && (a[p + 1] & 0xF0) == 0x80) add(r.rva + p + 6 + r32(p + 2), p);
                    break;
                case 3:
                    for (int64_t p = 0; p < n; ++p)
                        if (a[p] == 0xEB) add(r.rva + p + 2 + r8(p + 1), p);
                    break;
                case 4:
                    for (int64_t p = 0; p < n; ++p)
                        if ((a[p] & 0xF0) == 0x70) add(r.rva + p + 2 + r8(p + 1), p);
                    break;
                case 5:
                    for (int64_t p = 0; p < n; ++p)
                        if ((a[p] & 0xFB) == 0x48 && a[p + 1] == 0x8D && (a[p + 2] & 0xC7) == 0x05)
                            add(r.rva + p + 7 + r32(p + 3), p);
                    break;
                default:
                    for (int64_t p = 0; p < n; ++p)
                        if ((a[p] & 0xFE) == 0x48 && (a[p + 1] & 0xF8) == 0xB8 && p + 10 <= len) {
                            uint64_t v;
                            std::memcpy(&v, a + p + 2, 8);
                            add(static_cast<int64_t>(v - im.image_base), p);
                        }
            }
        }
    };
    const unsigned nt = std::max(1u, std::min<unsigned>(std::thread::hardware_concurrency(), 16));
    std::vector<std::thread> th;
    for (unsigned i = 1; i < nt; ++i) th.emplace_back(work);
    work();
    for (std::thread& t : th) t.join();
    out.clear();
    size_t n = 0;
    for (const auto& v : part) n += v.size();
    out.reserve(n);
    for (auto& v : part) {
        out.insert(out.end(), v.begin(), v.end());
        std::vector<XHit>().swap(v);
    }
}

RawXrefs::RawXrefs(const FImage& im, const RangeV& extra) {
    // scan_xrefs' order (on threads), then a stable order by target: the
    // key holds the target over the position in that order
    std::vector<XHit> hits;
    scan_xrefs_par(im, extra, [](int64_t, int64_t, uint8_t) { return true; }, hits);
    const size_t N = hits.size();
    if (N >= (uint64_t(1) << 32)) throw std::runtime_error("too many xrefs");
    std::vector<uint64_t> key(N);
    for (size_t i = 0; i < N; ++i) key[i] = (static_cast<uint64_t>(static_cast<uint32_t>(hits[i].t)) << 32) | i;
    std::sort(std::execution::par, key.begin(), key.end());
    tgt.resize(N);
    src.resize(N);
    kind.resize(N);
    for (size_t i = 0; i < N; ++i) {
        const size_t j = static_cast<size_t>(key[i] & 0xFFFFFFFFu);
        tgt[i] = static_cast<uint32_t>(hits[j].t);
        src[i] = static_cast<uint32_t>(hits[j].s);
        kind[i] = hits[j].k;
    }
}

size_t RawXrefs::lower(int64_t rva) const {
    if (rva <= 0) return 0;
    if (rva > 0xFFFFFFFFll) return tgt.size();
    return static_cast<size_t>(std::lower_bound(tgt.begin(), tgt.end(), static_cast<uint32_t>(rva)) - tgt.begin());
}

std::pair<size_t, size_t> RawXrefs::to(int64_t rva) const {
    if (rva < 0 || rva > 0xFFFFFFFFll) return {0, 0};
    const auto r = std::equal_range(tgt.begin(), tgt.end(), static_cast<uint32_t>(rva));
    return {static_cast<size_t>(r.first - tgt.begin()), static_cast<size_t>(r.second - tgt.begin())};
}

const KindEnc KIND_ENC[7] = {{M_JMP, 5}, {M_CALL, 5}, {M_NONE, 6}, {M_JMP, 2}, {M_NONE, 2}, {M_LEA, 7}, {M_MOVABS, 10}};

std::vector<int64_t> confirmed_refs_to(Code& code, const RawXrefs& xr, int64_t rva) {
    std::vector<int64_t> out;
    const auto [lo, hi] = xr.to(rva);
    Lite d;
    for (size_t i = lo; i < hi; ++i) {
        const int k = xr.kind[i];
        if (k < 5) continue;
        const int64_t src = xr.src[i];
        if (!code.insn(src, d) || d.size != KIND_ENC[k].size || d.mid != KIND_ENC[k].mid) continue;
        out.push_back(src);
    }
    return out;
}

std::vector<BranchRef> confirmed_branches_to(Code& code, const RawXrefs& xr, int64_t rva) {
    std::vector<BranchRef> out;
    const auto [lo, hi] = xr.to(rva);
    Lite d;
    for (size_t i = lo; i < hi; ++i) {
        const int k = xr.kind[i];
        if (k >= 5) continue;
        const int64_t src = xr.src[i];
        if (!code.insn(src, d)) continue;
        int64_t t;
        if (d.size != KIND_ENC[k].size || !hex_op(d.ops(), t) || t != rva) continue;
        if (d.mid == M_JMP || d.mid == M_CALL || mf(d.mid, F_JCC)) out.push_back({src, d.mid, d.size});
    }
    return out;
}

}  // namespace flow
