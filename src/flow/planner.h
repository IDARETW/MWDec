// The patch planner (devirt_flow.py: Planner).
#pragma once

#include <map>
#include <memory>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "flow/liveness.h"
#include "flow/walker.h"

namespace flow {

struct Patch {
    std::vector<uint8_t> data;
    uint8_t kind = 0;
    std::string tag;
};

// a dict rva -> Patch with Python's ordering (deleted keys re-insert at the end)
class PatchMap {
public:
    void set(int64_t rva, Patch p);
    bool erase(int64_t rva);
    const Patch* get(int64_t rva) const;
    bool contains(int64_t rva) const { return idx_.count(rva) != 0; }
    size_t size() const { return idx_.size(); }
    template <class F> void each(F&& f) const {
        for (const auto& e : v_)
            if (e.alive) f(e.rva, e.p);
    }
    std::vector<int64_t> keys_in_order() const;
    std::vector<int64_t> sorted_keys() const;

private:
    struct E {
        int64_t rva;
        Patch p;
        bool alive;
    };
    std::vector<E> v_;
    std::unordered_map<int64_t, size_t> idx_;
};

// an insertion-ordered Counter of strings
struct Counter {
    std::vector<std::pair<std::string, int64_t>> v;
    int64_t& operator[](const std::string& k) {
        for (auto& e : v)
            if (e.first == k) return e.second;
        v.emplace_back(k, 0);
        return v.back().second;
    }
    int64_t get(const std::string& k) const {
        for (auto& e : v)
            if (e.first == k) return e.second;
        return 0;
    }
};

struct BodyEl {
    char kind;  // 'p' pop, 'j' jmp, 'c' call, 'k' jcc
    int64_t a = 0;
    int cc = -1;
};

struct Res {
    bool ok = false;
    std::string detail;  // skip reason, or "inline" / "two-hop" / "jmp"
    std::vector<BodyEl> body;
    int64_t target = 0;  // check: final(E)
};

class Planner {
public:
    Planner(FImage& im, Code& code, const RawXrefs& xr, Walker& w, const std::vector<int64_t>& roots,
            const BitMap* keep, const Regions& reg);
    FImage& im;
    Code& code;
    const RawXrefs& xr;
    Walker& w;
    ByteMap& bm;
    const Regions& reg;
    const BitMap* keep;
    std::vector<std::pair<std::string, int64_t>> keep_overlaps;
    std::unordered_map<int64_t, int> inner_regs, inner_flags;
    std::unordered_set<int64_t> rootset;
    const std::vector<int64_t>& rel;
    OrderedMap<ChainP> chain_by_S;
    PatchMap patches;
    BitMap claimed;
    OrderedMap<Res> idiom_res, check_res;
    std::unordered_set<int64_t> drops;
    Counter peep_count, peep_done, peep_skip;
    std::map<std::string, std::vector<int64_t>> peep_sites;
    std::unordered_map<int64_t, int> peep_reg;  // -1 for None
    std::unordered_map<int64_t, std::pair<std::string, std::string>> peep_seen;
    bool compute_fold_dead = true;  // report-only liveness sweep (kept for decode-cache parity)
    // where plan_idioms spends its time, in seconds (logged with the plan phases)
    double t_live = 0, t_fold_dead = 0, t_entered = 0, t_final = 0, t_decode = 0, t_sort = 0, t_calls = 0;
    // Guards that publish a value when they run. A construct that calls one
    // is not a jump in disguise: it stays as shipped, and no other rewrite
    // may be aimed past it (final() does not see through it).
    std::unordered_set<int64_t> publishers;
    bool publishing(const Idiom& idm) const {
        if (publishers.empty()) return false;
        for (const ChainP& c : idm.inner)
            if (publishers.count(c->G)) return true;
        return false;
    }

    std::vector<std::tuple<int, int64_t, int64_t>> entered(int64_t lo, int64_t hi,
                                                          const std::unordered_set<int64_t>& own,
                                                          bool lo_start_ok = true);
    int64_t final(int64_t x);
    bool free_(int64_t lo, int64_t hi) const { return !claimed.any_in(lo, hi - lo); }
    void put(int64_t rva, std::vector<uint8_t> data, uint8_t kind, std::string tag, int64_t fill_to = -1);
    void plan_chains();
    bool decide_chain(int64_t S, Chain& ch);
    std::vector<std::pair<const char*, int64_t>> preds_of(int64_t S);
    void plan_idioms();
    Res plan_idiom(int64_t s, const Idiom& idm);
    void plan_checks(const std::unordered_map<int64_t, CheckFold>& checks);
    void plan_peephole();

private:
    struct Shape {
        int kind;  // 0 up, 1 down, 2 jmp8, 3 ld0, 4 ld8, 5 st0, 6 st8
        int reg;
        int size;
    };
    bool shape(int64_t a, Shape& s);
    std::pair<int64_t, int64_t> next(int64_t a, int size);  // (addr, joined-by-jmp-at or -1)
    bool other_way_in(int64_t a, int64_t own = -1);
    FlagLiveness& fl();
    RegLiveness& rl();
    std::unique_ptr<FlagLiveness> fl_;
    std::unique_ptr<RegLiveness> rl_;
};

std::vector<uint8_t> rel32(int64_t frm_next, int64_t to);

}  // namespace flow
