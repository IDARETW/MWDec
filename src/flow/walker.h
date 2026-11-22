// Recursive descent over everything reachable from the roots
// (devirt_flow.py: Walker).
#pragma once

#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "flow/idiom.h"

namespace flow {

// root reasons ("pdata", "reloc:.rdata", ...) interned; a provenance value
// is either a run start (>= 0) or -(1 + reason id)
int why_id(const std::string& s);
const std::string& why_str(int id);
inline int64_t why_val(const std::string& s) { return -1 - static_cast<int64_t>(why_id(s)); }

struct CheckFold {
    int64_t c = 0, site = 0;
    bool has_E = false;
    int64_t E = 0;
    InsnList insns;
    bool flags_changed = false;
    std::vector<std::string> regs_changed;
    std::vector<std::pair<int64_t, int64_t>> reads;
    std::optional<std::string> why;
};

// int64 -> int64 open-addressing map (insert-if-absent and lookup only)
class I64Map {
public:
    bool contains(int64_t k) const { return find(k) != nullptr; }
    const int64_t* find(int64_t k) const;
    bool insert(int64_t k, int64_t v);  // false if present (value kept)
    size_t size() const { return n_; }

private:
    void grow();
    std::vector<int64_t> keys_, vals_;
    size_t n_ = 0;
    static constexpr int64_t EMPTY = INT64_MIN;
};

template <class V> class OrderedMap {
public:
    // insertion-ordered like a Python dict; set() keeps an existing key's position
    void set(int64_t k, V v) {
        auto it = idx_.find(k);
        if (it != idx_.end()) {
            items_[it->second].second = std::move(v);
            return;
        }
        idx_.emplace(k, items_.size());
        items_.emplace_back(k, std::move(v));
    }
    V* get(int64_t k) {
        auto it = idx_.find(k);
        return it == idx_.end() ? nullptr : &items_[it->second].second;
    }
    const V* get(int64_t k) const {
        auto it = idx_.find(k);
        return it == idx_.end() ? nullptr : &items_[it->second].second;
    }
    bool contains(int64_t k) const { return idx_.count(k) != 0; }
    size_t size() const { return items_.size(); }
    const std::vector<std::pair<int64_t, V>>& items() const { return items_; }
    std::vector<std::pair<int64_t, V>>& items() { return items_; }
    std::vector<std::pair<int64_t, V>> sorted() const {
        auto v = items_;
        std::sort(v.begin(), v.end(), [](const auto& a, const auto& b) { return a.first < b.first; });
        return v;
    }

private:
    std::vector<std::pair<int64_t, V>> items_;
    std::unordered_map<int64_t, size_t> idx_;
};

struct DataRef {
    int64_t pc;
    int64_t t;
};

class Walker {
public:
    Walker(FImage& im, Code& code, const Regions& reg, bool bypass);
    FImage* imp;
    // read another image from now on (a view of the same bytes)
    void rebind(FImage& im) { imp = &im; }
    Code* code;
    ByteMap bm;
    bool bypass;
    bool resolve = true;
    OrderedMap<IdiomP> idioms;
    OrderedMap<ChainP> chains;
    int64_t overlaps = 0, undecodable = 0, outside = 0, jtables = 0;
    std::vector<DataRef> datarefs, coderefs;
    int64_t indirect = 0, insns = 0;
    std::vector<int64_t> work;
    bool keep_src = false;  // record provenance (Walker.src)
    I64Map src;
    std::unordered_set<int64_t> call_targets;
    std::map<int64_t, UnknownP> unknowns;
    bool keep_found_in = false;
    std::unordered_map<int64_t, int64_t> found_in;
    const std::unordered_map<int64_t, CheckFold>* checks = nullptr;
    bool atomic = true;
    std::unordered_set<int64_t> frozen;
    const ByteMap* stop_f = nullptr;
    const std::unordered_set<int64_t>* poison = nullptr;
    bool follow_refs = true;
    bool tables = true;
    // where the walk's time goes (seconds, calls)
    double t_chain = 0, t_construct = 0;
    int64_t n_chain = 0, n_construct = 0;
    // when set: every index range [lo, hi) of bm the walk sets a flag in
    std::vector<std::pair<int64_t, int64_t>>* touch_log = nullptr;

    void walk(const std::vector<std::pair<int64_t, int64_t>>& roots);  // (rva, why value)
    // provenance chain: [rva, src, src-of-src, ...]; strings as why values
    std::vector<int64_t> origin(int64_t rva, int depth) const;

private:
    struct H {
        int64_t pc;
        int size;
        bool synth;
    };
    void run(int64_t pc);
    void touch(int64_t i, int64_t e) {
        if (touch_log && i >= 0 && e > i) touch_log->emplace_back(i, e);
    }
    void push(int64_t rva, int64_t from);
    void mark(const InsnList& insns, uint8_t bit);
    void jump_table(int64_t site, std::string_view reg, const std::vector<H>& hist);
    int64_t run0_ = -1;
    bool have_run0_ = false;
};

}  // namespace flow
