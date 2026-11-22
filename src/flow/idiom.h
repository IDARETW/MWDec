// Disguised jumps (idioms), routine-call chains, the routine table, and the
// symbolic evaluation of stack-move constructs (devirt_flow.py: Idiom,
// resolve_idiom, Chain, match_chain, RoutineModel, resolve_construct).
#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "flow/code.h"
#include "flow/json.h"

namespace flow {

using InsnList = std::vector<std::pair<int64_t, int>>;  // (address, size)

// register names: 0..15 GPR64, 16 "flags", others interned after
int reg_id(std::string_view name);
const std::string& reg_str(int id);
using RegSet = uint64_t;
// names of a set, sorted as Python sorts strings
std::vector<int> sorted_regs(RegSet s);

enum VK : uint8_t { VNONE = 0, VR, VM, VC, VSEL, VCLOB };

struct Val {
    uint8_t k = VNONE;
    int8_t cc = 0;
    int16_t reg = 0;
    int64_t a = 0, b = 0;
    static Val R(int r) { Val v; v.k = VR; v.reg = static_cast<int16_t>(r); return v; }
    static Val M(int64_t o) { Val v; v.k = VM; v.a = o; return v; }
    static Val C(int64_t x) { Val v; v.k = VC; v.a = x; return v; }
    static Val Sel(int cc, int64_t taken, int64_t fall) {
        Val v;
        v.k = VSEL;
        v.cc = static_cast<int8_t>(cc);
        v.a = taken;
        v.b = fall;
        return v;
    }
    static Val Clob(int r) { Val v; v.k = VCLOB; v.reg = static_cast<int16_t>(r); return v; }
    bool operator==(const Val& o) const { return k == o.k && cc == o.cc && reg == o.reg && a == o.a && b == o.b; }
    bool operator!=(const Val& o) const { return !(*this == o); }
};

struct Chain {
    int64_t S = 0, E_raw = 0, E = 0, G = 0, R = 0, sub_site = 0;
    const char* call_form = "";
    InsnList insns;
    std::vector<int> push_order;  // reg ids; REG_FLAGS for pushfq
    std::vector<std::pair<const char*, int64_t>> preds;
    std::string flags;            // flags at E ("" = None)
    int8_t bypass = -1;           // -1 None, 0 False, 1 True
    std::optional<std::string> why;
    const char* S_patch = nullptr;
    std::optional<int64_t> final_;
    bool saves_flags() const;
};
using ChainP = std::shared_ptr<Chain>;

struct Effect {
    enum Kind { NET, CONT, UNKNOWN } kind = NET;
    std::array<int64_t, 3> t{};
    std::vector<int> clob;
    std::string why;
};

enum IKind : uint8_t { IK_JMP, IK_JCC, IK_CALL, IK_POPJMP };
const char* ikind_name(int k);

struct Idiom {
    int64_t start = 0;
    uint8_t kind = IK_JMP;
    int8_t cc = -1;
    int64_t target = 0, fall = 0, ret = 0, end = 0, pop = 0;
    InsnList insns;
    std::vector<ChainP> inner;
    std::vector<Effect> effects;
    bool flags_clob = false;
    std::vector<int> clob;  // sorted by name
    bool has_cont() const {
        for (const Effect& e : effects)
            if (e.kind == Effect::CONT) return true;
        return false;
    }
};
using IdiomP = std::shared_ptr<Idiom>;

struct Unknown {
    int64_t start = 0;
    ChainP chain;
    std::string why;
    InsnList insns;
};
using UnknownP = std::shared_ptr<Unknown>;

struct Construct {
    IdiomP idm;
    UnknownP unk;
};

struct RoutineInfo {
    std::optional<std::string> form;
    Json klass;
    std::vector<std::pair<int64_t, int64_t>> cont;  // (offset, RVA)
    std::vector<std::string> regs_changed;
    int8_t proven = -1;  // None / False / True
    bool stub_r8 = false;
    bool has_clobbers = false;
    std::vector<std::string> clobbers;
    bool extra = false;
    bool publishes = false;  // a guard that publishes a dword when it runs: its construct stays in place
    std::vector<int64_t> publish_rvas;  // the dwords
};

struct RoutineModel {
    std::vector<int64_t> order;  // insertion order of r
    std::unordered_map<int64_t, RoutineInfo> r;
    std::vector<std::pair<int64_t, int64_t>> writes;
    std::vector<int64_t> not_routines;
    std::unordered_set<int64_t> extra_used, extra_given;

    void load(const std::string& path, uint64_t image_base);
    void load_from(const Json& top, uint64_t image_base);  // routines.json as read
    const RoutineInfo* get(int64_t g) const {
        auto it = r.find(g);
        return it == r.end() ? nullptr : &it->second;
    }
    Effect effect(const Chain& ch);
};

std::optional<Idiom> resolve_idiom(Code& code, int64_t a, int max_insns = 64);
ChainP match_chain(Code& code, int64_t s);
Construct resolve_construct(Code& code, int64_t a, int max_insns = 1200, int max_depth = 24);

}  // namespace flow
