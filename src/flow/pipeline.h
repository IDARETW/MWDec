// The whole pass (devirt_flow.py: Pipeline and the free functions it uses).
#pragma once

#include <functional>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "flow/checks.h"
#include "flow/json.h"
#include "flow/planner.h"
#include "flow/sweep.h"

namespace flow {

extern bool g_regions_v2;  // extra_code_regions: pushed and called addresses count as landings (the default)
RangeV extra_code_regions(const FImage& im, int min_hits = 8, bool tails = true);
std::vector<int64_t> long_sub_sites(const FImage& im, const Code& code);
// devirt_flow.census_chains: {long-form site: Chain} (site order) and the sites without one
void census_chains(FImage& im, Code& code, const RawXrefs& xr, OrderedMap<ChainP>& res, std::vector<int64_t>& fail,
                   int depth = 120);

struct RefSrc {
    bool is_why = false;
    int64_t v = 0;  // src address, or why value
};

struct Viol {
    bool is_root = false;  // (why, r) appended after the xref violations
    int64_t src = 0;       // or why value
    int64_t t = 0;
};

struct Inv {
    std::vector<std::string> sub_of_chains, sub_not_chains;
    int64_t live_bytes_in_wipes = 0;
    std::vector<int64_t> patch_decode_bad;
    std::vector<Viol> refs_into_interior;
    std::vector<std::pair<int64_t, std::string>> bad_relocs;
    std::vector<std::tuple<int64_t, int64_t, bool>> plausible;
    int64_t blocks = 0, plaus = 0;
    Json to_json(bool summary) const;  // report form / log form
};

class Pipeline {
public:
    using Log = std::function<void(const std::string&)>;
    Pipeline(const std::string& path, Log log, const std::string& routines, const std::vector<std::string>& keep_plans,
             const std::vector<std::string>& stub_plans);
    // the same with everything already in memory (routines: routines.json as read, or null)
    Pipeline(FImage im, Log log, const Json& routines, std::vector<PlanF> keep_plans,
             const std::vector<PlanF>& stub_plans);
    ~Pipeline();
    void run();
    PlanF plan() const;
    PlanF dead_plan() const;
    PlanF stubs_plan() const;
    Json report();
    std::vector<int64_t> starts_out();
    // the live bitmap (packed) and its regions
    std::vector<uint8_t> live_bits() const;
    const Regions& regions() const { return reg_; }

    bool skip_report_only = false;  // leave out walks that only feed the report

private:
    using Roots = std::vector<std::pair<int64_t, int64_t>>;
    void log(const std::string& s) { log_(s); }
    double secs() const;
    void analyse();
    void apply_and_rewalk();
    void restore();
    std::vector<std::pair<int64_t, int64_t>> dead_bytes();
    struct KeepFor {
        Bits keep, live, keep_lost;
        std::vector<std::pair<int64_t, int64_t>> live_stubs;
    };
    KeepFor keep_for(Walker& wl, const Bits& code_idx, int64_t cap);
    const std::vector<int64_t>& ref_bounds();
    std::vector<std::pair<int64_t, int64_t>> wipes_(const Bits& keep, const Bits& live, const Bits& keep_lost,
                                                    const Bits& code_idx);
    std::vector<std::tuple<int64_t, int64_t, bool>> b_violations(const Bits& mask);
    int settle_b();
    Inv invariants(const Bits& mask, const std::unordered_set<int64_t>& drops_extra, Walker& wl);
    void check_all();
    std::vector<int64_t> targets(const Inv& inv);
    std::unordered_set<int64_t> ws_drops();
    void recompute_drops();
    void rollback(const std::unordered_set<int64_t>& drop, const std::string& reason, bool restore);
    using Saved = std::vector<std::pair<int64_t, std::vector<uint8_t>>>;
    Saved stubs_on(bool check_claimed);
    void stubs_off(const Saved& saved);
    struct Recs {
        std::vector<int64_t> fb, fe, bi, ei;
    };
    Recs rec_arrays(bool exclude_prot, bool only_prot) const;
    std::pair<Roots, Json> sweep(Walker& w, Walker& ws, Code& code, const std::string& tag);
    std::unique_ptr<Walker> new_ws(Code& code);
    Json sweep_summary(Walker& w1, Walker& ws, const Roots& roots, const Json& st);
    Json kept_only_content(Walker& ws, const Roots& roots);
    int access_size_memo(Code& code, int64_t pc);
    std::map<int64_t, int64_t> function_for(const std::vector<int64_t>& starts);
    std::vector<std::pair<int64_t, int64_t>> roots_with(const std::vector<int64_t>& rs, const std::string& why) const;
    Json fold_report();
    Json reachable_routines();
    std::set<int64_t> gset() const;

    Log log_;
    double t0_;
    FImage im_;
    std::vector<PlanF> keep_plans_;
    std::vector<std::pair<int64_t, int64_t>> baked_;
    RangeV extra_;
    RoutineModel model_;
    Regions reg_;
    std::unique_ptr<Code> code_;
    std::unique_ptr<BitMap> keep_, keep_wipe_;
    std::vector<std::pair<int64_t, int64_t>> stub_ranges_;
    std::vector<std::pair<int64_t, std::vector<uint8_t>>> stub_patches_;
    std::unique_ptr<RawXrefs> xr_;
    OrderedMap<ChainP> census_;
    std::vector<int64_t> cfail_;
    std::unordered_map<int64_t, CheckFold> checks_;
    Roots roots_;
    std::vector<int64_t> dropped_roots_, dropped_prot_, dropped_own_pointers_, dropped_reached_, lost_records_;
    std::pair<int64_t, int64_t> arxan_sec_{};
    std::vector<int64_t> b_roots_, b_data_, u_roots_, u_data_;
    std::unordered_set<int64_t> b_seen_, u_refs_;
    std::unordered_map<int64_t, int> asz_;
    std::unordered_map<int64_t, RefSrc> ref_src_;
    bool have_bounds_ = false;
    std::vector<int64_t> bounds_;
    bool have_static_writes_ = false;
    size_t static_writes_n_ = 0;
    int64_t wa0_istarts_ = 0;

    std::unique_ptr<Walker> w1_, ws_, w2_, wa_, wk_, w2s_own_, wb_, wu_;
    Walker* w2s_ = nullptr;
    std::unique_ptr<Code> code_s_own_, code2_, code3_own_;
    // the walks after a plan is applied run side by side, each with a decode cache of its own
    std::unique_ptr<Code> codeA_own_, codeK_own_, codeB_own_, codeU_own_;
    Code* code_s_ = nullptr;
    Code* code3_ = nullptr;
    std::unique_ptr<Planner> pl_;
    std::vector<std::pair<int64_t, std::vector<uint8_t>>> orig_;
    std::unique_ptr<Sweeper> bsweeper_;
    Roots sweep_roots_;
    Json sweep_stats_, sweep_before_;
    std::vector<std::pair<int64_t, int64_t>> wipes_v_, dead_wipes_;
    Bits wipe_mask_, dead_mask_, sec_mask_;
    Json wipe_stats_;
    std::vector<std::pair<int64_t, int64_t>> stubs_reachable_;
    std::unordered_set<int64_t> wipe_drops_, dead_drops_;
    Inv inv_, inv_union_;
    std::vector<std::pair<int64_t, std::string>> rolled_back_;
    int64_t unwiped_ = 0, b_rounds_ = 0, ws_rolled_back_ = 0;
    int64_t b_counts_[2]{};
    int64_t b_hidden_ = 0;  // branches found at any byte offset of unwalked bytes that land on a wiped byte
    int64_t b_ptrs_ = 0;    // relocated qwords in kept code-region bytes that point at a wiped byte
    bool sweep_on_ = true;
};

}  // namespace flow
