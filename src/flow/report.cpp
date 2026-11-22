// Pipeline::report (devirt_flow.py: report, fold_report, reachable_routines).
#include <algorithm>
#include <set>

#include "flow/pipeline.h"
#include "flow/pyutil.h"

namespace flow {

namespace {

Json cnt(const Counter& c) {
    Json j = Json::object();
    for (const auto& [k, v] : c.v) j[k] = Json(v);
    return j;
}

Json hexlist(const std::vector<int64_t>& v, size_t limit = SIZE_MAX) {
    Json j = Json::array();
    for (size_t k = 0; k < v.size() && k < limit; ++k) j.push(Json(hex8(v[k])));
    return j;
}

}  // namespace

Json Pipeline::reachable_routines() {
    Json out = Json::array();
    Walker& w = *w2s_;
    for (int64_t g : gset()) {
        if (!(w.bm.get(g) & (START | ISTART))) continue;
        const auto o = w.origin(g, 3000);
        Json e = Json::object();
        e["G"] = Json(hex8(g));
        e["path_len"] = Json(static_cast<int64_t>(o.size()));
        Json hops = Json::array();
        for (size_t k = 1; k < o.size() && k < 6; ++k)
            hops.push(o[k] >= 0 ? Json(hex8(o[k])) : Json(why_str(static_cast<int>(-1 - o[k]))));
        e["first_hops"] = hops;
        e["root"] = o.back() < 0 ? Json(why_str(static_cast<int>(-1 - o.back()))) : Json();
        e["root_addr"] = (o.size() > 1 && o[o.size() - 2] >= 0) ? Json(hex8(o[o.size() - 2])) : Json();
        out.push(e);
    }
    return out;
}

Json Pipeline::fold_report() {
    Planner& pl = *pl_;
    Walker& w1 = *w1_;
    std::vector<int64_t> folded, ok;
    for (const auto& [s, i] : w1.idioms.items())
        if (i->has_cont()) folded.push_back(s);
    Counter skip;
    for (int64_t s : folded) {
        const Res& r = *pl.idiom_res.get(s);
        if (r.ok)
            ok.push_back(s);
        else
            skip[r.detail] += 1;
    }
    Json unk = Json::array();
    std::set<std::string> unk_g;
    for (const auto& [s, u] : w1.unknowns) {
        Json e = Json::object();
        e["outermost_start"] = Json(hex8(s));
        e["S"] = Json(hex8(u->chain->S));
        e["G"] = Json(hex8(u->chain->G));
        const RoutineInfo* m = model_.get(u->chain->G);
        e["class"] = m ? m->klass : Json();
        e["why"] = Json(u->why);
        unk_g.insert(hex8(u->chain->G));
        unk.push(e);
    }
    Json o = Json::object();
    o["constructs_with_a_continuation_routine"] = Json(static_cast<int64_t>(folded.size()));
    o["folded"] = Json(static_cast<int64_t>(ok.size()));
    {
        Counter k;
        for (int64_t s : ok) k[ikind_name((*w1.idioms.get(s))->kind)] += 1;
        o["folded_by_kind"] = cnt(k);
    }
    {
        Json l = Json::array();
        for (int64_t s : ok) {
            const Idiom& i = **w1.idioms.get(s);
            if (i.kind != IK_POPJMP) continue;
            Json e = Json::object();
            e["start"] = Json(hex8(s));
            e["pop"] = Json(i.pop);
            e["target"] = Json(hex8(i.target));
            l.push(e);
        }
        o["folded_popjmp_entries"] = l;
    }
    o["skipped_by_reason"] = cnt(skip);
    {
        Json ss = Json::object();
        for (const auto& [r, n] : skip.v) {
            Json l = Json::array();
            for (int64_t s : folded) {
                const Res& x = *pl.idiom_res.get(s);
                if (!x.ok && x.detail == r && l.size() < 100) l.push(Json(hex8(s)));
            }
            ss[r] = l;
        }
        o["skipped_sites"] = ss;
    }
    {
        // Counter over dict values in insertion order: the planner fills these in sorted order
        auto vc = [](const std::unordered_map<int64_t, int>& m) {
            std::vector<std::pair<int64_t, int>> v(m.begin(), m.end());
            std::sort(v.begin(), v.end());
            Counter c;
            for (const auto& [k, x] : v) c[verdict_name(x)] += 1;
            return c;
        };
        o["register_liveness"] = cnt(vc(pl.inner_regs));
        o["flag_liveness"] = cnt(vc(pl.inner_flags));
    }
    o["unknown_continuation_constructs"] = Json(static_cast<int64_t>(unk.size()));
    {
        Json l = Json::array();
        for (const std::string& g : unk_g) l.push(Json(g));
        o["unknown_continuation_routines"] = l;
    }
    o["unknown_continuation_list"] = unk;
    {
        Json l = Json::array();
        for (const auto& [k, a] : pl.keep_overlaps) {
            Json e = Json::array();
            e.push(Json(k));
            e.push(Json(hex8(a)));
            l.push(e);
        }
        o["keep_plan_overlaps"] = l;
    }
    {
        Json c = Json::object();
        c["bake_source"] = baked_.empty() ? Json() : Json("keep plans");
        c["baked_values"] = Json(static_cast<int64_t>(baked_.size()));
        c["sites"] = Json(static_cast<int64_t>(checks_.size()));
        int64_t nf = 0;
        Counter by;
        for (const auto& [k, r] : pl.check_res.items()) {
            if (r.ok) ++nf;
            by[r.ok ? std::string("ok") : r.detail] += 1;
        }
        c["folded"] = Json(nf);
        c["by_result"] = cnt(by);
        std::vector<int64_t> keys;
        for (const auto& [k, ck] : checks_) keys.push_back(k);
        std::sort(keys.begin(), keys.end());
        Json l = Json::array();
        for (int64_t k : keys) {
            const CheckFold& ck = checks_.at(k);
            Json e = Json::object();
            e["start"] = Json(hex8(ck.c));
            e["site"] = Json(hex8(ck.site));
            e["E"] = ck.has_E ? Json(hex8(ck.E)) : Json();
            e["flags_changed"] = Json(ck.flags_changed);
            e["regs_changed"] = Json::array(ck.regs_changed.begin(), ck.regs_changed.end());
            Json rd = Json::array();
            for (const auto& [a, n] : ck.reads) rd.push(Json(hex8(a) + "+" + std::to_string(n)));
            e["reads"] = rd;
            e["why"] = ck.why ? Json(*ck.why) : Json();
            Json res = Json::array();
            const Res* r = pl.check_res.get(k);
            if (!r) {
                res.push(Json("?"));
            } else if (r->ok) {
                res.push(Json("ok"));
                res.push(Json("jmp"));
                res.push(Json(std::to_string(r->target)));
            } else {
                res.push(Json("skip"));
                res.push(Json(r->detail));
            }
            e["result"] = res;
            l.push(e);
        }
        c["list"] = l;
        o["checks"] = c;
    }
    o["peephole_forms_in_live_code"] = cnt(pl.peep_count);
    o["peephole_folded"] = cnt(pl.peep_done);
    o["peephole_skipped"] = cnt(pl.peep_skip);
    {
        Json ps = Json::object();
        for (const auto& [k, v] : pl.peep_sites) ps[k] = hexlist(v, 50);
        o["peephole_sample_sites"] = ps;
    }
    o["baked_values_applied"] = Json(static_cast<int64_t>(baked_.size()));
    o["routine_stub_patches_total"] = Json(static_cast<int64_t>(stub_ranges_.size()));
    o["routine_stub_patches_still_reachable"] = Json(static_cast<int64_t>(stubs_reachable_.size()));
    o["table_entries_that_are_not_routines"] = Json(static_cast<int64_t>(model_.not_routines.size()));
    {
        std::set<std::string> s;
        for (int64_t g : model_.extra_given) s.insert(hex8(g));
        o["routines_from_extra_file"] = Json::array(s.begin(), s.end());
    }
    o["folded_on_extra_file_alone"] = Json::array();
    {
        std::set<std::string> s;
        for (const auto& [g, m] : model_.r)
            if (!(m.form && *m.form == "call") && m.cont.size() != 3) s.insert(hex8(g));
        o["table_routines_without_continuation"] = Json::array(s.begin(), s.end());
    }
    return o;
}

Json Pipeline::report() {
    Walker& w1 = *w1_;
    Planner& pl = *pl_;
    Json o = Json::object();
    o["image"] = Json(basename_of(im_.path));
    {
        Json l = Json::array();
        for (const auto& [a, b] : extra_) l.push(Json(hex8(a) + "-" + hex8(b)));
        o["extra_code_regions"] = l;
    }
    {
        Counter c;
        for (const auto& [r, w] : roots_) c[why_str(static_cast<int>(-1 - w))] += 1;
        o["roots"] = cnt(c);
    }
    o["roots_dropped_inside_chains"] = hexlist(dropped_roots_);
    {
        Json d = Json::object();
        d["count"] = Json(static_cast<int64_t>(dropped_prot_.size()));
        d["reached_anyway"] = Json(static_cast<int64_t>(dropped_reached_.size()));
        d["not_reached_otherwise"] = hexlist(lost_records_);
        d["first"] = hexlist(dropped_prot_, 100);
        o["roots_dropped_on_protection_code"] = d;
    }
    {
        std::set<int64_t> gs;
        for (const auto& [x, ch] : census_.items()) gs.insert(ch->G);
        Json l = Json::array();
        for (int64_t g : gs)
            if (w2_->bm.get(g) & (START | CODE | IDIOM)) l.push(Json(hex8(g)));
        o["routine_entries_reached_from_game_roots"] = l;
    }
    o["long_sub_sites"] = Json(static_cast<int64_t>(census_.size() + cfail_.size()));
    o["chains_matched"] = Json(static_cast<int64_t>(census_.size()));
    o["long_sub_sites_without_chain"] = hexlist(cfail_);
    std::vector<ChainP> chains;
    for (const auto& [S, ch] : w1.chains.items()) chains.push_back(ch);
    std::vector<int64_t> unreached;
    for (const auto& [x, ch] : census_.items())
        if (!w1.chains.contains(ch->S)) unreached.push_back(ch->S);
    o["chains_reached_from_game_roots"] = Json(static_cast<int64_t>(chains.size()));
    o["chains_not_reached"] = Json(static_cast<int64_t>(unreached.size()));
    {
        int64_t n = 0;
        Counter how, why, flags;
        for (const ChainP& c : chains) {
            if (c->bypass == 1) {
                ++n;
                how[c->S_patch ? c->S_patch : "None"] += 1;
            } else {
                why[c->why ? *c->why : "None"] += 1;
            }
            flags[c->flags.empty() ? "None" : c->flags] += 1;
        }
        o["chains_bypassed"] = Json(n);
        o["chains_bypass_method"] = cnt(how);
        o["chains_not_bypassed_by_reason"] = cnt(why);
        o["chains_flags_at_E"] = cnt(flags);
    }
    {
        auto sc = chains;
        std::sort(sc.begin(), sc.end(), [](const ChainP& a, const ChainP& b) { return a->S < b->S; });
        Json l = Json::array();
        for (const ChainP& c : sc) {
            Json e = Json::object();
            e["S"] = Json(c->S);
            e["E"] = Json(c->E);
            e["E_raw"] = Json(c->E_raw);
            e["final"] = c->final_ ? Json(*c->final_) : Json();
            e["G"] = Json(c->G);
            e["R"] = Json(c->R);
            e["call_form"] = Json(c->call_form);
            e["sub_site"] = Json(c->sub_site);
            e["flags_at_E"] = c->flags.empty() ? Json() : Json(c->flags);
            Json pr = Json::array();
            for (const auto& [k, s] : c->preds) {
                Json x = Json::array();
                x.push(Json(k));
                x.push(Json(s));
                pr.push(x);
            }
            e["preds"] = pr;
            e["bypass"] = c->bypass < 0 ? Json() : Json(c->bypass == 1);
            e["why"] = c->why ? Json(*c->why) : Json();
            Json po = Json::array();
            for (int r : c->push_order) po.push(Json(reg_str(r)));
            e["push_order"] = po;
            l.push(e);
        }
        o["chains"] = l;
    }
    o["census_unreached_S"] = hexlist(unreached);
    {
        std::set<int64_t> in_all, in_ok;
        for (const auto& [s, i] : w1.idioms.items())
            for (const ChainP& c : i->inner) {
                in_all.insert(c->S);
                if (pl.idiom_res.get(s)->ok) in_ok.insert(c->S);
            }
        o["chains_inside_idioms"] = Json(static_cast<int64_t>(in_all.size()));
        o["chains_inside_rewritten_idioms"] = Json(static_cast<int64_t>(in_ok.size()));
        Json l = Json::array();
        for (const auto& [s, i] : w1.idioms.sorted())
            for (const ChainP& c : i->inner) {
                Json e = Json::object();
                e["S"] = Json(c->S);
                e["idiom"] = Json(s);
                e["E_raw"] = Json(c->E_raw);
                e["G"] = Json(c->G);
                auto it = pl.inner_flags.find(s);
                e["flags_after"] = Json(it == pl.inner_flags.end() ? std::string("preserved") : verdict_name(it->second));
                e["rewritten"] = Json(pl.idiom_res.get(s)->ok);
                l.push(e);
            }
        o["chains_inside_idioms_list"] = l;
    }
    {
        std::vector<std::pair<int64_t, int>> v(pl.inner_flags.begin(), pl.inner_flags.end());
        std::sort(v.begin(), v.end());
        Counter c;
        for (const auto& [k, x] : v) c[verdict_name(x)] += 1;
        o["inner_chain_flags"] = cnt(c);
    }
    {
        Counter kinds, okk, how, skip;
        for (const auto& [s, i] : w1.idioms.items()) kinds[ikind_name(i->kind)] += 1;
        int64_t call_empty = 0;
        std::map<std::string, std::vector<int64_t>> skip_sites;
        std::vector<std::string> skip_order;
        for (const auto& [s, r] : pl.idiom_res.items()) {
            const Idiom& i = **w1.idioms.get(s);
            if (r.ok) {
                okk[ikind_name(i.kind)] += 1;
                how[r.detail] += 1;
                if (i.kind == IK_CALL && !r.body.empty() && r.body[0].kind == 'j') ++call_empty;
            } else {
                skip[r.detail] += 1;
            }
        }
        for (const auto& [s, r] : pl.idiom_res.sorted())
            if (!r.ok) {
                if (!skip_sites.count(r.detail)) skip_order.push_back(r.detail);
                skip_sites[r.detail].push_back(s);
            }
        o["idioms_found"] = cnt(kinds);
        o["idioms_rewritten"] = cnt(okk);
        o["idioms_rewritten_how"] = cnt(how);
        o["idiom_calls_of_empty_routines_as_jmp"] = Json(call_empty);
        o["idioms_skipped_by_reason"] = cnt(skip);
        Json ss = Json::object();
        for (const std::string& k : skip_order) ss[k] = hexlist(skip_sites[k], 200);
        o["idioms_skipped_sites"] = ss;
    }
    {
        int64_t pb = 0;
        pl.patches.each([&pb](int64_t, const Patch& p) { pb += static_cast<int64_t>(p.data.size()); });
        o["patches"] = Json(static_cast<int64_t>(pl.patches.size()));
        o["patch_bytes"] = Json(pb);
    }
    o["reloc_drops_patches"] = Json(static_cast<int64_t>(pl.drops.size()));
    o["reloc_drops_wipes"] = Json(static_cast<int64_t>(wipe_drops_.size()));
    o["wipe_ranges"] = Json(static_cast<int64_t>(wipes_v_.size()));
    {
        int64_t wb = 0;
        for (const auto& [r, n] : wipes_v_) wb += n;
        o["wipe_bytes"] = Json(wb);
    }
    o["arxan_section_composition"] = wipe_stats_;
    {
        Json sec = Json::object();
        for (const auto& s : reg_.secs) {
            Json e = Json::object();
            int64_t live = 0;
            for (int64_t i = s.off; i < s.off + s.hi - s.lo; ++i)
                if (w2_->bm.f[static_cast<size_t>(i)] & (CODE | IDIOM | CHAIN)) ++live;
            e["live_code_bytes"] = Json(live);
            e["wiped_bytes"] = Json(wipe_mask_.count_range(s.off, s.off + s.hi - s.lo));
            e["dead_plan_bytes"] = Json(dead_mask_.count_range(s.off, s.off + s.hi - s.lo));
            sec[hex8(s.lo) + "-" + hex8(s.hi)] = e;
        }
        o["sections"] = sec;
    }
    {
        Json w = Json::object();
        w["insns"] = Json(w1.insns);
        w["overlaps"] = Json(w1.overlaps);
        w["undecodable"] = Json(w1.undecodable);
        w["outside"] = Json(w1.outside);
        w["jump_tables"] = Json(w1.jtables);
        o["walk1"] = w;
    }
    o["walk2_idioms_left"] = Json(static_cast<int64_t>(w2_->idioms.size()));
    {
        std::vector<std::string> order;
        std::map<std::string, std::vector<int64_t>> m;
        for (const auto& [s, r] : pl.idiom_res.items())
            if (!r.ok && (*w1.idioms.get(s))->inner.empty()) {
                if (!m.count(r.detail)) order.push_back(r.detail);
                m[r.detail].push_back(s);
            }
        Json j = Json::object();
        for (const std::string& k : order) {
            Json e = Json::object();
            e["count"] = Json(static_cast<int64_t>(m[k].size()));
            int64_t n = 0;
            for (int64_t x : m[k])
                if (w2s_->bm.get(x) & (START | ISTART)) ++n;
            e["reached_in_patched_walk"] = Json(n);
            j[k] = e;
        }
        o["plain_idioms_left_in_place"] = j;
    }
    o["stubs_plan_patches"] = Json(static_cast<int64_t>(stubs_reachable_.size()));
    o["stub_patches_total"] = Json(static_cast<int64_t>(stub_patches_.size()));
    o["routine_entries_reachable_with_stubs"] = reachable_routines();
    o["walk2_stubbed_insns"] = Json(w2s_->insns);
    {
        Json r = Json::object();
        r["count"] = Json(static_cast<int64_t>(rolled_back_.size()));
        Json l = Json::array();
        for (size_t k = 0; k < rolled_back_.size() && k < 300; ++k)
            l.push(Json(hex8(rolled_back_[k].first) + " " + rolled_back_[k].second));
        r["list"] = l;
        o["rolled_back_patches"] = r;
    }
    o["wipe_bytes_withdrawn_after_check"] = Json(unwiped_);
    o["folds"] = fold_report();
    {
        Json d = Json::object();
        int64_t b = 0;
        for (const auto& [r, n] : dead_wipes_) b += n;
        d["ranges"] = Json(static_cast<int64_t>(dead_wipes_.size()));
        d["bytes"] = Json(b);
        d["reloc_drops"] = Json(static_cast<int64_t>(dead_drops_.size()));
        o["dead_plan"] = d;
    }
    o["invariants_union_with_dead_plan"] = inv_union_.to_json(false);
    o["invariants"] = inv_.to_json(false);
    o["sweep"] = sweep_stats_;
    o["sweep_without_stubs"] = sweep_before_;
    return o;
}

}  // namespace flow
