// mwdec: static decryption of the Arxan-protected Modern Warfare (2019)
// executable. Nothing here loads, maps for execution, or runs the game.
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <exception>
#include <map>
#include <string>
#include <thread>
#include <vector>

#include "autoboot.h"
#include "bootstrap.h"
#include "imports.h"
#include "pe.h"
#include "plan.h"
#include "profile.h"
#include "strings.h"
#include "verify.h"
#include "writerkey.h"
#include "writers.h"
#include "flow/boot.h"
#include "flow/junk.h"
#include "flow/pipeline.h"
#include "flow/tables.h"
#include "flow/writers_find.h"

using namespace mwdec;

namespace {

struct Args {
    std::string command, exe;
    std::map<std::string, std::string> opt;
    bool has(const std::string& k) const { return opt.count(k) != 0; }
    std::string get(const std::string& k, const std::string& d = "") const {
        auto it = opt.find(k);
        return it == opt.end() ? d : it->second;
    }
};

const char* const kUsage =
    "mwdec - static decryption of the Arxan-protected Modern Warfare (2019) executable\n"
    "\n"
    "  mwdec info    <exe>                      what is encrypted, and with what\n"
    "  mwdec decrypt <exe> -o <out.exe>         write a decrypted copy\n"
    "  mwdec strings <exe> -o <strings.tsv>     list the encrypted string blobs, decrypted\n"
    "  mwdec imports <exe> -o <imports.tsv>     name every slot of both import tables\n"
    "  mwdec verify  <exe> --dump <dump.exe>    decrypt in memory, compare with a memory dump\n"
    "  mwdec findkey <image> --stash RVA [--bytes N]\n"
    "                                           a writer's key and encoding, from its stash\n"
    "                                           (the image must have its bootstrap layer off)\n"
    "  mwdec export  <exe> -o <clean.exe> --plan a.plan [--plan b.plan ...]\n"
    "                                           decrypt, then apply removal plans and\n"
    "                                           write an image without the protection\n"
    "  mwdec remove  <exe> -o <clean.exe> [--work DIR] [--unlock-sections] [--full] [--keep-work]\n"
    "                                           the whole removal in one process, from the\n"
    "                                           shipped file alone (tools/remove_build.py's steps);\n"
    "                                           --full adds the report-only walks and the proofs\n"
    "  mwdec flow    <decrypted.exe> -o flow.plan [--dead-plan P] [--stubs-out P]\n"
    "                [--routines R.json] [--keep-plan P ...] [--stub-plan P ...]\n"
    "                [--report R.json] [--live L.npy] [--starts-out S.txt]\n"
    "                                           control-flow plans (tools/devirt_flow.py in C++;\n"
    "                                           needs capstone.dll and unicorn.dll beside mwdec.exe)\n"
    "\n"
    "options\n"
    "  --plan <file>                        export: a patch plan from tools/devirt_*.py;\n"
    "                                       repeat to apply several, in order\n"
    "  --unlock-sections                    export: mark every section RWX in the headers,\n"
    "                                       as the protection did at run time\n"
    "  --bootstrap KEY,IV,RANGES[,ROUNDS]   RVAs (hex) of the layer-1 key, IV and range\n"
    "                                       list; without it, and without a profile, they\n"
    "                                       are found in the file\n"
    "  --no-profile                         ignore the built-in profile for this build\n"
    "                                       (layer 1 only, parameters found in the file)\n"
    "  --writers <table.tsv>                the layer-2 writer table to use, from\n"
    "                                       tools/find_writers.py (replaces the built-in one)\n"
    "  --layer1-only                        decrypt, verify: stop after the bootstrap layer\n"
    "  --keep-strings                       decrypt: leave the string blobs encrypted\n"
    "  --runs-out <file.tsv>                verify: write every differing run\n"
    "  --top N                              verify: differing runs to print (default 20)\n";

bool flag_takes_value(const std::string& k) {
    return k == "-o" || k == "--dump" || k == "--bootstrap" || k == "--runs-out" || k == "--top" ||
           k == "--plan" || k == "--stash" || k == "--bytes" || k == "--writers" || k == "--work";
}

Args parse(int argc, char** argv) {
    Args a;
    for (int i = 1; i < argc; ++i) {
        const std::string s = argv[i];
        if (!s.empty() && s[0] == '-') {
            if (flag_takes_value(s)) {
                if (i + 1 >= argc) throw std::runtime_error("missing value for " + s);
                if (s == "--plan" && a.opt.count(s))  // repeatable: keep them all, in order
                    a.opt[s] += std::string("|") + argv[++i];
                else
                    a.opt[s] = argv[++i];
            } else {
                a.opt[s] = "1";
            }
        } else if (a.command.empty()) {
            a.command = s;
        } else if (a.exe.empty()) {
            a.exe = s;
        } else {
            throw std::runtime_error("unexpected argument " + s);
        }
    }
    return a;
}

double entropy(const uint8_t* p, size_t n) {
    if (!n) return 0;
    uint64_t h[256]{};
    for (size_t i = 0; i < n; ++i) ++h[p[i]];
    double e = 0;
    for (uint64_t c : h)
        if (c) {
            const double f = static_cast<double>(c) / static_cast<double>(n);
            e -= f * std::log2(f);
        }
    return e;
}

BuildProfile profile_for(const Image& im, const Args& a) {
    BuildProfile p;
    if (!a.has("--no-profile"))
        if (auto found = find_profile(im)) p = *found;
    if (a.has("--bootstrap")) {
        unsigned long v[4] = {0, 0, 0, 64};
        const std::string s = a.get("--bootstrap");
        const int n = std::sscanf(s.c_str(), "%lx,%lx,%lx,%lu", &v[0], &v[1], &v[2], &v[3]);
        if (n < 3) throw std::runtime_error("--bootstrap wants KEY,IV,RANGES[,ROUNDS]");
        p.bootstrap.key_rva = v[0];
        p.bootstrap.iv_rva = v[1];
        p.bootstrap.ranges_rva = v[2];
        p.bootstrap.rounds = static_cast<unsigned>(v[3]);
        if (p.name.empty()) p.name = "(command line)";
    }
    if (p.name.empty()) {
        // No profile and nothing on the command line: read the three
        // bootstrap parameters out of the file (autoboot.h). That gives
        // layer 1 and nothing else; the writer table stays empty.
        AutoBootReport rep;
        if (auto found = find_bootstrap(im, &rep)) {
            p.bootstrap = *found;
            p.name = "(no profile; bootstrap parameters found in the file)";
            std::printf("no profile for this build. Found in the file: key %08X, starting block %08X, "
                        "range list %08X, %u cycles\n  (%zu islands, %zu x %zu pairs tried, best %.1f%% "
                        "common code bytes, next %.1f%%)%s\n",
                        found->key_rva, found->iv_rva, found->ranges_rva, found->rounds, rep.islands,
                        rep.key_candidates, rep.iv_candidates, 100 * rep.best, 100 * rep.second,
                        rep.from_code ? "\n  key and starting block read from the cipher's own set-up code" : "");
        } else {
            throw std::runtime_error("no profile for this build, and no bootstrap layer found in the file: " +
                                     rep.why);
        }
    }
    // A writer table from a file replaces the built-in one (or supplies
    // layer 2 for a build that has none built in).
    if (a.has("--writers")) p.writers = load_writer_table(a.get("--writers"));
    return p;
}

// The two import-copy lists: the profile's, or, for a build without one,
// found among the image's range lists (autoboot.h). Call after decrypting:
// the lists are inside encrypted code.
ImportProfile imports_for(const Image& im, const BuildProfile& p) {
    if (p.imports.src_ranges_rva && p.imports.dst_ranges_rva) return p.imports;
    if (auto found = find_import_lists(im)) {
        std::printf("import copy lists found in the image: %08X (loader's table), %08X (original table)\n",
                    found->src_ranges_rva, found->dst_ranges_rva);
        return *found;
    }
    throw std::runtime_error("no profile for this build, and the two import copy lists were not found in the image");
}

struct Decrypted {
    BootstrapResult boot;
    std::vector<WriterResult> writers;
    std::vector<uint8_t> touched;  // bitmap over RVAs: layer-1 ranges
    std::vector<uint8_t> written;  // bitmap over RVAs: code written by layer 2
};

void mark(std::vector<uint8_t>& bits, uint32_t rva, uint32_t n) {
    for (uint32_t a = rva; a < rva + n; ++a) bits[a >> 3] |= static_cast<uint8_t>(1u << (a & 7));
}

Decrypted decrypt_all(Image& im, const BuildProfile& p, bool apply, bool layer2 = true) {
    Decrypted d;
    d.touched.assign(im.mem.size() / 8 + 1, 0);
    d.written.assign(im.mem.size() / 8 + 1, 0);
    const auto t0 = std::chrono::steady_clock::now();
    d.boot = run_bootstrap(im, p.bootstrap, apply);
    for (const Range& r : d.boot.list.ranges) mark(d.touched, r.rva, r.size);
    const double s =
        std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    std::printf("layer 1 (bootstrap, XTEA-%u output feedback)\n", p.bootstrap.rounds);
    std::printf("  key   @ %08X  %08X %08X %08X %08X\n", p.bootstrap.key_rva, d.boot.key[0],
                d.boot.key[1], d.boot.key[2], d.boot.key[3]);
    std::printf("  iv    @ %08X  %08X %08X\n", p.bootstrap.iv_rva, d.boot.iv[0], d.boot.iv[1]);
    std::printf("  list  @ %08X  %zu bytes encoded, %zu ranges, %llu bytes covered\n",
                p.bootstrap.ranges_rva, d.boot.list.encoded_size, d.boot.list.ranges.size(),
                static_cast<unsigned long long>(d.boot.list.total));
    if (apply)
        std::printf("  %llu keystream blocks in %.1f s, final state %08X %08X\n",
                    static_cast<unsigned long long>(d.boot.blocks), s, d.boot.final_state[0],
                    d.boot.final_state[1]);
    if (!apply || !layer2 || p.writers.empty()) return d;

    d.writers = apply_writers(im, p.writers, d.written);
    uint64_t stash_bytes = 0, code_bytes = 0, code_changed = 0;
    size_t stash_writers = 0, code_ranges = 0;
    for (const WriterResult& w : d.writers) {
        if (w.writes_stash) {
            ++stash_writers;
            stash_bytes += w.bytes;
        } else {
            code_bytes += w.bytes;
            code_changed += w.changed;
            code_ranges += w.ranges;
        }
    }
    std::printf("layer 2 (writers)\n");
    std::printf("  %zu writers prepare other writers' stashes   %llu bytes\n", stash_writers,
                static_cast<unsigned long long>(stash_bytes));
    std::printf("  %zu writers produce code                     %llu bytes in %zu ranges, %llu changed\n",
                d.writers.size() - stash_writers, static_cast<unsigned long long>(code_bytes),
                code_ranges, static_cast<unsigned long long>(code_changed));
    return d;
}

void print_sections(const Image& im, const Decrypted* d) {
    std::printf("\n  #  name      rva       vsize     flags  entropy");
    if (d) std::printf("   layer-1 bytes        share");
    std::printf("\n");
    for (const Section& s : im.sections) {
        const size_t n = std::min<size_t>(s.vsize, s.rsize);
        std::printf("  %-2d %-8s  %08X  %08X  %c%c%c    %.3f", s.index, s.name.c_str(), s.rva,
                    s.vsize, (s.chars & 0x40000000u) ? 'r' : '-', s.writable() ? 'w' : '-',
                    s.executable() ? 'x' : '-', entropy(im.mem.data() + s.rva, n));
        if (d) {
            uint64_t c = 0;
            for (const Range& r : d->boot.list.ranges)
                if (s.contains(r.rva)) c += r.size;
            std::printf("   %12llu  %10.2f%%", static_cast<unsigned long long>(c),
                        s.vsize ? 100.0 * static_cast<double>(c) / s.vsize : 0.0);
        }
        std::printf("\n");
    }
}

int cmd_info(const Args& a) {
    Image im = Image::load(a.exe);
    const BuildProfile p = profile_for(im, a);
    std::printf("%s\n  profile       %s\n  image base    %llX\n  size of image %08X\n"
                "  entry point   %08X\n",
                a.exe.c_str(), p.name.c_str(), static_cast<unsigned long long>(im.image_base),
                im.size_of_image, im.entry_rva);
    const auto tls = im.tls_callbacks();
    std::printf("  TLS callbacks %zu:", tls.size());
    for (uint32_t t : tls) std::printf(" %08X", t);
    std::printf("\n  relocations   %zu DIR64 sites\n\n", im.relocations().size());
    const Decrypted d = decrypt_all(im, p, false);
    print_sections(im, &d);
    return 0;
}

int cmd_decrypt(const Args& a) {
    if (!a.has("-o")) throw std::runtime_error("decrypt needs -o <out.exe>");
    Image im = Image::load(a.exe);
    const BuildProfile p = profile_for(im, a);
    std::printf("%s: %s\n\n", a.exe.c_str(), p.name.c_str());
    const Decrypted d = decrypt_all(im, p, true, !a.has("--layer1-only"));
    print_sections(im, &d);
    if (!a.has("--keep-strings")) {
        const std::vector<XorBlob> blobs = find_xor_blobs(im);
        patch_xor_blobs(im, blobs);
        std::printf("\nstring blobs: %zu decrypted in place\n", blobs.size());
    }
    im.save(a.get("-o"));
    std::printf("\nwrote %s\n", a.get("-o").c_str());
    return 0;
}

int cmd_export(const Args& a) {
    if (!a.has("-o")) throw std::runtime_error("export needs -o <clean.exe>");
    if (!a.has("--plan")) throw std::runtime_error("export needs at least one --plan");
    Image im = Image::load(a.exe);
    const BuildProfile p = profile_for(im, a);
    std::printf("%s: %s\n\n", a.exe.c_str(), p.name.c_str());
    const Decrypted d = decrypt_all(im, p, true, true);

    const std::vector<XorBlob> blobs = find_xor_blobs(im);
    patch_xor_blobs(im, blobs);
    std::printf("strings\n  %zu blobs decrypted in place\n", blobs.size());

    // Read before any plan runs: the lists live in code a plan may wipe.
    const ImportTables tables = read_imports(im, imports_for(im, p));

    PlanStats st;
    std::vector<uint8_t> wiped;
    std::printf("removal plans\n");
    std::string list = a.get("--plan");
    std::vector<Plan> plans;
    for (size_t pos = 0; pos <= list.size();) {
        const size_t bar = std::min(list.find('|', pos), list.size());
        const std::string path = list.substr(pos, bar - pos);
        pos = bar + 1;
        if (path.empty()) continue;
        plans.push_back(Plan::load(path));
        std::printf("  %s: %zu patches, %zu relocation drops, %zu wipes\n", path.c_str(),
                    plans.back().patches.size(), plans.back().drop_relocs.size(),
                    plans.back().wipes.size());
    }
    apply_plans(im, plans, st, wiped);
    settle_relocations(im, wiped, st);
    if (st.patch_conflicts)
        std::printf("  WARNING: %llu bytes are patched to different values by two plans\n",
                    static_cast<unsigned long long>(st.patch_conflicts));
    if (st.patched_over_wipes)
        std::printf("  %llu bytes are wiped by one plan and patched by another; the patch stands\n",
                    static_cast<unsigned long long>(st.patched_over_wipes));
    for (unsigned k = 1; k < 8; ++k)
        if (st.patches[k])
            std::printf("  %-7s %8llu patches  %10llu bytes\n", plan_kind_name(k),
                        static_cast<unsigned long long>(st.patches[k]),
                        static_cast<unsigned long long>(st.patch_bytes[k]));
    std::printf("  wiped   %8llu ranges   %10llu bytes (%llu ranges refused)\n",
                static_cast<unsigned long long>(st.wiped_ranges),
                static_cast<unsigned long long>(st.wiped_bytes),
                static_cast<unsigned long long>(st.wipes_refused));
    std::printf("  relocations: %llu dropped by plan, %llu inside wiped bytes, %llu no longer an address; %llu left\n",
                static_cast<unsigned long long>(st.relocs_dropped_listed),
                static_cast<unsigned long long>(st.relocs_dropped_in_wipes),
                static_cast<unsigned long long>(st.relocs_dropped_dangling),
                static_cast<unsigned long long>(st.relocs_left));

    std::printf("PE\n");
    uint64_t refs = 0;
    const unsigned dropped = drop_protection_imports(im, tables, wiped, refs);
    if (dropped)
        std::printf("  %u import descriptor(s) of the protection removed\n", dropped);
    else
        std::printf("  the protection's import descriptor is kept (%llu references to its slots remain)\n",
                    static_cast<unsigned long long>(refs));
    if (const uint32_t gone = prune_exception_directory(im, wiped))
        std::printf("  %u exception-directory records removed (their code was wiped), %u left\n", gone,
                    im.dirs[3].size / 12);
    if (im.dirs[4].rva) {
        im.set_dir(4, 0, 0);
        std::printf("  certificate table dropped (the signature no longer matches the file)\n");
    }
    if (a.has("--unlock-sections")) {
        // What the protection's first start-up routine did at run time:
        // every section readable, writable and executable.
        for (Section& s : im.sections) {
            s.chars |= 0xE0000000u;
            std::memcpy(im.mem.data() + s.header + 36, &s.chars, 4);
        }
        std::printf("  every section marked readable, writable and executable\n");
    }
    print_sections(im, &d);
    im.save(a.get("-o"), true);
    std::printf("\nwrote %s (checksum recomputed)\n", a.get("-o").c_str());
    return 0;
}

int cmd_strings(const Args& a) {
    Image im = Image::load(a.exe, false);
    const BuildProfile p = profile_for(im, a);
    std::printf("%s: %s\n\n", a.exe.c_str(), p.name.c_str());
    decrypt_all(im, p, true);  // code references need decrypted code
    const std::vector<XorBlob> blobs = find_xor_blobs(im);
    size_t bytes = 0, referenced = 0;
    for (const XorBlob& b : blobs) bytes += b.length, referenced += b.ref_offsets != 0;
    std::printf("\nstring blobs: %zu (%zu bytes of text), %zu referenced from code\n", blobs.size(),
                bytes, referenced);
    if (a.has("-o")) {
        std::ofstream f(a.get("-o"), std::ios::binary);
        const std::string t = xor_blobs_tsv(blobs);
        f.write(t.data(), static_cast<std::streamsize>(t.size()));
        std::printf("wrote %s\n", a.get("-o").c_str());
    } else {
        for (size_t i = 0; i < blobs.size() && i < 20; ++i)
            std::printf("  %08X  %s\n", blobs[i].rva, blobs[i].text.c_str());
    }
    return 0;
}

int cmd_imports(const Args& a) {
    Image im = Image::load(a.exe, false);
    const BuildProfile p = profile_for(im, a);
    std::printf("%s: %s\n\n", a.exe.c_str(), p.name.c_str());
    decrypt_all(im, p, true);  // the copy lists are inside encrypted code
    const ImportTables r = read_imports(im, imports_for(im, p));
    std::printf("\nimports: %u descriptors, %zu slots; %u descriptors have a copy in the original table\n",
                r.descriptors, r.entries.size(), r.aliased);
    for (const std::string& dll : r.unaliased)
        std::printf("  no copy (loader's table only): %s\n", dll.c_str());
    if (a.has("-o")) {
        std::ofstream f(a.get("-o"), std::ios::binary);
        const std::string t = imports_tsv(r);
        f.write(t.data(), static_cast<std::streamsize>(t.size()));
        std::printf("wrote %s\n", a.get("-o").c_str());
    }
    return 0;
}

int cmd_verify(const Args& a) {
    if (!a.has("--dump")) throw std::runtime_error("verify needs --dump <dump.exe>");
    Image im = Image::load(a.exe);
    const BuildProfile p = profile_for(im, a);
    std::printf("%s: %s\n\n", a.exe.c_str(), p.name.c_str());
    const bool layer2 = !a.has("--layer1-only");
    const Decrypted d = decrypt_all(im, p, true, layer2);
    const Image dump = Image::load(a.get("--dump"), false);
    VerifyResult v = verify_against_dump(im, dump, layer2 ? d.written : d.touched);
    std::printf("\nreference dump %s\n  loaded at %llX (displacement %+lld), %llu relocation sites\n",
                a.get("--dump").c_str(),
                static_cast<unsigned long long>(im.image_base + v.delta),
                static_cast<long long>(v.delta), static_cast<unsigned long long>(v.reloc_sites));
    std::printf("\n  #  name      flags  compared      differing     (in a layer)   equal\n");
    for (const SectionDiff& s : v.sections)
        std::printf("  %-2d %-8s  %c%c     %12llu  %12llu  %12llu  %9.5f%%\n", s.section.index,
                    s.section.name.c_str(), s.section.writable() ? 'w' : '-',
                    s.section.executable() ? 'x' : '-',
                    static_cast<unsigned long long>(s.compared),
                    static_cast<unsigned long long>(s.differ),
                    static_cast<unsigned long long>(s.differ_in_mask),
                    s.compared ? 100.0 * static_cast<double>(s.compared - s.differ) / s.compared
                               : 100.0);

    if (a.has("--runs-out")) {
        std::ofstream f(a.get("--runs-out"));
        f << "rva\tsize\tdiffering\tin_layer\tsection\n";
        char line[128];
        for (const DiffRun& r : v.runs) {
            const Section* s = im.section_of(r.rva);
            std::snprintf(line, sizeof line, "%08X\t%u\t%u\t%u\t%d\n", r.rva, r.size, r.differing,
                          r.in_mask, s ? s->index : -1);
            f << line;
        }
        std::printf("\nwrote %zu differing runs to %s\n", v.runs.size(),
                    a.get("--runs-out").c_str());
    }
    std::vector<DiffRun> code;
    for (const DiffRun& r : v.runs) {
        const Section* s = im.section_of(r.rva);
        if (s && s->executable()) code.push_back(r);
    }
    std::sort(code.begin(), code.end(),
              [](const DiffRun& x, const DiffRun& y) { return x.differing > y.differing; });
    const size_t top = std::min<size_t>(code.size(), std::strtoul(a.get("--top", "20").c_str(), nullptr, 10));
    std::printf("\n%zu differing runs in executable sections; largest %zu:\n", code.size(), top);
    for (size_t i = 0; i < top; ++i)
        std::printf("  %08X  extent %-8u differing %-8u in a layer %u\n", code[i].rva, code[i].size,
                    code[i].differing, code[i].in_mask);
    return 0;
}

// The image is read as it is: give it one whose bootstrap layer is already
// off (`decrypt --layer1-only`), since a stash is ciphertext before that.
int cmd_findkey(const Args& a) {
    if (!a.has("--stash")) throw std::runtime_error("findkey needs --stash <RVA, hex>");
    const Image im = Image::load(a.exe, false);
    const uint32_t stash = static_cast<uint32_t>(std::strtoul(a.get("--stash").c_str(), nullptr, 16));
    const size_t n = std::strtoul(a.get("--bytes", "4096").c_str(), nullptr, 10);
    if (!im.in_bounds(stash, n)) throw std::runtime_error("the stash leaves the image");
    const std::vector<KeyCandidate> res = find_writer_keys(im.mem.data() + stash, n);
    std::printf("stash %08X, %zu bytes (the first %zu scored)\n", stash, n, std::min<size_t>(n, 4096));
    for (const KeyCandidate& k : res)
        std::printf("  %-7s key %08X  common code bytes %5.1f%%  (%zu keys of this encoding passed 80 bytes)\n",
                    variant_name(k.variant), k.key, 100 * k.share, k.survivors);
    if (res.empty()) std::printf("  no key of any encoding decodes the first 80 bytes to code\n");
    return 0;
}

// ------------------------------------------------------------- remove --
//
// The whole removal of one build in one process: the shipped file is read
// once, each step hands its image and tables to the next in memory, and the
// tables, plans and reports land in --work (the two intermediate images only
// with --keep-work). Every step is the C++ port of the Python tool that
// tools/remove_build.py ran for it, with the same output byte for byte.
//
// The default leaves out what only feeds a report or a proof: the flow
// pass's report-only walks, the live map, the junk constructs' emulator
// proof. --full puts them back.

double since(std::chrono::steady_clock::time_point t) {
    return std::chrono::duration<double>(std::chrono::steady_clock::now() - t).count();
}

void write_bytes(const std::string& path, const void* p, size_t n) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) throw std::runtime_error("cannot write " + path);
    f.write(static_cast<const char*>(p), static_cast<std::streamsize>(n));
    if (!f) throw std::runtime_error("short write on " + path);
}
void write_bytes(const std::string& path, const std::string& s) { write_bytes(path, s.data(), s.size()); }

mwdec::Plan to_plan(const flow::PlanF& p) {
    mwdec::Plan o;
    for (const auto& x : p.patches) o.patches.push_back({x.rva, x.kind, x.data});
    o.drop_relocs = p.drops;
    for (const auto& [r, n] : p.wipes) o.wipes.push_back({r, n});
    return o;
}

int cmd_remove(const Args& a0) {
    if (!a0.has("-o")) throw std::runtime_error("remove needs -o <clean.exe>");
    Args a = a0;
    a.opt["--no-profile"] = "1";  // everything from the file
    const bool full = a.has("--full"), keep = a.has("--keep-work"), unlock = a.has("--unlock-sections");
    const std::string work = a.get("--work");
    if (!work.empty()) std::filesystem::create_directories(work);
    auto W = [&work](const char* n) { return work + "\\" + n; };
    const auto t_all = std::chrono::steady_clock::now();
    auto t = std::chrono::steady_clock::now();
    auto step = [&t](const char* name) {
        std::printf("step %s %.1f\n", name, since(t));
        std::fflush(stdout);
        t = std::chrono::steady_clock::now();
    };
    auto log = [](const std::string& s) {
        std::printf("%s\n", s.c_str());
        std::fflush(stdout);
    };

    // layer 1, and the import tables from the image as it then stands
    Image im = Image::load(a.exe);
    BuildProfile p = profile_for(im, a);
    std::printf("%s: %s\n\n", a.exe.c_str(), p.name.c_str());
    Decrypted d = decrypt_all(im, p, true, false);
    const ImportTables it1 = read_imports(im, imports_for(im, p));
    const std::string imports = imports_tsv(it1);
    std::printf("\nimports: %u descriptors, %zu slots; %u descriptors have a copy in the original table\n",
                it1.descriptors, it1.entries.size(), it1.aliased);
    if (!work.empty()) write_bytes(W("imports.tsv"), imports);
    if (keep && !work.empty()) im.save(W("layer1.exe"));
    step("layer 1");

    // the writer table, from the layer-1 image
    flow::WritersFound wf;
    {
        flow::FImage l1;
        l1.load_bytes(im.file_bytes(false), "layer1.exe");
        wf = flow::find_writers(l1, log);
    }
    std::printf("sets of ranges that only noise was decoded for: %lld (%lld bytes)\n",
                static_cast<long long>(wf.unsettled_sets), static_cast<long long>(wf.unsettled_bytes));
    if (!work.empty()) write_bytes(W("writers.tsv"), flow::writers_tsv(wf.rows, "layer1.exe"));
    step("writers");

    // layer 2 and the string blobs
    for (const flow::WriterRow& r : wf.rows) {
        WriterProfile w;
        w.routine = static_cast<uint32_t>(r.site);
        w.writes_stash = r.writes_stash;
        w.variant = r.variant == "Xor" ? WriterVariant::Xor : r.variant == "Sub" ? WriterVariant::Sub
                    : r.variant == "XorAuto" ? WriterVariant::XorAuto : WriterVariant::MulRol;
        w.ranges_rva = static_cast<uint32_t>(r.list);
        w.stash_rva = static_cast<uint32_t>(r.stash);
        w.key_rva = static_cast<uint32_t>(r.key);
        p.writers.push_back(w);
    }
    d.writers = apply_writers(im, p.writers, d.written);
    {
        uint64_t stash_bytes = 0, code_bytes = 0, code_changed = 0;
        size_t stash_writers = 0, code_ranges = 0;
        for (const WriterResult& w : d.writers) {
            if (w.writes_stash) {
                ++stash_writers;
                stash_bytes += w.bytes;
            } else {
                code_bytes += w.bytes;
                code_changed += w.changed;
                code_ranges += w.ranges;
            }
        }
        std::printf("layer 2 (writers)\n  %zu writers prepare other writers' stashes   %llu bytes\n"
                    "  %zu writers produce code                     %llu bytes in %zu ranges, %llu changed\n",
                    stash_writers, static_cast<unsigned long long>(stash_bytes), d.writers.size() - stash_writers,
                    static_cast<unsigned long long>(code_bytes), code_ranges,
                    static_cast<unsigned long long>(code_changed));
    }
    const std::vector<XorBlob> blobs = find_xor_blobs(im);
    patch_xor_blobs(im, blobs);
    std::printf("\nstring blobs: %zu decrypted in place\n", blobs.size());
    if (keep && !work.empty()) im.save(W("dec.exe"));
    step("layer 2");

    // the checks, the routine table and the start-up path, from the decrypted image
    flow::ChecksOut ck;
    flow::RoutinesOut rt;
    flow::BootOut bt;
    {
        flow::FImage dec;
        dec.load_bytes(im.file_bytes(false), "dec.exe");
        // the start-up path beside the checks and the routine table: all
        // three only read the image, each with decoders of its own
        double boot_secs = 0;
        std::exception_ptr boot_err;
        std::thread boot([&] {
            try {
                const auto tb = std::chrono::steady_clock::now();
                bt = flow::devirt_boot(dec, imports);
                boot_secs = since(tb);
            } catch (...) {
                boot_err = std::current_exception();
            }
        });
        try {
            ck = flow::find_slot_checks(dec);
            log(ck.line);
            step("checks");
            rt = flow::find_routines(dec, ck.checks, "dec.exe", log);
            step("routines");
        } catch (...) {
            boot.join();
            throw;
        }
        boot.join();
        if (boot_err) std::rethrow_exception(boot_err);
        std::printf("%s\n(the boot plan ran beside the checks and the routine table)\nstep boot plan %.1f\n",
                    bt.plan.summary().c_str(), boot_secs);
        t = std::chrono::steady_clock::now();
    }
    if (!work.empty()) {
        ck.plan.save(W("checks_all.plan"));
        flow::write_text_crlf(W("checks.json"), ck.json.dump(1));
        flow::write_text_crlf(W("routines.json"), rt.json.dump(1));
        rt.stubs.save(W("routine_stubs.plan"));
        rt.bake.save(W("checks.plan"));
        bt.plan.save(W("boot.plan"));
        flow::write_text_crlf(W("boot.json"), bt.report.dump(1));
    }
    if (const flow::Json* tls = bt.report.get("tls"))
        for (const flow::Json& r : tls->items()) {
            const flow::Json* rc = r.get("routines_called");
            const flow::Json* pa = r.get("patched");
            if (rc && rc->as_int() && !(pa && pa->as_bool()))
                throw std::runtime_error("TLS callback " + std::to_string(r.get("index")->as_int()) +
                                         " begins with start-up calls that could not be taken off");
        }

    // the flow pass (the shipped file's bytes are let go while it runs, and
    // read again for the export: they are only the template it writes into)
    flow::PlanF fplan, dplan, splan;
    {
        flow::FImage fi;
        fi.load_bytes(im.file_bytes(false), "dec.exe");
        std::vector<uint8_t>().swap(im.file);
        flow::Pipeline pp(std::move(fi), log, rt.json, {rt.bake, bt.plan}, {rt.stubs});
        pp.skip_report_only = !full;
        pp.run();
        fplan = pp.plan();
        dplan = pp.dead_plan();
        splan = pp.stubs_plan();
        std::printf("%s\ndead plan: %s\nstubs plan: %s\n", fplan.summary().c_str(), dplan.summary().c_str(),
                    splan.summary().c_str());
        if (!work.empty()) {
            fplan.save(W("flow.plan"));
            dplan.save(W("dead.plan"));
            splan.save(W("stubs.plan"));
            write_bytes(W("flow.json"), pp.report().dump(1));
            if (full || keep) {
                const auto ent = pp.starts_out();
                std::string s;
                for (int64_t v : ent) {
                    char b[32];
                    std::snprintf(b, sizeof b, "%llX\r\n", static_cast<unsigned long long>(v));
                    s += b;
                }
                write_bytes(W("starts_folds.txt"), s);
                const auto bits = pp.live_bits();
                flow::save_npy_u8(W("live.npy"), bits.data(), bits.size());
                std::string js = "{\"regions\": [";
                const auto& secs = pp.regions().secs;
                for (size_t k = 0; k < secs.size(); ++k)
                    js += (k ? ", [" : "[") + std::to_string(secs[k].lo) + ", " + std::to_string(secs[k].hi) + ", " +
                          std::to_string(secs[k].off) + "]";
                js += "], \"packbits\": true}";
                write_bytes(W("live.json"), js);
            }
        }
    }
    step("flow plans");
    im.file = read_file(a.exe);

    // the junk constructs, against the decrypted image and the plans above
    flow::JunkOut jk;
    {
        flow::FImage dec;
        dec.load_bytes(im.file_bytes(false), "dec.exe");
        jk = flow::find_junk(dec, {&bt.plan, &rt.bake, &fplan, &dplan, &splan},
                             {"boot.plan", "checks.plan", "flow.plan", "dead.plan", "stubs.plan"}, full ? 300 : 0,
                             !a.has("--junk-no-older"), log);
    }
    if (!work.empty()) {
        jk.plan.save(W("junk.plan"));
        flow::write_text_crlf(W("junk.json"), jk.report.dump(1));
    }
    if (jk.proved_wrong) throw std::runtime_error(std::to_string(jk.proved_wrong) + " junk constructs are not a no-op in the emulator");
    step("junk plan");

    // the export: the plans applied to the decrypted image
    {
        const ImportTables tables = read_imports(im, imports_for(im, p));
        std::vector<Plan> plans;
        for (const flow::PlanF* q : {&bt.plan, &rt.bake, &fplan, &dplan, &splan, &jk.plan}) plans.push_back(to_plan(*q));
        PlanStats st;
        std::vector<uint8_t> wiped;
        std::printf("removal plans\n");
        apply_plans(im, plans, st, wiped);
        settle_relocations(im, wiped, st);
        if (st.patch_conflicts)
            std::printf("  WARNING: %llu bytes are patched to different values by two plans\n",
                        static_cast<unsigned long long>(st.patch_conflicts));
        std::printf("  wiped   %8llu ranges   %10llu bytes (%llu ranges refused)\n",
                    static_cast<unsigned long long>(st.wiped_ranges), static_cast<unsigned long long>(st.wiped_bytes),
                    static_cast<unsigned long long>(st.wipes_refused));
        std::printf("  relocations: %llu dropped by plan, %llu inside wiped bytes, %llu no longer an address; %llu left\n",
                    static_cast<unsigned long long>(st.relocs_dropped_listed),
                    static_cast<unsigned long long>(st.relocs_dropped_in_wipes),
                    static_cast<unsigned long long>(st.relocs_dropped_dangling),
                    static_cast<unsigned long long>(st.relocs_left));
        uint64_t refs = 0;
        const unsigned dropped = drop_protection_imports(im, tables, wiped, refs);
        if (dropped)
            std::printf("  %u import descriptor(s) of the protection removed\n", dropped);
        else
            std::printf("  the protection's import descriptor is kept (%llu references to its slots remain)\n",
                        static_cast<unsigned long long>(refs));
        if (const uint32_t gone = prune_exception_directory(im, wiped))
            std::printf("  %u exception-directory records removed (their code was wiped), %u left\n", gone,
                        im.dirs[3].size / 12);
        if (im.dirs[4].rva) im.set_dir(4, 0, 0);
        const std::string out = a.get("-o");
        {
            const std::vector<uint8_t> fb = im.file_bytes(true);
            write_bytes(out, fb.data(), fb.size());
            std::printf("wrote %s (%zu bytes)\n", out.c_str(), fb.size());
        }
        step("export");
        if (unlock) {
            for (Section& s : im.sections) {
                s.chars |= 0xE0000000u;
                std::memcpy(im.mem.data() + s.header + 36, &s.chars, 4);
            }
            std::string u = out;
            const size_t dot = u.find_last_of('.');
            u = (dot == std::string::npos ? u : u.substr(0, dot)) + ".unlocked.exe";
            const std::vector<uint8_t> fb = im.file_bytes(true);
            write_bytes(u, fb.data(), fb.size());
            std::printf("wrote %s (every section readable, writable and executable)\n", u.c_str());
            step("export, sections unlocked");
        }
    }
    PROCESS_MEMORY_COUNTERS pmc{};
    GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof pmc);
    std::printf("remove: %.1f s, peak working set %.2f GB, peak commit %.2f GB\n", since(t_all),
                pmc.PeakWorkingSetSize / 1073741824.0, pmc.PeakPagefileUsage / 1073741824.0);
    return 0;
}

}  // namespace

namespace flow {
int cmd_flow(int argc, char** argv);
int cmd_writers(int argc, char** argv);
int cmd_tables(int argc, char** argv);
int cmd_boot(int argc, char** argv);
int cmd_junk(int argc, char** argv);
}

int main(int argc, char** argv) {
    try {
        if (argc >= 2 && std::string(argv[1]) == "flow") return flow::cmd_flow(argc, argv);
        if (argc >= 2 && std::string(argv[1]) == "writers") return flow::cmd_writers(argc, argv);
        if (argc >= 2 && std::string(argv[1]) == "tables") return flow::cmd_tables(argc, argv);
        if (argc >= 2 && std::string(argv[1]) == "boot") return flow::cmd_boot(argc, argv);
        if (argc >= 2 && std::string(argv[1]) == "junk") return flow::cmd_junk(argc, argv);
        const Args a = parse(argc, argv);
        if (a.command.empty() || a.exe.empty() || a.has("-h") || a.has("--help")) {
            std::fputs(kUsage, stdout);
            return a.command.empty() ? 1 : 0;
        }
        if (a.command == "info") return cmd_info(a);
        if (a.command == "decrypt") return cmd_decrypt(a);
        if (a.command == "export") return cmd_export(a);
        if (a.command == "strings") return cmd_strings(a);
        if (a.command == "imports") return cmd_imports(a);
        if (a.command == "verify") return cmd_verify(a);
        if (a.command == "findkey") return cmd_findkey(a);
        if (a.command == "remove") return cmd_remove(a);
        throw std::runtime_error("unknown command " + a.command);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "mwdec: %s\n", e.what());
        return 2;
    }
}
