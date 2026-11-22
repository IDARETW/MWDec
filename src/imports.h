// The two import address tables.
//
// The PE import directory describes a table in a section the protection
// added (.idata); that is the one the Windows loader fills in, and most of
// the game's call sites were rewritten to use it. The original table at the
// start of .rdata is still there, and about a tenth of the call sites still
// go through it, but no directory entry names it and the loader never
// touches it. The third start-up routine keeps it alive: it copies every
// resolved pointer from the loader's table to the original one, one run per
// imported DLL, driven by two parallel range lists.
//
// A static image never runs that routine, so a disassembler shows those
// call sites going through a table of anonymous pointers. read_imports()
// decodes the two lists and names every slot of both tables.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "pe.h"
#include "profile.h"

namespace mwdec {

struct ImportEntry {
    uint32_t loader_slot = 0;  // RVA of the slot the loader fills
    uint32_t alias_slot = 0;   // RVA of its copy in the original table, or 0
    std::string dll;
    std::string name;          // or "#ordinal"
};

struct ImportTables {
    unsigned descriptors = 0;  // import descriptors in the directory
    unsigned aliased = 0;      // descriptors whose table is copied
    std::vector<ImportEntry> entries;
    std::vector<std::string> unaliased;  // DLLs with no copy (the protection's own)
    std::vector<uint32_t> aliased_tables;  // FirstThunk of each descriptor that has a copy
};

// Run after the code layers: the range lists live in encrypted code.
ImportTables read_imports(const Image& im, const ImportProfile& p);

std::string imports_tsv(const ImportTables& r);

// Removes the import descriptors that have no copy in the original table
// (the protection's own imports), together with their name table, slots and
// strings. `tables` must have been read before any plan was applied (the
// lists it comes from live in code that a plan may wipe). Refuses, and
// returns 0, unless they are the last descriptors and no code outside
// `wiped_bits` still refers to their slots. `refs_left` receives the number
// of such references found.
unsigned drop_protection_imports(Image& im, const ImportTables& tables,
                                 const std::vector<uint8_t>& wiped_bits, uint64_t& refs_left);

}  // namespace mwdec
