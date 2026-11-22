// Lazy binding of capstone.dll and unicorn.dll (the same builds the Python
// tools use, copied next to mwdec.exe by CMake). Only `mwdec flow` needs
// them; nothing is loaded until the first call to cs() or uc().
#pragma once

#include <capstone/capstone.h>
#include <unicorn/unicorn.h>

namespace flow {

struct CsApi {
    cs_err (*open)(cs_arch, cs_mode, csh*) = nullptr;
    cs_err (*close)(csh*) = nullptr;
    cs_err (*option)(csh, cs_opt_type, size_t) = nullptr;
    cs_insn* (*malloc_)(csh) = nullptr;
    void (*free_)(cs_insn*, size_t) = nullptr;
    bool (*disasm_iter)(csh, const uint8_t**, size_t*, uint64_t*, cs_insn*) = nullptr;
    cs_err (*regs_access)(csh, const cs_insn*, cs_regs, uint8_t*, cs_regs, uint8_t*) = nullptr;
    const char* (*reg_name)(csh, unsigned int) = nullptr;
    unsigned int (*version)(int*, int*) = nullptr;
};

struct UcApi {
    uc_err (*open)(uc_arch, uc_mode, uc_engine**) = nullptr;
    uc_err (*close)(uc_engine*) = nullptr;
    uc_err (*mem_map)(uc_engine*, uint64_t, uint64_t, uint32_t) = nullptr;
    uc_err (*mem_write)(uc_engine*, uint64_t, const void*, uint64_t) = nullptr;
    uc_err (*mem_read)(uc_engine*, uint64_t, void*, uint64_t) = nullptr;
    uc_err (*reg_write)(uc_engine*, int, const void*) = nullptr;
    uc_err (*reg_read)(uc_engine*, int, void*) = nullptr;
    uc_err (*hook_add)(uc_engine*, uc_hook*, int, void*, void*, uint64_t, uint64_t, ...) = nullptr;
    uc_err (*hook_del)(uc_engine*, uc_hook) = nullptr;
    uc_err (*emu_start)(uc_engine*, uint64_t, uint64_t, uint64_t, size_t) = nullptr;
    uc_err (*emu_stop)(uc_engine*) = nullptr;
    unsigned int (*version)(unsigned int*, unsigned int*) = nullptr;
};

// Throws std::runtime_error when the DLL or a function is missing.
const CsApi& cs();
const UcApi& uc();

}  // namespace flow
