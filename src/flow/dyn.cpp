#include "flow/dyn.h"

#include <windows.h>

#include <stdexcept>
#include <string>

namespace flow {

namespace {

std::wstring exe_dir() {
    wchar_t buf[MAX_PATH * 4];
    const DWORD n = GetModuleFileNameW(nullptr, buf, static_cast<DWORD>(std::size(buf)));
    std::wstring s(buf, n);
    const size_t k = s.find_last_of(L"\\/");
    return k == std::wstring::npos ? std::wstring() : s.substr(0, k + 1);
}

HMODULE load(const wchar_t* name) {
    HMODULE h = LoadLibraryW((exe_dir() + name).c_str());
    if (!h) h = LoadLibraryW(name);
    if (!h) {
        std::string n;
        for (const wchar_t* p = name; *p; ++p) n += static_cast<char>(*p);
        throw std::runtime_error("cannot load " + n + " (it must sit next to mwdec.exe)");
    }
    return h;
}

template <class F> void bind(HMODULE h, F& f, const char* name) {
    FARPROC p = GetProcAddress(h, name);
    if (!p) throw std::runtime_error(std::string("missing export ") + name);
    f = reinterpret_cast<F>(reinterpret_cast<void*>(p));
}

}  // namespace

const CsApi& cs() {
    static const CsApi api = [] {
        CsApi a;
        HMODULE h = load(L"capstone.dll");
        bind(h, a.open, "cs_open");
        bind(h, a.close, "cs_close");
        bind(h, a.option, "cs_option");
        bind(h, a.malloc_, "cs_malloc");
        bind(h, a.free_, "cs_free");
        bind(h, a.disasm_iter, "cs_disasm_iter");
        bind(h, a.regs_access, "cs_regs_access");
        bind(h, a.reg_name, "cs_reg_name");
        bind(h, a.version, "cs_version");
        return a;
    }();
    return api;
}

const UcApi& uc() {
    static const UcApi api = [] {
        UcApi a;
        HMODULE h = load(L"unicorn.dll");
        bind(h, a.open, "uc_open");
        bind(h, a.close, "uc_close");
        bind(h, a.mem_map, "uc_mem_map");
        bind(h, a.mem_write, "uc_mem_write");
        bind(h, a.mem_read, "uc_mem_read");
        bind(h, a.reg_write, "uc_reg_write");
        bind(h, a.reg_read, "uc_reg_read");
        bind(h, a.hook_add, "uc_hook_add");
        bind(h, a.hook_del, "uc_hook_del");
        bind(h, a.emu_start, "uc_emu_start");
        bind(h, a.emu_stop, "uc_emu_stop");
        bind(h, a.version, "uc_version");
        return a;
    }();
    return api;
}

}  // namespace flow
