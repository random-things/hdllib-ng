#pragma once

#include "hdllib/hdllib.h"

#include <cstdint>

namespace hdl {

HdlStatus InjectDll(uint32_t pid, const wchar_t* dll_path, uint64_t* out_base);

HdlStatus InjectDllEx(
    uint32_t pid,
    const wchar_t* dll_path,
    int method,
    const wchar_t* exe_path_or_null,
    const char* hook_export_or_null,
    uint32_t* out_pid,
    uint64_t* out_base);

HdlStatus UnloadDll(uint32_t pid, const wchar_t* dll_path, int reload, uint64_t* out_base);

}  // namespace hdl
