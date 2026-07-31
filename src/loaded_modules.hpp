#pragma once

#include "hdllib/hdllib.h"

#include <cstdint>
#include <string>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

namespace hdl {

/* In-process registry of module-list DLLs loaded into this process (not hdllib itself). */
void TrackLoadedModule(const wchar_t* dll_path, uint64_t base);
void UntrackLoadedModule(const wchar_t* dll_path);

struct TrackedModule {
    std::wstring path;
    uint64_t base = 0;
};

std::vector<TrackedModule> EnumTrackedModules();

/* FreeLibrary each tracked module except `self` (typically hdllib). Clears the registry. */
HdlStatus UnloadTrackedExcept(HMODULE self);

HMODULE SelfModule();

}  // namespace hdl
