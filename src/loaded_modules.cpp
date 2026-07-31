#include "loaded_modules.hpp"

#include "inject/common.hpp"
#include "log.hpp"

#include <mutex>
#include <unordered_map>
#include <utility>

namespace hdl {
namespace {

std::mutex g_mu;
std::unordered_map<std::wstring, uint64_t> g_tracked;

bool IsSelfPath(const wchar_t* path) {
    if (!path || !path[0]) {
        return false;
    }
    HMODULE self = SelfModule();
    if (!self) {
        return false;
    }
    wchar_t self_path[MAX_PATH];
    if (!GetModuleFileNameW(self, self_path, MAX_PATH)) {
        return false;
    }
    return inject::PathsEqual(self_path, path);
}

}  // namespace

HMODULE SelfModule() {
    HMODULE mod = nullptr;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       reinterpret_cast<LPCWSTR>(&SelfModule), &mod);
    return mod;
}

void TrackLoadedModule(const wchar_t* dll_path, uint64_t base) {
    if (!dll_path || !dll_path[0] || !base) {
        return;
    }
    const std::wstring full = inject::NormalizePath(dll_path);
    if (full.empty() || IsSelfPath(full.c_str())) {
        return;
    }
    std::lock_guard<std::mutex> lock(g_mu);
    g_tracked[full] = base;
    HDL_LOG_INFO("Tracked loaded module %ls @ 0x%llX", full.c_str(),
                 static_cast<unsigned long long>(base));
}

void UntrackLoadedModule(const wchar_t* dll_path) {
    if (!dll_path || !dll_path[0]) {
        return;
    }
    const std::wstring full = inject::NormalizePath(dll_path);
    if (full.empty()) {
        return;
    }
    std::lock_guard<std::mutex> lock(g_mu);
    g_tracked.erase(full);
}

std::vector<TrackedModule> EnumTrackedModules() {
    std::lock_guard<std::mutex> lock(g_mu);
    std::vector<TrackedModule> out;
    out.reserve(g_tracked.size());
    for (const auto& kv : g_tracked) {
        TrackedModule m;
        m.path = kv.first;
        m.base = kv.second;
        out.push_back(std::move(m));
    }
    return out;
}

HdlStatus UnloadTrackedExcept(HMODULE self) {
    std::vector<std::pair<std::wstring, uint64_t>> entries;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        entries.reserve(g_tracked.size());
        for (const auto& kv : g_tracked) {
            entries.emplace_back(kv.first, kv.second);
        }
        g_tracked.clear();
    }

    HdlStatus worst = HDL_OK;
    for (const auto& e : entries) {
        const uint64_t base = inject::FindModuleBaseByPath(GetCurrentProcessId(), e.first.c_str());
        if (!base) {
            continue;
        }
        HMODULE mod = reinterpret_cast<HMODULE>(static_cast<uintptr_t>(base));
        if (self && mod == self) {
            continue;
        }
        /* Single FreeLibrary — do not drain other holders' refcounts (system DLLs). */
        if (!::FreeLibrary(mod)) {
            HDL_LOG_ERROR("UnloadTrackedExcept FreeLibrary failed for %ls: %lu", e.first.c_str(),
                          GetLastError());
            worst = HDL_E_FAILED;
        } else {
            HDL_LOG_INFO("Unloaded tracked module %ls", e.first.c_str());
        }
    }
    return worst;
}

}  // namespace hdl
