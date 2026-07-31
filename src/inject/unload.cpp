#include "inject/common.hpp"
#include "inject/techniques.hpp"

#include "hdllib/hdllib.h"
#include "hdllib/pipe_name.h"
#include "protocol.hpp"

#include <cstring>
#include <vector>

namespace hdl {
namespace inject {
namespace {

HMODULE ModuleContaining(const void* addr) {
    HMODULE mod = nullptr;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       reinterpret_cast<LPCWSTR>(addr), &mod);
    return mod;
}

bool PipeReadExact(HANDLE pipe, void* buf, DWORD size) {
    uint8_t* p = static_cast<uint8_t*>(buf);
    DWORD remaining = size;
    while (remaining) {
        DWORD got = 0;
        if (!ReadFile(pipe, p, remaining, &got, nullptr) || got == 0) {
            return false;
        }
        p += got;
        remaining -= got;
    }
    return true;
}

bool PipeWriteExact(HANDLE pipe, const void* buf, DWORD size) {
    const uint8_t* p = static_cast<const uint8_t*>(buf);
    DWORD remaining = size;
    while (remaining) {
        DWORD wrote = 0;
        if (!WriteFile(pipe, p, remaining, &wrote, nullptr) || wrote == 0) {
            return false;
        }
        p += wrote;
        remaining -= wrote;
    }
    return true;
}

/* Ask the in-target helper to restore instrumentation before FreeLibrary (hdllib only). */
bool TryPrepareRemoteShutdown(DWORD pid, uint64_t module_base, uint32_t flags) {
    bool is_helper = false;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32W me{};
        me.dwSize = sizeof(me);
        if (Module32FirstW(snap, &me)) {
            do {
                if (reinterpret_cast<uint64_t>(me.modBaseAddr) == module_base) {
                    HMODULE probe =
                        LoadLibraryExW(me.szExePath, nullptr, DONT_RESOLVE_DLL_REFERENCES);
                    if (probe) {
                        if (GetProcAddress(probe, "HdlShutdown") ||
                            GetProcAddress(probe, "HdlShutdownEx")) {
                            is_helper = true;
                        }
                        FreeLibrary(probe);
                    }
                    break;
                }
            } while (Module32NextW(snap, &me));
        }
        CloseHandle(snap);
    }
    if (!is_helper) {
        return false;
    }

    wchar_t name[128];
    if (HdlFormatPipeName(pid, name, 128) != 0) {
        return false;
    }
    HANDLE pipe = CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0,
                              nullptr);
    if (pipe == INVALID_HANDLE_VALUE) {
        return false;
    }

    std::vector<uint8_t> req;
    proto::AppendPod(req, static_cast<uint32_t>(proto::OpShutdown));
    proto::AppendPod(req, flags);
    const uint32_t size = static_cast<uint32_t>(req.size());
    if (!PipeWriteExact(pipe, &size, sizeof(size)) ||
        !PipeWriteExact(pipe, req.data(), size)) {
        CloseHandle(pipe);
        return false;
    }

    uint32_t rsize = 0;
    if (!PipeReadExact(pipe, &rsize, sizeof(rsize)) || rsize < sizeof(int32_t)) {
        CloseHandle(pipe);
        return false;
    }
    std::vector<uint8_t> resp(rsize);
    if (!PipeReadExact(pipe, resp.data(), rsize)) {
        CloseHandle(pipe);
        return false;
    }
    CloseHandle(pipe);

    int32_t status = HDL_E_FAILED;
    memcpy(&status, resp.data(), sizeof(status));
    if (status != HDL_OK) {
        HDL_LOG_ERROR("OpShutdown returned %d", static_cast<int>(status));
        return false;
    }
    /* Wait until the pipe is gone so ServeClient has left the DLL. */
    for (int i = 0; i < 150; ++i) {
        HANDLE probe = CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0,
                                   nullptr);
        if (probe == INVALID_HANDLE_VALUE) {
            const DWORD err = GetLastError();
            if (err == ERROR_FILE_NOT_FOUND) {
                break;
            }
        } else {
            CloseHandle(probe);
        }
        Sleep(20);
    }
    Sleep(50);
    return true;
}

/* Decrement LoadLibrary refcount until the module leaves the list (or give up). */
HdlStatus FreeLibraryUntilGone(DWORD pid, const wchar_t* dll_path, HMODULE mod, bool remote,
                               HANDLE process) {
    auto free_library = reinterpret_cast<LPTHREAD_START_ROUTINE>(GetKernel32Proc("FreeLibrary"));
    if (!free_library) {
        return HDL_E_FAILED;
    }

    constexpr int kMaxFrees = 64;
    for (int i = 0; i < kMaxFrees; ++i) {
        if (!FindModuleBaseByPath(pid, dll_path)) {
            return HDL_OK;
        }

        if (remote) {
            HANDLE thread =
                ::CreateRemoteThread(process, nullptr, 0, free_library, mod, 0, nullptr);
            if (!thread) {
                HDL_LOG_ERROR("CreateRemoteThread(FreeLibrary) failed: %lu", GetLastError());
                return HDL_E_FAILED;
            }
            WaitForSingleObject(thread, INFINITE);
            CloseHandle(thread);
        } else {
            if (!::FreeLibrary(mod)) {
                HDL_LOG_ERROR("FreeLibrary failed: %lu", GetLastError());
                return HDL_E_FAILED;
            }
        }

        /* Brief pause so the loader can finish detach before re-checking. */
        Sleep(20);
    }
    return PollForModuleGone(pid, dll_path);
}

}  // namespace

HdlStatus UnloadLocal(const wchar_t* dll_path, int reload, uint64_t* out_base) {
    if (out_base) {
        *out_base = 0;
    }
    const DWORD pid = GetCurrentProcessId();
    const uint64_t base = FindModuleBaseByPath(pid, dll_path);
    if (!base) {
        return HDL_E_NOT_FOUND;
    }

    HMODULE mod = reinterpret_cast<HMODULE>(static_cast<uintptr_t>(base));
    if (mod == ModuleContaining(reinterpret_cast<const void*>(&UnloadLocal))) {
        /* In-process eject of the module we are executing would tear down our stack. */
        return HDL_E_BUSY;
    }

    const HdlStatus st = FreeLibraryUntilGone(pid, dll_path, mod, false, nullptr);
    if (st != HDL_OK) {
        return st;
    }
    HDL_LOG_INFO("Unloaded %ls", dll_path);

    if (!reload) {
        return HDL_OK;
    }
    if (GetFileAttributesW(dll_path) == INVALID_FILE_ATTRIBUTES) {
        return HDL_E_NOT_FOUND;
    }
    return Local(dll_path, out_base);
}

HdlStatus UnloadRemote(uint32_t pid, const wchar_t* dll_path, int reload, uint64_t* out_base) {
    return UnloadRemoteEx(pid, dll_path, reload, 0, out_base);
}

HdlStatus UnloadRemoteEx(uint32_t pid, const wchar_t* dll_path, int reload, uint32_t shutdown_flags,
                         uint64_t* out_base) {
    if (out_base) {
        *out_base = 0;
    }
    const uint64_t base = FindModuleBaseByPath(pid, dll_path);
    if (!base) {
        return HDL_E_NOT_FOUND;
    }

    if (!TryPrepareRemoteShutdown(pid, base, shutdown_flags)) {
        HDL_LOG_INFO("Prepare shutdown skipped or failed for pid %u (continuing unload)", pid);
    }

    HANDLE process = OpenTargetProcess(pid);
    if (!process) {
        HDL_LOG_ERROR("OpenProcess(%u) failed: %lu", pid, GetLastError());
        return HDL_E_ACCESS;
    }

    HMODULE mod = reinterpret_cast<HMODULE>(static_cast<uintptr_t>(base));
    const HdlStatus st = FreeLibraryUntilGone(pid, dll_path, mod, true, process);
    CloseHandle(process);
    if (st != HDL_OK) {
        return st;
    }
    HDL_LOG_INFO("Unloaded %ls from pid %u", dll_path, pid);

    if (!reload) {
        return HDL_OK;
    }
    if (GetFileAttributesW(dll_path) == INVALID_FILE_ATTRIBUTES) {
        return HDL_E_NOT_FOUND;
    }
    return CreateRemoteThreadMethod(pid, dll_path, out_base);
}

}  // namespace inject
}  // namespace hdl
