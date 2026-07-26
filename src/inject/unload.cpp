#include "inject/common.hpp"
#include "inject/techniques.hpp"

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
    if (out_base) {
        *out_base = 0;
    }
    const uint64_t base = FindModuleBaseByPath(pid, dll_path);
    if (!base) {
        return HDL_E_NOT_FOUND;
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
