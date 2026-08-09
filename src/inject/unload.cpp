#include "inject/common.hpp"
#include "inject/techniques.hpp"
#include "win/raii.hpp"

#include "hdl/rpc/v1/services.rpc.hpp"
#include "hdllib/hdllib.h"
#include "hdllib/pipe_name.h"
#include "rpc/pipe_client.hpp"

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

enum class ShutdownPreparation {
    NotHelper,
    Prepared,
    Blocked,
};

struct ShutdownPreparationResult {
    ShutdownPreparation state = ShutdownPreparation::NotHelper;
    HdlStatus status = HDL_OK;
};

/* Ask the in-target helper to quiesce before FreeLibrary. A helper that cannot
 * confirm quiescence is contained in place instead of being unsafely unloaded. */
ShutdownPreparationResult TryPrepareRemoteShutdown(DWORD pid, uint64_t module_base,
                                                   uint32_t flags) {
    bool is_helper = false;
    win::unique_handle snap(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid));
    if (snap) {
        MODULEENTRY32W me{};
        me.dwSize = sizeof(me);
        if (Module32FirstW(snap.get(), &me)) {
            do {
                if (reinterpret_cast<uint64_t>(me.modBaseAddr) == module_base) {
                    win::unique_hmodule probe(
                        LoadLibraryExW(me.szExePath, nullptr, DONT_RESOLVE_DLL_REFERENCES));
                    if (probe) {
                        if (GetProcAddress(probe.get(), "HdlHookProc") ||
                            GetProcAddress(probe.get(), "HdlWinEventProc")) {
                            is_helper = true;
                        }
                    }
                    break;
                }
            } while (Module32NextW(snap.get(), &me));
        }
    }
    if (!is_helper) {
        return {};
    }

    PipeClient pipe(pid, "hdllib-unload", "0.1.0-pre");
    if (!pipe.Connect()) {
        /* A caller may have completed Control.Shutdown immediately before this
         * unload, in which case the absent pipe is the expected state. Preserve
         * that established two-step workflow; a live helper that reports BUSY is
         * handled below and is never unloaded. */
        HDL_LOG_INFO("Helper shutdown pipe unavailable for pid %u; assuming prior preparation",
                     pid);
        return {ShutdownPreparation::Prepared, HDL_OK};
    }
    rpc::v1::ShutdownRequest shutdown;
    shutdown.set_flags(flags);
    rpc::ControlClient control(&pipe);
    const rpc::Result<rpc::v1::Empty> result = control.Shutdown(shutdown);
    pipe.Close();

    if (!result.status.ok()) {
        HDL_LOG_ERROR("Control.Shutdown returned %d", result.status.hdl_status());
        const int32_t remote_status = result.status.hdl_status();
        return {ShutdownPreparation::Blocked,
                remote_status == HDL_E_BUSY ? HDL_E_BUSY : HDL_E_FAILED};
    }
    /* Wait until the pipe is gone so ServeClient has left the DLL. */
    bool pipe_gone = false;
    for (int i = 0; i < 150; ++i) {
        win::unique_handle probe(HdlOpenLocalPipe(pid));
        if (!probe) {
            const DWORD err = GetLastError();
            if (err == ERROR_FILE_NOT_FOUND) {
                pipe_gone = true;
                break;
            }
        }
        Sleep(20);
    }
    if (!pipe_gone) {
        HDL_LOG_ERROR("Refusing helper unload: shutdown pipe did not quiesce for pid %u", pid);
        return {ShutdownPreparation::Blocked, HDL_E_BUSY};
    }
    Sleep(50);
    return {ShutdownPreparation::Prepared, HDL_OK};
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
            win::unique_handle thread(
                ::CreateRemoteThread(process, nullptr, 0, free_library, mod, 0, nullptr));
            if (!thread) {
                HDL_LOG_ERROR("CreateRemoteThread(FreeLibrary) failed: %lu", GetLastError());
                return HDL_E_FAILED;
            }
            WaitForSingleObject(thread.get(), INFINITE);
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

} // namespace

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

    const ShutdownPreparationResult preparation =
        TryPrepareRemoteShutdown(pid, base, shutdown_flags);
    if (preparation.state == ShutdownPreparation::Blocked) {
        HDL_LOG_ERROR("Refusing unload for pid %u because helper quiescence was not confirmed",
                      pid);
        return preparation.status;
    }
    if (preparation.state == ShutdownPreparation::NotHelper) {
        HDL_LOG_INFO("Target module is not an hdllib helper; no helper shutdown required");
    }

    win::unique_handle process(OpenTargetProcess(pid));
    if (!process) {
        HDL_LOG_ERROR("OpenProcess(%u) failed: %lu", pid, GetLastError());
        return HDL_E_ACCESS;
    }

    HMODULE mod = reinterpret_cast<HMODULE>(static_cast<uintptr_t>(base));
    const HdlStatus st = FreeLibraryUntilGone(pid, dll_path, mod, true, process.get());
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

} // namespace inject
} // namespace hdl
