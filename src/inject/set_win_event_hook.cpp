#include "inject/common.hpp"
#include "inject/techniques.hpp"
#include "win/raii.hpp"

namespace hdl {
namespace inject {

HdlStatus SetWinEventHookMethod(uint32_t pid, const wchar_t* dll_path, const char* hook_export,
                                uint64_t* out_base) {
    const char* export_name = (hook_export && hook_export[0]) ? hook_export : "HdlWinEventProc";

    win::unique_hmodule local(LoadLibraryW(dll_path));
    if (!local) {
        HDL_LOG_ERROR("SetWinEventHook: LoadLibraryW(local) failed: %lu", GetLastError());
        return HDL_E_FAILED;
    }

    auto proc = reinterpret_cast<WINEVENTPROC>(GetProcAddress(local.get(), export_name));
    if (!proc) {
        HDL_LOG_ERROR("SetWinEventHook: export '%s' not found", export_name);
        return HDL_E_NOT_FOUND;
    }

    HWINEVENTHOOK hook = SetWinEventHook(EVENT_MIN, EVENT_MAX, local.get(), proc, pid, 0,
                                         WINEVENT_INCONTEXT | WINEVENT_SKIPOWNPROCESS);
    if (!hook) {
        HDL_LOG_ERROR("SetWinEventHook failed: %lu", GetLastError());
        return HDL_E_FAILED;
    }

    // Force win-events in the target (cursor / focus noise).
    POINT pt{};
    GetCursorPos(&pt);
    SetCursorPos(pt.x + 1, pt.y);
    SetCursorPos(pt.x, pt.y);

    HWND hwnd = FindWindowForPid(pid);
    if (hwnd) {
        SetForegroundWindow(hwnd);
        PostMessageW(hwnd, WM_NULL, 0, 0);
    }

    const HdlStatus st = PollForModule(pid, dll_path, out_base);

    UnhookWinEvent(hook);

    if (st == HDL_OK) {
        HDL_LOG_INFO("SetWinEventHook inject into pid %u ok", pid);
    } else {
        HDL_LOG_ERROR("SetWinEventHook installed but module not observed");
    }
    return st;
}

} // namespace inject
} // namespace hdl
