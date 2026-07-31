#include "core.hpp"
#include "log.hpp"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

namespace {

DWORD WINAPI BootstrapThread(LPVOID) {
    if (hdl::CoreInit() != HDL_OK) {
        HDL_LOG_ERROR("CoreInit failed in bootstrap thread");
    }
    return 0;
}

}  // namespace

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved) {
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(module);
        // Defer init off the loader lock (thread + MinHook + pipe).
        {
            HANDLE t = CreateThread(nullptr, 0, BootstrapThread, nullptr, 0, nullptr);
            if (t) {
                CloseHandle(t);
            } else {
                HDL_LOG_ERROR("Failed to start bootstrap thread: %lu", GetLastError());
            }
        }
        break;
    case DLL_PROCESS_DETACH:
        if (reserved == nullptr) {
            hdl::CoreShutdownDetach();
        }
        break;
    default:
        break;
    }
    return TRUE;
}
