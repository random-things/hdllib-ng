#include "inject.hpp"
#include "inject/common.hpp"
#include "inject/select.hpp"
#include "inject/techniques.hpp"

namespace hdl {

HdlStatus InjectDll(uint32_t pid, const wchar_t* dll_path, uint64_t* out_base) {
    return InjectDllEx(pid, dll_path, HDL_INJECT_CREATE_REMOTE_THREAD, nullptr, nullptr, nullptr,
                       out_base);
}

HdlStatus InjectDllEx(uint32_t pid, const wchar_t* dll_path, int method,
                      const wchar_t* exe_path_or_null, const char* hook_export_or_null,
                      uint32_t* out_pid, uint64_t* out_base) {
    if (!dll_path || !dll_path[0]) {
        return HDL_E_INVALID_ARG;
    }
    if (out_base) {
        *out_base = 0;
    }
    if (out_pid) {
        *out_pid = 0;
    }

    const std::wstring full = inject::NormalizePath(dll_path);
    if (full.empty()) {
        return HDL_E_INVALID_ARG;
    }
    if (GetFileAttributesW(full.c_str()) == INVALID_FILE_ATTRIBUTES) {
        return HDL_E_NOT_FOUND;
    }

    if (method == HDL_INJECT_AUTO) {
        HdlTargetSpec spec{};
        spec.pid = pid;
        HWND hwnd = nullptr;
        uint32_t resolved = 0;
        const HdlStatus rst = inject::ResolveTarget(&spec, &resolved, &hwnd);
        if (rst != HDL_OK) {
            return rst;
        }
        const inject::TargetProfile profile =
            inject::BuildTargetProfile(resolved, hwnd, full.c_str(), hook_export_or_null);
        const int picked = inject::PickBestMethod(profile);
        if (picked < 0) {
            return HDL_E_FAILED;
        }
        method = picked;
        pid = resolved;
    }

    if (method == HDL_INJECT_EARLY_BIRD_APC) {
        return inject::EarlyBirdApcMethod(exe_path_or_null, full.c_str(), out_pid, out_base);
    }

    const DWORD self = GetCurrentProcessId();
    if (pid == 0 || pid == self) {
        return inject::Local(full.c_str(), out_base);
    }

    switch (method) {
    case HDL_INJECT_CREATE_REMOTE_THREAD:
        return inject::CreateRemoteThreadMethod(pid, full.c_str(), out_base);
    case HDL_INJECT_NT_CREATE_THREAD_EX:
        return inject::NtCreateThreadExMethod(pid, full.c_str(), out_base);
    case HDL_INJECT_RTL_CREATE_USER_THREAD:
        return inject::RtlCreateUserThreadMethod(pid, full.c_str(), out_base);
    case HDL_INJECT_QUEUE_USER_APC:
        return inject::QueueUserApcMethod(pid, full.c_str(), out_base);
    case HDL_INJECT_SET_WINDOWS_HOOK_EX:
        return inject::SetWindowsHookExMethod(pid, full.c_str(), hook_export_or_null, out_base);
    case HDL_INJECT_THREAD_HIJACK:
        return inject::ThreadHijackMethod(pid, full.c_str(), out_base);
    case HDL_INJECT_MANUAL_MAP:
        return inject::ManualMapMethod(pid, full.c_str(), out_base);
    case HDL_INJECT_ATOM_BOMBING:
        return inject::AtomBombingMethod(pid, full.c_str(), out_base);
    case HDL_INJECT_MODULE_STOMP:
        return inject::ModuleStompMethod(pid, full.c_str(), out_base);
    case HDL_INJECT_SECTION_MAP:
        return inject::SectionMapMethod(pid, full.c_str(), out_base);
    case HDL_INJECT_WINDOW_SUBCLASS:
        return inject::WindowSubclassMethod(pid, full.c_str(), out_base);
    case HDL_INJECT_INSTRUMENTATION_CALLBACK:
        return inject::InstrumentationCallbackMethod(pid, full.c_str(), out_base);
    case HDL_INJECT_KERNEL_CALLBACK_TABLE:
        return inject::KernelCallbackTableMethod(pid, full.c_str(), out_base);
    case HDL_INJECT_VEH:
        return inject::VehMethod(pid, full.c_str(), out_base);
    case HDL_INJECT_SET_WIN_EVENT_HOOK:
        return inject::SetWinEventHookMethod(pid, full.c_str(), hook_export_or_null, out_base);
    case HDL_INJECT_RTL_REMOTE_CALL:
        return inject::RtlRemoteCallMethod(pid, full.c_str(), out_base);
    case HDL_INJECT_SPECIAL_USER_APC:
        return inject::SpecialUserApcMethod(pid, full.c_str(), out_base);
    case HDL_INJECT_THREAD_POOL:
        return inject::ThreadPoolMethod(pid, full.c_str(), out_base);
    case HDL_INJECT_ETW_CALLBACK:
        return inject::EtwCallbackMethod(pid, full.c_str(), out_base);
    default:
        return HDL_E_INVALID_ARG;
    }
}

HdlStatus UnloadDll(uint32_t pid, const wchar_t* dll_path, int reload, uint64_t* out_base) {
    if (!dll_path || !dll_path[0]) {
        return HDL_E_INVALID_ARG;
    }
    if (out_base) {
        *out_base = 0;
    }

    const std::wstring full = inject::NormalizePath(dll_path);
    if (full.empty()) {
        return HDL_E_INVALID_ARG;
    }

    const DWORD self = GetCurrentProcessId();
    if (pid == 0 || pid == self) {
        return inject::UnloadLocal(full.c_str(), reload, out_base);
    }
    return inject::UnloadRemote(pid, full.c_str(), reload, out_base);
}

}  // namespace hdl
