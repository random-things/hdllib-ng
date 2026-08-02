#include "inject/select.hpp"
#include "win/raii.hpp"

#include <algorithm>
#include <cstring>
#include <string>

namespace hdl {
namespace inject {
namespace {

const MethodRequirement kCatalog[] = {
    {HDL_INJECT_CREATE_REMOTE_THREAD,
     "create_remote_thread",
     AttachMode::AttachPid,
     true,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     DllExportKind::None,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     0,
     5},
    {HDL_INJECT_NT_CREATE_THREAD_EX,
     "nt_create_thread_ex",
     AttachMode::AttachPid,
     true,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     DllExportKind::None,
     true,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     0,
     4},
    {HDL_INJECT_RTL_CREATE_USER_THREAD,
     "rtl_create_user_thread",
     AttachMode::AttachPid,
     true,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     DllExportKind::None,
     false,
     true,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     0,
     3},
    {HDL_INJECT_QUEUE_USER_APC,
     "queue_user_apc",
     AttachMode::AttachPid,
     true,
     true,
     false,
     false,
     false,
     true,
     false,
     false,
     false,
     false,
     DllExportKind::None,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     5,
     0},
    {HDL_INJECT_SET_WINDOWS_HOOK_EX,
     "set_windows_hook_ex",
     AttachMode::AttachPid,
     false,
     false,
     false,
     true,
     false,
     false,
     false,
     false,
     false,
     false,
     DllExportKind::HookProc,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     4,
     2},
    {HDL_INJECT_THREAD_HIJACK,
     "thread_hijack",
     AttachMode::AttachPid,
     true,
     false,
     true,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     DllExportKind::None,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     6,
     1},
    {HDL_INJECT_MANUAL_MAP,
     "manual_map",
     AttachMode::AttachPid,
     true,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     DllExportKind::None,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     12,
     1},
    {HDL_INJECT_EARLY_BIRD_APC,
     "early_bird_apc",
     AttachMode::SpawnExe,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     DllExportKind::None,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     2,
     0},
    {HDL_INJECT_ATOM_BOMBING,
     "atom_bombing",
     AttachMode::AttachPid,
     true,
     true,
     false,
     false,
     false,
     true,
     false,
     false,
     false,
     false,
     DllExportKind::None,
     false,
     false,
     true,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     8,
     0},
    {HDL_INJECT_MODULE_STOMP,
     "module_stomp",
     AttachMode::AttachPid,
     true,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     true,
     false,
     DllExportKind::None,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     10,
     1},
    {HDL_INJECT_SECTION_MAP,
     "section_map",
     AttachMode::AttachPid,
     true,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     DllExportKind::None,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     true,
     false,
     false,
     1,
     2},
    {HDL_INJECT_WINDOW_SUBCLASS,
     "window_subclass",
     AttachMode::AttachPid,
     true,
     false,
     false,
     true,
     false,
     false,
     false,
     false,
     false,
     false,
     DllExportKind::None,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     4,
     1},
    {HDL_INJECT_INSTRUMENTATION_CALLBACK,
     "instrumentation_callback",
     AttachMode::AttachPid,
     true,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     DllExportKind::None,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     true,
     3,
     -2},
    {HDL_INJECT_KERNEL_CALLBACK_TABLE,
     "kernel_callback_table",
     AttachMode::AttachPid,
     true,
     false,
     false,
     true,
     false,
     false,
     false,
     true,
     false,
     false,
     DllExportKind::None,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     7,
     0},
    {HDL_INJECT_VEH,
     "veh",
     AttachMode::AttachPid,
     true,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     DllExportKind::None,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     true,
     false,
     1,
     1},
    {HDL_INJECT_SET_WIN_EVENT_HOOK,
     "set_win_event_hook",
     AttachMode::AttachPid,
     false,
     false,
     false,
     false,
     true,
     false,
     false,
     false,
     false,
     false,
     DllExportKind::WinEventProc,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     3,
     1},
    {HDL_INJECT_RTL_REMOTE_CALL,
     "rtl_remote_call",
     AttachMode::AttachPid,
     true,
     false,
     true,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     DllExportKind::None,
     false,
     false,
     false,
     false,
     true,
     false,
     false,
     false,
     false,
     false,
     3,
     0},
    {HDL_INJECT_SPECIAL_USER_APC,
     "special_user_apc",
     AttachMode::AttachPid,
     true,
     true,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     true,
     DllExportKind::None,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     6,
     2},
    {HDL_INJECT_THREAD_POOL,
     "thread_pool",
     AttachMode::AttachPid,
     true,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     false,
     DllExportKind::None,
     false,
     false,
     false,
     false,
     false,
     true,
     false,
     false,
     false,
     false,
     5,
     2},
    {HDL_INJECT_ETW_CALLBACK,
     "etw_callback",
     AttachMode::AttachPid,
     true,
     false,
     false,
     false,
     false,
     false,
     true,
     false,
     false,
     false,
     DllExportKind::None,
     false,
     false,
     false,
     false,
     false,
     false,
     true,
     false,
     false,
     false,
     3,
     -1},
};

void AppendReason(char* buf, size_t cap, const char* tag) {
    if (!buf || !tag || !tag[0] || cap == 0) {
        return;
    }
    const size_t len = strnlen(buf, cap);
    if (len + 1 >= cap) {
        return;
    }
    if (len > 0) {
        if (len + 2 >= cap) {
            return;
        }
        buf[len] = ';';
        buf[len + 1] = '\0';
    }
    strncat_s(buf, cap, tag, _TRUNCATE);
}

bool IsElevated() {
    HANDLE raw_token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw_token)) {
        return false;
    }
    win::unique_handle token(raw_token);
    TOKEN_ELEVATION elev{};
    DWORD got = 0;
    const BOOL ok = GetTokenInformation(token.get(), TokenElevation, &elev, sizeof(elev), &got);
    return ok && elev.TokenIsElevated != 0;
}

bool ModulePresent(DWORD pid, const wchar_t* file) {
    win::unique_handle snap(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid));
    if (!snap) {
        return false;
    }
    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    bool found = false;
    if (Module32FirstW(snap.get(), &me)) {
        do {
            if (_wcsicmp(me.szModule, file) == 0) {
                found = true;
                break;
            }
        } while (Module32NextW(snap.get(), &me));
    }
    return found;
}

bool ProbeKct(HANDLE process) {
    using NtQueryInformationProcess_t = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    auto ntq = reinterpret_cast<NtQueryInformationProcess_t>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
    if (!ntq) {
        return false;
    }
    struct ProcessBasicInfo {
        PVOID Reserved1;
        PVOID PebBaseAddress;
        PVOID Reserved2[2];
        ULONG_PTR UniqueProcessId;
        PVOID Reserved3;
    } pbi{};
    ULONG ret = 0;
    if (ntq(process, 0 /*ProcessBasicInformation*/, &pbi, sizeof(pbi), &ret) < 0 ||
        !pbi.PebBaseAddress) {
        return false;
    }
    constexpr size_t kPebKct = 0x58;
    void* kct = nullptr;
    if (!ReadRemote(process, static_cast<uint8_t*>(pbi.PebBaseAddress) + kPebKct, &kct,
                    sizeof(kct))) {
        return false;
    }
    return kct != nullptr;
}

bool CheckDllExport(const wchar_t* dll_path, const char* export_name) {
    if (!dll_path || !dll_path[0] || !export_name || !export_name[0]) {
        return false;
    }
    win::unique_hmodule mod(LoadLibraryExW(dll_path, nullptr, DONT_RESOLVE_DLL_REFERENCES));
    if (!mod) {
        mod.reset(LoadLibraryW(dll_path));
    }
    if (!mod) {
        return false;
    }
    return GetProcAddress(mod.get(), export_name) != nullptr;
}

FARPROC NtdllProc(const char* name) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    return ntdll ? GetProcAddress(ntdll, name) : nullptr;
}

void ProbeLocalApis(TargetProfile& p) {
    p.api_nt_create_thread_ex = NtdllProc("NtCreateThreadEx") != nullptr;
    p.api_rtl_create_user_thread = NtdllProc("RtlCreateUserThread") != nullptr;
    p.api_nt_queue_apc = NtdllProc("NtQueueApcThread") != nullptr;
    p.api_nt_queue_apc_ex2 = NtdllProc("NtQueueApcThreadEx2") != nullptr;
    p.api_rtl_remote_call = NtdllProc("RtlRemoteCall") != nullptr;
    p.api_tp = NtdllProc("TpAllocWork") != nullptr && NtdllProc("TpPostWork") != nullptr;
    p.api_etw = NtdllProc("EtwEventRegister") != nullptr;
    p.api_nt_create_section =
        NtdllProc("NtCreateSection") != nullptr && NtdllProc("NtMapViewOfSection") != nullptr;
    p.api_rtl_add_veh = NtdllProc("RtlAddVectoredExceptionHandler") != nullptr;
    p.api_nt_set_info_process = NtdllProc("NtSetInformationProcess") != nullptr;
}

bool ThreadOpenable(DWORD pid, DWORD access) {
    win::unique_handle t(OpenApcThread(pid, access));
    return !!t;
}

} // namespace

const MethodRequirement* MethodCatalog(size_t* out_count) {
    if (out_count) {
        *out_count = sizeof(kCatalog) / sizeof(kCatalog[0]);
    }
    return kCatalog;
}

const MethodRequirement* FindMethodRequirement(int method) {
    for (const auto& e : kCatalog) {
        if (e.method == method) {
            return &e;
        }
    }
    return nullptr;
}

HdlStatus ResolveTarget(const HdlTargetSpec* spec, uint32_t* out_pid, HWND* out_hwnd) {
    if (!spec) {
        return HDL_E_INVALID_ARG;
    }
    const bool has_title = spec->window_title_or_null && spec->window_title_or_null[0];
    const bool has_class = spec->window_class_or_null && spec->window_class_or_null[0];

    if (spec->pid == 0 && !has_title && !has_class) {
        return HDL_E_INVALID_ARG;
    }

    if (out_pid) {
        *out_pid = 0;
    }
    if (out_hwnd) {
        *out_hwnd = nullptr;
    }

    // PID primary: optionally verify title/class.
    if (spec->pid != 0) {
        if (has_title || has_class) {
            HWND hwnd = nullptr;
            uint32_t matched_pid = 0;
            uint32_t count = 0;
            const HdlStatus st =
                FindWindowByTitleClass(spec->pid, spec->window_title_or_null,
                                       spec->window_class_or_null, &hwnd, &matched_pid, &count);
            if (st == HDL_E_BUSY) {
                return HDL_E_BUSY;
            }
            if (st != HDL_OK) {
                return HDL_E_NOT_FOUND;
            }
            if (out_hwnd) {
                *out_hwnd = hwnd;
            }
        } else {
            HWND hwnd = FindWindowForPid(spec->pid);
            if (out_hwnd) {
                *out_hwnd = hwnd;
            }
        }
        if (out_pid) {
            *out_pid = spec->pid;
        }
        return HDL_OK;
    }

    // Title/class only.
    HWND hwnd = nullptr;
    uint32_t pid = 0;
    uint32_t count = 0;
    const HdlStatus st = FindWindowByTitleClass(0, spec->window_title_or_null,
                                                spec->window_class_or_null, &hwnd, &pid, &count);
    if (st != HDL_OK) {
        return st;
    }
    if (out_pid) {
        *out_pid = pid;
    }
    if (out_hwnd) {
        *out_hwnd = hwnd;
    }
    return HDL_OK;
}

TargetProfile BuildTargetProfile(uint32_t pid, HWND hwnd_hint, const wchar_t* dll_path_or_null,
                                 const char* hook_export_or_null) {
    TargetProfile p{};
    p.pid = pid;
    ProbeLocalApis(p);
    p.elevated_self = IsElevated();

    if (pid == 0) {
        return p;
    }

    win::unique_handle probe(OpenTargetProcess(pid));
    if (probe) {
        p.process_openable = true;
        BOOL wow = FALSE;
        if (IsWow64Process(probe.get(), &wow)) {
            p.wow64_target = wow != FALSE;
        }
        p.kct_nonzero = ProbeKct(probe.get());
    } else {
        p.process_openable = false;
        win::unique_handle limited(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
        if (limited) {
            BOOL wow = FALSE;
            if (IsWow64Process(limited.get(), &wow)) {
                p.wow64_target = wow != FALSE;
            }
        }
    }

    p.threads_openable = ThreadOpenable(pid, THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION);
    p.suspend_context_openable =
        ThreadOpenable(pid, THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME |
                                THREAD_QUERY_INFORMATION);

    HWND hwnd = hwnd_hint;
    if (!hwnd) {
        hwnd = FindWindowForPid(pid);
    }
    p.hwnd = hwnd;
    p.has_hwnd = hwnd != nullptr;

    p.sacrificial_module = ModulePresent(pid, L"cryptbase.dll") ||
                           ModulePresent(pid, L"dpapi.dll") || ModulePresent(pid, L"profapi.dll");

    const char* hook_name =
        (hook_export_or_null && hook_export_or_null[0]) ? hook_export_or_null : "HdlHookProc";
    const char* winevent_name =
        (hook_export_or_null && hook_export_or_null[0]) ? hook_export_or_null : "HdlWinEventProc";

    if (dll_path_or_null && dll_path_or_null[0]) {
        const std::wstring full = NormalizePath(dll_path_or_null);
        p.has_hook_export = CheckDllExport(full.c_str(), hook_name);
        // Win-event uses its own default unless caller overrides via hook_export.
        if (hook_export_or_null && hook_export_or_null[0]) {
            p.has_winevent_export = CheckDllExport(full.c_str(), winevent_name);
        } else {
            p.has_winevent_export = CheckDllExport(full.c_str(), "HdlWinEventProc");
        }
    }

    return p;
}

void ScoreMethod(const MethodRequirement& req, const TargetProfile& profile,
                 HdlInjectCandidate* out) {
    if (!out) {
        return;
    }
    out->method = req.method;
    out->confidence = 0;
    out->flags = 0;
    out->reasons[0] = '\0';

    if (req.attach == AttachMode::SpawnExe) {
        AppendReason(out->reasons, sizeof(out->reasons), "early_bird_not_attach");
        return;
    }
    if (profile.wow64_target) {
        AppendReason(out->reasons, sizeof(out->reasons), "wow64_unsupported");
        return;
    }

    auto hard_fail = [&](const char* tag) {
        out->confidence = 0;
        out->flags = 0;
        AppendReason(out->reasons, sizeof(out->reasons), tag);
    };

    if (req.needs_process && !profile.process_openable) {
        hard_fail("needs_process_access");
        return;
    }
    if (req.needs_thread && !profile.threads_openable) {
        hard_fail("needs_thread");
        return;
    }
    if (req.needs_suspend_context && !profile.suspend_context_openable) {
        hard_fail("needs_suspend_context");
        return;
    }
    if (req.needs_hwnd && !profile.has_hwnd) {
        hard_fail("needs_hwnd");
        return;
    }
    if (req.needs_kct && !profile.kct_nonzero) {
        hard_fail("needs_kct");
        return;
    }
    if (req.needs_elevation && !profile.elevated_self) {
        hard_fail("needs_elevation");
        return;
    }
    if (req.export_kind == DllExportKind::HookProc && !profile.has_hook_export) {
        hard_fail("missing_export:hook");
        return;
    }
    if (req.export_kind == DllExportKind::WinEventProc && !profile.has_winevent_export) {
        hard_fail("missing_export:winevent");
        return;
    }

    auto api_fail = [&](bool needed, bool present, const char* tag) -> bool {
        if (needed && !present) {
            hard_fail(tag);
            return true;
        }
        return false;
    };
    if (api_fail(req.need_api_nt_create_thread_ex, profile.api_nt_create_thread_ex,
                 "missing_api:NtCreateThreadEx") ||
        api_fail(req.need_api_rtl_create_user_thread, profile.api_rtl_create_user_thread,
                 "missing_api:RtlCreateUserThread") ||
        api_fail(req.need_api_nt_queue_apc, profile.api_nt_queue_apc,
                 "missing_api:NtQueueApcThread") ||
        api_fail(req.need_api_rtl_remote_call, profile.api_rtl_remote_call,
                 "missing_api:RtlRemoteCall") ||
        api_fail(req.need_api_tp, profile.api_tp, "missing_api:Tp*") ||
        api_fail(req.need_api_etw, profile.api_etw, "missing_api:EtwEventRegister") ||
        api_fail(req.need_api_nt_create_section, profile.api_nt_create_section,
                 "missing_api:NtCreateSection") ||
        api_fail(req.need_api_rtl_add_veh, profile.api_rtl_add_veh,
                 "missing_api:RtlAddVectoredExceptionHandler") ||
        api_fail(req.need_api_nt_set_info_process, profile.api_nt_set_info_process,
                 "missing_api:NtSetInformationProcess")) {
        return;
    }
    if (req.prefers_special_apc_ex2 && !profile.api_nt_queue_apc_ex2 && !profile.api_nt_queue_apc) {
        hard_fail("missing_api:NtQueueApcThread");
        return;
    }
    if (req.need_api_nt_queue_apc_ex2 && !profile.api_nt_queue_apc_ex2) {
        hard_fail("missing_api:NtQueueApcThreadEx2");
        return;
    }

    int score = 55;
    out->flags = HDL_INJECT_CAND_ELIGIBLE;
    AppendReason(out->reasons, sizeof(out->reasons), "eligible");

    if (req.needs_process && profile.process_openable) {
        score += 15;
        AppendReason(out->reasons, sizeof(out->reasons), "process_ok");
    }
    if (req.needs_thread && profile.threads_openable) {
        score += 10;
        AppendReason(out->reasons, sizeof(out->reasons), "thread_ok");
    }
    if (req.needs_suspend_context && profile.suspend_context_openable) {
        score += 10;
        AppendReason(out->reasons, sizeof(out->reasons), "suspend_ok");
    }
    if (req.needs_hwnd && profile.has_hwnd) {
        score += 15;
        AppendReason(out->reasons, sizeof(out->reasons), "hwnd_ok");
    }
    if (req.needs_kct && profile.kct_nonzero) {
        score += 10;
        AppendReason(out->reasons, sizeof(out->reasons), "kct_ok");
    }

    if (req.prefers_hwnd) {
        if (profile.has_hwnd) {
            score += 10;
            AppendReason(out->reasons, sizeof(out->reasons), "hwnd_preferred");
        } else {
            score -= 15;
            AppendReason(out->reasons, sizeof(out->reasons), "no_hwnd_soft");
        }
    }

    if (req.needs_alertable) {
        // Cannot prove alertable — soft penalty.
        score -= 20;
        AppendReason(out->reasons, sizeof(out->reasons), "alertable_unknown");
    }

    if (req.prefers_special_apc_ex2) {
        if (profile.api_nt_queue_apc_ex2) {
            score += 15;
            AppendReason(out->reasons, sizeof(out->reasons), "special_apc_ex2");
        } else {
            score -= 10;
            AppendReason(out->reasons, sizeof(out->reasons), "special_apc_fallback");
        }
    }

    if (req.prefers_sacrificial) {
        if (profile.sacrificial_module) {
            score += 10;
            AppendReason(out->reasons, sizeof(out->reasons), "sacrificial_present");
        } else {
            score -= 5;
            AppendReason(out->reasons, sizeof(out->reasons), "sacrificial_absent");
        }
    }

    if (req.needs_elevation) {
        out->flags |= HDL_INJECT_CAND_NEEDS_ELEVATION;
    }

    // Stability vs stealth: prefer_stealth always uses stealth_bias (+ map/stomp boost).
    if (profile.prefer_stealth) {
        score += req.stealth_bias;
        if (req.stealth_bias > 0) {
            AppendReason(out->reasons, sizeof(out->reasons), "stealth_bias");
        }
        if (req.method == HDL_INJECT_MANUAL_MAP || req.method == HDL_INJECT_MODULE_STOMP) {
            score += 15;
            AppendReason(out->reasons, sizeof(out->reasons), "stealth_prefer_map");
        }
        // Soft-penalize classic CRT LoadLibrary remote-thread family.
        if (req.method == HDL_INJECT_CREATE_REMOTE_THREAD ||
            req.method == HDL_INJECT_NT_CREATE_THREAD_EX ||
            req.method == HDL_INJECT_RTL_CREATE_USER_THREAD) {
            score -= 12;
            AppendReason(out->reasons, sizeof(out->reasons), "stealth_avoid_crt");
        }
        if (req.method == HDL_INJECT_VEH) {
            score -= 20;
            AppendReason(out->reasons, sizeof(out->reasons), "stealth_avoid_veh");
        }
    } else if (profile.process_openable && !profile.has_hwnd) {
        score += req.stability_bias;
    } else {
        score += req.stealth_bias;
        if (req.stealth_bias > 0) {
            AppendReason(out->reasons, sizeof(out->reasons), "stealth_bias");
        }
    }

    if (score < 0) {
        score = 0;
    }
    if (score > 100) {
        score = 100;
    }
    out->confidence = score;
}

void ScoreAllMethods(const TargetProfile& profile, HdlInjectCandidate* out, uint32_t* inout_count) {
    if (!inout_count) {
        return;
    }
    size_t catalog_n = 0;
    const MethodRequirement* catalog = MethodCatalog(&catalog_n);
    const uint32_t need = static_cast<uint32_t>(catalog_n);

    if (!out || *inout_count < need) {
        *inout_count = need;
        return;
    }

    std::vector<HdlInjectCandidate> tmp(catalog_n);
    for (size_t i = 0; i < catalog_n; ++i) {
        ScoreMethod(catalog[i], profile, &tmp[i]);
    }

    std::sort(tmp.begin(), tmp.end(),
              [&](const HdlInjectCandidate& a, const HdlInjectCandidate& b) {
                  if (a.confidence != b.confidence) {
                      return a.confidence > b.confidence;
                  }
                  const MethodRequirement* ra = FindMethodRequirement(a.method);
                  const MethodRequirement* rb = FindMethodRequirement(b.method);
                  const int sa = ra ? ra->stability_bias : 0;
                  const int sb = rb ? rb->stability_bias : 0;
                  if (sa != sb) {
                      return sa > sb;
                  }
                  return a.method < b.method;
              });

    for (size_t i = 0; i < catalog_n; ++i) {
        out[i] = tmp[i];
    }
    *inout_count = need;
}

int PickBestMethod(const TargetProfile& profile, int min_confidence) {
    HdlInjectCandidate cands[kMethodCount];
    uint32_t n = kMethodCount;
    ScoreAllMethods(profile, cands, &n);
    if (n == 0) {
        return -1;
    }

    if (profile.prefer_stealth) {
        const int prefer[] = {HDL_INJECT_MANUAL_MAP, HDL_INJECT_MODULE_STOMP};
        for (int method : prefer) {
            for (uint32_t i = 0; i < n; ++i) {
                if (cands[i].method == method && (cands[i].flags & HDL_INJECT_CAND_ELIGIBLE) &&
                    cands[i].confidence >= min_confidence) {
                    return method;
                }
            }
        }
    }

    if ((cands[0].flags & HDL_INJECT_CAND_ELIGIBLE) == 0 || cands[0].confidence < min_confidence) {
        return -1;
    }
    return cands[0].method;
}

} // namespace inject
} // namespace hdl
