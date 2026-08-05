#include "local_inject.hpp"

#include "inject.hpp"
#include "inject/select.hpp"
#include "log.hpp"
#include "session_modules.hpp"

#include "hdllib/hdllib.h"
#include "hdllib/pipe_name.h"
#include "pipe_client.hpp"
#include "protocol.hpp"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <cstdio>
#include <cstring>
#include <cwctype>
#include <string>

void PrintLocalInjectUsage() {
    wprintf(LR"(hdlclient inject — load a DLL into a process (local, no pipe)

Usage:
  hdlclient inject <pid> <dll-path> [--method <name>] [--hook-export <name>] [--stealth]
  hdlclient inject --title <substr> [--class <name>] <dll-path> [--method auto|…] [--stealth]
  hdlclient inject --recommend <pid> [dll-path] [--hook-export <name>] [--stealth]
  hdlclient inject --recommend --title <substr> [--class <name>] [dll-path] [--stealth]
  hdlclient inject --early-bird <exe-path> <dll-path> [--stealth]

Methods:
  auto                          Probe target and pick best eligible method
  create_remote_thread          (default) CreateRemoteThread + LoadLibraryW
  nt_create_thread_ex           NtCreateThreadEx + LoadLibraryW
  rtl_create_user_thread        RtlCreateUserThread + LoadLibraryW
  queue_user_apc                QueueUserAPC + LoadLibraryW
  set_windows_hook_ex           SetWindowsHookEx (needs UI thread + hook export)
  thread_hijack                 Suspend + SetThreadContext stub
  manual_map                    Manual PE map
  early_bird_apc                CREATE_SUSPENDED + APC (use --early-bird)
  atom_bombing                  GlobalAddAtom + APC stub (path <= 255 chars)
  module_stomp                  Overwrite sacrificial DLL entry with LoadLibrary stub
  section_map                   NtCreateSection + NtMapViewOfSection + LoadLibraryW
  window_subclass               SetWindowLongPtr WndProc stub (needs window)
  instrumentation_callback      NtSetInformationProcess instrumentation callback
  kernel_callback_table         PEB KernelCallbackTable hijack (needs user32/window)
  veh                           RtlAddVectoredExceptionHandler + DebugBreak
  set_win_event_hook            SetWinEventHook INCONTEXT (export HdlWinEventProc)
  rtl_remote_call               ntdll!RtlRemoteCall into LoadLibrary stub
  special_user_apc              NtQueueApcThreadEx2 SPECIAL_USER_APC
  thread_pool                   TpAllocWork + TpPostWork in target
  etw_callback                  EtwEventRegister enable-callback + EnableTraceEx2

Notes:
  set_windows_hook_ex requires a hook export (default HdlHookProc).
  set_win_event_hook requires a win-event export (default HdlWinEventProc).
  --recommend ranks methods with confidence; does not inject.
  --stealth stages a bland %%TEMP%% copy, prefers manual_map/module_stomp on auto,
            and biases scoring away from CRT/VEH.
  Pipe path: HdlFormatPipeName (default \\.\pipe\RPCControl_<hash>); override HDL_PIPE.

  After inject, talk over the pipe:  hdlclient <pid> ping
  Inject another DLL via pipe:       hdlclient <pid> inject <dll-path> …
)");
}

static int MethodFromName(const wchar_t* name) {
    if (!name) {
        return HDL_INJECT_CREATE_REMOTE_THREAD;
    }
    struct Entry {
        const wchar_t* name;
        const wchar_t* alias;
        int method;
    };
    static const Entry kEntries[] = {
        {L"auto", L"recommend", HDL_INJECT_AUTO},
        {L"create_remote_thread", L"crt", HDL_INJECT_CREATE_REMOTE_THREAD},
        {L"nt_create_thread_ex", L"nt", HDL_INJECT_NT_CREATE_THREAD_EX},
        {L"rtl_create_user_thread", L"rtl", HDL_INJECT_RTL_CREATE_USER_THREAD},
        {L"queue_user_apc", L"apc", HDL_INJECT_QUEUE_USER_APC},
        {L"set_windows_hook_ex", L"hook", HDL_INJECT_SET_WINDOWS_HOOK_EX},
        {L"thread_hijack", L"hijack", HDL_INJECT_THREAD_HIJACK},
        {L"manual_map", L"manual", HDL_INJECT_MANUAL_MAP},
        {L"early_bird_apc", L"early_bird", HDL_INJECT_EARLY_BIRD_APC},
        {L"atom_bombing", L"atom", HDL_INJECT_ATOM_BOMBING},
        {L"module_stomp", L"stomp", HDL_INJECT_MODULE_STOMP},
        {L"section_map", L"section", HDL_INJECT_SECTION_MAP},
        {L"window_subclass", L"subclass", HDL_INJECT_WINDOW_SUBCLASS},
        {L"instrumentation_callback", L"instr", HDL_INJECT_INSTRUMENTATION_CALLBACK},
        {L"kernel_callback_table", L"kct", HDL_INJECT_KERNEL_CALLBACK_TABLE},
        {L"veh", L"veh", HDL_INJECT_VEH},
        {L"set_win_event_hook", L"winevent", HDL_INJECT_SET_WIN_EVENT_HOOK},
        {L"rtl_remote_call", L"rtl_remote", HDL_INJECT_RTL_REMOTE_CALL},
        {L"special_user_apc", L"special_apc", HDL_INJECT_SPECIAL_USER_APC},
        {L"thread_pool", L"pool", HDL_INJECT_THREAD_POOL},
        {L"etw_callback", L"etw", HDL_INJECT_ETW_CALLBACK},
    };
    for (const auto& e : kEntries) {
        if (_wcsicmp(name, e.name) == 0 || _wcsicmp(name, e.alias) == 0) {
            return e.method;
        }
    }
    return -2; // unknown (distinct from HDL_INJECT_AUTO == -1)
}

static const wchar_t* StatusName(HdlStatus st) {
    switch (st) {
    case HDL_OK:
        return L"OK";
    case HDL_E_INVALID_ARG:
        return L"INVALID_ARG";
    case HDL_E_ACCESS:
        return L"ACCESS";
    case HDL_E_NOT_FOUND:
        return L"NOT_FOUND";
    case HDL_E_NO_MEM:
        return L"NO_MEM";
    case HDL_E_BUSY:
        return L"BUSY";
    case HDL_E_FAILED:
        return L"FAILED";
    case HDL_E_BUFFER_SMALL:
        return L"BUFFER_SMALL";
    default:
        return L"?";
    }
}

static const char* MethodNameA(int method) {
    size_t n = 0;
    const hdl::inject::MethodRequirement* cat = hdl::inject::MethodCatalog(&n);
    for (size_t i = 0; i < n; ++i) {
        if (cat[i].method == method) {
            return cat[i].name;
        }
    }
    if (method == HDL_INJECT_AUTO) {
        return "auto";
    }
    return "?";
}

static bool StageStealthDll(const wchar_t* src_full, wchar_t* out_path, size_t out_cch) {
    wchar_t temp[MAX_PATH];
    const DWORD tlen = GetTempPathW(MAX_PATH, temp);
    if (tlen == 0 || tlen >= MAX_PATH) {
        return false;
    }
    const uint32_t tag = HdlPipeNameHash(GetCurrentProcessId() ^ GetTickCount() ^
                                         static_cast<uint32_t>(src_full[0]));
    if (swprintf_s(out_path, out_cch, L"%sdrvstore_%08X.dll", temp, static_cast<unsigned>(tag)) <
        0) {
        return false;
    }
    if (!CopyFileW(src_full, out_path, FALSE)) {
        return false;
    }
    return true;
}

static void PrintPipe(uint32_t pid) {
    wchar_t pipe[128];
    if (HdlFormatPipeName(pid, pipe, 128) != 0) {
        wprintf(L"(pipe name format failed)\n");
        return;
    }
    wprintf(L"Pipe: %ls\n", pipe);
}

static int RunRecommend(const HdlTargetSpec& spec, const wchar_t* dll_path, const char* hook_export,
                        bool stealth) {
    uint32_t pid = 0;
    HWND hwnd = nullptr;
    const HdlStatus rst = hdl::inject::ResolveTarget(&spec, &pid, &hwnd);
    if (rst != HDL_OK) {
        wprintf(L"Resolve target failed: %ls\n", StatusName(rst));
        return 1;
    }

    hdl::inject::TargetProfile profile =
        hdl::inject::BuildTargetProfile(pid, hwnd, dll_path, hook_export);
    profile.prefer_stealth = stealth;

    HdlInjectCandidate cands[hdl::inject::kMethodCount];
    uint32_t count = hdl::inject::kMethodCount;
    hdl::inject::ScoreAllMethods(profile, cands, &count);

    wprintf(L"Target pid %lu hwnd 0x%p%s\n", static_cast<unsigned long>(pid), hwnd,
            stealth ? L" [stealth]" : L"");
    wprintf(L"%-28s %4s  %s\n", L"method", L"conf", L"flags / reasons");
    wprintf(L"----------------------------------------------------------------------\n");
    for (uint32_t i = 0; i < count; ++i) {
        const char* name = MethodNameA(cands[i].method);
        wchar_t wname[64];
        MultiByteToWideChar(CP_UTF8, 0, name, -1, wname, 64);
        wchar_t reasons[280];
        MultiByteToWideChar(CP_UTF8, 0, cands[i].reasons, -1, reasons, 280);
        wprintf(L"%-28s %4d  %s%s\n", wname, cands[i].confidence, reasons,
                (cands[i].flags & HDL_INJECT_CAND_NEEDS_ELEVATION) ? L" [elev]" : L"");
    }
    return 0;
}

int RunLocalInject(int argc, wchar_t** argv) {
    if (argc < 1) {
        PrintLocalInjectUsage();
        return 1;
    }

    hdl::SetLogLevel(hdl::LogLevel::Off);

    uint32_t pid = 0;
    const wchar_t* dll_path = nullptr;
    const wchar_t* exe_path = nullptr;
    const wchar_t* title = nullptr;
    const wchar_t* wnd_class = nullptr;
    int method = HDL_INJECT_CREATE_REMOTE_THREAD;
    std::string hook_export;
    bool recommend = false;
    bool early_bird = false;
    bool stealth = false;
    bool method_flag = false;

    int argi = 0;
    while (argi < argc) {
        if (_wcsicmp(argv[argi], L"--early-bird") == 0) {
            if (argi + 2 >= argc) {
                PrintLocalInjectUsage();
                return 1;
            }
            early_bird = true;
            method = HDL_INJECT_EARLY_BIRD_APC;
            method_flag = true;
            exe_path = argv[argi + 1];
            dll_path = argv[argi + 2];
            argi += 3;
            break;
        }
        if (_wcsicmp(argv[argi], L"--recommend") == 0) {
            recommend = true;
            ++argi;
            continue;
        }
        if (_wcsicmp(argv[argi], L"--stealth") == 0) {
            stealth = true;
            ++argi;
            continue;
        }
        if (_wcsicmp(argv[argi], L"--title") == 0 && argi + 1 < argc) {
            title = argv[++argi];
            ++argi;
            continue;
        }
        if (_wcsicmp(argv[argi], L"--class") == 0 && argi + 1 < argc) {
            wnd_class = argv[++argi];
            ++argi;
            continue;
        }
        if (_wcsicmp(argv[argi], L"--method") == 0 && argi + 1 < argc) {
            method = MethodFromName(argv[++argi]);
            method_flag = true;
            if (method == -2) {
                wprintf(L"Unknown method\n");
                PrintLocalInjectUsage();
                return 1;
            }
            ++argi;
            continue;
        }
        if (_wcsicmp(argv[argi], L"--hook-export") == 0 && argi + 1 < argc) {
            char buf[256];
            WideCharToMultiByte(CP_UTF8, 0, argv[++argi], -1, buf, sizeof(buf), nullptr, nullptr);
            hook_export = buf;
            ++argi;
            continue;
        }
        if (argv[argi][0] == L'-') {
            wprintf(L"Unknown argument: %ls\n", argv[argi]);
            PrintLocalInjectUsage();
            return 1;
        }
        break;
    }

    if (early_bird) {
        for (; argi < argc; ++argi) {
            if (_wcsicmp(argv[argi], L"--stealth") == 0) {
                stealth = true;
                continue;
            }
            wprintf(L"Unknown argument: %ls\n", argv[argi]);
            PrintLocalInjectUsage();
            return 1;
        }
    } else {
        // Remaining positional: [pid] [dll]  — pid omitted when title/class used.
        if (argi < argc && iswdigit(argv[argi][0])) {
            pid = static_cast<uint32_t>(_wtoi(argv[argi]));
            if (pid == 0) {
                wprintf(L"Invalid pid\n");
                return 1;
            }
            ++argi;
        }
        if (argi < argc) {
            dll_path = argv[argi++];
        }
        for (; argi < argc; ++argi) {
            if (_wcsicmp(argv[argi], L"--method") == 0 && argi + 1 < argc) {
                method = MethodFromName(argv[++argi]);
                method_flag = true;
                if (method == -2) {
                    wprintf(L"Unknown method\n");
                    PrintLocalInjectUsage();
                    return 1;
                }
            } else if (_wcsicmp(argv[argi], L"--hook-export") == 0 && argi + 1 < argc) {
                char buf[256];
                WideCharToMultiByte(CP_UTF8, 0, argv[++argi], -1, buf, sizeof(buf), nullptr,
                                    nullptr);
                hook_export = buf;
            } else if (_wcsicmp(argv[argi], L"--stealth") == 0) {
                stealth = true;
            } else {
                wprintf(L"Unknown argument: %ls\n", argv[argi]);
                PrintLocalInjectUsage();
                return 1;
            }
        }
    }

    if (stealth) {
        hdl::SetLogLevel(hdl::LogLevel::Off);
    }

    HdlTargetSpec spec{};
    spec.pid = pid;
    spec.window_title_or_null = title;
    spec.window_class_or_null = wnd_class;

    if (recommend) {
        if (pid == 0 && !title && !wnd_class) {
            wprintf(L"--recommend requires <pid> and/or --title/--class\n");
            return 1;
        }
        wchar_t full_dll[MAX_PATH]{};
        const wchar_t* dll_arg = nullptr;
        if (dll_path) {
            if (GetFullPathNameW(dll_path, MAX_PATH, full_dll, nullptr) == 0) {
                wprintf(L"Bad dll path\n");
                return 1;
            }
            dll_arg = full_dll;
        }
        return RunRecommend(spec, dll_arg, hook_export.empty() ? nullptr : hook_export.c_str(),
                            stealth);
    }

    if (method == HDL_INJECT_EARLY_BIRD_APC) {
        if (!exe_path || !dll_path) {
            wprintf(L"early_bird_apc requires --early-bird <exe> <dll>\n");
            return 1;
        }
    } else {
        if (!dll_path) {
            PrintLocalInjectUsage();
            return 1;
        }
        if (pid == 0 && !title && !wnd_class) {
            wprintf(L"Need <pid> or --title/--class\n");
            return 1;
        }
        if (pid == 0 || title || wnd_class) {
            uint32_t resolved = 0;
            HWND hwnd = nullptr;
            const HdlStatus rst = hdl::inject::ResolveTarget(&spec, &resolved, &hwnd);
            if (rst != HDL_OK) {
                wprintf(L"Resolve target failed: %ls\n", StatusName(rst));
                return 1;
            }
            pid = resolved;
        }
    }

    wchar_t full_dll[MAX_PATH];
    if (GetFullPathNameW(dll_path, MAX_PATH, full_dll, nullptr) == 0) {
        wprintf(L"Bad dll path\n");
        return 1;
    }
    wchar_t full_exe[MAX_PATH]{};
    if (exe_path) {
        if (GetFullPathNameW(exe_path, MAX_PATH, full_exe, nullptr) == 0) {
            wprintf(L"Bad exe path\n");
            return 1;
        }
    }

    wchar_t staged_dll[MAX_PATH]{};
    const wchar_t* inject_dll = full_dll;
    if (stealth) {
        if (!StageStealthDll(full_dll, staged_dll, MAX_PATH)) {
            wprintf(L"Stealth stage copy failed: %lu\n", GetLastError());
            return 1;
        }
        inject_dll = staged_dll;
        wprintf(L"Staged: %ls\n", staged_dll);
    }

    // Title/class without --method => auto. Stealth without --method => auto.
    if (!method_flag && !early_bird) {
        if (title || wnd_class || stealth) {
            method = HDL_INJECT_AUTO;
        }
    }

    if (method == HDL_INJECT_AUTO) {
        HWND hwnd = nullptr;
        HdlTargetSpec auto_spec{};
        auto_spec.pid = pid;
        uint32_t resolved = pid;
        hdl::inject::ResolveTarget(&auto_spec, &resolved, &hwnd);
        hdl::inject::TargetProfile profile = hdl::inject::BuildTargetProfile(
            resolved, hwnd, inject_dll, hook_export.empty() ? nullptr : hook_export.c_str());
        profile.prefer_stealth = stealth;
        const int picked = hdl::inject::PickBestMethod(profile);
        if (picked < 0) {
            wprintf(L"Auto-select: no eligible method (confidence < %d)\n",
                    hdl::inject::kAutoConfidenceThreshold);
            return 1;
        }
        method = picked;
        pid = resolved;
        const char* name = MethodNameA(method);
        wchar_t wname[64];
        MultiByteToWideChar(CP_UTF8, 0, name, -1, wname, 64);
        wprintf(L"Auto-selected: %ls\n", wname);
    }

    uint64_t base = 0;
    uint32_t out_pid = 0;
    const HdlStatus st =
        hdl::InjectDllEx(pid, inject_dll, method, exe_path ? full_exe : nullptr,
                         hook_export.empty() ? nullptr : hook_export.c_str(), &out_pid, &base);

    if (st != HDL_OK) {
        wprintf(L"Inject failed: %ls\n", StatusName(st));
        return 1;
    }

    const uint32_t report_pid = out_pid ? out_pid : pid;
    wprintf(L"Injected into pid %lu.\n", static_cast<unsigned long>(report_pid));
    PrintPipe(report_pid);
    wprintf(L"Module base: 0x%llX\n", static_cast<unsigned long long>(base));
    hdlcli::RememberInjectedModule(report_pid, inject_dll, base);
    return 0;
}

void PrintLocalUnloadUsage() {
    wprintf(LR"(hdlclient unload — FreeLibrary a DLL in a process (local, no pipe)

Usage:
  hdlclient unload <pid> <dll-path> [--reload] [--modules]
  hdlclient reload <pid> <dll-path>

Notes:
  Uses CreateRemoteThread(FreeLibrary) (or FreeLibrary in-process for pid 0/self).
  For hdllib, Control.Shutdown is sent first (when the pipe is up) so hooks/patches/watches
  are restored outside the loader lock before FreeLibrary.
  --modules / HDL_SHUTDOWN_UNLOAD_MODULES also FreeLibrary tracked payload DLLs first.
  --reload / the reload subcommand loads the same path again after unload.
  Manual-mapped / stomped images without a module-list entry cannot be unloaded this way.
  To eject hdllib itself, prefer this local command over the pipe verb.
)");
}

int RunLocalUnload(int argc, wchar_t** argv, int reload_default) {
    if (argc < 2) {
        PrintLocalUnloadUsage();
        return 1;
    }
    const uint32_t pid = static_cast<uint32_t>(_wtoi(argv[0]));
    const wchar_t* path = argv[1];
    int reload = reload_default;
    uint32_t shutdown_flags = 0;
    for (int i = 2; i < argc; ++i) {
        if (_wcsicmp(argv[i], L"--reload") == 0) {
            reload = 1;
        } else if (_wcsicmp(argv[i], L"--modules") == 0) {
            shutdown_flags |= HDL_SHUTDOWN_UNLOAD_MODULES;
        } else if (_wcsicmp(argv[i], L"--help") == 0 || wcscmp(argv[i], L"/?") == 0) {
            PrintLocalUnloadUsage();
            return 0;
        }
    }
    wchar_t full[MAX_PATH];
    GetFullPathNameW(path, MAX_PATH, full, nullptr);

    if (shutdown_flags & HDL_SHUTDOWN_UNLOAD_MODULES) {
        PipeClient client(pid);
        if (client.Connect(2000)) {
            for (const auto& m : hdlcli::ListInjectedModules(pid)) {
                hdl::rpc::PreparedRequest req;
                std::vector<uint8_t> resp;
                hdl::rpc::SetMethod(req, hdl::rpc::Method::TrackLoadedDll);
                hdl::proto::AppendPod(req, m.base);
                hdl::proto::AppendWString(req, m.path.c_str());
                client.Request(req, resp);
            }
            client.Close();
        }
    }

    uint64_t base = 0;
    const HdlStatus st = hdl::UnloadDll(pid, full, reload, shutdown_flags, &base);
    if (st != HDL_OK) {
        wprintf(L"Unload failed: %ls\n", StatusName(st));
        return 1;
    }
    hdlcli::ClearInjectedModules(pid);
    if (reload) {
        wprintf(L"Reloaded into pid %lu at 0x%llX\n", static_cast<unsigned long>(pid),
                static_cast<unsigned long long>(base));
        PrintPipe(pid);
    } else {
        wprintf(L"Unloaded from pid %lu.\n", static_cast<unsigned long>(pid));
    }
    return 0;
}
