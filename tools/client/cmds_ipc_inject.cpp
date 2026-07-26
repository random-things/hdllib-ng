#include "cmd.hpp"
#include "usage.hpp"
#include "util.hpp"

#include "protocol.hpp"
#include "hdllib/hdllib.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

int CmdInject(CmdCtx& ctx) {
    using namespace hdl::proto;
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;

    if (ctx.argc < 4) {
        PrintUsage();
        return 1;
    }
    uint32_t target_pid = 0;
    uint32_t method = HDL_INJECT_CREATE_REMOTE_THREAD;
    const wchar_t* path = ctx.argv[3];
    std::wstring exe_path;
    std::string hook_export;
    for (int i = 4; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--target-pid") == 0 && i + 1 < ctx.argc) {
            target_pid = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
        } else if (wcscmp(ctx.argv[i], L"--method") == 0 && i + 1 < ctx.argc) {
            ++i;
            if (_wcsicmp(ctx.argv[i], L"create_remote_thread") == 0) {
                method = HDL_INJECT_CREATE_REMOTE_THREAD;
            } else if (_wcsicmp(ctx.argv[i], L"nt_create_thread_ex") == 0) {
                method = HDL_INJECT_NT_CREATE_THREAD_EX;
            } else if (_wcsicmp(ctx.argv[i], L"rtl_create_user_thread") == 0) {
                method = HDL_INJECT_RTL_CREATE_USER_THREAD;
            } else if (_wcsicmp(ctx.argv[i], L"queue_user_apc") == 0) {
                method = HDL_INJECT_QUEUE_USER_APC;
            } else if (_wcsicmp(ctx.argv[i], L"set_windows_hook_ex") == 0) {
                method = HDL_INJECT_SET_WINDOWS_HOOK_EX;
            } else if (_wcsicmp(ctx.argv[i], L"thread_hijack") == 0) {
                method = HDL_INJECT_THREAD_HIJACK;
            } else if (_wcsicmp(ctx.argv[i], L"manual_map") == 0) {
                method = HDL_INJECT_MANUAL_MAP;
            } else if (_wcsicmp(ctx.argv[i], L"early_bird_apc") == 0) {
                method = HDL_INJECT_EARLY_BIRD_APC;
            } else if (_wcsicmp(ctx.argv[i], L"atom_bombing") == 0) {
                method = HDL_INJECT_ATOM_BOMBING;
            } else if (_wcsicmp(ctx.argv[i], L"module_stomp") == 0) {
                method = HDL_INJECT_MODULE_STOMP;
            } else if (_wcsicmp(ctx.argv[i], L"section_map") == 0) {
                method = HDL_INJECT_SECTION_MAP;
            } else if (_wcsicmp(ctx.argv[i], L"window_subclass") == 0) {
                method = HDL_INJECT_WINDOW_SUBCLASS;
            } else if (_wcsicmp(ctx.argv[i], L"instrumentation_callback") == 0) {
                method = HDL_INJECT_INSTRUMENTATION_CALLBACK;
            } else if (_wcsicmp(ctx.argv[i], L"kernel_callback_table") == 0) {
                method = HDL_INJECT_KERNEL_CALLBACK_TABLE;
            } else if (_wcsicmp(ctx.argv[i], L"veh") == 0) {
                method = HDL_INJECT_VEH;
            } else if (_wcsicmp(ctx.argv[i], L"set_win_event_hook") == 0) {
                method = HDL_INJECT_SET_WIN_EVENT_HOOK;
            } else if (_wcsicmp(ctx.argv[i], L"rtl_remote_call") == 0) {
                method = HDL_INJECT_RTL_REMOTE_CALL;
            } else if (_wcsicmp(ctx.argv[i], L"special_user_apc") == 0) {
                method = HDL_INJECT_SPECIAL_USER_APC;
            } else if (_wcsicmp(ctx.argv[i], L"thread_pool") == 0) {
                method = HDL_INJECT_THREAD_POOL;
            } else if (_wcsicmp(ctx.argv[i], L"etw_callback") == 0) {
                method = HDL_INJECT_ETW_CALLBACK;
            } else {
                wprintf(L"Unknown method: %ls\n", ctx.argv[i]);
                return 1;
            }
        } else if (wcscmp(ctx.argv[i], L"--exe") == 0 && i + 1 < ctx.argc) {
            exe_path = ctx.argv[++i];
        } else if (wcscmp(ctx.argv[i], L"--hook-export") == 0 && i + 1 < ctx.argc) {
            char buf[256];
            WideCharToMultiByte(CP_UTF8, 0, ctx.argv[++i], -1, buf, sizeof(buf), nullptr, nullptr);
            hook_export = buf;
        }
    }
    wchar_t full[MAX_PATH];
    GetFullPathNameW(path, MAX_PATH, full, nullptr);
    wchar_t full_exe[MAX_PATH]{};
    if (!exe_path.empty()) {
        GetFullPathNameW(exe_path.c_str(), MAX_PATH, full_exe, nullptr);
    }
    AppendPod(req, static_cast<uint32_t>(OpInjectDll));
    AppendPod(req, target_pid);
    AppendPod(req, method);
    AppendWString(req, full);
    AppendWString(req, exe_path.empty() ? L"" : full_exe);
    AppendString(req, hook_export.c_str());
    if (!ctx.client.Request(req, resp)) return 1;
    Reader r(resp);
    int32_t st = 0;
    uint64_t base = 0;
    uint32_t out_pid = 0;
    if (!r.TakePod(st) || !r.TakePod(base)) return 1;
    r.TakePod(out_pid);
    wprintf(L"status=%ls base=%016llx out_pid=%u\n", StatusName(st),
            static_cast<unsigned long long>(base), out_pid);
    return st == HDL_OK ? 0 : 1;
}

int CmdUnload(CmdCtx& ctx) {
    using namespace hdl::proto;
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;

    if (ctx.argc < 4) {
        PrintUsage();
        return 1;
    }
    uint32_t target_pid = 0;
    int reload = 0;
    if (_wcsicmp(ctx.cmd.c_str(), L"reload") == 0) {
        reload = 1;
    }
    const wchar_t* path = ctx.argv[3];
    for (int i = 4; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--target-pid") == 0 && i + 1 < ctx.argc) {
            target_pid = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
        } else if (wcscmp(ctx.argv[i], L"--reload") == 0) {
            reload = 1;
        }
    }
    wchar_t full[MAX_PATH];
    GetFullPathNameW(path, MAX_PATH, full, nullptr);
    AppendPod(req, static_cast<uint32_t>(OpUnloadDll));
    AppendPod(req, target_pid);
    AppendPod(req, static_cast<int32_t>(reload));
    AppendWString(req, full);
    if (!ctx.client.Request(req, resp)) return 1;
    Reader r(resp);
    int32_t st = 0;
    uint64_t base = 0;
    if (!r.TakePod(st) || !r.TakePod(base)) return 1;
    wprintf(L"status=%ls base=%016llx reload=%d\n", StatusName(st),
            static_cast<unsigned long long>(base), reload);
    return st == HDL_OK ? 0 : 1;
}

