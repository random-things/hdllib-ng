#include "cmd.hpp"
#include "cmd_fail.hpp"
#include "json_out.hpp"
#include "rpc_helpers.hpp"
#include "session_modules.hpp"
#include "usage.hpp"
#include "util.hpp"

#include "hdl/rpc/v1/services.rpc.hpp"
#include "hdllib/hdllib.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <string>

namespace {

bool ParseInjectionMethod(const wchar_t* value, hdl::rpc::v1::InjectionMethod* output) {
    static constexpr const wchar_t* names[] = {L"create_remote_thread",
                                               L"nt_create_thread_ex",
                                               L"rtl_create_user_thread",
                                               L"queue_user_apc",
                                               L"set_windows_hook_ex",
                                               L"thread_hijack",
                                               L"manual_map",
                                               L"early_bird_apc",
                                               L"atom_bombing",
                                               L"module_stomp",
                                               L"section_map",
                                               L"window_subclass",
                                               L"instrumentation_callback",
                                               L"kernel_callback_table",
                                               L"veh",
                                               L"set_win_event_hook",
                                               L"rtl_remote_call",
                                               L"special_user_apc",
                                               L"thread_pool",
                                               L"etw_callback"};
    for (int index = 0; index < static_cast<int>(std::size(names)); ++index) {
        if (_wcsicmp(value, names[index]) == 0) {
            *output = static_cast<hdl::rpc::v1::InjectionMethod>(index);
            return true;
        }
    }
    return false;
}

void TrackRemote(PipeClient& client, uint64_t base, const std::wstring& path) {
    hdl::rpc::v1::TrackLoadedDllRequest request;
    request.set_base(base);
    request.set_dll_path(WideToUtf8(path));
    (void)hdl::rpc::InjectionClient(&client).TrackLoadedDll(request);
}

} // namespace

CommandResult CmdInject(CmdCtx& ctx) {
    if (ctx.argc < 4)
        return FailUsage(ctx);
    hdl::rpc::v1::InjectDllRequest request;
    request.set_method(hdl::rpc::v1::INJECTION_METHOD_CREATE_REMOTE_THREAD);
    const wchar_t* path = ctx.argv[3];
    std::wstring executable;
    for (int i = 4; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--target-pid") == 0 && i + 1 < ctx.argc)
            request.set_pid(_wtoi(ctx.argv[++i]));
        else if (wcscmp(ctx.argv[i], L"--method") == 0 && i + 1 < ctx.argc) {
            hdl::rpc::v1::InjectionMethod method;
            if (!ParseInjectionMethod(ctx.argv[++i], &method))
                return CmdFail(ctx.cmd.c_str(), HDL_E_INVALID_ARG, L"unknown inject method");
            request.set_method(method);
        } else if (wcscmp(ctx.argv[i], L"--exe") == 0 && i + 1 < ctx.argc)
            executable = ctx.argv[++i];
        else if (wcscmp(ctx.argv[i], L"--hook-export") == 0 && i + 1 < ctx.argc)
            request.set_hook_export(WideToUtf8(ctx.argv[++i]));
    }
    wchar_t full[MAX_PATH]{};
    GetFullPathNameW(path, MAX_PATH, full, nullptr);
    request.set_dll_path(WideToUtf8(full));
    if (!executable.empty()) {
        wchar_t full_exe[MAX_PATH]{};
        GetFullPathNameW(executable.c_str(), MAX_PATH, full_exe, nullptr);
        request.set_executable_path(WideToUtf8(full_exe));
    }
    const auto result = hdl::rpc::InjectionClient(&ctx.client).InjectDll(request);
    const uint64_t base = result.has_response ? result.response.base() : 0;
    const uint32_t out_pid = result.has_response ? result.response.out_pid() : 0;
    if (result.status.ok() && base) {
        const uint32_t track_pid = out_pid ? out_pid : (request.pid() ? request.pid() : ctx.pid);
        hdlcli::RememberInjectedModule(track_pid, full, base);
        if (track_pid == ctx.pid)
            TrackRemote(ctx.client, base, full);
    }
    JsonWriter writer;
    writer.BeginObject();
    writer.Key("base");
    writer.HexStr(base);
    writer.Key("out_pid");
    writer.Num(out_pid);
    writer.EndObject();
    return CmdStatus(ctx.cmd.c_str(), result.status.hdl_status(), writer.Take());
}

CommandResult CmdShutdown(CmdCtx& ctx) {
    hdl::rpc::v1::ShutdownRequest request;
    for (int i = 3; i < ctx.argc; ++i)
        if (wcscmp(ctx.argv[i], L"--modules") == 0)
            request.set_flags(request.flags() | HDL_SHUTDOWN_UNLOAD_MODULES);
    if (request.flags() & HDL_SHUTDOWN_UNLOAD_MODULES)
        for (const auto& module : hdlcli::ListInjectedModules(ctx.pid))
            TrackRemote(ctx.client, module.base, module.path);
    const auto result = hdl::rpc::ControlClient(&ctx.client).Shutdown(request);
    if (result.status.ok())
        hdlcli::ClearInjectedModules(ctx.pid);
    JsonWriter writer;
    writer.BeginObject();
    writer.Key("flags");
    writer.Num(request.flags());
    writer.EndObject();
    return CmdStatus(L"shutdown", result.status.hdl_status(), writer.Take());
}

CommandResult CmdUnload(CmdCtx& ctx) {
    if (ctx.argc < 4)
        return FailUsage(ctx);
    hdl::rpc::v1::UnloadDllRequest request;
    request.set_reload(_wcsicmp(ctx.cmd.c_str(), L"reload") == 0);
    for (int i = 4; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--target-pid") == 0 && i + 1 < ctx.argc)
            request.set_pid(_wtoi(ctx.argv[++i]));
        else if (wcscmp(ctx.argv[i], L"--reload") == 0)
            request.set_reload(true);
    }
    wchar_t full[MAX_PATH]{};
    GetFullPathNameW(ctx.argv[3], MAX_PATH, full, nullptr);
    request.set_dll_path(WideToUtf8(full));
    const auto result = hdl::rpc::InjectionClient(&ctx.client).UnloadDll(request);
    JsonWriter writer;
    writer.BeginObject();
    writer.Key("base");
    writer.HexStr(result.has_response ? result.response.base() : 0);
    writer.Key("reload");
    writer.Bool(request.reload());
    writer.EndObject();
    return CmdStatus(request.reload() ? L"reload" : L"unload", result.status.hdl_status(),
                     writer.Take());
}
