#include "cmd.hpp"
#include "cmd_fail.hpp"
#include "json_out.hpp"
#include "rpc_helpers.hpp"
#include "usage.hpp"

#include "hdl/rpc/v1/services.rpc.hpp"
#include "hdllib/hdllib.h"

#include <string>
#include <vector>

CommandResult CmdHooktrace(CmdCtx& ctx) {
    if (ctx.argc < 4)
        return FailUsage(ctx);
    hdl::rpc::v1::HookTraceRequest request;
    request.set_target(_wcstoui64(ctx.argv[3], nullptr, 0));
    for (int i = 4; i < ctx.argc; ++i)
        if (wcscmp(ctx.argv[i], L"--args") == 0 && i + 1 < ctx.argc)
            request.set_argument_count(_wtoi(ctx.argv[++i]));
    const auto result = hdl::rpc::HookClient(&ctx.client).HookTrace(request);
    if (!result.has_response)
        return FailIpc(ctx);
    JsonWriter writer;
    writer.BeginObject();
    writer.Key("handle");
    writer.HexStr(result.response.handle());
    writer.EndObject();
    return CmdStatus(L"hooktrace", result.status.hdl_status(), writer.Take());
}

CommandResult CmdHook(CmdCtx& ctx) {
    if (ctx.argc < 5)
        return FailUsage(ctx);
    for (int i = 5; i < ctx.argc; ++i)
        if (wcscmp(ctx.argv[i], L"--flags") == 0 && i + 1 < ctx.argc && _wtoi(ctx.argv[++i]) != 0)
            return FailUsage(ctx);
    hdl::rpc::v1::HookRequest request;
    request.set_target(_wcstoui64(ctx.argv[3], nullptr, 0));
    request.set_detour(_wcstoui64(ctx.argv[4], nullptr, 0));
    const auto result = hdl::rpc::HookClient(&ctx.client).Hook(request);
    if (!result.has_response)
        return FailIpc(ctx);
    JsonWriter writer;
    writer.BeginObject();
    writer.Key("handle");
    writer.HexStr(result.response.handle());
    writer.Key("trampoline");
    writer.HexStr(result.response.trampoline());
    writer.EndObject();
    return CmdStatus(L"hook", result.status.hdl_status(), writer.Take());
}

CommandResult CmdUnhook(CmdCtx& ctx) {
    if (ctx.argc < 4)
        return FailUsage(ctx);
    hdl::rpc::v1::UnhookRequest request;
    request.set_handle(_wcstoui64(ctx.argv[3], nullptr, 0));
    const auto result = hdl::rpc::HookClient(&ctx.client).Unhook(request);
    return result.has_response ? CmdStatus(L"unhook", result.status.hdl_status(), "{}")
                               : FailIpc(ctx);
}

CommandResult CmdHookEnable(CmdCtx& ctx) {
    if (ctx.argc < 5)
        return FailUsage(ctx);
    hdl::rpc::v1::EnableHookRequest request;
    request.set_handle(_wcstoui64(ctx.argv[3], nullptr, 0));
    request.set_enabled(_wtoi(ctx.argv[4]) != 0);
    const auto result = hdl::rpc::HookClient(&ctx.client).EnableHook(request);
    return result.has_response ? CmdStatus(L"hook-enable", result.status.hdl_status(), "{}")
                               : FailIpc(ctx);
}

CommandResult CmdHookhits(CmdCtx& ctx) {
    hdl::rpc::v1::PollHookHitsRequest request;
    request.set_max_hits(16);
    for (int i = 3; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--timeout") == 0 && i + 1 < ctx.argc)
            request.set_wait_timeout_ms(_wtoi(ctx.argv[++i]));
        else if (wcscmp(ctx.argv[i], L"--max") == 0 && i + 1 < ctx.argc)
            request.set_max_hits(_wtoi(ctx.argv[++i]));
    }
    std::vector<hdl::rpc::v1::HookHit> hits;
    const auto status =
        hdl::rpc::HookClient(&ctx.client)
            .PollHookHits(request, [&hits](const hdl::rpc::v1::PollHookHitsResponse& batch) {
                hits.insert(hits.end(), batch.hits().begin(), batch.hits().end());
                return true;
            });
    JsonWriter writer;
    writer.BeginObject();
    writer.Key("count");
    writer.Num(hits.size());
    writer.Key("hits");
    writer.BeginArray();
    for (const auto& hit : hits) {
        writer.BeginObject();
        writer.Key("hook_id");
        writer.HexStr(hit.hook_id());
        writer.Key("return_value");
        writer.HexStr(hit.return_value());
        writer.Key("caller");
        writer.HexStr(hit.caller());
        writer.Key("args");
        writer.BeginArray();
        for (uint64_t arg : hit.arguments())
            writer.HexStr(arg);
        writer.EndArray();
        writer.EndObject();
    }
    writer.EndArray();
    writer.EndObject();
    return CmdStatus(L"hookhits", status.hdl_status(), writer.Take());
}

CommandResult CmdHookImport(CmdCtx& ctx) {
    if (ctx.argc < 4)
        return FailUsage(ctx);
    hdl::rpc::v1::HookImportRequest request;
    std::wstring module;
    std::wstring value = ctx.argv[3];
    const size_t bang = value.find(L'!');
    if (bang != std::wstring::npos) {
        std::string dll, name;
        if (!WideToUtf8(value.substr(0, bang), &dll) || !WideToUtf8(value.substr(bang + 1), &name))
            return FailArg(ctx, L"bad DLL!Name");
        request.set_dll(std::move(dll));
        request.set_import_name(std::move(name));
    } else {
        for (int i = 3; i < ctx.argc; ++i) {
            std::string text;
            if (wcscmp(ctx.argv[i], L"--dll") == 0 && i + 1 < ctx.argc) {
                if (!WideToUtf8(ctx.argv[++i], &text))
                    return FailArg(ctx, L"bad DLL");
                request.set_dll(std::move(text));
            } else if (wcscmp(ctx.argv[i], L"--import") == 0 && i + 1 < ctx.argc) {
                if (!WideToUtf8(ctx.argv[++i], &text))
                    return FailArg(ctx, L"bad import");
                request.set_import_name(std::move(text));
            } else if (wcscmp(ctx.argv[i], L"--module") == 0 && i + 1 < ctx.argc)
                module = ctx.argv[++i];
            else if (wcscmp(ctx.argv[i], L"--args") == 0 && i + 1 < ctx.argc)
                request.set_argument_count(_wtoi(ctx.argv[++i]));
        }
    }
    if (request.dll().empty() || request.import_name().empty())
        return CmdFail(L"hook-import", HDL_E_INVALID_ARG,
                       L"need hook-import DLL!Name or --dll X --import Y");
    std::string module_utf8;
    if (!WideToUtf8(module, &module_utf8))
        return FailArg(ctx, L"bad module");
    request.set_module(std::move(module_utf8));
    const auto result = hdl::rpc::HookClient(&ctx.client).HookImport(request);
    if (!result.has_response)
        return FailIpc(ctx);
    JsonWriter writer;
    writer.BeginObject();
    writer.Key("handle");
    writer.HexStr(result.response.handle());
    writer.EndObject();
    return CmdStatus(L"hook-import", result.status.hdl_status(), writer.Take());
}
