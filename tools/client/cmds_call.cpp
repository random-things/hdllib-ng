#include "cmd.hpp"
#include "cmd_fail.hpp"
#include "json_out.hpp"
#include "rpc_helpers.hpp"
#include "usage.hpp"
#include "util.hpp"

#include "hdl/rpc/v1/services.rpc.hpp"
#include "hdllib/hdllib.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <cstdio>
#include <string>
#include <vector>

namespace {

bool EncodeCallArgument(const wchar_t* text, hdl::rpc::v1::CallArgument* argument) {
    if (!text || !argument)
        return false;
    if (wcsncmp(text, L"u64:", 4) == 0)
        argument->set_unsigned_value(_wcstoui64(text + 4, nullptr, 0));
    else if (wcsncmp(text, L"i64:", 4) == 0)
        argument->set_signed_value(_wcstoi64(text + 4, nullptr, 0));
    else if (wcsncmp(text, L"f32:", 4) == 0)
        argument->set_float_value(static_cast<float>(_wtof(text + 4)));
    else if (wcsncmp(text, L"f64:", 4) == 0)
        argument->set_double_value(_wtof(text + 4));
    else if (wcsncmp(text, L"ptr:", 4) == 0)
        argument->set_pointer_value(_wcstoui64(text + 4, nullptr, 0));
    else if (wcsncmp(text, L"cstr:", 5) == 0) {
        std::string value;
        if (!WideToUtf8(text + 5, &value))
            return false;
        argument->set_narrow_string(std::move(value));
    } else if (wcsncmp(text, L"wstr:", 5) == 0) {
        std::string value;
        if (!WideToUtf8(text + 5, &value))
            return false;
        argument->set_wide_string(std::move(value));
    } else if (wcsncmp(text, L"buf:", 4) == 0) {
        std::vector<uint8_t> value;
        if (!ParseHexBytes(text + 4, value) || value.empty())
            return false;
        argument->set_buffer(value.data(), value.size());
    } else
        return false;
    return true;
}

CommandResult PrintCallReply(const wchar_t* verb, const hdl::rpc::Status& status,
                             const hdl::rpc::v1::CallResult& result) {
    JsonWriter writer;
    writer.BeginObject();
    writer.Key("return");
    writer.HexStr(result.return_value());
    writer.Key("last_error");
    writer.Num(result.last_error());
    if (!result.buffer_copy_outs().empty()) {
        writer.Key("bufs");
        writer.BeginArray();
        for (const auto& copy : result.buffer_copy_outs()) {
            std::string hex;
            hex.reserve(copy.data().size() * 2);
            for (unsigned char byte : copy.data()) {
                char value[3];
                snprintf(value, sizeof(value), "%02x", byte);
                hex += value;
            }
            writer.BeginObject();
            writer.Key("index");
            writer.Num(copy.argument_index());
            writer.Key("hex");
            writer.Str(hex);
            writer.EndObject();
        }
        writer.EndArray();
    }
    writer.EndObject();
    return CmdStatus(verb, status.hdl_status(), writer.Take());
}

} // namespace

CommandResult CmdResolve(CmdCtx& ctx) {
    std::wstring module;
    const wchar_t* export_name = nullptr;
    for (int i = 3; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--module") == 0 && i + 1 < ctx.argc)
            module = ctx.argv[++i];
        else if (!export_name)
            export_name = ctx.argv[i];
    }
    if (!export_name)
        return FailUsage(ctx);
    std::string module_utf8, name;
    if (!WideToUtf8(module, &module_utf8) || !WideToUtf8(export_name, &name))
        return FailArg(ctx, L"invalid name");
    hdl::rpc::v1::ResolveExportRequest request;
    request.set_module(std::move(module_utf8));
    request.set_name(std::move(name));
    const auto result = hdl::rpc::CallClient(&ctx.client).ResolveExport(request);
    if (!result.has_response)
        return FailIpc(ctx);
    JsonWriter writer;
    writer.BeginObject();
    writer.Key("addr");
    writer.HexStr(result.response.address());
    writer.EndObject();
    return CmdStatus(L"resolve", result.status.hdl_status(), writer.Take());
}

CommandResult CmdCall(CmdCtx& ctx) {
    std::wstring module;
    const wchar_t* export_name = nullptr;
    uint64_t address = 0;
    bool have_address = false;
    bool main_thread = false;
    uint32_t timeout = 0;
    std::vector<std::wstring> arguments;
    for (int i = 3; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--module") == 0 && i + 1 < ctx.argc)
            module = ctx.argv[++i];
        else if (wcscmp(ctx.argv[i], L"--addr") == 0 && i + 1 < ctx.argc) {
            address = _wcstoui64(ctx.argv[++i], nullptr, 0);
            have_address = true;
        } else if (wcscmp(ctx.argv[i], L"--main") == 0)
            main_thread = true;
        else if (wcscmp(ctx.argv[i], L"--timeout") == 0 && i + 1 < ctx.argc)
            timeout = _wtoi(ctx.argv[++i]);
        else if (!have_address && !export_name)
            export_name = ctx.argv[i];
        else
            arguments.emplace_back(ctx.argv[i]);
    }
    if (!have_address && !export_name)
        return FailUsage(ctx);
    hdl::rpc::CallOptions options{timeout};
    hdl::rpc::CallClient client(&ctx.client);
    if (have_address) {
        hdl::rpc::v1::CallRequest request;
        request.set_address(address);
        request.set_thread_mode(main_thread ? hdl::rpc::v1::CALL_THREAD_MODE_MAIN
                                            : hdl::rpc::v1::CALL_THREAD_MODE_WORKER);
        for (const auto& text : arguments)
            if (!EncodeCallArgument(text.c_str(), request.add_arguments()))
                return FailArg(ctx, text.c_str());
        const auto result = client.Call(request, options);
        if (!result.has_response)
            return FailIpc(ctx);
        return PrintCallReply(L"call", result.status, result.response.result());
    }
    std::string module_utf8, name;
    if (!WideToUtf8(module, &module_utf8) || !WideToUtf8(export_name, &name))
        return FailArg(ctx, L"invalid name");
    hdl::rpc::v1::CallExportRequest request;
    request.set_module(std::move(module_utf8));
    request.set_name(std::move(name));
    for (const auto& text : arguments)
        if (!EncodeCallArgument(text.c_str(), request.add_arguments()))
            return FailArg(ctx, text.c_str());
    const auto result = client.CallExport(request, options);
    if (!result.has_response)
        return FailIpc(ctx);
    return PrintCallReply(L"call", result.status, result.response.result());
}

CommandResult CmdVcall(CmdCtx& ctx) {
    if (ctx.argc < 5)
        return FailUsage(ctx);
    hdl::rpc::v1::CallVtableRequest request;
    request.set_object(_wcstoui64(ctx.argv[3], nullptr, 0));
    request.set_index(_wtoi(ctx.argv[4]));
    request.set_prepend_this(true);
    request.set_thread_mode(hdl::rpc::v1::CALL_THREAD_MODE_WORKER);
    uint32_t timeout = 0;
    std::vector<std::wstring> arguments;
    for (int i = 5; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--main") == 0)
            request.set_thread_mode(hdl::rpc::v1::CALL_THREAD_MODE_MAIN);
        else if (wcscmp(ctx.argv[i], L"--no-this") == 0)
            request.set_prepend_this(false);
        else if (wcscmp(ctx.argv[i], L"--timeout") == 0 && i + 1 < ctx.argc)
            timeout = _wtoi(ctx.argv[++i]);
        else
            arguments.emplace_back(ctx.argv[i]);
    }
    for (const auto& text : arguments)
        if (!EncodeCallArgument(text.c_str(), request.add_arguments()))
            return FailArg(ctx, text.c_str());
    const auto result = hdl::rpc::CallClient(&ctx.client).CallVtable(request, {timeout});
    if (!result.has_response)
        return FailIpc(ctx);
    return PrintCallReply(L"vcall", result.status, result.response.result());
}

CommandResult CmdAlloc(CmdCtx& ctx) {
    if (ctx.argc < 4)
        return FailUsage(ctx);
    hdl::rpc::v1::AllocRequest request;
    request.set_size(_wcstoui64(ctx.argv[3], nullptr, 0));
    request.set_protection(PAGE_READWRITE);
    for (int i = 4; i < ctx.argc; ++i)
        if (wcscmp(ctx.argv[i], L"--protect") == 0 && i + 1 < ctx.argc)
            request.set_protection(_wcsicmp(ctx.argv[++i], L"RWX") == 0 ? PAGE_EXECUTE_READWRITE
                                                                        : PAGE_READWRITE);
    const auto result = hdl::rpc::MemoryClient(&ctx.client).Alloc(request);
    if (!result.has_response)
        return FailIpc(ctx);
    JsonWriter writer;
    writer.BeginObject();
    writer.Key("addr");
    writer.HexStr(result.response.address());
    writer.EndObject();
    return CmdStatus(L"alloc", result.status.hdl_status(), writer.Take());
}

CommandResult CmdFree(CmdCtx& ctx) {
    if (ctx.argc < 4)
        return FailUsage(ctx);
    hdl::rpc::v1::FreeRequest request;
    request.set_address(_wcstoui64(ctx.argv[3], nullptr, 0));
    const auto result = hdl::rpc::MemoryClient(&ctx.client).Free(request);
    return result.has_response ? CmdStatus(L"free", result.status.hdl_status(), "{}")
                               : FailIpc(ctx);
}
