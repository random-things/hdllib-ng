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
#include <limits>
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

const char* CallPhaseName(hdl::rpc::v1::CallPhase phase) {
    switch (phase) {
    case hdl::rpc::v1::CALL_PHASE_QUEUED:
        return "queued";
    case hdl::rpc::v1::CALL_PHASE_RUNNING:
        return "running";
    case hdl::rpc::v1::CALL_PHASE_COMPLETED:
        return "completed";
    case hdl::rpc::v1::CALL_PHASE_CANCELLED_BEFORE_START:
        return "cancelled_before_start";
    default:
        return "unknown";
    }
}

uint32_t TransportTimeout(uint32_t wait_timeout_ms) {
    if (!wait_timeout_ms)
        return 0;
    constexpr uint32_t kReplyAllowanceMs = 1000;
    return wait_timeout_ms > (std::numeric_limits<uint32_t>::max)() - kReplyAllowanceMs
               ? (std::numeric_limits<uint32_t>::max)()
               : wait_timeout_ms + kReplyAllowanceMs;
}

bool ParseCallId(const wchar_t* value, uint64_t* call_id) {
    if (!value || !call_id)
        return false;
    wchar_t* end = nullptr;
    *call_id = _wcstoui64(value, &end, 0);
    return end != value && *end == L'\0' && *call_id != 0;
}

void WriteCallInfo(JsonWriter& writer, const hdl::rpc::v1::CallInfo& call) {
    writer.BeginObject();
    writer.Key("call_id");
    writer.Num(call.call_id());
    writer.Key("target_address");
    writer.HexStr(call.target_address());
    writer.Key("phase");
    writer.Str(CallPhaseName(call.phase()));
    writer.Key("orphaned");
    writer.Bool(call.orphaned());
    writer.Key("acknowledged");
    writer.Bool(call.acknowledged());
    writer.Key("thread_id");
    writer.Num(call.thread_id());
    writer.Key("thread_mode");
    writer.Str(call.thread_mode() == hdl::rpc::v1::CALL_THREAD_MODE_MAIN ? "main" : "worker");
    writer.Key("created_tick_ms");
    writer.Num(call.created_tick_ms());
    writer.Key("started_tick_ms");
    writer.Num(call.started_tick_ms());
    writer.Key("finished_tick_ms");
    writer.Num(call.finished_tick_ms());
    writer.Key("wait_status");
    writer.Num(call.wait_status());
    writer.Key("completion_status");
    writer.Num(call.completion_status());
    writer.Key("return");
    writer.HexStr(call.return_value());
    writer.Key("last_error");
    writer.Num(call.last_error());
    writer.EndObject();
}

CommandResult CmdCallLifecycle(CmdCtx& ctx) {
    hdl::rpc::CallClient client(&ctx.client);
    if (wcscmp(ctx.argv[3], L"status") == 0) {
        if (ctx.argc == 4) {
            std::vector<hdl::rpc::v1::CallInfo> calls;
            const auto status = client.EnumOrphans(
                hdl::rpc::v1::Empty{}, [&calls](const hdl::rpc::v1::EnumOrphansResponse& response) {
                    calls.insert(calls.end(), response.calls().begin(), response.calls().end());
                    return true;
                });
            JsonWriter writer;
            writer.BeginObject();
            writer.Key("count");
            writer.Num(calls.size());
            writer.Key("calls");
            writer.BeginArray();
            for (const auto& call : calls)
                WriteCallInfo(writer, call);
            writer.EndArray();
            writer.EndObject();
            return CmdStatus(L"call status", status.hdl_status(), writer.Take());
        }
        if (ctx.argc != 5)
            return FailUsage(ctx);
        uint64_t call_id = 0;
        if (!ParseCallId(ctx.argv[4], &call_id))
            return FailArg(ctx, L"invalid call id");
        hdl::rpc::v1::GetCallStatusRequest request;
        request.set_call_id(call_id);
        const auto result = client.GetCallStatus(request);
        if (!result.has_response)
            return FailIpc(ctx);
        JsonWriter writer;
        writer.BeginObject();
        writer.Key("call");
        WriteCallInfo(writer, result.response.call());
        writer.EndObject();
        return CmdStatus(L"call status", result.status.hdl_status(), writer.Take());
    }
    if (wcscmp(ctx.argv[3], L"ack") == 0) {
        if (ctx.argc != 5)
            return FailUsage(ctx);
        uint64_t call_id = 0;
        if (!ParseCallId(ctx.argv[4], &call_id))
            return FailArg(ctx, L"invalid call id");
        hdl::rpc::v1::AcknowledgeOrphanRequest request;
        request.set_call_id(call_id);
        const auto result = client.AcknowledgeOrphan(request);
        if (!result.has_response)
            return FailIpc(ctx);
        JsonWriter writer;
        writer.BeginObject();
        writer.Key("call");
        WriteCallInfo(writer, result.response.call());
        writer.EndObject();
        return CmdStatus(L"call ack", result.status.hdl_status(), writer.Take());
    }
    return FailUsage(ctx);
}

CommandResult PrintCallReply(const wchar_t* verb, const hdl::rpc::Status& status,
                             const hdl::rpc::v1::CallResult& result) {
    JsonWriter writer;
    writer.BeginObject();
    writer.Key("return");
    writer.HexStr(result.return_value());
    writer.Key("last_error");
    writer.Num(result.last_error());
    writer.Key("call_id");
    writer.Num(result.call_id());
    writer.Key("phase");
    writer.Str(CallPhaseName(result.phase()));
    writer.Key("orphaned");
    writer.Bool(result.orphaned());
    writer.Key("blocking_call_id");
    writer.Num(result.blocking_call_id());
    writer.Key("unacknowledged_orphan_count");
    writer.Num(result.unacknowledged_orphan_count());
    std::wstring warning;
    if (result.orphaned() && result.call_id()) {
        warning = L"call " + std::to_wstring(result.call_id()) +
                  L" timed out and may still be running; inspect with 'call status " +
                  std::to_wstring(result.call_id()) + L"'";
    } else if (status.hdl_status() == HDL_E_BUSY && result.blocking_call_id()) {
        warning = L"target is occupied by call " + std::to_wstring(result.blocking_call_id()) +
                  L"; wait for completion or explicitly run 'call ack " +
                  std::to_wstring(result.blocking_call_id()) + L"'";
    } else if (status.ok() && result.unacknowledged_orphan_count()) {
        warning = std::to_wstring(result.unacknowledged_orphan_count()) +
                  L" unacknowledged call orphan(s) remain; inspect with 'call status'";
    }
    if (!warning.empty()) {
        writer.Key("warning");
        writer.Str(warning);
    }
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
    CommandResult output = CmdStatus(verb, status.hdl_status(), writer.Take());
    if (!status.ok())
        output.hint = warning;
    return output;
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
    if (ctx.argc >= 4 && (wcscmp(ctx.argv[3], L"status") == 0 || wcscmp(ctx.argv[3], L"ack") == 0))
        return CmdCallLifecycle(ctx);
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
    hdl::rpc::CallOptions options{TransportTimeout(timeout)};
    hdl::rpc::CallClient client(&ctx.client);
    if (have_address) {
        hdl::rpc::v1::CallRequest request;
        request.set_address(address);
        request.set_thread_mode(main_thread ? hdl::rpc::v1::CALL_THREAD_MODE_MAIN
                                            : hdl::rpc::v1::CALL_THREAD_MODE_WORKER);
        request.set_wait_timeout_ms(timeout);
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
    request.set_wait_timeout_ms(timeout);
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
    request.set_wait_timeout_ms(timeout);
    const auto result =
        hdl::rpc::CallClient(&ctx.client).CallVtable(request, {TransportTimeout(timeout)});
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
