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

CommandResult CmdPing(CmdCtx& ctx) {
    hdl::rpc::ControlClient client(&ctx.client);
    const auto result = client.Ping({});
    if (!result.has_response)
        return FailIpc(ctx);
    JsonWriter writer;
    writer.BeginObject();
    writer.Key("remote_pid");
    writer.Num(result.response.pid());
    writer.EndObject();
    return CmdStatus(L"ping", result.status.hdl_status(), writer.Take());
}

CommandResult CmdLog(CmdCtx& ctx) {
    if (ctx.argc < 4)
        return FailUsage(ctx);
    hdl::rpc::v1::SetLogLevelRequest request;
    request.set_level(static_cast<hdl::rpc::v1::LogLevel>(_wtoi(ctx.argv[3])));
    const auto result = hdl::rpc::ControlClient(&ctx.client).SetLogLevel(request);
    if (!result.has_response)
        return FailIpc(ctx);
    return CmdStatus(L"log", result.status.hdl_status(), "{}");
}

CommandResult CmdLogFile(CmdCtx& ctx) {
    const wchar_t* path = ctx.argc >= 4 ? ctx.argv[3] : L"";
    std::string utf8;
    if (!WideToUtf8(path, &utf8))
        return FailArg(ctx, L"path is not valid Unicode");
    hdl::rpc::v1::SetLogFileRequest request;
    request.set_path(std::move(utf8));
    const auto result = hdl::rpc::ControlClient(&ctx.client).SetLogFile(request);
    if (!result.has_response)
        return FailIpc(ctx);
    JsonWriter writer;
    writer.BeginObject();
    writer.Key("path");
    writer.Str(path);
    writer.EndObject();
    return CmdStatus(L"log-file", result.status.hdl_status(), writer.Take());
}

CommandResult CmdHealthVeh(CmdCtx& ctx) {
    if (ctx.argc < 4)
        return FailUsage(ctx);
    if (_wcsicmp(ctx.argv[3], L"status") == 0) {
        const auto result = hdl::rpc::ControlClient(&ctx.client).GetHealthVeh({});
        if (!result.has_response)
            return FailIpc(ctx);
        JsonWriter writer;
        writer.BeginObject();
        writer.Key("enabled");
        writer.Bool(result.response.enabled());
        writer.EndObject();
        return CmdStatus(L"health-veh", result.status.hdl_status(), writer.Take());
    }
    bool enabled = false;
    if (_wcsicmp(ctx.argv[3], L"on") == 0 || wcscmp(ctx.argv[3], L"1") == 0) {
        enabled = true;
    } else if (_wcsicmp(ctx.argv[3], L"off") != 0 && wcscmp(ctx.argv[3], L"0") != 0) {
        return FailUsage(ctx);
    }
    hdl::rpc::v1::SetHealthVehRequest request;
    request.set_enabled(enabled);
    const auto result = hdl::rpc::ControlClient(&ctx.client).SetHealthVeh(request);
    if (!result.has_response)
        return FailIpc(ctx);
    JsonWriter writer;
    writer.BeginObject();
    writer.Key("enabled");
    writer.Bool(enabled);
    writer.EndObject();
    return CmdStatus(L"health-veh", result.status.hdl_status(), writer.Take());
}

CommandResult CmdModules(CmdCtx& ctx) {
    bool stream_requested = false;
    for (int i = 3; i < ctx.argc; ++i)
        stream_requested |= wcscmp(ctx.argv[i], L"--stream") == 0;
    std::vector<hdl::rpc::v1::ModuleInfo> modules;
    const auto status =
        hdl::rpc::ProcessClient(&ctx.client)
            .EnumModules({}, [&modules](const hdl::rpc::v1::EnumModulesResponse& batch) {
                modules.insert(modules.end(), batch.modules().begin(), batch.modules().end());
                return true;
            });
    JsonWriter writer;
    writer.BeginObject();
    writer.Key(stream_requested ? "total" : "count");
    writer.Num(modules.size());
    writer.Key("modules");
    writer.BeginArray();
    for (const auto& module : modules) {
        writer.BeginObject();
        writer.Key("base");
        writer.HexStr(module.base());
        writer.Key("size");
        writer.HexStr(module.size());
        writer.Key("path");
        writer.Str(module.path());
        writer.EndObject();
    }
    writer.EndArray();
    writer.EndObject();
    return CmdStatus(L"modules", status.hdl_status(), writer.Take());
}

CommandResult CmdRegions(CmdCtx& ctx) {
    bool stream_requested = false;
    for (int i = 3; i < ctx.argc; ++i)
        stream_requested |= wcscmp(ctx.argv[i], L"--stream") == 0;
    std::vector<hdl::rpc::v1::RegionInfo> regions;
    const auto status =
        hdl::rpc::ProcessClient(&ctx.client)
            .EnumRegions({}, [&regions](const hdl::rpc::v1::EnumRegionsResponse& batch) {
                regions.insert(regions.end(), batch.regions().begin(), batch.regions().end());
                return true;
            });
    JsonWriter writer;
    writer.BeginObject();
    writer.Key(stream_requested ? "total" : "count");
    writer.Num(regions.size());
    writer.Key("regions");
    writer.BeginArray();
    for (const auto& region : regions) {
        writer.BeginObject();
        writer.Key("base");
        writer.HexStr(region.base());
        writer.Key("size");
        writer.HexStr(region.size());
        writer.Key("protect");
        writer.Num(region.protection());
        writer.EndObject();
    }
    writer.EndArray();
    writer.EndObject();
    return CmdStatus(L"regions", status.hdl_status(), writer.Take());
}

CommandResult CmdThreads(CmdCtx& ctx) {
    bool stream_requested = false;
    for (int i = 3; i < ctx.argc; ++i)
        stream_requested |= wcscmp(ctx.argv[i], L"--stream") == 0;
    std::vector<hdl::rpc::v1::ThreadInfo> threads;
    const auto status =
        hdl::rpc::ProcessClient(&ctx.client)
            .EnumThreads({}, [&threads](const hdl::rpc::v1::EnumThreadsResponse& batch) {
                threads.insert(threads.end(), batch.threads().begin(), batch.threads().end());
                return true;
            });
    JsonWriter writer;
    writer.BeginObject();
    writer.Key(stream_requested ? "total" : "count");
    writer.Num(threads.size());
    writer.Key("threads");
    writer.BeginArray();
    for (const auto& thread : threads) {
        writer.BeginObject();
        writer.Key("tid");
        writer.Num(thread.tid());
        writer.Key("start_address");
        writer.HexStr(thread.start_address());
        if (!stream_requested) {
            writer.Key("user_time_100ns");
            writer.Num(thread.user_time_100ns());
            writer.Key("kernel_time_100ns");
            writer.Num(thread.kernel_time_100ns());
        }
        writer.EndObject();
    }
    writer.EndArray();
    writer.EndObject();
    return CmdStatus(L"threads", status.hdl_status(), writer.Take());
}

CommandResult CmdHealth(CmdCtx& ctx) {
    const auto result = hdl::rpc::ProcessClient(&ctx.client).GetHealth({});
    if (!result.has_response)
        return FailIpc(ctx);
    const auto& info = result.response.health();
    JsonWriter writer;
    writer.BeginObject();
    writer.Key("pid");
    writer.Num(info.pid());
    writer.Key("thread_count");
    writer.Num(info.thread_count());
    writer.Key("handle_count");
    writer.Num(info.handle_count());
    writer.Key("cpu_percent");
    writer.Num(info.cpu_percent());
    writer.Key("gui_hung");
    writer.Num(info.gui_hung());
    writer.Key("flags");
    writer.Num(info.flags());
    writer.Key("working_set");
    writer.Num(info.working_set());
    writer.Key("private_bytes");
    writer.Num(info.private_bytes());
    writer.Key("last_exception_code");
    writer.Num(info.last_exception_code());
    writer.Key("last_exception_addr");
    writer.HexStr(info.last_exception_address());
    writer.EndObject();
    return CmdStatus(L"health", result.status.hdl_status(), writer.Take());
}

static const char* FpCategoryNameNarrow(uint32_t category) {
    switch (category) {
    case HDL_FP_CAT_LANGUAGE:
        return "language";
    case HDL_FP_CAT_RUNTIME:
        return "runtime";
    case HDL_FP_CAT_TOOLCHAIN:
        return "toolchain";
    case HDL_FP_CAT_UI:
        return "ui";
    case HDL_FP_CAT_GRAPHICS:
        return "graphics";
    case HDL_FP_CAT_ENGINE:
        return "engine";
    case HDL_FP_CAT_WEBHOST:
        return "webhost";
    case HDL_FP_CAT_AUDIO:
        return "audio";
    case HDL_FP_CAT_NETWORK:
        return "network";
    case HDL_FP_CAT_TOOLING:
        return "tooling";
    case HDL_FP_CAT_APP:
        return "app";
    default:
        return "?";
    }
}

CommandResult CmdFingerprint(CmdCtx& ctx) {
    uint32_t scan_flags = HDL_FP_SCAN_DEFAULT;
    bool stream_requested = false;
    for (int i = 3; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--stream") == 0)
            stream_requested = true;
        else if (wcscmp(ctx.argv[i], L"--modules-only") == 0)
            scan_flags = HDL_FP_SCAN_MODULES;
        else if (wcscmp(ctx.argv[i], L"--no-imports") == 0)
            scan_flags &= ~HDL_FP_SCAN_IMPORTS;
    }
    hdl::rpc::v1::FingerprintRequest request;
    request.set_scan_flags(scan_flags);
    std::vector<hdl::rpc::v1::FingerprintTag> tags;
    const auto status =
        hdl::rpc::ProcessClient(&ctx.client)
            .Fingerprint(request, [&tags](const hdl::rpc::v1::FingerprintResponse& batch) {
                tags.insert(tags.end(), batch.tags().begin(), batch.tags().end());
                return true;
            });
    JsonWriter writer;
    writer.BeginObject();
    writer.Key(stream_requested ? "total" : "count");
    writer.Num(tags.size());
    writer.Key("tags");
    writer.BeginArray();
    for (const auto& tag : tags) {
        writer.BeginObject();
        writer.Key("primary");
        writer.Bool((tag.flags() & HDL_FP_PRIMARY) != 0);
        writer.Key("category");
        writer.Str(FpCategoryNameNarrow(tag.category()));
        writer.Key("id");
        writer.Str(tag.id());
        writer.Key("confidence");
        writer.Num(tag.confidence());
        writer.Key("flags");
        writer.Num(tag.flags());
        writer.Key("evidence");
        writer.Str(tag.evidence());
        writer.EndObject();
    }
    writer.EndArray();
    writer.EndObject();
    return CmdStatus(L"fingerprint", status.hdl_status(), writer.Take());
}

CommandResult CmdEvents(CmdCtx& ctx) {
    hdl::rpc::v1::PollEventsRequest request;
    request.set_max_events(16);
    for (int i = 3; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--timeout") == 0 && i + 1 < ctx.argc)
            request.set_wait_timeout_ms(_wtoi(ctx.argv[++i]));
        else if (wcscmp(ctx.argv[i], L"--max") == 0 && i + 1 < ctx.argc)
            request.set_max_events(_wtoi(ctx.argv[++i]));
    }
    std::vector<hdl::rpc::v1::Event> events;
    const auto status =
        hdl::rpc::ProcessClient(&ctx.client)
            .PollEvents(request, [&events](const hdl::rpc::v1::PollEventsResponse& batch) {
                events.insert(events.end(), batch.events().begin(), batch.events().end());
                return true;
            });
    JsonWriter writer;
    writer.BeginObject();
    writer.Key("count");
    writer.Num(events.size());
    writer.Key("events");
    writer.BeginArray();
    for (const auto& event : events) {
        writer.BeginObject();
        writer.Key("type");
        writer.Num(event.type());
        writer.Key("code");
        writer.Num(event.code());
        writer.Key("timestamp_ms");
        writer.Num(event.timestamp_ms());
        writer.Key("address");
        writer.HexStr(event.address());
        writer.EndObject();
    }
    writer.EndArray();
    writer.EndObject();
    return CmdStatus(L"events", status.hdl_status(), writer.Take());
}

CommandResult CmdRead(CmdCtx& ctx) {
    if (ctx.argc < 5)
        return FailUsage(ctx);
    uint64_t address = 0, size = 0;
    if (!ParseHexU64(ctx.argv[3], &address) || !ParseHexU64(ctx.argv[4], &size) ||
        size > UINT32_MAX)
        return CmdFail(L"read", HDL_E_INVALID_ARG, L"bad address/size");
    hdl::rpc::v1::ReadMemoryRequest request;
    request.set_address(address);
    request.set_size(static_cast<uint32_t>(size));
    const auto result = hdl::rpc::MemoryClient(&ctx.client).ReadMemory(request);
    if (!result.has_response)
        return FailIpc(ctx);
    const std::string& bytes = result.response.data();
    std::string hex;
    hex.reserve(bytes.size() * 2);
    for (unsigned char byte : bytes) {
        char value[3];
        snprintf(value, sizeof(value), "%02X", byte);
        hex += value;
    }
    JsonWriter writer;
    writer.BeginObject();
    writer.Key("address");
    writer.HexStr(address);
    writer.Key("bytes");
    writer.Num(bytes.size());
    writer.Key("hex");
    writer.Str(hex);
    writer.EndObject();
    return CmdStatus(L"read", result.status.hdl_status(), writer.Take());
}

CommandResult CmdWrite(CmdCtx& ctx) {
    if (ctx.argc < 5)
        return FailUsage(ctx);
    uint64_t address = 0;
    if (!ParseHexU64(ctx.argv[3], &address))
        return CmdFail(L"write", HDL_E_INVALID_ARG, L"bad address");
    std::vector<uint8_t> bytes;
    if (ctx.argv[4][0] == L'@') {
        HANDLE file = CreateFileW(ctx.argv[4] + 1, GENERIC_READ, FILE_SHARE_READ, nullptr,
                                  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE)
            return CmdFail(L"write", HDL_E_NOT_FOUND, L"failed to open file");
        LARGE_INTEGER size{};
        if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 || size.QuadPart > 16 * 1024 * 1024) {
            CloseHandle(file);
            return CmdFail(L"write", HDL_E_INVALID_ARG, L"bad file size");
        }
        bytes.resize(static_cast<size_t>(size.QuadPart));
        DWORD read = 0;
        const BOOL ok =
            ReadFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &read, nullptr);
        CloseHandle(file);
        if (!ok || read != bytes.size())
            return CmdFail(L"write", HDL_E_FAILED, L"failed to read file");
    } else if (!ParseHexBytes(ctx.argv[4], bytes) || bytes.empty()) {
        return CmdFail(L"write", HDL_E_INVALID_ARG, L"bad hex bytes (or use @file)");
    }
    hdl::rpc::v1::WriteMemoryRequest request;
    request.set_address(address);
    request.set_data(bytes.data(), bytes.size());
    const auto result = hdl::rpc::MemoryClient(&ctx.client).WriteMemory(request);
    if (!result.has_response)
        return FailIpc(ctx);
    JsonWriter writer;
    writer.BeginObject();
    writer.Key("address");
    writer.HexStr(address);
    writer.Key("wrote");
    writer.Num(result.response.bytes_written());
    writer.EndObject();
    return CmdStatus(L"write", result.status.hdl_status(), writer.Take());
}
