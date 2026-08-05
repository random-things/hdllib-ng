#include "cmd.hpp"
#include "cmd_fail.hpp"
#include "json_out.hpp"
#include "usage.hpp"
#include "util.hpp"

#include "hdllib/hdllib.h"
#include "ipc/wire.hpp"
#include "protocol.hpp"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

CommandResult CmdPing(CmdCtx& ctx) {
    using namespace hdl::proto;
    PreparedRequest req;
    std::vector<uint8_t> resp;

    SetMethod(req, hdl::rpc::Method::Ping);
    if (!ctx.client.Request(req, resp)) {
        return FailIpc(ctx);
    }
    Reader r(resp);
    int32_t st = 0;
    uint32_t rpid = 0;
    if (!r.TakePod(st) || !r.TakePod(rpid)) {
        return FailBadResp(ctx);
    }
    JsonWriter w;
    w.BeginObject();
    w.Key("remote_pid");
    w.Num(rpid);
    w.EndObject();
    return CmdStatus(L"ping", st, w.Take());
}

CommandResult CmdLog(CmdCtx& ctx) {
    using namespace hdl::proto;
    PreparedRequest req;
    std::vector<uint8_t> resp;

    if (ctx.argc < 4) {
        return FailUsage(ctx);
    }
    SetMethod(req, hdl::rpc::Method::SetLogLevel);
    AppendPod(req, static_cast<int32_t>(_wtoi(ctx.argv[3])));
    if (!ctx.client.Request(req, resp)) {
        return FailIpc(ctx);
    }
    Reader r(resp);
    int32_t st = 0;
    r.TakePod(st);
    return CmdStatus(L"log", st, "{}");
}

CommandResult CmdLogFile(CmdCtx& ctx) {
    using namespace hdl::proto;
    PreparedRequest req;
    std::vector<uint8_t> resp;

    const wchar_t* path = L"";
    if (ctx.argc >= 4) {
        path = ctx.argv[3];
    }
    SetMethod(req, hdl::rpc::Method::SetLogFile);
    AppendWString(req, path);
    if (!ctx.client.Request(req, resp)) {
        return FailIpc(ctx);
    }
    Reader r(resp);
    int32_t st = 0;
    r.TakePod(st);
    JsonWriter w;
    w.BeginObject();
    w.Key("path");
    w.Str(path && path[0] ? path : L"");
    w.EndObject();
    return CmdStatus(L"log-file", st, w.Take());
}

CommandResult CmdHealthVeh(CmdCtx& ctx) {
    using namespace hdl::proto;
    PreparedRequest req;
    std::vector<uint8_t> resp;

    if (ctx.argc < 4) {
        return FailUsage(ctx);
    }
    const wchar_t* sub = ctx.argv[3];
    if (_wcsicmp(sub, L"status") == 0) {
        SetMethod(req, hdl::rpc::Method::GetHealthVeh);
        if (!ctx.client.Request(req, resp)) {
            return FailIpc(ctx);
        }
        Reader r(resp);
        int32_t st = 0;
        int32_t enabled = 0;
        if (!r.TakePod(st) || !r.TakePod(enabled)) {
            return FailBadResp(ctx);
        }
        JsonWriter w;
        w.BeginObject();
        w.Key("enabled");
        w.Bool(enabled != 0);
        w.EndObject();
        return CmdStatus(L"health-veh", st, w.Take());
    }

    int32_t enabled = -1;
    if (_wcsicmp(sub, L"on") == 0 || wcscmp(sub, L"1") == 0) {
        enabled = 1;
    } else if (_wcsicmp(sub, L"off") == 0 || wcscmp(sub, L"0") == 0) {
        enabled = 0;
    } else {
        return FailUsage(ctx);
    }
    SetMethod(req, hdl::rpc::Method::SetHealthVeh);
    AppendPod(req, enabled);
    if (!ctx.client.Request(req, resp)) {
        return FailIpc(ctx);
    }
    Reader r(resp);
    int32_t st = 0;
    if (!r.TakePod(st)) {
        return FailBadResp(ctx);
    }
    JsonWriter w;
    w.BeginObject();
    w.Key("enabled");
    w.Bool(enabled != 0);
    w.EndObject();
    return CmdStatus(L"health-veh", st, w.Take());
}

CommandResult CmdModules(CmdCtx& ctx) {
    using namespace hdl::proto;
    PreparedRequest req;
    std::vector<uint8_t> resp;

    bool stream = false;
    for (int i = 3; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--stream") == 0) {
            stream = true;
        }
    }
    SetMethod(req, hdl::rpc::Method::EnumModules);
    if (stream) {
        AppendPod(req, static_cast<uint64_t>(0));
        AppendPod(req, static_cast<uint32_t>(0));
        AppendPod(req, static_cast<uint32_t>(HDL_IPC_REQ_STREAM));
        std::vector<HdlModuleInfo> all;
        int32_t final_st = HDL_OK;
        uint32_t total = 0;
        bool bad_resp = false;
        if (!ctx.client.RequestStream(
                req, [&](int32_t st, uint32_t flags, const uint8_t* p, size_t n) {
                    Reader r(p, n);
                    uint32_t tot = 0, off = 0, count = 0;
                    if (!r.TakePod(tot) || !r.TakePod(off) || !r.TakePod(count)) {
                        bad_resp = true;
                        return false;
                    }
                    total = tot;
                    final_st = st;
                    for (uint32_t i = 0; i < count; ++i) {
                        HdlModuleInfo info{};
                        if (!hdl::proto::TakeHdlModuleInfo(r, info)) {
                            bad_resp = true;
                            return false;
                        }
                        all.push_back(info);
                    }
                    (void)flags;
                    return true;
                })) {
            return bad_resp ? FailBadResp(ctx) : FailIpc(ctx);
        }
        JsonWriter w;
        w.BeginObject();
        w.Key("total");
        w.Num(total);
        w.Key("modules");
        w.BeginArray();
        for (const auto& info : all) {
            w.BeginObject();
            w.Key("base");
            w.HexStr(info.base);
            w.Key("size");
            w.HexStr(info.size);
            w.Key("path");
            w.Str(info.path);
            w.EndObject();
        }
        w.EndArray();
        w.EndObject();
        return CmdStatus(L"modules", final_st, w.Take());
    }
    if (!ctx.client.Request(req, resp)) {
        return FailIpc(ctx);
    }
    Reader r(resp);
    int32_t st = 0;
    uint32_t count = 0;
    if (!r.TakePod(st) || !r.TakePod(count)) {
        return FailBadResp(ctx);
    }
    std::vector<HdlModuleInfo> items;
    items.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        HdlModuleInfo info{};
        if (!hdl::proto::TakeHdlModuleInfo(r, info)) {
            return FailBadResp(ctx);
        }
        items.push_back(info);
    }
    JsonWriter w;
    w.BeginObject();
    w.Key("count");
    w.Num(count);
    w.Key("modules");
    w.BeginArray();
    for (const auto& info : items) {
        w.BeginObject();
        w.Key("base");
        w.HexStr(info.base);
        w.Key("size");
        w.HexStr(info.size);
        w.Key("path");
        w.Str(info.path);
        w.EndObject();
    }
    w.EndArray();
    w.EndObject();
    return CmdStatus(L"modules", st, w.Take());
}

CommandResult CmdRegions(CmdCtx& ctx) {
    using namespace hdl::proto;
    PreparedRequest req;
    std::vector<uint8_t> resp;

    bool stream = false;
    for (int i = 3; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--stream") == 0) {
            stream = true;
        }
    }
    SetMethod(req, hdl::rpc::Method::EnumRegions);
    if (stream) {
        AppendPod(req, static_cast<uint64_t>(0));
        AppendPod(req, static_cast<uint32_t>(0));
        AppendPod(req, static_cast<uint32_t>(HDL_IPC_REQ_STREAM));
        std::vector<HdlRegionInfo> all;
        int32_t final_st = HDL_OK;
        uint32_t total = 0;
        bool bad_resp = false;
        if (!ctx.client.RequestStream(req, [&](int32_t st, uint32_t, const uint8_t* p, size_t n) {
                Reader r(p, n);
                uint32_t tot = 0, off = 0, count = 0;
                if (!r.TakePod(tot) || !r.TakePod(off) || !r.TakePod(count)) {
                    bad_resp = true;
                    return false;
                }
                total = tot;
                final_st = st;
                for (uint32_t i = 0; i < count; ++i) {
                    HdlRegionInfo info{};
                    if (!hdl::proto::TakeHdlRegionInfo(r, info)) {
                        bad_resp = true;
                        return false;
                    }
                    all.push_back(info);
                }
                return true;
            })) {
            return bad_resp ? FailBadResp(ctx) : FailIpc(ctx);
        }
        JsonWriter w;
        w.BeginObject();
        w.Key("total");
        w.Num(total);
        w.Key("regions");
        w.BeginArray();
        for (const auto& info : all) {
            w.BeginObject();
            w.Key("base");
            w.HexStr(info.base);
            w.Key("size");
            w.HexStr(info.size);
            w.Key("protect");
            w.Num(info.protect);
            w.EndObject();
        }
        w.EndArray();
        w.EndObject();
        return CmdStatus(L"regions", final_st, w.Take());
    }
    if (!ctx.client.Request(req, resp)) {
        return FailIpc(ctx);
    }
    Reader r(resp);
    int32_t st = 0;
    uint32_t count = 0;
    if (!r.TakePod(st) || !r.TakePod(count)) {
        return FailBadResp(ctx);
    }
    std::vector<HdlRegionInfo> items;
    items.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        HdlRegionInfo info{};
        if (!hdl::proto::TakeHdlRegionInfo(r, info)) {
            return FailBadResp(ctx);
        }
        items.push_back(info);
    }
    JsonWriter w;
    w.BeginObject();
    w.Key("count");
    w.Num(count);
    w.Key("regions");
    w.BeginArray();
    for (const auto& info : items) {
        w.BeginObject();
        w.Key("base");
        w.HexStr(info.base);
        w.Key("size");
        w.HexStr(info.size);
        w.Key("protect");
        w.Num(info.protect);
        w.EndObject();
    }
    w.EndArray();
    w.EndObject();
    const uint32_t show = count < 50 ? count : 50;
    if (count > show) {
        wchar_t more[64];
        swprintf_s(more, L"  ... (%u more)\n", count - show);
    }
    return CmdStatus(L"regions", st, w.Take());
}

CommandResult CmdThreads(CmdCtx& ctx) {
    using namespace hdl::proto;
    PreparedRequest req;
    std::vector<uint8_t> resp;

    bool stream = false;
    for (int i = 3; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--stream") == 0) {
            stream = true;
        }
    }
    SetMethod(req, hdl::rpc::Method::EnumThreads);
    if (stream) {
        AppendPod(req, static_cast<uint64_t>(0));
        AppendPod(req, static_cast<uint32_t>(0));
        AppendPod(req, static_cast<uint32_t>(HDL_IPC_REQ_STREAM));
        std::vector<HdlThreadInfo> all;
        int32_t final_st = HDL_OK;
        uint32_t total = 0;
        bool bad_resp = false;
        if (!ctx.client.RequestStream(req, [&](int32_t st, uint32_t, const uint8_t* p, size_t n) {
                Reader r(p, n);
                uint32_t tot = 0, off = 0, count = 0;
                if (!r.TakePod(tot) || !r.TakePod(off) || !r.TakePod(count)) {
                    bad_resp = true;
                    return false;
                }
                total = tot;
                final_st = st;
                for (uint32_t i = 0; i < count; ++i) {
                    HdlThreadInfo info{};
                    if (!hdl::proto::TakeHdlThreadInfo(r, info)) {
                        bad_resp = true;
                        return false;
                    }
                    all.push_back(info);
                }
                return true;
            })) {
            return bad_resp ? FailBadResp(ctx) : FailIpc(ctx);
        }
        JsonWriter w;
        w.BeginObject();
        w.Key("total");
        w.Num(total);
        w.Key("threads");
        w.BeginArray();
        for (const auto& info : all) {
            w.BeginObject();
            w.Key("tid");
            w.Num(info.tid);
            w.Key("start_address");
            w.HexStr(info.start_address);
            w.EndObject();
        }
        w.EndArray();
        w.EndObject();
        return CmdStatus(L"threads", final_st, w.Take());
    }
    if (!ctx.client.Request(req, resp)) {
        return FailIpc(ctx);
    }
    Reader r(resp);
    int32_t st = 0;
    uint32_t count = 0;
    if (!r.TakePod(st) || !r.TakePod(count)) {
        return FailBadResp(ctx);
    }
    std::vector<HdlThreadInfo> items;
    items.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        HdlThreadInfo info{};
        if (!hdl::proto::TakeHdlThreadInfo(r, info)) {
            return FailBadResp(ctx);
        }
        items.push_back(info);
    }
    JsonWriter w;
    w.BeginObject();
    w.Key("count");
    w.Num(count);
    w.Key("threads");
    w.BeginArray();
    for (const auto& info : items) {
        w.BeginObject();
        w.Key("tid");
        w.Num(info.tid);
        w.Key("start_address");
        w.HexStr(info.start_address);
        w.Key("user_time_100ns");
        w.Num(info.user_time_100ns);
        w.Key("kernel_time_100ns");
        w.Num(info.kernel_time_100ns);
        w.EndObject();
    }
    w.EndArray();
    w.EndObject();
    return CmdStatus(L"threads", st, w.Take());
}

CommandResult CmdHealth(CmdCtx& ctx) {
    using namespace hdl::proto;
    PreparedRequest req;
    std::vector<uint8_t> resp;

    SetMethod(req, hdl::rpc::Method::GetHealth);
    if (!ctx.client.Request(req, resp)) {
        return FailIpc(ctx);
    }
    Reader r(resp);
    int32_t st = 0;
    HdlHealthInfo info{};
    if (!r.TakePod(st) || !hdl::proto::TakeHdlHealthInfo(r, info)) {
        return FailBadResp(ctx);
    }
    JsonWriter w;
    w.BeginObject();
    w.Key("pid");
    w.Num(info.pid);
    w.Key("thread_count");
    w.Num(info.thread_count);
    w.Key("handle_count");
    w.Num(info.handle_count);
    w.Key("cpu_percent");
    w.Num(info.cpu_percent);
    w.Key("gui_hung");
    w.Num(info.gui_hung);
    w.Key("flags");
    w.Num(info.flags);
    w.Key("working_set");
    w.Num(info.working_set);
    w.Key("private_bytes");
    w.Num(info.private_bytes);
    w.Key("last_exception_code");
    w.Num(info.last_exception_code);
    w.Key("last_exception_addr");
    w.HexStr(info.last_exception_addr);
    w.EndObject();
    return CmdStatus(L"health", st, w.Take());
}

static const char* FpCategoryNameNarrow(uint32_t cat) {
    switch (cat) {
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
    using namespace hdl::proto;
    PreparedRequest req;
    std::vector<uint8_t> resp;

    uint32_t scan_flags = HDL_FP_SCAN_DEFAULT;
    bool stream = false;
    for (int i = 3; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--stream") == 0) {
            stream = true;
        } else if (wcscmp(ctx.argv[i], L"--modules-only") == 0) {
            scan_flags = HDL_FP_SCAN_MODULES;
        } else if (wcscmp(ctx.argv[i], L"--no-imports") == 0) {
            scan_flags &= ~HDL_FP_SCAN_IMPORTS;
        }
    }

    SetMethod(req, hdl::rpc::Method::Fingerprint);
    AppendPod(req, scan_flags);
    if (stream) {
        AppendPod(req, static_cast<uint64_t>(0));
        AppendPod(req, static_cast<uint32_t>(0));
        AppendPod(req, static_cast<uint32_t>(HDL_IPC_REQ_STREAM));
        std::vector<HdlFingerprintTag> all;
        int32_t final_st = HDL_OK;
        uint32_t total = 0;
        bool bad_resp = false;
        if (!ctx.client.RequestStream(
                req, [&](int32_t st, uint32_t flags, const uint8_t* p, size_t n) {
                    Reader r(p, n);
                    uint32_t tot = 0, off = 0, count = 0;
                    if (!r.TakePod(tot) || !r.TakePod(off) || !r.TakePod(count)) {
                        bad_resp = true;
                        return false;
                    }
                    total = tot;
                    final_st = st;
                    for (uint32_t i = 0; i < count; ++i) {
                        HdlFingerprintTag tag{};
                        if (!hdl::proto::TakeHdlFingerprintTag(r, tag)) {
                            bad_resp = true;
                            return false;
                        }
                        all.push_back(tag);
                    }
                    (void)flags;
                    return true;
                })) {
            return bad_resp ? FailBadResp(ctx) : FailIpc(ctx);
        }
        JsonWriter w;
        w.BeginObject();
        w.Key("total");
        w.Num(total);
        w.Key("tags");
        w.BeginArray();
        for (const auto& tag : all) {
            w.BeginObject();
            w.Key("primary");
            w.Bool((tag.flags & HDL_FP_PRIMARY) != 0);
            w.Key("category");
            w.Str(FpCategoryNameNarrow(tag.category));
            w.Key("id");
            w.Str(tag.id);
            w.Key("confidence");
            w.Num(tag.confidence);
            w.Key("flags");
            w.Num(tag.flags);
            w.Key("evidence");
            w.Str(tag.evidence);
            w.EndObject();
        }
        w.EndArray();
        w.EndObject();
        return CmdStatus(L"fingerprint", final_st, w.Take());
    }

    if (!ctx.client.Request(req, resp)) {
        return FailIpc(ctx);
    }
    Reader r(resp);
    int32_t st = 0;
    uint32_t count = 0;
    if (!r.TakePod(st) || !r.TakePod(count)) {
        return FailBadResp(ctx);
    }
    std::vector<HdlFingerprintTag> items;
    items.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        HdlFingerprintTag tag{};
        if (!hdl::proto::TakeHdlFingerprintTag(r, tag)) {
            return FailBadResp(ctx);
        }
        items.push_back(tag);
    }
    JsonWriter w;
    w.BeginObject();
    w.Key("count");
    w.Num(count);
    w.Key("tags");
    w.BeginArray();
    for (const auto& tag : items) {
        w.BeginObject();
        w.Key("primary");
        w.Bool((tag.flags & HDL_FP_PRIMARY) != 0);
        w.Key("category");
        w.Str(FpCategoryNameNarrow(tag.category));
        w.Key("id");
        w.Str(tag.id);
        w.Key("confidence");
        w.Num(tag.confidence);
        w.Key("flags");
        w.Num(tag.flags);
        w.Key("evidence");
        w.Str(tag.evidence);
        w.EndObject();
    }
    w.EndArray();
    w.EndObject();
    return CmdStatus(L"fingerprint", st, w.Take());
}

CommandResult CmdEvents(CmdCtx& ctx) {
    using namespace hdl::proto;
    PreparedRequest req;
    std::vector<uint8_t> resp;

    uint32_t timeout_ms = 0;
    uint32_t max_events = 16;
    for (int i = 3; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--timeout") == 0 && i + 1 < ctx.argc) {
            timeout_ms = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
        } else if (wcscmp(ctx.argv[i], L"--max") == 0 && i + 1 < ctx.argc) {
            max_events = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
        }
    }
    SetMethod(req, hdl::rpc::Method::PollEvents);
    AppendPod(req, max_events);
    AppendPod(req, timeout_ms);
    if (!ctx.client.Request(req, resp)) {
        return FailIpc(ctx);
    }
    Reader r(resp);
    int32_t st = 0;
    uint32_t count = 0;
    if (!r.TakePod(st) || !r.TakePod(count)) {
        return FailBadResp(ctx);
    }
    std::vector<HdlEvent> events;
    events.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        HdlEvent ev{};
        if (!hdl::proto::TakeHdlEvent(r, ev)) {
            return FailBadResp(ctx);
        }
        events.push_back(ev);
    }
    JsonWriter w;
    w.BeginObject();
    w.Key("count");
    w.Num(count);
    w.Key("events");
    w.BeginArray();
    for (const auto& ev : events) {
        w.BeginObject();
        w.Key("type");
        w.Num(ev.type);
        w.Key("code");
        w.Num(ev.code);
        w.Key("timestamp_ms");
        w.Num(ev.timestamp_ms);
        w.Key("address");
        w.HexStr(ev.address);
        w.EndObject();
    }
    w.EndArray();
    w.EndObject();
    return CmdStatus(L"events", st, w.Take());
}

CommandResult CmdRead(CmdCtx& ctx) {
    using namespace hdl::proto;
    PreparedRequest req;
    std::vector<uint8_t> resp;

    if (ctx.argc < 5) {
        return FailUsage(ctx);
    }
    uint64_t address = 0;
    uint64_t size64 = 0;
    if (!ParseHexU64(ctx.argv[3], &address) || !ParseHexU64(ctx.argv[4], &size64)) {
        return CmdFail(L"read", HDL_E_INVALID_ARG, L"bad address/size");
    }
    SetMethod(req, hdl::rpc::Method::ReadMemory);
    AppendPod(req, address);
    AppendPod(req, static_cast<uint32_t>(size64));
    if (!ctx.client.Request(req, resp)) {
        return FailIpc(ctx);
    }
    Reader r(resp);
    int32_t st = 0;
    uint32_t got = 0;
    if (!r.TakePod(st) || !r.TakePod(got)) {
        return FailBadResp(ctx);
    }
    std::vector<uint8_t> bytes;
    bytes.reserve(got);
    for (uint32_t i = 0; i < got; ++i) {
        uint8_t b = 0;
        if (!r.TakePod(b)) {
            return FailBadResp(ctx);
        }
        bytes.push_back(b);
    }
    std::string hex;
    hex.reserve(got * 2);
    for (uint8_t b : bytes) {
        char tmp[3];
        snprintf(tmp, sizeof(tmp), "%02X", b);
        hex += tmp;
    }
    JsonWriter w;
    w.BeginObject();
    w.Key("address");
    w.HexStr(address);
    w.Key("bytes");
    w.Num(got);
    w.Key("hex");
    w.Str(hex);
    w.EndObject();
    for (uint32_t i = 0; i < got; ++i) {
        wchar_t bw[8];
        swprintf_s(bw, L"%02X%s", bytes[i], ((i + 1) % 16 == 0 || i + 1 == got) ? L"\n" : L" ");
    }
    return CmdStatus(L"read", st, w.Take());
}

CommandResult CmdWrite(CmdCtx& ctx) {
    using namespace hdl::proto;
    PreparedRequest req;
    std::vector<uint8_t> resp;

    if (ctx.argc < 5) {
        return FailUsage(ctx);
    }
    uint64_t address = 0;
    if (!ParseHexU64(ctx.argv[3], &address)) {
        return CmdFail(L"write", HDL_E_INVALID_ARG, L"bad address");
    }
    std::vector<uint8_t> bytes;
    if (ctx.argv[4][0] == L'@') {
        const wchar_t* path = ctx.argv[4] + 1;
        HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL, nullptr);
        if (f == INVALID_HANDLE_VALUE) {
            return CmdFail(L"write", HDL_E_NOT_FOUND, L"failed to open file");
        }
        LARGE_INTEGER sz{};
        if (!GetFileSizeEx(f, &sz) || sz.QuadPart <= 0 || sz.QuadPart > 16 * 1024 * 1024) {
            CloseHandle(f);
            return CmdFail(L"write", HDL_E_INVALID_ARG, L"bad file size");
        }
        bytes.resize(static_cast<size_t>(sz.QuadPart));
        DWORD got = 0;
        const BOOL ok = ReadFile(f, bytes.data(), static_cast<DWORD>(bytes.size()), &got, nullptr);
        CloseHandle(f);
        if (!ok || got != bytes.size()) {
            return CmdFail(L"write", HDL_E_FAILED, L"failed to read file");
        }
    } else if (!ParseHexBytes(ctx.argv[4], bytes) || bytes.empty()) {
        return CmdFail(L"write", HDL_E_INVALID_ARG, L"bad hex bytes (or use @file)");
    }
    SetMethod(req, hdl::rpc::Method::WriteMemory);
    AppendPod(req, address);
    AppendPod(req, static_cast<uint32_t>(bytes.size()));
    AppendBytes(req, bytes.data(), bytes.size());
    if (!ctx.client.Request(req, resp)) {
        return FailIpc(ctx);
    }
    Reader r(resp);
    int32_t st = 0;
    uint32_t wrote = 0;
    if (!r.TakePod(st) || !r.TakePod(wrote)) {
        return FailBadResp(ctx);
    }
    JsonWriter w;
    w.BeginObject();
    w.Key("address");
    w.HexStr(address);
    w.Key("wrote");
    w.Num(wrote);
    w.EndObject();
    return CmdStatus(L"write", st, w.Take());
}
