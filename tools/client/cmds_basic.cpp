#include "cmd.hpp"
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

static int FailUsage(CmdCtx& ctx) {
    if (ctx.json) {
        EmitError(ctx, HDL_E_INVALID_ARG, ctx.cmd.c_str(), L"missing or invalid arguments");
    } else {
        PrintUsage();
    }
    return 1;
}

static int FailIpc(CmdCtx& ctx) {
    if (ctx.json) {
        EmitError(ctx, HDL_E_FAILED, ctx.cmd.c_str(), L"IPC request failed");
    } else {
        wprintf(L"IPC request failed\n");
    }
    return 1;
}

static int FailBadResp(CmdCtx& ctx) {
    if (ctx.json) {
        EmitError(ctx, HDL_E_FAILED, ctx.cmd.c_str(), L"bad response");
    } else {
        wprintf(L"Bad response\n");
    }
    return 1;
}

int CmdPing(CmdCtx& ctx) {
    using namespace hdl::proto;
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;

    AppendPod(req, static_cast<uint32_t>(OpPing));
    if (!ctx.client.Request(req, resp)) {
        return FailIpc(ctx);
    }
    Reader r(resp);
    int32_t st = 0;
    uint32_t rpid = 0;
    if (!r.TakePod(st) || !r.TakePod(rpid)) {
        return FailBadResp(ctx);
    }
    if (ctx.json) {
        JsonWriter w;
        w.BeginObject();
        w.Key("remote_pid");
        w.Num(rpid);
        w.EndObject();
        EmitEnvelope(ctx, st, L"ping", w.Take());
        return st == HDL_OK ? 0 : 1;
    }
    wprintf(L"status=%ls remote_pid=%u\n", StatusName(st), rpid);
    PrintStatusHint(L"ping", st);
    return st == HDL_OK ? 0 : 1;
}

int CmdLog(CmdCtx& ctx) {
    using namespace hdl::proto;
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;

    if (ctx.argc < 4) {
        return FailUsage(ctx);
    }
    AppendPod(req, static_cast<uint32_t>(OpSetLogLevel));
    AppendPod(req, static_cast<int32_t>(_wtoi(ctx.argv[3])));
    if (!ctx.client.Request(req, resp)) {
        return FailIpc(ctx);
    }
    Reader r(resp);
    int32_t st = 0;
    r.TakePod(st);
    if (ctx.json) {
        JsonWriter w;
        w.BeginObject();
        w.EndObject();
        EmitEnvelope(ctx, st, L"log", w.Take());
        return st == HDL_OK ? 0 : 1;
    }
    wprintf(L"status=%ls\n", StatusName(st));
    PrintStatusHint(L"log", st);
    return st == HDL_OK ? 0 : 1;
}

int CmdLogFile(CmdCtx& ctx) {
    using namespace hdl::proto;
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;

    const wchar_t* path = L"";
    if (ctx.argc >= 4) {
        path = ctx.argv[3];
    }
    AppendPod(req, static_cast<uint32_t>(OpSetLogFile));
    AppendWString(req, path);
    if (!ctx.client.Request(req, resp)) {
        return FailIpc(ctx);
    }
    Reader r(resp);
    int32_t st = 0;
    r.TakePod(st);
    if (ctx.json) {
        JsonWriter w;
        w.BeginObject();
        w.Key("path");
        w.Str(path && path[0] ? path : L"");
        w.EndObject();
        EmitEnvelope(ctx, st, L"log-file", w.Take());
        return st == HDL_OK ? 0 : 1;
    }
    wprintf(L"status=%ls\n", StatusName(st));
    PrintStatusHint(L"log-file", st);
    return st == HDL_OK ? 0 : 1;
}

int CmdHealthVeh(CmdCtx& ctx) {
    using namespace hdl::proto;
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;

    if (ctx.argc < 4) {
        return FailUsage(ctx);
    }
    const wchar_t* sub = ctx.argv[3];
    if (_wcsicmp(sub, L"status") == 0) {
        AppendPod(req, static_cast<uint32_t>(OpGetHealthVeh));
        if (!ctx.client.Request(req, resp)) {
            return FailIpc(ctx);
        }
        Reader r(resp);
        int32_t st = 0;
        int32_t enabled = 0;
        if (!r.TakePod(st) || !r.TakePod(enabled)) {
            if (ctx.json) {
                EmitError(ctx, HDL_E_FAILED, L"health-veh", L"bad response");
            } else {
                wprintf(L"Bad response\n");
            }
            return 1;
        }
        if (ctx.json) {
            JsonWriter w;
            w.BeginObject();
            w.Key("enabled");
            w.Bool(enabled != 0);
            w.EndObject();
            EmitEnvelope(ctx, st, L"health-veh", w.Take());
            return st == HDL_OK ? 0 : 1;
        }
        wprintf(L"status=%ls enabled=%d\n", StatusName(st), enabled != 0 ? 1 : 0);
        PrintStatusHint(L"health-veh", st);
        return st == HDL_OK ? 0 : 1;
    }

    int32_t enabled = -1;
    if (_wcsicmp(sub, L"on") == 0 || wcscmp(sub, L"1") == 0) {
        enabled = 1;
    } else if (_wcsicmp(sub, L"off") == 0 || wcscmp(sub, L"0") == 0) {
        enabled = 0;
    } else {
        return FailUsage(ctx);
    }
    AppendPod(req, static_cast<uint32_t>(OpSetHealthVeh));
    AppendPod(req, enabled);
    if (!ctx.client.Request(req, resp)) {
        return FailIpc(ctx);
    }
    Reader r(resp);
    int32_t st = 0;
    if (!r.TakePod(st)) {
        return FailBadResp(ctx);
    }
    if (ctx.json) {
        JsonWriter w;
        w.BeginObject();
        w.Key("enabled");
        w.Bool(enabled != 0);
        w.EndObject();
        EmitEnvelope(ctx, st, L"health-veh", w.Take());
        return st == HDL_OK ? 0 : 1;
    }
    wprintf(L"status=%ls enabled=%d\n", StatusName(st), enabled);
    PrintStatusHint(L"health-veh", st);
    return st == HDL_OK ? 0 : 1;
}

int CmdModules(CmdCtx& ctx) {
    using namespace hdl::proto;
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;

    bool stream = false;
    for (int i = 3; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--stream") == 0) {
            stream = true;
        }
    }
    AppendPod(req, static_cast<uint32_t>(OpEnumModules));
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
        if (ctx.json) {
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
            EmitEnvelope(ctx, final_st, L"modules", w.Take());
            return final_st == HDL_OK ? 0 : 1;
        }
        wprintf(L"status=%ls total=%u (stream)\n", StatusName(final_st), total);
        for (const auto& info : all) {
            wprintf(L"  %016llx  %8llx  %ls\n", static_cast<unsigned long long>(info.base),
                    static_cast<unsigned long long>(info.size), info.path);
        }
        PrintStatusHint(L"modules", final_st);
        return final_st == HDL_OK ? 0 : 1;
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
    if (ctx.json) {
        JsonWriter w;
        w.BeginObject();
        w.Key("count");
        w.Num(count);
        w.Key("modules");
        w.BeginArray();
        for (uint32_t i = 0; i < count; ++i) {
            HdlModuleInfo info{};
            if (!hdl::proto::TakeHdlModuleInfo(r, info)) {
                return FailBadResp(ctx);
            }
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
        EmitEnvelope(ctx, st, L"modules", w.Take());
        return st == HDL_OK ? 0 : 1;
    }
    wprintf(L"status=%ls count=%u\n", StatusName(st), count);
    for (uint32_t i = 0; i < count; ++i) {
        HdlModuleInfo info{};
        if (!hdl::proto::TakeHdlModuleInfo(r, info)) {
            return FailBadResp(ctx);
        }
        wprintf(L"  %016llx  %8llx  %ls\n", static_cast<unsigned long long>(info.base),
                static_cast<unsigned long long>(info.size), info.path);
    }
    PrintStatusHint(L"modules", st);
    return st == HDL_OK ? 0 : 1;
}

int CmdRegions(CmdCtx& ctx) {
    using namespace hdl::proto;
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;

    bool stream = false;
    for (int i = 3; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--stream") == 0) {
            stream = true;
        }
    }
    AppendPod(req, static_cast<uint32_t>(OpEnumRegions));
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
        if (ctx.json) {
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
            EmitEnvelope(ctx, final_st, L"regions", w.Take());
            return final_st == HDL_OK ? 0 : 1;
        }
        wprintf(L"status=%ls total=%u\n", StatusName(final_st), total);
        for (const auto& info : all) {
            wprintf(L"  %016llx  %8llx  prot=%08x\n", static_cast<unsigned long long>(info.base),
                    static_cast<unsigned long long>(info.size), info.protect);
        }
        PrintStatusHint(L"regions", final_st);
        return final_st == HDL_OK ? 0 : 1;
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
    if (ctx.json) {
        JsonWriter w;
        w.BeginObject();
        w.Key("count");
        w.Num(count);
        w.Key("regions");
        w.BeginArray();
        for (uint32_t i = 0; i < count; ++i) {
            HdlRegionInfo info{};
            if (!hdl::proto::TakeHdlRegionInfo(r, info)) {
                return FailBadResp(ctx);
            }
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
        EmitEnvelope(ctx, st, L"regions", w.Take());
        return st == HDL_OK ? 0 : 1;
    }
    wprintf(L"status=%ls count=%u\n", StatusName(st), count);
    const uint32_t show = count < 50 ? count : 50;
    for (uint32_t i = 0; i < show; ++i) {
        HdlRegionInfo info{};
        if (!hdl::proto::TakeHdlRegionInfo(r, info)) {
            return FailBadResp(ctx);
        }
        wprintf(L"  %016llx  %8llx  prot=%08x\n", static_cast<unsigned long long>(info.base),
                static_cast<unsigned long long>(info.size), info.protect);
    }
    if (count > show) {
        wprintf(L"  ... (%u more)\n", count - show);
    }
    PrintStatusHint(L"regions", st);
    return st == HDL_OK ? 0 : 1;
}

int CmdThreads(CmdCtx& ctx) {
    using namespace hdl::proto;
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;

    bool stream = false;
    for (int i = 3; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--stream") == 0) {
            stream = true;
        }
    }
    AppendPod(req, static_cast<uint32_t>(OpEnumThreads));
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
        if (ctx.json) {
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
            EmitEnvelope(ctx, final_st, L"threads", w.Take());
            return final_st == HDL_OK ? 0 : 1;
        }
        wprintf(L"status=%ls total=%u\n", StatusName(final_st), total);
        for (const auto& info : all) {
            wprintf(L"  tid=%u start=%016llx\n", info.tid,
                    static_cast<unsigned long long>(info.start_address));
        }
        PrintStatusHint(L"threads", final_st);
        return final_st == HDL_OK ? 0 : 1;
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
    if (ctx.json) {
        JsonWriter w;
        w.BeginObject();
        w.Key("count");
        w.Num(count);
        w.Key("threads");
        w.BeginArray();
        for (uint32_t i = 0; i < count; ++i) {
            HdlThreadInfo info{};
            if (!hdl::proto::TakeHdlThreadInfo(r, info)) {
                return FailBadResp(ctx);
            }
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
        EmitEnvelope(ctx, st, L"threads", w.Take());
        return st == HDL_OK ? 0 : 1;
    }
    wprintf(L"status=%ls count=%u\n", StatusName(st), count);
    for (uint32_t i = 0; i < count; ++i) {
        HdlThreadInfo info{};
        if (!hdl::proto::TakeHdlThreadInfo(r, info)) {
            return FailBadResp(ctx);
        }
        wprintf(L"  tid=%u start=%016llx user=%llu kernel=%llu\n", info.tid,
                static_cast<unsigned long long>(info.start_address),
                static_cast<unsigned long long>(info.user_time_100ns),
                static_cast<unsigned long long>(info.kernel_time_100ns));
    }
    PrintStatusHint(L"threads", st);
    return st == HDL_OK ? 0 : 1;
}

int CmdHealth(CmdCtx& ctx) {
    using namespace hdl::proto;
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;

    AppendPod(req, static_cast<uint32_t>(OpGetHealth));
    if (!ctx.client.Request(req, resp)) {
        return FailIpc(ctx);
    }
    Reader r(resp);
    int32_t st = 0;
    HdlHealthInfo info{};
    if (!r.TakePod(st) || !hdl::proto::TakeHdlHealthInfo(r, info)) {
        return FailBadResp(ctx);
    }
    if (ctx.json) {
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
        EmitEnvelope(ctx, st, L"health", w.Take());
        return st == HDL_OK ? 0 : 1;
    }
    wprintf(L"status=%ls pid=%u threads=%u handles=%u cpu=%u%% hung=%u flags=0x%x\n",
            StatusName(st), info.pid, info.thread_count, info.handle_count, info.cpu_percent,
            info.gui_hung, info.flags);
    wprintf(L"  working_set=%llu private=%llu last_exc=0x%x @ %016llx\n",
            static_cast<unsigned long long>(info.working_set),
            static_cast<unsigned long long>(info.private_bytes), info.last_exception_code,
            static_cast<unsigned long long>(info.last_exception_addr));
    PrintStatusHint(L"health", st);
    return st == HDL_OK ? 0 : 1;
}

static const wchar_t* FpCategoryName(uint32_t cat) {
    switch (cat) {
    case HDL_FP_CAT_LANGUAGE:
        return L"language";
    case HDL_FP_CAT_RUNTIME:
        return L"runtime";
    case HDL_FP_CAT_TOOLCHAIN:
        return L"toolchain";
    case HDL_FP_CAT_UI:
        return L"ui";
    case HDL_FP_CAT_GRAPHICS:
        return L"graphics";
    case HDL_FP_CAT_ENGINE:
        return L"engine";
    case HDL_FP_CAT_WEBHOST:
        return L"webhost";
    case HDL_FP_CAT_AUDIO:
        return L"audio";
    case HDL_FP_CAT_NETWORK:
        return L"network";
    case HDL_FP_CAT_TOOLING:
        return L"tooling";
    case HDL_FP_CAT_APP:
        return L"app";
    default:
        return L"?";
    }
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

int CmdFingerprint(CmdCtx& ctx) {
    using namespace hdl::proto;
    std::vector<uint8_t> req;
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

    AppendPod(req, static_cast<uint32_t>(OpFingerprint));
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
        if (ctx.json) {
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
            EmitEnvelope(ctx, final_st, L"fingerprint", w.Take());
            return final_st == HDL_OK ? 0 : 1;
        }
        wprintf(L"status=%ls total=%u (stream)\n", StatusName(final_st), total);
        for (const auto& tag : all) {
            const wchar_t* prim = (tag.flags & HDL_FP_PRIMARY) ? L"*" : L" ";
            wprintf(L"  %ls %-10ls %-16hs  conf=%u  flags=0x%x  %hs\n", prim,
                    FpCategoryName(tag.category), tag.id, tag.confidence, tag.flags, tag.evidence);
        }
        PrintStatusHint(L"fingerprint", final_st);
        return final_st == HDL_OK ? 0 : 1;
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
    if (ctx.json) {
        JsonWriter w;
        w.BeginObject();
        w.Key("count");
        w.Num(count);
        w.Key("tags");
        w.BeginArray();
        for (uint32_t i = 0; i < count; ++i) {
            HdlFingerprintTag tag{};
            if (!hdl::proto::TakeHdlFingerprintTag(r, tag)) {
                return FailBadResp(ctx);
            }
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
        EmitEnvelope(ctx, st, L"fingerprint", w.Take());
        return st == HDL_OK ? 0 : 1;
    }
    wprintf(L"status=%ls count=%u  (* = primary)\n", StatusName(st), count);
    for (uint32_t i = 0; i < count; ++i) {
        HdlFingerprintTag tag{};
        if (!hdl::proto::TakeHdlFingerprintTag(r, tag)) {
            return FailBadResp(ctx);
        }
        const wchar_t* prim = (tag.flags & HDL_FP_PRIMARY) ? L"*" : L" ";
        wprintf(L"  %ls %-10ls %-16hs  conf=%u  flags=0x%x  %hs\n", prim,
                FpCategoryName(tag.category), tag.id, tag.confidence, tag.flags, tag.evidence);
    }
    PrintStatusHint(L"fingerprint", st);
    return st == HDL_OK ? 0 : 1;
}

int CmdEvents(CmdCtx& ctx) {
    using namespace hdl::proto;
    std::vector<uint8_t> req;
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
    AppendPod(req, static_cast<uint32_t>(OpPollEvents));
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
    if (ctx.json) {
        JsonWriter w;
        w.BeginObject();
        w.Key("count");
        w.Num(count);
        w.Key("events");
        w.BeginArray();
        for (uint32_t i = 0; i < count; ++i) {
            HdlEvent ev{};
            if (!hdl::proto::TakeHdlEvent(r, ev)) {
                return FailBadResp(ctx);
            }
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
        EmitEnvelope(ctx, st, L"events", w.Take());
        return st == HDL_OK ? 0 : 1;
    }
    wprintf(L"status=%ls events=%u\n", StatusName(st), count);
    for (uint32_t i = 0; i < count; ++i) {
        HdlEvent ev{};
        if (!hdl::proto::TakeHdlEvent(r, ev)) {
            return FailBadResp(ctx);
        }
        wprintf(L"  type=%u code=0x%x ts=%llu addr=%016llx\n", ev.type, ev.code,
                static_cast<unsigned long long>(ev.timestamp_ms),
                static_cast<unsigned long long>(ev.address));
    }
    PrintStatusHint(L"events", st);
    return st == HDL_OK ? 0 : 1;
}

int CmdJob(CmdCtx& ctx) {
    using namespace hdl::proto;
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;

    if (ctx.argc < 4) {
        return FailUsage(ctx);
    }
    if (wcscmp(ctx.argv[3], L"create") == 0) {
        uint32_t timeout_ms = 0;
        for (int i = 4; i < ctx.argc; ++i) {
            if (wcscmp(ctx.argv[i], L"--timeout") == 0 && i + 1 < ctx.argc) {
                timeout_ms = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
            }
        }
        AppendPod(req, static_cast<uint32_t>(OpJobCreate));
        AppendPod(req, timeout_ms);
        if (!ctx.client.Request(req, resp)) {
            return FailIpc(ctx);
        }
        Reader r(resp);
        int32_t st = 0;
        uint64_t id = 0;
        if (!r.TakePod(st) || !r.TakePod(id)) {
            return FailBadResp(ctx);
        }
        if (ctx.json) {
            JsonWriter w;
            w.BeginObject();
            w.Key("job");
            w.HexStr(id);
            w.EndObject();
            EmitEnvelope(ctx, st, L"job", w.Take());
            return st == HDL_OK ? 0 : 1;
        }
        wprintf(L"status=%ls job=%llu\n", StatusName(st), static_cast<unsigned long long>(id));
        PrintStatusHint(L"job", st);
        return st == HDL_OK ? 0 : 1;
    }
    if (ctx.argc < 5) {
        return FailUsage(ctx);
    }
    const uint64_t id = _wcstoui64(ctx.argv[4], nullptr, 0);
    AppendPod(
        req, static_cast<uint32_t>(wcscmp(ctx.argv[3], L"cancel") == 0 ? OpJobCancel : OpJobClose));
    AppendPod(req, id);
    if (!ctx.client.Request(req, resp)) {
        return FailIpc(ctx);
    }
    Reader r(resp);
    int32_t st = 0;
    r.TakePod(st);
    if (ctx.json) {
        JsonWriter w;
        w.BeginObject();
        w.Key("job");
        w.HexStr(id);
        w.Key("action");
        w.Str(wcscmp(ctx.argv[3], L"cancel") == 0 ? "cancel" : "close");
        w.EndObject();
        EmitEnvelope(ctx, st, L"job", w.Take());
        return st == HDL_OK ? 0 : 1;
    }
    wprintf(L"status=%ls job=%llu\n", StatusName(st), static_cast<unsigned long long>(id));
    PrintStatusHint(L"job", st);
    return st == HDL_OK ? 0 : 1;
}

int CmdRead(CmdCtx& ctx) {
    using namespace hdl::proto;
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;

    if (ctx.argc < 5) {
        return FailUsage(ctx);
    }
    uint64_t address = 0;
    uint64_t size64 = 0;
    if (!ParseHexU64(ctx.argv[3], &address) || !ParseHexU64(ctx.argv[4], &size64)) {
        if (ctx.json) {
            EmitError(ctx, HDL_E_INVALID_ARG, L"read", L"bad address/size");
        } else {
            wprintf(L"Bad address/size\n");
        }
        return 1;
    }
    AppendPod(req, static_cast<uint32_t>(OpReadMemory));
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
    if (ctx.json) {
        std::string hex;
        hex.reserve(got * 2);
        for (uint32_t i = 0; i < got; ++i) {
            uint8_t b = 0;
            if (!r.TakePod(b)) {
                return FailBadResp(ctx);
            }
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
        EmitEnvelope(ctx, st, L"read", w.Take());
        return st == HDL_OK ? 0 : 1;
    }
    wprintf(L"status=%ls bytes=%u\n", StatusName(st), got);
    for (uint32_t i = 0; i < got; ++i) {
        uint8_t b = 0;
        if (!r.TakePod(b)) {
            return FailBadResp(ctx);
        }
        wprintf(L"%02X%s", b, ((i + 1) % 16 == 0 || i + 1 == got) ? L"\n" : L" ");
    }
    PrintStatusHint(L"read", st);
    return st == HDL_OK ? 0 : 1;
}

int CmdWrite(CmdCtx& ctx) {
    using namespace hdl::proto;
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;

    if (ctx.argc < 5) {
        return FailUsage(ctx);
    }
    uint64_t address = 0;
    if (!ParseHexU64(ctx.argv[3], &address)) {
        if (ctx.json) {
            EmitError(ctx, HDL_E_INVALID_ARG, L"write", L"bad address");
        } else {
            wprintf(L"Bad address\n");
        }
        return 1;
    }
    std::vector<uint8_t> bytes;
    if (ctx.argv[4][0] == L'@') {
        const wchar_t* path = ctx.argv[4] + 1;
        HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL, nullptr);
        if (f == INVALID_HANDLE_VALUE) {
            if (ctx.json) {
                EmitError(ctx, HDL_E_NOT_FOUND, L"write", L"failed to open file");
            } else {
                wprintf(L"Failed to open %ls\n", path);
            }
            return 1;
        }
        LARGE_INTEGER sz{};
        if (!GetFileSizeEx(f, &sz) || sz.QuadPart <= 0 || sz.QuadPart > 16 * 1024 * 1024) {
            CloseHandle(f);
            if (ctx.json) {
                EmitError(ctx, HDL_E_INVALID_ARG, L"write", L"bad file size");
            } else {
                wprintf(L"Bad file size\n");
            }
            return 1;
        }
        bytes.resize(static_cast<size_t>(sz.QuadPart));
        DWORD got = 0;
        const BOOL ok = ReadFile(f, bytes.data(), static_cast<DWORD>(bytes.size()), &got, nullptr);
        CloseHandle(f);
        if (!ok || got != bytes.size()) {
            if (ctx.json) {
                EmitError(ctx, HDL_E_FAILED, L"write", L"failed to read file");
            } else {
                wprintf(L"Failed to read file\n");
            }
            return 1;
        }
    } else if (!ParseHexBytes(ctx.argv[4], bytes) || bytes.empty()) {
        if (ctx.json) {
            EmitError(ctx, HDL_E_INVALID_ARG, L"write", L"bad hex bytes (or use @file)");
        } else {
            wprintf(L"Bad hex bytes (or use @file)\n");
        }
        return 1;
    }
    AppendPod(req, static_cast<uint32_t>(OpWriteMemory));
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
    if (ctx.json) {
        JsonWriter w;
        w.BeginObject();
        w.Key("address");
        w.HexStr(address);
        w.Key("wrote");
        w.Num(wrote);
        w.EndObject();
        EmitEnvelope(ctx, st, L"write", w.Take());
        return st == HDL_OK ? 0 : 1;
    }
    wprintf(L"status=%ls wrote=%u\n", StatusName(st), wrote);
    PrintStatusHint(L"write", st);
    return st == HDL_OK ? 0 : 1;
}
