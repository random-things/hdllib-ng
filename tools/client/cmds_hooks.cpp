#include "cmd.hpp"
#include "json_out.hpp"
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

int CmdHooktrace(CmdCtx& ctx) {
    using namespace hdl::proto;
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;

    if (ctx.argc < 4) {
        return FailUsage(ctx);
    }
    const uint64_t target = _wcstoui64(ctx.argv[3], nullptr, 0);
    uint32_t arg_count = 0;
    for (int i = 4; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--args") == 0 && i + 1 < ctx.argc) {
            arg_count = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
        }
    }
    AppendPod(req, static_cast<uint32_t>(OpHookTrace));
    AppendPod(req, target);
    AppendPod(req, arg_count);
    if (!ctx.client.Request(req, resp)) {
        return FailIpc(ctx);
    }
    Reader r(resp);
    int32_t st = 0;
    uint64_t handle = 0;
    if (!r.TakePod(st) || !r.TakePod(handle)) {
        return FailBadResp(ctx);
    }
    if (ctx.json) {
        JsonWriter w;
        w.BeginObject();
        w.Key("handle");
        w.HexStr(handle);
        w.EndObject();
        EmitEnvelope(ctx, st, L"hooktrace", w.Take());
        return st == HDL_OK ? 0 : 1;
    }
    wprintf(L"status=%ls handle=%016llx\n", StatusName(st),
            static_cast<unsigned long long>(handle));
    PrintStatusHint(L"hooktrace", st);
    return st == HDL_OK ? 0 : 1;
}

int CmdUnhook(CmdCtx& ctx) {
    using namespace hdl::proto;
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;

    if (ctx.argc < 4) {
        return FailUsage(ctx);
    }
    const uint64_t handle = _wcstoui64(ctx.argv[3], nullptr, 0);
    AppendPod(req, static_cast<uint32_t>(OpUnhook));
    AppendPod(req, handle);
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
        EmitEnvelope(ctx, st, L"unhook", w.Take());
        return st == HDL_OK ? 0 : 1;
    }
    wprintf(L"status=%ls\n", StatusName(st));
    PrintStatusHint(L"unhook", st);
    return st == HDL_OK ? 0 : 1;
}

int CmdHookEnable(CmdCtx& ctx) {
    using namespace hdl::proto;
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;

    if (ctx.argc < 5) {
        return FailUsage(ctx);
    }
    const uint64_t handle = _wcstoui64(ctx.argv[3], nullptr, 0);
    const int32_t enable = _wtoi(ctx.argv[4]);
    AppendPod(req, static_cast<uint32_t>(OpEnableHook));
    AppendPod(req, handle);
    AppendPod(req, enable);
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
        EmitEnvelope(ctx, st, L"hook-enable", w.Take());
        return st == HDL_OK ? 0 : 1;
    }
    wprintf(L"status=%ls\n", StatusName(st));
    PrintStatusHint(L"hook-enable", st);
    return st == HDL_OK ? 0 : 1;
}

int CmdHookhits(CmdCtx& ctx) {
    using namespace hdl::proto;
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;

    uint32_t timeout_ms = 0;
    uint32_t max_n = 16;
    for (int i = 3; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--timeout") == 0 && i + 1 < ctx.argc) {
            timeout_ms = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
        } else if (wcscmp(ctx.argv[i], L"--max") == 0 && i + 1 < ctx.argc) {
            max_n = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
        }
    }
    AppendPod(req, static_cast<uint32_t>(OpPollHookHits));
    AppendPod(req, max_n);
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

    std::vector<HdlHookHit> hits;
    hits.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        HdlHookHit hit{};
        if (!r.Take(&hit, sizeof(hit))) {
            break;
        }
        hits.push_back(hit);
    }

    if (ctx.json) {
        JsonWriter w;
        w.BeginObject();
        w.Key("count");
        w.Num(count);
        w.Key("hits");
        w.BeginArray();
        for (const auto& hit : hits) {
            w.BeginObject();
            w.Key("hook_id");
            w.HexStr(hit.hook_id);
            w.Key("return_value");
            w.HexStr(hit.return_value);
            w.Key("caller");
            w.HexStr(hit.caller);
            w.Key("args");
            w.BeginArray();
            for (uint32_t a = 0; a < hit.arg_count && a < 8; ++a) {
                w.HexStr(hit.args[a]);
            }
            w.EndArray();
            w.EndObject();
        }
        w.EndArray();
        w.EndObject();
        EmitEnvelope(ctx, st, L"hookhits", w.Take());
        return st == HDL_OK ? 0 : 1;
    }

    wprintf(L"status=%ls count=%u\n", StatusName(st), count);
    for (const auto& hit : hits) {
        wprintf(L"  hook=%016llx ret=%016llx caller=%016llx args=%u",
                static_cast<unsigned long long>(hit.hook_id),
                static_cast<unsigned long long>(hit.return_value),
                static_cast<unsigned long long>(hit.caller), hit.arg_count);
        for (uint32_t a = 0; a < hit.arg_count && a < 8; ++a) {
            wprintf(L" a%u=%llx", a, static_cast<unsigned long long>(hit.args[a]));
        }
        wprintf(L"\n");
    }
    PrintStatusHint(L"hookhits", st);
    return st == HDL_OK ? 0 : 1;
}

static std::string NarrowHook(const wchar_t* w) {
    char buf[512];
    WideCharToMultiByte(CP_UTF8, 0, w ? w : L"", -1, buf, sizeof(buf), nullptr, nullptr);
    return buf;
}

int CmdHookImport(CmdCtx& ctx) {
    using namespace hdl::proto;
    if (ctx.argc < 4) {
        return FailUsage(ctx);
    }
    std::wstring module;
    std::string dll;
    std::string import_name;
    uint32_t arg_count = 0;
    wchar_t* bang = wcschr(ctx.argv[3], L'!');
    if (bang) {
        wchar_t buf[512];
        wcsncpy_s(buf, ctx.argv[3], _TRUNCATE);
        wchar_t* b = wcschr(buf, L'!');
        if (!b) {
            if (ctx.json) {
                EmitError(ctx, HDL_E_INVALID_ARG, L"hook-import", L"bad DLL!Name");
            } else {
                wprintf(L"Bad DLL!Name\n");
            }
            return 1;
        }
        *b = 0;
        dll = NarrowHook(buf);
        import_name = NarrowHook(b + 1);
    } else {
        for (int i = 3; i < ctx.argc; ++i) {
            if (wcscmp(ctx.argv[i], L"--dll") == 0 && i + 1 < ctx.argc) {
                dll = NarrowHook(ctx.argv[++i]);
            } else if (wcscmp(ctx.argv[i], L"--import") == 0 && i + 1 < ctx.argc) {
                import_name = NarrowHook(ctx.argv[++i]);
            } else if (wcscmp(ctx.argv[i], L"--module") == 0 && i + 1 < ctx.argc) {
                module = ctx.argv[++i];
            } else if (wcscmp(ctx.argv[i], L"--args") == 0 && i + 1 < ctx.argc) {
                arg_count = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
            }
        }
    }
    if (dll.empty() || import_name.empty()) {
        if (ctx.json) {
            EmitError(ctx, HDL_E_INVALID_ARG, L"hook-import",
                      L"need hook-import DLL!Name or --dll X --import Y");
        } else {
            wprintf(L"Need hook-import DLL!Name or --dll X --import Y\n");
        }
        return 1;
    }
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;
    AppendPod(req, static_cast<uint32_t>(OpHookImport));
    AppendWString(req, module.c_str());
    AppendString(req, dll.c_str());
    AppendString(req, import_name.c_str());
    AppendPod(req, arg_count);
    if (!ctx.client.Request(req, resp)) {
        return FailIpc(ctx);
    }
    Reader r(resp);
    int32_t st = 0;
    uint64_t handle = 0;
    if (!r.TakePod(st) || !r.TakePod(handle)) {
        return FailBadResp(ctx);
    }
    if (ctx.json) {
        JsonWriter w;
        w.BeginObject();
        w.Key("handle");
        w.HexStr(handle);
        w.EndObject();
        EmitEnvelope(ctx, st, L"hook-import", w.Take());
        return st == HDL_OK ? 0 : 1;
    }
    wprintf(L"status=%ls handle=%016llx\n", StatusName(st),
            static_cast<unsigned long long>(handle));
    PrintStatusHint(L"hook-import", st);
    return st == HDL_OK ? 0 : 1;
}
