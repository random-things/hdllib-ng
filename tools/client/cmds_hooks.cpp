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

CommandResult CmdHooktrace(CmdCtx& ctx) {
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
    JsonWriter w;
    w.BeginObject();
    w.Key("handle");
    w.HexStr(handle);
    w.EndObject();
    return CmdStatus(L"hooktrace", st, w.Take());
}

CommandResult CmdHook(CmdCtx& ctx) {
    using namespace hdl::proto;
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;

    if (ctx.argc < 5) {
        return FailUsage(ctx);
    }
    const uint64_t target = _wcstoui64(ctx.argv[3], nullptr, 0);
    const uint64_t detour = _wcstoui64(ctx.argv[4], nullptr, 0);
    uint32_t flags = 0;
    for (int i = 5; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--flags") == 0 && i + 1 < ctx.argc) {
            flags = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
        }
    }
    if (flags != 0) {
        return FailUsage(ctx);
    }
    AppendPod(req, static_cast<uint32_t>(OpHook));
    AppendPod(req, target);
    AppendPod(req, detour);
    AppendPod(req, flags);
    if (!ctx.client.Request(req, resp)) {
        return FailIpc(ctx);
    }
    Reader r(resp);
    int32_t st = 0;
    uint64_t handle = 0;
    uint64_t trampoline = 0;
    if (!r.TakePod(st) || !r.TakePod(handle) || !r.TakePod(trampoline)) {
        return FailBadResp(ctx);
    }
    JsonWriter w;
    w.BeginObject();
    w.Key("handle");
    w.HexStr(handle);
    w.Key("trampoline");
    w.HexStr(trampoline);
    w.EndObject();
    return CmdStatus(L"hook", st, w.Take());
}

CommandResult CmdUnhook(CmdCtx& ctx) {
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
    return CmdStatus(L"unhook", st, "{}");
}

CommandResult CmdHookEnable(CmdCtx& ctx) {
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
    return CmdStatus(L"hook-enable", st, "{}");
}

CommandResult CmdHookhits(CmdCtx& ctx) {
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
        if (!hdl::proto::TakeHdlHookHit(r, hit)) {
            return FailBadResp(ctx);
        }
        hits.push_back(hit);
    }

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

    for (const auto& hit : hits) {
        for (uint32_t a = 0; a < hit.arg_count && a < 8; ++a) {
            wchar_t arg[64];
            swprintf_s(arg, L" a%u=%llx", a, static_cast<unsigned long long>(hit.args[a]));
        }
    }
    return CmdStatus(L"hookhits", st, w.Take());
}

static std::string NarrowHook(const wchar_t* w) {
    char buf[512];
    WideCharToMultiByte(CP_UTF8, 0, w ? w : L"", -1, buf, sizeof(buf), nullptr, nullptr);
    return buf;
}

CommandResult CmdHookImport(CmdCtx& ctx) {
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
            return CmdFail(L"hook-import", HDL_E_INVALID_ARG, L"bad DLL!Name");
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
        return CmdFail(L"hook-import", HDL_E_INVALID_ARG,
                       L"need hook-import DLL!Name or --dll X --import Y");
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
    JsonWriter w;
    w.BeginObject();
    w.Key("handle");
    w.HexStr(handle);
    w.EndObject();
    return CmdStatus(L"hook-import", st, w.Take());
}
