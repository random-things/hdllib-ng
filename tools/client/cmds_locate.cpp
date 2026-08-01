#include "cmd.hpp"
#include "json_out.hpp"
#include "recipes.hpp"
#include "usage.hpp"
#include "util.hpp"

#include "protocol.hpp"
#include "ipc/wire.hpp"
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

int CmdRip(CmdCtx& ctx) {
    using namespace hdl::proto;
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;

    if (ctx.argc < 4) {
        return FailUsage(ctx);
    }
    const uint64_t addr = _wcstoui64(ctx.argv[3], nullptr, 0);
    uint32_t disp = 3;
    uint32_t len = 7;
    for (int i = 4; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--disp") == 0 && i + 1 < ctx.argc) {
            disp = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
        } else if (wcscmp(ctx.argv[i], L"--len") == 0 && i + 1 < ctx.argc) {
            len = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
        }
    }
    AppendPod(req, static_cast<uint32_t>(OpResolveRip));
    AppendPod(req, addr);
    AppendPod(req, disp);
    AppendPod(req, len);
    if (!ctx.client.Request(req, resp)) {
        return FailIpc(ctx);
    }
    Reader r(resp);
    int32_t st = 0;
    uint64_t out = 0;
    if (!r.TakePod(st) || !r.TakePod(out)) {
        return FailBadResp(ctx);
    }
    if (ctx.json) {
        JsonWriter w;
        w.BeginObject();
        w.Key("addr");
        w.HexStr(out);
        w.EndObject();
        EmitEnvelope(ctx, st, L"rip", w.Take());
        return st == HDL_OK ? 0 : 1;
    }
    wprintf(L"status=%ls addr=%016llx\n", StatusName(st), static_cast<unsigned long long>(out));
    PrintStatusHint(L"rip", st);
    return st == HDL_OK ? 0 : 1;
}

int CmdPtrchain(CmdCtx& ctx) {
    using namespace hdl::proto;
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;

    if (ctx.argc < 4) {
        return FailUsage(ctx);
    }
    const uint64_t base = _wcstoui64(ctx.argv[3], nullptr, 0);
    std::vector<int64_t> offsets;
    for (int i = 4; i < ctx.argc; ++i) {
        offsets.push_back(_wcstoi64(ctx.argv[i], nullptr, 0));
    }
    AppendPod(req, static_cast<uint32_t>(OpFollowPointers));
    AppendPod(req, base);
    AppendPod(req, static_cast<uint32_t>(offsets.size()));
    for (int64_t o : offsets) {
        AppendPod(req, o);
    }
    if (!ctx.client.Request(req, resp)) {
        return FailIpc(ctx);
    }
    Reader r(resp);
    int32_t st = 0;
    uint64_t out = 0;
    if (!r.TakePod(st) || !r.TakePod(out)) {
        return FailBadResp(ctx);
    }
    if (ctx.json) {
        JsonWriter w;
        w.BeginObject();
        w.Key("addr");
        w.HexStr(out);
        w.EndObject();
        EmitEnvelope(ctx, st, L"ptrchain", w.Take());
        return st == HDL_OK ? 0 : 1;
    }
    wprintf(L"status=%ls addr=%016llx\n", StatusName(st), static_cast<unsigned long long>(out));
    PrintStatusHint(L"ptrchain", st);
    return st == HDL_OK ? 0 : 1;
}

int CmdModbase(CmdCtx& ctx) {
    using namespace hdl::proto;
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;

    std::wstring module;
    for (int i = 3; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--module") == 0 && i + 1 < ctx.argc) {
            module = ctx.argv[++i];
        }
    }
    AppendPod(req, static_cast<uint32_t>(OpModuleBase));
    AppendWString(req, module.c_str());
    if (!ctx.client.Request(req, resp)) {
        return FailIpc(ctx);
    }
    Reader r(resp);
    int32_t st = 0;
    uint64_t base = 0;
    if (!r.TakePod(st) || !r.TakePod(base)) {
        return FailBadResp(ctx);
    }
    if (ctx.json) {
        JsonWriter w;
        w.BeginObject();
        w.Key("base");
        w.HexStr(base);
        w.EndObject();
        EmitEnvelope(ctx, st, L"modbase", w.Take());
        return st == HDL_OK ? 0 : 1;
    }
    wprintf(L"status=%ls base=%016llx\n", StatusName(st), static_cast<unsigned long long>(base));
    PrintStatusHint(L"modbase", st);
    return st == HDL_OK ? 0 : 1;
}

int CmdResolvePattern(CmdCtx& ctx) {
    using namespace hdl::proto;
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;

    if (ctx.argc < 4) {
        return FailUsage(ctx);
    }
    char pattern[1024];
    WideCharToMultiByte(CP_UTF8, 0, ctx.argv[3], -1, pattern, sizeof(pattern), nullptr, nullptr);
    uint32_t hit = 0;
    int32_t off = 0;
    uint32_t rip_disp = 0;
    uint32_t rip_len = 0;
    uint32_t flags = 0;
    std::wstring module;
    std::vector<int64_t> follows;
    for (int i = 4; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--hit") == 0 && i + 1 < ctx.argc) {
            hit = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
        } else if (wcscmp(ctx.argv[i], L"--offset") == 0 && i + 1 < ctx.argc) {
            off = _wtoi(ctx.argv[++i]);
        } else if (wcscmp(ctx.argv[i], L"--rip-disp") == 0 && i + 1 < ctx.argc) {
            rip_disp = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
        } else if (wcscmp(ctx.argv[i], L"--rip-len") == 0 && i + 1 < ctx.argc) {
            rip_len = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
        } else if (wcscmp(ctx.argv[i], L"--follow") == 0 && i + 1 < ctx.argc) {
            follows.push_back(_wcstoi64(ctx.argv[++i], nullptr, 0));
        } else if (wcscmp(ctx.argv[i], L"--module") == 0 && i + 1 < ctx.argc) {
            module = ctx.argv[++i];
            flags |= HDL_SEARCH_MODULE;
        } else if (wcscmp(ctx.argv[i], L"--image") == 0) {
            flags |= HDL_SEARCH_IMAGE;
        } else if (wcscmp(ctx.argv[i], L"--executable") == 0) {
            flags |= HDL_SEARCH_EXECUTABLE;
        }
    }
    AppendPod(req, static_cast<uint32_t>(OpResolvePattern));
    AppendString(req, pattern);
    AppendPod(req, hit);
    AppendPod(req, off);
    AppendPod(req, rip_disp);
    AppendPod(req, rip_len);
    AppendPod(req, static_cast<uint32_t>(follows.size()));
    AppendPod(req, flags);
    AppendPod(req, static_cast<uint32_t>(256));
    AppendWString(req, module.c_str());
    for (int64_t f : follows) {
        AppendPod(req, f);
    }
    if (!ctx.client.Request(req, resp)) {
        return FailIpc(ctx);
    }
    Reader r(resp);
    int32_t st = 0;
    HdlPatternResult out{};
    if (!r.TakePod(st) || !hdl::proto::TakeHdlPatternResult(r, out)) {
        return FailBadResp(ctx);
    }
    if (ctx.json) {
        JsonWriter w;
        w.BeginObject();
        w.Key("match");
        w.HexStr(out.match_addr);
        w.Key("resolved");
        w.HexStr(out.resolved_addr);
        w.Key("base");
        w.HexStr(out.module_base);
        w.Key("rva");
        w.HexStr(out.rva);
        w.EndObject();
        EmitEnvelope(ctx, st, L"resolve-pattern", w.Take());
        return st == HDL_OK ? 0 : 1;
    }
    wprintf(L"status=%ls match=%016llx resolved=%016llx base=%016llx rva=%llx\n", StatusName(st),
            static_cast<unsigned long long>(out.match_addr),
            static_cast<unsigned long long>(out.resolved_addr),
            static_cast<unsigned long long>(out.module_base),
            static_cast<unsigned long long>(out.rva));
    PrintStatusHint(L"resolve-pattern", st);
    return st == HDL_OK ? 0 : 1;
}

int CmdXrefs(CmdCtx& ctx) {
    using namespace hdl::proto;
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;

    if (ctx.argc < 4) {
        return FailUsage(ctx);
    }
    char narrow[1024];
    WideCharToMultiByte(CP_UTF8, 0, ctx.argv[3], -1, narrow, sizeof(narrow), nullptr, nullptr);
    int is_wide = 0;
    uint32_t xref_flags = 0;
    uint32_t search_flags = HDL_SEARCH_IMAGE;
    std::wstring module;
    for (int i = 4; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--wide") == 0) {
            is_wide = 1;
        } else if (wcscmp(ctx.argv[i], L"--absolute") == 0) {
            xref_flags |= HDL_XREF_ABSOLUTE;
        } else if (wcscmp(ctx.argv[i], L"--rip") == 0) {
            xref_flags |= HDL_XREF_RIP_REL;
        } else if (wcscmp(ctx.argv[i], L"--module") == 0 && i + 1 < ctx.argc) {
            module = ctx.argv[++i];
            search_flags |= HDL_SEARCH_MODULE;
        } else if (wcscmp(ctx.argv[i], L"--image") == 0) {
            search_flags |= HDL_SEARCH_IMAGE;
        }
    }
    if (!xref_flags) {
        xref_flags = HDL_XREF_ABSOLUTE | HDL_XREF_RIP_REL;
    }
    std::vector<uint8_t> blob;
    if (is_wide) {
        const size_t n = wcslen(ctx.argv[3]) * sizeof(wchar_t);
        blob.resize(n);
        memcpy(blob.data(), ctx.argv[3], n);
    } else {
        blob.assign(reinterpret_cast<uint8_t*>(narrow),
                    reinterpret_cast<uint8_t*>(narrow) + strlen(narrow));
    }
    AppendPod(req, static_cast<uint32_t>(OpFindStringXrefs));
    AppendPod(req, static_cast<uint32_t>(blob.size()));
    AppendPod(req, static_cast<int32_t>(is_wide));
    AppendPod(req, xref_flags);
    AppendPod(req, search_flags);
    AppendPod(req, static_cast<uint32_t>(64));
    AppendWString(req, module.c_str());
    AppendBytes(req, blob.data(), blob.size());
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
        w.Key("addresses");
        w.BeginArray();
        for (uint32_t i = 0; i < count; ++i) {
            uint64_t a = 0;
            if (!r.TakePod(a)) {
                return FailBadResp(ctx);
            }
            w.HexStr(a);
        }
        w.EndArray();
        w.EndObject();
        EmitEnvelope(ctx, st, L"xrefs", w.Take());
        return st == HDL_OK ? 0 : 1;
    }
    wprintf(L"status=%ls count=%u\n", StatusName(st), count);
    for (uint32_t i = 0; i < count; ++i) {
        uint64_t a = 0;
        if (!r.TakePod(a)) {
            return FailBadResp(ctx);
        }
        wprintf(L"  %016llx\n", static_cast<unsigned long long>(a));
    }
    PrintStatusHint(L"xrefs", st);
    return st == HDL_OK ? 0 : 1;
}

int CmdPtrscan(CmdCtx& ctx) {
    using namespace hdl::proto;
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;

    if (ctx.argc < 4) {
        return FailUsage(ctx);
    }
    const uint64_t target = _wcstoui64(ctx.argv[3], nullptr, 0);
    uint32_t depth = 2;
    uint32_t max_off = 0x1000;
    uint32_t max_n = 32;
    uint32_t flags = HDL_SEARCH_IMAGE;
    std::wstring module;
    for (int i = 4; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--depth") == 0 && i + 1 < ctx.argc) {
            depth = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
        } else if (wcscmp(ctx.argv[i], L"--max-offset") == 0 && i + 1 < ctx.argc) {
            max_off = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
        } else if (wcscmp(ctx.argv[i], L"--max") == 0 && i + 1 < ctx.argc) {
            max_n = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
        } else if (wcscmp(ctx.argv[i], L"--module") == 0 && i + 1 < ctx.argc) {
            module = ctx.argv[++i];
            flags |= HDL_SEARCH_MODULE;
        }
    }
    AppendPod(req, static_cast<uint32_t>(OpPointerScan));
    AppendPod(req, target);
    AppendPod(req, depth);
    AppendPod(req, max_off);
    AppendPod(req, max_n);
    AppendPod(req, flags);
    AppendWString(req, module.c_str());
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
        w.Key("paths");
        w.BeginArray();
        for (uint32_t i = 0; i < count; ++i) {
            HdlPointerPath path{};
            if (!hdl::proto::TakeHdlPointerPath(r, path)) {
                return FailBadResp(ctx);
            }
            if (i == 0) {
                hdlcli::RememberPath(ctx.controller, path, module.empty() ? nullptr : module.c_str());
            }
            w.BeginObject();
            w.Key("base");
            w.HexStr(path.static_base);
            w.Key("depth");
            w.Num(path.depth);
            w.Key("offsets");
            w.BeginArray();
            for (uint32_t d = 0; d < path.depth && d < 8; ++d) {
                w.Num(path.offsets[d]);
            }
            w.EndArray();
            w.EndObject();
        }
        w.EndArray();
        w.EndObject();
        EmitEnvelope(ctx, st, L"ptrscan", w.Take());
        return st == HDL_OK ? 0 : 1;
    }
    wprintf(L"status=%ls count=%u\n", StatusName(st), count);
    for (uint32_t i = 0; i < count; ++i) {
        HdlPointerPath path{};
        if (!hdl::proto::TakeHdlPointerPath(r, path)) {
            return FailBadResp(ctx);
        }
        if (i == 0) {
            hdlcli::RememberPath(ctx.controller, path, module.empty() ? nullptr : module.c_str());
        }
        wprintf(L"  base=%016llx depth=%u offs=",
                static_cast<unsigned long long>(path.static_base), path.depth);
        for (uint32_t d = 0; d < path.depth && d < 8; ++d) {
            wprintf(L"%s0x%x", d ? L"," : L"", path.offsets[d]);
        }
        wprintf(L"\n");
    }
    PrintStatusHint(L"ptrscan", st);
    return st == HDL_OK ? 0 : 1;
}

int CmdProbe(CmdCtx& ctx) {
    using namespace hdl::proto;
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;

    if (ctx.argc < 4) {
        return FailUsage(ctx);
    }
    const uint64_t addr = _wcstoui64(ctx.argv[3], nullptr, 0);
    uint32_t size = 64;
    for (int i = 4; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--size") == 0 && i + 1 < ctx.argc) {
            size = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
        }
    }
    AppendPod(req, static_cast<uint32_t>(OpProbeStruct));
    AppendPod(req, addr);
    AppendPod(req, size);
    AppendPod(req, static_cast<uint32_t>(64));
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
        w.Key("fields");
        w.BeginArray();
        for (uint32_t i = 0; i < count; ++i) {
            HdlStructField f{};
            if (!hdl::proto::TakeHdlStructField(r, f)) {
                return FailBadResp(ctx);
            }
            w.BeginObject();
            w.Key("offset");
            w.Num(f.offset);
            w.Key("kind");
            w.Num(f.kind);
            w.Key("value");
            w.HexStr(f.value);
            w.EndObject();
        }
        w.EndArray();
        w.EndObject();
        EmitEnvelope(ctx, st, L"probe", w.Take());
        return st == HDL_OK ? 0 : 1;
    }
    wprintf(L"status=%ls fields=%u\n", StatusName(st), count);
    for (uint32_t i = 0; i < count; ++i) {
        HdlStructField f{};
        if (!hdl::proto::TakeHdlStructField(r, f)) {
            return FailBadResp(ctx);
        }
        wprintf(L"  +0x%x kind=%u value=%016llx\n", f.offset, f.kind,
                static_cast<unsigned long long>(f.value));
    }
    PrintStatusHint(L"probe", st);
    return st == HDL_OK ? 0 : 1;
}
