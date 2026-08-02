#include "cmd.hpp"
#include "cmd_fail.hpp"
#include "json_out.hpp"
#include "recipes.hpp"
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

CommandResult CmdRip(CmdCtx& ctx) {
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
    JsonWriter w;
    w.BeginObject();
    w.Key("addr");
    w.HexStr(out);
    w.EndObject();
    return CmdStatus(L"rip", st, w.Take());
}

CommandResult CmdPtrchain(CmdCtx& ctx) {
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
    JsonWriter w;
    w.BeginObject();
    w.Key("addr");
    w.HexStr(out);
    w.EndObject();
    return CmdStatus(L"ptrchain", st, w.Take());
}

CommandResult CmdModbase(CmdCtx& ctx) {
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
    JsonWriter w;
    w.BeginObject();
    w.Key("base");
    w.HexStr(base);
    w.EndObject();
    return CmdStatus(L"modbase", st, w.Take());
}

CommandResult CmdResolvePattern(CmdCtx& ctx) {
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
    return CmdStatus(L"resolve-pattern", st, w.Take());
}

CommandResult CmdXrefs(CmdCtx& ctx) {
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
    std::vector<uint64_t> addrs;
    addrs.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        uint64_t a = 0;
        if (!r.TakePod(a)) {
            return FailBadResp(ctx);
        }
        addrs.push_back(a);
    }
    JsonWriter w;
    w.BeginObject();
    w.Key("count");
    w.Num(count);
    w.Key("addresses");
    w.BeginArray();
    for (uint64_t a : addrs) {
        w.HexStr(a);
    }
    w.EndArray();
    w.EndObject();
    return CmdStatus(L"xrefs", st, w.Take());
}

CommandResult CmdPtrscan(CmdCtx& ctx) {
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
    std::vector<HdlPointerPath> paths;
    paths.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        HdlPointerPath path{};
        if (!hdl::proto::TakeHdlPointerPath(r, path)) {
            return FailBadResp(ctx);
        }
        if (i == 0) {
            hdlcli::RememberPath(ctx.controller, path, module.empty() ? nullptr : module.c_str());
        }
        paths.push_back(path);
    }
    JsonWriter w;
    w.BeginObject();
    w.Key("count");
    w.Num(count);
    w.Key("paths");
    w.BeginArray();
    for (const auto& path : paths) {
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
    for (const auto& path : paths) {
        for (uint32_t d = 0; d < path.depth && d < 8; ++d) {
            wchar_t off[32];
            swprintf_s(off, L"%s0x%x", d ? L"," : L"", path.offsets[d]);
        }
    }
    return CmdStatus(L"ptrscan", st, w.Take());
}

CommandResult CmdProbe(CmdCtx& ctx) {
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
    std::vector<HdlStructField> fields;
    fields.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        HdlStructField f{};
        if (!hdl::proto::TakeHdlStructField(r, f)) {
            return FailBadResp(ctx);
        }
        fields.push_back(f);
    }
    JsonWriter w;
    w.BeginObject();
    w.Key("count");
    w.Num(count);
    w.Key("fields");
    w.BeginArray();
    for (const auto& f : fields) {
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
    return CmdStatus(L"probe", st, w.Take());
}
