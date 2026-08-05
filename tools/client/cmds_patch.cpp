#include "cmds_place_internal.hpp"

using namespace cmds_place_detail;

CommandResult CmdPatch(CmdCtx& ctx) {
    using namespace hdl::proto;
    if (ctx.argc < 4) {
        return FailUsage(ctx);
    }
    if (_wcsicmp(ctx.argv[3], L"list") == 0) {
        PreparedRequest req;
        std::vector<uint8_t> resp;
        SetMethod(req, hdl::rpc::Method::PatchEnum);
        if (!ctx.client.Request(req, resp)) {
            return FailIpc(ctx);
        }
        Reader r(resp);
        int32_t st = 0;
        uint32_t count = 0;
        if (!r.TakePod(st) || !r.TakePod(count)) {
            return FailBadResp(ctx);
        }
        struct PatchItem {
            uint64_t handle;
            uint64_t addr;
            int32_t enabled;
            char name[64];
        };
        std::vector<PatchItem> items;
        items.reserve(count);
        for (uint32_t i = 0; i < count; ++i) {
            HdlPatchInfo p{};
            if (!hdl::proto::TakeHdlPatchInfo(r, p)) {
                return FailBadResp(ctx);
            }
            PatchItem pi;
            pi.handle = p.handle;
            pi.addr = p.addr;
            pi.enabled = p.enabled;
            strncpy_s(pi.name, p.name, _TRUNCATE);
            items.push_back(pi);
        }
        JsonWriter w;
        w.BeginObject();
        w.Key("count");
        w.Num(count);
        w.Key("patches");
        w.BeginArray();
        for (const auto& pi : items) {
            w.BeginObject();
            w.Key("handle");
            w.HexStr(pi.handle);
            w.Key("addr");
            w.HexStr(pi.addr);
            w.Key("enabled");
            w.Bool(pi.enabled != 0);
            w.Key("name");
            w.Str(pi.name);
            w.EndObject();
        }
        w.EndArray();
        w.EndObject();
        return CmdStatus(ctx.cmd.c_str(), st, w.Take());
    }
    if (_wcsicmp(ctx.argv[3], L"create") == 0 && ctx.argc >= 6) {
        const uint64_t addr = _wcstoui64(ctx.argv[4], nullptr, 0);
        std::vector<uint8_t> bytes;
        if (!ParseHexBytes(ctx.argv[5], bytes) || bytes.empty()) {
            return FailArg(ctx, L"bad hex bytes");
        }
        std::string name;
        for (int i = 6; i < ctx.argc; ++i) {
            if (wcscmp(ctx.argv[i], L"--name") == 0 && i + 1 < ctx.argc) {
                char buf[64];
                WideCharToMultiByte(CP_UTF8, 0, ctx.argv[++i], -1, buf, sizeof(buf), nullptr,
                                    nullptr);
                name = buf;
            }
        }
        PreparedRequest req;
        std::vector<uint8_t> resp;
        SetMethod(req, hdl::rpc::Method::PatchCreate);
        AppendPod(req, addr);
        AppendPod(req, static_cast<uint32_t>(bytes.size()));
        AppendString(req, name.c_str());
        AppendBytes(req, bytes.data(), bytes.size());
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
        return CmdStatus(ctx.cmd.c_str(), st, w.Take());
    }
    if ((_wcsicmp(ctx.argv[3], L"enable") == 0 || _wcsicmp(ctx.argv[3], L"disable") == 0) &&
        ctx.argc >= 5) {
        const uint64_t handle = _wcstoui64(ctx.argv[4], nullptr, 0);
        const int32_t en = _wcsicmp(ctx.argv[3], L"enable") == 0 ? 1 : 0;
        PreparedRequest req;
        std::vector<uint8_t> resp;
        SetMethod(req, hdl::rpc::Method::PatchEnable);
        AppendPod(req, handle);
        AppendPod(req, en);
        if (!ctx.client.Request(req, resp)) {
            return FailIpc(ctx);
        }
        Reader r(resp);
        int32_t st = 0;
        r.TakePod(st);
        return FinishStatus(ctx, st);
    }
    if (_wcsicmp(ctx.argv[3], L"remove") == 0 && ctx.argc >= 5) {
        const uint64_t handle = _wcstoui64(ctx.argv[4], nullptr, 0);
        PreparedRequest req;
        std::vector<uint8_t> resp;
        SetMethod(req, hdl::rpc::Method::PatchRemove);
        AppendPod(req, handle);
        if (!ctx.client.Request(req, resp)) {
            return FailIpc(ctx);
        }
        Reader r(resp);
        int32_t st = 0;
        r.TakePod(st);
        return FinishStatus(ctx, st);
    }
    return FailUsage(ctx);
}

CommandResult CmdStub(CmdCtx& ctx) {
    using namespace hdl::proto;
    int32_t kind = HDL_STUB_MOV_RAX_JMP;
    uint64_t target = 0;
    uint64_t steal_from = 0;
    uint32_t steal_min = 0;
    uint32_t alloc_rx = 1;
    std::vector<uint8_t> raw;
    for (int i = 3; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--kind") == 0 && i + 1 < ctx.argc) {
            ++i;
            if (_wcsicmp(ctx.argv[i], L"abs_jmp") == 0) {
                kind = HDL_STUB_ABS_JMP;
            } else if (_wcsicmp(ctx.argv[i], L"rel_jmp32") == 0) {
                kind = HDL_STUB_REL_JMP32;
            } else if (_wcsicmp(ctx.argv[i], L"raw") == 0) {
                kind = HDL_STUB_RAW;
            } else {
                kind = HDL_STUB_MOV_RAX_JMP;
            }
        } else if (wcscmp(ctx.argv[i], L"--target") == 0 && i + 1 < ctx.argc) {
            target = _wcstoui64(ctx.argv[++i], nullptr, 0);
        } else if (wcscmp(ctx.argv[i], L"--steal") == 0 && i + 1 < ctx.argc) {
            steal_from = _wcstoui64(ctx.argv[++i], nullptr, 0);
        } else if (wcscmp(ctx.argv[i], L"--steal-min") == 0 && i + 1 < ctx.argc) {
            steal_min = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
        } else if (wcscmp(ctx.argv[i], L"--alloc") == 0) {
            alloc_rx = 1;
        } else if (wcscmp(ctx.argv[i], L"--no-alloc") == 0) {
            alloc_rx = 0;
        } else if (wcscmp(ctx.argv[i], L"--raw") == 0 && i + 1 < ctx.argc) {
            if (!ParseHexBytes(ctx.argv[++i], raw)) {
                return FailArg(ctx, L"bad --raw hex");
            }
            kind = HDL_STUB_RAW;
        }
    }
    if (kind != HDL_STUB_RAW && !target && !steal_from) {
        return FailUsage(ctx);
    }
    PreparedRequest req;
    std::vector<uint8_t> resp;
    SetMethod(req, hdl::rpc::Method::BuildStub);
    AppendPod(req, kind);
    AppendPod(req, 0u);
    AppendPod(req, target);
    AppendPod(req, steal_from);
    AppendPod(req, steal_min);
    AppendPod(req, 0u);
    AppendPod(req, alloc_rx);
    AppendPod(req, static_cast<uint32_t>(raw.size()));
    if (!raw.empty()) {
        AppendBytes(req, raw.data(), raw.size());
    }
    if (!ctx.client.Request(req, resp)) {
        return FailIpc(ctx);
    }
    Reader r(resp);
    int32_t st = 0;
    HdlStubResult result{};
    if (!r.TakePod(st) || !hdl::proto::TakeHdlStubResult(r, result)) {
        return FailBadResp(ctx);
    }
    JsonWriter w;
    w.BeginObject();
    w.Key("stub_va");
    w.HexStr(result.stub_va);
    w.Key("stolen");
    w.Num(result.stolen_bytes);
    w.Key("size");
    w.Num(result.code_size);
    w.Key("code");
    w.BeginArray();
    for (uint32_t i = 0; i < result.code_size; ++i) {
        w.Num(result.code[i]);
    }
    w.EndArray();
    w.EndObject();
    for (uint32_t i = 0; i < result.code_size; ++i) {
        wchar_t bw[8];
        swprintf_s(bw, L"%02x%s", result.code[i], (i + 1 == result.code_size) ? L"\n" : L" ");
    }
    return CmdStatus(ctx.cmd.c_str(), st, w.Take());
}
