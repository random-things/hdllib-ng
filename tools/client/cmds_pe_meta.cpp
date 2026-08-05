#include "cmds_place_internal.hpp"

using namespace cmds_place_detail;

CommandResult CmdSections(CmdCtx& ctx) {
    using namespace hdl::proto;
    uint64_t base = 0;
    if (ctx.argc >= 4) {
        base = _wcstoui64(ctx.argv[3], nullptr, 0);
    }
    PreparedRequest req;
    std::vector<uint8_t> resp;
    SetMethod(req, hdl::rpc::Method::EnumSections);
    AppendPod(req, base);
    if (!ctx.client.Request(req, resp)) {
        return FailIpc(ctx);
    }
    Reader r(resp);
    int32_t st = 0;
    uint32_t count = 0;
    if (!r.TakePod(st) || !r.TakePod(count)) {
        return FailBadResp(ctx);
    }
    struct SectItem {
        char name[16];
        uint64_t va;
        uint64_t vsize;
    };
    std::vector<SectItem> items;
    items.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        HdlSectionInfo s{};
        if (!hdl::proto::TakeHdlSectionInfo(r, s)) {
            return FailBadResp(ctx);
        }
        SectItem si;
        strncpy_s(si.name, s.name, _TRUNCATE);
        si.va = s.va;
        si.vsize = s.vsize;
        items.push_back(si);
    }
    JsonWriter w;
    w.BeginObject();
    w.Key("count");
    w.Num(count);
    w.Key("sections");
    w.BeginArray();
    for (const auto& si : items) {
        w.BeginObject();
        w.Key("name");
        w.Str(si.name);
        w.Key("va");
        w.HexStr(si.va);
        w.Key("vsize");
        w.HexStr(si.vsize);
        w.EndObject();
    }
    w.EndArray();
    w.EndObject();
    return CmdStatus(ctx.cmd.c_str(), st, w.Take());
}

CommandResult CmdExports(CmdCtx& ctx) {
    using namespace hdl::proto;
    uint64_t base = 0;
    if (ctx.argc >= 4) {
        base = _wcstoui64(ctx.argv[3], nullptr, 0);
    }
    PreparedRequest req;
    std::vector<uint8_t> resp;
    SetMethod(req, hdl::rpc::Method::EnumExports);
    AppendPod(req, base);
    if (!ctx.client.Request(req, resp)) {
        return FailIpc(ctx);
    }
    Reader r(resp);
    int32_t st = 0;
    uint32_t count = 0;
    if (!r.TakePod(st) || !r.TakePod(count)) {
        return FailBadResp(ctx);
    }
    struct ExpItem {
        char name[256];
        uint32_t ordinal;
        uint64_t va;
    };
    std::vector<ExpItem> items;
    items.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        HdlExportInfo e{};
        if (!hdl::proto::TakeHdlExportInfo(r, e)) {
            return FailBadResp(ctx);
        }
        ExpItem ei;
        strncpy_s(ei.name, e.name, _TRUNCATE);
        ei.ordinal = e.ordinal;
        ei.va = e.va;
        items.push_back(ei);
    }
    const uint32_t show = count > 32 ? 32 : count;
    JsonWriter w;
    w.BeginObject();
    w.Key("count");
    w.Num(count);
    w.Key("exports");
    w.BeginArray();
    for (uint32_t i = 0; i < show; ++i) {
        w.BeginObject();
        w.Key("name");
        w.Str(items[i].name);
        w.Key("ordinal");
        w.Num(items[i].ordinal);
        w.Key("va");
        w.HexStr(items[i].va);
        w.EndObject();
    }
    w.EndArray();
    w.EndObject();
    return CmdStatus(ctx.cmd.c_str(), st, w.Take());
}

CommandResult CmdImports(CmdCtx& ctx) {
    using namespace hdl::proto;
    uint64_t base = 0;
    if (ctx.argc >= 4) {
        base = _wcstoui64(ctx.argv[3], nullptr, 0);
    }
    PreparedRequest req;
    std::vector<uint8_t> resp;
    SetMethod(req, hdl::rpc::Method::EnumImports);
    AppendPod(req, base);
    if (!ctx.client.Request(req, resp)) {
        return FailIpc(ctx);
    }
    Reader r(resp);
    int32_t st = 0;
    uint32_t count = 0;
    if (!r.TakePod(st) || !r.TakePod(count)) {
        return FailBadResp(ctx);
    }
    struct ImpItem {
        char module[128];
        char name[256];
        uint64_t iat_va;
    };
    std::vector<ImpItem> items;
    items.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        HdlImportInfo e{};
        if (!hdl::proto::TakeHdlImportInfo(r, e)) {
            return FailBadResp(ctx);
        }
        ImpItem ii;
        strncpy_s(ii.module, e.module, _TRUNCATE);
        strncpy_s(ii.name, e.name[0] ? e.name : "(ord)", _TRUNCATE);
        ii.iat_va = e.iat_va;
        items.push_back(ii);
    }
    const uint32_t show = count > 32 ? 32 : count;
    JsonWriter w;
    w.BeginObject();
    w.Key("count");
    w.Num(count);
    w.Key("imports");
    w.BeginArray();
    for (uint32_t i = 0; i < show; ++i) {
        w.BeginObject();
        w.Key("module");
        w.Str(items[i].module);
        w.Key("name");
        w.Str(items[i].name);
        w.Key("iat");
        w.HexStr(items[i].iat_va);
        w.EndObject();
    }
    w.EndArray();
    w.EndObject();
    return CmdStatus(ctx.cmd.c_str(), st, w.Take());
}

CommandResult CmdFunctions(CmdCtx& ctx) {
    using namespace hdl::proto;
    uint32_t max_results = 64;
    std::wstring module;
    for (int i = 3; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--max") == 0 && i + 1 < ctx.argc) {
            max_results = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
        } else if (wcscmp(ctx.argv[i], L"--module") == 0 && i + 1 < ctx.argc) {
            module = ctx.argv[++i];
        }
    }
    PreparedRequest req;
    std::vector<uint8_t> resp;
    SetMethod(req, hdl::rpc::Method::EnumFunctions);
    AppendPod(req, 0ull);
    AppendPod(req, 0ull);
    AppendPod(req, module.empty() ? 0u : HDL_SEARCH_MODULE);
    AppendPod(req, max_results);
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
    struct FnItem {
        uint64_t start;
        uint32_t confidence;
    };
    std::vector<FnItem> items;
    items.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        HdlFunctionInfo f{};
        if (!hdl::proto::TakeHdlFunctionInfo(r, f)) {
            return FailBadResp(ctx);
        }
        items.push_back({f.start, f.confidence});
    }
    const uint32_t show = count > 32 ? 32 : count;
    JsonWriter w;
    w.BeginObject();
    w.Key("count");
    w.Num(count);
    w.Key("functions");
    w.BeginArray();
    for (uint32_t i = 0; i < show; ++i) {
        w.BeginObject();
        w.Key("start");
        w.HexStr(items[i].start);
        w.Key("conf");
        w.Num(items[i].confidence);
        w.EndObject();
    }
    w.EndArray();
    w.EndObject();
    return CmdStatus(ctx.cmd.c_str(), st, w.Take());
}

CommandResult CmdXrefsFrom(CmdCtx& ctx) {
    using namespace hdl::proto;
    if (ctx.argc < 4) {
        return FailUsage(ctx);
    }
    const uint64_t seed = _wcstoui64(ctx.argv[3], nullptr, 0);
    uint32_t depth = 2;
    uint32_t nodes = 64;
    PreparedRequest req;
    std::vector<uint8_t> resp;
    SetMethod(req, hdl::rpc::Method::XrefsFrom);
    AppendPod(req, seed);
    AppendPod(req, depth);
    AppendPod(req, nodes);
    AppendPod(req, 0u);
    if (!ctx.client.Request(req, resp)) {
        return FailIpc(ctx);
    }
    Reader r(resp);
    int32_t st = 0;
    uint32_t count = 0;
    if (!r.TakePod(st) || !r.TakePod(count)) {
        return FailBadResp(ctx);
    }
    struct EdgeItem {
        uint64_t from;
        uint64_t to;
        uint32_t kind;
    };
    std::vector<EdgeItem> items;
    items.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        HdlXrefEdge e{};
        if (!hdl::proto::TakeHdlXrefEdge(r, e)) {
            return FailBadResp(ctx);
        }
        items.push_back({e.from, e.to, e.kind});
    }
    JsonWriter w;
    w.BeginObject();
    w.Key("count");
    w.Num(count);
    w.Key("edges");
    w.BeginArray();
    for (const auto& e : items) {
        w.BeginObject();
        w.Key("from");
        w.HexStr(e.from);
        w.Key("to");
        w.HexStr(e.to);
        w.Key("kind");
        w.Num(e.kind);
        w.EndObject();
    }
    w.EndArray();
    w.EndObject();
    return CmdStatus(ctx.cmd.c_str(), st, w.Take());
}

CommandResult CmdResolveFunction(CmdCtx& ctx) {
    using namespace hdl::proto;
    if (ctx.argc < 4) {
        return FailUsage(ctx);
    }
    const uint64_t addr = _wcstoui64(ctx.argv[3], nullptr, 0);
    std::wstring module;
    for (int i = 4; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--module") == 0 && i + 1 < ctx.argc) {
            module = ctx.argv[++i];
        }
    }
    PreparedRequest req;
    std::vector<uint8_t> resp;
    SetMethod(req, hdl::rpc::Method::ResolveFunction);
    AppendPod(req, addr);
    AppendPod(req, module.empty() ? 0u : HDL_SEARCH_MODULE);
    AppendWString(req, module.c_str());
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
    if (st == HDL_OK) {
        HdlFunctionInfo f{};
        if (hdl::proto::TakeHdlFunctionInfo(r, f)) {
            w.Key("start");
            w.HexStr(f.start);
            w.Key("end");
            w.HexStr(f.end);
            w.Key("conf");
            w.Num(f.confidence);
            w.Key("flags");
            w.Num(f.flags);
        }
    }
    w.EndObject();
    return CmdStatus(ctx.cmd.c_str(), st, w.Take());
}

CommandResult CmdXrefsTo(CmdCtx& ctx) {
    using namespace hdl::proto;
    if (ctx.argc < 4) {
        return FailUsage(ctx);
    }
    const uint64_t target = _wcstoui64(ctx.argv[3], nullptr, 0);
    uint32_t nodes = 64;
    uint32_t kinds = HDL_XREF_CALL | HDL_XREF_JMP | HDL_XREF_FUNC;
    std::wstring module;
    for (int i = 4; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--max") == 0 && i + 1 < ctx.argc) {
            nodes = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
        } else if (wcscmp(ctx.argv[i], L"--module") == 0 && i + 1 < ctx.argc) {
            module = ctx.argv[++i];
        } else if (wcscmp(ctx.argv[i], L"--exact") == 0) {
            kinds = HDL_XREF_CALL | HDL_XREF_JMP;
        }
    }
    PreparedRequest req;
    std::vector<uint8_t> resp;
    SetMethod(req, hdl::rpc::Method::XrefsTo);
    AppendPod(req, target);
    AppendPod(req, nodes);
    AppendPod(req, kinds);
    AppendPod(req, module.empty() ? 0u : HDL_SEARCH_MODULE);
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
    struct EdgeItem {
        uint64_t from;
        uint64_t to;
        uint32_t kind;
    };
    std::vector<EdgeItem> items;
    items.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        HdlXrefEdge e{};
        if (!hdl::proto::TakeHdlXrefEdge(r, e)) {
            return FailBadResp(ctx);
        }
        items.push_back({e.from, e.to, e.kind});
    }
    JsonWriter w;
    w.BeginObject();
    w.Key("count");
    w.Num(count);
    w.Key("edges");
    w.BeginArray();
    for (const auto& e : items) {
        w.BeginObject();
        w.Key("from");
        w.HexStr(e.from);
        w.Key("to");
        w.HexStr(e.to);
        w.Key("kind");
        w.Num(e.kind);
        w.EndObject();
    }
    w.EndArray();
    w.EndObject();
    return CmdStatus(ctx.cmd.c_str(), st, w.Take());
}

CommandResult CmdInvalidateFnIndex(CmdCtx& ctx) {
    using namespace hdl::proto;
    std::wstring module;
    for (int i = 3; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--module") == 0 && i + 1 < ctx.argc) {
            module = ctx.argv[++i];
        }
    }
    PreparedRequest req;
    std::vector<uint8_t> resp;
    SetMethod(req, hdl::rpc::Method::InvalidateFnIndex);
    AppendWString(req, module.c_str());
    if (!ctx.client.Request(req, resp)) {
        return FailIpc(ctx);
    }
    Reader r(resp);
    int32_t st = 0;
    if (!r.TakePod(st)) {
        return FailBadResp(ctx);
    }
    return FinishStatus(ctx, st);
}
