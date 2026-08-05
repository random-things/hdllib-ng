#include "cmds_place_internal.hpp"

using namespace cmds_place_detail;

CommandResult CmdCaves(CmdCtx& ctx) {
    using namespace hdl::proto;
    PreparedRequest req;
    std::vector<uint8_t> resp;
    uint32_t min_size = 16;
    uint32_t fill = 0xCC;
    uint32_t flags = 0;
    uint32_t max_results = 64;
    uint64_t near_addr = 0;
    uint64_t max_distance = 0;
    std::wstring module;
    for (int i = 3; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--min") == 0 && i + 1 < ctx.argc) {
            min_size = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
        } else if (wcscmp(ctx.argv[i], L"--fill") == 0 && i + 1 < ctx.argc) {
            fill = static_cast<uint32_t>(wcstoul(ctx.argv[++i], nullptr, 0));
        } else if (wcscmp(ctx.argv[i], L"--near") == 0 && i + 1 < ctx.argc) {
            near_addr = _wcstoui64(ctx.argv[++i], nullptr, 0);
        } else if (wcscmp(ctx.argv[i], L"--dist") == 0 && i + 1 < ctx.argc) {
            max_distance = _wcstoui64(ctx.argv[++i], nullptr, 0);
        } else if (wcscmp(ctx.argv[i], L"--max") == 0 && i + 1 < ctx.argc) {
            max_results = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
        } else if (wcscmp(ctx.argv[i], L"--module") == 0 && i + 1 < ctx.argc) {
            module = ctx.argv[++i];
            flags |= HDL_SEARCH_MODULE;
        } else if (wcscmp(ctx.argv[i], L"--image") == 0) {
            flags |= HDL_SEARCH_IMAGE;
        } else if (wcscmp(ctx.argv[i], L"--executable") == 0) {
            flags |= HDL_SEARCH_EXECUTABLE;
        }
    }
    SetMethod(req, hdl::rpc::Method::FindCaves);
    AppendPod(req, min_size);
    AppendPod(req, fill);
    AppendPod(req, flags);
    AppendPod(req, max_results);
    AppendPod(req, near_addr);
    AppendPod(req, max_distance);
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
    struct CaveItem {
        uint64_t addr;
        uint64_t size;
        uint64_t region_base;
    };
    std::vector<CaveItem> items;
    items.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        HdlCaveInfo c{};
        if (!hdl::proto::TakeHdlCaveInfo(r, c)) {
            return FailBadResp(ctx);
        }
        items.push_back({c.addr, c.size, c.region_base});
    }
    JsonWriter w;
    w.BeginObject();
    w.Key("count");
    w.Num(count);
    w.Key("caves");
    w.BeginArray();
    for (const auto& c : items) {
        w.BeginObject();
        w.Key("addr");
        w.HexStr(c.addr);
        w.Key("size");
        w.HexStr(c.size);
        w.Key("region");
        w.HexStr(c.region_base);
        w.EndObject();
    }
    w.EndArray();
    w.EndObject();
    return CmdStatus(ctx.cmd.c_str(), st, w.Take());
}

CommandResult CmdAllocNear(CmdCtx& ctx) {
    using namespace hdl::proto;
    if (ctx.argc < 5) {
        return FailUsage(ctx);
    }
    const uint64_t near_addr = _wcstoui64(ctx.argv[3], nullptr, 0);
    const uint64_t size = _wcstoui64(ctx.argv[4], nullptr, 0);
    uint64_t dist = 0x7FFFFFFFull;
    uint32_t protect = PAGE_EXECUTE_READWRITE;
    for (int i = 5; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--dist") == 0 && i + 1 < ctx.argc) {
            dist = _wcstoui64(ctx.argv[++i], nullptr, 0);
        }
    }
    PreparedRequest req;
    std::vector<uint8_t> resp;
    SetMethod(req, hdl::rpc::Method::AllocNear);
    AppendPod(req, near_addr);
    AppendPod(req, dist);
    AppendPod(req, size);
    AppendPod(req, protect);
    if (!ctx.client.Request(req, resp)) {
        return FailIpc(ctx);
    }
    Reader r(resp);
    int32_t st = 0;
    uint64_t addr = 0;
    if (!r.TakePod(st) || !r.TakePod(addr)) {
        return FailBadResp(ctx);
    }
    JsonWriter w;
    w.BeginObject();
    w.Key("addr");
    w.HexStr(addr);
    w.EndObject();
    return CmdStatus(ctx.cmd.c_str(), st, w.Take());
}

CommandResult CmdProtect(CmdCtx& ctx) {
    using namespace hdl::proto;
    if (ctx.argc < 6) {
        return FailUsage(ctx);
    }
    const uint64_t addr = _wcstoui64(ctx.argv[3], nullptr, 0);
    const uint64_t size = _wcstoui64(ctx.argv[4], nullptr, 0);
    uint32_t protect = PAGE_EXECUTE_READWRITE;
    if (_wcsicmp(ctx.argv[5], L"R") == 0) {
        protect = PAGE_READONLY;
    } else if (_wcsicmp(ctx.argv[5], L"RW") == 0) {
        protect = PAGE_READWRITE;
    } else if (_wcsicmp(ctx.argv[5], L"RX") == 0) {
        protect = PAGE_EXECUTE_READ;
    } else if (_wcsicmp(ctx.argv[5], L"RWX") == 0) {
        protect = PAGE_EXECUTE_READWRITE;
    } else {
        protect = static_cast<uint32_t>(wcstoul(ctx.argv[5], nullptr, 0));
    }
    PreparedRequest req;
    std::vector<uint8_t> resp;
    SetMethod(req, hdl::rpc::Method::ProtectMemory);
    AppendPod(req, addr);
    AppendPod(req, size);
    AppendPod(req, protect);
    if (!ctx.client.Request(req, resp)) {
        return FailIpc(ctx);
    }
    Reader r(resp);
    int32_t st = 0;
    uint32_t old = 0;
    if (!r.TakePod(st) || !r.TakePod(old)) {
        return FailBadResp(ctx);
    }
    JsonWriter w;
    w.BeginObject();
    w.Key("old");
    w.Num(old);
    w.EndObject();
    return CmdStatus(ctx.cmd.c_str(), st, w.Take());
}

CommandResult CmdFlushICache(CmdCtx& ctx) {
    using namespace hdl::proto;
    if (ctx.argc < 5) {
        return FailUsage(ctx);
    }
    const uint64_t addr = _wcstoui64(ctx.argv[3], nullptr, 0);
    const uint64_t size = _wcstoui64(ctx.argv[4], nullptr, 0);
    PreparedRequest req;
    std::vector<uint8_t> resp;
    SetMethod(req, hdl::rpc::Method::FlushICache);
    AppendPod(req, addr);
    AppendPod(req, size);
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
