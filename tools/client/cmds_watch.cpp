#include "cmds_place_internal.hpp"

using namespace cmds_place_detail;

CommandResult CmdWatch(CmdCtx& ctx) {
    using namespace hdl::proto;
    if (ctx.argc < 4) {
        return FailUsage(ctx);
    }
    if (_wcsicmp(ctx.argv[3], L"refresh") == 0) {
        PreparedRequest req;
        std::vector<uint8_t> resp;
        SetMethod(req, hdl::rpc::Method::WatchRefresh);
        if (!ctx.client.Request(req, resp)) {
            return FailIpc(ctx);
        }
        Reader r(resp);
        int32_t st = 0;
        r.TakePod(st);
        return FinishStatus(ctx, st);
    }
    if (_wcsicmp(ctx.argv[3], L"hits") == 0) {
        uint32_t max_hits = 32;
        uint32_t timeout_ms = 0;
        for (int i = 4; i < ctx.argc; ++i) {
            if (wcscmp(ctx.argv[i], L"--max") == 0 && i + 1 < ctx.argc) {
                max_hits = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
            } else if (wcscmp(ctx.argv[i], L"--timeout") == 0 && i + 1 < ctx.argc) {
                timeout_ms = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
            }
        }
        PreparedRequest req;
        std::vector<uint8_t> resp;
        SetMethod(req, hdl::rpc::Method::PollWatchHits);
        AppendPod(req, max_hits);
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
        struct WatchHitItem {
            uint64_t watch_handle;
            uint64_t rip;
            uint64_t accessed;
            uint32_t size;
            uint32_t tid;
        };
        std::vector<WatchHitItem> items;
        items.reserve(count);
        for (uint32_t i = 0; i < count; ++i) {
            HdlWatchHit h{};
            if (!hdl::proto::TakeHdlWatchHit(r, h)) {
                return FailBadResp(ctx);
            }
            items.push_back({h.watch_handle, h.rip, h.accessed, h.size, h.tid});
        }
        JsonWriter w;
        w.BeginObject();
        w.Key("count");
        w.Num(count);
        w.Key("hits");
        w.BeginArray();
        for (const auto& h : items) {
            w.BeginObject();
            w.Key("handle");
            w.HexStr(h.watch_handle);
            w.Key("rip");
            w.HexStr(h.rip);
            w.Key("accessed");
            w.HexStr(h.accessed);
            w.Key("size");
            w.Num(h.size);
            w.Key("tid");
            w.Num(h.tid);
            w.EndObject();
        }
        w.EndArray();
        w.EndObject();
        return CmdStatus(ctx.cmd.c_str(), st, w.Take());
    }
    if (_wcsicmp(ctx.argv[3], L"list") == 0) {
        PreparedRequest req;
        std::vector<uint8_t> resp;
        SetMethod(req, hdl::rpc::Method::EnumWatches);
        if (!ctx.client.Request(req, resp)) {
            return FailIpc(ctx);
        }
        Reader r(resp);
        int32_t st = 0;
        uint32_t count = 0;
        if (!r.TakePod(st) || !r.TakePod(count)) {
            return FailBadResp(ctx);
        }
        struct WiItem {
            uint64_t handle;
            uint64_t addr;
            uint32_t type;
        };
        std::vector<WiItem> items;
        items.reserve(count);
        for (uint32_t i = 0; i < count; ++i) {
            HdlWatchInfo wi{};
            if (!hdl::proto::TakeHdlWatchInfo(r, wi)) {
                return FailBadResp(ctx);
            }
            items.push_back({wi.handle, wi.addr, wi.type});
        }
        JsonWriter w;
        w.BeginObject();
        w.Key("count");
        w.Num(count);
        w.Key("watches");
        w.BeginArray();
        for (const auto& wi : items) {
            w.BeginObject();
            w.Key("handle");
            w.HexStr(wi.handle);
            w.Key("addr");
            w.HexStr(wi.addr);
            w.Key("type");
            w.Num(wi.type);
            w.EndObject();
        }
        w.EndArray();
        w.EndObject();
        return CmdStatus(ctx.cmd.c_str(), st, w.Take());
    }
    if (_wcsicmp(ctx.argv[3], L"unwatch") == 0 && ctx.argc >= 5) {
        const uint64_t handle = _wcstoui64(ctx.argv[4], nullptr, 0);
        PreparedRequest req;
        std::vector<uint8_t> resp;
        SetMethod(req, hdl::rpc::Method::Unwatch);
        AppendPod(req, handle);
        if (!ctx.client.Request(req, resp)) {
            return FailIpc(ctx);
        }
        Reader r(resp);
        int32_t st = 0;
        r.TakePod(st);
        return FinishStatus(ctx, st);
    }
    if (_wcsicmp(ctx.argv[3], L"hw") == 0 && ctx.argc >= 5) {
        const uint64_t addr = _wcstoui64(ctx.argv[4], nullptr, 0);
        uint32_t size = 1;
        uint32_t access = HDL_WATCH_HW_WRITE;
        uint32_t tid = 0;
        for (int i = 5; i < ctx.argc; ++i) {
            if (wcscmp(ctx.argv[i], L"--size") == 0 && i + 1 < ctx.argc) {
                size = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
            } else if (wcscmp(ctx.argv[i], L"--access") == 0 && i + 1 < ctx.argc) {
                ++i;
                if (_wcsicmp(ctx.argv[i], L"exec") == 0) {
                    access = HDL_WATCH_HW_EXEC;
                } else if (_wcsicmp(ctx.argv[i], L"rw") == 0) {
                    access = HDL_WATCH_HW_RW;
                } else {
                    access = HDL_WATCH_HW_WRITE;
                }
            } else if (wcscmp(ctx.argv[i], L"--tid") == 0 && i + 1 < ctx.argc) {
                tid = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
            }
        }
        PreparedRequest req;
        std::vector<uint8_t> resp;
        SetMethod(req, hdl::rpc::Method::WatchHw);
        AppendPod(req, addr);
        AppendPod(req, size);
        AppendPod(req, access);
        AppendPod(req, tid);
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
    if (_wcsicmp(ctx.argv[3], L"page") == 0 && ctx.argc >= 6) {
        const uint64_t addr = _wcstoui64(ctx.argv[4], nullptr, 0);
        const uint64_t size = _wcstoui64(ctx.argv[5], nullptr, 0);
        uint32_t mode = HDL_WATCH_PAGE_GUARD;
        for (int i = 6; i < ctx.argc; ++i) {
            if (wcscmp(ctx.argv[i], L"--mode") == 0 && i + 1 < ctx.argc) {
                ++i;
                if (_wcsicmp(ctx.argv[i], L"noaccess") == 0) {
                    mode = HDL_WATCH_PAGE_NOACCESS;
                } else {
                    mode = HDL_WATCH_PAGE_GUARD;
                }
            }
        }
        PreparedRequest req;
        std::vector<uint8_t> resp;
        SetMethod(req, hdl::rpc::Method::WatchPage);
        AppendPod(req, addr);
        AppendPod(req, size);
        AppendPod(req, mode);
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
    return FailUsage(ctx);
}
