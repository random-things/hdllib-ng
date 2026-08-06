#include "cmds_place_internal.hpp"

using namespace cmds_place_detail;

CommandResult CmdWatch(CmdCtx& ctx) {
    if (ctx.argc < 4)
        return FailUsage(ctx);
    hdl::rpc::WatchClient client(&ctx.client);
    if (_wcsicmp(ctx.argv[3], L"refresh") == 0) {
        const auto result = client.WatchRefresh({});
        return result.has_response ? FinishStatus(ctx, result.status.hdl_status()) : FailIpc(ctx);
    }
    if (_wcsicmp(ctx.argv[3], L"hits") == 0) {
        hdl::rpc::v1::PollWatchHitsRequest request;
        request.set_max_hits(32);
        for (int i = 4; i < ctx.argc; ++i) {
            if (wcscmp(ctx.argv[i], L"--max") == 0 && i + 1 < ctx.argc)
                request.set_max_hits(_wtoi(ctx.argv[++i]));
            else if (wcscmp(ctx.argv[i], L"--timeout") == 0 && i + 1 < ctx.argc)
                request.set_wait_timeout_ms(_wtoi(ctx.argv[++i]));
        }
        std::vector<hdl::rpc::v1::WatchHit> hits;
        const auto status = client.PollWatchHits(
            request, [&hits](const hdl::rpc::v1::PollWatchHitsResponse& batch) {
                hits.insert(hits.end(), batch.hits().begin(), batch.hits().end());
                return true;
            });
        JsonWriter writer;
        writer.BeginObject();
        writer.Key("count");
        writer.Num(hits.size());
        writer.Key("hits");
        writer.BeginArray();
        for (const auto& hit : hits) {
            writer.BeginObject();
            writer.Key("handle");
            writer.HexStr(hit.watch_handle());
            writer.Key("rip");
            writer.HexStr(hit.instruction_pointer());
            writer.Key("accessed");
            writer.HexStr(hit.accessed_address());
            writer.Key("size");
            writer.Num(hit.size());
            writer.Key("tid");
            writer.Num(hit.thread_id());
            writer.EndObject();
        }
        writer.EndArray();
        writer.EndObject();
        return CmdStatus(ctx.cmd.c_str(), status.hdl_status(), writer.Take());
    }
    if (_wcsicmp(ctx.argv[3], L"list") == 0) {
        std::vector<hdl::rpc::v1::WatchInfo> watches;
        const auto status =
            client.EnumWatches({}, [&watches](const hdl::rpc::v1::EnumWatchesResponse& batch) {
                watches.insert(watches.end(), batch.watches().begin(), batch.watches().end());
                return true;
            });
        JsonWriter writer;
        writer.BeginObject();
        writer.Key("count");
        writer.Num(watches.size());
        writer.Key("watches");
        writer.BeginArray();
        for (const auto& watch : watches) {
            writer.BeginObject();
            writer.Key("handle");
            writer.HexStr(watch.handle());
            writer.Key("addr");
            writer.HexStr(watch.address());
            writer.Key("type");
            writer.Num(watch.type());
            writer.EndObject();
        }
        writer.EndArray();
        writer.EndObject();
        return CmdStatus(ctx.cmd.c_str(), status.hdl_status(), writer.Take());
    }
    if (_wcsicmp(ctx.argv[3], L"unwatch") == 0 && ctx.argc >= 5) {
        hdl::rpc::v1::UnwatchRequest request;
        request.set_handle(_wcstoui64(ctx.argv[4], nullptr, 0));
        const auto result = client.Unwatch(request);
        return result.has_response ? FinishStatus(ctx, result.status.hdl_status()) : FailIpc(ctx);
    }
    if (_wcsicmp(ctx.argv[3], L"hw") == 0 && ctx.argc >= 5) {
        hdl::rpc::v1::WatchHwRequest request;
        request.set_address(_wcstoui64(ctx.argv[4], nullptr, 0));
        request.set_size(1);
        request.set_access(hdl::rpc::v1::WATCH_HARDWARE_ACCESS_WRITE);
        for (int i = 5; i < ctx.argc; ++i) {
            if (wcscmp(ctx.argv[i], L"--size") == 0 && i + 1 < ctx.argc)
                request.set_size(_wtoi(ctx.argv[++i]));
            else if (wcscmp(ctx.argv[i], L"--access") == 0 && i + 1 < ctx.argc) {
                ++i;
                request.set_access(_wcsicmp(ctx.argv[i], L"exec") == 0
                                       ? hdl::rpc::v1::WATCH_HARDWARE_ACCESS_EXECUTE
                                   : _wcsicmp(ctx.argv[i], L"rw") == 0
                                       ? hdl::rpc::v1::WATCH_HARDWARE_ACCESS_READ_WRITE
                                       : hdl::rpc::v1::WATCH_HARDWARE_ACCESS_WRITE);
            } else if (wcscmp(ctx.argv[i], L"--tid") == 0 && i + 1 < ctx.argc)
                request.set_thread_id(_wtoi(ctx.argv[++i]));
        }
        const auto result = client.WatchHw(request);
        if (!result.has_response)
            return FailIpc(ctx);
        JsonWriter writer;
        writer.BeginObject();
        writer.Key("handle");
        writer.HexStr(result.response.handle());
        writer.EndObject();
        return CmdStatus(ctx.cmd.c_str(), result.status.hdl_status(), writer.Take());
    }
    if (_wcsicmp(ctx.argv[3], L"page") == 0 && ctx.argc >= 6) {
        hdl::rpc::v1::WatchPageRequest request;
        request.set_address(_wcstoui64(ctx.argv[4], nullptr, 0));
        request.set_size(_wcstoui64(ctx.argv[5], nullptr, 0));
        request.set_mode(hdl::rpc::v1::WATCH_PAGE_MODE_GUARD);
        for (int i = 6; i < ctx.argc; ++i)
            if (wcscmp(ctx.argv[i], L"--mode") == 0 && i + 1 < ctx.argc)
                request.set_mode(_wcsicmp(ctx.argv[++i], L"noaccess") == 0
                                     ? hdl::rpc::v1::WATCH_PAGE_MODE_NO_ACCESS
                                     : hdl::rpc::v1::WATCH_PAGE_MODE_GUARD);
        const auto result = client.WatchPage(request);
        if (!result.has_response)
            return FailIpc(ctx);
        JsonWriter writer;
        writer.BeginObject();
        writer.Key("handle");
        writer.HexStr(result.response.handle());
        writer.EndObject();
        return CmdStatus(ctx.cmd.c_str(), result.status.hdl_status(), writer.Take());
    }
    return FailUsage(ctx);
}
