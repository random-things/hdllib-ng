#include "cmds_place_internal.hpp"

using namespace cmds_place_detail;

CommandResult CmdCaves(CmdCtx& ctx) {
    hdl::rpc::v1::FindCavesRequest request;
    request.set_min_size(16);
    request.set_fill_byte(0xCC);
    request.set_max_results(64);
    std::wstring module;
    for (int i = 3; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--min") == 0 && i + 1 < ctx.argc)
            request.set_min_size(_wtoi(ctx.argv[++i]));
        else if (wcscmp(ctx.argv[i], L"--fill") == 0 && i + 1 < ctx.argc)
            request.set_fill_byte(wcstoul(ctx.argv[++i], nullptr, 0));
        else if (wcscmp(ctx.argv[i], L"--near") == 0 && i + 1 < ctx.argc)
            request.set_near_address(_wcstoui64(ctx.argv[++i], nullptr, 0));
        else if (wcscmp(ctx.argv[i], L"--dist") == 0 && i + 1 < ctx.argc)
            request.set_max_distance(_wcstoui64(ctx.argv[++i], nullptr, 0));
        else if (wcscmp(ctx.argv[i], L"--max") == 0 && i + 1 < ctx.argc)
            request.set_max_results(_wtoi(ctx.argv[++i]));
        else if (wcscmp(ctx.argv[i], L"--module") == 0 && i + 1 < ctx.argc) {
            module = ctx.argv[++i];
            request.mutable_scope()->set_flags(request.scope().flags() | HDL_SEARCH_MODULE);
        } else if (wcscmp(ctx.argv[i], L"--image") == 0)
            request.mutable_scope()->set_flags(request.scope().flags() | HDL_SEARCH_IMAGE);
        else if (wcscmp(ctx.argv[i], L"--executable") == 0)
            request.mutable_scope()->set_flags(request.scope().flags() | HDL_SEARCH_EXECUTABLE);
    }
    std::string module_utf8;
    if (!WideToUtf8(module, &module_utf8))
        return FailArg(ctx, L"module is not valid Unicode");
    request.mutable_scope()->set_module(std::move(module_utf8));
    std::vector<hdl::rpc::v1::CaveInfo> caves;
    const auto status =
        hdl::rpc::MemoryClient(&ctx.client)
            .FindCaves(request, [&caves](const hdl::rpc::v1::FindCavesResponse& batch) {
                caves.insert(caves.end(), batch.caves().begin(), batch.caves().end());
                return true;
            });
    JsonWriter writer;
    writer.BeginObject();
    writer.Key("count");
    writer.Num(caves.size());
    writer.Key("caves");
    writer.BeginArray();
    for (const auto& cave : caves) {
        writer.BeginObject();
        writer.Key("addr");
        writer.HexStr(cave.address());
        writer.Key("size");
        writer.HexStr(cave.size());
        writer.Key("region");
        writer.HexStr(cave.region_base());
        writer.EndObject();
    }
    writer.EndArray();
    writer.EndObject();
    return CmdStatus(ctx.cmd.c_str(), status.hdl_status(), writer.Take());
}

CommandResult CmdAllocNear(CmdCtx& ctx) {
    if (ctx.argc < 5)
        return FailUsage(ctx);
    hdl::rpc::v1::AllocNearRequest request;
    request.set_near_address(_wcstoui64(ctx.argv[3], nullptr, 0));
    request.set_size(_wcstoui64(ctx.argv[4], nullptr, 0));
    request.set_max_distance(0x7FFFFFFFull);
    request.set_protection(PAGE_EXECUTE_READWRITE);
    for (int i = 5; i < ctx.argc; ++i)
        if (wcscmp(ctx.argv[i], L"--dist") == 0 && i + 1 < ctx.argc)
            request.set_max_distance(_wcstoui64(ctx.argv[++i], nullptr, 0));
    const auto result = hdl::rpc::MemoryClient(&ctx.client).AllocNear(request);
    if (!result.has_response)
        return FailIpc(ctx);
    JsonWriter writer;
    writer.BeginObject();
    writer.Key("addr");
    writer.HexStr(result.response.address());
    writer.EndObject();
    return CmdStatus(ctx.cmd.c_str(), result.status.hdl_status(), writer.Take());
}

CommandResult CmdProtect(CmdCtx& ctx) {
    if (ctx.argc < 6)
        return FailUsage(ctx);
    uint32_t protection = PAGE_EXECUTE_READWRITE;
    if (_wcsicmp(ctx.argv[5], L"R") == 0)
        protection = PAGE_READONLY;
    else if (_wcsicmp(ctx.argv[5], L"RW") == 0)
        protection = PAGE_READWRITE;
    else if (_wcsicmp(ctx.argv[5], L"RX") == 0)
        protection = PAGE_EXECUTE_READ;
    else if (_wcsicmp(ctx.argv[5], L"RWX") != 0)
        protection = wcstoul(ctx.argv[5], nullptr, 0);
    hdl::rpc::v1::ProtectMemoryRequest request;
    request.set_address(_wcstoui64(ctx.argv[3], nullptr, 0));
    request.set_size(_wcstoui64(ctx.argv[4], nullptr, 0));
    request.set_protection(protection);
    const auto result = hdl::rpc::MemoryClient(&ctx.client).ProtectMemory(request);
    if (!result.has_response)
        return FailIpc(ctx);
    JsonWriter writer;
    writer.BeginObject();
    writer.Key("old");
    writer.Num(result.response.old_protection());
    writer.EndObject();
    return CmdStatus(ctx.cmd.c_str(), result.status.hdl_status(), writer.Take());
}

CommandResult CmdFlushICache(CmdCtx& ctx) {
    if (ctx.argc < 5)
        return FailUsage(ctx);
    hdl::rpc::v1::FlushICacheRequest request;
    request.set_address(_wcstoui64(ctx.argv[3], nullptr, 0));
    request.set_size(_wcstoui64(ctx.argv[4], nullptr, 0));
    const auto result = hdl::rpc::MemoryClient(&ctx.client).FlushICache(request);
    if (!result.has_response)
        return FailIpc(ctx);
    return FinishStatus(ctx, result.status.hdl_status());
}
