#include "cmds_place_internal.hpp"

using namespace cmds_place_detail;

CommandResult CmdVtable(CmdCtx& ctx) {
    if (ctx.argc < 4)
        return FailUsage(ctx);
    hdl::rpc::v1::WalkVtableRequest request;
    request.set_address(_wcstoui64(ctx.argv[3], nullptr, 0));
    request.set_is_object(true);
    for (int i = 4; i < ctx.argc; ++i)
        if (wcscmp(ctx.argv[i], L"--vtable") == 0)
            request.set_is_object(false);
    std::vector<uint64_t> slots;
    const auto status =
        hdl::rpc::LocateClient(&ctx.client)
            .WalkVtable(request, [&slots](const hdl::rpc::v1::WalkVtableResponse& batch) {
                slots.insert(slots.end(), batch.slots().begin(), batch.slots().end());
                return true;
            });
    JsonWriter writer;
    writer.BeginObject();
    writer.Key("count");
    writer.Num(slots.size());
    writer.Key("slots");
    writer.BeginArray();
    for (uint64_t slot : slots)
        writer.HexStr(slot);
    writer.EndArray();
    writer.EndObject();
    return CmdStatus(ctx.cmd.c_str(), status.hdl_status(), writer.Take());
}

CommandResult CmdRtti(CmdCtx& ctx) {
    if (ctx.argc < 4)
        return FailUsage(ctx);
    hdl::rpc::v1::QueryRttiNameRequest request;
    request.set_address(_wcstoui64(ctx.argv[3], nullptr, 0));
    request.set_is_object(true);
    const auto result = hdl::rpc::LocateClient(&ctx.client).QueryRttiName(request);
    if (!result.has_response)
        return FailIpc(ctx);
    JsonWriter writer;
    writer.BeginObject();
    writer.Key("name");
    writer.Str(result.response.name());
    writer.EndObject();
    return CmdStatus(ctx.cmd.c_str(), result.status.hdl_status(), writer.Take());
}
