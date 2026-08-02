#include "cmds_place_internal.hpp"

using namespace cmds_place_detail;

CommandResult CmdVtable(CmdCtx& ctx) {
    using namespace hdl::proto;
    if (ctx.argc < 4) {
        return FailUsage(ctx);
    }
    const uint64_t addr = _wcstoui64(ctx.argv[3], nullptr, 0);
    int32_t is_object = 1;
    for (int i = 4; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--vtable") == 0) {
            is_object = 0;
        }
    }
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;
    AppendPod(req, static_cast<uint32_t>(OpWalkVtable));
    AppendPod(req, addr);
    AppendPod(req, is_object);
    if (!ctx.client.Request(req, resp)) {
        return FailIpc(ctx);
    }
    Reader r(resp);
    int32_t st = 0;
    uint32_t count = 0;
    if (!r.TakePod(st) || !r.TakePod(count)) {
        return FailBadResp(ctx);
    }
    std::vector<uint64_t> slots;
    slots.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        uint64_t slot = 0;
        if (!r.TakePod(slot)) {
            return FailBadResp(ctx);
        }
        slots.push_back(slot);
    }
    JsonWriter w;
    w.BeginObject();
    w.Key("count");
    w.Num(count);
    w.Key("slots");
    w.BeginArray();
    for (uint64_t slot : slots) {
        w.HexStr(slot);
    }
    w.EndArray();
    w.EndObject();
    return CmdStatus(ctx.cmd.c_str(), st, w.Take());
}

CommandResult CmdRtti(CmdCtx& ctx) {
    using namespace hdl::proto;
    if (ctx.argc < 4) {
        return FailUsage(ctx);
    }
    const uint64_t addr = _wcstoui64(ctx.argv[3], nullptr, 0);
    int32_t is_object = 1;
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;
    AppendPod(req, static_cast<uint32_t>(OpQueryRttiName));
    AppendPod(req, addr);
    AppendPod(req, is_object);
    if (!ctx.client.Request(req, resp)) {
        return FailIpc(ctx);
    }
    Reader r(resp);
    int32_t st = 0;
    std::string name;
    if (!r.TakePod(st) || !r.TakeString(name)) {
        return FailBadResp(ctx);
    }
    JsonWriter w;
    w.BeginObject();
    w.Key("name");
    w.Str(name);
    w.EndObject();
    return CmdStatus(ctx.cmd.c_str(), st, w.Take());
}
