#include "cmds_place_internal.hpp"

using namespace cmds_place_detail;

CommandResult CmdDisasmBackend(CmdCtx& ctx) {
    hdl::rpc::CodeClient client(&ctx.client);
    if (ctx.argc >= 4 && _wcsicmp(ctx.argv[3], L"list") == 0) {
        std::vector<hdl::rpc::v1::DisasmBackendInfo> backends;
        const auto status = client.DisasmEnumBackends(
            {}, [&backends](const hdl::rpc::v1::DisasmEnumBackendsResponse& batch) {
                backends.insert(backends.end(), batch.backends().begin(), batch.backends().end());
                return true;
            });
        JsonWriter writer;
        writer.BeginObject();
        writer.Key("backends");
        writer.BeginArray();
        for (const auto& backend : backends) {
            writer.BeginObject();
            writer.Key("id");
            writer.Num(backend.id());
            writer.Key("name");
            writer.Str(backend.name());
            writer.EndObject();
        }
        writer.EndArray();
        writer.EndObject();
        return CmdStatus(ctx.cmd.c_str(), status.hdl_status(), writer.Take());
    }
    if (ctx.argc >= 4 && _wcsicmp(ctx.argv[3], L"get") == 0) {
        const auto result = client.DisasmGetBackend({});
        if (!result.has_response)
            return FailIpc(ctx);
        JsonWriter writer;
        writer.BeginObject();
        writer.Key("id");
        writer.Num(result.response.backend_id());
        writer.EndObject();
        return CmdStatus(ctx.cmd.c_str(), result.status.hdl_status(), writer.Take());
    }
    if (ctx.argc >= 5 && _wcsicmp(ctx.argv[3], L"set") == 0) {
        hdl::rpc::v1::DisasmSetBackendRequest request;
        request.set_backend_id(_wtoi(ctx.argv[4]));
        const auto result = client.DisasmSetBackend(request);
        return result.has_response ? FinishStatus(ctx, result.status.hdl_status()) : FailIpc(ctx);
    }
    return FailUsage(ctx);
}

CommandResult CmdDisasm(CmdCtx& ctx) {
    if (ctx.argc < 4)
        return FailUsage(ctx);
    hdl::rpc::v1::DisasmRequest request;
    request.set_address(_wcstoui64(ctx.argv[3], nullptr, 0));
    request.set_max_instructions(16);
    for (int i = 4; i < ctx.argc; ++i)
        if (wcscmp(ctx.argv[i], L"--max") == 0 && i + 1 < ctx.argc)
            request.set_max_instructions(_wtoi(ctx.argv[++i]));
    std::vector<hdl::rpc::v1::Instruction> instructions;
    const auto status =
        hdl::rpc::CodeClient(&ctx.client)
            .Disasm(request, [&instructions](const hdl::rpc::v1::DisasmResponse& batch) {
                instructions.insert(instructions.end(), batch.instructions().begin(),
                                    batch.instructions().end());
                return true;
            });
    JsonWriter writer;
    writer.BeginObject();
    writer.Key("count");
    writer.Num(instructions.size());
    writer.Key("insns");
    writer.BeginArray();
    for (const auto& instruction : instructions) {
        writer.BeginObject();
        writer.Key("addr");
        writer.HexStr(instruction.address());
        writer.Key("mnemonic");
        writer.Str(instruction.mnemonic());
        writer.Key("op");
        writer.Str(instruction.operands());
        writer.EndObject();
    }
    writer.EndArray();
    writer.EndObject();
    return CmdStatus(ctx.cmd.c_str(), status.hdl_status(), writer.Take());
}

CommandResult CmdInstrLen(CmdCtx& ctx) {
    if (ctx.argc < 4)
        return FailUsage(ctx);
    hdl::rpc::v1::InstrLenRequest request;
    request.set_address(_wcstoui64(ctx.argv[3], nullptr, 0));
    const auto result = hdl::rpc::CodeClient(&ctx.client).InstrLen(request);
    if (!result.has_response)
        return FailIpc(ctx);
    JsonWriter writer;
    writer.BeginObject();
    writer.Key("len");
    writer.Num(result.response.length());
    writer.EndObject();
    return CmdStatus(ctx.cmd.c_str(), result.status.hdl_status(), writer.Take());
}
