#include "cmds_place_internal.hpp"

using namespace cmds_place_detail;

CommandResult CmdPatch(CmdCtx& ctx) {
    if (ctx.argc < 4)
        return FailUsage(ctx);
    hdl::rpc::CodeClient client(&ctx.client);
    if (_wcsicmp(ctx.argv[3], L"list") == 0) {
        std::vector<hdl::rpc::v1::PatchInfo> patches;
        const auto status =
            client.PatchEnum({}, [&patches](const hdl::rpc::v1::PatchEnumResponse& batch) {
                patches.insert(patches.end(), batch.patches().begin(), batch.patches().end());
                return true;
            });
        JsonWriter writer;
        writer.BeginObject();
        writer.Key("count");
        writer.Num(patches.size());
        writer.Key("patches");
        writer.BeginArray();
        for (const auto& patch : patches) {
            writer.BeginObject();
            writer.Key("handle");
            writer.HexStr(patch.handle());
            writer.Key("addr");
            writer.HexStr(patch.address());
            writer.Key("enabled");
            writer.Bool(patch.enabled());
            writer.Key("name");
            writer.Str(patch.name());
            writer.EndObject();
        }
        writer.EndArray();
        writer.EndObject();
        return CmdStatus(ctx.cmd.c_str(), status.hdl_status(), writer.Take());
    }
    if (_wcsicmp(ctx.argv[3], L"create") == 0 && ctx.argc >= 6) {
        std::vector<uint8_t> bytes;
        if (!ParseHexBytes(ctx.argv[5], bytes) || bytes.empty())
            return FailArg(ctx, L"bad hex bytes");
        hdl::rpc::v1::PatchCreateRequest request;
        request.set_address(_wcstoui64(ctx.argv[4], nullptr, 0));
        request.set_data(bytes.data(), bytes.size());
        for (int i = 6; i < ctx.argc; ++i)
            if (wcscmp(ctx.argv[i], L"--name") == 0 && i + 1 < ctx.argc) {
                std::string name;
                if (!WideToUtf8(ctx.argv[++i], &name))
                    return FailArg(ctx, L"invalid name");
                request.set_name(std::move(name));
            }
        const auto result = client.PatchCreate(request);
        if (!result.has_response)
            return FailIpc(ctx);
        JsonWriter writer;
        writer.BeginObject();
        writer.Key("handle");
        writer.HexStr(result.response.handle());
        writer.EndObject();
        return CmdStatus(ctx.cmd.c_str(), result.status.hdl_status(), writer.Take());
    }
    if ((_wcsicmp(ctx.argv[3], L"enable") == 0 || _wcsicmp(ctx.argv[3], L"disable") == 0) &&
        ctx.argc >= 5) {
        hdl::rpc::v1::PatchEnableRequest request;
        request.set_handle(_wcstoui64(ctx.argv[4], nullptr, 0));
        request.set_enabled(_wcsicmp(ctx.argv[3], L"enable") == 0);
        const auto result = client.PatchEnable(request);
        return result.has_response ? FinishStatus(ctx, result.status.hdl_status()) : FailIpc(ctx);
    }
    if (_wcsicmp(ctx.argv[3], L"remove") == 0 && ctx.argc >= 5) {
        hdl::rpc::v1::PatchRemoveRequest request;
        request.set_handle(_wcstoui64(ctx.argv[4], nullptr, 0));
        const auto result = client.PatchRemove(request);
        return result.has_response ? FinishStatus(ctx, result.status.hdl_status()) : FailIpc(ctx);
    }
    return FailUsage(ctx);
}

CommandResult CmdStub(CmdCtx& ctx) {
    hdl::rpc::v1::BuildStubRequest request;
    request.set_kind(hdl::rpc::v1::STUB_KIND_MOVE_RAX_JUMP);
    request.set_allocate_rx(true);
    std::vector<uint8_t> raw;
    for (int i = 3; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--kind") == 0 && i + 1 < ctx.argc) {
            ++i;
            request.set_kind(
                _wcsicmp(ctx.argv[i], L"abs_jmp") == 0 ? hdl::rpc::v1::STUB_KIND_ABSOLUTE_JUMP
                : _wcsicmp(ctx.argv[i], L"rel_jmp32") == 0
                    ? hdl::rpc::v1::STUB_KIND_RELATIVE_JUMP_32
                : _wcsicmp(ctx.argv[i], L"raw") == 0 ? hdl::rpc::v1::STUB_KIND_RAW
                                                     : hdl::rpc::v1::STUB_KIND_MOVE_RAX_JUMP);
        } else if (wcscmp(ctx.argv[i], L"--target") == 0 && i + 1 < ctx.argc)
            request.set_target(_wcstoui64(ctx.argv[++i], nullptr, 0));
        else if (wcscmp(ctx.argv[i], L"--steal") == 0 && i + 1 < ctx.argc)
            request.set_steal_from(_wcstoui64(ctx.argv[++i], nullptr, 0));
        else if (wcscmp(ctx.argv[i], L"--steal-min") == 0 && i + 1 < ctx.argc)
            request.set_steal_min_bytes(_wtoi(ctx.argv[++i]));
        else if (wcscmp(ctx.argv[i], L"--no-alloc") == 0)
            request.set_allocate_rx(false);
        else if (wcscmp(ctx.argv[i], L"--alloc") == 0)
            request.set_allocate_rx(true);
        else if (wcscmp(ctx.argv[i], L"--raw") == 0 && i + 1 < ctx.argc) {
            if (!ParseHexBytes(ctx.argv[++i], raw))
                return FailArg(ctx, L"bad --raw hex");
            request.set_kind(hdl::rpc::v1::STUB_KIND_RAW);
        }
    }
    if (request.kind() != hdl::rpc::v1::STUB_KIND_RAW && !request.target() && !request.steal_from())
        return FailUsage(ctx);
    request.set_raw(raw.data(), raw.size());
    const auto result = hdl::rpc::CodeClient(&ctx.client).BuildStub(request);
    if (!result.has_response)
        return FailIpc(ctx);
    const auto& stub = result.response.result();
    JsonWriter writer;
    writer.BeginObject();
    writer.Key("stub_va");
    writer.HexStr(stub.stub_address());
    writer.Key("stolen");
    writer.Num(stub.stolen_bytes());
    writer.Key("size");
    writer.Num(stub.code().size());
    writer.Key("code");
    writer.BeginArray();
    for (unsigned char byte : stub.code())
        writer.Num(byte);
    writer.EndArray();
    writer.EndObject();
    return CmdStatus(ctx.cmd.c_str(), result.status.hdl_status(), writer.Take());
}
