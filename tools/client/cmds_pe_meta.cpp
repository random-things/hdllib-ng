#include "cmds_place_internal.hpp"

using namespace cmds_place_detail;

CommandResult CmdSections(CmdCtx& ctx) {
    hdl::rpc::v1::EnumSectionsRequest request;
    if (ctx.argc >= 4)
        request.set_module_base(_wcstoui64(ctx.argv[3], nullptr, 0));
    std::vector<hdl::rpc::v1::SectionInfo> values;
    const auto status =
        hdl::rpc::PeClient(&ctx.client)
            .EnumSections(request, [&values](const hdl::rpc::v1::EnumSectionsResponse& batch) {
                values.insert(values.end(), batch.sections().begin(), batch.sections().end());
                return true;
            });
    JsonWriter writer;
    writer.BeginObject();
    writer.Key("count");
    writer.Num(values.size());
    writer.Key("sections");
    writer.BeginArray();
    for (const auto& value : values) {
        writer.BeginObject();
        writer.Key("name");
        writer.Str(value.name());
        writer.Key("va");
        writer.HexStr(value.virtual_address());
        writer.Key("vsize");
        writer.HexStr(value.virtual_size());
        writer.EndObject();
    }
    writer.EndArray();
    writer.EndObject();
    return CmdStatus(ctx.cmd.c_str(), status.hdl_status(), writer.Take());
}

CommandResult CmdExports(CmdCtx& ctx) {
    hdl::rpc::v1::EnumExportsRequest request;
    if (ctx.argc >= 4)
        request.set_module_base(_wcstoui64(ctx.argv[3], nullptr, 0));
    std::vector<hdl::rpc::v1::ExportInfo> values;
    const auto status =
        hdl::rpc::PeClient(&ctx.client)
            .EnumExports(request, [&values](const hdl::rpc::v1::EnumExportsResponse& batch) {
                values.insert(values.end(), batch.exports().begin(), batch.exports().end());
                return true;
            });
    JsonWriter writer;
    writer.BeginObject();
    writer.Key("count");
    writer.Num(values.size());
    writer.Key("exports");
    writer.BeginArray();
    for (size_t i = 0; i < (std::min)(values.size(), size_t{32}); ++i) {
        const auto& value = values[i];
        writer.BeginObject();
        writer.Key("name");
        writer.Str(value.name());
        writer.Key("ordinal");
        writer.Num(value.ordinal());
        writer.Key("va");
        writer.HexStr(value.virtual_address());
        writer.EndObject();
    }
    writer.EndArray();
    writer.EndObject();
    return CmdStatus(ctx.cmd.c_str(), status.hdl_status(), writer.Take());
}

CommandResult CmdImports(CmdCtx& ctx) {
    hdl::rpc::v1::EnumImportsRequest request;
    if (ctx.argc >= 4)
        request.set_module_base(_wcstoui64(ctx.argv[3], nullptr, 0));
    std::vector<hdl::rpc::v1::ImportInfo> values;
    const auto status =
        hdl::rpc::PeClient(&ctx.client)
            .EnumImports(request, [&values](const hdl::rpc::v1::EnumImportsResponse& batch) {
                values.insert(values.end(), batch.imports().begin(), batch.imports().end());
                return true;
            });
    JsonWriter writer;
    writer.BeginObject();
    writer.Key("count");
    writer.Num(values.size());
    writer.Key("imports");
    writer.BeginArray();
    for (size_t i = 0; i < (std::min)(values.size(), size_t{32}); ++i) {
        const auto& value = values[i];
        writer.BeginObject();
        writer.Key("module");
        writer.Str(value.module());
        writer.Key("name");
        writer.Str(value.name().empty() ? "(ord)" : value.name());
        writer.Key("iat");
        writer.HexStr(value.iat_address());
        writer.EndObject();
    }
    writer.EndArray();
    writer.EndObject();
    return CmdStatus(ctx.cmd.c_str(), status.hdl_status(), writer.Take());
}

CommandResult CmdFunctions(CmdCtx& ctx) {
    hdl::rpc::v1::EnumFunctionsRequest request;
    request.set_max_results(64);
    std::wstring module;
    for (int i = 3; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--max") == 0 && i + 1 < ctx.argc)
            request.set_max_results(_wtoi(ctx.argv[++i]));
        else if (wcscmp(ctx.argv[i], L"--module") == 0 && i + 1 < ctx.argc)
            module = ctx.argv[++i];
    }
    std::string module_utf8;
    if (!WideToUtf8(module, &module_utf8))
        return FailArg(ctx, L"bad module");
    request.mutable_scope()->set_module(std::move(module_utf8));
    if (!module.empty())
        request.mutable_scope()->set_flags(HDL_SEARCH_MODULE);
    std::vector<hdl::rpc::v1::FunctionInfo> values;
    const auto status =
        hdl::rpc::LocateClient(&ctx.client)
            .EnumFunctions(request, [&values](const hdl::rpc::v1::EnumFunctionsResponse& batch) {
                values.insert(values.end(), batch.functions().begin(), batch.functions().end());
                return true;
            });
    JsonWriter writer;
    writer.BeginObject();
    writer.Key("count");
    writer.Num(values.size());
    writer.Key("functions");
    writer.BeginArray();
    for (size_t i = 0; i < (std::min)(values.size(), size_t{32}); ++i) {
        writer.BeginObject();
        writer.Key("start");
        writer.HexStr(values[i].start());
        writer.Key("conf");
        writer.Num(values[i].confidence());
        writer.EndObject();
    }
    writer.EndArray();
    writer.EndObject();
    return CmdStatus(ctx.cmd.c_str(), status.hdl_status(), writer.Take());
}

CommandResult CmdXrefsFrom(CmdCtx& ctx) {
    if (ctx.argc < 4)
        return FailUsage(ctx);
    hdl::rpc::v1::XrefsFromRequest request;
    request.set_seed(_wcstoui64(ctx.argv[3], nullptr, 0));
    request.set_max_depth(2);
    request.set_max_nodes(64);
    std::vector<hdl::rpc::v1::XrefEdge> values;
    const auto status =
        hdl::rpc::LocateClient(&ctx.client)
            .XrefsFrom(request, [&values](const hdl::rpc::v1::XrefsFromResponse& batch) {
                values.insert(values.end(), batch.edges().begin(), batch.edges().end());
                return true;
            });
    JsonWriter writer;
    writer.BeginObject();
    writer.Key("count");
    writer.Num(values.size());
    writer.Key("edges");
    writer.BeginArray();
    for (const auto& value : values) {
        writer.BeginObject();
        writer.Key("from");
        writer.HexStr(value.from());
        writer.Key("to");
        writer.HexStr(value.to());
        writer.Key("kind");
        writer.Num(value.kind());
        writer.EndObject();
    }
    writer.EndArray();
    writer.EndObject();
    return CmdStatus(ctx.cmd.c_str(), status.hdl_status(), writer.Take());
}

CommandResult CmdResolveFunction(CmdCtx& ctx) {
    if (ctx.argc < 4)
        return FailUsage(ctx);
    hdl::rpc::v1::ResolveFunctionRequest request;
    request.set_address(_wcstoui64(ctx.argv[3], nullptr, 0));
    std::wstring module;
    for (int i = 4; i < ctx.argc; ++i)
        if (wcscmp(ctx.argv[i], L"--module") == 0 && i + 1 < ctx.argc)
            module = ctx.argv[++i];
    std::string module_utf8;
    if (!WideToUtf8(module, &module_utf8))
        return FailArg(ctx, L"bad module");
    request.mutable_scope()->set_module(std::move(module_utf8));
    if (!module.empty())
        request.mutable_scope()->set_flags(HDL_SEARCH_MODULE);
    const auto result = hdl::rpc::LocateClient(&ctx.client).ResolveFunction(request);
    if (!result.has_response)
        return FailIpc(ctx);
    JsonWriter writer;
    writer.BeginObject();
    if (result.response.has_function()) {
        const auto& fn = result.response.function();
        writer.Key("start");
        writer.HexStr(fn.start());
        writer.Key("end");
        writer.HexStr(fn.end());
        writer.Key("conf");
        writer.Num(fn.confidence());
        writer.Key("flags");
        writer.Num(fn.flags());
    }
    writer.EndObject();
    return CmdStatus(ctx.cmd.c_str(), result.status.hdl_status(), writer.Take());
}

CommandResult CmdXrefsTo(CmdCtx& ctx) {
    if (ctx.argc < 4)
        return FailUsage(ctx);
    hdl::rpc::v1::XrefsToRequest request;
    request.set_target(_wcstoui64(ctx.argv[3], nullptr, 0));
    request.set_max_nodes(64);
    request.set_kinds(HDL_XREF_CALL | HDL_XREF_JMP | HDL_XREF_FUNC);
    std::wstring module;
    for (int i = 4; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--max") == 0 && i + 1 < ctx.argc)
            request.set_max_nodes(_wtoi(ctx.argv[++i]));
        else if (wcscmp(ctx.argv[i], L"--module") == 0 && i + 1 < ctx.argc)
            module = ctx.argv[++i];
        else if (wcscmp(ctx.argv[i], L"--exact") == 0)
            request.set_kinds(HDL_XREF_CALL | HDL_XREF_JMP);
    }
    std::string module_utf8;
    if (!WideToUtf8(module, &module_utf8))
        return FailArg(ctx, L"bad module");
    request.mutable_scope()->set_module(std::move(module_utf8));
    if (!module.empty())
        request.mutable_scope()->set_flags(HDL_SEARCH_MODULE);
    std::vector<hdl::rpc::v1::XrefEdge> values;
    const auto status =
        hdl::rpc::LocateClient(&ctx.client)
            .XrefsTo(request, [&values](const hdl::rpc::v1::XrefsToResponse& batch) {
                values.insert(values.end(), batch.edges().begin(), batch.edges().end());
                return true;
            });
    JsonWriter writer;
    writer.BeginObject();
    writer.Key("count");
    writer.Num(values.size());
    writer.Key("edges");
    writer.BeginArray();
    for (const auto& value : values) {
        writer.BeginObject();
        writer.Key("from");
        writer.HexStr(value.from());
        writer.Key("to");
        writer.HexStr(value.to());
        writer.Key("kind");
        writer.Num(value.kind());
        writer.EndObject();
    }
    writer.EndArray();
    writer.EndObject();
    return CmdStatus(ctx.cmd.c_str(), status.hdl_status(), writer.Take());
}

CommandResult CmdInvalidateFnIndex(CmdCtx& ctx) {
    std::wstring module;
    for (int i = 3; i < ctx.argc; ++i)
        if (wcscmp(ctx.argv[i], L"--module") == 0 && i + 1 < ctx.argc)
            module = ctx.argv[++i];
    std::string utf8;
    if (!WideToUtf8(module, &utf8))
        return FailArg(ctx, L"bad module");
    hdl::rpc::v1::InvalidateFnIndexRequest request;
    request.set_module(std::move(utf8));
    const auto result = hdl::rpc::LocateClient(&ctx.client).InvalidateFnIndex(request);
    return result.has_response ? FinishStatus(ctx, result.status.hdl_status()) : FailIpc(ctx);
}
