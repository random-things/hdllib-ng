#include "cmd.hpp"
#include "cmd_fail.hpp"
#include "json_out.hpp"
#include "recipes.hpp"
#include "rpc_helpers.hpp"
#include "usage.hpp"
#include "util.hpp"

#include "hdl/rpc/v1/services.rpc.hpp"
#include "hdllib/hdllib.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <algorithm>
#include <string>
#include <vector>

namespace {

bool SetUtf8(std::wstring_view value, std::string* field) {
    return WideToUtf8(value, field);
}

HdlPointerPath ToDomainPath(const hdl::rpc::v1::PointerPath& value) {
    HdlPointerPath path{};
    path.static_base = value.static_base();
    path.depth = static_cast<uint32_t>((std::min)(value.offsets_size(), 8));
    for (uint32_t i = 0; i < path.depth; ++i)
        path.offsets[i] = value.offsets(i);
    return path;
}

} // namespace

CommandResult CmdRip(CmdCtx& ctx) {
    if (ctx.argc < 4)
        return FailUsage(ctx);
    hdl::rpc::v1::ResolveRipRequest request;
    request.set_address(_wcstoui64(ctx.argv[3], nullptr, 0));
    request.set_displacement_offset(3);
    request.set_instruction_length(7);
    for (int i = 4; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--disp") == 0 && i + 1 < ctx.argc)
            request.set_displacement_offset(_wtoi(ctx.argv[++i]));
        else if (wcscmp(ctx.argv[i], L"--len") == 0 && i + 1 < ctx.argc)
            request.set_instruction_length(_wtoi(ctx.argv[++i]));
    }
    const auto result = hdl::rpc::LocateClient(&ctx.client).ResolveRip(request);
    if (!result.has_response)
        return FailIpc(ctx);
    JsonWriter writer;
    writer.BeginObject();
    writer.Key("addr");
    writer.HexStr(result.response.address());
    writer.EndObject();
    return CmdStatus(L"rip", result.status.hdl_status(), writer.Take());
}

CommandResult CmdPtrchain(CmdCtx& ctx) {
    if (ctx.argc < 4)
        return FailUsage(ctx);
    hdl::rpc::v1::FollowPointersRequest request;
    request.set_base(_wcstoui64(ctx.argv[3], nullptr, 0));
    for (int i = 4; i < ctx.argc; ++i)
        request.add_offsets(_wcstoi64(ctx.argv[i], nullptr, 0));
    const auto result = hdl::rpc::LocateClient(&ctx.client).FollowPointers(request);
    if (!result.has_response)
        return FailIpc(ctx);
    JsonWriter writer;
    writer.BeginObject();
    writer.Key("addr");
    writer.HexStr(result.response.address());
    writer.EndObject();
    return CmdStatus(L"ptrchain", result.status.hdl_status(), writer.Take());
}

CommandResult CmdModbase(CmdCtx& ctx) {
    hdl::rpc::v1::ModuleBaseRequest request;
    std::wstring module;
    for (int i = 3; i < ctx.argc; ++i)
        if (wcscmp(ctx.argv[i], L"--module") == 0 && i + 1 < ctx.argc)
            module = ctx.argv[++i];
    if (!SetUtf8(module, request.mutable_module()))
        return FailArg(ctx, L"bad module");
    const auto result = hdl::rpc::LocateClient(&ctx.client).ModuleBase(request);
    if (!result.has_response)
        return FailIpc(ctx);
    JsonWriter writer;
    writer.BeginObject();
    writer.Key("base");
    writer.HexStr(result.response.base());
    writer.EndObject();
    return CmdStatus(L"modbase", result.status.hdl_status(), writer.Take());
}

CommandResult CmdResolvePattern(CmdCtx& ctx) {
    if (ctx.argc < 4)
        return FailUsage(ctx);
    hdl::rpc::v1::ResolvePatternRequest request;
    if (!SetUtf8(ctx.argv[3], request.mutable_pattern()))
        return FailArg(ctx, L"bad pattern");
    request.set_max_scan_hits(256);
    std::wstring module;
    for (int i = 4; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--hit") == 0 && i + 1 < ctx.argc)
            request.set_hit_index(_wtoi(ctx.argv[++i]));
        else if (wcscmp(ctx.argv[i], L"--offset") == 0 && i + 1 < ctx.argc)
            request.set_pattern_offset(_wtoi(ctx.argv[++i]));
        else if (wcscmp(ctx.argv[i], L"--rip-disp") == 0 && i + 1 < ctx.argc)
            request.set_rip_displacement_offset(_wtoi(ctx.argv[++i]));
        else if (wcscmp(ctx.argv[i], L"--rip-len") == 0 && i + 1 < ctx.argc)
            request.set_rip_instruction_length(_wtoi(ctx.argv[++i]));
        else if (wcscmp(ctx.argv[i], L"--follow") == 0 && i + 1 < ctx.argc)
            request.add_follow_offsets(_wcstoi64(ctx.argv[++i], nullptr, 0));
        else if (wcscmp(ctx.argv[i], L"--module") == 0 && i + 1 < ctx.argc) {
            module = ctx.argv[++i];
            request.mutable_scope()->set_flags(request.scope().flags() | HDL_SEARCH_MODULE);
        } else if (wcscmp(ctx.argv[i], L"--image") == 0)
            request.mutable_scope()->set_flags(request.scope().flags() | HDL_SEARCH_IMAGE);
        else if (wcscmp(ctx.argv[i], L"--executable") == 0)
            request.mutable_scope()->set_flags(request.scope().flags() | HDL_SEARCH_EXECUTABLE);
    }
    if (!SetUtf8(module, request.mutable_scope()->mutable_module()))
        return FailArg(ctx, L"bad module");
    const auto result = hdl::rpc::LocateClient(&ctx.client).ResolvePattern(request);
    if (!result.has_response)
        return FailIpc(ctx);
    const auto& value = result.response.result();
    JsonWriter writer;
    writer.BeginObject();
    writer.Key("match");
    writer.HexStr(value.match_address());
    writer.Key("resolved");
    writer.HexStr(value.resolved_address());
    writer.Key("base");
    writer.HexStr(value.module_base());
    writer.Key("rva");
    writer.HexStr(value.rva());
    writer.EndObject();
    return CmdStatus(L"resolve-pattern", result.status.hdl_status(), writer.Take());
}

CommandResult CmdXrefs(CmdCtx& ctx) {
    if (ctx.argc < 4)
        return FailUsage(ctx);
    hdl::rpc::v1::FindStringXrefsRequest request;
    uint32_t search_flags = HDL_SEARCH_IMAGE;
    uint32_t xref_flags = 0;
    bool wide = false;
    std::wstring module;
    for (int i = 4; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--wide") == 0)
            wide = true;
        else if (wcscmp(ctx.argv[i], L"--absolute") == 0)
            xref_flags |= HDL_XREF_ABSOLUTE;
        else if (wcscmp(ctx.argv[i], L"--rip") == 0)
            xref_flags |= HDL_XREF_RIP_REL;
        else if (wcscmp(ctx.argv[i], L"--module") == 0 && i + 1 < ctx.argc) {
            module = ctx.argv[++i];
            search_flags |= HDL_SEARCH_MODULE;
        } else if (wcscmp(ctx.argv[i], L"--image") == 0)
            search_flags |= HDL_SEARCH_IMAGE;
    }
    std::string value;
    if (!SetUtf8(ctx.argv[3], &value) ||
        !SetUtf8(module, request.mutable_scope()->mutable_module()))
        return FailArg(ctx, L"invalid text");
    if (wide)
        request.set_wide_value(value);
    else
        request.set_narrow_value(value);
    request.set_xref_flags(xref_flags ? xref_flags : HDL_XREF_ABSOLUTE | HDL_XREF_RIP_REL);
    request.mutable_scope()->set_flags(search_flags);
    request.set_max_results(64);
    const auto result = hdl::rpc::LocateClient(&ctx.client).FindStringXrefs(request);
    if (!result.has_response)
        return FailIpc(ctx);
    JsonWriter writer;
    writer.BeginObject();
    writer.Key("count");
    writer.Num(result.response.addresses_size());
    writer.Key("addresses");
    writer.BeginArray();
    for (const auto address : result.response.addresses())
        writer.HexStr(address);
    writer.EndArray();
    writer.EndObject();
    return CmdStatus(L"xrefs", result.status.hdl_status(), writer.Take());
}

CommandResult CmdPtrscan(CmdCtx& ctx) {
    if (ctx.argc < 4)
        return FailUsage(ctx);
    hdl::rpc::v1::PointerScanRequest request;
    request.set_target(_wcstoui64(ctx.argv[3], nullptr, 0));
    request.set_max_depth(2);
    request.set_max_offset(0x1000);
    request.set_max_results(32);
    request.mutable_scope()->set_flags(HDL_SEARCH_IMAGE);
    std::wstring module;
    const wchar_t* store_add = nullptr;
    for (int i = 4; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--depth") == 0 && i + 1 < ctx.argc)
            request.set_max_depth(_wtoi(ctx.argv[++i]));
        else if (wcscmp(ctx.argv[i], L"--max-offset") == 0 && i + 1 < ctx.argc)
            request.set_max_offset(_wtoi(ctx.argv[++i]));
        else if (wcscmp(ctx.argv[i], L"--max") == 0 && i + 1 < ctx.argc)
            request.set_max_results(_wtoi(ctx.argv[++i]));
        else if (wcscmp(ctx.argv[i], L"--module") == 0 && i + 1 < ctx.argc) {
            module = ctx.argv[++i];
            request.mutable_scope()->set_flags(request.scope().flags() | HDL_SEARCH_MODULE);
        } else if (wcscmp(ctx.argv[i], L"--store-add") == 0 && i + 1 < ctx.argc)
            store_add = ctx.argv[++i];
    }
    if (!SetUtf8(module, request.mutable_scope()->mutable_module()))
        return FailArg(ctx, L"bad module");
    const auto result = hdl::rpc::LocateClient(&ctx.client).PointerScan(request);
    if (!result.has_response)
        return FailIpc(ctx);
    std::vector<HdlPointerPath> paths;
    paths.reserve(result.response.paths_size());
    for (const auto& value : result.response.paths())
        paths.push_back(ToDomainPath(value));
    if (!paths.empty())
        hdlcli::RememberPath(ctx.controller, paths[0], module.empty() ? nullptr : module.c_str());
    if (store_add && !paths.empty()) {
        if (!ctx.store_path || !ctx.store_path[0])
            return FailArg(ctx, L"--store-add requires --store PATH");
        hdlcli::ControllerState state;
        state.client = &ctx.client;
        state.pid = ctx.pid;
        state.store_path = ctx.store_path;
        if (GetFileAttributesW(ctx.store_path) != INVALID_FILE_ATTRIBUTES &&
            !state.store.Load(ctx.store_path))
            return CmdFail(ctx.cmd.c_str(), HDL_E_FAILED, L"store load failed");
        std::wstring error;
        if (!hdlcli::StoreAddPathInterest(state, WideToUtf8(store_add).c_str(), paths[0],
                                          module.empty() ? nullptr : module.c_str(), &error))
            return CmdFail(ctx.cmd.c_str(), HDL_E_FAILED, error.c_str());
        if (!state.store.Save(ctx.store_path))
            return CmdFail(ctx.cmd.c_str(), HDL_E_FAILED, L"store save failed");
    }
    JsonWriter writer;
    writer.BeginObject();
    writer.Key("count");
    writer.Num(paths.size());
    writer.Key("paths");
    writer.BeginArray();
    for (const auto& path : paths) {
        writer.BeginObject();
        writer.Key("base");
        writer.HexStr(path.static_base);
        writer.Key("depth");
        writer.Num(path.depth);
        writer.Key("offsets");
        writer.BeginArray();
        for (uint32_t i = 0; i < path.depth; ++i)
            writer.Num(path.offsets[i]);
        writer.EndArray();
        writer.EndObject();
    }
    writer.EndArray();
    if (store_add) {
        writer.Key("store_add");
        writer.Str(store_add);
    }
    writer.EndObject();
    return CmdStatus(L"ptrscan", result.status.hdl_status(), writer.Take());
}

CommandResult CmdProbe(CmdCtx& ctx) {
    if (ctx.argc < 4)
        return FailUsage(ctx);
    hdl::rpc::v1::ProbeStructRequest request;
    request.set_address(_wcstoui64(ctx.argv[3], nullptr, 0));
    request.set_size(64);
    request.set_max_fields(64);
    for (int i = 4; i < ctx.argc; ++i)
        if (wcscmp(ctx.argv[i], L"--size") == 0 && i + 1 < ctx.argc)
            request.set_size(_wtoi(ctx.argv[++i]));
    const auto result = hdl::rpc::LocateClient(&ctx.client).ProbeStruct(request);
    if (!result.has_response)
        return FailIpc(ctx);
    JsonWriter writer;
    writer.BeginObject();
    writer.Key("count");
    writer.Num(result.response.fields_size());
    writer.Key("fields");
    writer.BeginArray();
    for (const auto& field : result.response.fields()) {
        writer.BeginObject();
        writer.Key("offset");
        writer.Num(field.offset());
        writer.Key("kind");
        writer.Num(field.kind());
        writer.Key("value");
        writer.HexStr(field.value());
        writer.EndObject();
    }
    writer.EndArray();
    writer.EndObject();
    return CmdStatus(L"probe", result.status.hdl_status(), writer.Take());
}
