#include "cmd.hpp"
#include "cmd_fail.hpp"
#include "json_out.hpp"
#include "recipes.hpp"
#include "rpc_helpers.hpp"
#include "session_persist.hpp"
#include "usage.hpp"
#include "util.hpp"

#include "hdl/rpc/v1/services.rpc.hpp"
#include "hdllib/hdllib.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <algorithm>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

namespace {

std::string Narrow(const wchar_t* value) {
    return WideToUtf8(value ? value : L"");
}

uint64_t SessionOrFallback(CmdCtx& ctx, uint64_t parsed) {
    return parsed ? parsed : hdlcli::ResolveSessionId(ctx);
}

void JsonBeginWithSession(JsonWriter& writer, uint64_t session) {
    writer.BeginObject();
    writer.Key("session");
    writer.HexStr(session);
}

std::string SessionDataJson(uint64_t session) {
    JsonWriter writer;
    JsonBeginWithSession(writer, session);
    writer.EndObject();
    return writer.Take();
}

void JsonWriteCandidates(JsonWriter& writer, const std::vector<hdl::rpc::v1::Candidate>& values) {
    writer.Key("candidates");
    writer.BeginArray();
    for (const auto& value : values) {
        writer.BeginObject();
        writer.Key("id");
        writer.HexStr(value.id());
        writer.Key("kind");
        writer.Num(value.kind());
        writer.Key("conf");
        writer.Num(value.confidence());
        writer.Key("addr");
        writer.HexStr(value.address());
        writer.Key("tag");
        writer.Str(value.tag());
        writer.EndObject();
    }
    writer.EndArray();
}

template <typename Values> void JsonWriteHeatFields(JsonWriter& writer, const Values& values) {
    writer.Key("fields");
    writer.BeginArray();
    for (const auto& value : values) {
        writer.BeginObject();
        writer.Key("offset");
        writer.Num(value.offset());
        writer.Key("changes");
        writer.Num(value.changes());
        writer.Key("kind");
        writer.Num(value.kind());
        writer.Key("size");
        writer.Num(value.size());
        writer.Key("value");
        writer.HexStr(value.last_value());
        writer.EndObject();
    }
    writer.EndArray();
}

const wchar_t* TakeStoreAddName(CmdCtx& ctx) {
    for (int i = 3; i < ctx.argc; ++i)
        if (wcscmp(ctx.argv[i], L"--store-add") == 0 && i + 1 < ctx.argc)
            return ctx.argv[i + 1];
    return nullptr;
}

HdlPointerPath ToDomainPath(const hdl::rpc::v1::PointerPath& value) {
    HdlPointerPath path{};
    path.static_base = value.static_base();
    path.depth = static_cast<uint32_t>((std::min)(value.offsets_size(), 8));
    for (uint32_t index = 0; index < path.depth; ++index)
        path.offsets[index] = value.offsets(index);
    return path;
}

bool ApplyStoreAddPath(CmdCtx& ctx, const HdlPointerPath& path, const wchar_t* module,
                       CommandResult* error_out) {
    const wchar_t* name = TakeStoreAddName(ctx);
    if (!name)
        return true;
    if (!ctx.store_path || !ctx.store_path[0]) {
        if (error_out)
            *error_out = FailArg(ctx, L"--store-add requires --store PATH");
        return false;
    }
    hdlcli::ControllerState state;
    state.client = &ctx.client;
    state.pid = ctx.pid;
    state.store_path = ctx.store_path;
    if (GetFileAttributesW(ctx.store_path) != INVALID_FILE_ATTRIBUTES &&
        !state.store.Load(ctx.store_path)) {
        if (error_out)
            *error_out = CmdFail(ctx.cmd.c_str(), HDL_E_FAILED, L"store load failed");
        return false;
    }
    std::wstring error;
    if (!hdlcli::StoreAddPathInterest(state, WideToUtf8(name).c_str(), path, module, &error)) {
        if (error_out)
            *error_out = CmdFail(ctx.cmd.c_str(), HDL_E_FAILED, error.c_str());
        return false;
    }
    if (!state.store.Save(ctx.store_path)) {
        if (error_out)
            *error_out = CmdFail(ctx.cmd.c_str(), HDL_E_FAILED, L"store save failed");
        return false;
    }
    return true;
}

void ToProto(const HdlFieldPred& input, hdl::rpc::v1::FieldPredicate* output) {
    output->set_offset(input.offset);
    switch (input.kind) {
    case HDL_PRED_EQ_I32:
        output->mutable_equals_i32()->set_value(static_cast<int32_t>(input.a));
        break;
    case HDL_PRED_EQ_F32: {
        float value = 0;
        const uint32_t bits = static_cast<uint32_t>(input.a);
        std::memcpy(&value, &bits, sizeof(value));
        output->mutable_equals_f32()->set_value(value);
        break;
    }
    case HDL_PRED_RANGE_I32:
        output->mutable_range_i32()->set_minimum(static_cast<int32_t>(input.a));
        output->mutable_range_i32()->set_maximum(static_cast<int32_t>(input.b));
        break;
    case HDL_PRED_LE_I32:
        output->mutable_relative_le_i32()->set_relative_offset(static_cast<int32_t>(input.a));
        break;
    case HDL_PRED_PTR:
        output->mutable_pointer();
        break;
    case HDL_PRED_VTABLE:
        output->mutable_vtable();
        break;
    case HDL_PRED_EQ_U64:
        output->mutable_equals_u64()->set_value(static_cast<uint64_t>(input.a));
        break;
    }
}

bool ParseValueTypeLocal(const wchar_t* value, int32_t* output) {
    if (!value || !output)
        return false;
    struct Pair {
        const wchar_t* text;
        int32_t type;
    };
    static constexpr Pair pairs[] = {
        {L"bytes", HDL_VALUE_BYTES},    {L"aob", HDL_VALUE_BYTES},  {L"i8", HDL_VALUE_I8},
        {L"u8", HDL_VALUE_U8},          {L"i16", HDL_VALUE_I16},    {L"u16", HDL_VALUE_U16},
        {L"i32", HDL_VALUE_I32},        {L"u32", HDL_VALUE_U32},    {L"i64", HDL_VALUE_I64},
        {L"u64", HDL_VALUE_U64},        {L"f32", HDL_VALUE_F32},    {L"float", HDL_VALUE_F32},
        {L"f64", HDL_VALUE_F64},        {L"double", HDL_VALUE_F64}, {L"string", HDL_VALUE_STRING},
        {L"wstring", HDL_VALUE_WSTRING}};
    for (const auto& pair : pairs)
        if (_wcsicmp(value, pair.text) == 0) {
            *output = pair.type;
            return true;
        }
    return false;
}

bool SetSearchValueLocal(int32_t type, const std::wstring& text,
                         hdl::rpc::v1::SearchValue* output) {
    wchar_t* end = nullptr;
    switch (type) {
    case HDL_VALUE_BYTES:
        output->set_aob_pattern(WideToUtf8(text));
        return true;
    case HDL_VALUE_STRING:
        output->set_narrow_bytes(WideToUtf8(text));
        return !text.empty();
    case HDL_VALUE_WSTRING:
        output->set_wide_text(WideToUtf8(text));
        return !text.empty();
    case HDL_VALUE_I8:
        output->set_signed_8(static_cast<int32_t>(_wcstoi64(text.c_str(), &end, 0)));
        break;
    case HDL_VALUE_U8:
        output->set_unsigned_8(static_cast<uint32_t>(_wcstoui64(text.c_str(), &end, 0)));
        break;
    case HDL_VALUE_I16:
        output->set_signed_16(static_cast<int32_t>(_wcstoi64(text.c_str(), &end, 0)));
        break;
    case HDL_VALUE_U16:
        output->set_unsigned_16(static_cast<uint32_t>(_wcstoui64(text.c_str(), &end, 0)));
        break;
    case HDL_VALUE_I32:
        output->set_signed_32(static_cast<int32_t>(_wcstoi64(text.c_str(), &end, 0)));
        break;
    case HDL_VALUE_U32:
        output->set_unsigned_32(static_cast<uint32_t>(_wcstoui64(text.c_str(), &end, 0)));
        break;
    case HDL_VALUE_I64:
        output->set_signed_64(_wcstoi64(text.c_str(), &end, 0));
        break;
    case HDL_VALUE_U64:
        output->set_unsigned_64(_wcstoui64(text.c_str(), &end, 0));
        break;
    case HDL_VALUE_F32:
        output->set_float_32(static_cast<float>(wcstod(text.c_str(), &end)));
        break;
    case HDL_VALUE_F64:
        output->set_float_64(wcstod(text.c_str(), &end));
        break;
    default:
        return false;
    }
    return end != text.c_str() && *end == L'\0';
}

bool OpenInWide(const wchar_t* path, std::ifstream* output) {
    if (!path || !output)
        return false;
    output->open(path, std::ios::binary);
    return static_cast<bool>(*output);
}
bool OpenOutWide(const wchar_t* path, std::ofstream* output) {
    if (!path || !output)
        return false;
    output->open(path, std::ios::binary);
    return static_cast<bool>(*output);
}

} // namespace

bool ClientParsePred(const wchar_t* spec, HdlFieldPred* output) {
    if (!spec || !output)
        return false;
    std::wstring rest(spec);
    auto take = [](std::wstring* value) {
        const size_t pos = value->find(L':');
        if (pos == std::wstring::npos) {
            std::wstring part = *value;
            value->clear();
            return part;
        }
        std::wstring part = value->substr(0, pos);
        *value = value->substr(pos + 1);
        return part;
    };
    const std::wstring kind = take(&rest), offset = take(&rest);
    *output = {};
    output->offset = _wtoi(offset.c_str());
    if (kind == L"eq_i32") {
        output->kind = HDL_PRED_EQ_I32;
        output->a = _wtoi64(rest.c_str());
    } else if (kind == L"range_i32") {
        output->kind = HDL_PRED_RANGE_I32;
        output->a = _wtoi64(take(&rest).c_str());
        output->b = _wtoi64(rest.c_str());
    } else if (kind == L"le_i32") {
        output->kind = HDL_PRED_LE_I32;
        output->a = _wtoi64(rest.c_str());
    } else if (kind == L"eq_u64") {
        output->kind = HDL_PRED_EQ_U64;
        output->a = static_cast<int64_t>(_wcstoui64(rest.c_str(), nullptr, 0));
    } else if (kind == L"eq_f32") {
        output->kind = HDL_PRED_EQ_F32;
        const float value = static_cast<float>(_wtof(rest.c_str()));
        uint32_t bits = 0;
        std::memcpy(&bits, &value, sizeof(bits));
        output->a = bits;
    } else if (kind == L"ptr")
        output->kind = HDL_PRED_PTR;
    else if (kind == L"vtable")
        output->kind = HDL_PRED_VTABLE;
    else
        return false;
    return true;
}

CommandResult CmdDiscoverCreate(CmdCtx& ctx) {
    const auto result = hdl::rpc::DiscoverClient(&ctx.client).DiscoverCreate(hdl::rpc::v1::Empty{});
    const uint64_t id = result.has_response ? result.response.session_id() : 0;
    if (result.status.ok() && id && !hdlcli::PersistSessionId(ctx, id))
        return CmdFail(ctx.cmd.c_str(), HDL_E_FAILED, L"session sidecar write failed");
    JsonWriter writer;
    writer.BeginObject();
    writer.Key("session");
    writer.HexStr(id);
    writer.EndObject();
    return CmdStatus(ctx.cmd.c_str(), result.status.hdl_status(), writer.Take());
}

CommandResult CmdDiscoverClose(CmdCtx& ctx) {
    uint64_t id = 0;
    for (int i = 3; i < ctx.argc; ++i)
        if (wcscmp(ctx.argv[i], L"--session") == 0 && i + 1 < ctx.argc)
            id = _wcstoui64(ctx.argv[++i], nullptr, 0);
    id = SessionOrFallback(ctx, id);
    hdl::rpc::v1::DiscoverCloseRequest request;
    request.set_session_id(id);
    const auto result = hdl::rpc::DiscoverClient(&ctx.client).DiscoverClose(request);
    if (result.status.ok() && !hdlcli::ClearPersistedSession(ctx.pid, ctx.store_path))
        return CmdFail(ctx.cmd.c_str(), HDL_E_FAILED, L"session sidecar clear failed");
    return CmdStatus(ctx.cmd.c_str(), result.status.hdl_status(), SessionDataJson(id));
}

CommandResult CmdDiscoverAdd(CmdCtx& ctx) {
    hdl::rpc::v1::DiscoverAddCandidateRequest request;
    request.set_kind(hdl::rpc::v1::CANDIDATE_KIND_ADDRESS);
    for (int i = 3; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--session") == 0 && i + 1 < ctx.argc)
            request.set_session_id(_wcstoui64(ctx.argv[++i], nullptr, 0));
        else if (wcscmp(ctx.argv[i], L"--kind") == 0 && i + 1 < ctx.argc) {
            const auto* kind = ctx.argv[++i];
            request.set_kind(
                _wcsicmp(kind, L"function") == 0 ? hdl::rpc::v1::CANDIDATE_KIND_FUNCTION
                : _wcsicmp(kind, L"object") == 0 ? hdl::rpc::v1::CANDIDATE_KIND_OBJECT
                                                 : hdl::rpc::v1::CANDIDATE_KIND_ADDRESS);
        } else if (wcscmp(ctx.argv[i], L"--addr") == 0 && i + 1 < ctx.argc)
            request.set_address(_wcstoui64(ctx.argv[++i], nullptr, 0));
        else if (wcscmp(ctx.argv[i], L"--tag") == 0 && i + 1 < ctx.argc)
            request.set_tag(Narrow(ctx.argv[++i]));
    }
    request.set_session_id(SessionOrFallback(ctx, request.session_id()));
    const auto result = hdl::rpc::DiscoverClient(&ctx.client).DiscoverAddCandidate(request);
    JsonWriter writer;
    JsonBeginWithSession(writer, request.session_id());
    writer.Key("cand");
    writer.HexStr(result.has_response ? result.response.candidate_id() : 0);
    writer.EndObject();
    return CmdStatus(ctx.cmd.c_str(), result.status.hdl_status(), writer.Take());
}

CommandResult CmdDiscoverConstraint(CmdCtx& ctx) {
    hdl::rpc::v1::DiscoverConstraintScanRequest request;
    request.set_max_results(64);
    std::wstring module;
    for (int i = 3; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--session") == 0 && i + 1 < ctx.argc)
            request.set_session_id(_wcstoui64(ctx.argv[++i], nullptr, 0));
        else if (wcscmp(ctx.argv[i], L"--size") == 0 && i + 1 < ctx.argc)
            request.set_object_size(_wtoi(ctx.argv[++i]));
        else if (wcscmp(ctx.argv[i], L"--pred") == 0 && i + 1 < ctx.argc) {
            HdlFieldPred pred{};
            if (!ClientParsePred(ctx.argv[++i], &pred))
                return FailArg(ctx, L"Bad --pred");
            ToProto(pred, request.add_predicates());
        } else if (wcscmp(ctx.argv[i], L"--module") == 0 && i + 1 < ctx.argc) {
            module = ctx.argv[++i];
            request.mutable_scope()->set_flags(request.scope().flags() | HDL_SEARCH_MODULE);
        } else if (wcscmp(ctx.argv[i], L"--image") == 0)
            request.mutable_scope()->set_flags(request.scope().flags() | HDL_SEARCH_IMAGE);
        else if (wcscmp(ctx.argv[i], L"--max") == 0 && i + 1 < ctx.argc)
            request.set_max_results(_wtoi(ctx.argv[++i]));
        else if (wcscmp(ctx.argv[i], L"--tag") == 0 && i + 1 < ctx.argc)
            request.set_tag(Narrow(ctx.argv[++i]));
    }
    request.set_session_id(SessionOrFallback(ctx, request.session_id()));
    request.mutable_scope()->set_module(WideToUtf8(module));
    const auto result = hdl::rpc::DiscoverClient(&ctx.client).DiscoverConstraintScan(request);
    return CmdStatus(ctx.cmd.c_str(), result.status.hdl_status(),
                     SessionDataJson(request.session_id()));
}

CommandResult CmdDiscoverSynth(CmdCtx& ctx) {
    hdl::rpc::v1::DiscoverSynthesizePatternRequest request;
    request.set_bytes_after(24);
    request.mutable_scope()->set_flags(HDL_SEARCH_IMAGE);
    std::wstring module;
    for (int i = 3; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--session") == 0 && i + 1 < ctx.argc)
            request.set_session_id(_wcstoui64(ctx.argv[++i], nullptr, 0));
        else if (wcscmp(ctx.argv[i], L"--cand") == 0 && i + 1 < ctx.argc)
            request.set_candidate_id(_wcstoui64(ctx.argv[++i], nullptr, 0));
        else if (wcscmp(ctx.argv[i], L"--before") == 0 && i + 1 < ctx.argc)
            request.set_bytes_before(_wtoi(ctx.argv[++i]));
        else if (wcscmp(ctx.argv[i], L"--after") == 0 && i + 1 < ctx.argc)
            request.set_bytes_after(_wtoi(ctx.argv[++i]));
        else if (wcscmp(ctx.argv[i], L"--module") == 0 && i + 1 < ctx.argc) {
            module = ctx.argv[++i];
            request.mutable_scope()->set_flags(request.scope().flags() | HDL_SEARCH_MODULE);
        }
    }
    request.set_session_id(SessionOrFallback(ctx, request.session_id()));
    request.mutable_scope()->set_module(WideToUtf8(module));
    const auto result = hdl::rpc::DiscoverClient(&ctx.client).DiscoverSynthesizePattern(request);
    if (!result.has_response)
        return FailIpc(ctx);
    const auto& pattern = result.response.pattern();
    JsonWriter writer;
    JsonBeginWithSession(writer, request.session_id());
    writer.Key("hits");
    writer.Num(pattern.unique_hits());
    writer.Key("match");
    writer.HexStr(pattern.match_address());
    writer.Key("resolved");
    writer.HexStr(pattern.resolved_address());
    writer.Key("pattern");
    writer.Str(pattern.pattern());
    writer.EndObject();
    return CmdStatus(ctx.cmd.c_str(), result.status.hdl_status(), writer.Take());
}

CommandResult CmdDiscoverPathscan(CmdCtx& ctx) {
    if (ctx.argc < 4)
        return FailUsage(ctx);
    hdl::rpc::v1::DiscoverPathConsensusRequest request;
    request.set_target(_wcstoui64(ctx.argv[3], nullptr, 0));
    request.set_max_depth(2);
    request.set_max_offset(0x1000);
    request.set_max_results(64);
    request.mutable_scope()->set_flags(HDL_SEARCH_IMAGE);
    std::wstring module;
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
            ++i;
    }
    request.mutable_scope()->set_module(WideToUtf8(module));
    const auto result = hdl::rpc::DiscoverClient(&ctx.client).DiscoverPathConsensus(request);
    if (!result.has_response)
        return FailIpc(ctx);
    std::vector<HdlPointerPath> paths;
    for (const auto& value : result.response.paths())
        paths.push_back(ToDomainPath(value));
    if (!paths.empty()) {
        hdlcli::RememberPath(ctx.controller, paths[0], module.empty() ? nullptr : module.c_str());
        CommandResult error;
        if (!ApplyStoreAddPath(ctx, paths[0], module.empty() ? nullptr : module.c_str(), &error))
            return error;
    }
    JsonWriter writer;
    writer.BeginObject();
    writer.Key("paths");
    writer.BeginArray();
    for (const auto& path : paths) {
        writer.BeginObject();
        writer.Key("base");
        writer.HexStr(path.static_base);
        writer.Key("depth");
        writer.Num(path.depth);
        writer.EndObject();
    }
    writer.EndArray();
    if (!paths.empty() && TakeStoreAddName(ctx)) {
        writer.Key("store_add");
        writer.Str(TakeStoreAddName(ctx));
        writer.Key("store");
        writer.Str(ctx.store_path ? ctx.store_path : L"");
    }
    writer.EndObject();
    return CmdStatus(ctx.cmd.c_str(), result.status.hdl_status(), writer.Take());
}

CommandResult CmdDiscoverPathValidate(CmdCtx& ctx) {
    if (ctx.argc < 4)
        return FailUsage(ctx);
    hdl::rpc::v1::DiscoverPathValidateRequest request;
    request.set_expected(_wcstoui64(ctx.argv[3], nullptr, 0));
    uint64_t base = 0;
    uint32_t depth = 0;
    std::vector<int32_t> offsets;
    for (int i = 4; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--base") == 0 && i + 1 < ctx.argc)
            base = _wcstoui64(ctx.argv[++i], nullptr, 0);
        else if (wcscmp(ctx.argv[i], L"--depth") == 0 && i + 1 < ctx.argc)
            depth = _wtoi(ctx.argv[++i]);
        else if (wcscmp(ctx.argv[i], L"--offs") == 0 && i + 1 < ctx.argc) {
            wchar_t* cursor = ctx.argv[++i];
            while (cursor && *cursor && offsets.size() < 8) {
                offsets.push_back(static_cast<int32_t>(wcstol(cursor, &cursor, 0)));
                if (*cursor == L',')
                    ++cursor;
            }
        }
    }
    if (!base || !depth || depth > 8 || offsets.size() < depth)
        return FailArg(ctx, L"Need --base HEX --depth N --offs A,B,...");
    auto* path = request.add_paths();
    path->set_static_base(base);
    for (uint32_t i = 0; i < depth; ++i)
        path->add_offsets(offsets[i]);
    const auto result = hdl::rpc::DiscoverClient(&ctx.client).DiscoverPathValidate(request);
    if (!result.has_response)
        return FailIpc(ctx);
    std::vector<HdlPointerPath> paths;
    for (const auto& value : result.response.paths())
        paths.push_back(ToDomainPath(value));
    if (!paths.empty())
        hdlcli::RememberPath(ctx.controller, paths[0], nullptr);
    JsonWriter writer;
    writer.BeginObject();
    writer.Key("kept");
    writer.Num(paths.size());
    writer.Key("paths");
    writer.BeginArray();
    for (const auto& value : paths) {
        writer.BeginObject();
        writer.Key("base");
        writer.HexStr(value.static_base);
        writer.Key("depth");
        writer.Num(value.depth);
        writer.EndObject();
    }
    writer.EndArray();
    writer.EndObject();
    return CmdStatus(ctx.cmd.c_str(), result.status.hdl_status(), writer.Take());
}

CommandResult CmdDiscoverScan(CmdCtx& ctx) {
    hdl::rpc::v1::DiscoverScanValueRequest request;
    int32_t value_type = HDL_VALUE_I32;
    std::wstring value, module;
    request.set_tag("scan");
    request.set_comparison(hdl::rpc::v1::SEARCH_COMPARISON_EXACT);
    request.set_alignment(hdl::rpc::v1::SEARCH_ALIGNMENT_NATURAL);
    request.set_max_results(64);
    for (int i = 3; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--session") == 0 && i + 1 < ctx.argc)
            request.set_session_id(_wcstoui64(ctx.argv[++i], nullptr, 0));
        else if (wcscmp(ctx.argv[i], L"--type") == 0 && i + 1 < ctx.argc) {
            if (!ParseValueTypeLocal(ctx.argv[++i], &value_type))
                return FailArg(ctx, L"Bad --type");
        } else if (wcscmp(ctx.argv[i], L"--value") == 0 && i + 1 < ctx.argc)
            value = ctx.argv[++i];
        else if (wcscmp(ctx.argv[i], L"--tag") == 0 && i + 1 < ctx.argc)
            request.set_tag(Narrow(ctx.argv[++i]));
        else if (wcscmp(ctx.argv[i], L"--module") == 0 && i + 1 < ctx.argc) {
            module = ctx.argv[++i];
            request.mutable_scope()->set_flags(request.scope().flags() | HDL_SEARCH_MODULE);
        } else if (wcscmp(ctx.argv[i], L"--image") == 0)
            request.mutable_scope()->set_flags(request.scope().flags() | HDL_SEARCH_IMAGE);
        else if (wcscmp(ctx.argv[i], L"--max") == 0 && i + 1 < ctx.argc)
            request.set_max_results(_wtoi(ctx.argv[++i]));
    }
    request.set_session_id(SessionOrFallback(ctx, request.session_id()));
    request.mutable_scope()->set_module(WideToUtf8(module));
    if (!request.session_id() || value.empty())
        return FailArg(ctx, L"Need --session ID --type T --value V");
    if (!SetSearchValueLocal(value_type, value, request.mutable_value()))
        return FailArg(ctx, L"Bad --value");
    const auto result = hdl::rpc::DiscoverClient(&ctx.client).DiscoverScanValue(request);
    JsonWriter writer;
    JsonBeginWithSession(writer, request.session_id());
    writer.Key("added");
    writer.Num(result.has_response ? result.response.added_count() : 0);
    writer.EndObject();
    return CmdStatus(ctx.cmd.c_str(), result.status.hdl_status(), writer.Take());
}

CommandResult CmdDiscoverMisc(CmdCtx& ctx) {
    uint64_t id = 0, address = 0, candidate_id = 0;
    uint32_t size = 64, argument_count = 0, flags = 0, rank_flags = 0;
    std::wstring module, out_path, in_path;
    std::string name, dll, import_name;
    std::vector<uint64_t> diff_addresses;
    for (int i = 3; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--session") == 0 && i + 1 < ctx.argc)
            id = _wcstoui64(ctx.argv[++i], nullptr, 0);
        else if (wcscmp(ctx.argv[i], L"--addr") == 0 && i + 1 < ctx.argc) {
            const auto value = _wcstoui64(ctx.argv[++i], nullptr, 0);
            if (ctx.cmd == L"discover-diff")
                diff_addresses.push_back(value);
            else
                address = value;
        } else if (wcscmp(ctx.argv[i], L"--seed") == 0 && i + 1 < ctx.argc)
            address = _wcstoui64(ctx.argv[++i], nullptr, 0);
        else if (wcscmp(ctx.argv[i], L"--size") == 0 && i + 1 < ctx.argc)
            size = _wtoi(ctx.argv[++i]);
        else if (wcscmp(ctx.argv[i], L"--args") == 0 && i + 1 < ctx.argc)
            argument_count = _wtoi(ctx.argv[++i]);
        else if (wcscmp(ctx.argv[i], L"--name") == 0 && i + 1 < ctx.argc)
            name = Narrow(ctx.argv[++i]);
        else if (wcscmp(ctx.argv[i], L"--module") == 0 && i + 1 < ctx.argc) {
            module = ctx.argv[++i];
            flags |= HDL_SEARCH_MODULE | HDL_SEARCH_IMAGE;
        } else if (wcscmp(ctx.argv[i], L"--dll") == 0 && i + 1 < ctx.argc)
            dll = Narrow(ctx.argv[++i]);
        else if (wcscmp(ctx.argv[i], L"--import") == 0 && i + 1 < ctx.argc)
            import_name = Narrow(ctx.argv[++i]);
        else if (wcscmp(ctx.argv[i], L"--out") == 0 && i + 1 < ctx.argc)
            out_path = ctx.argv[++i];
        else if (wcscmp(ctx.argv[i], L"--in") == 0 && i + 1 < ctx.argc)
            in_path = ctx.argv[++i];
        else if (wcscmp(ctx.argv[i], L"--id") == 0 && i + 1 < ctx.argc)
            candidate_id = _wcstoui64(ctx.argv[++i], nullptr, 0);
        else if (wcscmp(ctx.argv[i], L"--flags") == 0 && i + 1 < ctx.argc)
            rank_flags = wcstoul(ctx.argv[++i], nullptr, 0);
    }
    id = SessionOrFallback(ctx, id);
    hdl::rpc::DiscoverClient client(&ctx.client);
    if (ctx.cmd == L"discover-heat") {
        hdl::rpc::v1::DiscoverGetHeatRequest request;
        request.set_session_id(id);
        request.set_base(address);
        request.set_max_fields(size ? size : 64);
        const auto result = client.DiscoverGetHeat(request);
        if (!result.has_response)
            return FailIpc(ctx);
        JsonWriter writer;
        JsonBeginWithSession(writer, id);
        JsonWriteHeatFields(writer, result.response.fields());
        writer.EndObject();
        return CmdStatus(ctx.cmd.c_str(), result.status.hdl_status(), writer.Take());
    }
    if (ctx.cmd == L"discover-diff") {
        if (!id || diff_addresses.size() < 2)
            return FailArg(ctx, L"Need --session ID --addr A --addr B ... [--size N]");
        hdl::rpc::v1::DiscoverDiffObjectsRequest request;
        request.set_session_id(id);
        for (auto value : diff_addresses)
            request.add_addresses(value);
        request.set_max_size(size ? size : 64);
        request.set_max_fields(64);
        const auto result = client.DiscoverDiffObjects(request);
        if (!result.has_response)
            return FailIpc(ctx);
        JsonWriter writer;
        JsonBeginWithSession(writer, id);
        JsonWriteHeatFields(writer, result.response.fields());
        writer.EndObject();
        return CmdStatus(ctx.cmd.c_str(), result.status.hdl_status(), writer.Take());
    }
    if (ctx.cmd == L"discover-rank") {
        hdl::rpc::v1::DiscoverRankFunctionsRequest request;
        request.set_session_id(id);
        request.set_action_name(name);
        request.set_flags(rank_flags);
        request.set_max_results(64);
        const auto result = client.DiscoverRankFunctions(request);
        if (!result.has_response)
            return FailIpc(ctx);
        std::vector<hdl::rpc::v1::Candidate> values(result.response.candidates().begin(),
                                                    result.response.candidates().end());
        JsonWriter writer;
        JsonBeginWithSession(writer, id);
        writer.Key("count");
        writer.Num(values.size());
        JsonWriteCandidates(writer, values);
        writer.EndObject();
        return CmdStatus(ctx.cmd.c_str(), result.status.hdl_status(), writer.Take());
    }
    if (ctx.cmd == L"discover-cands") {
        hdl::rpc::v1::DiscoverGetCandidatesRequest request;
        request.set_session_id(id);
        request.set_max_results(256);
        std::vector<hdl::rpc::v1::Candidate> values;
        const auto status = client.DiscoverGetCandidates(request, [&values](const auto& batch) {
            values.insert(values.end(), batch.candidates().begin(), batch.candidates().end());
            return true;
        });
        JsonWriter writer;
        JsonBeginWithSession(writer, id);
        writer.Key("count");
        writer.Num(values.size());
        JsonWriteCandidates(writer, values);
        writer.EndObject();
        return CmdStatus(ctx.cmd.c_str(), status.hdl_status(), writer.Take());
    }
    if (ctx.cmd == L"discover-export") {
        if (!id || out_path.empty())
            return FailArg(ctx, L"Need --session ID --out PATH");
        hdl::rpc::v1::DiscoverExportRequest request;
        request.set_session_id(id);
        const auto result = client.DiscoverExport(request);
        const std::string json = result.has_response ? result.response.json() : std::string{};
        if (result.status.ok()) {
            std::ofstream output;
            if (!OpenOutWide(out_path.c_str(), &output)) {
                JsonWriter writer;
                JsonBeginWithSession(writer, id);
                writer.Key("bytes");
                writer.Num(json.size());
                writer.Key("out");
                writer.Str(out_path);
                writer.EndObject();
                return CmdStatus(ctx.cmd.c_str(), HDL_E_FAILED, writer.Take());
            }
            output.write(json.data(), static_cast<std::streamsize>(json.size()));
        }
        JsonWriter writer;
        JsonBeginWithSession(writer, id);
        writer.Key("bytes");
        writer.Num(json.size());
        writer.Key("out");
        writer.Str(out_path);
        writer.EndObject();
        return CmdStatus(ctx.cmd.c_str(), result.status.hdl_status(), writer.Take());
    }
    if (ctx.cmd == L"discover-evidence") {
        if (!id || !candidate_id)
            return FailArg(ctx, L"Need --session ID --id CAND_ID");
        hdl::rpc::v1::DiscoverGetEvidenceRequest request;
        request.set_session_id(id);
        request.set_candidate_id(candidate_id);
        const auto result = client.DiscoverGetEvidence(request);
        JsonWriter writer;
        JsonBeginWithSession(writer, id);
        writer.Key("evidence");
        writer.Str(result.has_response ? result.response.evidence() : std::string{});
        writer.EndObject();
        return CmdStatus(ctx.cmd.c_str(), result.status.hdl_status(), writer.Take());
    }
    hdl::rpc::Result<hdl::rpc::v1::Empty> result;
    if (ctx.cmd == L"discover-watch") {
        hdl::rpc::v1::DiscoverWatchRequest request;
        request.set_session_id(id);
        request.set_function(address);
        request.set_argument_count(argument_count);
        result = client.DiscoverWatch(request);
    } else if (ctx.cmd == L"discover-unwatch") {
        hdl::rpc::v1::DiscoverUnwatchAllRequest request;
        request.set_session_id(id);
        result = client.DiscoverUnwatchAll(request);
    } else if (ctx.cmd == L"discover-action-begin") {
        hdl::rpc::v1::DiscoverActionBeginRequest request;
        request.set_session_id(id);
        request.set_name(name);
        result = client.DiscoverActionBegin(request);
    } else if (ctx.cmd == L"discover-action-end") {
        hdl::rpc::v1::DiscoverActionEndRequest request;
        request.set_session_id(id);
        result = client.DiscoverActionEnd(request);
    } else if (ctx.cmd == L"discover-watch-region") {
        hdl::rpc::v1::DiscoverWatchRegionRequest request;
        request.set_session_id(id);
        request.set_base(address);
        request.set_size(size);
        result = client.DiscoverWatchRegion(request);
    } else if (ctx.cmd == L"discover-cluster") {
        hdl::rpc::v1::DiscoverClusterTypeRequest request;
        request.set_session_id(id);
        request.set_seed(address);
        request.set_object_size(size);
        request.set_max_results(64);
        request.mutable_scope()->set_flags(flags);
        request.mutable_scope()->set_module(WideToUtf8(module));
        result = client.DiscoverClusterType(request);
    } else if (ctx.cmd == L"discover-watch-import") {
        if (!id || dll.empty() || import_name.empty())
            return FailArg(ctx,
                           L"Need --session ID --dll NAME --import NAME [--args N] [--module MOD]");
        hdl::rpc::v1::DiscoverWatchImportRequest request;
        request.set_session_id(id);
        request.set_module(WideToUtf8(module));
        request.set_dll(dll);
        request.set_import_name(import_name);
        request.set_argument_count(argument_count);
        result = client.DiscoverWatchImport(request);
    } else if (ctx.cmd == L"discover-reset-heat") {
        if (!id || !address)
            return FailArg(ctx, L"Need --session ID --addr HEX");
        hdl::rpc::v1::DiscoverResetHeatRequest request;
        request.set_session_id(id);
        request.set_base(address);
        result = client.DiscoverResetHeat(request);
    } else if (ctx.cmd == L"discover-import") {
        if (!id || in_path.empty())
            return FailArg(ctx, L"Need --session ID --in PATH");
        std::ifstream input;
        if (!OpenInWide(in_path.c_str(), &input))
            return FailArg(ctx, L"Cannot read --in file");
        hdl::rpc::v1::DiscoverImportRequest request;
        request.set_session_id(id);
        request.set_json(
            std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()));
        result = client.DiscoverImport(request);
    } else if (ctx.cmd == L"discover-apply-watch") {
        if (!id || !address)
            return FailArg(ctx, L"Need --session ID --addr HEX [--size N]");
        hdl::rpc::v1::DiscoverApplyWatchHitsRequest request;
        request.set_session_id(id);
        request.set_object_base(address);
        request.set_size(size ? size : 64);
        result = client.DiscoverApplyWatchHits(request);
    } else
        return FailArg(ctx, L"Unknown discover command");
    return CmdStatus(ctx.cmd.c_str(), result.status.hdl_status(), SessionDataJson(id));
}
