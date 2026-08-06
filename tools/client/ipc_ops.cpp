#include "ipc_ops.hpp"

#include "rpc_helpers.hpp"
#include "util.hpp"

#include "hdl/rpc/v1/services.rpc.hpp"

#include <algorithm>
#include <cstring>

namespace hdlcli {
namespace {

IpcStatus AsIpc(const hdl::rpc::Status& status) {
    return {status.hdl_status()};
}

template <size_t N> void CopyText(char (&output)[N], const std::string& value) {
    const size_t size = (std::min)(value.size(), N - 1);
    std::memcpy(output, value.data(), size);
    output[size] = 0;
}

void ToDomain(const hdl::rpc::v1::Candidate& input, HdlCandidate* output) {
    *output = {};
    output->id = input.id();
    output->kind = input.kind();
    output->confidence = input.confidence();
    output->address = input.address();
    output->module_base = input.module_base();
    output->rva = input.rva();
    output->field_offset = input.field_offset();
    output->flags = input.flags();
    CopyText(output->tag, input.tag());
}

void ToDomain(const hdl::rpc::v1::SynthesizedPattern& input, HdlSynthesizedPattern* output) {
    *output = {};
    CopyText(output->pattern, input.pattern());
    output->pattern_offset = input.pattern_offset();
    output->rip_disp_offset = input.rip_displacement_offset();
    output->rip_instr_len = input.rip_instruction_length();
    output->match_addr = input.match_address();
    output->resolved_addr = input.resolved_address();
    output->unique_hits = input.unique_hits();
}

void ToDomain(const hdl::rpc::v1::PointerPath& input, HdlPointerPath* output) {
    *output = {};
    output->static_base = input.static_base();
    output->depth = static_cast<uint32_t>((std::min)(input.offsets_size(), 8));
    for (uint32_t i = 0; i < output->depth; ++i)
        output->offsets[i] = input.offsets(i);
}

void ToProto(const HdlPointerPath& input, hdl::rpc::v1::PointerPath* output) {
    output->set_static_base(input.static_base);
    for (uint32_t i = 0; i < input.depth && i < 8; ++i)
        output->add_offsets(input.offsets[i]);
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

bool ToProto(const HdlCallArg& input, hdl::rpc::v1::CallArgument* output) {
    switch (input.kind) {
    case HDL_CALL_ARG_U64:
        output->set_unsigned_value(input.u64);
        return true;
    case HDL_CALL_ARG_I64:
        output->set_signed_value(static_cast<int64_t>(input.u64));
        return true;
    case HDL_CALL_ARG_PTR:
        output->set_pointer_value(reinterpret_cast<uint64_t>(input.ptr));
        return true;
    case HDL_CALL_ARG_BUF:
        if (input.size && !input.ptr)
            return false;
        output->set_buffer(input.ptr, input.size);
        return true;
    case HDL_CALL_ARG_CSTR:
        if (!input.ptr)
            return false;
        output->set_narrow_string(static_cast<const char*>(input.ptr));
        return true;
    case HDL_CALL_ARG_WSTR:
        if (!input.ptr)
            return false;
        output->set_wide_string(WideToUtf8(static_cast<const wchar_t*>(input.ptr)));
        return true;
    case HDL_CALL_ARG_F32: {
        float value = 0;
        const uint32_t bits = static_cast<uint32_t>(input.u64);
        std::memcpy(&value, &bits, sizeof(value));
        output->set_float_value(value);
        return true;
    }
    case HDL_CALL_ARG_F64: {
        double value = 0;
        std::memcpy(&value, &input.u64, sizeof(value));
        output->set_double_value(value);
        return true;
    }
    default:
        return false;
    }
}

void CopyCallResult(const hdl::rpc::v1::CallResult& input, const std::vector<HdlCallArg>& args,
                    HdlCallResult* output) {
    *output = {};
    output->return_value = input.return_value();
    output->last_error = input.last_error();
    for (const auto& copy : input.buffer_copy_outs()) {
        if (copy.argument_index() >= args.size())
            continue;
        const auto& arg = args[copy.argument_index()];
        if (arg.kind == HDL_CALL_ARG_BUF && arg.ptr)
            std::memcpy(const_cast<void*>(arg.ptr), copy.data().data(),
                        (std::min)(static_cast<size_t>(arg.size), copy.data().size()));
    }
}

} // namespace

IpcStatus Ping(PipeClient& client, uint32_t* out_pid) {
    const auto result = hdl::rpc::ControlClient(&client).Ping(hdl::rpc::v1::Empty{});
    if (out_pid)
        *out_pid = result.has_response ? result.response.pid() : 0;
    return AsIpc(result.status);
}

IpcStatus ModBase(PipeClient& client, const wchar_t* module, uint64_t* out_base) {
    hdl::rpc::v1::ModuleBaseRequest request;
    request.set_module(WideToUtf8(module ? module : L""));
    const auto result = hdl::rpc::LocateClient(&client).ModuleBase(request);
    if (out_base)
        *out_base = result.has_response ? result.response.base() : 0;
    return AsIpc(result.status);
}

IpcStatus ResolvePattern(PipeClient& client, const char* pattern, uint32_t hit_index,
                         int32_t pattern_offset, uint32_t rip_disp, uint32_t rip_len,
                         const std::vector<int64_t>& follows, uint32_t search_flags,
                         const wchar_t* module, HdlPatternResult* output) {
    hdl::rpc::v1::ResolvePatternRequest request;
    request.set_pattern(pattern ? pattern : "");
    request.set_hit_index(hit_index);
    request.set_pattern_offset(pattern_offset);
    request.set_rip_displacement_offset(rip_disp);
    request.set_rip_instruction_length(rip_len);
    for (auto value : follows)
        request.add_follow_offsets(value);
    request.mutable_scope()->set_flags(search_flags);
    request.mutable_scope()->set_module(WideToUtf8(module ? module : L""));
    request.set_max_scan_hits(64);
    const auto result = hdl::rpc::LocateClient(&client).ResolvePattern(request);
    if (output) {
        *output = {};
        if (result.has_response) {
            const auto& value = result.response.result();
            output->match_addr = value.match_address();
            output->resolved_addr = value.resolved_address();
            output->module_base = value.module_base();
            output->rva = value.rva();
        }
    }
    return AsIpc(result.status);
}

IpcStatus FollowPointers(PipeClient& client, uint64_t base, const std::vector<int64_t>& offsets,
                         uint64_t* out_address) {
    hdl::rpc::v1::FollowPointersRequest request;
    request.set_base(base);
    for (auto value : offsets)
        request.add_offsets(value);
    const auto result = hdl::rpc::LocateClient(&client).FollowPointers(request);
    if (out_address)
        *out_address = result.has_response ? result.response.address() : 0;
    return AsIpc(result.status);
}

IpcStatus DiscoverCreate(PipeClient& client, uint64_t* out_id) {
    const auto result = hdl::rpc::DiscoverClient(&client).DiscoverCreate(hdl::rpc::v1::Empty{});
    if (out_id)
        *out_id = result.has_response ? result.response.session_id() : 0;
    return AsIpc(result.status);
}
IpcStatus DiscoverClose(PipeClient& client, uint64_t id) {
    hdl::rpc::v1::DiscoverCloseRequest request;
    request.set_session_id(id);
    return AsIpc(hdl::rpc::DiscoverClient(&client).DiscoverClose(request).status);
}
IpcStatus DiscoverWatch(PipeClient& client, uint64_t session, uint64_t function, uint32_t args) {
    hdl::rpc::v1::DiscoverWatchRequest request;
    request.set_session_id(session);
    request.set_function(function);
    request.set_argument_count(args);
    return AsIpc(hdl::rpc::DiscoverClient(&client).DiscoverWatch(request).status);
}
IpcStatus DiscoverUnwatchAll(PipeClient& client, uint64_t session) {
    hdl::rpc::v1::DiscoverUnwatchAllRequest request;
    request.set_session_id(session);
    return AsIpc(hdl::rpc::DiscoverClient(&client).DiscoverUnwatchAll(request).status);
}
IpcStatus DiscoverActionBegin(PipeClient& client, uint64_t session, const char* name) {
    hdl::rpc::v1::DiscoverActionBeginRequest request;
    request.set_session_id(session);
    request.set_name(name ? name : "");
    return AsIpc(hdl::rpc::DiscoverClient(&client).DiscoverActionBegin(request).status);
}
IpcStatus DiscoverActionEnd(PipeClient& client, uint64_t session) {
    hdl::rpc::v1::DiscoverActionEndRequest request;
    request.set_session_id(session);
    return AsIpc(hdl::rpc::DiscoverClient(&client).DiscoverActionEnd(request).status);
}
IpcStatus DiscoverWatchRegion(PipeClient& client, uint64_t session, uint64_t base, uint32_t size) {
    hdl::rpc::v1::DiscoverWatchRegionRequest request;
    request.set_session_id(session);
    request.set_base(base);
    request.set_size(size);
    return AsIpc(hdl::rpc::DiscoverClient(&client).DiscoverWatchRegion(request).status);
}

IpcStatus DiscoverRank(PipeClient& client, uint64_t session, const char* name,
                       std::vector<HdlCandidate>* output, uint32_t flags) {
    hdl::rpc::v1::DiscoverRankFunctionsRequest request;
    request.set_session_id(session);
    request.set_action_name(name ? name : "");
    request.set_flags(flags);
    request.set_max_results(64);
    const auto result = hdl::rpc::DiscoverClient(&client).DiscoverRankFunctions(request);
    if (output) {
        output->clear();
        if (result.has_response)
            for (const auto& value : result.response.candidates()) {
                output->emplace_back();
                ToDomain(value, &output->back());
            }
    }
    return AsIpc(result.status);
}

IpcStatus DiscoverSynth(PipeClient& client, uint64_t session, uint64_t candidate_id,
                        uint32_t before, uint32_t after, uint32_t search_flags,
                        const wchar_t* module, HdlSynthesizedPattern* output) {
    hdl::rpc::v1::DiscoverSynthesizePatternRequest request;
    request.set_session_id(session);
    request.set_candidate_id(candidate_id);
    request.set_bytes_before(before);
    request.set_bytes_after(after);
    request.mutable_scope()->set_flags(search_flags);
    request.mutable_scope()->set_module(WideToUtf8(module ? module : L""));
    const auto result = hdl::rpc::DiscoverClient(&client).DiscoverSynthesizePattern(request);
    if (output) {
        *output = {};
        if (result.has_response)
            ToDomain(result.response.pattern(), output);
    }
    return AsIpc(result.status);
}

IpcStatus DiscoverConstraint(PipeClient& client, uint64_t session, uint32_t object_size,
                             const std::vector<HdlFieldPred>& predicates, uint32_t search_flags,
                             const wchar_t* module, uint32_t max_results, const char* tag) {
    hdl::rpc::v1::DiscoverConstraintScanRequest request;
    request.set_session_id(session);
    request.set_object_size(object_size);
    for (const auto& value : predicates)
        ToProto(value, request.add_predicates());
    request.mutable_scope()->set_flags(search_flags);
    request.mutable_scope()->set_module(WideToUtf8(module ? module : L""));
    request.set_max_results(max_results);
    request.set_tag(tag ? tag : "");
    return AsIpc(hdl::rpc::DiscoverClient(&client).DiscoverConstraintScan(request).status);
}

IpcStatus DiscoverGetCandidates(PipeClient& client, uint64_t session,
                                std::vector<HdlCandidate>* output) {
    hdl::rpc::v1::DiscoverGetCandidatesRequest request;
    request.set_session_id(session);
    request.set_max_results(256);
    if (output)
        output->clear();
    const auto status = hdl::rpc::DiscoverClient(&client).DiscoverGetCandidates(
        request, [output](const auto& batch) {
            if (output)
                for (const auto& value : batch.candidates()) {
                    output->emplace_back();
                    ToDomain(value, &output->back());
                }
            return true;
        });
    return AsIpc(status);
}

IpcStatus DiscoverCluster(PipeClient& client, uint64_t session, uint64_t seed, uint32_t object_size,
                          uint32_t search_flags, const wchar_t* module, uint32_t max_results) {
    hdl::rpc::v1::DiscoverClusterTypeRequest request;
    request.set_session_id(session);
    request.set_seed(seed);
    request.set_object_size(object_size);
    request.mutable_scope()->set_flags(search_flags);
    request.mutable_scope()->set_module(WideToUtf8(module ? module : L""));
    request.set_max_results(max_results);
    return AsIpc(hdl::rpc::DiscoverClient(&client).DiscoverClusterType(request).status);
}

IpcStatus DiscoverAddCandidate(PipeClient& client, uint64_t session, uint32_t kind,
                               uint64_t address, const char* tag, uint64_t* out_id) {
    hdl::rpc::v1::DiscoverAddCandidateRequest request;
    request.set_session_id(session);
    request.set_kind(static_cast<hdl::rpc::v1::CandidateKind>(kind));
    request.set_address(address);
    request.set_tag(tag ? tag : "");
    const auto result = hdl::rpc::DiscoverClient(&client).DiscoverAddCandidate(request);
    if (out_id)
        *out_id = result.has_response ? result.response.candidate_id() : 0;
    return AsIpc(result.status);
}

IpcStatus PathConsensus(PipeClient& client, uint64_t target, uint32_t max_depth,
                        uint32_t max_offset, uint32_t max_results, uint32_t search_flags,
                        const wchar_t* module, std::vector<HdlPointerPath>* output) {
    hdl::rpc::v1::DiscoverPathConsensusRequest request;
    request.set_target(target);
    request.set_max_depth(max_depth);
    request.set_max_offset(max_offset);
    request.set_max_results(max_results);
    request.mutable_scope()->set_flags(search_flags);
    request.mutable_scope()->set_module(WideToUtf8(module ? module : L""));
    const auto result = hdl::rpc::DiscoverClient(&client).DiscoverPathConsensus(request);
    if (output) {
        output->clear();
        if (result.has_response)
            for (const auto& value : result.response.paths()) {
                output->emplace_back();
                ToDomain(value, &output->back());
            }
    }
    return AsIpc(result.status);
}

IpcStatus PathValidate(PipeClient& client, uint64_t expected, std::vector<HdlPointerPath>* paths) {
    hdl::rpc::v1::DiscoverPathValidateRequest request;
    request.set_expected(expected);
    if (paths)
        for (const auto& value : *paths)
            ToProto(value, request.add_paths());
    const auto result = hdl::rpc::DiscoverClient(&client).DiscoverPathValidate(request);
    if (paths) {
        paths->clear();
        if (result.has_response)
            for (const auto& value : result.response.paths()) {
                paths->emplace_back();
                ToDomain(value, &paths->back());
            }
    }
    return AsIpc(result.status);
}

IpcStatus CallExport(PipeClient& client, const wchar_t* module, const char* name,
                     const std::vector<HdlCallArg>& args, uint32_t timeout_ms,
                     HdlCallResult* output) {
    hdl::rpc::v1::CallExportRequest request;
    request.set_module(WideToUtf8(module ? module : L""));
    request.set_name(name ? name : "");
    for (const auto& value : args)
        if (!ToProto(value, request.add_arguments()))
            return {HDL_E_INVALID_ARG};
    const auto result = hdl::rpc::CallClient(&client).CallExport(request, {timeout_ms});
    if (output) {
        *output = {};
        if (result.has_response)
            CopyCallResult(result.response.result(), args, output);
    }
    return AsIpc(result.status);
}

IpcStatus FindCaves(PipeClient& client, const HdlCaveQuery& query,
                    std::vector<HdlCaveInfo>* output) {
    hdl::rpc::v1::FindCavesRequest request;
    request.set_min_size(query.min_size);
    request.set_fill_byte(query.fill_byte);
    request.mutable_scope()->set_flags(query.search_flags);
    request.mutable_scope()->set_module(
        WideToUtf8(query.module_or_null ? query.module_or_null : L""));
    request.set_max_results(query.max_results);
    request.set_near_address(query.near_addr);
    request.set_max_distance(query.max_distance);
    if (output)
        output->clear();
    const auto status =
        hdl::rpc::MemoryClient(&client).FindCaves(request, [output](const auto& batch) {
            if (output)
                for (const auto& value : batch.caves())
                    output->push_back({value.address(), value.size(), value.region_base(), 0});
            return true;
        });
    return AsIpc(status);
}

IpcStatus AllocNear(PipeClient& client, uint64_t near_address, uint64_t max_distance, uint64_t size,
                    uint32_t protection, uint64_t* out_address) {
    hdl::rpc::v1::AllocNearRequest request;
    request.set_near_address(near_address);
    request.set_max_distance(max_distance);
    request.set_size(size);
    request.set_protection(protection);
    const auto result = hdl::rpc::MemoryClient(&client).AllocNear(request);
    if (out_address)
        *out_address = result.has_response ? result.response.address() : 0;
    return AsIpc(result.status);
}

IpcStatus BuildStub(PipeClient& client, const HdlStubDesc& desc, HdlStubResult* output) {
    hdl::rpc::v1::BuildStubRequest request;
    request.set_kind(static_cast<hdl::rpc::v1::StubKind>(desc.kind));
    request.set_flags(desc.flags);
    request.set_target(desc.target);
    request.set_steal_from(desc.steal_from);
    request.set_steal_min_bytes(desc.steal_min_bytes);
    if (desc.raw_size)
        request.set_raw(desc.raw, desc.raw_size);
    request.set_allocate_rx(desc.alloc_rx != 0);
    const auto result = hdl::rpc::CodeClient(&client).BuildStub(request);
    if (output) {
        *output = {};
        if (result.has_response) {
            const auto& value = result.response.result();
            output->stub_va = value.stub_address();
            output->stolen_bytes = value.stolen_bytes();
            output->code_size =
                static_cast<uint32_t>((std::min)(value.code().size(), sizeof(output->code)));
            std::memcpy(output->code, value.code().data(), output->code_size);
        }
    }
    return AsIpc(result.status);
}

IpcStatus PatchCreate(PipeClient& client, uint64_t address, const uint8_t* bytes, uint32_t size,
                      const char* name, uint64_t* out_handle) {
    hdl::rpc::v1::PatchCreateRequest request;
    request.set_address(address);
    if (size)
        request.set_data(bytes, size);
    request.set_name(name ? name : "");
    const auto result = hdl::rpc::CodeClient(&client).PatchCreate(request);
    if (out_handle)
        *out_handle = result.has_response ? result.response.handle() : 0;
    return AsIpc(result.status);
}
IpcStatus PatchEnable(PipeClient& client, uint64_t handle, int enable) {
    hdl::rpc::v1::PatchEnableRequest request;
    request.set_handle(handle);
    request.set_enabled(enable != 0);
    return AsIpc(hdl::rpc::CodeClient(&client).PatchEnable(request).status);
}
IpcStatus PatchRemove(PipeClient& client, uint64_t handle) {
    hdl::rpc::v1::PatchRemoveRequest request;
    request.set_handle(handle);
    return AsIpc(hdl::rpc::CodeClient(&client).PatchRemove(request).status);
}

IpcStatus PatchEnum(PipeClient& client, std::vector<HdlPatchInfo>* output) {
    if (output)
        output->clear();
    const auto status =
        hdl::rpc::CodeClient(&client).PatchEnum(hdl::rpc::v1::Empty{}, [output](const auto& batch) {
            if (output)
                for (const auto& value : batch.patches()) {
                    HdlPatchInfo info{};
                    info.handle = value.handle();
                    info.addr = value.address();
                    info.size = value.size();
                    info.enabled = value.enabled();
                    CopyText(info.name, value.name());
                    output->push_back(info);
                }
            return true;
        });
    return AsIpc(status);
}

IpcStatus WatchHw(PipeClient& client, uint64_t address, uint32_t size, uint32_t access,
                  uint32_t thread_id, uint64_t* out_handle) {
    hdl::rpc::v1::WatchHwRequest request;
    request.set_address(address);
    request.set_size(size);
    request.set_access(static_cast<hdl::rpc::v1::WatchHardwareAccess>(access));
    request.set_thread_id(thread_id);
    const auto result = hdl::rpc::WatchClient(&client).WatchHw(request);
    if (out_handle)
        *out_handle = result.has_response ? result.response.handle() : 0;
    return AsIpc(result.status);
}
IpcStatus WatchPage(PipeClient& client, uint64_t address, uint64_t size, uint32_t mode,
                    uint64_t* out_handle) {
    hdl::rpc::v1::WatchPageRequest request;
    request.set_address(address);
    request.set_size(size);
    request.set_mode(static_cast<hdl::rpc::v1::WatchPageMode>(mode));
    const auto result = hdl::rpc::WatchClient(&client).WatchPage(request);
    if (out_handle)
        *out_handle = result.has_response ? result.response.handle() : 0;
    return AsIpc(result.status);
}
IpcStatus Unwatch(PipeClient& client, uint64_t handle) {
    hdl::rpc::v1::UnwatchRequest request;
    request.set_handle(handle);
    return AsIpc(hdl::rpc::WatchClient(&client).Unwatch(request).status);
}

IpcStatus ResolveExport(PipeClient& client, const wchar_t* module, const char* name,
                        uint64_t* out_address) {
    hdl::rpc::v1::ResolveExportRequest request;
    request.set_module(WideToUtf8(module ? module : L""));
    request.set_name(name ? name : "");
    const auto result = hdl::rpc::CallClient(&client).ResolveExport(request);
    if (out_address)
        *out_address = result.has_response ? result.response.address() : 0;
    return AsIpc(result.status);
}

IpcStatus EnumImports(PipeClient& client, uint64_t module_base,
                      std::vector<HdlImportInfo>* output) {
    hdl::rpc::v1::EnumImportsRequest request;
    request.set_module_base(module_base);
    if (output)
        output->clear();
    const auto status =
        hdl::rpc::PeClient(&client).EnumImports(request, [output](const auto& batch) {
            if (output)
                for (const auto& value : batch.imports()) {
                    HdlImportInfo info{};
                    CopyText(info.module, value.module());
                    CopyText(info.name, value.name());
                    info.ordinal = value.ordinal();
                    info.iat_va = value.iat_address();
                    info.bound_va = value.bound_address();
                    output->push_back(info);
                }
            return true;
        });
    return AsIpc(status);
}

IpcStatus Fingerprint(PipeClient& client, uint32_t scan_flags,
                      std::vector<HdlFingerprintTag>* output) {
    hdl::rpc::v1::FingerprintRequest request;
    request.set_scan_flags(scan_flags ? scan_flags : HDL_FP_SCAN_DEFAULT);
    if (output)
        output->clear();
    const auto status =
        hdl::rpc::ProcessClient(&client).Fingerprint(request, [output](const auto& batch) {
            if (output)
                for (const auto& value : batch.tags()) {
                    HdlFingerprintTag tag{};
                    tag.category = value.category();
                    tag.confidence = value.confidence();
                    tag.flags = value.flags();
                    CopyText(tag.id, value.id());
                    CopyText(tag.evidence, value.evidence());
                    output->push_back(tag);
                }
            return true;
        });
    return AsIpc(status);
}

} // namespace hdlcli
