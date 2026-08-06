#include "handlers.hpp"

#include "common.hpp"
#include "convert.hpp"

#include "discover.hpp"

#include <mutex>
#include <string>
#include <vector>

namespace hdl::ipc {
namespace {

struct LockedDiscover {
    std::shared_ptr<DiscoverSessionHolder> holder;
    std::unique_lock<std::mutex> lock;
    HdlDiscoverSession* session = nullptr;

    explicit LockedDiscover(uint64_t id) : holder(FindDiscover(id)) {
        if (holder) {
            lock = std::unique_lock<std::mutex>(holder->mu);
            session = holder->session;
        }
    }
};

bool BuildSearchDesc(const rpc::v1::SearchScope& scope, const rpc::v1::SearchValue& value,
                     rpc::v1::SearchComparison comparison, rpc::v1::SearchAlignment alignment,
                     uint32_t max_results, SearchValueStorage* storage, std::wstring* module,
                     HdlSearchDesc* desc) {
    const int comparison_value = static_cast<int>(comparison);
    const int alignment_value = static_cast<int>(alignment);
    if (comparison_value < rpc::v1::SEARCH_COMPARISON_EXACT ||
        comparison_value > rpc::v1::SEARCH_COMPARISON_LESS ||
        alignment_value < rpc::v1::SEARCH_ALIGNMENT_NATURAL ||
        alignment_value > rpc::v1::SEARCH_ALIGNMENT_BYTE || !FromProto(value, storage) ||
        !Utf8ToWide(scope.module(), module)) {
        return false;
    }
    *desc = {};
    desc->start = scope.start();
    desc->size = scope.size();
    desc->value_type = storage->type;
    desc->cmp = static_cast<int32_t>(comparison);
    desc->alignment = static_cast<uint32_t>(alignment);
    desc->max_results = max_results;
    desc->value = storage->data();
    desc->value_size = storage->size();
    desc->flags = scope.flags();
    desc->module_or_null = module->empty() ? nullptr : module->c_str();
    return true;
}

template <typename T, typename Query>
HdlStatus QueryDynamic(uint32_t initial, Query query, std::vector<T>* values) {
    uint32_t count = initial;
    values->resize(initial);
    HdlStatus status = query(values->data(), &count);
    if (status == HDL_E_BUFFER_SMALL) {
        values->resize(count);
        status = query(values->data(), &count);
    }
    values->resize(status == HDL_OK ? count : 0);
    return status;
}

} // namespace

rpc::Status HandleDiscover_DiscoverCreate(rpc::CallContext&, const rpc::v1::Empty&,
                                          rpc::v1::DiscoverCreateResponse* response) {
    HdlDiscoverSession* session = nullptr;
    const HdlStatus status = DiscoverCreate(&session);
    if (status == HDL_OK && session)
        response->set_session_id(AllocDiscoverSession(session));
    return rpc::Status::FromHdl(status);
}

rpc::Status HandleDiscover_DiscoverClose(rpc::CallContext&,
                                         const rpc::v1::DiscoverCloseRequest& request,
                                         rpc::v1::Empty*) {
    auto holder = TakeDiscoverSession(request.session_id());
    if (!holder)
        return rpc::Status::FromHdl(HDL_E_NOT_FOUND);
    std::lock_guard<std::mutex> lock(holder->mu);
    if (holder->session) {
        DiscoverClose(holder->session);
        holder->session = nullptr;
    }
    return rpc::Status::Ok();
}

rpc::Status HandleDiscover_DiscoverAddCandidate(rpc::CallContext&,
                                                const rpc::v1::DiscoverAddCandidateRequest& request,
                                                rpc::v1::DiscoverAddCandidateResponse* response) {
    if (request.kind() < rpc::v1::CANDIDATE_KIND_ADDRESS ||
        request.kind() > rpc::v1::CANDIDATE_KIND_FIELD ||
        request.tag().find('\0') != std::string::npos)
        return rpc::Status::FromHdl(HDL_E_INVALID_ARG);
    LockedDiscover locked(request.session_id());
    if (!locked.session)
        return rpc::Status::FromHdl(HDL_E_NOT_FOUND);
    uint64_t candidate_id = 0;
    const HdlStatus status = DiscoverAddCandidate(
        locked.session, request.kind(), request.address(),
        request.tag().empty() ? nullptr : request.tag().c_str(), &candidate_id);
    response->set_candidate_id(candidate_id);
    return rpc::Status::FromHdl(status);
}

rpc::Status HandleDiscover_DiscoverScanValue(rpc::CallContext&,
                                             const rpc::v1::DiscoverScanValueRequest& request,
                                             rpc::v1::DiscoverScanValueResponse* response) {
    if (!request.has_value() || request.tag().find('\0') != std::string::npos) {
        return rpc::Status::FromHdl(HDL_E_INVALID_ARG);
    }
    SearchValueStorage storage;
    std::wstring module;
    HdlSearchDesc desc{};
    if (!BuildSearchDesc(request.scope(), request.value(), request.comparison(),
                         request.alignment(), request.max_results(), &storage, &module, &desc)) {
        return rpc::Status::FromHdl(HDL_E_INVALID_ARG);
    }
    LockedDiscover locked(request.session_id());
    if (!locked.session)
        return rpc::Status::FromHdl(HDL_E_NOT_FOUND);
    uint32_t before = 0;
    DiscoverGetCandidates(locked.session, nullptr, &before);
    const HdlStatus status = DiscoverScanValue(
        locked.session, &desc, request.tag().empty() ? nullptr : request.tag().c_str(),
        MakeToken(nullptr, CurrentRequestJob()));
    uint32_t after = 0;
    DiscoverGetCandidates(locked.session, nullptr, &after);
    response->set_added_count(after >= before ? after - before : 0);
    return rpc::Status::FromHdl(status);
}

rpc::Status HandleDiscover_DiscoverConstraintScan(
    rpc::CallContext&, const rpc::v1::DiscoverConstraintScanRequest& request, rpc::v1::Empty*) {
    if (request.predicates_size() > 32 || request.tag().find('\0') != std::string::npos) {
        return rpc::Status::FromHdl(HDL_E_INVALID_ARG);
    }
    std::wstring module;
    if (!Utf8ToWide(request.scope().module(), &module))
        return rpc::Status::FromHdl(HDL_E_INVALID_ARG);
    std::vector<HdlFieldPred> predicates(request.predicates_size());
    for (int index = 0; index < request.predicates_size(); ++index) {
        if (!FromProto(request.predicates(index), &predicates[index])) {
            return rpc::Status::FromHdl(HDL_E_INVALID_ARG);
        }
    }
    LockedDiscover locked(request.session_id());
    if (!locked.session)
        return rpc::Status::FromHdl(HDL_E_NOT_FOUND);
    return rpc::Status::FromHdl(DiscoverConstraintScan(
        locked.session, request.object_size(), predicates.empty() ? nullptr : predicates.data(),
        static_cast<uint32_t>(predicates.size()), request.scope().flags(),
        module.empty() ? nullptr : module.c_str(), request.max_results(),
        request.tag().empty() ? nullptr : request.tag().c_str(), nullptr));
}

rpc::Status
HandleDiscover_DiscoverSynthesizePattern(rpc::CallContext&,
                                         const rpc::v1::DiscoverSynthesizePatternRequest& request,
                                         rpc::v1::DiscoverSynthesizePatternResponse* response) {
    std::wstring module;
    if (!Utf8ToWide(request.scope().module(), &module))
        return rpc::Status::FromHdl(HDL_E_INVALID_ARG);
    LockedDiscover locked(request.session_id());
    if (!locked.session)
        return rpc::Status::FromHdl(HDL_E_NOT_FOUND);
    HdlSynthesizedPattern pattern{};
    const HdlStatus status = DiscoverSynthesizePattern(
        locked.session, request.candidate_id(), request.bytes_before(), request.bytes_after(),
        request.scope().flags(), module.empty() ? nullptr : module.c_str(), &pattern, nullptr);
    ToProto(pattern, response->mutable_pattern());
    return rpc::Status::FromHdl(status);
}

rpc::Status
HandleDiscover_DiscoverPathConsensus(rpc::CallContext&,
                                     const rpc::v1::DiscoverPathConsensusRequest& request,
                                     rpc::v1::DiscoverPathConsensusResponse* response) {
    std::wstring module;
    if (!Utf8ToWide(request.scope().module(), &module))
        return rpc::Status::FromHdl(HDL_E_INVALID_ARG);
    uint32_t maximum = request.max_results();
    if (!maximum || maximum > 256)
        maximum = 64;
    std::vector<HdlPointerPath> paths(maximum);
    uint32_t count = maximum;
    const HdlStatus status =
        DiscoverPathConsensus(request.target(), request.max_depth(), request.max_offset(), maximum,
                              request.scope().flags(), module.empty() ? nullptr : module.c_str(),
                              paths.data(), &count, nullptr);
    if (status == HDL_OK) {
        for (uint32_t index = 0; index < count; ++index)
            ToProto(paths[index], response->add_paths());
    }
    return rpc::Status::FromHdl(status);
}

rpc::Status HandleDiscover_DiscoverPathValidate(rpc::CallContext&,
                                                const rpc::v1::DiscoverPathValidateRequest& request,
                                                rpc::v1::DiscoverPathValidateResponse* response) {
    if (request.paths_size() > 256)
        return rpc::Status::FromHdl(HDL_E_INVALID_ARG);
    std::vector<HdlPointerPath> paths(request.paths_size());
    for (int index = 0; index < request.paths_size(); ++index) {
        if (!FromProto(request.paths(index), &paths[index]))
            return rpc::Status::FromHdl(HDL_E_INVALID_ARG);
    }
    uint32_t count = static_cast<uint32_t>(paths.size());
    const HdlStatus status = DiscoverPathValidate(paths.data(), &count, request.expected());
    if (status == HDL_OK) {
        for (uint32_t index = 0; index < count; ++index)
            ToProto(paths[index], response->add_paths());
    }
    return rpc::Status::FromHdl(status);
}

rpc::Status HandleDiscover_DiscoverWatch(rpc::CallContext&,
                                         const rpc::v1::DiscoverWatchRequest& request,
                                         rpc::v1::Empty*) {
    LockedDiscover locked(request.session_id());
    return rpc::Status::FromHdl(
        locked.session ? DiscoverWatch(locked.session, request.function(), request.argument_count())
                       : HDL_E_NOT_FOUND);
}

rpc::Status HandleDiscover_DiscoverUnwatchAll(rpc::CallContext&,
                                              const rpc::v1::DiscoverUnwatchAllRequest& request,
                                              rpc::v1::Empty*) {
    LockedDiscover locked(request.session_id());
    return rpc::Status::FromHdl(locked.session ? DiscoverUnwatchAll(locked.session)
                                               : HDL_E_NOT_FOUND);
}

rpc::Status HandleDiscover_DiscoverActionBegin(rpc::CallContext&,
                                               const rpc::v1::DiscoverActionBeginRequest& request,
                                               rpc::v1::Empty*) {
    if (request.name().find('\0') != std::string::npos)
        return rpc::Status::FromHdl(HDL_E_INVALID_ARG);
    LockedDiscover locked(request.session_id());
    return rpc::Status::FromHdl(locked.session
                                    ? DiscoverActionBegin(locked.session, request.name().c_str())
                                    : HDL_E_NOT_FOUND);
}

rpc::Status HandleDiscover_DiscoverActionEnd(rpc::CallContext&,
                                             const rpc::v1::DiscoverActionEndRequest& request,
                                             rpc::v1::Empty*) {
    LockedDiscover locked(request.session_id());
    return rpc::Status::FromHdl(locked.session ? DiscoverActionEnd(locked.session)
                                               : HDL_E_NOT_FOUND);
}

rpc::Status HandleDiscover_DiscoverWatchRegion(rpc::CallContext&,
                                               const rpc::v1::DiscoverWatchRegionRequest& request,
                                               rpc::v1::Empty*) {
    LockedDiscover locked(request.session_id());
    return rpc::Status::FromHdl(
        locked.session ? DiscoverWatchRegion(locked.session, request.base(), request.size())
                       : HDL_E_NOT_FOUND);
}

rpc::Status HandleDiscover_DiscoverGetHeat(rpc::CallContext&,
                                           const rpc::v1::DiscoverGetHeatRequest& request,
                                           rpc::v1::DiscoverGetHeatResponse* response) {
    uint32_t maximum = request.max_fields();
    if (!maximum || maximum > 512)
        maximum = 64;
    LockedDiscover locked(request.session_id());
    if (!locked.session)
        return rpc::Status::FromHdl(HDL_E_NOT_FOUND);
    std::vector<HdlHeatField> fields;
    const HdlStatus status = QueryDynamic<HdlHeatField>(
        maximum,
        [&locked, &request](HdlHeatField* out, uint32_t* count) {
            return DiscoverGetHeat(locked.session, request.base(), out, count);
        },
        &fields);
    if (status == HDL_OK)
        for (const auto& field : fields)
            ToProto(field, response->add_fields());
    return rpc::Status::FromHdl(status);
}

rpc::Status
HandleDiscover_DiscoverRankFunctions(rpc::CallContext&,
                                     const rpc::v1::DiscoverRankFunctionsRequest& request,
                                     rpc::v1::DiscoverRankFunctionsResponse* response) {
    if (request.action_name().find('\0') != std::string::npos)
        return rpc::Status::FromHdl(HDL_E_INVALID_ARG);
    uint32_t maximum = request.max_results();
    if (!maximum || maximum > 256)
        maximum = 64;
    LockedDiscover locked(request.session_id());
    if (!locked.session)
        return rpc::Status::FromHdl(HDL_E_NOT_FOUND);
    std::vector<HdlCandidate> candidates;
    const HdlStatus status = QueryDynamic<HdlCandidate>(
        maximum,
        [&locked, &request](HdlCandidate* out, uint32_t* count) {
            return DiscoverRankFunctions(locked.session, request.action_name().c_str(),
                                         request.flags(), out, count);
        },
        &candidates);
    if (status == HDL_OK)
        for (const auto& value : candidates)
            ToProto(value, response->add_candidates());
    return rpc::Status::FromHdl(status);
}

rpc::Status HandleDiscover_DiscoverWatchImport(rpc::CallContext&,
                                               const rpc::v1::DiscoverWatchImportRequest& request,
                                               rpc::v1::Empty*) {
    std::wstring module;
    if (!Utf8ToWide(request.module(), &module) || request.dll().find('\0') != std::string::npos ||
        request.import_name().find('\0') != std::string::npos)
        return rpc::Status::FromHdl(HDL_E_INVALID_ARG);
    LockedDiscover locked(request.session_id());
    return rpc::Status::FromHdl(
        locked.session
            ? DiscoverWatchImport(locked.session, module.empty() ? nullptr : module.c_str(),
                                  request.dll().c_str(), request.import_name().c_str(),
                                  request.argument_count())
            : HDL_E_NOT_FOUND);
}

rpc::Status HandleDiscover_DiscoverResetHeat(rpc::CallContext&,
                                             const rpc::v1::DiscoverResetHeatRequest& request,
                                             rpc::v1::Empty*) {
    LockedDiscover locked(request.session_id());
    return rpc::Status::FromHdl(locked.session ? DiscoverResetHeat(locked.session, request.base())
                                               : HDL_E_NOT_FOUND);
}

rpc::Status HandleDiscover_DiscoverExport(rpc::CallContext&,
                                          const rpc::v1::DiscoverExportRequest& request,
                                          rpc::v1::DiscoverExportResponse* response) {
    LockedDiscover locked(request.session_id());
    if (!locked.session)
        return rpc::Status::FromHdl(HDL_E_NOT_FOUND);
    uint32_t size = 0;
    HdlStatus status = DiscoverExport(locked.session, nullptr, &size);
    if (status != HDL_E_BUFFER_SMALL && status != HDL_OK)
        return rpc::Status::FromHdl(status);
    std::vector<char> json(size ? size : 1);
    uint32_t capacity = static_cast<uint32_t>(json.size());
    status = DiscoverExport(locked.session, json.data(), &capacity);
    if (status == HDL_OK) {
        const size_t length = capacity && json[capacity - 1] == '\0' ? capacity - 1 : capacity;
        response->set_json(json.data(), length);
    }
    return rpc::Status::FromHdl(status);
}

rpc::Status HandleDiscover_DiscoverImport(rpc::CallContext&,
                                          const rpc::v1::DiscoverImportRequest& request,
                                          rpc::v1::Empty*) {
    if (request.json().find('\0') != std::string::npos || request.json().size() > UINT32_MAX) {
        return rpc::Status::FromHdl(HDL_E_INVALID_ARG);
    }
    LockedDiscover locked(request.session_id());
    return rpc::Status::FromHdl(locked.session
                                    ? DiscoverImport(locked.session, request.json().c_str(),
                                                     static_cast<uint32_t>(request.json().size()))
                                    : HDL_E_NOT_FOUND);
}

rpc::Status HandleDiscover_DiscoverDiffObjects(rpc::CallContext&,
                                               const rpc::v1::DiscoverDiffObjectsRequest& request,
                                               rpc::v1::DiscoverDiffObjectsResponse* response) {
    if (request.addresses_size() > 64)
        return rpc::Status::FromHdl(HDL_E_INVALID_ARG);
    uint32_t maximum = request.max_fields();
    if (!maximum || maximum > 512)
        maximum = 64;
    std::vector<uint64_t> addresses(request.addresses().begin(), request.addresses().end());
    LockedDiscover locked(request.session_id());
    if (!locked.session)
        return rpc::Status::FromHdl(HDL_E_NOT_FOUND);
    std::vector<HdlHeatField> fields;
    const HdlStatus status = QueryDynamic<HdlHeatField>(
        maximum,
        [&locked, &request, &addresses](HdlHeatField* out, uint32_t* count) {
            return DiscoverDiffObjects(locked.session, addresses.data(),
                                       static_cast<uint32_t>(addresses.size()), request.max_size(),
                                       out, count);
        },
        &fields);
    if (status == HDL_OK)
        for (const auto& field : fields)
            ToProto(field, response->add_fields());
    return rpc::Status::FromHdl(status);
}

rpc::Status HandleDiscover_DiscoverApplyWatchHits(
    rpc::CallContext&, const rpc::v1::DiscoverApplyWatchHitsRequest& request, rpc::v1::Empty*) {
    LockedDiscover locked(request.session_id());
    return rpc::Status::FromHdl(
        locked.session
            ? DiscoverApplyWatchHits(locked.session, request.object_base(), request.size())
            : HDL_E_NOT_FOUND);
}

rpc::Status HandleDiscover_DiscoverGetEvidence(rpc::CallContext&,
                                               const rpc::v1::DiscoverGetEvidenceRequest& request,
                                               rpc::v1::DiscoverGetEvidenceResponse* response) {
    LockedDiscover locked(request.session_id());
    if (!locked.session)
        return rpc::Status::FromHdl(HDL_E_NOT_FOUND);
    std::vector<char> evidence(160);
    const HdlStatus status =
        DiscoverGetCandidateEvidence(locked.session, request.candidate_id(), evidence.data(),
                                     static_cast<uint32_t>(evidence.size()));
    if (status == HDL_OK)
        response->set_evidence(evidence.data());
    return rpc::Status::FromHdl(status);
}

rpc::Status HandleDiscover_DiscoverClusterType(rpc::CallContext&,
                                               const rpc::v1::DiscoverClusterTypeRequest& request,
                                               rpc::v1::Empty*) {
    std::wstring module;
    if (!Utf8ToWide(request.scope().module(), &module))
        return rpc::Status::FromHdl(HDL_E_INVALID_ARG);
    LockedDiscover locked(request.session_id());
    return rpc::Status::FromHdl(
        locked.session ? DiscoverClusterType(locked.session, request.seed(), request.object_size(),
                                             request.scope().flags(),
                                             module.empty() ? nullptr : module.c_str(),
                                             request.max_results(), nullptr)
                       : HDL_E_NOT_FOUND);
}

rpc::Status HandleDiscover_DiscoverGetCandidates(
    rpc::CallContext&, const rpc::v1::DiscoverGetCandidatesRequest& request,
    rpc::ServerWriter<rpc::v1::DiscoverGetCandidatesResponse>& writer) {
    uint32_t maximum = request.max_results();
    if (!maximum || maximum > 1024)
        maximum = 256;
    LockedDiscover locked(request.session_id());
    if (!locked.session)
        return rpc::Status::FromHdl(HDL_E_NOT_FOUND);
    std::vector<HdlCandidate> candidates;
    const HdlStatus status = QueryDynamic<HdlCandidate>(
        maximum,
        [&locked](HdlCandidate* out, uint32_t* count) {
            return DiscoverGetCandidates(locked.session, out, count);
        },
        &candidates);
    return WriteBatches(
        status, candidates, 32, writer,
        [](const HdlCandidate& value, rpc::v1::DiscoverGetCandidatesResponse* batch) {
            ToProto(value, batch->add_candidates());
            return true;
        });
}

} // namespace hdl::ipc
