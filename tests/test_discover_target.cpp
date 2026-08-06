#include "domain_api.hpp"
#include "support.hpp"
#include "test_runners.hpp"

#include <cstdio>
#include <vector>

using hdltest::Counters;
using hdltest::IlLevel;
using hdltest::Report;
using hdltest::TargetProc;
using hdltest::TargetProfile;

void RunDiscoverTargetTests(Counters& counters, const wchar_t* target_path,
                            const wchar_t* dll_path) {
    std::printf("\n== Discover (inject into hdl_test_target) ==\n");
    TargetProc target;
    TargetProfile profile{"discover_fixtures", false, true, IlLevel::Medium};
    if (!hdltest::SpawnTarget(target_path, profile, target)) {
        Report(counters, false, false, "discover spawn target", "");
        return;
    }
    uint64_t base = 0;
    const HdlStatus inject_status = hdl::InjectDllEx(
        target.pid, dll_path, HDL_INJECT_CREATE_REMOTE_THREAD, nullptr, nullptr, nullptr, &base);
    const bool verified =
        inject_status == HDL_OK &&
        hdltest::VerifyInjected(target.pid, dll_path, HDL_INJECT_CREATE_REMOTE_THREAD, base);
    Report(counters, verified, false, "discover inject", "");
    if (!verified)
        return;

    auto resolve_export = [&](const char* name, uint64_t* output) {
        hdl::rpc::v1::ResolveExportRequest request;
        request.set_name(name);
        hdl::rpc::v1::ResolveExportResponse response;
        int32_t status = HDL_E_FAILED;
        const bool ok = hdltest::PipeUnary<hdl::rpc::Method::Call_ResolveExport>(
                            target.pid, request, &response, &status) &&
                        status == HDL_OK && response.address();
        if (ok)
            *output = response.address();
        return ok;
    };
    auto call_export = [&](const char* name, const int64_t* argument = nullptr) {
        hdl::rpc::v1::CallExportRequest request;
        request.set_name(name);
        if (argument)
            request.add_arguments()->set_signed_value(*argument);
        hdl::rpc::v1::CallExportResponse response;
        int32_t status = HDL_E_FAILED;
        return hdltest::PipeUnary<hdl::rpc::Method::Call_CallExport>(target.pid, request, &response,
                                                                     &status, 5000) &&
               status == HDL_OK;
    };
    uint64_t truth_leaf = 0, truth_action = 0, truth_obj_a = 0, truth_obj_b = 0, truth_dyn_root = 0;
    Report(counters, resolve_export("HdlTestDiscoverLeaf", &truth_leaf), false,
           "discover truth Leaf", "");
    Report(counters, resolve_export("HdlTestDiscoverAction", &truth_action), false,
           "discover truth Action", "");
    Report(counters, resolve_export("HdlTestDiscoverObjA", &truth_obj_a), false,
           "discover truth ObjA", "");
    Report(counters, resolve_export("HdlTestDiscoverObjB", &truth_obj_b), false,
           "discover truth ObjB", "");
    Report(counters, resolve_export("HdlTestDiscoverDynRoot", &truth_dyn_root), false,
           "discover truth DynRoot", "");

    {
        hdl::rpc::v1::EnumFunctionsRequest request;
        request.mutable_scope()->set_flags(HDL_SEARCH_MODULE);
        request.mutable_scope()->set_module("hdl_test_target.exe");
        request.set_max_results(128);
        bool saw_export = false;
        int32_t status = HDL_E_FAILED;
        const bool called = hdltest::PipeStream<hdl::rpc::Method::Locate_EnumFunctions>(
            target.pid, request,
            [&](const auto& batch) {
                for (const auto& fn : batch.functions())
                    if (fn.start() == truth_leaf && (fn.flags() & HDL_FN_EXPORT) &&
                        fn.confidence() >= 50)
                        saw_export = true;
                return true;
            },
            &status);
        Report(counters, called && status == HDL_OK && saw_export, false,
               "discover EnumFunctions HdlTest export", "");
    }
    uint64_t session = 0;
    {
        hdl::rpc::v1::DiscoverCreateResponse response;
        int32_t status = HDL_E_FAILED;
        const bool ok = hdltest::PipeUnary<hdl::rpc::Method::Discover_DiscoverCreate>(
                            target.pid, hdl::rpc::v1::Empty{}, &response, &status) &&
                        status == HDL_OK && response.session_id();
        session = response.session_id();
        Report(counters, ok, false, "discover create", "");
        if (!ok)
            return;
    }
    {
        hdl::rpc::v1::DiscoverConstraintScanRequest request;
        request.set_session_id(session);
        request.set_object_size(24);
        request.set_max_results(64);
        request.set_tag("player");
        request.mutable_scope()->set_flags(HDL_SEARCH_MODULE | HDL_SEARCH_IMAGE);
        request.mutable_scope()->set_module("hdl_test_target.exe");
        auto* range = request.add_predicates();
        range->set_offset(8);
        range->mutable_range_i32()->set_minimum(1);
        range->mutable_range_i32()->set_maximum(100);
        auto* relative = request.add_predicates();
        relative->set_offset(8);
        relative->mutable_relative_le_i32()->set_relative_offset(4);
        hdl::rpc::v1::Empty response;
        int32_t status = HDL_E_FAILED;
        const bool called = hdltest::PipeUnary<hdl::rpc::Method::Discover_DiscoverConstraintScan>(
            target.pid, request, &response, &status);
        Report(counters, called && status == HDL_OK, false, "discover constraint scan", "");
    }
    {
        hdl::rpc::v1::DiscoverGetCandidatesRequest request;
        request.set_session_id(session);
        request.set_max_results(128);
        bool found_a = false, found_b = false;
        int32_t status = HDL_E_FAILED;
        const bool called = hdltest::PipeStream<hdl::rpc::Method::Discover_DiscoverGetCandidates>(
            target.pid, request,
            [&](const auto& batch) {
                for (const auto& value : batch.candidates()) {
                    found_a |= value.address() == truth_obj_a;
                    found_b |= value.address() == truth_obj_b;
                }
                return true;
            },
            &status);
        Report(counters, called && status == HDL_OK && found_a && found_b, false,
               "discover candidates include objs", "");
    }
    {
        hdl::rpc::v1::DiscoverAddCandidateRequest add;
        add.set_session_id(session);
        add.set_kind(hdl::rpc::v1::CANDIDATE_KIND_FUNCTION);
        add.set_address(truth_leaf);
        add.set_tag("leaf");
        hdl::rpc::v1::DiscoverAddCandidateResponse added;
        int32_t status = HDL_E_FAILED;
        const bool add_ok = hdltest::PipeUnary<hdl::rpc::Method::Discover_DiscoverAddCandidate>(
                                target.pid, add, &added, &status) &&
                            status == HDL_OK && added.candidate_id();
        Report(counters, add_ok, false, "discover add leaf cand", "");
        hdl::rpc::v1::DiscoverSynthesizePatternRequest request;
        request.set_session_id(session);
        request.set_candidate_id(added.candidate_id());
        request.set_bytes_after(24);
        request.mutable_scope()->set_flags(HDL_SEARCH_MODULE | HDL_SEARCH_IMAGE);
        request.mutable_scope()->set_module("hdl_test_target.exe");
        hdl::rpc::v1::DiscoverSynthesizePatternResponse response;
        status = HDL_E_FAILED;
        const bool synth_ok =
            hdltest::PipeUnary<hdl::rpc::Method::Discover_DiscoverSynthesizePattern>(
                target.pid, request, &response, &status) &&
            status == HDL_OK && !response.pattern().pattern().empty() &&
            response.pattern().resolved_address() == truth_leaf;
        Report(counters, synth_ok, false, "discover synthesize leaf", "");
    }
    {
        hdl::rpc::v1::DiscoverWatchRequest watch;
        watch.set_session_id(session);
        watch.set_function(truth_leaf);
        hdl::rpc::v1::Empty empty;
        int32_t status = HDL_E_FAILED;
        Report(counters,
               hdltest::PipeUnary<hdl::rpc::Method::Discover_DiscoverWatch>(target.pid, watch,
                                                                            &empty, &status) &&
                   status == HDL_OK,
               false, "discover watch leaf", "");
        hdl::rpc::v1::DiscoverWatchRegionRequest region;
        region.set_session_id(session);
        region.set_base(truth_obj_a);
        region.set_size(24);
        (void)hdltest::PipeUnary<hdl::rpc::Method::Discover_DiscoverWatchRegion>(target.pid, region,
                                                                                 &empty, &status);
        hdl::rpc::v1::DiscoverActionBeginRequest begin;
        begin.set_session_id(session);
        begin.set_name("fire");
        Report(counters,
               hdltest::PipeUnary<hdl::rpc::Method::Discover_DiscoverActionBegin>(
                   target.pid, begin, &empty, &status) &&
                   status == HDL_OK,
               false, "discover action begin", "");
        Report(counters, call_export("HdlTestDiscoverAction"), false, "discover call action", "");
        const int64_t damage = 5;
        Report(counters, call_export("HdlTestDiscoverDamage", &damage), false,
               "discover call damage", "");
        hdl::rpc::v1::DiscoverActionEndRequest end;
        end.set_session_id(session);
        Report(counters,
               hdltest::PipeUnary<hdl::rpc::Method::Discover_DiscoverActionEnd>(target.pid, end,
                                                                                &empty, &status) &&
                   status == HDL_OK,
               false, "discover action end", "");
        hdl::rpc::v1::DiscoverRankFunctionsRequest rank;
        rank.set_session_id(session);
        rank.set_action_name("fire");
        rank.set_max_results(32);
        hdl::rpc::v1::DiscoverRankFunctionsResponse ranked;
        status = HDL_E_FAILED;
        const bool rank_called =
            hdltest::PipeUnary<hdl::rpc::Method::Discover_DiscoverRankFunctions>(target.pid, rank,
                                                                                 &ranked, &status);
        bool near_action = false;
        for (const auto& value : ranked.candidates())
            if (value.address() >= truth_action && value.address() < truth_action + 0x80)
                near_action = true;
        Report(counters, rank_called && status == HDL_OK && near_action, false,
               "discover rank near Action", "");
        hdl::rpc::v1::DiscoverGetHeatRequest heat;
        heat.set_session_id(session);
        heat.set_base(truth_obj_a);
        heat.set_max_fields(16);
        hdl::rpc::v1::DiscoverGetHeatResponse heated;
        status = HDL_E_FAILED;
        const bool heat_called = hdltest::PipeUnary<hdl::rpc::Method::Discover_DiscoverGetHeat>(
            target.pid, heat, &heated, &status);
        bool health_hot = false;
        for (const auto& field : heated.fields())
            health_hot |= field.offset() == 8;
        Report(counters, heat_called && status == HDL_OK && health_hot, false,
               "discover heat on health", "");
    }
    {
        call_export("HdlTestDiscoverAllocDyn");
        auto read_dynamic = [&]() {
            hdl::rpc::v1::FollowPointersRequest request;
            request.set_base(truth_dyn_root);
            request.add_offsets(0);
            hdl::rpc::v1::FollowPointersResponse response;
            int32_t status = HDL_E_FAILED;
            (void)hdltest::PipeUnary<hdl::rpc::Method::Locate_FollowPointers>(target.pid, request,
                                                                              &response, &status);
            return status == HDL_OK ? response.address() : 0;
        };
        const uint64_t dynamic_one = read_dynamic();
        hdl::rpc::v1::DiscoverPathConsensusRequest consensus;
        consensus.set_target(dynamic_one);
        consensus.set_max_depth(2);
        consensus.set_max_offset(0x100);
        consensus.set_max_results(64);
        consensus.mutable_scope()->set_flags(HDL_SEARCH_MODULE | HDL_SEARCH_IMAGE);
        consensus.mutable_scope()->set_module("hdl_test_target.exe");
        hdl::rpc::v1::DiscoverPathConsensusResponse paths;
        int32_t status = HDL_E_FAILED;
        const bool consensus_ok =
            hdltest::PipeUnary<hdl::rpc::Method::Discover_DiscoverPathConsensus>(
                target.pid, consensus, &paths, &status) &&
            status == HDL_OK && paths.paths_size() >= 1;
        Report(counters, consensus_ok, false, "discover pathconsensus", "");
        call_export("HdlTestDiscoverAllocDyn");
        const uint64_t dynamic_two = read_dynamic();
        hdl::rpc::v1::DiscoverPathValidateRequest validate;
        validate.set_expected(dynamic_two);
        for (const auto& path : paths.paths())
            *validate.add_paths() = path;
        hdl::rpc::v1::DiscoverPathValidateResponse kept;
        status = HDL_E_FAILED;
        const bool validate_called =
            hdltest::PipeUnary<hdl::rpc::Method::Discover_DiscoverPathValidate>(
                target.pid, validate, &kept, &status);
        bool has_root = false;
        for (const auto& path : kept.paths())
            has_root |= path.static_base() == truth_dyn_root && path.offsets_size() == 1 &&
                        path.offsets(0) == 0;
        Report(counters,
               validate_called && status == HDL_OK && has_root && dynamic_one && dynamic_two, false,
               "discover pathvalidate keeps DynRoot", "");
    }
    {
        hdl::rpc::v1::DiscoverCloseRequest request;
        request.set_session_id(session);
        hdl::rpc::v1::Empty response;
        int32_t status = HDL_E_FAILED;
        Report(counters,
               hdltest::PipeUnary<hdl::rpc::Method::Discover_DiscoverClose>(target.pid, request,
                                                                            &response, &status) &&
                   status == HDL_OK,
               false, "discover close", "");
    }
}
