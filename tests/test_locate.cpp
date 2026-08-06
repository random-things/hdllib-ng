#include "domain_api.hpp"
#include "support.hpp"
#include "test_runners.hpp"

#include <cstdio>

using hdltest::Counters;
using hdltest::IlLevel;
using hdltest::Report;
using hdltest::TargetProc;
using hdltest::TargetProfile;

void RunLocateTargetTests(Counters& counters, const wchar_t* target_path, const wchar_t* dll_path) {
    std::printf("\n== Locate (inject into hdl_test_target) ==\n");
    TargetProfile profile{"locate_fixtures", false, true, IlLevel::Medium};
    TargetProc target;
    if (!hdltest::SpawnTarget(target_path, profile, target)) {
        Report(counters, false, false, "locate spawn target", "");
        return;
    }
    uint64_t base = 0;
    const HdlStatus inject_status = hdl::InjectDllEx(
        target.pid, dll_path, HDL_INJECT_CREATE_REMOTE_THREAD, nullptr, nullptr, nullptr, &base);
    const bool verified =
        inject_status == HDL_OK &&
        hdltest::VerifyInjected(target.pid, dll_path, HDL_INJECT_CREATE_REMOTE_THREAD, base);
    Report(counters, verified, false, "locate inject", "");
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
    uint64_t truth_fn = 0, truth_str = 0, truth_leaf = 0, truth_root = 0, truth_obj = 0,
             truth_str_ptr = 0;
    Report(counters, resolve_export("HdlTestLocateFn", &truth_fn), false, "locate truth Fn export",
           "");
    Report(counters, resolve_export("HdlTestLocateString", &truth_str), false,
           "locate truth String export", "");
    Report(counters, resolve_export("HdlTestLocateLeaf", &truth_leaf), false,
           "locate truth Leaf export", "");
    Report(counters, resolve_export("HdlTestLocateRoot", &truth_root), false,
           "locate truth Root export", "");
    Report(counters, resolve_export("HdlTestLocateObj", &truth_obj), false,
           "locate truth Obj export", "");
    Report(counters, resolve_export("HdlTestLocateStringPtr", &truth_str_ptr), false,
           "locate truth StringPtr export", "");

    {
        hdl::rpc::v1::ResolvePatternRequest request;
        request.set_pattern("31 4C 44 48");
        request.set_max_scan_hits(64);
        request.mutable_scope()->set_flags(HDL_SEARCH_MODULE | HDL_SEARCH_IMAGE);
        request.mutable_scope()->set_module("hdl_test_target.exe");
        hdl::rpc::v1::ResolvePatternResponse response;
        int32_t status = HDL_E_FAILED;
        const bool called = hdltest::PipeUnary<hdl::rpc::Method::Locate_ResolvePattern>(
            target.pid, request, &response, &status);
        const auto& result = response.result();
        Report(counters,
               called && status == HDL_OK && truth_fn && result.match_address() >= truth_fn &&
                   result.match_address() < truth_fn + 0x80,
               false, "locate ResolvePattern near Fn", "");
    }
    for (const uint32_t xref_flags :
         {static_cast<uint32_t>(HDL_XREF_ABSOLUTE), static_cast<uint32_t>(HDL_XREF_RIP_REL)}) {
        hdl::rpc::v1::FindStringXrefsRequest request;
        request.set_narrow_value("HDL_LOCATE_STRING_v1");
        request.set_xref_flags(xref_flags);
        request.mutable_scope()->set_flags(HDL_SEARCH_MODULE | HDL_SEARCH_IMAGE);
        request.mutable_scope()->set_module("hdl_test_target.exe");
        request.set_max_results(xref_flags == HDL_XREF_ABSOLUTE ? 64 : 256);
        hdl::rpc::v1::FindStringXrefsResponse response;
        int32_t status = HDL_E_FAILED;
        const bool called = hdltest::PipeUnary<hdl::rpc::Method::Locate_FindStringXrefs>(
            target.pid, request, &response, &status);
        bool found = false;
        for (uint64_t value : response.addresses())
            if (value == truth_str_ptr)
                found = true;
        Report(counters,
               called && status == HDL_OK &&
                   (xref_flags == HDL_XREF_ABSOLUTE ? found : response.addresses_size() >= 1),
               false,
               xref_flags == HDL_XREF_ABSOLUTE ? "locate xrefs absolute hits StringPtr"
                                               : "locate xrefs rip count",
               "");
    }
    {
        hdl::rpc::v1::PointerScanRequest request;
        request.set_target(truth_leaf);
        request.set_max_depth(2);
        request.set_max_offset(0x100);
        request.set_max_results(64);
        request.mutable_scope()->set_flags(HDL_SEARCH_MODULE | HDL_SEARCH_IMAGE);
        request.mutable_scope()->set_module("hdl_test_target.exe");
        hdl::rpc::v1::PointerScanResponse response;
        int32_t status = HDL_E_FAILED;
        const bool called = hdltest::PipeUnary<hdl::rpc::Method::Locate_PointerScan>(
            target.pid, request, &response, &status);
        bool found = false;
        for (const auto& path : response.paths())
            if (!path.offsets().empty() && path.offsets(path.offsets_size() - 1) == 0)
                found = true;
        Report(counters, called && status == HDL_OK && found, false, "locate ptrscan finds path",
               "");
    }
    {
        hdl::rpc::v1::ProbeStructRequest request;
        request.set_address(truth_obj);
        request.set_size(40);
        request.set_max_fields(16);
        hdl::rpc::v1::ProbeStructResponse response;
        int32_t status = HDL_E_FAILED;
        const bool called = hdltest::PipeUnary<hdl::rpc::Method::Locate_ProbeStruct>(
            target.pid, request, &response, &status);
        bool has_vtable = false;
        for (const auto& field : response.fields())
            if (field.offset() == 0 && (field.kind() == hdl::rpc::v1::FIELD_KIND_VTABLE ||
                                        field.kind() == hdl::rpc::v1::FIELD_KIND_POINTER))
                has_vtable = true;
        Report(counters, called && status == HDL_OK && has_vtable, false,
               "locate probe vtable field", "");
    }
    auto follow = [&](uint64_t start, std::initializer_list<int64_t> offsets, uint64_t expected,
                      const char* label) {
        hdl::rpc::v1::FollowPointersRequest request;
        request.set_base(start);
        for (auto offset : offsets)
            request.add_offsets(offset);
        hdl::rpc::v1::FollowPointersResponse response;
        int32_t status = HDL_E_FAILED;
        const bool called = hdltest::PipeUnary<hdl::rpc::Method::Locate_FollowPointers>(
            target.pid, request, &response, &status);
        Report(counters, called && status == HDL_OK && response.address() == expected, false, label,
               "");
    };
    follow(truth_str_ptr, {0}, truth_str, "locate FollowPointers StringPtr");
    follow(truth_root, {0, 0}, truth_leaf, "locate FollowPointers Root to leaf");
}
