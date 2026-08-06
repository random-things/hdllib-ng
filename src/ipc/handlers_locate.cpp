#include "handlers.hpp"

#include "common.hpp"
#include "convert.hpp"

#include "locate.hpp"

#include <thread>
#include <vector>

namespace hdl::ipc {

rpc::Status HandleLocate_ResolvePattern(rpc::CallContext&,
                                        const rpc::v1::ResolvePatternRequest& request,
                                        rpc::v1::ResolvePatternResponse* response) {
    if (request.pattern().empty() || request.pattern().find('\0') != std::string::npos ||
        request.follow_offsets_size() > 16) {
        return rpc::Status::FromHdl(HDL_E_INVALID_ARG);
    }
    std::wstring module;
    if (!Utf8ToWide(request.scope().module(), &module)) {
        return rpc::Status::FromHdl(HDL_E_INVALID_ARG);
    }
    std::vector<int64_t> follows(request.follow_offsets().begin(), request.follow_offsets().end());
    HdlPatternResolve input{};
    input.pattern = request.pattern().c_str();
    input.hit_index = request.hit_index();
    input.pattern_offset = request.pattern_offset();
    input.rip_disp_offset = request.rip_displacement_offset();
    input.rip_instr_len = request.rip_instruction_length();
    input.follow_offsets = follows.empty() ? nullptr : follows.data();
    input.follow_count = static_cast<uint32_t>(follows.size());
    input.flags = request.scope().flags();
    input.module_or_null = module.empty() ? nullptr : module.c_str();
    input.max_scan_hits = request.max_scan_hits();

    const auto job = CurrentRequestJob();
    volatile int cancel = 0;
    std::thread watcher;
    if (job && job->deadline_tick) {
        watcher = std::thread([job, &cancel] {
            while (!cancel) {
                if (JobCheck(job) != HDL_OK) {
                    cancel = 1;
                    break;
                }
                Sleep(20);
            }
        });
    }
    HdlPatternResult result{};
    const HdlStatus status =
        ResolvePattern(&input, &result, watcher.joinable() ? &cancel : nullptr);
    if (watcher.joinable()) {
        cancel = 1;
        watcher.join();
    }
    ToProto(result, response->mutable_result());
    return rpc::Status::FromHdl(status);
}

rpc::Status HandleLocate_FindStringXrefs(rpc::CallContext&,
                                         const rpc::v1::FindStringXrefsRequest& request,
                                         rpc::v1::FindStringXrefsResponse* response) {
    std::vector<uint8_t> bytes;
    bool wide = false;
    if (request.value_case() == rpc::v1::FindStringXrefsRequest::kNarrowValue) {
        bytes.assign(request.narrow_value().begin(), request.narrow_value().end());
    } else if (request.value_case() == rpc::v1::FindStringXrefsRequest::kWideValue) {
        std::wstring value;
        if (!Utf8ToWide(request.wide_value(), &value)) {
            return rpc::Status::FromHdl(HDL_E_INVALID_ARG);
        }
        wide = true;
        bytes.resize(value.size() * sizeof(wchar_t));
        if (!bytes.empty()) {
            std::memcpy(bytes.data(), value.data(), bytes.size());
        }
    } else {
        return rpc::Status::FromHdl(HDL_E_INVALID_ARG);
    }
    std::wstring module;
    if (!Utf8ToWide(request.scope().module(), &module)) {
        return rpc::Status::FromHdl(HDL_E_INVALID_ARG);
    }
    uint32_t maximum = request.max_results();
    if (!maximum || maximum > 4096) {
        maximum = 256;
    }
    std::vector<uint64_t> xrefs(maximum);
    uint32_t count = maximum;
    const HdlStatus status =
        FindStringXrefs(bytes.data(), static_cast<uint32_t>(bytes.size()), wide,
                        request.xref_flags(), request.scope().flags(),
                        module.empty() ? nullptr : module.c_str(), xrefs.data(), &count, nullptr);
    if (status == HDL_OK) {
        for (uint32_t index = 0; index < count; ++index) {
            response->add_addresses(xrefs[index]);
        }
    }
    return rpc::Status::FromHdl(status);
}

rpc::Status HandleLocate_PointerScan(rpc::CallContext&, const rpc::v1::PointerScanRequest& request,
                                     rpc::v1::PointerScanResponse* response) {
    std::wstring module;
    if (!Utf8ToWide(request.scope().module(), &module)) {
        return rpc::Status::FromHdl(HDL_E_INVALID_ARG);
    }
    uint32_t maximum = request.max_results();
    if (!maximum || maximum > 256) {
        maximum = 64;
    }
    std::vector<HdlPointerPath> paths(maximum);
    uint32_t count = maximum;
    const HdlStatus status =
        PointerScan(request.target(), request.max_depth(), request.max_offset(), maximum,
                    request.scope().flags(), module.empty() ? nullptr : module.c_str(),
                    paths.data(), &count, nullptr);
    if (status == HDL_OK) {
        for (uint32_t index = 0; index < count; ++index) {
            ToProto(paths[index], response->add_paths());
        }
    }
    return rpc::Status::FromHdl(status);
}

rpc::Status HandleLocate_ProbeStruct(rpc::CallContext&, const rpc::v1::ProbeStructRequest& request,
                                     rpc::v1::ProbeStructResponse* response) {
    uint32_t maximum = request.max_fields();
    if (!maximum || maximum > 512) {
        maximum = 64;
    }
    std::vector<HdlStructField> fields(maximum);
    uint32_t count = maximum;
    HdlStatus status = ProbeStruct(request.address(), request.size(), fields.data(), &count);
    if (status == HDL_E_BUFFER_SMALL && count <= 512) {
        fields.resize(count);
        uint32_t retry_count = count;
        status = ProbeStruct(request.address(), request.size(), fields.data(), &retry_count);
        count = retry_count;
    }
    if (status == HDL_OK) {
        for (uint32_t index = 0; index < count; ++index) {
            ToProto(fields[index], response->add_fields());
        }
    }
    return rpc::Status::FromHdl(status);
}

} // namespace hdl::ipc
