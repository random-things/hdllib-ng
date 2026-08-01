#include "handlers.hpp"
#include "wire.hpp"

#include "jobs.hpp"
#include "locate.hpp"
#include "protocol.hpp"

#include <cstring>
#include <string>
#include <thread>
#include <vector>

namespace hdl {
namespace ipc {

bool HandleResolvePattern(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    std::string pattern;
    uint32_t hit_index = 0;
    int32_t pattern_offset = 0;
    uint32_t rip_disp = 0;
    uint32_t rip_len = 0;
    uint32_t follow_count = 0;
    uint32_t search_flags = 0;
    uint32_t max_scan = 0;
    std::wstring module;
    if (!r.TakeString(pattern) || !r.TakePod(hit_index) || !r.TakePod(pattern_offset) ||
        !r.TakePod(rip_disp) || !r.TakePod(rip_len) || !r.TakePod(follow_count) ||
        follow_count > 16 || !r.TakePod(search_flags) || !r.TakePod(max_scan) ||
        !r.TakeWString(module)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    std::vector<int64_t> follows(follow_count);
    for (uint32_t i = 0; i < follow_count; ++i) {
        if (!r.TakePod(follows[i])) {
            AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
            return WriteFrame(pipe, resp);
        }
    }
    uint64_t job_id = 0;
    uint32_t timeout_ms = 0;
    uint32_t flags = 0;
    TakeOptionalJobTimeoutFlags(r, &job_id, &timeout_ms, &flags);
    (void)flags;
    auto job = BindJob(job_id, timeout_ms);

    HdlPatternResolve in{};
    in.pattern = pattern.c_str();
    in.hit_index = hit_index;
    in.pattern_offset = pattern_offset;
    in.rip_disp_offset = rip_disp;
    in.rip_instr_len = rip_len;
    in.follow_offsets = follow_count ? follows.data() : nullptr;
    in.follow_count = follow_count;
    in.flags = search_flags;
    in.module_or_null = module.empty() ? nullptr : module.c_str();
    in.max_scan_hits = max_scan;
    HdlPatternResult out{};
    volatile int local = 0;
    std::thread watcher;
    if (job) {
        watcher = std::thread([job, &local]() {
            while (!local) {
                if (JobCheck(job) != HDL_OK) {
                    local = 1;
                    break;
                }
                Sleep(20);
            }
        });
    }
    const HdlStatus st = ResolvePattern(&in, &out, job ? &local : nullptr);
    if (job) {
        local = 1;
        if (watcher.joinable()) {
            watcher.join();
        }
    }
    AppendPod(resp, static_cast<int32_t>(st));
    proto::AppendHdlPatternResult(resp, out);
    return WriteFrame(pipe, resp);
}

bool HandleFindStringXrefs(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint32_t str_len = 0;
    int32_t is_wide = 0;
    uint32_t xref_flags = 0;
    uint32_t search_flags = 0;
    uint32_t max_out = 0;
    std::wstring module;
    if (!r.TakePod(str_len) || !r.TakePod(is_wide) || !r.TakePod(xref_flags) ||
        !r.TakePod(search_flags) || !r.TakePod(max_out) || !r.TakeWString(module) ||
        r.left < str_len) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    std::vector<uint8_t> str(str_len);
    if (str_len) {
        memcpy(str.data(), r.p, str_len);
        r.p += str_len;
        r.left -= str_len;
    }
    if (max_out == 0 || max_out > 4096) {
        max_out = 256;
    }
    std::vector<uint64_t> xrefs(max_out);
    uint32_t count = max_out;
    const HdlStatus st =
        FindStringXrefs(str.data(), str_len, is_wide, xref_flags, search_flags,
                        module.empty() ? nullptr : module.c_str(), xrefs.data(), &count, nullptr);
    AppendPod(resp, static_cast<int32_t>(st));
    AppendPod(resp, count);
    if (st == HDL_OK && count) {
        AppendBytes(resp, xrefs.data(), count * sizeof(uint64_t));
    }
    return WriteFrame(pipe, resp);
}

bool HandlePointerScan(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t target = 0;
    uint32_t max_depth = 0;
    uint32_t max_offset = 0;
    uint32_t max_results = 0;
    uint32_t search_flags = 0;
    std::wstring module;
    if (!r.TakePod(target) || !r.TakePod(max_depth) || !r.TakePod(max_offset) ||
        !r.TakePod(max_results) || !r.TakePod(search_flags) || !r.TakeWString(module)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    if (max_results == 0 || max_results > 256) {
        max_results = 64;
    }
    std::vector<HdlPointerPath> paths(max_results);
    uint32_t count = max_results;
    const HdlStatus st =
        PointerScan(target, max_depth, max_offset, max_results, search_flags,
                    module.empty() ? nullptr : module.c_str(), paths.data(), &count, nullptr);
    AppendPod(resp, static_cast<int32_t>(st));
    AppendPod(resp, count);
    if (st == HDL_OK && count) {
        for (uint32_t _i = 0; _i < count; ++_i)
            proto::AppendHdlPointerPath(resp, paths[_i]);
    }
    return WriteFrame(pipe, resp);
}

bool HandleProbeStruct(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t addr = 0;
    uint32_t size = 0;
    uint32_t max_fields = 0;
    if (!r.TakePod(addr) || !r.TakePod(size) || !r.TakePod(max_fields)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    if (max_fields == 0 || max_fields > 512) {
        max_fields = 64;
    }
    std::vector<HdlStructField> fields(max_fields);
    uint32_t count = max_fields;
    const HdlStatus st = ProbeStruct(addr, size, fields.data(), &count);
    AppendPod(resp, static_cast<int32_t>(st == HDL_E_BUFFER_SMALL ? HDL_OK : st));
    AppendPod(resp, count);
    if (st == HDL_OK && count) {
        for (uint32_t _i = 0; _i < count; ++_i)
            proto::AppendHdlStructField(resp, fields[_i]);
    }
    return WriteFrame(pipe, resp);
}

} // namespace ipc
} // namespace hdl
