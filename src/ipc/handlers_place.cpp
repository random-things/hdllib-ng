#include "handlers.hpp"
#include "wire.hpp"

#include "alloc.hpp"
#include "jobs.hpp"
#include "place.hpp"
#include "protocol.hpp"

#include <string>
#include <thread>
#include <vector>

namespace hdl {
namespace ipc {

bool HandleFindCaves(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint32_t min_size = 0;
    uint32_t fill_byte = 0;
    uint32_t search_flags = 0;
    uint32_t max_results = 0;
    uint64_t near_addr = 0;
    uint64_t max_distance = 0;
    std::wstring module;
    uint64_t job_id = 0;
    uint32_t timeout_ms = 0;
    uint32_t flags = 0;
    if (!r.TakePod(min_size) || !r.TakePod(fill_byte) || !r.TakePod(search_flags) ||
        !r.TakePod(max_results) || !r.TakePod(near_addr) || !r.TakePod(max_distance) ||
        !r.TakeWString(module)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    TakeOptionalJobTimeoutFlags(r, &job_id, &timeout_ms, &flags);

    HdlCaveQuery q{};
    q.min_size = min_size;
    q.fill_byte = fill_byte;
    q.search_flags = search_flags;
    q.max_results = max_results;
    q.near_addr = near_addr;
    q.max_distance = max_distance;
    q.module_or_null = module.empty() ? nullptr : module.c_str();

    auto job = BindJob(job_id, timeout_ms);
    volatile int cancel = 0;
    std::thread watcher;
    if (job) {
        watcher = std::thread([job, &cancel]() {
            while (!cancel) {
                if (JobCheck(job) != HDL_OK) {
                    cancel = 1;
                    break;
                }
                Sleep(20);
            }
        });
    }

    uint32_t count = 0;
    HdlStatus st = FindCaves(&q, nullptr, &count, &cancel);
    std::vector<HdlCaveInfo> caves;
    if (st == HDL_E_BUFFER_SMALL && count > 0) {
        caves.resize(count);
        st = FindCaves(&q, caves.data(), &count, &cancel);
    } else if (st == HDL_OK) {
        count = 0;
    }
    if (watcher.joinable()) {
        cancel = 1;
        watcher.join();
    }
    if (job) {
        const HdlStatus cs = JobCheck(job);
        if (cs != HDL_OK && st == HDL_OK) {
            st = cs;
        }
    }

    if (flags & HDL_IPC_REQ_STREAM) {
        return WriteStreamed(pipe, st, caves.data(), count, 64);
    }
    AppendPod(resp, static_cast<int32_t>(st));
    AppendPod(resp, count);
    if (count && st == HDL_OK) {
        for (uint32_t _i = 0; _i < count; ++_i) proto::AppendHdlCaveInfo(resp, caves[_i]);
    }
    return WriteFrame(pipe, resp);
}

bool HandleAllocNear(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t near_addr = 0;
    uint64_t max_distance = 0;
    uint64_t size = 0;
    uint32_t protect = 0;
    if (!r.TakePod(near_addr) || !r.TakePod(max_distance) || !r.TakePod(size) ||
        !r.TakePod(protect)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    uint64_t addr = 0;
    const HdlStatus st =
        AllocNear(near_addr, max_distance, static_cast<size_t>(size), protect, &addr);
    AppendPod(resp, static_cast<int32_t>(st));
    AppendPod(resp, addr);
    return WriteFrame(pipe, resp);
}

bool HandleProtectMemory(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t addr = 0;
    uint64_t size = 0;
    uint32_t protect = 0;
    if (!r.TakePod(addr) || !r.TakePod(size) || !r.TakePod(protect)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    uint32_t old = 0;
    const HdlStatus st = ProtectMemory(addr, static_cast<size_t>(size), protect, &old);
    AppendPod(resp, static_cast<int32_t>(st));
    AppendPod(resp, old);
    return WriteFrame(pipe, resp);
}

bool HandleFlushICache(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t addr = 0;
    uint64_t size = 0;
    if (!r.TakePod(addr) || !r.TakePod(size)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    AppendPod(resp, static_cast<int32_t>(FlushICache(addr, static_cast<size_t>(size))));
    return WriteFrame(pipe, resp);
}

}  // namespace ipc
}  // namespace hdl
