#include "handlers.hpp"

#include "common.hpp"
#include "convert.hpp"

#include "alloc.hpp"
#include "place.hpp"

#include <thread>
#include <vector>

namespace hdl::ipc {

rpc::Status HandleMemory_FindCaves(rpc::CallContext&, const rpc::v1::FindCavesRequest& request,
                                   rpc::ServerWriter<rpc::v1::FindCavesResponse>& writer) {
    std::wstring module;
    if (!Utf8ToWide(request.scope().module(), &module)) {
        return rpc::Status::FromHdl(HDL_E_INVALID_ARG);
    }
    HdlCaveQuery query{};
    query.min_size = request.min_size();
    query.fill_byte = request.fill_byte();
    query.search_flags = request.scope().flags();
    query.max_results = request.max_results();
    query.near_addr = request.near_address();
    query.max_distance = request.max_distance();
    query.module_or_null = module.empty() ? nullptr : module.c_str();

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

    uint32_t count = 0;
    HdlStatus status = FindCaves(&query, nullptr, &count, &cancel);
    std::vector<HdlCaveInfo> caves;
    if (status == HDL_E_BUFFER_SMALL && count) {
        caves.resize(count);
        status = FindCaves(&query, caves.data(), &count, &cancel);
        caves.resize(status == HDL_OK ? count : 0);
    } else if (status == HDL_OK) {
        count = 0;
    }
    if (watcher.joinable()) {
        cancel = 1;
        watcher.join();
    }
    if (job) {
        const HdlStatus cancellation = JobCheck(job);
        if (cancellation != HDL_OK && status == HDL_OK) {
            status = cancellation;
        }
    }
    return WriteBatches(status, caves, 64, writer,
                        [](const HdlCaveInfo& value, rpc::v1::FindCavesResponse* batch) {
                            ToProto(value, batch->add_caves());
                            return true;
                        });
}

rpc::Status HandleMemory_AllocNear(rpc::CallContext&, const rpc::v1::AllocNearRequest& request,
                                   rpc::v1::AllocNearResponse* response) {
    uint64_t address = 0;
    const HdlStatus status =
        AllocNear(request.near_address(), request.max_distance(),
                  static_cast<size_t>(request.size()), request.protection(), &address);
    response->set_address(address);
    return rpc::Status::FromHdl(status);
}

rpc::Status HandleMemory_ProtectMemory(rpc::CallContext&,
                                       const rpc::v1::ProtectMemoryRequest& request,
                                       rpc::v1::ProtectMemoryResponse* response) {
    uint32_t old_protection = 0;
    const HdlStatus status = ProtectMemory(request.address(), static_cast<size_t>(request.size()),
                                           request.protection(), &old_protection);
    response->set_old_protection(old_protection);
    return rpc::Status::FromHdl(status);
}

rpc::Status HandleMemory_FlushICache(rpc::CallContext&, const rpc::v1::FlushICacheRequest& request,
                                     rpc::v1::Empty*) {
    return rpc::Status::FromHdl(
        FlushICache(request.address(), static_cast<size_t>(request.size())));
}

} // namespace hdl::ipc
