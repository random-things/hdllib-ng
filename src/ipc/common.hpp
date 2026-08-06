#pragma once

#include "jobs.hpp"
#include "rpc/status.hpp"

#include "hdllib/hdllib.h"

#include <algorithm>
#include <cstdint>
#include <memory>
#include <mutex>
#include <vector>

namespace hdl::ipc {

struct SearchSessionHolder {
    std::mutex mu;
    HdlSearchSession* session = nullptr;
};

struct DiscoverSessionHolder {
    std::mutex mu;
    HdlDiscoverSession* session = nullptr;
};

class RequestJobScope {
  public:
    explicit RequestJobScope(std::shared_ptr<Job> job);
    ~RequestJobScope();
    RequestJobScope(const RequestJobScope&) = delete;
    RequestJobScope& operator=(const RequestJobScope&) = delete;

  private:
    std::shared_ptr<Job> previous_;
};

std::shared_ptr<Job> CurrentRequestJob();

std::shared_ptr<SearchSessionHolder> FindSession(uint64_t id);
std::shared_ptr<DiscoverSessionHolder> FindDiscover(uint64_t id);

uint64_t AllocSearchSession(HdlSearchSession* session);
std::shared_ptr<SearchSessionHolder> TakeSearchSession(uint64_t id);
void CloseAllSessions();

uint64_t AllocDiscoverSession(HdlDiscoverSession* session);
std::shared_ptr<DiscoverSessionHolder> TakeDiscoverSession(uint64_t id);
void CloseAllDiscoverSessions();

template <typename T>
HdlStatus EnumerateAll(HdlStatus (*enumerate)(T*, uint32_t*), std::vector<T>* values) {
    values->clear();
    uint32_t required = 0;
    HdlStatus status = enumerate(nullptr, &required);
    if (status != HDL_OK && status != HDL_E_BUFFER_SMALL) {
        return status;
    }
    constexpr uint32_t kGrowthSlack = 64;
    constexpr int kMaxAttempts = 4;
    for (int attempt = 0; attempt < kMaxAttempts; ++attempt) {
        if (!required) {
            return HDL_OK;
        }
        const uint32_t capacity =
            required <= UINT32_MAX - kGrowthSlack ? required + kGrowthSlack : required;
        values->resize(capacity);
        uint32_t count = capacity;
        status = enumerate(values->data(), &count);
        if (status == HDL_OK) {
            values->resize(count);
            return HDL_OK;
        }
        values->clear();
        if (status != HDL_E_BUFFER_SMALL) {
            return status;
        }
        required = count;
    }
    return HDL_E_BUFFER_SMALL;
}

template <typename Domain, typename Response, typename Add>
rpc::Status WriteBatches(HdlStatus status, const std::vector<Domain>& values, size_t chunk_size,
                         rpc::ServerWriter<Response>& writer, Add add) {
    if (status != HDL_OK) {
        return rpc::Status::FromHdl(status);
    }
    for (size_t offset = 0; offset < values.size(); offset += chunk_size) {
        Response response;
        const size_t end = (std::min)(values.size(), offset + chunk_size);
        for (size_t index = offset; index < end; ++index) {
            if (!add(values[index], &response)) {
                return rpc::Status::FromHdl(HDL_E_FAILED, "Domain value conversion failed");
            }
        }
        if (!writer.Write(response)) {
            return rpc::Status::FromHdl(HDL_E_CANCELLED, "Stream write failed");
        }
    }
    return rpc::Status::Ok();
}

} // namespace hdl::ipc
