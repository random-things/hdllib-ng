#pragma once

#include "hdl/rpc/v1/services.rpc.hpp"

#include <cstdint>
#include <vector>

namespace hdl::rpc {

// An in-process request under construction. The method is generated from the
// protobuf service schema; only payload bytes are serialized into the method's
// input message.
struct PreparedRequest {
    Method method{};
    bool has_method = false;
    uint32_t timeout_ms = 0;
    std::vector<uint8_t> payload;

    void clear() {
        has_method = false;
        timeout_ms = 0;
        payload.clear();
    }
};

inline void SetMethod(PreparedRequest& request, Method method) {
    request.method = method;
    request.has_method = true;
}

} // namespace hdl::rpc
