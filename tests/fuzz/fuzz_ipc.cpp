#include "hdl/rpc/v1/envelope.pb.h"
#include "hdl/rpc/v1/services.rpc.hpp"

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size > 64u * 1024u * 1024u)
        return 0;
    hdl::rpc::v1::Envelope envelope;
    if (!envelope.ParseFromArray(data, static_cast<int>(size)) || !envelope.has_request())
        return 0;
    hdl::rpc::Method method{};
    if (!hdl::rpc::ParseMethod(envelope.request().method(), &method))
        return 0;
    (void)hdl::rpc::ValidateRequestPayload(method, envelope.request().payload());
    return 0;
}
