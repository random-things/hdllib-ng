#include "dispatch.hpp"
#include "common.hpp"
#include "handlers.hpp"
#include "protocol.hpp"
#include "rpc/runtime.hpp"

#include <vector>

namespace hdl {
namespace ipc {

bool HandleRequest(HANDLE pipe, const std::vector<uint8_t>& req) {
    ::hdl::rpc::v1::Envelope envelope;
    if (!rpc::ParseEnvelope(req.data(), req.size(), &envelope) || !envelope.has_request()) {
        return false;
    }
    const auto& request = envelope.request();
    if (request.request_id() == 0) {
        return false;
    }

    rpc::Method method{};
    if (!rpc::ParseMethod(request.method(), &method)) {
        return rpc::WriteErrorResponse(pipe, request.request_id(), rpc::v1::RPC_CODE_UNIMPLEMENTED,
                                       HDL_E_NOT_FOUND, "METHOD_NOT_FOUND", "Unknown RPC method");
    }
    const bool stream_response = rpc::MethodIsServerStreaming(method) && request.stream_response();
    rpc::ResponseScope scope(request.request_id(), stream_response);
    auto request_job = std::make_shared<Job>();
    request_job->timeout_ms = request.timeout_ms();
    if (request_job->timeout_ms) {
        request_job->deadline_tick = GetTickCount64() + request_job->timeout_ms;
    }
    RequestJobScope job_scope(request_job);

    ::hdl::rpc::v1::Payload payload;
    if (!payload.ParseFromString(request.payload())) {
        return rpc::WriteErrorResponse(
            pipe, request.request_id(), rpc::v1::RPC_CODE_INVALID_ARGUMENT, HDL_E_INVALID_ARG,
            "INVALID_PAYLOAD", "Request payload is not a valid Payload message");
    }
    proto::Reader r(reinterpret_cast<const uint8_t*>(payload.value().data()),
                    payload.value().size());
    switch (method) {
#define HDL_RPC_METHOD(Name)                                                                       \
    case rpc::Method::Name:                                                                        \
        return Handle##Name(pipe, r);
#include "hdl/rpc/v1/services.rpc.dispatch.inc"
#undef HDL_RPC_METHOD
    }

    std::vector<uint8_t> resp;
    proto::AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
    return WriteFrame(pipe, resp);
}

} // namespace ipc
} // namespace hdl
