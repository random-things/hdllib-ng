#include "dispatch.hpp"

#include "common.hpp"
#include "handlers.hpp"
#include "ipc/framing.hpp"
#include "rpc/runtime.hpp"

#include <memory>
#include <string>
#include <vector>

namespace hdl::ipc {
namespace {

bool WriteEnvelope(HANDLE pipe, const ::hdl::rpc::v1::Envelope& envelope) {
    if (envelope.ByteSizeLong() > rpc::kMaxFrameBytes)
        return false;
    std::vector<uint8_t> bytes;
    return rpc::SerializeEnvelope(envelope, &bytes) && bytes.size() <= rpc::kMaxFrameBytes &&
           WriteFrameBytes(pipe, bytes.data(), static_cast<uint32_t>(bytes.size()));
}

bool WriteUnary(HANDLE pipe, uint64_t request_id, const rpc::Status& status,
                const google::protobuf::MessageLite& message) {
    ::hdl::rpc::v1::Envelope envelope;
    auto* response = envelope.mutable_response();
    response->set_request_id(request_id);
    response->set_sequence(0);
    response->set_end_stream(true);
    *response->mutable_status() = status.proto();
    if (message.ByteSizeLong() > rpc::kMaxFrameBytes ||
        !message.SerializeToString(response->mutable_payload())) {
        return false;
    }
    return WriteEnvelope(pipe, envelope);
}

class StreamResponseSink final : public rpc::ServerWriterBase {
  public:
    StreamResponseSink(HANDLE pipe, uint64_t request_id, rpc::CallContext* context)
        : pipe_(pipe), request_id_(request_id), context_(context) {}

    bool WriteMessage(const google::protobuf::MessageLite& message) override {
        if (failed_ || message.ByteSizeLong() > rpc::kMaxStreamChunkBytes) {
            Fail();
            return false;
        }
        ::hdl::rpc::v1::Envelope envelope;
        auto* response = envelope.mutable_response();
        response->set_request_id(request_id_);
        response->set_sequence(sequence_++);
        response->set_end_stream(false);
        rpc::SetRpcStatus(HDL_OK, response->mutable_status());
        if (!message.SerializeToString(response->mutable_payload()) ||
            !WriteEnvelope(pipe_, envelope)) {
            Fail();
            return false;
        }
        return true;
    }

    bool Finish(const rpc::Status& status) override {
        if (failed_) {
            return false;
        }
        ::hdl::rpc::v1::Envelope envelope;
        auto* response = envelope.mutable_response();
        response->set_request_id(request_id_);
        response->set_sequence(sequence_);
        response->set_end_stream(true);
        *response->mutable_status() = status.proto();
        if (!WriteEnvelope(pipe_, envelope)) {
            Fail();
            return false;
        }
        return true;
    }

  private:
    void Fail() {
        failed_ = true;
        if (context_) {
            context_->Cancel();
        }
    }

    HANDLE pipe_ = nullptr;
    uint64_t request_id_ = 0;
    rpc::CallContext* context_ = nullptr;
    uint32_t sequence_ = 0;
    bool failed_ = false;
};

template <typename Request>
bool ParseTypedRequest(const ::hdl::rpc::v1::Request& envelope_request, Request* request) {
    return request && envelope_request.has_payload() &&
           request->ParseFromString(envelope_request.payload());
}

} // namespace

bool HandleRequest(HANDLE pipe, const std::vector<uint8_t>& bytes) {
    ::hdl::rpc::v1::Envelope envelope;
    if (!rpc::ParseEnvelope(bytes.data(), bytes.size(), &envelope) || !envelope.has_request()) {
        (void)rpc::WriteGoAway(pipe, rpc::v1::RPC_CODE_DATA_LOSS, HDL_E_FAILED, "INVALID_ENVELOPE",
                               "Expected a protobuf Request envelope");
        return false;
    }
    const auto& request = envelope.request();
    if (request.request_id() == 0) {
        (void)rpc::WriteGoAway(pipe, rpc::v1::RPC_CODE_INVALID_ARGUMENT, HDL_E_INVALID_ARG,
                               "INVALID_REQUEST_ID", "Request ID zero is reserved");
        return false;
    }

    rpc::Method method{};
    if (!rpc::ParseMethod(request.method(), &method)) {
        return rpc::WriteErrorResponse(pipe, request.request_id(), rpc::v1::RPC_CODE_UNIMPLEMENTED,
                                       HDL_E_NOT_FOUND, "METHOD_NOT_FOUND", "Unknown RPC method");
    }

    auto request_job = std::make_shared<Job>();
    request_job->timeout_ms = request.timeout_ms();
    if (request_job->timeout_ms) {
        request_job->deadline_tick = GetTickCount64() + request_job->timeout_ms;
    }
    RequestJobScope job_scope(request_job);
    rpc::CallContext context(request.request_id(), request.timeout_ms());

    switch (method) {
#define HDL_RPC_UNARY(MethodName, Name, RequestType, ResponseType)                                 \
    case rpc::Method::MethodName: {                                                                \
        RequestType typed_request;                                                                 \
        if (!ParseTypedRequest(request, &typed_request)) {                                         \
            return rpc::WriteErrorResponse(                                                        \
                pipe, request.request_id(), rpc::v1::RPC_CODE_INVALID_ARGUMENT, HDL_E_INVALID_ARG, \
                "INVALID_PAYLOAD", "Request payload does not match the method input type");        \
        }                                                                                          \
        ResponseType typed_response;                                                               \
        const rpc::Status status = Handle##Name(context, typed_request, &typed_response);          \
        bool wrote = WriteUnary(pipe, request.request_id(), status, typed_response);               \
        if (wrote)                                                                                 \
            wrote = FlushFileBuffers(pipe) != FALSE;                                               \
        if (wrote) {                                                                               \
            context.RunAfterReply();                                                               \
        }                                                                                          \
        return wrote;                                                                              \
    }
#define HDL_RPC_STREAM(MethodName, Name, RequestType, ResponseType)                                \
    case rpc::Method::MethodName: {                                                                \
        RequestType typed_request;                                                                 \
        if (!ParseTypedRequest(request, &typed_request)) {                                         \
            return rpc::WriteErrorResponse(                                                        \
                pipe, request.request_id(), rpc::v1::RPC_CODE_INVALID_ARGUMENT, HDL_E_INVALID_ARG, \
                "INVALID_PAYLOAD", "Request payload does not match the method input type");        \
        }                                                                                          \
        StreamResponseSink sink(pipe, request.request_id(), &context);                             \
        rpc::ServerWriter<ResponseType> writer(&sink);                                             \
        const rpc::Status status = Handle##Name(context, typed_request, writer);                   \
        bool wrote = writer.Finish(status);                                                        \
        if (wrote)                                                                                 \
            wrote = FlushFileBuffers(pipe) != FALSE;                                               \
        if (wrote) {                                                                               \
            context.RunAfterReply();                                                               \
        }                                                                                          \
        return wrote;                                                                              \
    }
#include "hdl/rpc/v1/services.rpc.dispatch.inc"
#undef HDL_RPC_STREAM
#undef HDL_RPC_UNARY
    }

    return rpc::WriteErrorResponse(pipe, request.request_id(), rpc::v1::RPC_CODE_UNIMPLEMENTED,
                                   HDL_E_NOT_FOUND, "METHOD_NOT_FOUND", "Unknown RPC method");
}

} // namespace hdl::ipc
