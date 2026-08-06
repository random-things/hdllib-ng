#include "rpc/pipe_client.hpp"

#include "hdllib/types.h"
#include "rpc/pipe_io.hpp"
#include "rpc/runtime.hpp"

#include "hdl/rpc/v1/envelope.pb.h"

#include <algorithm>
#include <vector>

namespace {

hdl::rpc::PipeIoResult ReadFrame(HANDLE pipe, HANDLE completion_port, uint32_t maximum,
                                 std::vector<uint8_t>* frame,
                                 const hdl::rpc::PipeDeadline& deadline) {
    uint32_t size = 0;
    if (!frame) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return hdl::rpc::PipeIoResult::Error;
    }
    hdl::rpc::PipeIoResult result =
        hdl::rpc::ReadPipeExact(pipe, completion_port, &size, sizeof(size), deadline);
    if (result != hdl::rpc::PipeIoResult::Ok) {
        return result;
    }
    if (size > maximum) {
        SetLastError(ERROR_INVALID_DATA);
        return hdl::rpc::PipeIoResult::Error;
    }
    frame->resize(size);
    return size ? hdl::rpc::ReadPipeExact(pipe, completion_port, frame->data(), size, deadline)
                : hdl::rpc::PipeIoResult::Ok;
}

hdl::rpc::PipeIoResult WriteFrame(HANDLE pipe, HANDLE completion_port, uint32_t maximum,
                                  const hdl::rpc::v1::Envelope& envelope,
                                  const hdl::rpc::PipeDeadline& deadline) {
    if (envelope.ByteSizeLong() > maximum) {
        SetLastError(ERROR_BUFFER_OVERFLOW);
        return hdl::rpc::PipeIoResult::Error;
    }
    std::vector<uint8_t> bytes;
    if (!hdl::rpc::SerializeEnvelope(envelope, &bytes) || bytes.size() > maximum) {
        SetLastError(ERROR_INVALID_DATA);
        return hdl::rpc::PipeIoResult::Error;
    }
    const uint32_t size = static_cast<uint32_t>(bytes.size());
    hdl::rpc::PipeIoResult result =
        hdl::rpc::WritePipeExact(pipe, completion_port, &size, sizeof(size), deadline);
    if (result != hdl::rpc::PipeIoResult::Ok || !size) {
        return result;
    }
    return hdl::rpc::WritePipeExact(pipe, completion_port, bytes.data(), size, deadline);
}

hdl::rpc::Status TransportFailure(std::string_view reason, std::string_view message = {}) {
    return hdl::rpc::Status::Transport(hdl::rpc::v1::RPC_CODE_UNAVAILABLE, reason, message);
}

hdl::rpc::Status IoFailure(hdl::rpc::PipeIoResult result, std::string_view reason) {
    if (result == hdl::rpc::PipeIoResult::Timeout) {
        return hdl::rpc::Status::FromHdl(HDL_E_TIMEOUT, "Named-pipe I/O timed out");
    }
    return TransportFailure(reason);
}

} // namespace

PipeClient::PipeClient(uint32_t pid, std::string client_name, std::string client_build)
    : pid_(pid), client_name_(std::move(client_name)), client_build_(std::move(client_build)) {}

PipeClient::~PipeClient() {
    Close();
}

bool PipeClient::Connect(DWORD timeout_ms) {
    std::lock_guard<std::mutex> lock(request_mutex_);
    CloseUnlocked();
    negotiate_error_.clear();
    const hdl::rpc::PipeDeadline deadline(timeout_ms);
    HANDLE pipe = INVALID_HANDLE_VALUE;
    HANDLE completion_port = nullptr;
    const hdl::rpc::PipeIoResult connected =
        hdl::rpc::ConnectLocalPipe(pid_, deadline, &pipe, &completion_port);
    if (connected != hdl::rpc::PipeIoResult::Ok) {
        negotiate_error_ = connected == hdl::rpc::PipeIoResult::Timeout
                               ? "RPC connection deadline exceeded"
                               : "RPC pipe connection failed";
        return false;
    }
    handle_ = pipe;
    completion_port_ = completion_port;
    const hdl::rpc::PipeIoResult preface =
        hdl::rpc::WritePipeExact(pipe, completion_port, hdl::rpc::kConnectionPreface,
                                 static_cast<DWORD>(hdl::rpc::kConnectionPrefaceSize), deadline);
    if (preface != hdl::rpc::PipeIoResult::Ok) {
        negotiate_error_ = preface == hdl::rpc::PipeIoResult::Timeout
                               ? "RPC preface deadline exceeded"
                               : "RPC preface failed (transport)";
        CloseUnlocked();
        return false;
    }
    if (!Negotiate(deadline)) {
        const std::string error = negotiate_error_;
        CloseUnlocked();
        negotiate_error_ = error;
        return false;
    }
    return true;
}

void PipeClient::Close() {
    std::lock_guard<std::mutex> lock(request_mutex_);
    CloseUnlocked();
}

void PipeClient::CloseUnlocked() {
    if (handle_) {
        CloseHandle(static_cast<HANDLE>(handle_));
        handle_ = nullptr;
    }
    if (completion_port_) {
        CloseHandle(static_cast<HANDLE>(completion_port_));
        completion_port_ = nullptr;
    }
    proto_major_ = 0;
    proto_minor_ = 0;
    max_frame_bytes_ = 0;
    next_request_id_ = 1;
    methods_.clear();
}

bool PipeClient::Negotiate(const hdl::rpc::PipeDeadline& deadline) {
    hdl::rpc::v1::Envelope envelope;
    auto* hello = envelope.mutable_client_hello();
    hello->set_protocol_major(hdl::rpc::kProtocolMajor);
    hello->set_protocol_minor(hdl::rpc::kProtocolMinor);
    hello->set_client_name(client_name_);
    hello->set_client_build(client_build_);
    HANDLE pipe = static_cast<HANDLE>(handle_);
    HANDLE completion_port = static_cast<HANDLE>(completion_port_);
    const hdl::rpc::PipeIoResult write =
        WriteFrame(pipe, completion_port, hdl::rpc::kMaxFrameBytes, envelope, deadline);
    if (write != hdl::rpc::PipeIoResult::Ok) {
        negotiate_error_ = write == hdl::rpc::PipeIoResult::Timeout
                               ? "ClientHello deadline exceeded"
                               : "ClientHello failed (transport)";
        return false;
    }
    std::vector<uint8_t> bytes;
    hdl::rpc::v1::Envelope response;
    const hdl::rpc::PipeIoResult read =
        ReadFrame(pipe, completion_port, hdl::rpc::kMaxFrameBytes, &bytes, deadline);
    if (read != hdl::rpc::PipeIoResult::Ok) {
        negotiate_error_ = read == hdl::rpc::PipeIoResult::Timeout
                               ? "ServerHello deadline exceeded"
                               : "ServerHello response failed (transport)";
        return false;
    }
    if (!hdl::rpc::ParseEnvelope(bytes.data(), bytes.size(), &response) ||
        !response.has_server_hello()) {
        negotiate_error_ = "ServerHello response malformed";
        return false;
    }
    const auto& server = response.server_hello();
    if (server.protocol_major() != hdl::rpc::kProtocolMajor) {
        negotiate_error_ =
            "RPC protocol major mismatch (DLL=" + std::to_string(server.protocol_major()) +
            " client=" + std::to_string(hdl::rpc::kProtocolMajor) + ")";
        return false;
    }
    if (!server.has_limits() || !server.limits().max_frame_bytes() ||
        server.limits().max_in_flight() != 1) {
        negotiate_error_ = "ServerHello transport limits unsupported";
        return false;
    }
    proto_major_ = server.protocol_major();
    proto_minor_ = server.protocol_minor();
    max_frame_bytes_ = (std::min)(server.limits().max_frame_bytes(), hdl::rpc::kMaxFrameBytes);
    for (const auto& method : server.methods())
        methods_[method.name()] = method.server_streaming();
    return true;
}

bool PipeClient::MethodAvailable(std::string_view method, bool streaming) const {
    const auto found = methods_.find(std::string(method));
    return found != methods_.end() && found->second == streaming;
}

hdl::rpc::RawUnaryResult PipeClient::Unary(std::string_view method,
                                           const google::protobuf::MessageLite& request,
                                           google::protobuf::MessageLite* response,
                                           hdl::rpc::CallOptions options) {
    std::lock_guard<std::mutex> lock(request_mutex_);
    hdl::rpc::RawUnaryResult result;
    if (!handle_ || !response || !MethodAvailable(method, false)) {
        result.status = TransportFailure("METHOD_UNAVAILABLE");
        return result;
    }
    const uint64_t request_id = next_request_id_++;
    const hdl::rpc::PipeDeadline deadline(options.timeout_ms);
    hdl::rpc::v1::Envelope envelope;
    auto* rpc_request = envelope.mutable_request();
    rpc_request->set_request_id(request_id);
    rpc_request->set_method(method.data(), method.size());
    rpc_request->set_timeout_ms(options.timeout_ms);
    if (request.ByteSizeLong() > max_frame_bytes_ ||
        !request.SerializeToString(rpc_request->mutable_payload())) {
        result.status = TransportFailure("WRITE_FAILED");
        CloseUnlocked();
        return result;
    }
    const hdl::rpc::PipeIoResult write =
        WriteFrame(static_cast<HANDLE>(handle_), static_cast<HANDLE>(completion_port_),
                   max_frame_bytes_, envelope, deadline);
    if (write != hdl::rpc::PipeIoResult::Ok) {
        result.status = IoFailure(write, "WRITE_FAILED");
        result.status.set_outcome_unknown(true);
        CloseUnlocked();
        return result;
    }
    std::vector<uint8_t> bytes;
    hdl::rpc::v1::Envelope reply;
    const hdl::rpc::PipeIoResult read =
        ReadFrame(static_cast<HANDLE>(handle_), static_cast<HANDLE>(completion_port_),
                  max_frame_bytes_, &bytes, deadline);
    if (read != hdl::rpc::PipeIoResult::Ok) {
        result.status = IoFailure(read, "READ_FAILED");
        result.status.set_outcome_unknown(true);
        CloseUnlocked();
        return result;
    }
    if (!hdl::rpc::ParseEnvelope(bytes.data(), bytes.size(), &reply) || !reply.has_response() ||
        reply.response().request_id() != request_id || reply.response().sequence() != 0 ||
        !reply.response().end_stream() || !reply.response().has_status()) {
        result.status = TransportFailure("INVALID_RESPONSE");
        CloseUnlocked();
        return result;
    }
    const auto& rpc_response = reply.response();
    result.status = hdl::rpc::Status(rpc_response.status());
    if (rpc_response.has_payload()) {
        if (!response->ParseFromString(rpc_response.payload())) {
            result.status = TransportFailure("INVALID_RESPONSE_PAYLOAD");
            CloseUnlocked();
            return result;
        }
        result.has_response = true;
    }
    return result;
}

hdl::rpc::Status PipeClient::ServerStream(
    std::string_view method, const google::protobuf::MessageLite& request,
    google::protobuf::MessageLite* response,
    const std::function<bool(const google::protobuf::MessageLite&)>& on_message,
    hdl::rpc::CallOptions options) {
    std::lock_guard<std::mutex> lock(request_mutex_);
    if (!handle_ || !response || !on_message || !MethodAvailable(method, true)) {
        return TransportFailure("METHOD_UNAVAILABLE");
    }
    const uint64_t request_id = next_request_id_++;
    const hdl::rpc::PipeDeadline deadline(options.timeout_ms);
    hdl::rpc::v1::Envelope envelope;
    auto* rpc_request = envelope.mutable_request();
    rpc_request->set_request_id(request_id);
    rpc_request->set_method(method.data(), method.size());
    rpc_request->set_timeout_ms(options.timeout_ms);
    if (request.ByteSizeLong() > max_frame_bytes_ ||
        !request.SerializeToString(rpc_request->mutable_payload())) {
        CloseUnlocked();
        return TransportFailure("WRITE_FAILED");
    }
    const hdl::rpc::PipeIoResult write =
        WriteFrame(static_cast<HANDLE>(handle_), static_cast<HANDLE>(completion_port_),
                   max_frame_bytes_, envelope, deadline);
    if (write != hdl::rpc::PipeIoResult::Ok) {
        hdl::rpc::Status status = IoFailure(write, "WRITE_FAILED");
        status.set_outcome_unknown(true);
        CloseUnlocked();
        return status;
    }
    uint32_t expected_sequence = 0;
    for (;;) {
        std::vector<uint8_t> bytes;
        hdl::rpc::v1::Envelope reply;
        const hdl::rpc::PipeIoResult read =
            ReadFrame(static_cast<HANDLE>(handle_), static_cast<HANDLE>(completion_port_),
                      max_frame_bytes_, &bytes, deadline);
        if (read != hdl::rpc::PipeIoResult::Ok) {
            hdl::rpc::Status status = IoFailure(read, "READ_FAILED");
            status.set_outcome_unknown(true);
            CloseUnlocked();
            return status;
        }
        if (!hdl::rpc::ParseEnvelope(bytes.data(), bytes.size(), &reply) || !reply.has_response() ||
            reply.response().request_id() != request_id ||
            reply.response().sequence() != expected_sequence++ || !reply.response().has_status()) {
            CloseUnlocked();
            return TransportFailure("INVALID_STREAM_RESPONSE");
        }
        const auto& rpc_response = reply.response();
        if (rpc_response.end_stream()) {
            if (rpc_response.has_payload()) {
                CloseUnlocked();
                return TransportFailure("TERMINAL_PAYLOAD");
            }
            return hdl::rpc::Status(rpc_response.status());
        }
        if (rpc_response.status().code() != hdl::rpc::v1::RPC_CODE_OK ||
            !rpc_response.has_payload() || !response->ParseFromString(rpc_response.payload())) {
            CloseUnlocked();
            return TransportFailure("INVALID_STREAM_PAYLOAD");
        }
        if (!on_message(*response)) {
            CloseUnlocked();
            return hdl::rpc::Status::FromHdl(HDL_E_CANCELLED, "Stream callback stopped");
        }
        response->Clear();
    }
}
