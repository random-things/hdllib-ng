#include "pipe_client.hpp"
#include "hdllib/hdllib.h"
#include "hdllib/pipe_name.h"
#include "protocol.hpp"
#include "rpc/runtime.hpp"

#include "hdl/rpc/v1/envelope.pb.h"
#include "hdl/rpc/v1/services.rpc.hpp"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <cstdio>
#include <cstring>

namespace {

bool ReadExact(HANDLE pipe, void* buf, DWORD size) {
    uint8_t* p = static_cast<uint8_t*>(buf);
    DWORD remaining = size;
    while (remaining) {
        DWORD got = 0;
        if (!ReadFile(pipe, p, remaining, &got, nullptr) || got == 0) {
            return false;
        }
        p += got;
        remaining -= got;
    }
    return true;
}

bool WriteExact(HANDLE pipe, const void* buf, DWORD size) {
    const uint8_t* p = static_cast<const uint8_t*>(buf);
    DWORD remaining = size;
    while (remaining) {
        DWORD wrote = 0;
        if (!WriteFile(pipe, p, remaining, &wrote, nullptr) || wrote == 0) {
            return false;
        }
        p += wrote;
        remaining -= wrote;
    }
    return true;
}

bool ReadFrame(HANDLE pipe, std::vector<uint8_t>& resp) {
    uint32_t rsize = 0;
    if (!ReadExact(pipe, &rsize, sizeof(rsize))) {
        return false;
    }
    resp.resize(rsize);
    if (rsize && !ReadExact(pipe, resp.data(), rsize)) {
        return false;
    }
    return true;
}

bool MakeRequestEnvelope(const hdl::rpc::PreparedRequest& prepared, uint64_t request_id,
                         bool stream_response, hdl::rpc::v1::Envelope* envelope) {
    if (!envelope || !prepared.has_method) {
        return false;
    }
    auto* request = envelope->mutable_request();
    request->set_request_id(request_id);
    const std::string_view method_name = hdl::rpc::MethodName(prepared.method);
    if (method_name.empty()) {
        return false;
    }
    request->set_method(method_name.data(), method_name.size());
    request->set_timeout_ms(prepared.timeout_ms);
    request->set_stream_response(stream_response);
    hdl::rpc::v1::Payload payload;
    payload.set_value(prepared.payload.data(), prepared.payload.size());
    if (!payload.SerializeToString(request->mutable_payload())) {
        return false;
    }
    return true;
}

bool ReadRpcResponse(HANDLE pipe, uint64_t request_id, hdl::rpc::v1::Response* out) {
    std::vector<uint8_t> frame;
    hdl::rpc::v1::Envelope envelope;
    if (!out || !ReadFrame(pipe, frame) ||
        !hdl::rpc::ParseEnvelope(frame.data(), frame.size(), &envelope) ||
        !envelope.has_response() || envelope.response().request_id() != request_id) {
        return false;
    }
    *out = std::move(*envelope.mutable_response());
    return true;
}

bool UnpackResponse(const hdl::rpc::v1::Response& response, std::vector<uint8_t>* out) {
    hdl::rpc::v1::Payload payload;
    if (!out || !payload.ParseFromString(response.payload())) {
        return false;
    }
    out->assign(payload.value().begin(), payload.value().end());
    return true;
}

} // namespace

PipeClient::PipeClient(uint32_t pid) : pid_(pid) {}

PipeClient::~PipeClient() {
    Close();
}

bool PipeClient::Connect(DWORD timeout_ms) {
    Close();
    negotiate_error_.clear();
    const DWORD start = GetTickCount();
    for (;;) {
        HANDLE h = HdlOpenLocalPipe(pid_);
        if (h != INVALID_HANDLE_VALUE) {
            DWORD mode = PIPE_READMODE_BYTE | PIPE_WAIT;
            SetNamedPipeHandleState(h, &mode, nullptr, nullptr);
            handle_ = h;
            if (!WriteExact(h, hdl::rpc::kConnectionPreface,
                            static_cast<DWORD>(hdl::rpc::kConnectionPrefaceSize))) {
                negotiate_error_ = "RPC preface failed (transport)";
                Close();
                return false;
            }
            if (!Negotiate()) {
                /* Preserve negotiate_error_ set by Negotiate(); do not call Close(). */
                if (handle_) {
                    CloseHandle(static_cast<HANDLE>(handle_));
                    handle_ = nullptr;
                }
                proto_major_ = 0;
                proto_minor_ = 0;
                next_request_id_ = 0;
                return false;
            }
            return true;
        }
        if (GetLastError() != ERROR_PIPE_BUSY && GetLastError() != ERROR_FILE_NOT_FOUND) {
            return false;
        }
        if (GetTickCount() - start > timeout_ms) {
            return false;
        }
        HdlWaitLocalPipe(pid_, 200);
        Sleep(50);
    }
}

void PipeClient::Close() {
    if (handle_) {
        CloseHandle(static_cast<HANDLE>(handle_));
        handle_ = nullptr;
    }
    proto_major_ = 0;
    proto_minor_ = 0;
    next_request_id_ = 1;
}

bool PipeClient::Negotiate() {
    negotiate_error_.clear();
    hdl::rpc::v1::Envelope envelope;
    auto* hello = envelope.mutable_client_hello();
    hello->set_protocol_major(hdl::rpc::kProtocolMajor);
    hello->set_protocol_minor(hdl::rpc::kProtocolMinor);
    hello->set_client_name("hdlclient");
    hello->set_client_build("0.1.0-pre");
    std::vector<uint8_t> bytes;
    if (!hdl::rpc::SerializeEnvelope(envelope, &bytes)) {
        negotiate_error_ = "ClientHello serialization failed";
        return false;
    }
    HANDLE pipe = static_cast<HANDLE>(handle_);
    const uint32_t size = static_cast<uint32_t>(bytes.size());
    if (!WriteExact(pipe, &size, sizeof(size)) ||
        (size != 0 && !WriteExact(pipe, bytes.data(), size))) {
        negotiate_error_ = "ClientHello failed (transport)";
        return false;
    }
    std::vector<uint8_t> response_bytes;
    hdl::rpc::v1::Envelope response;
    if (!ReadFrame(pipe, response_bytes) ||
        !hdl::rpc::ParseEnvelope(response_bytes.data(), response_bytes.size(), &response) ||
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
    proto_major_ = server.protocol_major();
    proto_minor_ = server.protocol_minor();
    return true;
}

bool PipeClient::Request(const hdl::rpc::PreparedRequest& req, std::vector<uint8_t>& resp) {
    if (!handle_ || !req.has_method) {
        return false;
    }
    HANDLE pipe = static_cast<HANDLE>(handle_);
    const uint64_t request_id = next_request_id_++;
    hdl::rpc::v1::Envelope envelope;
    std::vector<uint8_t> bytes;
    if (!MakeRequestEnvelope(req, request_id, false, &envelope) ||
        !hdl::rpc::SerializeEnvelope(envelope, &bytes)) {
        return false;
    }
    const uint32_t size = static_cast<uint32_t>(bytes.size());
    if (!WriteExact(pipe, &size, sizeof(size))) {
        return false;
    }
    if (size && !WriteExact(pipe, bytes.data(), size)) {
        return false;
    }
    hdl::rpc::v1::Response response;
    if (!ReadRpcResponse(pipe, request_id, &response) || response.sequence() != 0 ||
        !response.end_stream()) {
        return false;
    }
    return UnpackResponse(response, &resp);
}

bool PipeClient::RequestStream(
    const hdl::rpc::PreparedRequest& req,
    const std::function<bool(int32_t, uint32_t, const uint8_t*, size_t)>& on_frame) {
    if (!handle_ || !on_frame || !req.has_method ||
        !hdl::rpc::MethodIsServerStreaming(req.method)) {
        return false;
    }
    HANDLE pipe = static_cast<HANDLE>(handle_);
    const uint64_t request_id = next_request_id_++;
    hdl::rpc::v1::Envelope envelope;
    std::vector<uint8_t> bytes;
    if (!MakeRequestEnvelope(req, request_id, true, &envelope) ||
        !hdl::rpc::SerializeEnvelope(envelope, &bytes)) {
        return false;
    }
    const uint32_t size = static_cast<uint32_t>(bytes.size());
    if (!WriteExact(pipe, &size, sizeof(size))) {
        return false;
    }
    if (size && !WriteExact(pipe, bytes.data(), size)) {
        return false;
    }

    uint32_t expected_sequence = 0;
    for (;;) {
        hdl::rpc::v1::Response response;
        if (!ReadRpcResponse(pipe, request_id, &response) ||
            response.sequence() != expected_sequence++) {
            return false;
        }
        std::vector<uint8_t> resp;
        if (!UnpackResponse(response, &resp)) {
            return false;
        }
        hdl::proto::Reader r(resp);
        int32_t status = 0;
        uint32_t flags = 0;
        if (!r.TakePod(status) || !r.TakePod(flags)) {
            return false;
        }
        if (!on_frame(status, flags, r.p, r.left)) {
            // With max_in_flight=1, closing is the cancellation signal. A
            // streaming handler observes the broken write at its next chunk.
            Close();
            return false;
        }
        if (response.end_stream()) {
            return true;
        }
    }
}
