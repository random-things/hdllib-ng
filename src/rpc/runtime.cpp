#include "rpc/runtime.hpp"

#include "ipc/framing.hpp"

#include "hdllib/hdllib.h"

#include <array>
#include <limits>

#include <bcrypt.h>

#pragma comment(lib, "Bcrypt.lib")

namespace hdl::rpc {
namespace {

struct ServerIdentity {
    std::array<uint8_t, 16> bytes{};
    bool valid = false;
};

const ServerIdentity& GetServerIdentity() {
    static const ServerIdentity identity = [] {
        ServerIdentity value;
        value.valid =
            BCryptGenRandom(nullptr, value.bytes.data(), static_cast<ULONG>(value.bytes.size()),
                            BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0;
        return value;
    }();
    return identity;
}

std::string_view HdlReason(int32_t status) {
    switch (status) {
    case HDL_OK:
        return "OK";
    case HDL_E_INVALID_ARG:
        return "INVALID_ARGUMENT";
    case HDL_E_ACCESS:
        return "ACCESS_DENIED";
    case HDL_E_NOT_FOUND:
        return "NOT_FOUND";
    case HDL_E_NO_MEM:
        return "RESOURCE_EXHAUSTED";
    case HDL_E_BUSY:
        return "BUSY";
    case HDL_E_CANCELLED:
        return "CANCELLED";
    case HDL_E_NOT_INIT:
        return "NOT_INITIALIZED";
    case HDL_E_TIMEOUT:
        return "DEADLINE_EXCEEDED";
    case HDL_E_BUFFER_SMALL:
        return "BUFFER_TOO_SMALL";
    default:
        return "INTERNAL";
    }
}

} // namespace

Status Status::Ok() {
    return FromHdl(HDL_OK);
}

Status Status::FromHdl(int32_t hdl_status, std::string_view message) {
    ::hdl::rpc::v1::RpcStatus value;
    SetRpcStatus(hdl_status, &value);
    value.set_message(message.data(), message.size());
    return Status(std::move(value));
}

Status Status::Transport(::hdl::rpc::v1::RpcCode code, std::string_view reason,
                         std::string_view message) {
    ::hdl::rpc::v1::RpcStatus value;
    value.set_code(code);
    value.set_hdl_status(::hdl::rpc::v1::HDL_STATUS_FAILED);
    value.set_reason(reason.data(), reason.size());
    value.set_message(message.data(), message.size());
    return Status(std::move(value));
}

CallContext::CallContext(uint64_t request_id, uint32_t timeout_ms)
    : request_id_(request_id), timeout_ms_(timeout_ms),
      deadline_tick_(timeout_ms ? GetTickCount64() + timeout_ms : 0) {}

uint32_t CallContext::remaining_timeout_ms() const {
    if (!deadline_tick_) {
        return 0;
    }
    const uint64_t now = GetTickCount64();
    if (now >= deadline_tick_) {
        return 1;
    }
    const uint64_t remaining = deadline_tick_ - now;
    return remaining > (std::numeric_limits<uint32_t>::max)()
               ? (std::numeric_limits<uint32_t>::max)()
               : static_cast<uint32_t>(remaining);
}

bool CallContext::deadline_exceeded() const {
    return deadline_tick_ && GetTickCount64() >= deadline_tick_;
}

void CallContext::DeferAfterReply(std::function<void()> action) {
    after_reply_ = std::move(action);
}

void CallContext::RunAfterReply() {
    if (after_reply_) {
        auto action = std::move(after_reply_);
        action();
    }
}

bool SerializeEnvelope(const ::hdl::rpc::v1::Envelope& envelope, std::vector<uint8_t>* out) {
    if (!out || envelope.ByteSizeLong() > kMaxFrameBytes) {
        return false;
    }
    out->resize(envelope.ByteSizeLong());
    return envelope.SerializeToArray(out->data(), static_cast<int>(out->size()));
}

bool ParseEnvelope(const uint8_t* data, size_t size, ::hdl::rpc::v1::Envelope* out) {
    if (!out || (!data && size != 0) || size > kMaxFrameBytes) {
        return false;
    }
    out->Clear();
    return out->ParseFromArray(data, static_cast<int>(size));
}

::hdl::rpc::v1::RpcCode MapHdlStatus(int32_t status) {
    using ::hdl::rpc::v1::RpcCode;
    switch (status) {
    case HDL_OK:
        return RpcCode::RPC_CODE_OK;
    case HDL_E_INVALID_ARG:
        return RpcCode::RPC_CODE_INVALID_ARGUMENT;
    case HDL_E_ACCESS:
        return RpcCode::RPC_CODE_PERMISSION_DENIED;
    case HDL_E_NOT_FOUND:
        return RpcCode::RPC_CODE_NOT_FOUND;
    case HDL_E_NO_MEM:
        return RpcCode::RPC_CODE_RESOURCE_EXHAUSTED;
    case HDL_E_BUSY:
        return RpcCode::RPC_CODE_ABORTED;
    case HDL_E_CANCELLED:
        return RpcCode::RPC_CODE_CANCELLED;
    case HDL_E_NOT_INIT:
        return RpcCode::RPC_CODE_FAILED_PRECONDITION;
    case HDL_E_TIMEOUT:
        return RpcCode::RPC_CODE_DEADLINE_EXCEEDED;
    default:
        return RpcCode::RPC_CODE_INTERNAL;
    }
}

::hdl::rpc::v1::HdlStatusCode ToHdlStatusCode(int32_t status) {
    if (status < HDL_OK || status > HDL_E_TIMEOUT) {
        return ::hdl::rpc::v1::HDL_STATUS_FAILED;
    }
    return static_cast<::hdl::rpc::v1::HdlStatusCode>(status);
}

void SetRpcStatus(int32_t hdl_status, ::hdl::rpc::v1::RpcStatus* out) {
    if (!out) {
        return;
    }
    out->set_code(MapHdlStatus(hdl_status));
    out->set_hdl_status(ToHdlStatusCode(hdl_status));
    const std::string_view reason = HdlReason(hdl_status);
    out->set_reason(reason.data(), reason.size());
}

bool WriteServerHello(HANDLE pipe) {
    ::hdl::rpc::v1::Envelope envelope;
    auto* hello = envelope.mutable_server_hello();
    hello->set_protocol_major(kProtocolMajor);
    hello->set_protocol_minor(kProtocolMinor);
    hello->set_server_name("hdllib");
    hello->set_server_build("0.1.0-pre");

    const auto& identity = GetServerIdentity();
    if (!identity.valid) {
        return false;
    }
    hello->set_server_instance_id(identity.bytes.data(), identity.bytes.size());
    for (const MethodMetadata& method : kMethods) {
        auto* info = hello->add_methods();
        info->set_name(method.name.data(), method.name.size());
        info->set_server_streaming(method.server_streaming);
        info->set_default_timeout_ms(0);
        info->set_max_timeout_ms(0);
    }
    auto* limits = hello->mutable_limits();
    limits->set_max_frame_bytes(kMaxFrameBytes);
    limits->set_max_in_flight(kMaxInFlight);
    limits->set_max_stream_chunk_bytes(kMaxStreamChunkBytes);

    std::vector<uint8_t> bytes;
    return SerializeEnvelope(envelope, &bytes) &&
           ipc::WriteFrameBytes(pipe, bytes.data(), static_cast<uint32_t>(bytes.size()));
}

bool WriteErrorResponse(HANDLE pipe, uint64_t request_id, ::hdl::rpc::v1::RpcCode code,
                        int32_t hdl_status, std::string_view reason, std::string_view message) {
    ::hdl::rpc::v1::Envelope envelope;
    auto* response = envelope.mutable_response();
    response->set_request_id(request_id);
    response->set_sequence(0);
    response->set_end_stream(true);
    auto* status = response->mutable_status();
    status->set_code(code);
    status->set_hdl_status(ToHdlStatusCode(hdl_status));
    status->set_reason(reason.data(), reason.size());
    status->set_message(message.data(), message.size());

    std::vector<uint8_t> bytes;
    return SerializeEnvelope(envelope, &bytes) &&
           ipc::WriteFrameBytes(pipe, bytes.data(), static_cast<uint32_t>(bytes.size()));
}

bool WriteGoAway(HANDLE pipe, ::hdl::rpc::v1::RpcCode code, int32_t hdl_status,
                 std::string_view reason, std::string_view message) {
    ::hdl::rpc::v1::Envelope envelope;
    auto* status = envelope.mutable_go_away()->mutable_status();
    status->set_code(code);
    status->set_hdl_status(ToHdlStatusCode(hdl_status));
    status->set_reason(reason.data(), reason.size());
    status->set_message(message.data(), message.size());
    std::vector<uint8_t> bytes;
    return SerializeEnvelope(envelope, &bytes) &&
           ipc::WriteFrameBytes(pipe, bytes.data(), static_cast<uint32_t>(bytes.size()));
}

} // namespace hdl::rpc
