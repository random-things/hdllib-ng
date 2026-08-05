#include "rpc/runtime.hpp"

#include "ipc/framing.hpp"

#include "hdllib/hdllib.h"

#include <array>
#include <cstring>

#include <bcrypt.h>

#pragma comment(lib, "Bcrypt.lib")

namespace hdl::rpc {
namespace {

struct ActiveResponse {
    uint64_t request_id = 0;
    uint32_t sequence = 0;
    bool streaming = false;
};

thread_local ActiveResponse g_active_response;
thread_local bool g_has_active_response = false;

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

} // namespace

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
    case HDL_E_BUFFER_SMALL:
    case HDL_E_FAILED:
    default:
        return RpcCode::RPC_CODE_INTERNAL;
    }
}

void SetRpcStatus(int32_t hdl_status, ::hdl::rpc::v1::RpcStatus* out) {
    if (!out) {
        return;
    }
    out->set_code(MapHdlStatus(hdl_status));
    out->set_hdl_status(hdl_status);
    switch (hdl_status) {
    case HDL_OK:
        out->set_reason("OK");
        break;
    case HDL_E_INVALID_ARG:
        out->set_reason("INVALID_ARGUMENT");
        break;
    case HDL_E_ACCESS:
        out->set_reason("ACCESS_DENIED");
        break;
    case HDL_E_NOT_FOUND:
        out->set_reason("NOT_FOUND");
        break;
    case HDL_E_NO_MEM:
        out->set_reason("RESOURCE_EXHAUSTED");
        break;
    case HDL_E_BUSY:
        out->set_reason("BUSY");
        break;
    case HDL_E_CANCELLED:
        out->set_reason("CANCELLED");
        break;
    case HDL_E_NOT_INIT:
        out->set_reason("NOT_INITIALIZED");
        break;
    case HDL_E_TIMEOUT:
        out->set_reason("DEADLINE_EXCEEDED");
        break;
    default:
        out->set_reason("INTERNAL");
        break;
    }
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
        // The transport never invents a deadline. In particular, a low-selectivity
        // search may legitimately take far longer than an interactive command.
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
    status->set_hdl_status(hdl_status);
    status->set_reason(reason.data(), reason.size());
    status->set_message(message.data(), message.size());

    // Keep the compact adapter consumable by the current client while the
    // protobuf status remains the transport-level source of truth.
    ::hdl::rpc::v1::Payload payload;
    payload.set_value(&hdl_status, sizeof(hdl_status));
    if (!payload.SerializeToString(response->mutable_payload())) {
        return false;
    }
    std::vector<uint8_t> bytes;
    return SerializeEnvelope(envelope, &bytes) &&
           ipc::WriteFrameBytes(pipe, bytes.data(), static_cast<uint32_t>(bytes.size()));
}

ResponseScope::ResponseScope(uint64_t request_id, bool streaming) {
    if (!g_has_active_response) {
        g_active_response = ActiveResponse{request_id, 0, streaming};
        g_has_active_response = true;
        active_ = true;
    }
}

ResponseScope::~ResponseScope() {
    if (active_) {
        g_active_response = {};
        g_has_active_response = false;
    }
}

bool WriteHandlerResponse(HANDLE pipe, const void* data, uint32_t size) {
    if (!g_has_active_response) {
        return ipc::WriteFrameBytes(pipe, data, size);
    }

    int32_t hdl_status = HDL_E_FAILED;
    if (data && size >= sizeof(hdl_status)) {
        std::memcpy(&hdl_status, data, sizeof(hdl_status));
    }
    bool end_stream = true;
    if (g_active_response.streaming && data && size >= sizeof(int32_t) + sizeof(uint32_t)) {
        uint32_t flags = 0;
        std::memcpy(&flags, static_cast<const uint8_t*>(data) + sizeof(int32_t), sizeof(flags));
        end_stream = (flags & 1u) == 0;
    }

    ::hdl::rpc::v1::Envelope envelope;
    auto* response = envelope.mutable_response();
    response->set_request_id(g_active_response.request_id);
    response->set_sequence(g_active_response.sequence++);
    response->set_end_stream(end_stream);
    SetRpcStatus(hdl_status, response->mutable_status());
    ::hdl::rpc::v1::Payload payload;
    if (data && size) {
        payload.set_value(data, size);
    }
    if (!payload.SerializeToString(response->mutable_payload())) {
        return false;
    }

    std::vector<uint8_t> bytes;
    return SerializeEnvelope(envelope, &bytes) &&
           ipc::WriteFrameBytes(pipe, bytes.data(), static_cast<uint32_t>(bytes.size()));
}

} // namespace hdl::rpc
