#pragma once

#include "hdl/rpc/v1/envelope.pb.h"
#include "hdl/rpc/v1/services.rpc.hpp"
#include "rpc/status.hpp"

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

namespace hdl::rpc {

inline constexpr uint32_t kProtocolMajor = 1;
inline constexpr uint32_t kProtocolMinor = 0;
inline constexpr uint32_t kMaxFrameBytes = 64u * 1024u * 1024u;
inline constexpr uint32_t kMaxInFlight = 1;
inline constexpr uint32_t kMaxStreamChunkBytes = 1u * 1024u * 1024u;
inline constexpr char kConnectionPreface[] = "HDLRPC1\n";
inline constexpr size_t kConnectionPrefaceSize = sizeof(kConnectionPreface) - 1;

bool SerializeEnvelope(const ::hdl::rpc::v1::Envelope& envelope, std::vector<uint8_t>* out);
bool ParseEnvelope(const uint8_t* data, size_t size, ::hdl::rpc::v1::Envelope* out);

::hdl::rpc::v1::RpcCode MapHdlStatus(int32_t status);
::hdl::rpc::v1::HdlStatusCode ToHdlStatusCode(int32_t status);
void SetRpcStatus(int32_t hdl_status, ::hdl::rpc::v1::RpcStatus* out);

bool WriteServerHello(HANDLE pipe);
bool WriteErrorResponse(HANDLE pipe, uint64_t request_id, ::hdl::rpc::v1::RpcCode code,
                        int32_t hdl_status, std::string_view reason, std::string_view message = {});
bool WriteGoAway(HANDLE pipe, ::hdl::rpc::v1::RpcCode code, int32_t hdl_status,
                 std::string_view reason, std::string_view message = {});

} // namespace hdl::rpc
