#pragma once

#include "rpc/status.hpp"

#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

namespace hdl::rpc {
class PipeDeadline;
}

class PipeClient final : public hdl::rpc::ClientChannel {
  public:
    explicit PipeClient(uint32_t pid, std::string client_name = "hdlclient",
                        std::string client_build = "0.1.0-pre");
    ~PipeClient() override;

    bool Connect(DWORD timeout_ms = 5000);
    void Close();

    hdl::rpc::RawUnaryResult Unary(std::string_view method,
                                   const google::protobuf::MessageLite& request,
                                   google::protobuf::MessageLite* response,
                                   hdl::rpc::CallOptions options) override;
    hdl::rpc::Status
    ServerStream(std::string_view method, const google::protobuf::MessageLite& request,
                 google::protobuf::MessageLite* response,
                 const std::function<bool(const google::protobuf::MessageLite&)>& on_message,
                 hdl::rpc::CallOptions options) override;

    uint32_t ProtoMajor() const { return proto_major_; }
    uint32_t ProtoMinor() const { return proto_minor_; }
    const std::string& NegotiateError() const { return negotiate_error_; }

  private:
    bool Negotiate(const hdl::rpc::PipeDeadline& deadline);
    void CloseUnlocked();
    bool MethodAvailable(std::string_view method, bool streaming) const;

    uint32_t pid_ = 0;
    std::string client_name_;
    std::string client_build_;
    void* handle_ = nullptr;
    void* completion_port_ = nullptr;
    uint32_t proto_major_ = 0;
    uint32_t proto_minor_ = 0;
    uint32_t max_frame_bytes_ = 0;
    uint64_t next_request_id_ = 1;
    std::unordered_map<std::string, bool> methods_;
    std::string negotiate_error_;
    std::mutex request_mutex_;
};
