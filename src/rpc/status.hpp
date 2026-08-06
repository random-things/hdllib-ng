#pragma once

#include "hdl/rpc/v1/common.pb.h"

#include <google/protobuf/message_lite.h>

#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <utility>

namespace hdl::rpc {

class Status {
  public:
    Status() = default;
    explicit Status(::hdl::rpc::v1::RpcStatus value) : value_(std::move(value)) {}

    static Status Ok();
    static Status FromHdl(int32_t hdl_status, std::string_view message = {});
    static Status Transport(::hdl::rpc::v1::RpcCode code, std::string_view reason,
                            std::string_view message = {});

    bool ok() const { return value_.code() == ::hdl::rpc::v1::RPC_CODE_OK; }
    ::hdl::rpc::v1::RpcCode code() const { return value_.code(); }
    int32_t hdl_status() const { return static_cast<int32_t>(value_.hdl_status()); }
    const std::string& reason() const { return value_.reason(); }
    const std::string& message() const { return value_.message(); }
    bool outcome_unknown() const { return value_.outcome_unknown(); }
    void set_outcome_unknown(bool value) { value_.set_outcome_unknown(value); }
    const ::hdl::rpc::v1::RpcStatus& proto() const { return value_; }

  private:
    ::hdl::rpc::v1::RpcStatus value_;
};

template <typename T> struct Result {
    Status status;
    T response;
    bool has_response = false;

    explicit operator bool() const { return status.ok(); }
};

struct CallOptions {
    uint32_t timeout_ms = 0;
};

template <typename T> using StreamCallback = std::function<bool(const T&)>;

struct RawUnaryResult {
    Status status;
    bool has_response = false;
};

class ClientChannel {
  public:
    virtual ~ClientChannel() = default;
    virtual RawUnaryResult Unary(std::string_view method,
                                 const google::protobuf::MessageLite& request,
                                 google::protobuf::MessageLite* response, CallOptions options) = 0;
    virtual Status
    ServerStream(std::string_view method, const google::protobuf::MessageLite& request,
                 google::protobuf::MessageLite* response,
                 const std::function<bool(const google::protobuf::MessageLite&)>& on_message,
                 CallOptions options) = 0;
};

template <typename Response>
Result<Response> InvokeUnary(ClientChannel* channel, std::string_view method,
                             const google::protobuf::MessageLite& request, CallOptions options) {
    Result<Response> result;
    if (!channel) {
        result.status = Status::Transport(::hdl::rpc::v1::RPC_CODE_FAILED_PRECONDITION,
                                          "NO_CHANNEL", "RPC client has no channel");
        return result;
    }
    const RawUnaryResult raw = channel->Unary(method, request, &result.response, options);
    result.status = raw.status;
    result.has_response = raw.has_response;
    return result;
}

template <typename Response>
Status InvokeServerStream(ClientChannel* channel, std::string_view method,
                          const google::protobuf::MessageLite& request,
                          StreamCallback<Response> on_message, CallOptions options) {
    if (!channel) {
        return Status::Transport(::hdl::rpc::v1::RPC_CODE_FAILED_PRECONDITION, "NO_CHANNEL",
                                 "RPC client has no channel");
    }
    Response response;
    return channel->ServerStream(
        method, request, &response,
        [callback = std::move(on_message)](const google::protobuf::MessageLite& message) {
            return callback(static_cast<const Response&>(message));
        },
        options);
}

class CallContext {
  public:
    CallContext(uint64_t request_id, uint32_t timeout_ms);

    uint64_t request_id() const { return request_id_; }
    uint32_t timeout_ms() const { return timeout_ms_; }
    uint32_t remaining_timeout_ms() const;
    bool deadline_exceeded() const;
    bool cancelled() const { return cancelled_; }
    void Cancel() { cancelled_ = true; }
    void DeferAfterReply(std::function<void()> action);
    void RunAfterReply();

  private:
    uint64_t request_id_ = 0;
    uint32_t timeout_ms_ = 0;
    uint64_t deadline_tick_ = 0;
    bool cancelled_ = false;
    std::function<void()> after_reply_;
};

class ServerWriterBase {
  public:
    virtual ~ServerWriterBase() = default;
    virtual bool WriteMessage(const google::protobuf::MessageLite& message) = 0;
    virtual bool Finish(const Status& status) = 0;
};

template <typename T> class ServerWriter {
  public:
    explicit ServerWriter(ServerWriterBase* writer) : writer_(writer) {}
    bool Write(const T& message) { return writer_ && writer_->WriteMessage(message); }
    bool Finish(const Status& status) { return writer_ && writer_->Finish(status); }

  private:
    ServerWriterBase* writer_ = nullptr;
};

} // namespace hdl::rpc
