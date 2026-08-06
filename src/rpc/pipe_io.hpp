#pragma once

#include <cstdint>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

namespace hdl::rpc {

// An absolute deadline shared by every operation that makes up one connection
// or RPC. A zero timeout intentionally means no deadline.
class PipeDeadline final {
  public:
    explicit PipeDeadline(DWORD timeout_ms);

    bool expired() const;
    DWORD remaining_ms() const;

  private:
    ULONGLONG expires_at_ = 0;
};

enum class PipeIoResult {
    Ok,
    Timeout,
    Error,
};

// Opens the local pipe for overlapped I/O and associates it with a private I/O
// completion port. The returned handles are owned by the caller.
PipeIoResult ConnectLocalPipe(uint32_t pid, const PipeDeadline& deadline, HANDLE* pipe,
                              HANDLE* completion_port);

PipeIoResult ReadPipeExact(HANDLE pipe, HANDLE completion_port, void* buffer, DWORD size,
                           const PipeDeadline& deadline);
PipeIoResult WritePipeExact(HANDLE pipe, HANDLE completion_port, const void* buffer, DWORD size,
                            const PipeDeadline& deadline);

} // namespace hdl::rpc
