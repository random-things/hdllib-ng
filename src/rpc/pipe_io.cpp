#include "rpc/pipe_io.hpp"

#include "hdllib/pipe_name.h"

#include <algorithm>

namespace hdl::rpc {
namespace {

constexpr DWORD kRetrySliceMs = 200;
constexpr DWORD kMissingPipeBackoffMs = 50;

using StartIo = BOOL (*)(HANDLE, void*, DWORD, OVERLAPPED*);

BOOL StartRead(HANDLE pipe, void* buffer, DWORD size, OVERLAPPED* overlapped) {
    return ReadFile(pipe, buffer, size, nullptr, overlapped);
}

BOOL StartWrite(HANDLE pipe, void* buffer, DWORD size, OVERLAPPED* overlapped) {
    return WriteFile(pipe, buffer, size, nullptr, overlapped);
}

void DrainCancelledOperation(HANDLE completion_port, OVERLAPPED* operation) {
    for (;;) {
        DWORD transferred = 0;
        ULONG_PTR key = 0;
        OVERLAPPED* completed = nullptr;
        GetQueuedCompletionStatus(completion_port, &transferred, &key, &completed, INFINITE);
        if (completed == operation) {
            return;
        }
    }
}

PipeIoResult Transfer(HANDLE pipe, HANDLE completion_port, void* buffer, DWORD size,
                      const PipeDeadline& deadline, StartIo start_io, DWORD* bytes_transferred) {
    if (!pipe || pipe == INVALID_HANDLE_VALUE || !completion_port || !buffer || !size) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return PipeIoResult::Error;
    }
    if (deadline.expired()) {
        SetLastError(ERROR_TIMEOUT);
        return PipeIoResult::Timeout;
    }

    OVERLAPPED operation{};
    if (!start_io(pipe, buffer, size, &operation)) {
        const DWORD error = GetLastError();
        if (error != ERROR_IO_PENDING) {
            return PipeIoResult::Error;
        }
    }

    for (;;) {
        DWORD transferred = 0;
        ULONG_PTR key = 0;
        OVERLAPPED* completed = nullptr;
        const BOOL completed_ok = GetQueuedCompletionStatus(completion_port, &transferred, &key,
                                                            &completed, deadline.remaining_ms());
        if (completed == &operation) {
            if (!completed_ok) {
                return PipeIoResult::Error;
            }
            if (!transferred) {
                SetLastError(ERROR_BROKEN_PIPE);
                return PipeIoResult::Error;
            }
            *bytes_transferred = transferred;
            return PipeIoResult::Ok;
        }
        if (!completed && !completed_ok && GetLastError() == WAIT_TIMEOUT) {
            // CancelIoEx can report ERROR_NOT_FOUND when completion won the
            // race. Either way, the completion packet must be consumed before
            // this stack-owned OVERLAPPED goes out of scope.
            CancelIoEx(pipe, &operation);
            DrainCancelledOperation(completion_port, &operation);
            SetLastError(ERROR_TIMEOUT);
            return PipeIoResult::Timeout;
        }
        if (!completed && !completed_ok) {
            return PipeIoResult::Error;
        }
        // This transport serializes operations. Ignore an unrelated packet
        // defensively while retaining the original absolute deadline.
    }
}

HANDLE OpenOverlappedLocalPipe(uint32_t pid) {
    wchar_t name[128];
    if (HdlFormatPipeName(pid, name, 128) != 0) {
        SetLastError(ERROR_INVALID_NAME);
        return INVALID_HANDLE_VALUE;
    }
    return CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                       FILE_FLAG_OVERLAPPED, nullptr);
}

} // namespace

PipeDeadline::PipeDeadline(DWORD timeout_ms)
    : expires_at_(timeout_ms ? GetTickCount64() + timeout_ms : 0) {}

bool PipeDeadline::expired() const {
    return expires_at_ && GetTickCount64() >= expires_at_;
}

DWORD PipeDeadline::remaining_ms() const {
    if (!expires_at_) {
        return INFINITE;
    }
    const ULONGLONG now = GetTickCount64();
    if (now >= expires_at_) {
        return 0;
    }
    const ULONGLONG remaining = expires_at_ - now;
    return static_cast<DWORD>((std::min)(remaining, static_cast<ULONGLONG>(INFINITE - 1)));
}

PipeIoResult ConnectLocalPipe(uint32_t pid, const PipeDeadline& deadline, HANDLE* pipe,
                              HANDLE* completion_port) {
    if (!pipe || !completion_port) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return PipeIoResult::Error;
    }
    *pipe = INVALID_HANDLE_VALUE;
    *completion_port = nullptr;

    for (;;) {
        if (deadline.expired()) {
            SetLastError(ERROR_TIMEOUT);
            return PipeIoResult::Timeout;
        }

        HANDLE opened = OpenOverlappedLocalPipe(pid);
        if (opened != INVALID_HANDLE_VALUE) {
            DWORD mode = PIPE_READMODE_BYTE | PIPE_WAIT;
            if (!SetNamedPipeHandleState(opened, &mode, nullptr, nullptr)) {
                CloseHandle(opened);
                return PipeIoResult::Error;
            }
            HANDLE port = CreateIoCompletionPort(opened, nullptr, 0, 1);
            if (!port) {
                CloseHandle(opened);
                return PipeIoResult::Error;
            }
            *pipe = opened;
            *completion_port = port;
            return PipeIoResult::Ok;
        }

        const DWORD open_error = GetLastError();
        if (open_error != ERROR_PIPE_BUSY && open_error != ERROR_FILE_NOT_FOUND) {
            return PipeIoResult::Error;
        }

        const DWORD remaining = deadline.remaining_ms();
        if (!remaining) {
            SetLastError(ERROR_TIMEOUT);
            return PipeIoResult::Timeout;
        }
        const DWORD wait_ms =
            remaining == INFINITE ? kRetrySliceMs : (std::min)(remaining, kRetrySliceMs);
        if (HdlWaitLocalPipe(pid, wait_ms)) {
            continue;
        }
        const DWORD wait_error = GetLastError();
        if (wait_error != ERROR_SEM_TIMEOUT && wait_error != ERROR_FILE_NOT_FOUND) {
            return PipeIoResult::Error;
        }
        if (wait_error == ERROR_FILE_NOT_FOUND) {
            const DWORD after_wait = deadline.remaining_ms();
            if (!after_wait) {
                SetLastError(ERROR_TIMEOUT);
                return PipeIoResult::Timeout;
            }
            Sleep(after_wait == INFINITE ? kMissingPipeBackoffMs
                                         : (std::min)(after_wait, kMissingPipeBackoffMs));
        }
    }
}

PipeIoResult ReadPipeExact(HANDLE pipe, HANDLE completion_port, void* buffer, DWORD size,
                           const PipeDeadline& deadline) {
    auto* cursor = static_cast<uint8_t*>(buffer);
    DWORD remaining = size;
    while (remaining) {
        DWORD transferred = 0;
        const PipeIoResult result =
            Transfer(pipe, completion_port, cursor, remaining, deadline, StartRead, &transferred);
        if (result != PipeIoResult::Ok) {
            return result;
        }
        cursor += transferred;
        remaining -= transferred;
    }
    return PipeIoResult::Ok;
}

PipeIoResult WritePipeExact(HANDLE pipe, HANDLE completion_port, const void* buffer, DWORD size,
                            const PipeDeadline& deadline) {
    auto* cursor = static_cast<const uint8_t*>(buffer);
    DWORD remaining = size;
    while (remaining) {
        DWORD transferred = 0;
        const PipeIoResult result = Transfer(pipe, completion_port, const_cast<uint8_t*>(cursor),
                                             remaining, deadline, StartWrite, &transferred);
        if (result != PipeIoResult::Ok) {
            return result;
        }
        cursor += transferred;
        remaining -= transferred;
    }
    return PipeIoResult::Ok;
}

} // namespace hdl::rpc
