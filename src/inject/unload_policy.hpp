#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

namespace hdl::inject {

enum class ShutdownConnectDisposition {
    PreparedPipeGone,
    Busy,
    Failed,
};

inline bool IsTransientShutdownPipeError(DWORD error) {
    return error == ERROR_TIMEOUT || error == WAIT_TIMEOUT || error == ERROR_PIPE_BUSY ||
           error == ERROR_SEM_TIMEOUT || error == ERROR_BUSY || error == ERROR_PIPE_LISTENING;
}

/* A failed negotiated connection is never evidence of quiescence by itself.
 * Only a separately confirmed ERROR_FILE_NOT_FOUND result preserves the
 * explicit Shutdown-then-Unload workflow. */
inline ShutdownConnectDisposition ClassifyShutdownConnectFailure(DWORD connect_error,
                                                                 bool probe_reachable,
                                                                 DWORD probe_error,
                                                                 bool absence_confirmed) {
    if (absence_confirmed && !probe_reachable && probe_error == ERROR_FILE_NOT_FOUND &&
        IsTransientShutdownPipeError(connect_error)) {
        return ShutdownConnectDisposition::PreparedPipeGone;
    }
    if (IsTransientShutdownPipeError(connect_error) ||
        (!probe_reachable && IsTransientShutdownPipeError(probe_error))) {
        return ShutdownConnectDisposition::Busy;
    }
    return ShutdownConnectDisposition::Failed;
}

} // namespace hdl::inject
