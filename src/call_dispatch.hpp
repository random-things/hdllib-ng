#pragma once

#include "hdllib/hdllib.h"

#include <cstdint>
#include <functional>

namespace hdl {

// Finds a primary top-level HWND for the current process (best-effort).
HWND FindPrimaryWindow();

/* Heap-owned window dispatch. Only call_id crosses the window-message boundary. */
HdlStatus PostWindowCall(HWND hwnd, uint64_t call_id, std::function<void()> execute,
                         std::function<void()> cancel, std::function<void()> finished);

/* Cancel queued tickets. Returns BUSY while a callback is executing target code. */
HdlStatus CancelQueuedWindowCalls();
void ResetWindowCallDispatcher();

} // namespace hdl
