#pragma once

#include "hdllib/hdllib.h"

namespace hdl {

HdlStatus CoreInit();
void CoreShutdown();
void CoreShutdownEx(uint32_t flags);
/* Instrumentation teardown only (caller replies on the pipe, then Finish). */
void CoreShutdownPrepare(uint32_t flags);
/* Signal IPC stop without join + free allocs (safe after reply from ServeClient). */
void CoreShutdownFinish();
/* Loader-lock safe residual teardown (no IPC thread join). */
void CoreShutdownDetach();
bool CoreIsInitialized();

HdlStatus StartIpc();
void StopIpc();
bool IsIpcRunning();

}  // namespace hdl
