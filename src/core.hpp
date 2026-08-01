#pragma once

#include "hdllib/hdllib.h"

namespace hdl {

HdlStatus CoreInit();
void CoreShutdown();
void CoreShutdownEx(uint32_t flags);
/* Instrumentation teardown only (caller replies on the pipe, then Finish). */
void CoreShutdownPrepare(uint32_t flags);
/* Signal IPC stop without join. Alloc/registry finish runs after the accept thread
 * joins workers (CoreOnIpcServerExited). keep_alive_pipe: leave connected for reply. */
void CoreShutdownFinish(void* keep_alive_pipe = nullptr);
/* Loader-lock safe: FreeLibrary detach must do nothing. Tear down via OpShutdown first. */
void CoreShutdownDetach();
/* Called from IPC ThreadMain after workers are joined — runs pending FinishShutdownResources. */
void CoreOnIpcServerExited();
bool CoreIsInitialized();

HdlStatus StartIpc();
void StopIpc();
bool IsIpcRunning();

}  // namespace hdl
