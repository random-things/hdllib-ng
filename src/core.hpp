#pragma once

#include "hdllib/hdllib.h"

namespace hdl {

enum class CoreInitPhase : uint32_t {
    Uninitialized = 0,
    ApplyingDefaults,
    DisassemblyRegistry,
    Hooks,
    Health,
    CallRegistry,
    Watch,
    Ipc,
    Ready,
    Failed,
};

struct CoreInitDiagnostics {
    uint64_t attempt_id;
    uint32_t owner_thread_id;
    uint32_t waiting_callers;
    CoreInitPhase phase;
    CoreInitPhase failure_phase;
    HdlStatus last_status;
    uint32_t win32_error;
    uint64_t elapsed_ms;
};

HdlStatus CoreInit();
CoreInitDiagnostics CoreGetInitDiagnostics();
const char* CoreInitPhaseName(CoreInitPhase phase);
void CoreShutdown();
void CoreShutdownEx(uint32_t flags);
/* Quiesce calls and tear down instrumentation (caller replies, then Finish). */
HdlStatus CoreShutdownPrepare(uint32_t flags);
/* Signal IPC stop without join. Alloc/registry finish runs after the accept thread
 * joins workers (CoreOnIpcServerExited). keep_alive_pipe: leave connected for reply. */
void CoreShutdownFinish(void* keep_alive_pipe = nullptr);
/* Loader-lock safe: FreeLibrary detach must do nothing. Tear down via Control.Shutdown first. */
void CoreShutdownDetach();
/* Called from IPC ThreadMain after workers are joined — runs pending FinishShutdownResources. */
void CoreOnIpcServerExited();
bool CoreIsInitialized();

HdlStatus StartIpc();
void StopIpc();
bool IsIpcRunning();

} // namespace hdl
