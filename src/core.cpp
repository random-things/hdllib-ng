#include "core.hpp"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include "alloc.hpp"
#include "call_dispatch.hpp"
#include "call_registry.hpp"
#include "code.hpp"
#include "disasm/backend.hpp"
#include "discover.hpp"
#include "env.hpp"
#include "health.hpp"
#include "hooks.hpp"
#include "ipc/common.hpp"
#include "ipc_server.hpp"
#include "jobs.hpp"
#include "loaded_modules.hpp"
#include "log.hpp"
#include "watch.hpp"

#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>

namespace hdl {
namespace {

/* Single state avoids a window where g_init is true but bootstrapping is not yet set. */
enum : int {
    kUninit = 0,
    kBootstrapping = 1,
    kReady = 2,
};

std::atomic<int> g_state{kUninit};
std::mutex g_boot_mu;
std::condition_variable g_boot_cv;
struct InitAttempt {
    uint64_t id = 0;
    uint32_t owner_thread_id = 0;
    bool complete = false;
    HdlStatus result = HDL_E_FAILED;
};
std::shared_ptr<InitAttempt> g_active_init;
std::atomic<uint64_t> g_init_attempt{0};
std::atomic<uint32_t> g_init_owner_thread{0};
std::atomic<uint32_t> g_init_waiters{0};
std::atomic<CoreInitPhase> g_init_phase{CoreInitPhase::Uninitialized};
std::atomic<CoreInitPhase> g_last_failure_phase{CoreInitPhase::Uninitialized};
std::atomic<int32_t> g_last_init_status{HDL_E_NOT_INIT};
std::atomic<uint32_t> g_last_init_win32_error{ERROR_SUCCESS};
std::atomic<uint64_t> g_init_started_ms{0};
std::atomic<uint64_t> g_init_elapsed_ms{0};
std::mutex g_shutdown_mu;
/* Set by CoreShutdownFinish; cleared/handled in CoreOnIpcServerExited after workers join. */
std::atomic<bool> g_finish_after_ipc{false};

void WaitNotBootstrapping() {
    std::unique_lock<std::mutex> lock(g_boot_mu);
    g_boot_cv.wait(lock, [] { return g_state.load() != kBootstrapping; });
}

const char* InitPhaseName(CoreInitPhase phase) {
    switch (phase) {
    case CoreInitPhase::Uninitialized:
        return "uninitialized";
    case CoreInitPhase::ApplyingDefaults:
        return "applying-defaults";
    case CoreInitPhase::DisassemblyRegistry:
        return "disassembly-registry";
    case CoreInitPhase::Hooks:
        return "hooks";
    case CoreInitPhase::Health:
        return "health";
    case CoreInitPhase::CallRegistry:
        return "call-registry";
    case CoreInitPhase::Watch:
        return "watch";
    case CoreInitPhase::Ipc:
        return "ipc";
    case CoreInitPhase::Ready:
        return "ready";
    case CoreInitPhase::Failed:
        return "failed";
    default:
        return "unknown";
    }
}

void SetInitPhase(CoreInitPhase phase) {
    g_init_phase.store(phase);
}

/* Close jobs/sessions. Prefer calling after IPC workers have joined (ThreadMain does
 * the IPC maps); this covers HDL_NO_IPC and any leftovers. Close IPC holders first so
 * DiscoverCloseAll only sweeps domain sessions not still referenced by the maps. */
void CloseDomainSessionsAndJobs() {
    ipc::CloseAllSessions();
    ipc::CloseAllDiscoverSessions();
    JobCloseAll();
    DiscoverCloseAll();
}

/* Tear down instrumentation only. Does not touch IPC maps, jobs, or allocs —
 * workers may still be on ServeClient stacks until the accept thread joins them. */
HdlStatus BeginShutdown(uint32_t flags) {
    WaitNotBootstrapping();
    std::lock_guard<std::mutex> shutdown_lock(g_shutdown_mu);
    if (g_state.load() != kReady) {
        return HDL_E_NOT_INIT;
    }

    /* Close admission before detaching queued UI work so another request cannot
     * enter the gap. A failed attempt reopens admission and leaves the helper ready. */
    (void)CallRegistryTryBeginShutdown();
    const HdlStatus dispatch = CancelQueuedWindowCalls();
    const HdlStatus quiesce = CallRegistryTryBeginShutdown();
    if (dispatch == HDL_E_BUSY || quiesce != HDL_OK) {
        CallRegistryAbortShutdown();
        return HDL_E_BUSY;
    }

    int expected = kReady;
    if (!g_state.compare_exchange_strong(expected, kUninit)) {
        /* Another shutdown won admission and owns teardown. Do not reopen calls. */
        return HDL_E_NOT_INIT;
    }
    HDL_LOG_INFO("helper shutting down (flags=0x%X)", flags);

    WatchShutdown();
    PatchShutdown();
    HealthShutdown();
    HooksShutdown();

    if (flags & HDL_SHUTDOWN_UNLOAD_MODULES) {
        const HdlStatus st = UnloadTrackedExcept(SelfModule());
        if (st != HDL_OK) {
            HDL_LOG_ERROR("UnloadTrackedExcept status %d", static_cast<int>(st));
        }
    }
    return HDL_OK;
}

void FinishShutdownResources() {
    ResetWindowCallDispatcher();
    CallRegistryShutdown();
    AllocShutdown();
    disasm::RegistryShutdown();
}

} // namespace

HdlStatus CoreInit() {
    std::shared_ptr<InitAttempt> attempt;
    bool owns_attempt = false;
    {
        std::unique_lock<std::mutex> lock(g_boot_mu);
        if (g_state.load() == kReady) {
            return HDL_OK;
        }
        if (g_state.load() == kBootstrapping && g_active_init) {
            attempt = g_active_init;
            if (attempt->owner_thread_id == GetCurrentThreadId()) {
                HDL_LOG_ERROR("recursive CoreInit refused attempt=%llu owner_tid=%lu phase=%s",
                              static_cast<unsigned long long>(attempt->id),
                              static_cast<unsigned long>(attempt->owner_thread_id),
                              InitPhaseName(g_init_phase.load()));
                return HDL_E_BUSY;
            }
            g_init_waiters.fetch_add(1);
            g_boot_cv.wait(lock, [&attempt] { return attempt->complete; });
            g_init_waiters.fetch_sub(1);
            HDL_LOG_DEBUG("joined initialization attempt=%llu status=%d",
                          static_cast<unsigned long long>(attempt->id),
                          static_cast<int>(attempt->result));
            return attempt->result;
        }

        attempt = std::make_shared<InitAttempt>();
        attempt->id = g_init_attempt.fetch_add(1) + 1;
        attempt->owner_thread_id = GetCurrentThreadId();
        g_active_init = attempt;
        g_state.store(kBootstrapping);
        owns_attempt = true;
    }

    if (!owns_attempt) {
        return HDL_E_FAILED;
    }

    const uint64_t started_ms = GetTickCount64();
    g_init_started_ms.store(started_ms);
    g_init_elapsed_ms.store(0);
    g_init_owner_thread.store(attempt->owner_thread_id);
    g_last_init_status.store(HDL_E_FAILED);
    g_last_init_win32_error.store(ERROR_SUCCESS);
    g_last_failure_phase.store(CoreInitPhase::Uninitialized);
    SetInitPhase(CoreInitPhase::ApplyingDefaults);
    ApplyQuietLogDefaults();
    HDL_LOG_INFO("helper initializing attempt=%llu owner_tid=%lu",
                 static_cast<unsigned long long>(attempt->id),
                 static_cast<unsigned long>(attempt->owner_thread_id));
    HdlStatus result = HDL_OK;
    SetInitPhase(CoreInitPhase::DisassemblyRegistry);
    disasm::RegistryInit();
    SetInitPhase(CoreInitPhase::Hooks);
    if (HooksInit() != HDL_OK) {
        disasm::RegistryShutdown();
        result = HDL_E_FAILED;
    } else {
        SetInitPhase(CoreInitPhase::Health);
        if (HealthInit() != HDL_OK) {
            HooksShutdown();
            disasm::RegistryShutdown();
            result = HDL_E_FAILED;
        } else {
            SetInitPhase(CoreInitPhase::CallRegistry);
            CallRegistryInit();
            ResetWindowCallDispatcher();
            SetInitPhase(CoreInitPhase::Watch);
            WatchInit();
            if (!EnvFlag(L"HDL_NO_IPC")) {
                SetInitPhase(CoreInitPhase::Ipc);
                const HdlStatus st = StartIpcServer();
                if (st != HDL_OK) {
                    g_last_init_win32_error.store(GetLastError());
                    WatchShutdown();
                    CallRegistryShutdown();
                    HealthShutdown();
                    HooksShutdown();
                    disasm::RegistryShutdown();
                    result = st;
                }
            } else {
                HDL_LOG_INFO("IPC skipped (HDL_NO_IPC)");
            }
        }
    }

    const CoreInitPhase failed_phase = g_init_phase.load();
    const uint64_t elapsed_ms = GetTickCount64() - started_ms;
    g_init_elapsed_ms.store(elapsed_ms);
    g_last_init_status.store(result);
    if (result == HDL_OK) {
        SetInitPhase(CoreInitPhase::Ready);
        HDL_LOG_INFO("helper ready attempt=%llu elapsed_ms=%llu",
                     static_cast<unsigned long long>(attempt->id),
                     static_cast<unsigned long long>(elapsed_ms));
    } else {
        g_last_failure_phase.store(failed_phase);
        SetInitPhase(CoreInitPhase::Failed);
        HDL_LOG_ERROR("helper initialization failed attempt=%llu phase=%s status=%d "
                      "win32_error=%lu elapsed_ms=%llu",
                      static_cast<unsigned long long>(attempt->id), InitPhaseName(failed_phase),
                      static_cast<int>(result),
                      static_cast<unsigned long>(g_last_init_win32_error.load()),
                      static_cast<unsigned long long>(elapsed_ms));
        /* Errors must remain observable even when the normal bootstrap log level is off. */
        char message[256];
        _snprintf_s(message, _TRUNCATE,
                    "[ERROR] helper initialization failed attempt=%llu phase=%s status=%d "
                    "win32_error=%lu elapsed_ms=%llu\n",
                    static_cast<unsigned long long>(attempt->id), InitPhaseName(failed_phase),
                    static_cast<int>(result),
                    static_cast<unsigned long>(g_last_init_win32_error.load()),
                    static_cast<unsigned long long>(elapsed_ms));
        OutputDebugStringA(message);
    }

    {
        std::lock_guard<std::mutex> lock(g_boot_mu);
        attempt->result = result;
        attempt->complete = true;
        if (g_active_init == attempt) {
            g_active_init.reset();
        }
        g_state.store(result == HDL_OK ? kReady : kUninit);
    }
    g_boot_cv.notify_all();
    return result;
}

CoreInitDiagnostics CoreGetInitDiagnostics() {
    CoreInitDiagnostics result{};
    result.attempt_id = g_init_attempt.load();
    result.owner_thread_id = g_init_owner_thread.load();
    result.waiting_callers = g_init_waiters.load();
    result.phase = g_init_phase.load();
    result.failure_phase = g_last_failure_phase.load();
    result.last_status = static_cast<HdlStatus>(g_last_init_status.load());
    result.win32_error = g_last_init_win32_error.load();
    const uint64_t started_ms = g_init_started_ms.load();
    result.elapsed_ms = g_state.load() == kBootstrapping && started_ms != 0
                            ? GetTickCount64() - started_ms
                            : g_init_elapsed_ms.load();
    return result;
}

const char* CoreInitPhaseName(CoreInitPhase phase) {
    return InitPhaseName(phase);
}

void CoreShutdown() {
    if (BeginShutdown(0) == HDL_OK) {
        StopIpcServer(); /* ThreadMain joins workers then closes IPC session/job maps. */
        CloseDomainSessionsAndJobs();
        FinishShutdownResources();
    }
}

void CoreShutdownEx(uint32_t flags) {
    if (BeginShutdown(flags) == HDL_OK) {
        StopIpcServer();
        CloseDomainSessionsAndJobs();
        FinishShutdownResources();
    }
}

HdlStatus CoreShutdownPrepare(uint32_t flags) {
    /* Call quiescence + instrumentation; session/job maps close after IPC workers join. */
    return BeginShutdown(flags);
}

void CoreShutdownFinish(void* keep_alive_pipe) {
    /* Do not free allocs here — this may run on a ServeClient worker that ThreadMain
     * must join first. ThreadMain calls CoreOnIpcServerExited after joining workers. */
    g_finish_after_ipc.store(true);
    StopIpcServerNoJoin(keep_alive_pipe);
}

void CoreOnIpcServerExited() {
    if (g_finish_after_ipc.exchange(false)) {
        /* ThreadMain already joined workers and cleared IPC maps; this sweeps any
         * domain sessions/jobs not registered in those maps, then frees allocs. */
        CloseDomainSessionsAndJobs();
        FinishShutdownResources();
    }
}

void CoreShutdownDetach() {
    /* Loader lock: no locks, joins, MinHook, VirtualProtect, or heap teardown.
     * Explicit Control.Shutdown (or CoreShutdown) must have run before FreeLibrary. */
}

bool CoreIsInitialized() {
    return g_state.load() == kReady;
}

HdlStatus StartIpc() {
    return StartIpcServer();
}

void StopIpc() {
    StopIpcServer();
}

bool IsIpcRunning() {
    return IsIpcServerRunning();
}

} // namespace hdl
