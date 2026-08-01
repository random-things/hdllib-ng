#include "core.hpp"
#include "alloc.hpp"
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
/* Set by CoreShutdownFinish; cleared/handled in CoreOnIpcServerExited after workers join. */
std::atomic<bool> g_finish_after_ipc{false};

void WaitNotBootstrapping() {
    std::unique_lock<std::mutex> lock(g_boot_mu);
    g_boot_cv.wait(lock, [] { return g_state.load() != kBootstrapping; });
}

void PublishState(int state) {
    {
        std::lock_guard<std::mutex> lock(g_boot_mu);
        g_state.store(state);
    }
    g_boot_cv.notify_all();
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
bool BeginShutdown(uint32_t flags) {
    WaitNotBootstrapping();
    int expected = kReady;
    if (!g_state.compare_exchange_strong(expected, kUninit)) {
        return false;
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
    return true;
}

void FinishShutdownResources() {
    AllocShutdown();
    disasm::RegistryShutdown();
}

}  // namespace

HdlStatus CoreInit() {
    int expected = kUninit;
    if (!g_state.compare_exchange_strong(expected, kBootstrapping)) {
        WaitNotBootstrapping();
        return g_state.load() == kReady ? HDL_OK : HDL_E_FAILED;
    }

    ApplyQuietLogDefaults();
    HDL_LOG_INFO("helper initializing");
    HdlStatus result = HDL_OK;
    disasm::RegistryInit();
    if (HooksInit() != HDL_OK) {
        disasm::RegistryShutdown();
        result = HDL_E_FAILED;
    } else if (HealthInit() != HDL_OK) {
        HooksShutdown();
        disasm::RegistryShutdown();
        result = HDL_E_FAILED;
    } else {
        WatchInit();
        if (!EnvFlag(L"HDL_NO_IPC")) {
            const HdlStatus st = StartIpcServer();
            if (st != HDL_OK) {
                WatchShutdown();
                HealthShutdown();
                HooksShutdown();
                disasm::RegistryShutdown();
                result = st;
            }
        } else {
            HDL_LOG_INFO("IPC skipped (HDL_NO_IPC)");
        }
    }

    if (result == HDL_OK) {
        HDL_LOG_INFO("helper ready");
        PublishState(kReady);
    } else {
        PublishState(kUninit);
    }
    return result;
}

void CoreShutdown() {
    if (BeginShutdown(0)) {
        StopIpcServer(); /* ThreadMain joins workers then closes IPC session/job maps. */
        CloseDomainSessionsAndJobs();
        FinishShutdownResources();
    }
}

void CoreShutdownEx(uint32_t flags) {
    if (BeginShutdown(flags)) {
        StopIpcServer();
        CloseDomainSessionsAndJobs();
        FinishShutdownResources();
    }
}

void CoreShutdownPrepare(uint32_t flags) {
    /* Instrumentation only — session/job maps close after workers join in ThreadMain. */
    BeginShutdown(flags);
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
     * Explicit OpShutdown (or CoreShutdown) must have run before FreeLibrary. */
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

}  // namespace hdl
