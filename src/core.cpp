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

std::atomic<bool> g_init{false};
std::atomic<bool> g_bootstrapping{false};
std::mutex g_boot_mu;
std::condition_variable g_boot_cv;

void WaitBootstrapDone() {
    std::unique_lock<std::mutex> lock(g_boot_mu);
    g_boot_cv.wait(lock, [] { return !g_bootstrapping.load(); });
}

/* Tear down instrumentation / sessions. Does not touch IPC or allocs. */
bool BeginShutdown(uint32_t flags) {
    WaitBootstrapDone();
    bool expected = true;
    if (!g_init.compare_exchange_strong(expected, false)) {
        return false;
    }
    HDL_LOG_INFO("helper shutting down (flags=0x%X)", flags);

    JobCloseAll();
    DiscoverCloseAll();
    ipc::CloseAllSessions();
    ipc::CloseAllDiscoverSessions();

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
    bool expected = false;
    if (!g_init.compare_exchange_strong(expected, true)) {
        WaitBootstrapDone();
        return g_init.load() ? HDL_OK : HDL_E_FAILED;
    }

    {
        std::lock_guard<std::mutex> lock(g_boot_mu);
        g_bootstrapping = true;
    }

    ApplyQuietLogDefaults();
    HDL_LOG_INFO("helper initializing");
    HdlStatus result = HDL_OK;
    disasm::RegistryInit();
    if (HooksInit() != HDL_OK) {
        disasm::RegistryShutdown();
        g_init = false;
        result = HDL_E_FAILED;
    } else if (HealthInit() != HDL_OK) {
        HooksShutdown();
        disasm::RegistryShutdown();
        g_init = false;
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
                g_init = false;
                result = st;
            }
        } else {
            HDL_LOG_INFO("IPC skipped (HDL_NO_IPC)");
        }
    }

    if (result == HDL_OK) {
        HDL_LOG_INFO("helper ready");
    }

    {
        std::lock_guard<std::mutex> lock(g_boot_mu);
        g_bootstrapping = false;
    }
    g_boot_cv.notify_all();
    return result;
}

void CoreShutdown() {
    if (BeginShutdown(0)) {
        StopIpcServer();
        FinishShutdownResources();
    }
}

void CoreShutdownEx(uint32_t flags) {
    if (BeginShutdown(flags)) {
        StopIpcServer();
        FinishShutdownResources();
    }
}

void CoreShutdownPrepare(uint32_t flags) {
    /* Instrumentation only — caller replies, then finishes IPC/allocs. */
    BeginShutdown(flags);
}

void CoreShutdownFinish() {
    StopIpcServerNoJoin();
    FinishShutdownResources();
}

void CoreShutdownDetach() {
    if (BeginShutdown(0)) {
        StopIpcServerNoJoin();
        FinishShutdownResources();
    } else {
        /* Prepare already ran: ensure IPC stop signal + leftover allocs. */
        StopIpcServerNoJoin();
        FinishShutdownResources();
    }
}

bool CoreIsInitialized() {
    return g_init.load() && !g_bootstrapping.load();
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
