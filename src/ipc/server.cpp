#include "server.hpp"

#include "common.hpp"
#include "core.hpp"
#include "dispatch.hpp"
#include "framing.hpp"
#include "log.hpp"

#include <atomic>
#include <memory>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

namespace hdl {
namespace ipc {
namespace {

std::atomic<bool> g_running{false};
std::atomic<bool> g_ready{false};
std::atomic<bool> g_stop{false};
/* True while ThreadMain is on the stack (including post-loop cleanup). */
std::atomic<bool> g_accept_alive{false};
HANDLE g_stop_event = nullptr;
std::thread g_thread;

std::mutex g_clients_mu;
std::vector<HANDLE> g_client_pipes;
std::atomic<int> g_client_count{0};

struct WorkerSlot {
    std::thread thread;
    std::shared_ptr<std::atomic<bool>> done;
};

std::mutex g_workers_mu;
std::vector<WorkerSlot> g_workers;

void SignalStop() {
    g_stop = true;
    if (g_stop_event) {
        SetEvent(g_stop_event);
    }
    HANDLE client = CreateFileW(PipeName().c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                                OPEN_EXISTING, 0, nullptr);
    if (client != INVALID_HANDLE_VALUE) {
        CloseHandle(client);
    }
}

void WaitAcceptThreadExit() {
    for (int i = 0; i < 250 && g_accept_alive.load(); ++i) {
        if (g_stop_event) {
            SetEvent(g_stop_event);
        }
        Sleep(20);
    }
    if (g_thread.joinable()) {
        g_thread.join();
    }
}

void UnregisterClient(HANDLE pipe) {
    std::lock_guard<std::mutex> lock(g_clients_mu);
    for (auto it = g_client_pipes.begin(); it != g_client_pipes.end(); ++it) {
        if (*it == pipe) {
            g_client_pipes.erase(it);
            break;
        }
    }
}

void ReapFinishedWorkers() {
    std::vector<WorkerSlot> alive;
    std::vector<WorkerSlot> finished;
    {
        std::lock_guard<std::mutex> lock(g_workers_mu);
        for (auto& w : g_workers) {
            if (w.done && w.done->load()) {
                finished.push_back(std::move(w));
            } else {
                alive.push_back(std::move(w));
            }
        }
        g_workers = std::move(alive);
    }
    for (auto& w : finished) {
        if (w.thread.joinable()) {
            w.thread.join();
        }
    }
}

void JoinAllWorkers() {
    std::vector<WorkerSlot> local;
    {
        std::lock_guard<std::mutex> lock(g_workers_mu);
        local.swap(g_workers);
    }
    for (auto& w : local) {
        if (w.thread.joinable()) {
            w.thread.join();
        }
    }
    if (g_client_count.load() != 0) {
        HDL_LOG_ERROR("IPC workers joined but g_client_count=%d", g_client_count.load());
    }
}

void ServeClient(HANDLE pipe) {
    g_client_count.fetch_add(1);
    {
        std::lock_guard<std::mutex> lock(g_clients_mu);
        g_client_pipes.push_back(pipe);
    }

    while (!g_stop.load()) {
        std::vector<uint8_t> req;
        if (!ReadFrame(pipe, req)) {
            break;
        }
        if (!HandleRequest(pipe, req)) {
            break;
        }
    }

    UnregisterClient(pipe);
    FlushFileBuffers(pipe);
    DisconnectNamedPipe(pipe);
    CloseHandle(pipe);
    g_client_count.fetch_sub(1);
}

void SpawnWorker(HANDLE pipe) {
    ReapFinishedWorkers();
    auto done = std::make_shared<std::atomic<bool>>(false);
    WorkerSlot slot;
    slot.done = done;
    slot.thread = std::thread([pipe, done]() {
        ServeClient(pipe);
        done->store(true);
    });
    std::lock_guard<std::mutex> lock(g_workers_mu);
    g_workers.push_back(std::move(slot));
}

void ThreadMain() {
    g_accept_alive = true;
    const std::wstring name = PipeName();
    HDL_LOG_INFO("IPC server starting on %ls (multi-client, ACL)", name.c_str());

    while (!g_stop.load()) {
        std::vector<uint8_t> sd_storage;
        SECURITY_ATTRIBUTES* sa = BuildPipeSa(sd_storage);

        HANDLE pipe = CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                                       PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                                       PIPE_UNLIMITED_INSTANCES, 64 * 1024, 64 * 1024, 0, sa);

        if (pipe == INVALID_HANDLE_VALUE) {
            HDL_LOG_ERROR("CreateNamedPipeW failed: %lu", GetLastError());
            Sleep(200);
            continue;
        }

        /* First successful listen instance — server is usable for connects. */
        g_ready = true;
        g_running = true;

        OVERLAPPED ov{};
        ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        ConnectNamedPipe(pipe, &ov);
        DWORD err = GetLastError();

        bool connected = false;
        if (err == ERROR_PIPE_CONNECTED) {
            connected = true;
        } else if (err == ERROR_IO_PENDING) {
            HANDLE waits[2] = {ov.hEvent, g_stop_event};
            const DWORD wr = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
            if (wr == WAIT_OBJECT_0) {
                connected = true;
            } else {
                CancelIoEx(pipe, &ov);
                CloseHandle(ov.hEvent);
                CloseHandle(pipe);
                break;
            }
        } else {
            HDL_LOG_ERROR("ConnectNamedPipe failed: %lu", err);
            CloseHandle(ov.hEvent);
            CloseHandle(pipe);
            continue;
        }

        CloseHandle(ov.hEvent);

        if (!connected || g_stop.load()) {
            CloseHandle(pipe);
            break;
        }

        SpawnWorker(pipe);
    }

    /* Wake blocked readers, then join every worker before tearing down maps. */
    {
        std::lock_guard<std::mutex> lock(g_clients_mu);
        for (HANDLE h : g_client_pipes) {
            CancelIoEx(h, nullptr);
        }
    }
    JoinAllWorkers();
    {
        std::lock_guard<std::mutex> lock(g_clients_mu);
        for (HANDLE h : g_client_pipes) {
            DisconnectNamedPipe(h);
        }
        g_client_pipes.clear();
    }

    /* Session/job teardown only after every ServeClient worker has joined. */
    CloseAllSessions();
    CloseAllDiscoverSessions();
    JobCloseAll();
    g_ready = false;
    g_running = false;
    HDL_LOG_INFO("IPC server stopped");
    g_accept_alive = false;
    CoreOnIpcServerExited();
}

} // namespace

HdlStatus Start() {
    /* Healthy server already up — do not disturb. */
    if (g_running.load() && g_ready.load() && !g_stop.load()) {
        return HDL_OK;
    }
    /* Stop in progress or prior detach: wait until ThreadMain has left the stack. */
    WaitAcceptThreadExit();

    g_stop = false;
    g_ready = false;
    g_running = false;
    if (!g_stop_event) {
        g_stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    } else {
        ResetEvent(g_stop_event);
    }
    g_thread = std::thread(ThreadMain);
    for (int i = 0; i < 50 && !g_ready.load(); ++i) {
        Sleep(10);
    }
    if (!g_ready.load()) {
        HDL_LOG_ERROR("IPC server failed to become ready");
        SignalStop();
        WaitAcceptThreadExit();
        return HDL_E_FAILED;
    }
    return HDL_OK;
}

void Stop() {
    SignalStop();
    {
        std::lock_guard<std::mutex> lock(g_clients_mu);
        for (HANDLE h : g_client_pipes) {
            CancelIoEx(h, nullptr);
            DisconnectNamedPipe(h);
        }
    }
    WaitAcceptThreadExit();
    if (g_stop_event) {
        CloseHandle(g_stop_event);
        g_stop_event = nullptr;
    }
}

void StopNoJoin(void* keep_alive_pipe) {
    const HANDLE keep = static_cast<HANDLE>(keep_alive_pipe);
    SignalStop();
    {
        std::lock_guard<std::mutex> lock(g_clients_mu);
        for (HANDLE h : g_client_pipes) {
            if (h == keep) {
                continue; /* Leave in-flight reply readable; ServeClient will close it. */
            }
            CancelIoEx(h, nullptr);
            DisconnectNamedPipe(h);
        }
    }
    /*
     * Detach so ServeClient OpShutdown path does not join under its own accept thread.
     * Do NOT clear g_running here — ThreadMain owns that flag until it exits.
     * Start() waits on g_accept_alive before spawning a replacement thread.
     */
    if (g_thread.joinable()) {
        g_thread.detach();
    }
}

bool IsRunning() {
    return g_running.load() && g_ready.load();
}

} // namespace ipc
} // namespace hdl
