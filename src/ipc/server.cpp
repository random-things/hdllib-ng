#include "server.hpp"

#include "common.hpp"
#include "dispatch.hpp"
#include "framing.hpp"
#include "log.hpp"

#include <atomic>
#include <mutex>
#include <thread>
#include <vector>

namespace hdl {
namespace ipc {
namespace {

std::atomic<bool> g_running{false};
std::atomic<bool> g_stop{false};
HANDLE g_stop_event = nullptr;
std::thread g_thread;

std::mutex g_clients_mu;
std::vector<HANDLE> g_client_pipes;
std::atomic<int> g_client_count{0};

void UnregisterClient(HANDLE pipe) {
    std::lock_guard<std::mutex> lock(g_clients_mu);
    for (auto it = g_client_pipes.begin(); it != g_client_pipes.end(); ++it) {
        if (*it == pipe) {
            g_client_pipes.erase(it);
            break;
        }
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

void ThreadMain() {
    const std::wstring name = PipeName();
    HDL_LOG_INFO("IPC server starting on %ls (multi-client, ACL)", name.c_str());
    g_running = true;

    while (!g_stop.load()) {
        std::vector<uint8_t> sd_storage;
        SECURITY_ATTRIBUTES* sa = BuildPipeSa(sd_storage);

        HANDLE pipe = CreateNamedPipeW(
            name.c_str(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            64 * 1024,
            64 * 1024,
            0,
            sa);

        if (pipe == INVALID_HANDLE_VALUE) {
            HDL_LOG_ERROR("CreateNamedPipeW failed: %lu", GetLastError());
            Sleep(200);
            continue;
        }

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

        // Detach a worker so additional clients can connect concurrently.
        std::thread(ServeClient, pipe).detach();
    }

    // Nudge active clients so ServeClient readers unblock.
    {
        std::lock_guard<std::mutex> lock(g_clients_mu);
        for (HANDLE h : g_client_pipes) {
            CancelIoEx(h, nullptr);
            DisconnectNamedPipe(h);
        }
    }
    for (int i = 0; i < 100 && g_client_count.load() > 0; ++i) {
        Sleep(20);
    }

    CloseAllSessions();
    CloseAllDiscoverSessions();
    JobCloseAll();
    g_running = false;
    HDL_LOG_INFO("IPC server stopped");
}

}  // namespace

HdlStatus Start() {
    if (g_running.load()) {
        return HDL_OK;
    }
    g_stop = false;
    if (!g_stop_event) {
        g_stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    } else {
        ResetEvent(g_stop_event);
    }
    if (g_thread.joinable()) {
        g_thread.join();
    }
    g_thread = std::thread(ThreadMain);
    for (int i = 0; i < 50 && !g_running.load(); ++i) {
        Sleep(10);
    }
    return HDL_OK;
}

void Stop() {
    g_stop = true;
    if (g_stop_event) {
        SetEvent(g_stop_event);
    }
    HANDLE client = CreateFileW(PipeName().c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                                OPEN_EXISTING, 0, nullptr);
    if (client != INVALID_HANDLE_VALUE) {
        CloseHandle(client);
    }
    if (g_thread.joinable()) {
        g_thread.join();
    }
    if (g_stop_event) {
        CloseHandle(g_stop_event);
        g_stop_event = nullptr;
    }
}

void StopNoJoin() {
    g_stop = true;
    if (g_stop_event) {
        SetEvent(g_stop_event);
    }
    {
        std::lock_guard<std::mutex> lock(g_clients_mu);
        for (HANDLE h : g_client_pipes) {
            CancelIoEx(h, nullptr);
            DisconnectNamedPipe(h);
        }
    }
    if (g_thread.joinable()) {
        g_thread.detach();
    }
    /* Leave g_stop_event for the detached thread; do not close under loader lock. */
}

bool IsRunning() {
    return g_running.load();
}

}  // namespace ipc
}  // namespace hdl
