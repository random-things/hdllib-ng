#include "server.hpp"

#include "common.hpp"
#include "core.hpp"
#include "dispatch.hpp"
#include "framing.hpp"
#include "hdllib/pipe_name.h"
#include "log.hpp"
#include "rpc/runtime.hpp"
#include "win/raii.hpp"

#include <array>
#include <atomic>
#include <cstring>
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
hdl::win::unique_handle g_stop_event;
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
        SetEvent(g_stop_event.get());
    }
    HANDLE client = HdlOpenLocalPipe(GetCurrentProcessId());
    if (client != INVALID_HANDLE_VALUE) {
        CloseHandle(client);
    }
}

void WaitAcceptThreadExit() {
    for (int i = 0; i < 250 && g_accept_alive.load(); ++i) {
        if (g_stop_event) {
            SetEvent(g_stop_event.get());
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

    std::array<char, rpc::kConnectionPrefaceSize> preface{};
    std::vector<uint8_t> hello_frame;
    ::hdl::rpc::v1::Envelope hello;
    const bool preface_valid =
        ReadExact(pipe, preface.data(), static_cast<DWORD>(preface.size())) &&
        std::memcmp(preface.data(), rpc::kConnectionPreface, preface.size()) == 0;
    bool handshake_frame_too_large = false;
    const bool frame_read =
        preface_valid && ReadFrame(pipe, hello_frame, &handshake_frame_too_large);
    const bool hello_valid = frame_read &&
                             rpc::ParseEnvelope(hello_frame.data(), hello_frame.size(), &hello) &&
                             hello.has_client_hello();
    if (preface_valid && !hello_valid) {
        if (handshake_frame_too_large) {
            (void)rpc::WriteGoAway(pipe, rpc::v1::RPC_CODE_RESOURCE_EXHAUSTED, HDL_E_INVALID_ARG,
                                   "FRAME_TOO_LARGE", "Handshake frame exceeds the server limit");
        } else {
            (void)rpc::WriteGoAway(pipe, rpc::v1::RPC_CODE_DATA_LOSS, HDL_E_FAILED,
                                   "INVALID_HANDSHAKE", "Expected a protobuf ClientHello envelope");
        }
    }
    // Even on a major mismatch, identify the server version so the client can
    // report a useful negotiation error before this connection is closed.
    const bool hello_sent = hello_valid && rpc::WriteServerHello(pipe);
    const bool negotiated =
        hello_sent && hello.client_hello().protocol_major() == rpc::kProtocolMajor;

    while (negotiated && !g_stop.load()) {
        std::vector<uint8_t> req;
        bool frame_too_large = false;
        if (!ReadFrame(pipe, req, &frame_too_large)) {
            if (frame_too_large) {
                (void)rpc::WriteGoAway(pipe, rpc::v1::RPC_CODE_RESOURCE_EXHAUSTED,
                                       HDL_E_INVALID_ARG, "FRAME_TOO_LARGE",
                                       "Request frame exceeds the negotiated limit");
            }
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

        hdl::win::unique_handle pipe(
            CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                             PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                             PIPE_UNLIMITED_INSTANCES, 64 * 1024, 64 * 1024, 0, sa));

        if (!pipe) {
            HDL_LOG_ERROR("CreateNamedPipeW failed: %lu", GetLastError());
            Sleep(200);
            continue;
        }

        /* First successful listen instance — server is usable for connects. */
        g_ready = true;
        g_running = true;

        OVERLAPPED ov{};
        hdl::win::unique_handle ov_event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        ov.hEvent = ov_event.get();
        ConnectNamedPipe(pipe.get(), &ov);
        DWORD err = GetLastError();

        bool connected = false;
        if (err == ERROR_PIPE_CONNECTED) {
            connected = true;
        } else if (err == ERROR_IO_PENDING) {
            HANDLE waits[2] = {ov.hEvent, g_stop_event.get()};
            const DWORD wr = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
            if (wr == WAIT_OBJECT_0) {
                connected = true;
            } else {
                CancelIoEx(pipe.get(), &ov);
                break;
            }
        } else {
            HDL_LOG_ERROR("ConnectNamedPipe failed: %lu", err);
            continue;
        }

        ov_event.reset();

        if (!connected || g_stop.load()) {
            break;
        }

        SpawnWorker(pipe.release());
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
        g_stop_event.reset(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    } else {
        ResetEvent(g_stop_event.get());
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
    g_stop_event.reset();
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
     * Detach so the ServeClient Control.Shutdown path does not join its own accept thread.
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
