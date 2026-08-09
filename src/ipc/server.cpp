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
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <system_error>
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
std::atomic<uint32_t> g_start_attempts{0};
std::atomic<DWORD> g_start_last_error{ERROR_SUCCESS};
std::atomic<uint64_t> g_start_elapsed_ms{0};
hdl::win::unique_handle g_stop_event;
std::thread g_thread;

/* The listener runs on a fresh thread and can be delayed by loader/CI contention.
 * A 500 ms polling window can make a healthy first bootstrap fail while an immediate
 * retry succeeds. Keep the wait bounded, but allow transient setup retries. */
constexpr DWORD kStartupTimeoutMs = 5000;

void EmitStartupFailureDiagnostic(const char* reason) {
    char message[320];
    _snprintf_s(
        message, _TRUNCATE,
        "[ERROR] IPC bootstrap failed reason=%s attempts=%u last_error=%lu "
        "accept_alive=%d elapsed_ms=%llu\n",
        reason, g_start_attempts.load(), static_cast<unsigned long>(g_start_last_error.load()),
        g_accept_alive.load() ? 1 : 0, static_cast<unsigned long long>(g_start_elapsed_ms.load()));
    OutputDebugStringA(message);
}

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
    const uint64_t started_ms = GetTickCount64();
    const std::wstring name = PipeName();
    HDL_LOG_INFO("IPC server starting on %ls (multi-client, ACL)", name.c_str());

    while (!g_stop.load()) {
        g_start_attempts.fetch_add(1);
        std::vector<uint8_t> sd_storage;
        SECURITY_ATTRIBUTES* sa = BuildPipeSa(sd_storage);
        if (!sa) {
            DWORD err = GetLastError();
            if (err == ERROR_SUCCESS) {
                err = ERROR_INVALID_SECURITY_DESCR;
            }
            g_start_last_error.store(err);
            g_start_elapsed_ms.store(GetTickCount64() - started_ms);
            HDL_LOG_ERROR("IPC startup ACL construction failed: %lu (attempt=%u)", err,
                          g_start_attempts.load());
            Sleep(200);
            continue;
        }

        hdl::win::unique_handle pipe(
            CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                             PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                             PIPE_UNLIMITED_INSTANCES, 64 * 1024, 64 * 1024, 0, sa));

        if (!pipe) {
            const DWORD err = GetLastError();
            g_start_last_error.store(err);
            g_start_elapsed_ms.store(GetTickCount64() - started_ms);
            HDL_LOG_ERROR("CreateNamedPipeW failed: %lu (attempt=%u)", err,
                          g_start_attempts.load());
            Sleep(200);
            continue;
        }

        OVERLAPPED ov{};
        hdl::win::unique_handle ov_event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        if (!ov_event) {
            const DWORD err = GetLastError();
            g_start_last_error.store(err);
            g_start_elapsed_ms.store(GetTickCount64() - started_ms);
            HDL_LOG_ERROR("IPC listener event creation failed: %lu (attempt=%u)", err,
                          g_start_attempts.load());
            Sleep(200);
            continue;
        }
        ov.hEvent = ov_event.get();
        const BOOL connect_started = ConnectNamedPipe(pipe.get(), &ov);
        const DWORD err = connect_started ? ERROR_SUCCESS : GetLastError();

        bool connected = false;
        bool listening = false;
        if (connect_started || err == ERROR_PIPE_CONNECTED) {
            connected = true;
            listening = true;
        } else if (err == ERROR_IO_PENDING) {
            listening = true;
        } else {
            g_start_last_error.store(err);
            g_start_elapsed_ms.store(GetTickCount64() - started_ms);
            HDL_LOG_ERROR("ConnectNamedPipe failed: %lu (attempt=%u)", err,
                          g_start_attempts.load());
            Sleep(200);
            continue;
        }

        if (listening) {
            /* First established listen operation — the endpoint is now connectable. */
            g_start_last_error.store(ERROR_SUCCESS);
            g_start_elapsed_ms.store(GetTickCount64() - started_ms);
            g_ready = true;
            g_running = true;
        }

        if (err == ERROR_IO_PENDING) {
            HANDLE waits[2] = {ov.hEvent, g_stop_event.get()};
            const DWORD wr = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
            if (wr == WAIT_OBJECT_0) {
                connected = true;
            } else {
                CancelIoEx(pipe.get(), &ov);
                break;
            }
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
    g_start_attempts = 0;
    g_start_last_error = ERROR_SUCCESS;
    g_start_elapsed_ms = 0;
    if (!g_stop_event) {
        g_stop_event.reset(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    } else {
        ResetEvent(g_stop_event.get());
    }
    if (!g_stop_event) {
        const DWORD err = GetLastError();
        HDL_LOG_ERROR("IPC startup failed to create stop event: %lu", err);
        g_start_last_error.store(err);
        EmitStartupFailureDiagnostic("stop-event");
        SetLastError(err);
        return HDL_E_FAILED;
    }
    try {
        g_thread = std::thread(ThreadMain);
    } catch (const std::system_error& error) {
        const DWORD code = static_cast<DWORD>(error.code().value());
        g_start_last_error.store(code);
        HDL_LOG_ERROR("IPC startup failed to create listener thread: code=%lu message=%s",
                      static_cast<unsigned long>(code), error.what());
        EmitStartupFailureDiagnostic("listener-thread");
        SetLastError(code);
        return HDL_E_FAILED;
    }
    for (DWORD elapsed = 0; elapsed < kStartupTimeoutMs && !g_ready.load(); elapsed += 10) {
        Sleep(10);
    }
    if (!g_ready.load()) {
        DWORD startup_error = g_start_last_error.load();
        if (startup_error == ERROR_SUCCESS) {
            startup_error = ERROR_TIMEOUT;
            g_start_last_error.store(startup_error);
        }
        HDL_LOG_ERROR("IPC server failed to become ready timeout_ms=%lu attempts=%u "
                      "last_error=%lu accept_alive=%d observed_elapsed_ms=%llu",
                      static_cast<unsigned long>(kStartupTimeoutMs), g_start_attempts.load(),
                      static_cast<unsigned long>(g_start_last_error.load()),
                      g_accept_alive.load() ? 1 : 0,
                      static_cast<unsigned long long>(g_start_elapsed_ms.load()));
        EmitStartupFailureDiagnostic("readiness-timeout");
        SignalStop();
        WaitAcceptThreadExit();
        SetLastError(startup_error);
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
