#include "call_dispatch.hpp"

#include "log.hpp"

#include <atomic>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <utility>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

namespace hdl {
namespace {

struct DispatchTicket {
    uint64_t call_id = 0;
    std::function<void()> execute;
    std::function<void()> cancel;
    std::function<void()> finished;
    std::atomic<uint32_t> state{0}; /* 0 queued, 1 running, 2 done */
};

struct WindowState {
    WNDPROC previous = nullptr;
    std::unordered_map<uint64_t, std::shared_ptr<DispatchTicket>> tickets;
};

std::mutex g_mu;
std::unordered_map<HWND, WindowState> g_windows;
std::once_flag g_message_once;
UINT g_call_message = 0;

UINT CallMessage() {
    std::call_once(g_message_once,
                   [] { g_call_message = RegisterWindowMessageW(L"hdllib.call.dispatch.v1"); });
    return g_call_message;
}

LRESULT CALLBACK DispatchWndProc(HWND hwnd, UINT message, WPARAM w_param, LPARAM l_param);

bool RestoreWindowLocked(HWND hwnd, WindowState& state) {
    if (!IsWindow(hwnd)) {
        return true;
    }
    if (!state.previous) {
        return false;
    }
    SetLastError(0);
    const LONG_PTR current = GetWindowLongPtrW(hwnd, GWLP_WNDPROC);
    if ((!current && GetLastError() != 0) ||
        current != reinterpret_cast<LONG_PTR>(DispatchWndProc)) {
        /* Another component extended the subclass chain after us. Replacing its
         * WndProc would be unsafe; keep our state and refuse module teardown. */
        return false;
    }
    SetLastError(0);
    const LONG_PTR replaced =
        SetWindowLongPtrW(hwnd, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(state.previous));
    return replaced != 0 || GetLastError() == 0;
}

LRESULT CALLBACK DispatchWndProc(HWND hwnd, UINT message, WPARAM w_param, LPARAM l_param) {
    (void)l_param;
    const UINT call_message = CallMessage();
    if (call_message && message == call_message) {
        const uint64_t call_id = static_cast<uint64_t>(w_param);
        std::shared_ptr<DispatchTicket> ticket;
        {
            std::lock_guard<std::mutex> lock(g_mu);
            const auto window = g_windows.find(hwnd);
            if (window != g_windows.end()) {
                const auto found = window->second.tickets.find(call_id);
                if (found != window->second.tickets.end()) {
                    ticket = found->second;
                }
            }
        }
        uint32_t queued = 0;
        if (!ticket || !ticket->state.compare_exchange_strong(queued, 1)) {
            return 0;
        }

        if (ticket->execute) {
            ticket->execute();
        }
        ticket->state.store(2);

        {
            std::lock_guard<std::mutex> lock(g_mu);
            const auto window = g_windows.find(hwnd);
            if (window != g_windows.end()) {
                window->second.tickets.erase(call_id);
                if (window->second.tickets.empty() && RestoreWindowLocked(hwnd, window->second)) {
                    g_windows.erase(window);
                }
            }
        }
        if (ticket->finished) {
            ticket->finished();
        }
        return 0;
    }

    WNDPROC previous = nullptr;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        const auto window = g_windows.find(hwnd);
        if (window != g_windows.end()) {
            previous = window->second.previous;
        }
    }
    const LRESULT result = previous ? CallWindowProcW(previous, hwnd, message, w_param, l_param)
                                    : DefWindowProcW(hwnd, message, w_param, l_param);

    if (message == WM_NCDESTROY) {
        std::vector<std::shared_ptr<DispatchTicket>> cancelled;
        {
            std::lock_guard<std::mutex> lock(g_mu);
            const auto window = g_windows.find(hwnd);
            if (window != g_windows.end()) {
                for (const auto& [id, ticket] : window->second.tickets) {
                    (void)id;
                    uint32_t queued = 0;
                    if (ticket->state.compare_exchange_strong(queued, 2)) {
                        cancelled.push_back(ticket);
                    }
                }
                g_windows.erase(window);
            }
        }
        for (const auto& ticket : cancelled) {
            if (ticket->cancel) {
                ticket->cancel();
            }
            if (ticket->finished) {
                ticket->finished();
            }
        }
    }
    return result;
}

struct EnumCtx {
    HWND best = nullptr;
    LONG best_area = -1;
};

BOOL CALLBACK EnumPrimary(HWND hwnd, LPARAM parameter) {
    auto* context = reinterpret_cast<EnumCtx*>(parameter);
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid != GetCurrentProcessId() || hwnd == GetConsoleWindow() || !IsWindow(hwnd) ||
        GetWindow(hwnd, GW_OWNER) != nullptr) {
        return TRUE;
    }
    RECT rect{};
    GetWindowRect(hwnd, &rect);
    LONG score = (rect.right - rect.left) * (rect.bottom - rect.top);
    if (!IsWindowVisible(hwnd)) {
        score -= 1000000000L;
    }
    if (score > context->best_area) {
        context->best_area = score;
        context->best = hwnd;
    }
    return TRUE;
}

} // namespace

HWND FindPrimaryWindow() {
    EnumCtx context;
    EnumWindows(EnumPrimary, reinterpret_cast<LPARAM>(&context));
    if (context.best) {
        return context.best;
    }
    struct AnyCtx {
        HWND hwnd = nullptr;
    } any;
    EnumWindows(
        [](HWND hwnd, LPARAM parameter) -> BOOL {
            auto* context = reinterpret_cast<AnyCtx*>(parameter);
            DWORD pid = 0;
            GetWindowThreadProcessId(hwnd, &pid);
            if (pid == GetCurrentProcessId() && hwnd != GetConsoleWindow()) {
                context->hwnd = hwnd;
                return FALSE;
            }
            return TRUE;
        },
        reinterpret_cast<LPARAM>(&any));
    return any.hwnd;
}

HdlStatus PostWindowCall(HWND hwnd, uint64_t call_id, std::function<void()> execute,
                         std::function<void()> cancel, std::function<void()> finished) {
    if (!hwnd || !IsWindow(hwnd) || !call_id || !execute || !cancel || !finished) {
        return HDL_E_INVALID_ARG;
    }
    const UINT message = CallMessage();
    if (!message) {
        return HDL_E_FAILED;
    }

    auto ticket = std::make_shared<DispatchTicket>();
    ticket->call_id = call_id;
    ticket->execute = std::move(execute);
    ticket->cancel = std::move(cancel);
    ticket->finished = std::move(finished);

    {
        std::lock_guard<std::mutex> lock(g_mu);
        auto window = g_windows.find(hwnd);
        if (window == g_windows.end()) {
            SetLastError(0);
            const LONG_PTR previous =
                SetWindowLongPtrW(hwnd, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(DispatchWndProc));
            if (!previous && GetLastError() != 0) {
                return HDL_E_FAILED;
            }
            WindowState state;
            state.previous = reinterpret_cast<WNDPROC>(previous);
            window = g_windows.emplace(hwnd, std::move(state)).first;
        }
        if (!window->second.tickets.emplace(call_id, ticket).second) {
            return HDL_E_BUSY;
        }
    }

    if (!PostMessageW(hwnd, message, static_cast<WPARAM>(call_id), 0)) {
        std::lock_guard<std::mutex> lock(g_mu);
        const auto window = g_windows.find(hwnd);
        if (window != g_windows.end()) {
            window->second.tickets.erase(call_id);
            if (window->second.tickets.empty() && RestoreWindowLocked(hwnd, window->second)) {
                g_windows.erase(window);
            }
        }
        return HDL_E_FAILED;
    }
    return HDL_OK;
}

HdlStatus CancelQueuedWindowCalls() {
    std::vector<std::shared_ptr<DispatchTicket>> cancelled;
    bool blocked = false;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        for (auto window = g_windows.begin(); window != g_windows.end();) {
            for (auto ticket = window->second.tickets.begin();
                 ticket != window->second.tickets.end();) {
                uint32_t queued = 0;
                if (ticket->second->state.compare_exchange_strong(queued, 2)) {
                    cancelled.push_back(ticket->second);
                    ticket = window->second.tickets.erase(ticket);
                } else {
                    if (ticket->second->state.load() == 1) {
                        blocked = true;
                    }
                    ++ticket;
                }
            }
            if (window->second.tickets.empty()) {
                if (RestoreWindowLocked(window->first, window->second)) {
                    window = g_windows.erase(window);
                } else {
                    blocked = true;
                    ++window;
                }
            } else {
                ++window;
            }
        }
    }
    for (const auto& ticket : cancelled) {
        if (ticket->cancel) {
            ticket->cancel();
        }
        if (ticket->finished) {
            ticket->finished();
        }
    }
    return blocked ? HDL_E_BUSY : HDL_OK;
}

void ResetWindowCallDispatcher() {
    (void)CancelQueuedWindowCalls();
}

} // namespace hdl
