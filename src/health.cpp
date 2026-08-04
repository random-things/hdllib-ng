#include "health.hpp"
#include "env.hpp"
#include "log.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <Psapi.h>
#include <TlHelp32.h>
#include <Windows.h>

#pragma comment(lib, "Psapi.lib")

namespace hdl {
namespace {

std::atomic<bool> g_health_ready{false};
PVOID g_veh = nullptr;

std::mutex g_event_mu;
std::condition_variable g_event_cv;
std::deque<HdlEvent> g_events;
constexpr size_t kMaxEvents = 256;

std::mutex g_exc_mu;
uint32_t g_last_exc_code = 0;
uint64_t g_last_exc_addr = 0;
uint64_t g_last_exc_tick = 0;

std::mutex g_cpu_mu;
ULONGLONG g_prev_tick = 0;
ULONGLONG g_prev_user = 0;
ULONGLONG g_prev_kernel = 0;
uint32_t g_cpu_percent = 0;

using NtQueryInformationThread_t = LONG(WINAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
constexpr ULONG ThreadQuerySetWin32StartAddress = 9;

uint64_t NowMs() {
    return GetTickCount64();
}

void PushEventUnlocked(const HdlEvent& ev) {
    if (g_events.size() >= kMaxEvents) {
        g_events.pop_front();
    }
    g_events.push_back(ev);
    g_event_cv.notify_all();
}

LONG CALLBACK ExceptionVeh(EXCEPTION_POINTERS* info) {
    if (!info || !info->ExceptionRecord) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    const EXCEPTION_RECORD* er = info->ExceptionRecord;
    // Record fatal-ish first-chance exceptions that assistants care about.
    const DWORD code = er->ExceptionCode;
    const bool interesting =
        code == EXCEPTION_ACCESS_VIOLATION || code == EXCEPTION_STACK_OVERFLOW ||
        code == EXCEPTION_ILLEGAL_INSTRUCTION || code == EXCEPTION_INT_DIVIDE_BY_ZERO ||
        code == EXCEPTION_PRIV_INSTRUCTION || code == EXCEPTION_IN_PAGE_ERROR ||
        code == EXCEPTION_ARRAY_BOUNDS_EXCEEDED || code == EXCEPTION_DATATYPE_MISALIGNMENT ||
        code == EXCEPTION_FLT_DIVIDE_BY_ZERO || code == EXCEPTION_BREAKPOINT;

    if (interesting) {
        HdlEvent ev{};
        ev.type = HDL_EVENT_EXCEPTION;
        ev.code = code;
        ev.timestamp_ms = NowMs();
        ev.address = reinterpret_cast<uint64_t>(er->ExceptionAddress);
        ev.detail = er->ExceptionFlags;
        {
            std::lock_guard<std::mutex> lock(g_exc_mu);
            g_last_exc_code = code;
            g_last_exc_addr = ev.address;
            g_last_exc_tick = ev.timestamp_ms;
        }
        {
            std::lock_guard<std::mutex> lock(g_event_mu);
            PushEventUnlocked(ev);
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

struct HungEnumCtx {
    DWORD pid = 0;
    bool hung = false;
};

BOOL CALLBACK HungEnumProc(HWND hwnd, LPARAM lp) {
    auto* ctx = reinterpret_cast<HungEnumCtx*>(lp);
    DWORD wpid = 0;
    GetWindowThreadProcessId(hwnd, &wpid);
    if (wpid != ctx->pid || !IsWindowVisible(hwnd)) {
        return TRUE;
    }
    // IsHungAppWindow is a strong signal; also probe with a short timeout.
    if (IsHungAppWindow(hwnd)) {
        ctx->hung = true;
        return FALSE;
    }
    DWORD_PTR result = 0;
    const LRESULT sm =
        SendMessageTimeoutW(hwnd, WM_NULL, 0, 0, SMTO_ABORTIFHUNG | SMTO_BLOCK, 200, &result);
    if (sm == 0) {
        ctx->hung = true;
        return FALSE;
    }
    return TRUE;
}

void SampleCpu(HANDLE process, FILETIME* out_user, FILETIME* out_kernel, uint32_t* out_percent) {
    FILETIME create{}, exit{}, kernel{}, user{};
    if (!GetProcessTimes(process, &create, &exit, &kernel, &user)) {
        *out_percent = 0;
        return;
    }
    *out_user = user;
    *out_kernel = kernel;

    ULARGE_INTEGER u{}, k{};
    u.LowPart = user.dwLowDateTime;
    u.HighPart = user.dwHighDateTime;
    k.LowPart = kernel.dwLowDateTime;
    k.HighPart = kernel.dwHighDateTime;

    const ULONGLONG now = GetTickCount64();
    std::lock_guard<std::mutex> lock(g_cpu_mu);
    if (g_prev_tick != 0 && now > g_prev_tick) {
        const ULONGLONG du = u.QuadPart - g_prev_user;
        const ULONGLONG dk = k.QuadPart - g_prev_kernel;
        const ULONGLONG dt_100ns = (now - g_prev_tick) * 10000ULL; // ms -> 100ns
        SYSTEM_INFO si{};
        GetSystemInfo(&si);
        const ULONGLONG capacity =
            dt_100ns * (si.dwNumberOfProcessors ? si.dwNumberOfProcessors : 1);
        if (capacity) {
            const ULONGLONG used = du + dk;
            uint32_t pct = static_cast<uint32_t>((used * 100ULL) / capacity);
            if (pct > 100) {
                pct = 100;
            }
            g_cpu_percent = pct;
        }
    }
    g_prev_tick = now;
    g_prev_user = u.QuadPart;
    g_prev_kernel = k.QuadPart;
    *out_percent = g_cpu_percent;
}

uint64_t QueryThreadStartAddress(HANDLE thread) {
    static NtQueryInformationThread_t fn = nullptr;
    static bool resolved = false;
    if (!resolved) {
        resolved = true;
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll) {
            fn = reinterpret_cast<NtQueryInformationThread_t>(
                GetProcAddress(ntdll, "NtQueryInformationThread"));
        }
    }
    if (!fn) {
        return 0;
    }
    PVOID start = nullptr;
    const LONG st = fn(thread, ThreadQuerySetWin32StartAddress, &start, sizeof(start), nullptr);
    return st >= 0 ? reinterpret_cast<uint64_t>(start) : 0;
}

} // namespace

HdlStatus SetHealthVeh(bool enabled) {
    if (enabled) {
        if (g_veh) {
            return HDL_OK;
        }
        g_veh = AddVectoredExceptionHandler(1, ExceptionVeh);
        if (!g_veh) {
            HDL_LOG_ERROR("AddVectoredExceptionHandler failed: %lu", GetLastError());
            return HDL_E_FAILED;
        }
        HDL_LOG_INFO("health VEH enabled");
        return HDL_OK;
    }
    if (g_veh) {
        RemoveVectoredExceptionHandler(g_veh);
        g_veh = nullptr;
        HDL_LOG_INFO("health VEH disabled");
    }
    return HDL_OK;
}

bool IsHealthVehEnabled() {
    return g_veh != nullptr;
}

HdlStatus HealthInit() {
    bool expected = false;
    if (!g_health_ready.compare_exchange_strong(expected, true)) {
        return HDL_OK;
    }
    /* VEH is opt-in: targets that walk the VEH list will not see us by default. */
    if (EnvFlag(L"HDL_HEALTH_VEH")) {
        if (SetHealthVeh(true) != HDL_OK) {
            g_health_ready = false;
            return HDL_E_FAILED;
        }
    }
    HDL_LOG_INFO("health monitor ready");
    return HDL_OK;
}

void HealthShutdown() {
    bool expected = true;
    if (!g_health_ready.compare_exchange_strong(expected, false)) {
        return;
    }
    SetHealthVeh(false);
    HealthClearEvents();
}

void HealthPushEvent(const HdlEvent* ev) {
    if (!ev) {
        return;
    }
    std::lock_guard<std::mutex> lock(g_event_mu);
    PushEventUnlocked(*ev);
}

void HealthClearEvents() {
    std::lock_guard<std::mutex> lock(g_event_mu);
    g_events.clear();
}

uint32_t HealthPollEvents(HdlEvent* out, uint32_t max_events, uint32_t timeout_ms) {
    /* First poll installs VEH so exception events can be captured when requested. */
    if (g_health_ready.load()) {
        SetHealthVeh(true);
    }
    std::unique_lock<std::mutex> lock(g_event_mu);
    if (g_events.empty() && timeout_ms > 0) {
        g_event_cv.wait_for(lock, std::chrono::milliseconds(timeout_ms),
                            [] { return !g_events.empty() || !g_health_ready.load(); });
    }
    uint32_t n = 0;
    while (n < max_events && !g_events.empty()) {
        if (out) {
            out[n] = g_events.front();
        }
        g_events.pop_front();
        ++n;
    }
    return n;
}

HdlStatus GetHealth(HdlHealthInfo* out) {
    if (!out) {
        return HDL_E_INVALID_ARG;
    }
    memset(out, 0, sizeof(*out));
    out->pid = GetCurrentProcessId();

    PROCESS_MEMORY_COUNTERS_EX pmc{};
    if (GetProcessMemoryInfo(GetCurrentProcess(), reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc),
                             sizeof(pmc))) {
        out->working_set = pmc.WorkingSetSize;
        out->private_bytes = pmc.PrivateUsage;
    }

    DWORD handle_count = 0;
    if (GetProcessHandleCount(GetCurrentProcess(), &handle_count)) {
        out->handle_count = handle_count;
    }

    FILETIME user{}, kernel{};
    SampleCpu(GetCurrentProcess(), &user, &kernel, &out->cpu_percent);
    {
        ULARGE_INTEGER u{}, k{};
        u.LowPart = user.dwLowDateTime;
        u.HighPart = user.dwHighDateTime;
        k.LowPart = kernel.dwLowDateTime;
        k.HighPart = kernel.dwHighDateTime;
        out->user_time_100ns = u.QuadPart;
        out->kernel_time_100ns = k.QuadPart;
    }

    uint32_t threads = 0;
    EnumThreads(nullptr, &threads);
    out->thread_count = threads;

    HungEnumCtx hung{};
    hung.pid = out->pid;
    EnumWindows(HungEnumProc, reinterpret_cast<LPARAM>(&hung));
    out->gui_hung = hung.hung ? 1u : 0u;

    {
        std::lock_guard<std::mutex> lock(g_exc_mu);
        out->last_exception_code = g_last_exc_code;
        out->last_exception_addr = g_last_exc_addr;
        out->last_exception_tick_ms = g_last_exc_tick;
    }

    if (out->gui_hung) {
        out->flags |= HDL_HEALTH_GUI_HUNG;
    }
    if (out->cpu_percent >= 85) {
        out->flags |= HDL_HEALTH_HIGH_CPU;
    }
    if (out->last_exception_code && (NowMs() - out->last_exception_tick_ms) < 60000) {
        out->flags |= HDL_HEALTH_RECENT_EXCEPTION;
    }
    return HDL_OK;
}

HdlStatus EnumThreads(HdlThreadInfo* out, uint32_t* inout_count) {
    if (!inout_count) {
        return HDL_E_INVALID_ARG;
    }
    const DWORD pid = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        return HDL_E_FAILED;
    }

    std::vector<HdlThreadInfo> list;
    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) {
                continue;
            }
            HdlThreadInfo info{};
            info.tid = te.th32ThreadID;
            HANDLE th = OpenThread(THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME, FALSE,
                                   te.th32ThreadID);
            if (th) {
                FILETIME create{}, exit{}, kernel{}, user{};
                if (GetThreadTimes(th, &create, &exit, &kernel, &user)) {
                    ULARGE_INTEGER u{}, k{};
                    u.LowPart = user.dwLowDateTime;
                    u.HighPart = user.dwHighDateTime;
                    k.LowPart = kernel.dwLowDateTime;
                    k.HighPart = kernel.dwHighDateTime;
                    info.user_time_100ns = u.QuadPart;
                    info.kernel_time_100ns = k.QuadPart;
                }
                info.start_address = QueryThreadStartAddress(th);
                // Suspend count probe: Suspend/Resume is invasive; leave 0 unless we can query.
                info.suspend_count = 0;
                CloseHandle(th);
            }
            list.push_back(info);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);

    const uint32_t need = static_cast<uint32_t>(list.size());
    if (!out || *inout_count < need) {
        *inout_count = need;
        return HDL_E_BUFFER_SMALL;
    }
    if (need) {
        memcpy(out, list.data(), need * sizeof(HdlThreadInfo));
    }
    *inout_count = need;
    return HDL_OK;
}

} // namespace hdl
