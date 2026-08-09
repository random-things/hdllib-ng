#include "call_registry.hpp"

#include "health.hpp"
#include "win/raii.hpp"

#include <algorithm>
#include <atomic>
#include <deque>
#include <mutex>
#include <unordered_map>

namespace hdl {

struct CallRecord {
    HdlCallInfo info{};
    win::unique_handle completion_event;
    win::unique_handle worker_thread;
    bool waiter_attached = true;
    bool execution_exited = false;
};

namespace {

constexpr size_t kMaxActiveCalls = 64;
constexpr size_t kMaxRecentCalls = 256;
constexpr uint64_t kRecentRetentionMs = 10ull * 60ull * 1000ull;

std::mutex g_mu;
std::unordered_map<uint64_t, std::shared_ptr<CallRecord>> g_active;
std::deque<std::shared_ptr<CallRecord>> g_recent;
std::atomic<uint64_t> g_next_call_id{1};
bool g_accepting_calls = false;

uint64_t NextCallId() {
    uint64_t id = g_next_call_id.fetch_add(1);
    if (id == 0) {
        id = g_next_call_id.fetch_add(1);
    }
    return id;
}

bool IsTerminal(const HdlCallInfo& info) {
    return info.phase == HDL_CALL_PHASE_COMPLETED ||
           info.phase == HDL_CALL_PHASE_CANCELLED_BEFORE_START;
}

bool IsOrphaned(const HdlCallInfo& info) {
    return (info.flags & HDL_CALL_INFO_ORPHANED) != 0;
}

bool IsAcknowledged(const HdlCallInfo& info) {
    return (info.flags & HDL_CALL_INFO_ACKNOWLEDGED) != 0;
}

bool BlocksOverlap(const HdlCallInfo& info) {
    return !IsTerminal(info) && !IsAcknowledged(info);
}

void PushCallEvent(uint32_t type, const HdlCallInfo& info, uint32_t code) {
    HdlEvent event{};
    event.type = type;
    event.code = code;
    event.timestamp_ms = GetTickCount64();
    event.address = info.target_address;
    event.detail = info.call_id;
    HealthPushEvent(&event);
}

void PruneRecentLocked() {
    const uint64_t now = GetTickCount64();
    std::erase_if(g_recent, [now](const std::shared_ptr<CallRecord>& record) {
        return record->info.finished_tick_ms &&
               now - record->info.finished_tick_ms >= kRecentRetentionMs;
    });
    while (g_recent.size() > kMaxRecentCalls) {
        const auto acknowledged =
            std::find_if(g_recent.begin(), g_recent.end(),
                         [](const auto& record) { return IsAcknowledged(record->info); });
        if (acknowledged != g_recent.end()) {
            g_recent.erase(acknowledged);
        } else {
            g_recent.pop_front();
        }
    }
}

void MoveToRecentLocked(const std::shared_ptr<CallRecord>& record) {
    if (!record || !IsTerminal(record->info) || !record->execution_exited) {
        return;
    }
    const auto found = g_active.find(record->info.call_id);
    if (found == g_active.end()) {
        return;
    }
    if (record->worker_thread && record->waiter_attached) {
        return;
    }
    if (record->worker_thread) {
        if (WaitForSingleObject(record->worker_thread.get(), 0) != WAIT_OBJECT_0) {
            return;
        }
        record->worker_thread.reset();
    }
    g_active.erase(found);
    g_recent.push_back(record);
    PruneRecentLocked();
}

void ReapCompletedLocked() {
    std::vector<std::shared_ptr<CallRecord>> candidates;
    candidates.reserve(g_active.size());
    for (const auto& [id, record] : g_active) {
        (void)id;
        if (IsTerminal(record->info)) {
            if (record->worker_thread && !record->waiter_attached &&
                WaitForSingleObject(record->worker_thread.get(), 0) == WAIT_OBJECT_0) {
                record->execution_exited = true;
            }
            candidates.push_back(record);
        }
    }
    for (const auto& record : candidates) {
        MoveToRecentLocked(record);
    }
    PruneRecentLocked();
}

uint32_t CountUnacknowledgedOrphansLocked() {
    uint32_t count = 0;
    for (const auto& [id, record] : g_active) {
        (void)id;
        if (IsOrphaned(record->info) && !IsAcknowledged(record->info) &&
            !IsTerminal(record->info)) {
            ++count;
        }
    }
    return count;
}

std::shared_ptr<CallRecord> FindLocked(uint64_t call_id) {
    const auto active = g_active.find(call_id);
    if (active != g_active.end()) {
        return active->second;
    }
    for (auto it = g_recent.rbegin(); it != g_recent.rend(); ++it) {
        if ((*it)->info.call_id == call_id) {
            return *it;
        }
    }
    return nullptr;
}

DWORD WaitSlice(HANDLE handle, uint32_t timeout_ms, volatile int* cancel) {
    const uint64_t start = GetTickCount64();
    for (;;) {
        if (cancel && *cancel) {
            return WAIT_ABANDONED;
        }
        DWORD slice = 50;
        if (timeout_ms) {
            const uint64_t elapsed = GetTickCount64() - start;
            if (elapsed >= timeout_ms) {
                return WAIT_TIMEOUT;
            }
            slice = static_cast<DWORD>((std::min<uint64_t>)(slice, timeout_ms - elapsed));
        }
        const DWORD wait = WaitForSingleObject(handle, slice);
        if (wait == WAIT_OBJECT_0 || wait == WAIT_FAILED) {
            return wait;
        }
    }
}

} // namespace

void CallRegistryInit() {
    std::lock_guard<std::mutex> lock(g_mu);
    ReapCompletedLocked();
    if (g_active.empty()) {
        g_recent.clear();
        g_accepting_calls = true;
    }
}

CallReservation ReserveCall(uint64_t target_address, uint32_t thread_mode) {
    CallReservation result;
    std::lock_guard<std::mutex> lock(g_mu);
    ReapCompletedLocked();
    result.unacknowledged_orphan_count = CountUnacknowledgedOrphansLocked();
    if (!g_accepting_calls) {
        result.status = HDL_E_NOT_INIT;
        return result;
    }
    for (const auto& [id, existing] : g_active) {
        (void)id;
        if (existing->info.target_address == target_address && BlocksOverlap(existing->info)) {
            result.status = HDL_E_BUSY;
            result.blocking_call_id = existing->info.call_id;
            return result;
        }
    }
    if (g_active.size() >= kMaxActiveCalls) {
        result.status = HDL_E_BUSY;
        return result;
    }
    auto record = std::make_shared<CallRecord>();
    record->completion_event.reset(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!record->completion_event) {
        result.status = HDL_E_FAILED;
        return result;
    }
    record->info.call_id = NextCallId();
    record->info.target_address = target_address;
    record->info.created_tick_ms = GetTickCount64();
    record->info.thread_mode = thread_mode;
    record->info.phase = HDL_CALL_PHASE_QUEUED;
    record->info.wait_status = HDL_OK;
    record->info.completion_status = HDL_OK;
    g_active.emplace(record->info.call_id, record);
    result.status = HDL_OK;
    result.record = std::move(record);
    return result;
}

void SetCallThread(const std::shared_ptr<CallRecord>& record, HANDLE thread, uint32_t thread_id) {
    if (!record) {
        if (thread) {
            CloseHandle(thread);
        }
        return;
    }
    std::lock_guard<std::mutex> lock(g_mu);
    record->worker_thread.reset(thread);
    record->info.thread_id = thread_id;
}

bool BeginCallExecution(const std::shared_ptr<CallRecord>& record, uint32_t thread_id) {
    if (!record) {
        return false;
    }
    HdlCallInfo completed{};
    bool cancelled = false;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        if (record->info.phase != HDL_CALL_PHASE_QUEUED) {
            return false;
        }
        record->info.thread_id = thread_id;
        if (IsOrphaned(record->info)) {
            record->info.phase = HDL_CALL_PHASE_CANCELLED_BEFORE_START;
            record->info.finished_tick_ms = GetTickCount64();
            record->info.completion_status = HDL_E_CANCELLED;
            completed = record->info;
            cancelled = true;
        } else {
            record->info.phase = HDL_CALL_PHASE_RUNNING;
            record->info.started_tick_ms = GetTickCount64();
        }
    }
    if (cancelled) {
        PushCallEvent(HDL_EVENT_CALL_COMPLETED, completed, HDL_E_CANCELLED);
    }
    return !cancelled;
}

void CompleteCallExecution(const std::shared_ptr<CallRecord>& record, HdlStatus status,
                           uint64_t return_value, uint32_t last_error) {
    if (!record) {
        return;
    }
    HdlCallInfo completed{};
    bool emit = false;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        if (IsTerminal(record->info)) {
            return;
        }
        record->info.phase = HDL_CALL_PHASE_COMPLETED;
        record->info.finished_tick_ms = GetTickCount64();
        record->info.completion_status = status;
        record->info.return_value = return_value;
        record->info.last_error = last_error;
        emit = IsOrphaned(record->info);
        completed = record->info;
    }
    if (emit) {
        PushCallEvent(HDL_EVENT_CALL_COMPLETED, completed, static_cast<uint32_t>(status));
    }
}

void SignalCallCompletion(const std::shared_ptr<CallRecord>& record) {
    if (record && record->completion_event) {
        SetEvent(record->completion_event.get());
    }
}

HdlStatus WaitForCallWorker(const std::shared_ptr<CallRecord>& record, uint32_t timeout_ms,
                            volatile int* cancel) {
    if (!record || !record->worker_thread) {
        return HDL_E_FAILED;
    }
    const DWORD wait = WaitSlice(record->worker_thread.get(), timeout_ms, cancel);
    if (wait == WAIT_OBJECT_0) {
        return HDL_OK;
    }
    if (wait == WAIT_TIMEOUT) {
        return HDL_E_TIMEOUT;
    }
    if (wait == WAIT_ABANDONED) {
        return HDL_E_CANCELLED;
    }
    return HDL_E_FAILED;
}

HdlStatus WaitForCallDispatch(const std::shared_ptr<CallRecord>& record, uint32_t timeout_ms,
                              volatile int* cancel) {
    if (!record || !record->completion_event) {
        return HDL_E_FAILED;
    }
    const DWORD wait = WaitSlice(record->completion_event.get(), timeout_ms, cancel);
    if (wait == WAIT_OBJECT_0) {
        return HDL_OK;
    }
    if (wait == WAIT_TIMEOUT) {
        return HDL_E_TIMEOUT;
    }
    if (wait == WAIT_ABANDONED) {
        return HDL_E_CANCELLED;
    }
    return HDL_E_FAILED;
}

bool MarkCallWaitAbandoned(const std::shared_ptr<CallRecord>& record, HdlStatus wait_status) {
    if (!record) {
        return false;
    }
    HdlCallInfo orphan{};
    bool emit = false;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        record->waiter_attached = false;
        if (!IsTerminal(record->info) && !IsOrphaned(record->info)) {
            record->info.flags |= HDL_CALL_INFO_ORPHANED;
            record->info.wait_status = wait_status;
            orphan = record->info;
            emit = true;
        }
    }
    if (emit) {
        PushCallEvent(HDL_EVENT_CALL_ORPHANED, orphan, static_cast<uint32_t>(wait_status));
    }
    return emit;
}

void FinishSynchronousCall(const std::shared_ptr<CallRecord>& record) {
    if (!record) {
        return;
    }
    std::lock_guard<std::mutex> lock(g_mu);
    record->waiter_attached = false;
    if (record->worker_thread &&
        WaitForSingleObject(record->worker_thread.get(), 0) == WAIT_OBJECT_0) {
        record->execution_exited = true;
    }
    MoveToRecentLocked(record);
}

void MarkCallExecutionExited(const std::shared_ptr<CallRecord>& record) {
    if (!record) {
        return;
    }
    std::lock_guard<std::mutex> lock(g_mu);
    record->execution_exited = true;
    MoveToRecentLocked(record);
}

void CancelQueuedCall(const std::shared_ptr<CallRecord>& record) {
    if (!record) {
        return;
    }
    HdlCallInfo completed{};
    bool emit = false;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        if (record->info.phase != HDL_CALL_PHASE_QUEUED) {
            return;
        }
        record->info.phase = HDL_CALL_PHASE_CANCELLED_BEFORE_START;
        record->info.finished_tick_ms = GetTickCount64();
        record->info.completion_status = HDL_E_CANCELLED;
        completed = record->info;
        emit = IsOrphaned(record->info);
    }
    if (emit) {
        PushCallEvent(HDL_EVENT_CALL_COMPLETED, completed, HDL_E_CANCELLED);
    }
    SignalCallCompletion(record);
}

void RollbackCall(const std::shared_ptr<CallRecord>& record) {
    if (!record) {
        return;
    }
    std::lock_guard<std::mutex> lock(g_mu);
    g_active.erase(record->info.call_id);
}

HdlCallInfo SnapshotCall(const std::shared_ptr<CallRecord>& record) {
    if (!record) {
        return {};
    }
    std::lock_guard<std::mutex> lock(g_mu);
    return record->info;
}

uint64_t CallRecordId(const std::shared_ptr<CallRecord>& record) {
    return record ? record->info.call_id : 0;
}

HdlStatus EnumCallOrphans(std::vector<HdlCallInfo>* out) {
    if (!out) {
        return HDL_E_INVALID_ARG;
    }
    std::lock_guard<std::mutex> lock(g_mu);
    ReapCompletedLocked();
    out->clear();
    for (const auto& [id, record] : g_active) {
        (void)id;
        if (IsOrphaned(record->info)) {
            out->push_back(record->info);
        }
    }
    for (const auto& record : g_recent) {
        if (IsOrphaned(record->info)) {
            out->push_back(record->info);
        }
    }
    std::sort(out->begin(), out->end(),
              [](const HdlCallInfo& a, const HdlCallInfo& b) { return a.call_id < b.call_id; });
    return HDL_OK;
}

HdlStatus GetCallStatus(uint64_t call_id, HdlCallInfo* out) {
    if (!call_id || !out) {
        return HDL_E_INVALID_ARG;
    }
    std::lock_guard<std::mutex> lock(g_mu);
    ReapCompletedLocked();
    const auto record = FindLocked(call_id);
    if (!record) {
        return HDL_E_NOT_FOUND;
    }
    *out = record->info;
    return HDL_OK;
}

HdlStatus AcknowledgeCallOrphan(uint64_t call_id, HdlCallInfo* out) {
    if (!call_id) {
        return HDL_E_INVALID_ARG;
    }
    std::lock_guard<std::mutex> lock(g_mu);
    ReapCompletedLocked();
    const auto record = FindLocked(call_id);
    if (!record) {
        return HDL_E_NOT_FOUND;
    }
    if (!IsOrphaned(record->info)) {
        return HDL_E_INVALID_ARG;
    }
    record->info.flags |= HDL_CALL_INFO_ACKNOWLEDGED;
    if (out) {
        *out = record->info;
    }
    return HDL_OK;
}

uint32_t UnacknowledgedCallOrphanCount() {
    std::lock_guard<std::mutex> lock(g_mu);
    ReapCompletedLocked();
    return CountUnacknowledgedOrphansLocked();
}

HdlStatus CallRegistryTryBeginShutdown() {
    std::lock_guard<std::mutex> lock(g_mu);
    g_accepting_calls = false;
    ReapCompletedLocked();
    /* Any active record can still have a waiter, worker epilogue, UI callback, or
     * record-owned buffers live in this module. Do not tear those resources down. */
    if (!g_active.empty()) {
        return HDL_E_BUSY;
    }
    return HDL_OK;
}

void CallRegistryAbortShutdown() {
    std::lock_guard<std::mutex> lock(g_mu);
    g_accepting_calls = true;
}

void CallRegistryShutdown() {
    std::lock_guard<std::mutex> lock(g_mu);
    ReapCompletedLocked();
    g_active.clear();
    g_recent.clear();
    g_accepting_calls = false;
}

} // namespace hdl
