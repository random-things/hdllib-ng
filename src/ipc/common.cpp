#include "common.hpp"

#include "discover.hpp"
#include "memory.hpp"

#include <atomic>
#include <mutex>
#include <unordered_map>

namespace hdl {
namespace ipc {
namespace {

std::mutex g_sessions_mu;
std::unordered_map<uint64_t, std::shared_ptr<SearchSessionHolder>> g_sessions;
std::atomic<uint64_t> g_next_session_id{1};

std::mutex g_discover_mu;
std::unordered_map<uint64_t, std::shared_ptr<DiscoverSessionHolder>> g_discover;
std::atomic<uint64_t> g_next_discover_id{1};

void CloseSearchHolder(const std::shared_ptr<SearchSessionHolder>& holder) {
    if (!holder) {
        return;
    }
    std::lock_guard<std::mutex> lock(holder->mu);
    if (holder->session) {
        SearchClose(holder->session);
        holder->session = nullptr;
    }
}

void CloseDiscoverHolder(const std::shared_ptr<DiscoverSessionHolder>& holder) {
    if (!holder) {
        return;
    }
    std::lock_guard<std::mutex> lock(holder->mu);
    if (holder->session) {
        DiscoverClose(holder->session);
        holder->session = nullptr;
    }
}

} // namespace

bool WriteFrame(HANDLE pipe, const std::vector<uint8_t>& resp) {
    return WriteFrameBytes(pipe, resp.data(), static_cast<uint32_t>(resp.size()));
}

void TakeOptionalJobTimeoutFlags(proto::Reader& r, uint64_t* job_id, uint32_t* timeout_ms,
                                 uint32_t* flags) {
    if (job_id) {
        *job_id = 0;
    }
    if (timeout_ms) {
        *timeout_ms = 0;
    }
    if (flags) {
        *flags = 0;
    }
    if (job_id && r.left >= sizeof(uint64_t)) {
        r.TakePod(*job_id);
    }
    if (timeout_ms && r.left >= sizeof(uint32_t)) {
        r.TakePod(*timeout_ms);
    }
    if (flags && r.left >= sizeof(uint32_t)) {
        r.TakePod(*flags);
    }
}

std::shared_ptr<Job> BindJob(uint64_t job_id, uint32_t timeout_ms) {
    if (job_id) {
        auto existing = JobFind(job_id);
        if (existing && timeout_ms && existing->deadline_tick == 0) {
            existing->timeout_ms = timeout_ms;
            existing->deadline_tick = GetTickCount64() + timeout_ms;
        }
        return existing;
    }
    if (timeout_ms) {
        return JobCreate(timeout_ms);
    }
    return nullptr;
}

std::shared_ptr<SearchSessionHolder> FindSession(uint64_t id) {
    std::lock_guard<std::mutex> lock(g_sessions_mu);
    const auto it = g_sessions.find(id);
    return it == g_sessions.end() ? nullptr : it->second;
}

std::shared_ptr<DiscoverSessionHolder> FindDiscover(uint64_t id) {
    std::lock_guard<std::mutex> lock(g_discover_mu);
    const auto it = g_discover.find(id);
    return it == g_discover.end() ? nullptr : it->second;
}

uint64_t AllocSearchSession(HdlSearchSession* session) {
    auto holder = std::make_shared<SearchSessionHolder>();
    holder->session = session;
    const uint64_t id = g_next_session_id.fetch_add(1);
    {
        std::lock_guard<std::mutex> lock(g_sessions_mu);
        g_sessions[id] = holder;
    }
    return id;
}

std::shared_ptr<SearchSessionHolder> TakeSearchSession(uint64_t id) {
    std::lock_guard<std::mutex> lock(g_sessions_mu);
    const auto it = g_sessions.find(id);
    if (it == g_sessions.end()) {
        return nullptr;
    }
    auto holder = it->second;
    g_sessions.erase(it);
    return holder;
}

void CloseAllSessions() {
    std::unordered_map<uint64_t, std::shared_ptr<SearchSessionHolder>> local;
    {
        std::lock_guard<std::mutex> lock(g_sessions_mu);
        local.swap(g_sessions);
    }
    for (auto& kv : local) {
        CloseSearchHolder(kv.second);
    }
}

uint64_t AllocDiscoverSession(HdlDiscoverSession* session) {
    auto holder = std::make_shared<DiscoverSessionHolder>();
    holder->session = session;
    const uint64_t id = g_next_discover_id.fetch_add(1);
    {
        std::lock_guard<std::mutex> lock(g_discover_mu);
        g_discover[id] = holder;
    }
    return id;
}

std::shared_ptr<DiscoverSessionHolder> TakeDiscoverSession(uint64_t id) {
    std::lock_guard<std::mutex> lock(g_discover_mu);
    const auto it = g_discover.find(id);
    if (it == g_discover.end()) {
        return nullptr;
    }
    auto holder = it->second;
    g_discover.erase(it);
    return holder;
}

void CloseAllDiscoverSessions() {
    std::unordered_map<uint64_t, std::shared_ptr<DiscoverSessionHolder>> local;
    {
        std::lock_guard<std::mutex> lock(g_discover_mu);
        local.swap(g_discover);
    }
    for (auto& kv : local) {
        CloseDiscoverHolder(kv.second);
    }
}

} // namespace ipc
} // namespace hdl
