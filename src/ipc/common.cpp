#include "common.hpp"

#include "discover.hpp"
#include "memory.hpp"

#include <atomic>
#include <mutex>
#include <unordered_map>
#include <utility>

namespace hdl {
namespace ipc {
namespace {

std::mutex g_sessions_mu;
std::unordered_map<uint64_t, std::shared_ptr<SearchSessionHolder>> g_sessions;
std::atomic<uint64_t> g_next_session_id{1};

std::mutex g_discover_mu;
std::unordered_map<uint64_t, std::shared_ptr<DiscoverSessionHolder>> g_discover;
std::atomic<uint64_t> g_next_discover_id{1};
thread_local std::shared_ptr<Job> g_request_job;

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

RequestJobScope::RequestJobScope(std::shared_ptr<Job> job) : previous_(std::move(g_request_job)) {
    g_request_job = std::move(job);
}

RequestJobScope::~RequestJobScope() {
    g_request_job = std::move(previous_);
}

std::shared_ptr<Job> CurrentRequestJob() {
    return g_request_job;
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
