#include "session_modules.hpp"

namespace hdlcli {
namespace {

std::mutex g_mu;
std::unordered_map<uint32_t, std::vector<SessionModule>> g_by_pid;

}  // namespace

void RememberInjectedModule(uint32_t pid, const wchar_t* path, uint64_t base) {
    if (!pid || !path || !path[0] || !base) {
        return;
    }
    std::lock_guard<std::mutex> lock(g_mu);
    auto& list = g_by_pid[pid];
    for (auto& m : list) {
        if (_wcsicmp(m.path.c_str(), path) == 0) {
            m.base = base;
            return;
        }
    }
    SessionModule m;
    m.path = path;
    m.base = base;
    list.push_back(std::move(m));
}

std::vector<SessionModule> ListInjectedModules(uint32_t pid) {
    std::lock_guard<std::mutex> lock(g_mu);
    const auto it = g_by_pid.find(pid);
    return it == g_by_pid.end() ? std::vector<SessionModule>{} : it->second;
}

void ClearInjectedModules(uint32_t pid) {
    std::lock_guard<std::mutex> lock(g_mu);
    g_by_pid.erase(pid);
}

}  // namespace hdlcli
