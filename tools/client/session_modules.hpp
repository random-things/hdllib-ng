#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace hdlcli {

struct SessionModule {
    std::wstring path;
    uint64_t base = 0;
};

void RememberInjectedModule(uint32_t pid, const wchar_t* path, uint64_t base);
std::vector<SessionModule> ListInjectedModules(uint32_t pid);
void ClearInjectedModules(uint32_t pid);

}  // namespace hdlcli
