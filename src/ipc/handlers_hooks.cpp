#include "handlers.hpp"
#include "wire.hpp"

#include "hooks.hpp"
#include "protocol.hpp"

#include <vector>

namespace hdl {
namespace ipc {

bool HandleHookTrace(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t target = 0;
    uint32_t arg_count = 0;
    if (!r.TakePod(target) || !r.TakePod(arg_count)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    HdlHookHandle handle = nullptr;
    const HdlStatus st = HookTrace(target, arg_count, &handle);
    AppendPod(resp, static_cast<int32_t>(st));
    AppendPod(resp, reinterpret_cast<uint64_t>(handle));
    return WriteFrame(pipe, resp);
}

bool HandleHook(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t target_va = 0;
    uint64_t detour_va = 0;
    uint32_t flags = 0;
    if (!r.TakePod(target_va) || !r.TakePod(detour_va) || !r.TakePod(flags) || flags != 0 ||
        !target_va || !detour_va) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    void* trampoline = nullptr;
    HdlHookHandle handle = nullptr;
    const HdlStatus st = Hook(reinterpret_cast<void*>(target_va),
                              reinterpret_cast<void*>(detour_va), &trampoline, &handle);
    AppendPod(resp, static_cast<int32_t>(st));
    AppendPod(resp, reinterpret_cast<uint64_t>(handle));
    AppendPod(resp, reinterpret_cast<uint64_t>(trampoline));
    return WriteFrame(pipe, resp);
}

bool HandleEnableHook(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t handle = 0;
    int32_t enable = 0;
    if (!r.TakePod(handle) || !r.TakePod(enable)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    AppendPod(resp,
              static_cast<int32_t>(EnableHook(reinterpret_cast<HdlHookHandle>(handle), enable)));
    return WriteFrame(pipe, resp);
}

bool HandleUnhook(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t handle = 0;
    if (!r.TakePod(handle)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    AppendPod(resp, static_cast<int32_t>(Unhook(reinterpret_cast<HdlHookHandle>(handle))));
    return WriteFrame(pipe, resp);
}

bool HandlePollHookHits(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint32_t max_events = 0;
    uint32_t timeout_ms = 0;
    if (!r.TakePod(max_events) || !r.TakePod(timeout_ms)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    if (max_events == 0 || max_events > 64) {
        max_events = 64;
    }
    std::vector<HdlHookHit> hits(max_events);
    uint32_t count = max_events;
    const HdlStatus st = PollHookHits(hits.data(), &count, timeout_ms);
    AppendPod(resp, static_cast<int32_t>(st));
    AppendPod(resp, count);
    if (count) {
        for (uint32_t _i = 0; _i < count; ++_i)
            proto::AppendHdlHookHit(resp, hits[_i]);
    }
    return WriteFrame(pipe, resp);
}

bool HandleHookImport(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    std::wstring module;
    std::string dll;
    std::string import_name;
    uint32_t arg_count = 0;
    if (!r.TakeWString(module) || !r.TakeString(dll) || !r.TakeString(import_name) ||
        !r.TakePod(arg_count)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    HdlHookHandle handle = nullptr;
    const HdlStatus st = HookImport(module.empty() ? nullptr : module.c_str(), dll.c_str(),
                                    import_name.c_str(), arg_count, &handle);
    AppendPod(resp, static_cast<int32_t>(st));
    AppendPod(resp, reinterpret_cast<uint64_t>(handle));
    return WriteFrame(pipe, resp);
}

} // namespace ipc
} // namespace hdl
