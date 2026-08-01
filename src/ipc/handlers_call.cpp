#include "handlers.hpp"
#include "wire.hpp"

#include "alloc.hpp"
#include "call.hpp"
#include "jobs.hpp"
#include "protocol.hpp"
#include "resolve.hpp"

#include <string>
#include <thread>
#include <vector>

namespace hdl {
namespace ipc {
namespace {

bool TakeCallArgs(proto::Reader& r, uint32_t arg_count, std::vector<HdlCallArg>& args,
                  std::vector<std::vector<uint8_t>>& owned, std::vector<uint8_t>& resp) {
    using namespace proto;
    args.resize(arg_count);
    owned.resize(arg_count);
    for (uint32_t i = 0; i < arg_count; ++i) {
        int32_t kind = 0;
        uint32_t size = 0;
        uint64_t u64 = 0;
        if (!r.TakePod(kind) || !r.TakePod(size) || !r.TakePod(u64)) {
            AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
            return false;
        }
        args[i].kind = kind;
        args[i].size = size;
        args[i].u64 = u64;
        args[i].ptr = nullptr;
        if (kind == HDL_CALL_ARG_BUF || kind == HDL_CALL_ARG_CSTR || kind == HDL_CALL_ARG_WSTR) {
            uint32_t blob = 0;
            if (!r.TakePod(blob) || r.left < blob) {
                AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
                return false;
            }
            owned[i].assign(r.p, r.p + blob);
            r.p += blob;
            r.left -= blob;
            args[i].ptr = owned[i].data();
            if (kind == HDL_CALL_ARG_BUF) {
                args[i].size = blob;
            }
        } else if (kind == HDL_CALL_ARG_PTR) {
            args[i].ptr = reinterpret_cast<const void*>(u64);
        }
    }
    return true;
}

void AppendBufArgs(std::vector<uint8_t>& resp, const std::vector<HdlCallArg>& args,
                   const std::vector<std::vector<uint8_t>>& owned) {
    using namespace proto;
    uint32_t buf_n = 0;
    for (uint32_t i = 0; i < static_cast<uint32_t>(args.size()); ++i) {
        if (args[i].kind == HDL_CALL_ARG_BUF) {
            ++buf_n;
        }
    }
    AppendPod(resp, buf_n);
    for (uint32_t i = 0; i < static_cast<uint32_t>(args.size()); ++i) {
        if (args[i].kind == HDL_CALL_ARG_BUF) {
            AppendPod(resp, i);
            AppendPod(resp, static_cast<uint32_t>(owned[i].size()));
            AppendBytes(resp, owned[i].data(), owned[i].size());
        }
    }
}

std::thread StartJobWatcher(const std::shared_ptr<Job>& job, volatile int* local_cancel) {
    return std::thread([job, local_cancel]() {
        while (!*local_cancel) {
            const HdlStatus cs = JobCheck(job);
            if (cs != HDL_OK) {
                *local_cancel = 1;
                break;
            }
            Sleep(20);
        }
    });
}

} // namespace

bool HandleResolveExport(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    std::wstring module;
    std::string name;
    if (!r.TakeWString(module) || !r.TakeString(name)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    uint64_t addr = 0;
    const HdlStatus st =
        ResolveExport(module.empty() ? nullptr : module.c_str(), name.c_str(), &addr);
    AppendPod(resp, static_cast<int32_t>(st));
    AppendPod(resp, addr);
    return WriteFrame(pipe, resp);
}

bool HandleCallExport(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    std::wstring module;
    std::string name;
    uint32_t arg_count = 0;
    uint32_t timeout_ms = 0;
    uint64_t job_id = 0;
    if (!r.TakeWString(module) || !r.TakeString(name) || !r.TakePod(arg_count) ||
        !r.TakePod(timeout_ms) || !r.TakePod(job_id) || arg_count > 16) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    std::vector<HdlCallArg> args;
    std::vector<std::vector<uint8_t>> owned;
    if (!TakeCallArgs(r, arg_count, args, owned, resp)) {
        return WriteFrame(pipe, resp);
    }

    auto job = BindJob(job_id, 0);
    volatile int local_cancel = 0;
    std::thread watcher;
    if (job) {
        watcher = StartJobWatcher(job, &local_cancel);
    }

    HdlCallResult result{};
    const HdlStatus st = CallExport(module.empty() ? nullptr : module.c_str(), name.c_str(),
                                    arg_count ? args.data() : nullptr, arg_count, &result,
                                    timeout_ms, job ? &local_cancel : nullptr);

    if (job) {
        local_cancel = 1;
        if (watcher.joinable()) {
            watcher.join();
        }
    }

    AppendPod(resp, static_cast<int32_t>(st));
    proto::AppendHdlCallResult(resp, result);
    AppendBufArgs(resp, args, owned);
    return WriteFrame(pipe, resp);
}

bool HandleCall(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t address = 0;
    uint32_t arg_count = 0;
    uint32_t thread_mode = 0;
    uint32_t timeout_ms = 0;
    uint64_t job_id = 0;
    if (!r.TakePod(address) || !r.TakePod(arg_count) || !r.TakePod(thread_mode) ||
        !r.TakePod(timeout_ms) || !r.TakePod(job_id) || arg_count > 16) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    std::vector<HdlCallArg> args;
    std::vector<std::vector<uint8_t>> owned;
    if (!TakeCallArgs(r, arg_count, args, owned, resp)) {
        return WriteFrame(pipe, resp);
    }

    auto job = BindJob(job_id, 0);
    volatile int local_cancel = 0;
    std::thread watcher;
    if (job) {
        watcher = StartJobWatcher(job, &local_cancel);
    }

    HdlCallDesc desc{};
    desc.address = address;
    desc.args = arg_count ? args.data() : nullptr;
    desc.arg_count = arg_count;
    desc.thread_mode = thread_mode;
    desc.timeout_ms = timeout_ms;
    HdlCallResult result{};
    const HdlStatus st = Call(&desc, &result, job ? &local_cancel : nullptr);

    if (job) {
        local_cancel = 1;
        if (watcher.joinable()) {
            watcher.join();
        }
    }

    AppendPod(resp, static_cast<int32_t>(st));
    proto::AppendHdlCallResult(resp, result);
    AppendBufArgs(resp, args, owned);
    return WriteFrame(pipe, resp);
}

bool HandleAlloc(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t size = 0;
    uint32_t protect = 0;
    if (!r.TakePod(size) || !r.TakePod(protect)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    uint64_t addr = 0;
    const HdlStatus st = Alloc(static_cast<size_t>(size), protect, &addr);
    AppendPod(resp, static_cast<int32_t>(st));
    AppendPod(resp, addr);
    return WriteFrame(pipe, resp);
}

bool HandleFree(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t addr = 0;
    if (!r.TakePod(addr)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    AppendPod(resp, static_cast<int32_t>(Free(addr)));
    return WriteFrame(pipe, resp);
}

bool HandleResolveRip(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t addr = 0;
    uint32_t disp = 0;
    uint32_t len = 0;
    if (!r.TakePod(addr) || !r.TakePod(disp) || !r.TakePod(len)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    uint64_t out = 0;
    const HdlStatus st = ResolveRipRelative(addr, disp, len, &out);
    AppendPod(resp, static_cast<int32_t>(st));
    AppendPod(resp, out);
    return WriteFrame(pipe, resp);
}

bool HandleFollowPointers(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t base = 0;
    uint32_t count = 0;
    if (!r.TakePod(base) || !r.TakePod(count) || count > 64) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    std::vector<int64_t> offsets(count);
    for (uint32_t i = 0; i < count; ++i) {
        if (!r.TakePod(offsets[i])) {
            AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
            return WriteFrame(pipe, resp);
        }
    }
    uint64_t out = 0;
    const HdlStatus st = FollowPointers(base, count ? offsets.data() : nullptr, count, &out);
    AppendPod(resp, static_cast<int32_t>(st));
    AppendPod(resp, out);
    return WriteFrame(pipe, resp);
}

bool HandleModuleBase(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    std::wstring module;
    if (!r.TakeWString(module)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    uint64_t base = 0;
    const HdlStatus st = ModuleBase(module.empty() ? nullptr : module.c_str(), &base);
    AppendPod(resp, static_cast<int32_t>(st));
    AppendPod(resp, base);
    return WriteFrame(pipe, resp);
}

bool HandleCallVtable(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t obj = 0;
    uint32_t index = 0;
    uint32_t arg_count = 0;
    int32_t prepend_this = 1;
    uint32_t thread_mode = 0;
    uint32_t timeout_ms = 0;
    uint64_t job_id = 0;
    if (!r.TakePod(obj) || !r.TakePod(index) || !r.TakePod(arg_count) || !r.TakePod(prepend_this) ||
        !r.TakePod(thread_mode) || !r.TakePod(timeout_ms) || !r.TakePod(job_id) || arg_count > 16) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    std::vector<HdlCallArg> args;
    std::vector<std::vector<uint8_t>> owned;
    if (!TakeCallArgs(r, arg_count, args, owned, resp)) {
        return WriteFrame(pipe, resp);
    }
    auto job = BindJob(job_id, 0);
    volatile int local_cancel = 0;
    std::thread watcher;
    if (job) {
        watcher = StartJobWatcher(job, &local_cancel);
    }
    HdlCallResult result{};
    const HdlStatus st =
        CallVtable(obj, index, arg_count ? args.data() : nullptr, arg_count, prepend_this,
                   thread_mode, &result, timeout_ms, job ? &local_cancel : nullptr);
    if (job) {
        local_cancel = 1;
        if (watcher.joinable()) {
            watcher.join();
        }
    }
    AppendPod(resp, static_cast<int32_t>(st));
    proto::AppendHdlCallResult(resp, result);
    return WriteFrame(pipe, resp);
}

} // namespace ipc
} // namespace hdl
