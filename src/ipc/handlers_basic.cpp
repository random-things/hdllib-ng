#include "handlers.hpp"
#include "wire.hpp"

#include "core.hpp"
#include "fingerprint.hpp"
#include "health.hpp"
#include "inject.hpp"
#include "jobs.hpp"
#include "loaded_modules.hpp"
#include "log.hpp"
#include "memory.hpp"
#include "protocol.hpp"

#include <string>
#include <vector>

namespace hdl {
namespace ipc {
namespace {

template <typename T>
HdlStatus EnumerateAll(HdlStatus (*enumerate)(T*, uint32_t*), std::vector<T>* values) {
    values->clear();
    uint32_t required = 0;
    HdlStatus st = enumerate(nullptr, &required);
    if (st != HDL_OK && st != HDL_E_BUFFER_SMALL) {
        return st;
    }

    constexpr uint32_t kGrowthSlack = 64;
    constexpr int kMaxAttempts = 4;
    for (int attempt = 0; attempt < kMaxAttempts; ++attempt) {
        if (required == 0) {
            return HDL_OK;
        }
        // The collection can grow between the size query and fill call. For regions,
        // allocating this vector can itself add mappings to the process being queried.
        const uint32_t capacity =
            required <= UINT32_MAX - kGrowthSlack ? required + kGrowthSlack : required;
        values->resize(capacity);
        uint32_t count = capacity;
        st = enumerate(values->data(), &count);
        if (st == HDL_OK) {
            values->resize(count);
            return HDL_OK;
        }
        values->clear();
        if (st != HDL_E_BUFFER_SMALL) {
            return st;
        }
        required = count;
    }
    return HDL_E_BUFFER_SMALL;
}

} // namespace

bool HandlePing(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    (void)r;
    std::vector<uint8_t> resp;
    AppendPod(resp, static_cast<int32_t>(HDL_OK));
    AppendPod(resp, static_cast<uint32_t>(GetCurrentProcessId()));
    return WriteFrame(pipe, resp);
}

bool HandleSetLogLevel(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    int32_t level = 0;
    if (!r.TakePod(level)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    SetLogLevel(static_cast<LogLevel>(level));
    AppendPod(resp, static_cast<int32_t>(HDL_OK));
    return WriteFrame(pipe, resp);
}

bool HandleSetLogFile(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    std::wstring path;
    if (!r.TakeWString(path)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    /* The pipe path is untrusted, but the pipe DACL admits only SYSTEM/Admins/owner (see
     * BuildPipeSa), all of whom can already run arbitrary code via Memory.WriteMemory/Call.Call.
     * append-only log at a caller-chosen path is strictly weaker; SetLogFile still normalizes via
     * GetFullPathNameW and rejects oversized paths. */
    const wchar_t* log_path = path.empty() ? nullptr : path.c_str();
    // codeql[cpp/path-injection]
    const bool log_ok = SetLogFile(log_path);
    AppendPod(resp, static_cast<int32_t>(log_ok ? HDL_OK : HDL_E_FAILED));
    return WriteFrame(pipe, resp);
}

bool HandleSetHealthVeh(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    int32_t enabled = 0;
    if (!r.TakePod(enabled)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    AppendPod(resp, static_cast<int32_t>(SetHealthVeh(enabled != 0)));
    return WriteFrame(pipe, resp);
}

bool HandleGetHealthVeh(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    (void)r;
    std::vector<uint8_t> resp;
    AppendPod(resp, static_cast<int32_t>(HDL_OK));
    AppendPod(resp, static_cast<int32_t>(IsHealthVehEnabled() ? 1 : 0));
    return WriteFrame(pipe, resp);
}

bool HandleInjectDll(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint32_t pid = 0;
    uint32_t method = HDL_INJECT_CREATE_REMOTE_THREAD;
    std::wstring path;
    std::wstring exe_path;
    std::string hook_export;
    if (!r.TakePod(pid) || !r.TakePod(method) || !r.TakeWString(path) || !r.TakeWString(exe_path) ||
        !r.TakeString(hook_export)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    uint64_t base = 0;
    uint32_t out_pid = 0;
    const HdlStatus st = InjectDllEx(
        pid, path.c_str(), static_cast<int>(method), exe_path.empty() ? nullptr : exe_path.c_str(),
        hook_export.empty() ? nullptr : hook_export.c_str(), &out_pid, &base);
    if (st == HDL_OK && base) {
        const DWORD self = GetCurrentProcessId();
        const uint32_t effective = out_pid ? out_pid : (pid ? pid : self);
        if (effective == self) {
            TrackLoadedModule(path.c_str(), base);
        }
    }
    AppendPod(resp, static_cast<int32_t>(st));
    AppendPod(resp, base);
    AppendPod(resp, out_pid);
    return WriteFrame(pipe, resp);
}

bool HandleUnloadDll(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint32_t pid = 0;
    int32_t reload = 0;
    std::wstring path;
    if (!r.TakePod(pid) || !r.TakePod(reload) || !r.TakeWString(path)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    uint64_t base = 0;
    const HdlStatus st = UnloadDll(pid, path.c_str(), reload, 0, &base);
    if (st == HDL_OK) {
        UntrackLoadedModule(path.c_str());
    }
    AppendPod(resp, static_cast<int32_t>(st));
    AppendPod(resp, base);
    return WriteFrame(pipe, resp);
}

bool HandleShutdown(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint32_t flags = 0;
    if (!r.TakePod(flags)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    /* Restore instrumentation first, reply, then signal IPC stop without joining
     * (this thread is a ServeClient worker — joining the accept loop would deadlock). */
    CoreShutdownPrepare(flags);
    AppendPod(resp, static_cast<int32_t>(HDL_OK));
    const bool wrote = WriteFrame(pipe, resp);
    if (wrote) {
        FlushFileBuffers(pipe);
    }
    /* Keep this pipe connected until ServeClient returns so the client can read OK. */
    CoreShutdownFinish(pipe);
    return wrote;
}

bool HandleTrackLoadedDll(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t base = 0;
    std::wstring path;
    if (!r.TakePod(base) || !r.TakeWString(path) || !base || path.empty()) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    TrackLoadedModule(path.c_str(), base);
    AppendPod(resp, static_cast<int32_t>(HDL_OK));
    return WriteFrame(pipe, resp);
}

bool HandleReadMemory(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t address = 0;
    uint32_t size = 0;
    if (!r.TakePod(address) || !r.TakePod(size) || size > 16u * 1024u * 1024u) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    std::vector<uint8_t> buf(size);
    size_t got = 0;
    const HdlStatus st = ReadMemory(address, buf.data(), size, &got);
    AppendPod(resp, static_cast<int32_t>(st));
    AppendPod(resp, static_cast<uint32_t>(got));
    if (got) {
        AppendBytes(resp, buf.data(), got);
    }
    return WriteFrame(pipe, resp);
}

bool HandleWriteMemory(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t address = 0;
    uint32_t size = 0;
    if (!r.TakePod(address) || !r.TakePod(size) || size > 16u * 1024u * 1024u || r.left < size) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    size_t wrote = 0;
    const HdlStatus st = WriteMemory(address, r.p, size, &wrote);
    AppendPod(resp, static_cast<int32_t>(st));
    AppendPod(resp, static_cast<uint32_t>(wrote));
    return WriteFrame(pipe, resp);
}

bool HandleEnumRegions(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t job_id = 0;
    uint32_t timeout_ms = 0;
    uint32_t flags = 0;
    // Aggregate delivery has no trailer; streamed delivery carries the compact flags tuple.
    TakeOptionalJobTimeoutFlags(r, &job_id, &timeout_ms, &flags);
    (void)job_id;
    (void)timeout_ms;

    std::vector<HdlRegionInfo> regions;
    const HdlStatus st = EnumerateAll(&EnumRegions, &regions);
    const uint32_t count = static_cast<uint32_t>(regions.size());

    if (flags & HDL_IPC_REQ_STREAM) {
        return WriteStreamed(pipe, st, regions.data(), count, 64);
    }

    AppendPod(resp, static_cast<int32_t>(st));
    AppendPod(resp, count);
    if (count) {
        for (uint32_t _i = 0; _i < count; ++_i)
            proto::AppendHdlRegionInfo(resp, regions[_i]);
    }
    return WriteFrame(pipe, resp);
}

bool HandleEnumModules(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t job_id = 0;
    uint32_t timeout_ms = 0;
    uint32_t flags = 0;
    TakeOptionalJobTimeoutFlags(r, &job_id, &timeout_ms, &flags);
    (void)job_id;
    (void)timeout_ms;

    std::vector<HdlModuleInfo> modules;
    const HdlStatus st = EnumerateAll(&EnumModules, &modules);
    const uint32_t count = static_cast<uint32_t>(modules.size());

    if (flags & HDL_IPC_REQ_STREAM) {
        return WriteStreamed(pipe, st, modules.data(), count, 16);
    }

    AppendPod(resp, static_cast<int32_t>(st));
    AppendPod(resp, count);
    if (count) {
        for (uint32_t _i = 0; _i < count; ++_i)
            proto::AppendHdlModuleInfo(resp, modules[_i]);
    }
    return WriteFrame(pipe, resp);
}

bool HandleFingerprint(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint32_t scan_flags = HDL_FP_SCAN_DEFAULT;
    if (r.left >= sizeof(uint32_t)) {
        if (!r.TakePod(scan_flags)) {
            AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
            return WriteFrame(pipe, resp);
        }
        if (scan_flags == 0) {
            scan_flags = HDL_FP_SCAN_DEFAULT;
        }
    }
    uint64_t job_id = 0;
    uint32_t timeout_ms = 0;
    uint32_t flags = 0;
    TakeOptionalJobTimeoutFlags(r, &job_id, &timeout_ms, &flags);
    (void)job_id;
    (void)timeout_ms;

    uint32_t count = 0;
    EnumFingerprintTags(scan_flags, nullptr, &count);
    std::vector<HdlFingerprintTag> tags(count);
    const HdlStatus st = count ? EnumFingerprintTags(scan_flags, tags.data(), &count) : HDL_OK;

    if (flags & HDL_IPC_REQ_STREAM) {
        return WriteStreamed(pipe, st, tags.data(), count, 16);
    }

    AppendPod(resp, static_cast<int32_t>(st));
    AppendPod(resp, count);
    if (count) {
        for (uint32_t _i = 0; _i < count; ++_i)
            proto::AppendHdlFingerprintTag(resp, tags[_i]);
    }
    return WriteFrame(pipe, resp);
}

bool HandleGetHealth(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    (void)r;
    std::vector<uint8_t> resp;
    HdlHealthInfo info{};
    const HdlStatus st = GetHealth(&info);
    AppendPod(resp, static_cast<int32_t>(st));
    proto::AppendHdlHealthInfo(resp, info);
    return WriteFrame(pipe, resp);
}

bool HandleEnumThreads(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t job_id = 0;
    uint32_t timeout_ms = 0;
    uint32_t flags = 0;
    TakeOptionalJobTimeoutFlags(r, &job_id, &timeout_ms, &flags);
    (void)job_id;
    (void)timeout_ms;

    std::vector<HdlThreadInfo> threads;
    const HdlStatus st = EnumerateAll(&EnumThreads, &threads);
    const uint32_t count = static_cast<uint32_t>(threads.size());

    if (flags & HDL_IPC_REQ_STREAM) {
        return WriteStreamed(pipe, st, threads.data(), count, 32);
    }

    AppendPod(resp, static_cast<int32_t>(st));
    AppendPod(resp, count);
    if (count) {
        for (uint32_t _i = 0; _i < count; ++_i)
            proto::AppendHdlThreadInfo(resp, threads[_i]);
    }
    return WriteFrame(pipe, resp);
}

bool HandlePollEvents(HANDLE pipe, proto::Reader& r) {
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
    std::vector<HdlEvent> events(max_events);
    const uint32_t got = HealthPollEvents(events.data(), max_events, timeout_ms);
    AppendPod(resp, static_cast<int32_t>(HDL_OK));
    AppendPod(resp, got);
    if (got) {
        for (uint32_t _i = 0; _i < got; ++_i)
            proto::AppendHdlEvent(resp, events[_i]);
    }
    return WriteFrame(pipe, resp);
}

} // namespace ipc
} // namespace hdl
