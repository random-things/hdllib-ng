#include "handlers.hpp"
#include "wire.hpp"

#include "code.hpp"
#include "disasm/backend.hpp"
#include "graph.hpp"
#include "jobs.hpp"
#include "pe_meta.hpp"
#include "protocol.hpp"
#include "vtable.hpp"
#include "watch.hpp"

#include <string>
#include <thread>
#include <vector>

namespace hdl {
namespace ipc {

bool HandleDisasmEnumBackends(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    (void)r;
    std::vector<uint8_t> resp;
    uint32_t count = 0;
    HdlStatus st = disasm::EnumBackends(nullptr, &count);
    std::vector<HdlDisasmBackendInfo> list;
    if (st == HDL_E_BUFFER_SMALL && count) {
        list.resize(count);
        st = disasm::EnumBackends(list.data(), &count);
    } else if (st == HDL_OK) {
        count = 0;
    }
    AppendPod(resp, static_cast<int32_t>(st));
    AppendPod(resp, count);
    if (count && st == HDL_OK) {
        for (uint32_t _i = 0; _i < count; ++_i)
            proto::AppendHdlDisasmBackendInfo(resp, list[_i]);
    }
    return WriteFrame(pipe, resp);
}

bool HandleDisasmGetBackend(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    (void)r;
    std::vector<uint8_t> resp;
    int32_t id = 0;
    const HdlStatus st = disasm::GetBackend(&id);
    AppendPod(resp, static_cast<int32_t>(st));
    AppendPod(resp, id);
    return WriteFrame(pipe, resp);
}

bool HandleDisasmSetBackend(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    int32_t id = 0;
    if (!r.TakePod(id)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    AppendPod(resp, static_cast<int32_t>(disasm::SetBackend(id)));
    return WriteFrame(pipe, resp);
}

bool HandleInstrLen(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t addr = 0;
    if (!r.TakePod(addr)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    uint32_t len = 0;
    const HdlStatus st = InstrLen(addr, &len);
    AppendPod(resp, static_cast<int32_t>(st));
    AppendPod(resp, len);
    return WriteFrame(pipe, resp);
}

bool HandleDisasm(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t addr = 0;
    uint32_t max_insns = 0;
    if (!r.TakePod(addr) || !r.TakePod(max_insns)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    uint32_t count = 0;
    HdlStatus st = DisasmRange(addr, max_insns, nullptr, &count);
    std::vector<HdlInsn> list;
    if (st == HDL_E_BUFFER_SMALL && count) {
        list.resize(count);
        st = DisasmRange(addr, max_insns, list.data(), &count);
    } else if (st == HDL_OK) {
        count = 0;
    }
    AppendPod(resp, static_cast<int32_t>(st));
    AppendPod(resp, count);
    if (count && st == HDL_OK) {
        for (uint32_t _i = 0; _i < count; ++_i)
            proto::AppendHdlInsn(resp, list[_i]);
    }
    return WriteFrame(pipe, resp);
}

bool HandleBuildStub(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    HdlStubDesc desc{};
    uint32_t raw_len = 0;
    if (!r.TakePod(desc.kind) || !r.TakePod(desc.flags) || !r.TakePod(desc.target) ||
        !r.TakePod(desc.steal_from) || !r.TakePod(desc.steal_min_bytes) ||
        !r.TakePod(desc.reserved) || !r.TakePod(desc.alloc_rx) || !r.TakePod(raw_len)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    std::vector<uint8_t> raw;
    if (raw_len) {
        if (r.left < raw_len) {
            AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
            return WriteFrame(pipe, resp);
        }
        raw.assign(r.p, r.p + raw_len);
        r.p += raw_len;
        r.left -= raw_len;
        desc.raw = raw.data();
        desc.raw_size = raw_len;
    }
    HdlStubResult result{};
    const HdlStatus st = BuildStub(&desc, &result);
    AppendPod(resp, static_cast<int32_t>(st));
    proto::AppendHdlStubResult(resp, result);
    return WriteFrame(pipe, resp);
}

bool HandlePatchCreate(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t addr = 0;
    uint32_t size = 0;
    std::string name;
    if (!r.TakePod(addr) || !r.TakePod(size) || !r.TakeString(name) || r.left < size) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    const uint8_t* bytes = r.p;
    HdlPatchHandle handle = 0;
    const HdlStatus st =
        PatchCreate(addr, bytes, size, name.empty() ? nullptr : name.c_str(), &handle);
    AppendPod(resp, static_cast<int32_t>(st));
    AppendPod(resp, handle);
    return WriteFrame(pipe, resp);
}

bool HandlePatchEnable(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t handle = 0;
    int32_t enable = 0;
    if (!r.TakePod(handle) || !r.TakePod(enable)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    AppendPod(resp, static_cast<int32_t>(PatchEnable(handle, enable)));
    return WriteFrame(pipe, resp);
}

bool HandlePatchRemove(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t handle = 0;
    if (!r.TakePod(handle)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    AppendPod(resp, static_cast<int32_t>(PatchRemove(handle)));
    return WriteFrame(pipe, resp);
}

bool HandlePatchEnum(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    uint64_t job_id = 0;
    uint32_t timeout_ms = 0;
    uint32_t flags = 0;
    TakeOptionalJobTimeoutFlags(r, &job_id, &timeout_ms, &flags);
    uint32_t count = 0;
    HdlStatus st = PatchEnum(nullptr, &count);
    std::vector<HdlPatchInfo> list;
    if (st == HDL_E_BUFFER_SMALL && count) {
        list.resize(count);
        st = PatchEnum(list.data(), &count);
    } else if (st == HDL_OK) {
        count = 0;
    }
    if (flags & HDL_IPC_REQ_STREAM) {
        return WriteStreamed(pipe, st, list.data(), count, 32);
    }
    std::vector<uint8_t> resp;
    AppendPod(resp, static_cast<int32_t>(st));
    AppendPod(resp, count);
    if (count && st == HDL_OK) {
        for (uint32_t _i = 0; _i < count; ++_i)
            proto::AppendHdlPatchInfo(resp, list[_i]);
    }
    return WriteFrame(pipe, resp);
}

static bool HandlePeEnum(HANDLE pipe, proto::Reader& r, int which) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t base = 0;
    uint64_t job_id = 0;
    uint32_t timeout_ms = 0;
    uint32_t flags = 0;
    if (!r.TakePod(base)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    TakeOptionalJobTimeoutFlags(r, &job_id, &timeout_ms, &flags);

    if (which == 0) {
        uint32_t count = 0;
        HdlStatus st = EnumSections(base, nullptr, &count);
        std::vector<HdlSectionInfo> list;
        if (st == HDL_E_BUFFER_SMALL && count) {
            list.resize(count);
            st = EnumSections(base, list.data(), &count);
        } else if (st == HDL_OK) {
            count = 0;
        }
        if (flags & HDL_IPC_REQ_STREAM) {
            return WriteStreamed(pipe, st, list.data(), count, 32);
        }
        AppendPod(resp, static_cast<int32_t>(st));
        AppendPod(resp, count);
        if (count && st == HDL_OK) {
            for (uint32_t _i = 0; _i < count; ++_i)
                proto::AppendHdlSectionInfo(resp, list[_i]);
        }
        return WriteFrame(pipe, resp);
    }
    if (which == 1) {
        uint32_t count = 0;
        HdlStatus st = EnumExports(base, nullptr, &count);
        std::vector<HdlExportInfo> list;
        if (st == HDL_E_BUFFER_SMALL && count) {
            list.resize(count);
            st = EnumExports(base, list.data(), &count);
        } else if (st == HDL_OK) {
            count = 0;
        }
        if (flags & HDL_IPC_REQ_STREAM) {
            return WriteStreamed(pipe, st, list.data(), count, 32);
        }
        AppendPod(resp, static_cast<int32_t>(st));
        AppendPod(resp, count);
        if (count && st == HDL_OK) {
            for (uint32_t _i = 0; _i < count; ++_i)
                proto::AppendHdlExportInfo(resp, list[_i]);
        }
        return WriteFrame(pipe, resp);
    }
    uint32_t count = 0;
    HdlStatus st = EnumImports(base, nullptr, &count);
    std::vector<HdlImportInfo> list;
    if (st == HDL_E_BUFFER_SMALL && count) {
        list.resize(count);
        st = EnumImports(base, list.data(), &count);
    } else if (st == HDL_OK) {
        count = 0;
    }
    if (flags & HDL_IPC_REQ_STREAM) {
        return WriteStreamed(pipe, st, list.data(), count, 32);
    }
    AppendPod(resp, static_cast<int32_t>(st));
    AppendPod(resp, count);
    if (count && st == HDL_OK) {
        for (uint32_t _i = 0; _i < count; ++_i)
            proto::AppendHdlImportInfo(resp, list[_i]);
    }
    return WriteFrame(pipe, resp);
}

bool HandleEnumSections(HANDLE pipe, proto::Reader& r) {
    return HandlePeEnum(pipe, r, 0);
}
bool HandleEnumExports(HANDLE pipe, proto::Reader& r) {
    return HandlePeEnum(pipe, r, 1);
}
bool HandleEnumImports(HANDLE pipe, proto::Reader& r) {
    return HandlePeEnum(pipe, r, 2);
}

bool HandleEnumFunctions(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t start = 0;
    uint64_t size = 0;
    uint32_t search_flags = 0;
    uint32_t max_results = 0;
    std::wstring module;
    uint64_t job_id = 0;
    uint32_t timeout_ms = 0;
    uint32_t flags = 0;
    if (!r.TakePod(start) || !r.TakePod(size) || !r.TakePod(search_flags) ||
        !r.TakePod(max_results) || !r.TakeWString(module)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    TakeOptionalJobTimeoutFlags(r, &job_id, &timeout_ms, &flags);
    volatile int cancel = 0;
    uint32_t count = 0;
    HdlStatus st =
        EnumFunctions(start, size, search_flags, module.empty() ? nullptr : module.c_str(),
                      max_results, nullptr, &count, &cancel);
    std::vector<HdlFunctionInfo> list;
    if (st == HDL_E_BUFFER_SMALL && count) {
        list.resize(count);
        st = EnumFunctions(start, size, search_flags, module.empty() ? nullptr : module.c_str(),
                           max_results, list.data(), &count, &cancel);
    } else if (st == HDL_OK) {
        count = 0;
    }
    if (flags & HDL_IPC_REQ_STREAM) {
        return WriteStreamed(pipe, st, list.data(), count, 64);
    }
    AppendPod(resp, static_cast<int32_t>(st));
    AppendPod(resp, count);
    if (count && st == HDL_OK) {
        for (uint32_t _i = 0; _i < count; ++_i)
            proto::AppendHdlFunctionInfo(resp, list[_i]);
    }
    return WriteFrame(pipe, resp);
}

bool HandleXrefsFrom(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t seed = 0;
    uint32_t max_depth = 0;
    uint32_t max_nodes = 0;
    uint32_t kinds = 0;
    if (!r.TakePod(seed) || !r.TakePod(max_depth) || !r.TakePod(max_nodes) || !r.TakePod(kinds)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    volatile int cancel = 0;
    uint32_t count = 0;
    HdlStatus st = XrefsFrom(seed, max_depth, max_nodes, kinds, nullptr, &count, &cancel);
    std::vector<HdlXrefEdge> list;
    if (st == HDL_E_BUFFER_SMALL && count) {
        list.resize(count);
        st = XrefsFrom(seed, max_depth, max_nodes, kinds, list.data(), &count, &cancel);
    } else if (st == HDL_OK) {
        count = 0;
    }
    AppendPod(resp, static_cast<int32_t>(st));
    AppendPod(resp, count);
    if (count && st == HDL_OK) {
        for (uint32_t _i = 0; _i < count; ++_i)
            proto::AppendHdlXrefEdge(resp, list[_i]);
    }
    return WriteFrame(pipe, resp);
}

bool HandleResolveFunction(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t addr = 0;
    uint32_t search_flags = 0;
    std::wstring module;
    if (!r.TakePod(addr) || !r.TakePod(search_flags) || !r.TakeWString(module)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    volatile int cancel = 0;
    HdlFunctionInfo fi{};
    const HdlStatus st = ResolveFunction(addr, search_flags,
                                         module.empty() ? nullptr : module.c_str(), &fi, &cancel);
    AppendPod(resp, static_cast<int32_t>(st));
    if (st == HDL_OK) {
        proto::AppendHdlFunctionInfo(resp, fi);
    }
    return WriteFrame(pipe, resp);
}

bool HandleXrefsTo(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t target = 0;
    uint32_t max_nodes = 0;
    uint32_t kinds = 0;
    uint32_t search_flags = 0;
    std::wstring module;
    if (!r.TakePod(target) || !r.TakePod(max_nodes) || !r.TakePod(kinds) ||
        !r.TakePod(search_flags) || !r.TakeWString(module)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    volatile int cancel = 0;
    uint32_t count = 0;
    HdlStatus st = XrefsTo(target, max_nodes, kinds, search_flags,
                           module.empty() ? nullptr : module.c_str(), nullptr, &count, &cancel);
    std::vector<HdlXrefEdge> list;
    if (st == HDL_E_BUFFER_SMALL && count) {
        list.resize(count);
        st = XrefsTo(target, max_nodes, kinds, search_flags,
                     module.empty() ? nullptr : module.c_str(), list.data(), &count, &cancel);
    } else if (st == HDL_OK) {
        count = 0;
    }
    AppendPod(resp, static_cast<int32_t>(st));
    AppendPod(resp, count);
    if (count && st == HDL_OK) {
        for (uint32_t _i = 0; _i < count; ++_i)
            proto::AppendHdlXrefEdge(resp, list[_i]);
    }
    return WriteFrame(pipe, resp);
}

bool HandleInvalidateFnIndex(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    std::wstring module;
    if (!r.TakeWString(module)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    AppendPod(resp, static_cast<int32_t>(
                        InvalidateFunctionIndex(module.empty() ? nullptr : module.c_str())));
    return WriteFrame(pipe, resp);
}

bool HandleWalkVtable(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t addr = 0;
    int32_t is_object = 0;
    if (!r.TakePod(addr) || !r.TakePod(is_object)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    uint32_t count = 0;
    HdlStatus st = WalkVtable(addr, is_object, nullptr, &count);
    std::vector<uint64_t> slots;
    if (st == HDL_E_BUFFER_SMALL && count) {
        slots.resize(count);
        st = WalkVtable(addr, is_object, slots.data(), &count);
    } else if (st == HDL_OK) {
        count = 0;
    }
    AppendPod(resp, static_cast<int32_t>(st));
    AppendPod(resp, count);
    if (count && st == HDL_OK) {
        AppendBytes(resp, slots.data(), count * sizeof(uint64_t));
    }
    return WriteFrame(pipe, resp);
}

bool HandleQueryRttiName(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t addr = 0;
    int32_t is_object = 0;
    if (!r.TakePod(addr) || !r.TakePod(is_object)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    char name[256]{};
    const HdlStatus st = QueryRttiName(addr, is_object, name, sizeof(name));
    AppendPod(resp, static_cast<int32_t>(st));
    AppendString(resp, name);
    return WriteFrame(pipe, resp);
}

bool HandleWatchHw(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t addr = 0;
    uint32_t size = 0;
    uint32_t access = 0;
    uint32_t tid = 0;
    if (!r.TakePod(addr) || !r.TakePod(size) || !r.TakePod(access) || !r.TakePod(tid)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    HdlWatchHandle handle = 0;
    const HdlStatus st = WatchHw(addr, size, access, tid, &handle);
    AppendPod(resp, static_cast<int32_t>(st));
    AppendPod(resp, handle);
    return WriteFrame(pipe, resp);
}

bool HandleWatchPage(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t addr = 0;
    uint64_t size = 0;
    uint32_t mode = 0;
    if (!r.TakePod(addr) || !r.TakePod(size) || !r.TakePod(mode)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    HdlWatchHandle handle = 0;
    const HdlStatus st = WatchPage(addr, static_cast<size_t>(size), mode, &handle);
    AppendPod(resp, static_cast<int32_t>(st));
    AppendPod(resp, handle);
    return WriteFrame(pipe, resp);
}

bool HandleUnwatch(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t handle = 0;
    if (!r.TakePod(handle)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    AppendPod(resp, static_cast<int32_t>(Unwatch(handle)));
    return WriteFrame(pipe, resp);
}

bool HandleEnumWatches(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    (void)r;
    std::vector<uint8_t> resp;
    uint32_t count = 0;
    HdlStatus st = EnumWatches(nullptr, &count);
    std::vector<HdlWatchInfo> list;
    if (st == HDL_E_BUFFER_SMALL && count) {
        list.resize(count);
        st = EnumWatches(list.data(), &count);
    } else if (st == HDL_OK) {
        count = 0;
    }
    AppendPod(resp, static_cast<int32_t>(st));
    AppendPod(resp, count);
    if (count && st == HDL_OK) {
        for (uint32_t _i = 0; _i < count; ++_i)
            proto::AppendHdlWatchInfo(resp, list[_i]);
    }
    return WriteFrame(pipe, resp);
}

bool HandleWatchRefresh(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    (void)r;
    std::vector<uint8_t> resp;
    AppendPod(resp, static_cast<int32_t>(WatchRefresh()));
    return WriteFrame(pipe, resp);
}

bool HandlePollWatchHits(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint32_t max_hits = 0;
    uint32_t timeout_ms = 0;
    if (!r.TakePod(max_hits) || !r.TakePod(timeout_ms)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    if (max_hits == 0 || max_hits > 64) {
        max_hits = 64;
    }
    std::vector<HdlWatchHit> hits(max_hits);
    uint32_t count = max_hits;
    const HdlStatus st = PollWatchHits(hits.data(), &count, timeout_ms);
    AppendPod(resp, static_cast<int32_t>(st));
    AppendPod(resp, count);
    if (count && st == HDL_OK) {
        for (uint32_t _i = 0; _i < count; ++_i)
            proto::AppendHdlWatchHit(resp, hits[_i]);
    }
    return WriteFrame(pipe, resp);
}

} // namespace ipc
} // namespace hdl
