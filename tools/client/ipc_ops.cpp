#include "ipc_ops.hpp"

#include "protocol.hpp"
#include "util.hpp"

#include <cstring>

namespace hdlcli {
namespace {

using namespace hdl::proto;

IpcStatus TakeStatus(const std::vector<uint8_t>& resp, Reader* r) {
    IpcStatus s;
    if (!r->TakePod(s.status)) {
        s.status = HDL_E_FAILED;
    }
    return s;
}

}  // namespace

IpcStatus Ping(PipeClient& c, uint32_t* out_pid) {
    std::vector<uint8_t> req, resp;
    AppendPod(req, static_cast<uint32_t>(OpPing));
    if (!c.Request(req, resp)) {
        return IpcStatus{HDL_E_FAILED};
    }
    Reader r(resp);
    IpcStatus s = TakeStatus(resp, &r);
    uint32_t pid = 0;
    r.TakePod(pid);
    if (out_pid) {
        *out_pid = pid;
    }
    return s;
}

IpcStatus ModBase(PipeClient& c, const wchar_t* module_or_null, uint64_t* out_base) {
    std::vector<uint8_t> req, resp;
    AppendPod(req, static_cast<uint32_t>(OpModuleBase));
    AppendWString(req, module_or_null ? module_or_null : L"");
    if (!c.Request(req, resp)) {
        return IpcStatus{HDL_E_FAILED};
    }
    Reader r(resp);
    IpcStatus s = TakeStatus(resp, &r);
    uint64_t base = 0;
    r.TakePod(base);
    if (out_base) {
        *out_base = base;
    }
    return s;
}

IpcStatus ResolvePattern(PipeClient& c, const char* pattern, uint32_t hit_index,
                         int32_t pattern_offset, uint32_t rip_disp, uint32_t rip_len,
                         const std::vector<int64_t>& follows, uint32_t search_flags,
                         const wchar_t* module_or_null, HdlPatternResult* out) {
    std::vector<uint8_t> req, resp;
    AppendPod(req, static_cast<uint32_t>(OpResolvePattern));
    AppendString(req, pattern);
    AppendPod(req, hit_index);
    AppendPod(req, pattern_offset);
    AppendPod(req, rip_disp);
    AppendPod(req, rip_len);
    AppendPod(req, static_cast<uint32_t>(follows.size()));
    AppendPod(req, search_flags);
    AppendPod(req, static_cast<uint32_t>(64));
    AppendWString(req, module_or_null ? module_or_null : L"");
    for (int64_t f : follows) {
        AppendPod(req, f);
    }
    if (!c.Request(req, resp)) {
        return IpcStatus{HDL_E_FAILED};
    }
    Reader r(resp);
    IpcStatus s = TakeStatus(resp, &r);
    HdlPatternResult pr{};
    r.Take(&pr, sizeof(pr));
    if (out) {
        *out = pr;
    }
    return s;
}

IpcStatus FollowPointers(PipeClient& c, uint64_t base, const std::vector<int64_t>& offsets,
                         uint64_t* out_addr) {
    std::vector<uint8_t> req, resp;
    AppendPod(req, static_cast<uint32_t>(OpFollowPointers));
    AppendPod(req, base);
    AppendPod(req, static_cast<uint32_t>(offsets.size()));
    for (int64_t o : offsets) {
        AppendPod(req, o);
    }
    if (!c.Request(req, resp)) {
        return IpcStatus{HDL_E_FAILED};
    }
    Reader r(resp);
    IpcStatus s = TakeStatus(resp, &r);
    uint64_t addr = 0;
    r.TakePod(addr);
    if (out_addr) {
        *out_addr = addr;
    }
    return s;
}

IpcStatus DiscoverCreate(PipeClient& c, uint64_t* out_id) {
    std::vector<uint8_t> req, resp;
    AppendPod(req, static_cast<uint32_t>(OpDiscoverCreate));
    if (!c.Request(req, resp)) {
        return IpcStatus{HDL_E_FAILED};
    }
    Reader r(resp);
    IpcStatus s = TakeStatus(resp, &r);
    uint64_t id = 0;
    r.TakePod(id);
    if (out_id) {
        *out_id = id;
    }
    return s;
}

IpcStatus DiscoverClose(PipeClient& c, uint64_t id) {
    std::vector<uint8_t> req, resp;
    AppendPod(req, static_cast<uint32_t>(OpDiscoverClose));
    AppendPod(req, id);
    if (!c.Request(req, resp)) {
        return IpcStatus{HDL_E_FAILED};
    }
    Reader r(resp);
    return TakeStatus(resp, &r);
}

IpcStatus DiscoverWatch(PipeClient& c, uint64_t session, uint64_t fn, uint32_t args) {
    std::vector<uint8_t> req, resp;
    AppendPod(req, static_cast<uint32_t>(OpDiscoverWatch));
    AppendPod(req, session);
    AppendPod(req, fn);
    AppendPod(req, args);
    if (!c.Request(req, resp)) {
        return IpcStatus{HDL_E_FAILED};
    }
    Reader r(resp);
    return TakeStatus(resp, &r);
}

IpcStatus DiscoverUnwatchAll(PipeClient& c, uint64_t session) {
    std::vector<uint8_t> req, resp;
    AppendPod(req, static_cast<uint32_t>(OpDiscoverUnwatchAll));
    AppendPod(req, session);
    if (!c.Request(req, resp)) {
        return IpcStatus{HDL_E_FAILED};
    }
    Reader r(resp);
    return TakeStatus(resp, &r);
}

IpcStatus DiscoverActionBegin(PipeClient& c, uint64_t session, const char* name) {
    std::vector<uint8_t> req, resp;
    AppendPod(req, static_cast<uint32_t>(OpDiscoverActionBegin));
    AppendPod(req, session);
    AppendString(req, name ? name : "");
    if (!c.Request(req, resp)) {
        return IpcStatus{HDL_E_FAILED};
    }
    Reader r(resp);
    return TakeStatus(resp, &r);
}

IpcStatus DiscoverActionEnd(PipeClient& c, uint64_t session) {
    std::vector<uint8_t> req, resp;
    AppendPod(req, static_cast<uint32_t>(OpDiscoverActionEnd));
    AppendPod(req, session);
    if (!c.Request(req, resp)) {
        return IpcStatus{HDL_E_FAILED};
    }
    Reader r(resp);
    return TakeStatus(resp, &r);
}

IpcStatus DiscoverWatchRegion(PipeClient& c, uint64_t session, uint64_t base, uint32_t size) {
    std::vector<uint8_t> req, resp;
    AppendPod(req, static_cast<uint32_t>(OpDiscoverWatchRegion));
    AppendPod(req, session);
    AppendPod(req, base);
    AppendPod(req, size);
    if (!c.Request(req, resp)) {
        return IpcStatus{HDL_E_FAILED};
    }
    Reader r(resp);
    return TakeStatus(resp, &r);
}

IpcStatus DiscoverRank(PipeClient& c, uint64_t session, const char* name,
                       std::vector<HdlCandidate>* out, uint32_t flags) {
    std::vector<uint8_t> req, resp;
    AppendPod(req, static_cast<uint32_t>(OpDiscoverRankFunctions));
    AppendPod(req, session);
    AppendString(req, name ? name : "");
    AppendPod(req, flags);
    AppendPod(req, static_cast<uint32_t>(64));
    if (!c.Request(req, resp)) {
        return IpcStatus{HDL_E_FAILED};
    }
    Reader r(resp);
    IpcStatus s = TakeStatus(resp, &r);
    uint32_t count = 0;
    r.TakePod(count);
    if (out) {
        out->resize(count);
        for (uint32_t i = 0; i < count; ++i) {
            r.Take(&(*out)[i], sizeof(HdlCandidate));
        }
    }
    return s;
}

IpcStatus DiscoverSynth(PipeClient& c, uint64_t session, uint64_t cand_id, uint32_t before,
                        uint32_t after, uint32_t search_flags, const wchar_t* module_or_null,
                        HdlSynthesizedPattern* out) {
    std::vector<uint8_t> req, resp;
    AppendPod(req, static_cast<uint32_t>(OpDiscoverSynthesizePattern));
    AppendPod(req, session);
    AppendPod(req, cand_id);
    AppendPod(req, before);
    AppendPod(req, after);
    AppendPod(req, search_flags);
    AppendWString(req, module_or_null ? module_or_null : L"");
    if (!c.Request(req, resp)) {
        return IpcStatus{HDL_E_FAILED};
    }
    Reader r(resp);
    IpcStatus s = TakeStatus(resp, &r);
    HdlSynthesizedPattern pat{};
    r.Take(&pat, sizeof(pat));
    if (out) {
        *out = pat;
    }
    return s;
}

IpcStatus DiscoverConstraint(PipeClient& c, uint64_t session, uint32_t object_size,
                             const std::vector<HdlFieldPred>& preds, uint32_t search_flags,
                             const wchar_t* module_or_null, uint32_t max_results, const char* tag) {
    std::vector<uint8_t> req, resp;
    AppendPod(req, static_cast<uint32_t>(OpDiscoverConstraintScan));
    AppendPod(req, session);
    AppendPod(req, object_size);
    AppendPod(req, static_cast<uint32_t>(preds.size()));
    AppendPod(req, search_flags);
    AppendPod(req, max_results);
    AppendWString(req, module_or_null ? module_or_null : L"");
    AppendString(req, tag ? tag : "");
    for (const auto& p : preds) {
        AppendPod(req, p);
    }
    if (!c.Request(req, resp)) {
        return IpcStatus{HDL_E_FAILED};
    }
    Reader r(resp);
    return TakeStatus(resp, &r);
}

IpcStatus DiscoverGetCandidates(PipeClient& c, uint64_t session, std::vector<HdlCandidate>* out) {
    std::vector<uint8_t> req, resp;
    AppendPod(req, static_cast<uint32_t>(OpDiscoverGetCandidates));
    AppendPod(req, session);
    AppendPod(req, static_cast<uint32_t>(256));
    if (!c.Request(req, resp)) {
        return IpcStatus{HDL_E_FAILED};
    }
    Reader r(resp);
    IpcStatus s = TakeStatus(resp, &r);
    uint32_t count = 0;
    r.TakePod(count);
    if (out) {
        out->resize(count);
        for (uint32_t i = 0; i < count; ++i) {
            r.Take(&(*out)[i], sizeof(HdlCandidate));
        }
    }
    return s;
}

IpcStatus DiscoverCluster(PipeClient& c, uint64_t session, uint64_t seed, uint32_t object_size,
                          uint32_t search_flags, const wchar_t* module_or_null,
                          uint32_t max_results) {
    std::vector<uint8_t> req, resp;
    AppendPod(req, static_cast<uint32_t>(OpDiscoverClusterType));
    AppendPod(req, session);
    AppendPod(req, seed);
    AppendPod(req, object_size);
    AppendPod(req, search_flags);
    AppendPod(req, max_results);
    AppendWString(req, module_or_null ? module_or_null : L"");
    if (!c.Request(req, resp)) {
        return IpcStatus{HDL_E_FAILED};
    }
    Reader r(resp);
    return TakeStatus(resp, &r);
}

IpcStatus DiscoverAddCandidate(PipeClient& c, uint64_t session, uint32_t kind, uint64_t addr,
                               const char* tag, uint64_t* out_cand_id) {
    std::vector<uint8_t> req, resp;
    AppendPod(req, static_cast<uint32_t>(OpDiscoverAddCandidate));
    AppendPod(req, session);
    AppendPod(req, kind);
    AppendPod(req, addr);
    AppendString(req, tag ? tag : "");
    if (!c.Request(req, resp)) {
        return IpcStatus{HDL_E_FAILED};
    }
    Reader r(resp);
    IpcStatus s = TakeStatus(resp, &r);
    uint64_t id = 0;
    r.TakePod(id);
    if (out_cand_id) {
        *out_cand_id = id;
    }
    return s;
}

IpcStatus PathConsensus(PipeClient& c, uint64_t target, uint32_t max_depth, uint32_t max_offset,
                        uint32_t max_results, uint32_t search_flags, const wchar_t* module_or_null,
                        std::vector<HdlPointerPath>* out) {
    std::vector<uint8_t> req, resp;
    AppendPod(req, static_cast<uint32_t>(OpDiscoverPathConsensus));
    AppendPod(req, target);
    AppendPod(req, max_depth);
    AppendPod(req, max_offset);
    AppendPod(req, max_results);
    AppendPod(req, search_flags);
    AppendWString(req, module_or_null ? module_or_null : L"");
    if (!c.Request(req, resp)) {
        return IpcStatus{HDL_E_FAILED};
    }
    Reader r(resp);
    IpcStatus s = TakeStatus(resp, &r);
    uint32_t count = 0;
    r.TakePod(count);
    if (out) {
        out->resize(count);
        for (uint32_t i = 0; i < count; ++i) {
            r.Take(&(*out)[i], sizeof(HdlPointerPath));
        }
    }
    return s;
}

IpcStatus PathValidate(PipeClient& c, uint64_t expected, std::vector<HdlPointerPath>* paths) {
    if (!paths) {
        return IpcStatus{HDL_E_INVALID_ARG};
    }
    std::vector<uint8_t> req, resp;
    AppendPod(req, static_cast<uint32_t>(OpDiscoverPathValidate));
    AppendPod(req, expected);
    AppendPod(req, static_cast<uint32_t>(paths->size()));
    for (const auto& p : *paths) {
        AppendBytes(req, &p, sizeof(p));
    }
    if (!c.Request(req, resp)) {
        return IpcStatus{HDL_E_FAILED};
    }
    Reader r(resp);
    IpcStatus s = TakeStatus(resp, &r);
    uint32_t kept = 0;
    r.TakePod(kept);
    paths->resize(kept);
    for (uint32_t i = 0; i < kept; ++i) {
        r.Take(&(*paths)[i], sizeof(HdlPointerPath));
    }
    return s;
}

IpcStatus CallExport(PipeClient& c, const wchar_t* module, const char* name,
                     const std::vector<HdlCallArg>& args, uint32_t timeout_ms, HdlCallResult* out) {
    std::vector<uint8_t> req, resp;
    AppendPod(req, static_cast<uint32_t>(OpCallExport));
    AppendWString(req, module ? module : L"");
    AppendString(req, name ? name : "");
    AppendPod(req, static_cast<uint32_t>(args.size()));
    AppendPod(req, timeout_ms);
    AppendPod(req, static_cast<uint64_t>(0));
    for (const auto& a : args) {
        AppendPod(req, a.kind);
        AppendPod(req, a.size);
        AppendPod(req, a.u64);
    }
    if (!c.Request(req, resp)) {
        return IpcStatus{HDL_E_FAILED};
    }
    Reader r(resp);
    IpcStatus s = TakeStatus(resp, &r);
    HdlCallResult cr{};
    r.Take(&cr, sizeof(cr));
    if (out) {
        *out = cr;
    }
    return s;
}

IpcStatus FindCaves(PipeClient& c, const HdlCaveQuery& q, std::vector<HdlCaveInfo>* out) {
    std::vector<uint8_t> req, resp;
    AppendPod(req, static_cast<uint32_t>(OpFindCaves));
    AppendPod(req, q.min_size);
    AppendPod(req, q.fill_byte);
    AppendPod(req, q.search_flags);
    AppendPod(req, q.max_results);
    AppendPod(req, q.near_addr);
    AppendPod(req, q.max_distance);
    AppendWString(req, q.module_or_null ? q.module_or_null : L"");
    if (!c.Request(req, resp)) {
        return IpcStatus{HDL_E_FAILED};
    }
    Reader r(resp);
    IpcStatus s = TakeStatus(resp, &r);
    uint32_t count = 0;
    r.TakePod(count);
    if (out) {
        out->resize(count);
        for (uint32_t i = 0; i < count; ++i) {
            r.Take(&(*out)[i], sizeof(HdlCaveInfo));
        }
    }
    return s;
}

IpcStatus AllocNear(PipeClient& c, uint64_t near_addr, uint64_t max_distance, uint64_t size,
                    uint32_t protect, uint64_t* out_addr) {
    std::vector<uint8_t> req, resp;
    AppendPod(req, static_cast<uint32_t>(OpAllocNear));
    AppendPod(req, near_addr);
    AppendPod(req, max_distance);
    AppendPod(req, size);
    AppendPod(req, protect);
    if (!c.Request(req, resp)) {
        return IpcStatus{HDL_E_FAILED};
    }
    Reader r(resp);
    IpcStatus s = TakeStatus(resp, &r);
    uint64_t addr = 0;
    r.TakePod(addr);
    if (out_addr) {
        *out_addr = addr;
    }
    return s;
}

IpcStatus BuildStub(PipeClient& c, const HdlStubDesc& desc, HdlStubResult* out) {
    std::vector<uint8_t> req, resp;
    AppendPod(req, static_cast<uint32_t>(OpBuildStub));
    AppendPod(req, desc.kind);
    AppendPod(req, desc.flags);
    AppendPod(req, desc.target);
    AppendPod(req, desc.steal_from);
    AppendPod(req, desc.steal_min_bytes);
    AppendPod(req, desc.reserved);
    AppendPod(req, desc.alloc_rx);
    AppendPod(req, desc.raw_size);
    if (desc.raw_size && desc.raw) {
        AppendBytes(req, desc.raw, desc.raw_size);
    }
    if (!c.Request(req, resp)) {
        return IpcStatus{HDL_E_FAILED};
    }
    Reader r(resp);
    IpcStatus s = TakeStatus(resp, &r);
    HdlStubResult result{};
    r.Take(&result, sizeof(result));
    if (out) {
        *out = result;
    }
    return s;
}

IpcStatus PatchCreate(PipeClient& c, uint64_t addr, const uint8_t* bytes, uint32_t size,
                      const char* name, uint64_t* out_handle) {
    std::vector<uint8_t> req, resp;
    AppendPod(req, static_cast<uint32_t>(OpPatchCreate));
    AppendPod(req, addr);
    AppendPod(req, size);
    AppendString(req, name ? name : "");
    if (size && bytes) {
        AppendBytes(req, bytes, size);
    }
    if (!c.Request(req, resp)) {
        return IpcStatus{HDL_E_FAILED};
    }
    Reader r(resp);
    IpcStatus s = TakeStatus(resp, &r);
    uint64_t handle = 0;
    r.TakePod(handle);
    if (out_handle) {
        *out_handle = handle;
    }
    return s;
}

IpcStatus PatchEnable(PipeClient& c, uint64_t handle, int enable) {
    std::vector<uint8_t> req, resp;
    AppendPod(req, static_cast<uint32_t>(OpPatchEnable));
    AppendPod(req, handle);
    AppendPod(req, static_cast<int32_t>(enable));
    if (!c.Request(req, resp)) {
        return IpcStatus{HDL_E_FAILED};
    }
    Reader r(resp);
    return TakeStatus(resp, &r);
}

IpcStatus PatchRemove(PipeClient& c, uint64_t handle) {
    std::vector<uint8_t> req, resp;
    AppendPod(req, static_cast<uint32_t>(OpPatchRemove));
    AppendPod(req, handle);
    if (!c.Request(req, resp)) {
        return IpcStatus{HDL_E_FAILED};
    }
    Reader r(resp);
    return TakeStatus(resp, &r);
}

IpcStatus PatchEnum(PipeClient& c, std::vector<HdlPatchInfo>* out) {
    std::vector<uint8_t> req, resp;
    AppendPod(req, static_cast<uint32_t>(OpPatchEnum));
    if (!c.Request(req, resp)) {
        return IpcStatus{HDL_E_FAILED};
    }
    Reader r(resp);
    IpcStatus s = TakeStatus(resp, &r);
    uint32_t count = 0;
    r.TakePod(count);
    if (out) {
        out->resize(count);
        for (uint32_t i = 0; i < count; ++i) {
            r.Take(&(*out)[i], sizeof(HdlPatchInfo));
        }
    }
    return s;
}

IpcStatus WatchHw(PipeClient& c, uint64_t addr, uint32_t size, uint32_t access, uint32_t tid,
                  uint64_t* out_handle) {
    std::vector<uint8_t> req, resp;
    AppendPod(req, static_cast<uint32_t>(OpWatchHw));
    AppendPod(req, addr);
    AppendPod(req, size);
    AppendPod(req, access);
    AppendPod(req, tid);
    if (!c.Request(req, resp)) {
        return IpcStatus{HDL_E_FAILED};
    }
    Reader r(resp);
    IpcStatus s = TakeStatus(resp, &r);
    uint64_t handle = 0;
    r.TakePod(handle);
    if (out_handle) {
        *out_handle = handle;
    }
    return s;
}

IpcStatus WatchPage(PipeClient& c, uint64_t addr, uint64_t size, uint32_t mode, uint64_t* out_handle) {
    std::vector<uint8_t> req, resp;
    AppendPod(req, static_cast<uint32_t>(OpWatchPage));
    AppendPod(req, addr);
    AppendPod(req, size);
    AppendPod(req, mode);
    if (!c.Request(req, resp)) {
        return IpcStatus{HDL_E_FAILED};
    }
    Reader r(resp);
    IpcStatus s = TakeStatus(resp, &r);
    uint64_t handle = 0;
    r.TakePod(handle);
    if (out_handle) {
        *out_handle = handle;
    }
    return s;
}

IpcStatus Unwatch(PipeClient& c, uint64_t handle) {
    std::vector<uint8_t> req, resp;
    AppendPod(req, static_cast<uint32_t>(OpUnwatch));
    AppendPod(req, handle);
    if (!c.Request(req, resp)) {
        return IpcStatus{HDL_E_FAILED};
    }
    Reader r(resp);
    return TakeStatus(resp, &r);
}

IpcStatus ResolveExport(PipeClient& c, const wchar_t* module, const char* name, uint64_t* out_addr) {
    std::vector<uint8_t> req, resp;
    AppendPod(req, static_cast<uint32_t>(OpResolveExport));
    AppendWString(req, module ? module : L"");
    AppendString(req, name ? name : "");
    if (!c.Request(req, resp)) {
        return IpcStatus{HDL_E_FAILED};
    }
    Reader r(resp);
    IpcStatus s = TakeStatus(resp, &r);
    uint64_t addr = 0;
    r.TakePod(addr);
    if (out_addr) {
        *out_addr = addr;
    }
    return s;
}

IpcStatus EnumImports(PipeClient& c, uint64_t module_base, std::vector<HdlImportInfo>* out) {
    std::vector<uint8_t> req, resp;
    AppendPod(req, static_cast<uint32_t>(OpEnumImports));
    AppendPod(req, module_base);
    if (!c.Request(req, resp)) {
        return IpcStatus{HDL_E_FAILED};
    }
    Reader r(resp);
    IpcStatus s = TakeStatus(resp, &r);
    uint32_t count = 0;
    r.TakePod(count);
    if (out) {
        out->resize(count);
        for (uint32_t i = 0; i < count; ++i) {
            r.Take(&(*out)[i], sizeof(HdlImportInfo));
        }
    }
    return s;
}

IpcStatus Fingerprint(PipeClient& c, uint32_t scan_flags, std::vector<HdlFingerprintTag>* out) {
    std::vector<uint8_t> req, resp;
    AppendPod(req, static_cast<uint32_t>(OpFingerprint));
    AppendPod(req, scan_flags ? scan_flags : HDL_FP_SCAN_DEFAULT);
    if (!c.Request(req, resp)) {
        return IpcStatus{HDL_E_FAILED};
    }
    Reader r(resp);
    IpcStatus s = TakeStatus(resp, &r);
    uint32_t count = 0;
    r.TakePod(count);
    if (out) {
        out->resize(count);
        for (uint32_t i = 0; i < count; ++i) {
            r.Take(&(*out)[i], sizeof(HdlFingerprintTag));
        }
    }
    return s;
}

}  // namespace hdlcli
