#include "handlers.hpp"

#include "discover.hpp"
#include "protocol.hpp"

#include <string>
#include <vector>

namespace hdl {
namespace ipc {

bool HandleDiscoverCreate(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    (void)r;
    std::vector<uint8_t> resp;
    HdlDiscoverSession* session = nullptr;
    const HdlStatus st = DiscoverCreate(&session);
    uint64_t id = 0;
    if (st == HDL_OK && session) {
        id = AllocDiscoverSession(session);
    }
    AppendPod(resp, static_cast<int32_t>(st));
    AppendPod(resp, id);
    return WriteFrame(pipe, resp);
}

bool HandleDiscoverClose(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t id = 0;
    if (!r.TakePod(id)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    HdlDiscoverSession* session = nullptr;
    if (!TakeDiscoverSession(id, &session)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_NOT_FOUND));
        return WriteFrame(pipe, resp);
    }
    DiscoverClose(session);
    AppendPod(resp, static_cast<int32_t>(HDL_OK));
    return WriteFrame(pipe, resp);
}

bool HandleDiscoverAddCandidate(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t id = 0;
    uint32_t kind = 0;
    uint64_t address = 0;
    std::string tag;
    if (!r.TakePod(id) || !r.TakePod(kind) || !r.TakePod(address) || !r.TakeString(tag)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    HdlDiscoverSession* session = FindDiscover(id);
    uint64_t cand_id = 0;
    const HdlStatus st =
        session ? DiscoverAddCandidate(session, kind, address, tag.empty() ? nullptr : tag.c_str(),
                                       &cand_id)
                : HDL_E_NOT_FOUND;
    AppendPod(resp, static_cast<int32_t>(st));
    AppendPod(resp, cand_id);
    return WriteFrame(pipe, resp);
}

bool HandleDiscoverScanValue(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t id = 0;
    uint64_t start = 0;
    uint64_t size = 0;
    int32_t value_type = 0;
    int32_t cmp = 0;
    uint32_t alignment = 0;
    uint32_t max_results = 0;
    uint32_t value_len = 0;
    if (!r.TakePod(id) || !r.TakePod(start) || !r.TakePod(size) || !r.TakePod(value_type) ||
        !r.TakePod(cmp) || !r.TakePod(alignment) || !r.TakePod(max_results) ||
        !r.TakePod(value_len) || r.left < value_len) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    const uint8_t* value_ptr = value_len ? r.p : nullptr;
    r.p += value_len;
    r.left -= value_len;

    uint32_t search_flags = 0;
    std::wstring module;
    std::string tag;
    if (!r.TakePod(search_flags) || !r.TakeWString(module) || !r.TakeString(tag)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }

    uint64_t job_id = 0;
    uint32_t timeout_ms = 0;
    uint32_t flags = 0;
    TakeOptionalJobTimeoutFlags(r, &job_id, &timeout_ms, &flags);
    (void)flags;
    auto job = BindJob(job_id, timeout_ms);

    HdlDiscoverSession* session = FindDiscover(id);
    if (!session) {
        if (job && !job_id) {
            JobClose(job->id);
        }
        AppendPod(resp, static_cast<int32_t>(HDL_E_NOT_FOUND));
        return WriteFrame(pipe, resp);
    }

    HdlSearchDesc desc{};
    desc.start = start;
    desc.size = size;
    desc.value_type = value_type;
    desc.cmp = cmp;
    desc.alignment = alignment;
    desc.max_results = max_results;
    desc.value = value_ptr;
    desc.value_size = value_len;
    desc.flags = search_flags;
    desc.module_or_null = module.empty() ? nullptr : module.c_str();

    uint32_t before = 0;
    DiscoverGetCandidates(session, nullptr, &before);

    const HdlStatus st =
        DiscoverScanValue(session, &desc, tag.empty() ? nullptr : tag.c_str(), MakeToken(nullptr, job));
    if (job && !job_id) {
        JobClose(job->id);
    }

    uint32_t after = 0;
    DiscoverGetCandidates(session, nullptr, &after);
    const uint32_t added = (after >= before) ? (after - before) : 0;
    AppendPod(resp, static_cast<int32_t>(st));
    AppendPod(resp, added);
    return WriteFrame(pipe, resp);
}

bool HandleDiscoverConstraintScan(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t id = 0;
    uint32_t object_size = 0;
    uint32_t pred_count = 0;
    uint32_t search_flags = 0;
    uint32_t max_results = 0;
    std::wstring module;
    std::string tag;
    if (!r.TakePod(id) || !r.TakePod(object_size) || !r.TakePod(pred_count) ||
        pred_count > 32 || !r.TakePod(search_flags) || !r.TakePod(max_results) ||
        !r.TakeWString(module) || !r.TakeString(tag)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    std::vector<HdlFieldPred> preds(pred_count);
    for (uint32_t i = 0; i < pred_count; ++i) {
        if (!r.TakePod(preds[i])) {
            AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
            return WriteFrame(pipe, resp);
        }
    }
    HdlDiscoverSession* session = FindDiscover(id);
    const HdlStatus st =
        session ? DiscoverConstraintScan(session, object_size, preds.data(), pred_count,
                                         search_flags, module.empty() ? nullptr : module.c_str(),
                                         max_results, tag.empty() ? nullptr : tag.c_str(),
                                         nullptr)
                : HDL_E_NOT_FOUND;
    AppendPod(resp, static_cast<int32_t>(st));
    return WriteFrame(pipe, resp);
}

bool HandleDiscoverSynthesizePattern(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t id = 0;
    uint64_t cand_id = 0;
    uint32_t before = 0;
    uint32_t after = 0;
    uint32_t search_flags = 0;
    std::wstring module;
    if (!r.TakePod(id) || !r.TakePod(cand_id) || !r.TakePod(before) || !r.TakePod(after) ||
        !r.TakePod(search_flags) || !r.TakeWString(module)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    HdlDiscoverSession* session = FindDiscover(id);
    HdlSynthesizedPattern out{};
    const HdlStatus st =
        session ? DiscoverSynthesizePattern(session, cand_id, before, after, search_flags,
                                            module.empty() ? nullptr : module.c_str(), &out,
                                            nullptr)
                : HDL_E_NOT_FOUND;
    AppendPod(resp, static_cast<int32_t>(st));
    AppendBytes(resp, &out, sizeof(out));
    return WriteFrame(pipe, resp);
}

bool HandleDiscoverPathConsensus(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t target = 0;
    uint32_t max_depth = 0;
    uint32_t max_offset = 0;
    uint32_t max_results = 0;
    uint32_t search_flags = 0;
    std::wstring module;
    if (!r.TakePod(target) || !r.TakePod(max_depth) || !r.TakePod(max_offset) ||
        !r.TakePod(max_results) || !r.TakePod(search_flags) || !r.TakeWString(module)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    if (max_results == 0 || max_results > 256) {
        max_results = 64;
    }
    std::vector<HdlPointerPath> paths(max_results);
    uint32_t count = max_results;
    const HdlStatus st =
        DiscoverPathConsensus(target, max_depth, max_offset, max_results, search_flags,
                              module.empty() ? nullptr : module.c_str(), paths.data(), &count,
                              nullptr);
    AppendPod(resp, static_cast<int32_t>(st));
    AppendPod(resp, count);
    if (st == HDL_OK && count) {
        AppendBytes(resp, paths.data(), count * sizeof(HdlPointerPath));
    }
    return WriteFrame(pipe, resp);
}

bool HandleDiscoverPathValidate(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t expected = 0;
    uint32_t count = 0;
    if (!r.TakePod(expected) || !r.TakePod(count) || count > 256) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    std::vector<HdlPointerPath> paths(count);
    for (uint32_t i = 0; i < count; ++i) {
        if (!r.Take(&paths[i], sizeof(HdlPointerPath))) {
            AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
            return WriteFrame(pipe, resp);
        }
    }
    uint32_t kept = count;
    const HdlStatus st = DiscoverPathValidate(paths.data(), &kept, expected);
    AppendPod(resp, static_cast<int32_t>(st));
    AppendPod(resp, kept);
    if (st == HDL_OK && kept) {
        AppendBytes(resp, paths.data(), kept * sizeof(HdlPointerPath));
    }
    return WriteFrame(pipe, resp);
}

bool HandleDiscoverWatch(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t id = 0;
    uint64_t fn = 0;
    uint32_t arg_count = 0;
    if (!r.TakePod(id) || !r.TakePod(fn) || !r.TakePod(arg_count)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    HdlDiscoverSession* session = FindDiscover(id);
    const HdlStatus st = session ? DiscoverWatch(session, fn, arg_count) : HDL_E_NOT_FOUND;
    AppendPod(resp, static_cast<int32_t>(st));
    return WriteFrame(pipe, resp);
}

bool HandleDiscoverUnwatchAll(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t id = 0;
    if (!r.TakePod(id)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    HdlDiscoverSession* session = FindDiscover(id);
    const HdlStatus st = session ? DiscoverUnwatchAll(session) : HDL_E_NOT_FOUND;
    AppendPod(resp, static_cast<int32_t>(st));
    return WriteFrame(pipe, resp);
}

bool HandleDiscoverActionBegin(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t id = 0;
    std::string name;
    if (!r.TakePod(id) || !r.TakeString(name)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    HdlDiscoverSession* session = FindDiscover(id);
    const HdlStatus st =
        session ? DiscoverActionBegin(session, name.c_str()) : HDL_E_NOT_FOUND;
    AppendPod(resp, static_cast<int32_t>(st));
    return WriteFrame(pipe, resp);
}

bool HandleDiscoverActionEnd(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t id = 0;
    if (!r.TakePod(id)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    HdlDiscoverSession* session = FindDiscover(id);
    const HdlStatus st = session ? DiscoverActionEnd(session) : HDL_E_NOT_FOUND;
    AppendPod(resp, static_cast<int32_t>(st));
    return WriteFrame(pipe, resp);
}

bool HandleDiscoverWatchRegion(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t id = 0;
    uint64_t base = 0;
    uint32_t size = 0;
    if (!r.TakePod(id) || !r.TakePod(base) || !r.TakePod(size)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    HdlDiscoverSession* session = FindDiscover(id);
    const HdlStatus st = session ? DiscoverWatchRegion(session, base, size) : HDL_E_NOT_FOUND;
    AppendPod(resp, static_cast<int32_t>(st));
    return WriteFrame(pipe, resp);
}

bool HandleDiscoverGetHeat(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t id = 0;
    uint64_t base = 0;
    uint32_t max_fields = 0;
    if (!r.TakePod(id) || !r.TakePod(base) || !r.TakePod(max_fields)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    if (max_fields == 0 || max_fields > 512) {
        max_fields = 64;
    }
    HdlDiscoverSession* session = FindDiscover(id);
    std::vector<HdlHeatField> fields(max_fields);
    uint32_t count = max_fields;
    HdlStatus st =
        session ? DiscoverGetHeat(session, base, fields.data(), &count) : HDL_E_NOT_FOUND;
    if (st == HDL_E_BUFFER_SMALL) {
        fields.resize(count);
        count = static_cast<uint32_t>(fields.size());
        st = DiscoverGetHeat(session, base, fields.data(), &count);
    }
    AppendPod(resp, static_cast<int32_t>(st));
    AppendPod(resp, count);
    if (st == HDL_OK && count) {
        AppendBytes(resp, fields.data(), count * sizeof(HdlHeatField));
    }
    return WriteFrame(pipe, resp);
}

bool HandleDiscoverRankFunctions(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t id = 0;
    std::string name;
    uint32_t flags = 0;
    uint32_t max_out = 0;
    if (!r.TakePod(id) || !r.TakeString(name) || !r.TakePod(flags) || !r.TakePod(max_out)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    if (max_out == 0 || max_out > 256) {
        max_out = 64;
    }
    HdlDiscoverSession* session = FindDiscover(id);
    std::vector<HdlCandidate> cands(max_out);
    uint32_t count = max_out;
    HdlStatus st = session ? DiscoverRankFunctions(session, name.c_str(), flags, cands.data(), &count)
                           : HDL_E_NOT_FOUND;
    if (st == HDL_E_BUFFER_SMALL) {
        cands.resize(count);
        count = static_cast<uint32_t>(cands.size());
        st = DiscoverRankFunctions(session, name.c_str(), flags, cands.data(), &count);
    }
    AppendPod(resp, static_cast<int32_t>(st));
    AppendPod(resp, count);
    if (st == HDL_OK && count) {
        AppendBytes(resp, cands.data(), count * sizeof(HdlCandidate));
    }
    return WriteFrame(pipe, resp);
}

bool HandleDiscoverClusterType(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t id = 0;
    uint64_t seed = 0;
    uint32_t object_size = 0;
    uint32_t search_flags = 0;
    uint32_t max_results = 0;
    std::wstring module;
    if (!r.TakePod(id) || !r.TakePod(seed) || !r.TakePod(object_size) ||
        !r.TakePod(search_flags) || !r.TakePod(max_results) || !r.TakeWString(module)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    HdlDiscoverSession* session = FindDiscover(id);
    const HdlStatus st =
        session ? DiscoverClusterType(session, seed, object_size, search_flags,
                                      module.empty() ? nullptr : module.c_str(), max_results,
                                      nullptr)
                : HDL_E_NOT_FOUND;
    AppendPod(resp, static_cast<int32_t>(st));
    return WriteFrame(pipe, resp);
}

bool HandleDiscoverGetCandidates(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t id = 0;
    uint32_t max_out = 0;
    if (!r.TakePod(id) || !r.TakePod(max_out)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    if (max_out == 0 || max_out > 1024) {
        max_out = 256;
    }
    HdlDiscoverSession* session = FindDiscover(id);
    std::vector<HdlCandidate> cands(max_out);
    uint32_t count = max_out;
    HdlStatus st =
        session ? DiscoverGetCandidates(session, cands.data(), &count) : HDL_E_NOT_FOUND;
    if (st == HDL_E_BUFFER_SMALL) {
        cands.resize(count);
        count = static_cast<uint32_t>(cands.size());
        st = DiscoverGetCandidates(session, cands.data(), &count);
    }
    AppendPod(resp, static_cast<int32_t>(st));
    AppendPod(resp, count);
    if (st == HDL_OK && count) {
        AppendBytes(resp, cands.data(), count * sizeof(HdlCandidate));
    }
    return WriteFrame(pipe, resp);
}

bool HandleDiscoverWatchImport(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t id = 0;
    std::wstring module;
    std::string dll;
    std::string import_name;
    uint32_t arg_count = 0;
    if (!r.TakePod(id) || !r.TakeWString(module) || !r.TakeString(dll) ||
        !r.TakeString(import_name) || !r.TakePod(arg_count)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    HdlDiscoverSession* session = FindDiscover(id);
    const HdlStatus st =
        session ? DiscoverWatchImport(session, module.empty() ? nullptr : module.c_str(),
                                      dll.c_str(), import_name.c_str(), arg_count)
                : HDL_E_NOT_FOUND;
    AppendPod(resp, static_cast<int32_t>(st));
    return WriteFrame(pipe, resp);
}

bool HandleDiscoverResetHeat(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t id = 0;
    uint64_t base = 0;
    if (!r.TakePod(id) || !r.TakePod(base)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    HdlDiscoverSession* session = FindDiscover(id);
    const HdlStatus st = session ? DiscoverResetHeat(session, base) : HDL_E_NOT_FOUND;
    AppendPod(resp, static_cast<int32_t>(st));
    return WriteFrame(pipe, resp);
}

bool HandleDiscoverExport(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t id = 0;
    uint32_t cap = 0;
    if (!r.TakePod(id) || !r.TakePod(cap)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    if (cap == 0) {
        cap = 65536;
    }
    HdlDiscoverSession* session = FindDiscover(id);
    std::vector<char> buf(cap);
    uint32_t size = cap;
    HdlStatus st = session ? DiscoverExport(session, buf.data(), &size) : HDL_E_NOT_FOUND;
    if (st == HDL_E_BUFFER_SMALL) {
        buf.resize(size);
        size = static_cast<uint32_t>(buf.size());
        st = DiscoverExport(session, buf.data(), &size);
    }
    AppendPod(resp, static_cast<int32_t>(st));
    AppendPod(resp, size);
    if (st == HDL_OK && size) {
        AppendBytes(resp, buf.data(), size);
    }
    return WriteFrame(pipe, resp);
}

bool HandleDiscoverImport(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t id = 0;
    std::string json;
    if (!r.TakePod(id) || !r.TakeString(json)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    HdlDiscoverSession* session = FindDiscover(id);
    const HdlStatus st =
        session ? DiscoverImport(session, json.c_str(), static_cast<uint32_t>(json.size()))
                : HDL_E_NOT_FOUND;
    AppendPod(resp, static_cast<int32_t>(st));
    return WriteFrame(pipe, resp);
}

bool HandleDiscoverDiffObjects(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t id = 0;
    uint32_t count = 0;
    uint32_t max_size = 0;
    uint32_t max_fields = 0;
    if (!r.TakePod(id) || !r.TakePod(count) || count > 64 || !r.TakePod(max_size) ||
        !r.TakePod(max_fields)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    std::vector<uint64_t> addrs(count);
    for (uint32_t i = 0; i < count; ++i) {
        if (!r.TakePod(addrs[i])) {
            AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
            return WriteFrame(pipe, resp);
        }
    }
    if (max_fields == 0 || max_fields > 512) {
        max_fields = 64;
    }
    HdlDiscoverSession* session = FindDiscover(id);
    std::vector<HdlHeatField> fields(max_fields);
    uint32_t out_count = max_fields;
    HdlStatus st = session ? DiscoverDiffObjects(session, addrs.data(), count, max_size,
                                                 fields.data(), &out_count)
                           : HDL_E_NOT_FOUND;
    if (st == HDL_E_BUFFER_SMALL) {
        fields.resize(out_count);
        out_count = static_cast<uint32_t>(fields.size());
        st = DiscoverDiffObjects(session, addrs.data(), count, max_size, fields.data(), &out_count);
    }
    AppendPod(resp, static_cast<int32_t>(st));
    AppendPod(resp, out_count);
    if (st == HDL_OK && out_count) {
        AppendBytes(resp, fields.data(), out_count * sizeof(HdlHeatField));
    }
    return WriteFrame(pipe, resp);
}

bool HandleDiscoverApplyWatchHits(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t id = 0;
    uint64_t object_base = 0;
    uint32_t size = 0;
    if (!r.TakePod(id) || !r.TakePod(object_base) || !r.TakePod(size)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    HdlDiscoverSession* session = FindDiscover(id);
    const HdlStatus st =
        session ? DiscoverApplyWatchHits(session, object_base, size) : HDL_E_NOT_FOUND;
    AppendPod(resp, static_cast<int32_t>(st));
    return WriteFrame(pipe, resp);
}

bool HandleDiscoverGetEvidence(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t id = 0;
    uint64_t cand_id = 0;
    uint32_t cap = 0;
    if (!r.TakePod(id) || !r.TakePod(cand_id) || !r.TakePod(cap)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    if (cap == 0 || cap > 160) {
        cap = 160;
    }
    HdlDiscoverSession* session = FindDiscover(id);
    std::string ev;
    ev.resize(cap);
    const HdlStatus st =
        session ? DiscoverGetCandidateEvidence(session, cand_id, ev.data(), cap) : HDL_E_NOT_FOUND;
    AppendPod(resp, static_cast<int32_t>(st));
    AppendString(resp, st == HDL_OK ? ev.c_str() : "");
    return WriteFrame(pipe, resp);
}

}  // namespace ipc
}  // namespace hdl
