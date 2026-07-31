#include "handlers.hpp"

#include "jobs.hpp"
#include "memory.hpp"
#include "protocol.hpp"

#include <string>
#include <vector>

namespace hdl {
namespace ipc {

bool HandleSearchMemory(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t start = 0;
    uint64_t size = 0;
    uint32_t max_hits = 0;
    std::string pattern;
    if (!r.TakePod(start) || !r.TakePod(size) || !r.TakePod(max_hits) || !r.TakeString(pattern)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    uint64_t job_id = 0;
    uint32_t timeout_ms = 0;
    uint32_t flags = 0;
    TakeOptionalJobTimeoutFlags(r, &job_id, &timeout_ms, &flags);
    auto job = BindJob(job_id, timeout_ms);

    /* Positive max_hits caps the IPC reply; 0 = unlimited scan / return all (prefer --stream). */
    if (max_hits > 100000) {
        max_hits = 100000;
    }

    HdlSearchSession* session = nullptr;
    HdlStatus st = SearchCreate(&session);
    uint32_t hit_count = 0;
    uint32_t reply_count = 0;
    std::vector<uint64_t> hits;
    if (st == HDL_OK) {
        HdlSearchDesc desc{};
        desc.start = start;
        desc.size = size;
        desc.value_type = HDL_VALUE_BYTES;
        desc.cmp = HDL_CMP_EXACT;
        desc.alignment = 1; /* AOB is always byte-unaligned */
        desc.max_results = max_hits; /* 0 = unlimited */
        desc.value = pattern.c_str();
        desc.value_size = 0;
        st = SearchFirst(session, &desc, MakeToken(nullptr, job));
        if (st == HDL_OK || st == HDL_E_CANCELLED || st == HDL_E_TIMEOUT) {
            SearchGetCount(session, &hit_count);
            if (hit_count) {
                hits.resize(hit_count);
                uint32_t all = hit_count;
                SearchGetHits(session, hits.data(), &all);
                hit_count = all;
            }
            reply_count = (max_hits && max_hits < hit_count) ? max_hits : hit_count;
        }
        SearchClose(session);
    }
    if (job && !job_id) {
        JobClose(job->id);
    }

    if ((flags & HDL_IPC_REQ_STREAM)) {
        return WriteStreamed(pipe, st, hits.empty() ? nullptr : hits.data(), reply_count, 256);
    }

    AppendPod(resp, static_cast<int32_t>(st));
    AppendPod(resp, reply_count);
    if (reply_count && !hits.empty()) {
        AppendBytes(resp, hits.data(), reply_count * sizeof(uint64_t));
    }
    return WriteFrame(pipe, resp);
}

bool HandleSearchCreate(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    (void)r;
    std::vector<uint8_t> resp;
    HdlSearchSession* session = nullptr;
    const HdlStatus st = SearchCreate(&session);
    uint64_t id = 0;
    if (st == HDL_OK) {
        id = AllocSearchSession(session);
    }
    AppendPod(resp, static_cast<int32_t>(st));
    AppendPod(resp, id);
    return WriteFrame(pipe, resp);
}

bool HandleSearchClose(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t id = 0;
    if (!r.TakePod(id)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    HdlSearchSession* session = nullptr;
    if (!TakeSearchSession(id, &session)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_NOT_FOUND));
        return WriteFrame(pipe, resp);
    }
    SearchClose(session);
    AppendPod(resp, static_cast<int32_t>(HDL_OK));
    return WriteFrame(pipe, resp);
}

bool HandleSearchReset(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t id = 0;
    if (!r.TakePod(id)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    HdlSearchSession* session = FindSession(id);
    if (!session) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_NOT_FOUND));
        return WriteFrame(pipe, resp);
    }
    SearchReset(session);
    AppendPod(resp, static_cast<int32_t>(HDL_OK));
    return WriteFrame(pipe, resp);
}

bool HandleSearchFirst(HANDLE pipe, proto::Reader& r) {
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
    if (r.left >= sizeof(uint32_t)) {
        /* Extended scope: search_flags + module wstring (may be empty). */
        if (!r.TakePod(search_flags) || !r.TakeWString(module)) {
            AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
            return WriteFrame(pipe, resp);
        }
    }

    uint64_t job_id = 0;
    uint32_t timeout_ms = 0;
    uint32_t flags = 0;
    TakeOptionalJobTimeoutFlags(r, &job_id, &timeout_ms, &flags);
    (void)flags;
    auto job = BindJob(job_id, timeout_ms);

    HdlSearchSession* session = FindSession(id);
    if (!session) {
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
    const HdlStatus st = SearchFirst(session, &desc, MakeToken(nullptr, job));
    if (job && !job_id) {
        JobClose(job->id);
    }
    uint32_t count = 0;
    SearchGetCount(session, &count);
    AppendPod(resp, static_cast<int32_t>(st));
    AppendPod(resp, count);
    return WriteFrame(pipe, resp);
}

bool HandleSearchNext(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t id = 0;
    int32_t cmp = 0;
    uint32_t value_len = 0;
    if (!r.TakePod(id) || !r.TakePod(cmp) || !r.TakePod(value_len) || r.left < value_len) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    const uint8_t* value_ptr = value_len ? r.p : nullptr;
    r.p += value_len;
    r.left -= value_len;

    uint64_t job_id = 0;
    uint32_t timeout_ms = 0;
    uint32_t flags = 0;
    TakeOptionalJobTimeoutFlags(r, &job_id, &timeout_ms, &flags);
    (void)flags;
    auto job = BindJob(job_id, timeout_ms);

    HdlSearchSession* session = FindSession(id);
    if (!session) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_NOT_FOUND));
        return WriteFrame(pipe, resp);
    }
    const HdlStatus st =
        SearchNext(session, cmp, value_ptr, value_len, MakeToken(nullptr, job));
    if (job && !job_id) {
        JobClose(job->id);
    }
    uint32_t count = 0;
    SearchGetCount(session, &count);
    AppendPod(resp, static_cast<int32_t>(st));
    AppendPod(resp, count);
    return WriteFrame(pipe, resp);
}

bool HandleSearchGetHits(HANDLE pipe, proto::Reader& r) {
    using namespace proto;
    std::vector<uint8_t> resp;
    uint64_t id = 0;
    uint32_t max_hits = 0;
    if (!r.TakePod(id) || !r.TakePod(max_hits)) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    uint64_t job_id = 0;
    uint32_t timeout_ms = 0;
    uint32_t flags = 0;
    TakeOptionalJobTimeoutFlags(r, &job_id, &timeout_ms, &flags);
    (void)job_id;
    (void)timeout_ms;

    if (max_hits > 100000) {
        max_hits = 100000;
    }
    HdlSearchSession* session = FindSession(id);
    if (!session) {
        AppendPod(resp, static_cast<int32_t>(HDL_E_NOT_FOUND));
        return WriteFrame(pipe, resp);
    }
    uint32_t total = 0;
    SearchGetCount(session, &total);
    const uint32_t got = (max_hits && max_hits < total) ? max_hits : total;
    std::vector<uint64_t> all_hits(total ? total : 1);
    uint32_t all = total;
    const HdlStatus st = total ? SearchGetHits(session, all_hits.data(), &all) : HDL_OK;

    if (flags & HDL_IPC_REQ_STREAM) {
        return WriteStreamed(pipe, st, all_hits.data(), total, got, 256);
    }

    AppendPod(resp, static_cast<int32_t>(st));
    AppendPod(resp, total);
    AppendPod(resp, got);
    if (got) {
        AppendBytes(resp, all_hits.data(), got * sizeof(uint64_t));
    }
    return WriteFrame(pipe, resp);
}

}  // namespace ipc
}  // namespace hdl
