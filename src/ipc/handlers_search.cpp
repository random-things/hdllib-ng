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
    uint64_t start = 0;
    uint64_t size = 0;
    uint32_t max_hits = 0;
    std::string pattern;
    if (!r.TakePod(start) || !r.TakePod(size) || !r.TakePod(max_hits) || !r.TakeString(pattern)) {
        return WriteSearchStreamError(pipe, HDL_E_INVALID_ARG);
    }
    uint64_t job_id = 0;
    uint32_t timeout_ms = 0;
    uint32_t flags = 0;
    TakeOptionalJobTimeoutFlags(r, &job_id, &timeout_ms, &flags);
    (void)flags; /* search always streams */
    auto job = BindJob(job_id, timeout_ms);

    SearchHitStreamer stream(pipe);
    HdlSearchSession* session = nullptr;
    HdlStatus st = SearchCreate(&session);
    if (st == HDL_OK) {
        SearchSetRetainHits(session, false); /* stream-only; client accumulates */
        SearchSetHitHandler(session, &SearchHitStreamer::OnHitThunk, &stream);

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
        SearchClose(session);
    }
    if (job && !job_id) {
        JobClose(job->id);
    }
    return stream.Finish(st);
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
        return WriteSearchStreamError(pipe, HDL_E_INVALID_ARG);
    }
    const uint8_t* value_ptr = value_len ? r.p : nullptr;
    r.p += value_len;
    r.left -= value_len;

    uint32_t search_flags = 0;
    std::wstring module;
    if (r.left >= sizeof(uint32_t)) {
        /* Extended scope: search_flags + module wstring (may be empty). */
        if (!r.TakePod(search_flags) || !r.TakeWString(module)) {
            return WriteSearchStreamError(pipe, HDL_E_INVALID_ARG);
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
        if (job && !job_id) {
            JobClose(job->id);
        }
        return WriteSearchStreamError(pipe, HDL_E_NOT_FOUND);
    }

    /* Stream hits as found (bounded buffer + WriteFile backpressure); retain for --next. */
    SearchHitStreamer stream(pipe);
    SearchSetRetainHits(session, true);
    SearchSetHitHandler(session, &SearchHitStreamer::OnHitThunk, &stream);

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
    SearchSetHitHandler(session, nullptr, nullptr);
    if (job && !job_id) {
        JobClose(job->id);
    }
    return stream.Finish(st);
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
    uint64_t id = 0;
    uint32_t max_hits = 0;
    if (!r.TakePod(id) || !r.TakePod(max_hits)) {
        return WriteSearchStreamError(pipe, HDL_E_INVALID_ARG);
    }
    uint64_t job_id = 0;
    uint32_t timeout_ms = 0;
    uint32_t flags = 0;
    TakeOptionalJobTimeoutFlags(r, &job_id, &timeout_ms, &flags);
    (void)job_id;
    (void)timeout_ms;
    (void)flags;

    HdlSearchSession* session = FindSession(id);
    if (!session) {
        return WriteSearchStreamError(pipe, HDL_E_NOT_FOUND);
    }
    uint32_t total = 0;
    SearchGetCount(session, &total);
    const uint32_t got = (max_hits && max_hits < total) ? max_hits : total;
    std::vector<uint64_t> all_hits(total ? total : 1);
    uint32_t all = total;
    const HdlStatus st = total ? SearchGetHits(session, all_hits.data(), &all) : HDL_OK;
    return WriteStreamed(pipe, st, all_hits.data(), total, got, kSearchStreamCap);
}

}  // namespace ipc
}  // namespace hdl
