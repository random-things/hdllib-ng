#include "discover_internal.hpp"

namespace hdl {

HdlStatus DiscoverCreate(HdlDiscoverSession** out_session) {
    if (!out_session) {
        return HDL_E_INVALID_ARG;
    }
    auto* s = new (std::nothrow) Session();
    if (!s) {
        return HDL_E_NO_MEM;
    }
    {
        std::lock_guard<std::mutex> lock(g_sessions_mu);
        g_sessions.insert(s);
    }
    *out_session = reinterpret_cast<HdlDiscoverSession*>(s);
    return HDL_OK;
}

void DiscoverClose(HdlDiscoverSession* session) {
    if (!session) {
        return;
    }
    auto* s = reinterpret_cast<Session*>(session);
    {
        std::lock_guard<std::mutex> lock(g_sessions_mu);
        g_sessions.erase(s);
    }
    DiscoverUnwatchAll(session);
    delete s;
}

void DiscoverCloseAll() {
    std::vector<Session*> copy;
    {
        std::lock_guard<std::mutex> lock(g_sessions_mu);
        copy.assign(g_sessions.begin(), g_sessions.end());
        g_sessions.clear();
    }
    for (Session* s : copy) {
        DiscoverUnwatchAll(reinterpret_cast<HdlDiscoverSession*>(s));
        delete s;
    }
}

HdlStatus DiscoverAddCandidate(HdlDiscoverSession* session, uint32_t kind, uint64_t address,
                               const char* tag_or_null, uint64_t* out_id) {
    if (!session || !address ||
        (kind != HDL_CAND_ADDRESS && kind != HDL_CAND_FUNCTION && kind != HDL_CAND_OBJECT &&
         kind != HDL_CAND_FIELD)) {
        return HDL_E_INVALID_ARG;
    }
    auto* s = reinterpret_cast<Session*>(session);
    std::lock_guard<std::mutex> lock(s->mu);
    HdlCandidate c = MakeCand(s, kind, address, tag_or_null, 50);
    if (out_id) {
        *out_id = c.id;
    }
    s->cands.push_back(c);
    return HDL_OK;
}

HdlStatus DiscoverGetCandidates(HdlDiscoverSession* session, HdlCandidate* out,
                                uint32_t* inout_count) {
    if (!session || !inout_count) {
        return HDL_E_INVALID_ARG;
    }
    auto* s = reinterpret_cast<Session*>(session);
    std::lock_guard<std::mutex> lock(s->mu);
    const uint32_t need = static_cast<uint32_t>(s->cands.size());
    if (!out || *inout_count < need) {
        *inout_count = need;
        return need ? HDL_E_BUFFER_SMALL : HDL_OK;
    }
    if (need) {
        memcpy(out, s->cands.data(), need * sizeof(HdlCandidate));
    }
    *inout_count = need;
    return HDL_OK;
}

HdlStatus DiscoverResetHeat(HdlDiscoverSession* session, uint64_t base) {
    if (!session) {
        return HDL_E_INVALID_ARG;
    }
    auto* s = reinterpret_cast<Session*>(session);
    std::lock_guard<std::mutex> lock(s->mu);
    if (base == 0) {
        for (auto& r : s->regions) {
            r.heat.clear();
        }
        return HDL_OK;
    }
    for (auto& r : s->regions) {
        if (r.base == base) {
            r.heat.clear();
            return HDL_OK;
        }
    }
    return HDL_E_NOT_FOUND;
}

HdlStatus DiscoverGetCandidateEvidence(HdlDiscoverSession* session, uint64_t cand_id, char* buf,
                                       uint32_t cap) {
    if (!session || !buf || cap == 0) {
        return HDL_E_INVALID_ARG;
    }
    auto* s = reinterpret_cast<Session*>(session);
    std::lock_guard<std::mutex> lock(s->mu);
    const auto it = s->evidence.find(cand_id);
    if (it == s->evidence.end()) {
        buf[0] = 0;
        return HDL_E_NOT_FOUND;
    }
    strncpy_s(buf, cap, it->second.data(), _TRUNCATE);
    return HDL_OK;
}

} // namespace hdl
