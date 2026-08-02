#include "discover_internal.hpp"

#include "hooks.hpp"
#include "resolve.hpp"
#include "watch.hpp"

namespace hdl {

HdlStatus DiscoverWatch(HdlDiscoverSession* session, uint64_t fn_addr, uint32_t arg_count) {
    if (!session || !fn_addr) {
        return HDL_E_INVALID_ARG;
    }
    HdlHookHandle h = nullptr;
    const HdlStatus st = HookTrace(fn_addr, arg_count, &h);
    if (st != HDL_OK) {
        return st;
    }
    auto* s = reinterpret_cast<Session*>(session);
    std::lock_guard<std::mutex> lock(s->mu);
    s->watches.push_back(h);
    return HDL_OK;
}

HdlStatus DiscoverUnwatchAll(HdlDiscoverSession* session) {
    if (!session) {
        return HDL_E_INVALID_ARG;
    }
    auto* s = reinterpret_cast<Session*>(session);
    std::vector<HdlHookHandle> handles;
    {
        std::lock_guard<std::mutex> lock(s->mu);
        handles.swap(s->watches);
    }
    for (HdlHookHandle h : handles) {
        Unhook(h);
    }
    return HDL_OK;
}

HdlStatus DiscoverWatchRegion(HdlDiscoverSession* session, uint64_t base, uint32_t size) {
    if (!session || !base || size == 0) {
        return HDL_E_INVALID_ARG;
    }
    if (size > 4096) {
        size = 4096;
    }
    auto* s = reinterpret_cast<Session*>(session);
    std::lock_guard<std::mutex> lock(s->mu);
    for (auto& r : s->regions) {
        if (r.base == base) {
            r.size = size;
            r.before.clear();
            r.heat.clear();
            return HDL_OK;
        }
    }
    WatchedRegion wr;
    wr.base = base;
    wr.size = size;
    s->regions.push_back(std::move(wr));
    return HDL_OK;
}

HdlStatus DiscoverActionBegin(HdlDiscoverSession* session, const char* name) {
    if (!session || !name || !name[0]) {
        return HDL_E_INVALID_ARG;
    }
    auto* s = reinterpret_cast<Session*>(session);
    std::lock_guard<std::mutex> lock(s->mu);
    if (s->action_open) {
        return HDL_E_BUSY;
    }
    SetTag(s->action_name, sizeof(s->action_name), name);
    s->action_open = true;
    s->action_begin_ms = GetTickCount64();

    /* Drain stale hits so the window is clean. */
    HdlHookHit junk[64];
    for (;;) {
        uint32_t n = 64;
        if (PollHookHits(junk, &n, 0) != HDL_OK || n == 0) {
            break;
        }
    }

    for (auto& r : s->regions) {
        r.before.assign(r.size, 0);
        size_t got = 0;
        ReadMemory(r.base, r.before.data(), r.size, &got);
        r.before.resize(got);
    }
    return HDL_OK;
}

HdlStatus DiscoverActionEnd(HdlDiscoverSession* session) {
    if (!session) {
        return HDL_E_INVALID_ARG;
    }
    auto* s = reinterpret_cast<Session*>(session);
    ActionRecord rec{};
    {
        std::lock_guard<std::mutex> lock(s->mu);
        if (!s->action_open) {
            return HDL_E_NOT_FOUND;
        }
        SetTag(rec.name, sizeof(rec.name), s->action_name);
        rec.begin_ms = s->action_begin_ms;
        rec.end_ms = GetTickCount64();
        s->action_open = false;
        s->action_name[0] = 0;
    }

    /* Collect hook hits for this window. */
    for (;;) {
        HdlHookHit hits[64];
        uint32_t n = 64;
        if (PollHookHits(hits, &n, 0) != HDL_OK || n == 0) {
            break;
        }
        for (uint32_t i = 0; i < n; ++i) {
            RecordHookHit(rec, hits[i]);
        }
    }

    {
        std::lock_guard<std::mutex> lock(s->mu);
        for (auto& r : s->regions) {
            std::vector<uint8_t> after(r.size, 0);
            size_t got = 0;
            ReadMemory(r.base, after.data(), r.size, &got);
            after.resize(got);
            const uint32_t n = static_cast<uint32_t>((std::min)(r.before.size(), after.size()));
            if (n) {
                AccumulateRegionDiff(r, r.before.data(), after.data(), n);
            }
            r.before = std::move(after);
        }
        s->actions.push_back(std::move(rec));
    }
    return HDL_OK;
}

HdlStatus DiscoverGetHeat(HdlDiscoverSession* session, uint64_t base, HdlHeatField* out,
                          uint32_t* inout_count) {
    if (!session || !inout_count) {
        return HDL_E_INVALID_ARG;
    }
    auto* s = reinterpret_cast<Session*>(session);
    std::lock_guard<std::mutex> lock(s->mu);
    const WatchedRegion* wr = nullptr;
    for (const auto& r : s->regions) {
        if (r.base == base) {
            wr = &r;
            break;
        }
    }
    if (!wr) {
        return HDL_E_NOT_FOUND;
    }
    const uint32_t need = static_cast<uint32_t>(wr->heat.size());
    if (!out || *inout_count < need) {
        *inout_count = need;
        return need ? HDL_E_BUFFER_SMALL : HDL_E_NOT_FOUND;
    }
    if (need == 0) {
        *inout_count = 0;
        return HDL_E_NOT_FOUND;
    }
    memcpy(out, wr->heat.data(), need * sizeof(HdlHeatField));
    *inout_count = need;
    return HDL_OK;
}

HdlStatus DiscoverWatchImport(HdlDiscoverSession* session, const wchar_t* module_or_null,
                              const char* dll_name, const char* import_name, uint32_t arg_count) {
    if (!session || !dll_name || !import_name || !import_name[0]) {
        return HDL_E_INVALID_ARG;
    }
    HdlHookHandle h = nullptr;
    const HdlStatus st = HookImport(module_or_null, dll_name, import_name, arg_count, &h);
    if (st != HDL_OK) {
        return st;
    }
    auto* s = reinterpret_cast<Session*>(session);
    std::lock_guard<std::mutex> lock(s->mu);
    s->watches.push_back(h);
    return HDL_OK;
}

HdlStatus DiscoverRankFunctions(HdlDiscoverSession* session, const char* action_name,
                                uint32_t flags, HdlCandidate* out, uint32_t* inout_count) {
    if (!session || !action_name || !inout_count) {
        return HDL_E_INVALID_ARG;
    }
    auto* s = reinterpret_cast<Session*>(session);
    std::lock_guard<std::mutex> lock(s->mu);
    const ActionRecord* rec = nullptr;
    for (auto it = s->actions.rbegin(); it != s->actions.rend(); ++it) {
        if (_stricmp(it->name, action_name) == 0) {
            rec = &(*it);
            break;
        }
    }

    const bool caller_only = (flags & HDL_RANK_CALLER_ONLY) != 0;
    const std::unordered_map<uint64_t, uint32_t>* weights = nullptr;
    if (caller_only) {
        if (!rec || rec->caller_hits.empty()) {
            *inout_count = 0;
            return HDL_E_NOT_FOUND;
        }
        weights = &rec->caller_hits;
    } else if (rec && !rec->frame_weights.empty()) {
        weights = &rec->frame_weights;
    } else if (rec && !rec->caller_hits.empty()) {
        weights = &rec->caller_hits;
    } else {
        *inout_count = 0;
        return HDL_E_NOT_FOUND;
    }

    std::vector<std::pair<uint64_t, uint32_t>> ranked(weights->begin(), weights->end());
    std::sort(ranked.begin(), ranked.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });

    const uint32_t need = static_cast<uint32_t>(ranked.size());
    std::vector<HdlCandidate> built;
    built.reserve(need);
    for (const auto& kv : ranked) {
        char tag[48];
        snprintf(tag, sizeof(tag), "%s#%u", action_name, kv.second);
        HdlCandidate c =
            MakeCand(s, HDL_CAND_FUNCTION, kv.first, tag, (std::min)(100u, 40u + kv.second * 10u));
        char ev[160]{};
        if (caller_only) {
            snprintf(ev, sizeof(ev), "action=%s caller=0x%llx hits=%u", action_name,
                     static_cast<unsigned long long>(kv.first), kv.second);
        } else {
            snprintf(ev, sizeof(ev), "action=%s fn=0x%llx weight=%u", action_name,
                     static_cast<unsigned long long>(kv.first), kv.second);
        }
        s->evidence[c.id] = {};
        strncpy_s(s->evidence[c.id].data(), s->evidence[c.id].size(), ev, _TRUNCATE);
        s->cands.push_back(c);
        built.push_back(c);
    }

    if (!out || *inout_count < need) {
        *inout_count = need;
        return HDL_E_BUFFER_SMALL;
    }
    memcpy(out, built.data(), need * sizeof(HdlCandidate));
    *inout_count = need;
    return HDL_OK;
}

HdlStatus DiscoverDiffObjects(HdlDiscoverSession* session, const uint64_t* addrs, uint32_t count,
                              uint32_t max_size, HdlHeatField* out, uint32_t* inout_count) {
    if (!session || !addrs || !count || !inout_count) {
        return HDL_E_INVALID_ARG;
    }
    if (max_size == 0) {
        max_size = 4096;
    }
    if (max_size > 4096) {
        max_size = 4096;
    }

    auto* s = reinterpret_cast<Session*>(session);
    std::lock_guard<std::mutex> lock(s->mu);

    uint32_t total = 0;
    for (uint32_t i = 0; i < count; ++i) {
        if (!addrs[i]) {
            continue;
        }
        WatchedRegion* wr = nullptr;
        for (auto& r : s->regions) {
            if (r.base == addrs[i]) {
                wr = &r;
                break;
            }
        }
        if (!wr) {
            WatchedRegion fresh;
            fresh.base = addrs[i];
            fresh.size = max_size;
            s->regions.push_back(std::move(fresh));
            wr = &s->regions.back();
        }
        if (wr->size < max_size) {
            wr->size = max_size;
        }
        if (wr->before.size() != wr->size) {
            wr->before.assign(wr->size, 0);
            size_t got = 0;
            ReadMemory(wr->base, wr->before.data(), wr->size, &got);
            wr->before.resize(got);
        }
        std::vector<uint8_t> after(wr->size, 0);
        size_t got = 0;
        ReadMemory(wr->base, after.data(), wr->size, &got);
        after.resize(got);
        const uint32_t n = static_cast<uint32_t>((std::min)(wr->before.size(), after.size()));
        if (n) {
            AccumulateRegionDiff(*wr, wr->before.data(), after.data(), n);
        }
        wr->before = std::move(after);
        total += static_cast<uint32_t>(wr->heat.size());
    }

    if (!out || *inout_count < total) {
        *inout_count = total;
        return total ? HDL_E_BUFFER_SMALL : HDL_OK;
    }

    uint32_t w = 0;
    for (uint32_t i = 0; i < count; ++i) {
        if (!addrs[i]) {
            continue;
        }
        for (const auto& r : s->regions) {
            if (r.base != addrs[i]) {
                continue;
            }
            for (const auto& hf : r.heat) {
                out[w++] = hf;
            }
            break;
        }
    }
    *inout_count = w;
    return w ? HDL_OK : HDL_OK;
}

HdlStatus DiscoverApplyWatchHits(HdlDiscoverSession* session, uint64_t object_base, uint32_t size) {
    if (!session || !object_base || size == 0) {
        return HDL_E_INVALID_ARG;
    }
    if (size > 4096) {
        size = 4096;
    }

    auto* s = reinterpret_cast<Session*>(session);
    uint32_t added = 0;
    for (;;) {
        HdlWatchHit hits[64];
        uint32_t n = 64;
        if (PollWatchHits(hits, &n, 0) != HDL_OK || n == 0) {
            break;
        }
        std::lock_guard<std::mutex> lock(s->mu);
        for (uint32_t i = 0; i < n; ++i) {
            const uint64_t va = hits[i].accessed ? hits[i].accessed : hits[i].rip;
            if (va < object_base || va >= object_base + size) {
                continue;
            }
            const uint32_t off = static_cast<uint32_t>(va - object_base);
            HdlCandidate c = MakeCand(s, HDL_CAND_FIELD, object_base, "watch-hit", 70);
            c.field_offset = off;
            char tag[48];
            snprintf(tag, sizeof(tag), "watch+0x%x", off);
            SetTag(c.tag, sizeof(c.tag), tag);
            s->cands.push_back(c);
            ++added;
        }
    }
    return added ? HDL_OK : HDL_E_NOT_FOUND;
}

} // namespace hdl
