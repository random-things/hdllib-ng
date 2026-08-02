#include "discover_internal.hpp"

namespace hdl {

HdlStatus DiscoverScanValue(HdlDiscoverSession* session, const HdlSearchDesc* desc,
                            const char* tag_or_null, const CancelToken& token) {
    if (!session || !desc) {
        return HDL_E_INVALID_ARG;
    }
    HdlSearchSession* search = nullptr;
    HdlStatus st = SearchCreate(&search);
    if (st != HDL_OK) {
        return st;
    }
    st = SearchFirst(search, desc, token);
    if (st != HDL_OK) {
        SearchClose(search);
        return st;
    }
    uint32_t count = 0;
    SearchGetCount(search, &count);
    std::vector<uint64_t> hits(count);
    uint32_t got = count;
    if (count) {
        SearchGetHits(search, hits.data(), &got);
    }
    SearchClose(search);

    auto* s = reinterpret_cast<Session*>(session);
    std::lock_guard<std::mutex> lock(s->mu);
    for (uint32_t i = 0; i < got; ++i) {
        s->cands.push_back(MakeCand(s, HDL_CAND_ADDRESS, hits[i], tag_or_null, 60));
    }
    return got ? HDL_OK : HDL_E_NOT_FOUND;
}

HdlStatus DiscoverScanValue(HdlDiscoverSession* session, const HdlSearchDesc* desc,
                            const char* tag_or_null, volatile int* cancel) {
    return DiscoverScanValue(session, desc, tag_or_null, MakeToken(cancel, nullptr));
}

HdlStatus DiscoverConstraintScan(HdlDiscoverSession* session, uint32_t object_size,
                                 const HdlFieldPred* preds, uint32_t pred_count,
                                 uint32_t search_flags, const wchar_t* module_or_null,
                                 uint32_t max_results, const char* tag_or_null,
                                 volatile int* cancel) {
    if (!session || !preds || pred_count == 0 || object_size < 8) {
        return HDL_E_INVALID_ARG;
    }
    if (object_size > 4096) {
        object_size = 4096;
    }
    if (max_results == 0) {
        max_results = 64;
    }

    ModRange mod{};
    HdlStatus st = ResolveModuleRange(search_flags, module_or_null, &mod);
    if (st != HDL_OK) {
        return st;
    }

    std::vector<uint64_t> hits;
    uint8_t* cursor = nullptr;
    MEMORY_BASIC_INFORMATION mbi{};
    while (VirtualQuery(cursor, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (cancel && *cancel) {
            return HDL_E_CANCELLED;
        }
        if (RegionOk(mbi, search_flags, mod)) {
            uint64_t base = reinterpret_cast<uint64_t>(mbi.BaseAddress);
            uint64_t end = base + mbi.RegionSize;
            if (search_flags & HDL_SEARCH_MODULE) {
                if (base < mod.base) {
                    base = mod.base;
                }
                if (end > mod.end) {
                    end = mod.end;
                }
            }
            for (uint64_t p = base & ~7ull; p + object_size <= end; p += 8) {
                if (cancel && *cancel) {
                    return HDL_E_CANCELLED;
                }
                bool ok = true;
                for (uint32_t i = 0; i < pred_count; ++i) {
                    const int32_t off = preds[i].offset;
                    if (off < 0 || static_cast<uint32_t>(off) + 8 > object_size) {
                        if (preds[i].kind == HDL_PRED_LE_I32) {
                            const int64_t other = off + preds[i].a;
                            if (off < 0 || other < 0 ||
                                static_cast<uint32_t>(off) + 4 > object_size ||
                                static_cast<uint32_t>(other) + 4 > object_size) {
                                ok = false;
                                break;
                            }
                        } else {
                            ok = false;
                            break;
                        }
                    }
                    if (!PredHolds(p, preds[i])) {
                        ok = false;
                        break;
                    }
                }
                if (ok) {
                    hits.push_back(p);
                    if (hits.size() >= max_results) {
                        break;
                    }
                }
            }
        }
        if (hits.size() >= max_results) {
            break;
        }
        const uintptr_t next = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        if (next <= reinterpret_cast<uintptr_t>(cursor)) {
            break;
        }
        cursor = reinterpret_cast<uint8_t*>(next);
    }

    auto* s = reinterpret_cast<Session*>(session);
    std::lock_guard<std::mutex> lock(s->mu);
    for (uint64_t h : hits) {
        s->cands.push_back(MakeCand(s, HDL_CAND_OBJECT, h, tag_or_null, 75));
    }
    return hits.empty() ? HDL_E_NOT_FOUND : HDL_OK;
}

} // namespace hdl
