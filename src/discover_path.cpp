#include "discover_internal.hpp"

#include "locate.hpp"

namespace hdl {

HdlStatus DiscoverSynthesizePattern(HdlDiscoverSession* session, uint64_t cand_id,
                                    uint32_t window_before, uint32_t window_after,
                                    uint32_t search_flags, const wchar_t* module_or_null,
                                    HdlSynthesizedPattern* out, volatile int* cancel) {
    if (!session || !out || !cand_id) {
        return HDL_E_INVALID_ARG;
    }
    if (window_before > 64) {
        window_before = 64;
    }
    if (window_after > 64) {
        window_after = 64;
    }
    if (window_before + window_after < 8) {
        window_after = 16;
    }

    auto* s = reinterpret_cast<Session*>(session);
    uint64_t addr = 0;
    {
        std::lock_guard<std::mutex> lock(s->mu);
        for (const auto& c : s->cands) {
            if (c.id == cand_id) {
                addr = c.address;
                break;
            }
        }
    }
    if (!addr) {
        return HDL_E_NOT_FOUND;
    }

    memset(out, 0, sizeof(*out));
    const uint64_t start = addr > window_before ? addr - window_before : addr;
    const uint32_t total = static_cast<uint32_t>((addr - start) + window_after);
    std::vector<uint8_t> bytes(total);
    size_t got = 0;
    if (ReadMemory(start, bytes.data(), total, &got) != HDL_OK || got < 8) {
        return HDL_E_ACCESS;
    }
    bytes.resize(got);
    const int32_t pattern_offset = static_cast<int32_t>(addr - start);

    /* Progressive wildcarding: start exact, then mask RIP-looking disp32s and absolute ptrs. */
    std::vector<uint8_t> mask(bytes.size(), 1);
    auto try_emit = [&](HdlSynthesizedPattern* dest) -> bool {
        const std::string aob = BytesToAob(bytes.data(), mask.data(), bytes.size());
        if (aob.size() >= sizeof(dest->pattern)) {
            return false;
        }
        const uint32_t hits =
            CountPatternHits(aob.c_str(), search_flags, module_or_null, 8, cancel);
        if (hits == 0) {
            return false;
        }
        strncpy_s(dest->pattern, aob.c_str(), _TRUNCATE);
        dest->pattern_offset = pattern_offset;
        dest->match_addr = start;
        dest->resolved_addr = addr;
        dest->unique_hits = hits;
        return hits == 1;
    };

    if (try_emit(out)) {
        return HDL_OK;
    }

    /* Wildcard 4-byte values that look like pointers into any module image. */
    for (size_t i = 0; i + 8 <= bytes.size(); i += 1) {
        uint64_t v = 0;
        memcpy(&v, bytes.data() + i, 8);
        if (PtrLooksExecutable(v) || (PtrLooksReadable(v) && (v & 0xFFFFull) == 0)) {
            for (size_t j = 0; j < 8 && i + j < mask.size(); ++j) {
                mask[i + j] = 0;
            }
        }
    }
    for (size_t i = 0; i + 5 <= bytes.size(); ++i) {
        /* call/jmp rel32 */
        if (bytes[i] == 0xE8 || bytes[i] == 0xE9) {
            mask[i + 1] = mask[i + 2] = mask[i + 3] = mask[i + 4] = 0;
        }
        /* rex.w lea/mov with modrm RIP-relative: 48 8D/8B 0D/15/1D/25/2D/35/3D */
        if (i + 7 <= bytes.size() && bytes[i] == 0x48 &&
            (bytes[i + 1] == 0x8D || bytes[i + 1] == 0x8B) && ((bytes[i + 2] & 0xC7) == 0x05)) {
            mask[i + 3] = mask[i + 4] = mask[i + 5] = mask[i + 6] = 0;
        }
    }

    if (try_emit(out)) {
        return HDL_OK;
    }

    /* Accept near-unique (≤3) as soft success if we have a pattern. */
    if (out->pattern[0] && out->unique_hits > 0 && out->unique_hits <= 3) {
        return HDL_OK;
    }
    if (out->pattern[0] == 0) {
        const std::string aob = BytesToAob(bytes.data(), mask.data(), bytes.size());
        strncpy_s(out->pattern, aob.c_str(), _TRUNCATE);
        out->pattern_offset = pattern_offset;
        out->match_addr = start;
        out->resolved_addr = addr;
        out->unique_hits = CountPatternHits(out->pattern, search_flags, module_or_null, 16, cancel);
    }
    return out->unique_hits ? HDL_OK : HDL_E_NOT_FOUND;
}

HdlStatus DiscoverPathConsensus(uint64_t target_addr, uint32_t max_depth, uint32_t max_offset,
                                uint32_t max_results, uint32_t search_flags,
                                const wchar_t* module_or_null, HdlPointerPath* out,
                                uint32_t* inout_count, volatile int* cancel) {
    if (!inout_count) {
        return HDL_E_INVALID_ARG;
    }
    uint32_t count = *inout_count;
    if (!out || count == 0) {
        /* size probe via PointerScan */
        return PointerScan(target_addr, max_depth, max_offset, max_results, search_flags,
                           module_or_null, out, inout_count, cancel);
    }
    HdlStatus st =
        PointerScan(target_addr, max_depth, max_offset, max_results ? max_results : count,
                    search_flags, module_or_null, out, &count, cancel);
    if (st != HDL_OK) {
        *inout_count = count;
        return st;
    }
    st = DiscoverPathValidate(out, &count, target_addr);
    *inout_count = count;
    return st;
}

HdlStatus DiscoverPathValidate(HdlPointerPath* paths, uint32_t* inout_count,
                               uint64_t expected_target) {
    if (!paths || !inout_count || !expected_target) {
        return HDL_E_INVALID_ARG;
    }
    uint32_t n = *inout_count;
    uint32_t w = 0;
    for (uint32_t i = 0; i < n; ++i) {
        if (PathResolvesTo(paths[i], expected_target)) {
            if (w != i) {
                paths[w] = paths[i];
            }
            ++w;
        }
    }
    *inout_count = w;
    return w ? HDL_OK : HDL_E_NOT_FOUND;
}

} // namespace hdl
