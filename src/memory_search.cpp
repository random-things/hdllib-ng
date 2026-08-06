#include "memory_internal.hpp"

#include <Psapi.h>
#include <new>

#pragma comment(lib, "Psapi.lib")

namespace hdl {
namespace {

bool PushHitImpl(SearchSession& s, uint64_t address, const uint8_t* data, size_t n) {
    if (CapReached(s)) {
        return false;
    }
    if (s.retain_hits) {
        s.addresses.push_back(address);
        s.snapshots.insert(s.snapshots.end(), data, data + n);
    }
    ++s.emitted_hits;
    if (s.on_hit) {
        const HdlStatus st = s.on_hit(address, s.on_hit_user);
        if (st != HDL_OK) {
            s.abort_status = st;
            return false;
        }
    }
    return true;
}

bool PushHitFromMemoryImpl(SearchSession& s, uint64_t address, const uint8_t* data, size_t n) {
    std::vector<uint8_t> tmp(n);
    if (!SehReadBytes(data, tmp.data(), n)) {
        return true;
    }
    return PushHitImpl(s, address, tmp.data(), n);
}

} // namespace

bool PushHit(SearchSession& s, uint64_t address, const uint8_t* data, size_t n) {
    return PushHitImpl(s, address, data, n);
}

bool PushHitFromMemory(SearchSession& s, uint64_t address, const uint8_t* data, size_t n) {
    return PushHitFromMemoryImpl(s, address, data, n);
}

size_t ValueWidth(int value_type) {
    switch (value_type) {
    case HDL_VALUE_I8:
    case HDL_VALUE_U8:
        return 1;
    case HDL_VALUE_I16:
    case HDL_VALUE_U16:
        return 2;
    case HDL_VALUE_I32:
    case HDL_VALUE_U32:
    case HDL_VALUE_F32:
        return 4;
    case HDL_VALUE_I64:
    case HDL_VALUE_U64:
    case HDL_VALUE_F64:
        return 8;
    default:
        return 0;
    }
}

uint32_t NaturalAlignment(int value_type) {
    switch (value_type) {
    case HDL_VALUE_I16:
    case HDL_VALUE_U16:
        return 2;
    case HDL_VALUE_I32:
    case HDL_VALUE_U32:
    case HDL_VALUE_F32:
        return 4;
    case HDL_VALUE_I64:
    case HDL_VALUE_U64:
    case HDL_VALUE_F64:
        return 8;
    case HDL_VALUE_WSTRING:
        return 2;
    default:
        return 1;
    }
}

bool IsNumericType(int value_type) {
    switch (value_type) {
    case HDL_VALUE_I8:
    case HDL_VALUE_U8:
    case HDL_VALUE_I16:
    case HDL_VALUE_U16:
    case HDL_VALUE_I32:
    case HDL_VALUE_U32:
    case HDL_VALUE_I64:
    case HDL_VALUE_U64:
    case HDL_VALUE_F32:
    case HDL_VALUE_F64:
        return true;
    default:
        return false;
    }
}

int CompareNumeric(int value_type, const uint8_t* a, const uint8_t* b) {
    switch (value_type) {
    case HDL_VALUE_I8: {
        const int8_t va = *reinterpret_cast<const int8_t*>(a);
        const int8_t vb = *reinterpret_cast<const int8_t*>(b);
        return (va > vb) - (va < vb);
    }
    case HDL_VALUE_U8: {
        const uint8_t va = a[0];
        const uint8_t vb = b[0];
        return (va > vb) - (va < vb);
    }
    case HDL_VALUE_I16: {
        int16_t va = 0;
        int16_t vb = 0;
        memcpy(&va, a, 2);
        memcpy(&vb, b, 2);
        return (va > vb) - (va < vb);
    }
    case HDL_VALUE_U16: {
        uint16_t va = 0;
        uint16_t vb = 0;
        memcpy(&va, a, 2);
        memcpy(&vb, b, 2);
        return (va > vb) - (va < vb);
    }
    case HDL_VALUE_I32: {
        int32_t va = 0;
        int32_t vb = 0;
        memcpy(&va, a, 4);
        memcpy(&vb, b, 4);
        return (va > vb) - (va < vb);
    }
    case HDL_VALUE_U32: {
        uint32_t va = 0;
        uint32_t vb = 0;
        memcpy(&va, a, 4);
        memcpy(&vb, b, 4);
        return (va > vb) - (va < vb);
    }
    case HDL_VALUE_I64: {
        int64_t va = 0;
        int64_t vb = 0;
        memcpy(&va, a, 8);
        memcpy(&vb, b, 8);
        return (va > vb) - (va < vb);
    }
    case HDL_VALUE_U64: {
        uint64_t va = 0;
        uint64_t vb = 0;
        memcpy(&va, a, 8);
        memcpy(&vb, b, 8);
        return (va > vb) - (va < vb);
    }
    case HDL_VALUE_F32: {
        float va = 0;
        float vb = 0;
        memcpy(&va, a, 4);
        memcpy(&vb, b, 4);
        if (va < vb)
            return -1;
        if (va > vb)
            return 1;
        return 0;
    }
    case HDL_VALUE_F64: {
        double va = 0;
        double vb = 0;
        memcpy(&va, a, 8);
        memcpy(&vb, b, 8);
        if (va < vb)
            return -1;
        if (va > vb)
            return 1;
        return 0;
    }
    default:
        return memcmp(a, b, ValueWidth(value_type));
    }
}

bool AddNumeric(int value_type, const uint8_t* base, const uint8_t* delta, uint8_t* out,
                bool subtract) {
    switch (value_type) {
    case HDL_VALUE_I8: {
        const int8_t a = *reinterpret_cast<const int8_t*>(base);
        const int8_t d = *reinterpret_cast<const int8_t*>(delta);
        const int8_t r = static_cast<int8_t>(subtract ? a - d : a + d);
        memcpy(out, &r, 1);
        return true;
    }
    case HDL_VALUE_U8: {
        const uint8_t r = static_cast<uint8_t>(subtract ? base[0] - delta[0] : base[0] + delta[0]);
        out[0] = r;
        return true;
    }
    case HDL_VALUE_I16: {
        int16_t a = 0;
        int16_t d = 0;
        memcpy(&a, base, 2);
        memcpy(&d, delta, 2);
        const int16_t r = static_cast<int16_t>(subtract ? a - d : a + d);
        memcpy(out, &r, 2);
        return true;
    }
    case HDL_VALUE_U16: {
        uint16_t a = 0;
        uint16_t d = 0;
        memcpy(&a, base, 2);
        memcpy(&d, delta, 2);
        const uint16_t r = static_cast<uint16_t>(subtract ? a - d : a + d);
        memcpy(out, &r, 2);
        return true;
    }
    case HDL_VALUE_I32: {
        int32_t a = 0;
        int32_t d = 0;
        memcpy(&a, base, 4);
        memcpy(&d, delta, 4);
        const int32_t r = subtract ? a - d : a + d;
        memcpy(out, &r, 4);
        return true;
    }
    case HDL_VALUE_U32: {
        uint32_t a = 0;
        uint32_t d = 0;
        memcpy(&a, base, 4);
        memcpy(&d, delta, 4);
        const uint32_t r = subtract ? a - d : a + d;
        memcpy(out, &r, 4);
        return true;
    }
    case HDL_VALUE_I64: {
        int64_t a = 0;
        int64_t d = 0;
        memcpy(&a, base, 8);
        memcpy(&d, delta, 8);
        const int64_t r = subtract ? a - d : a + d;
        memcpy(out, &r, 8);
        return true;
    }
    case HDL_VALUE_U64: {
        uint64_t a = 0;
        uint64_t d = 0;
        memcpy(&a, base, 8);
        memcpy(&d, delta, 8);
        const uint64_t r = subtract ? a - d : a + d;
        memcpy(out, &r, 8);
        return true;
    }
    case HDL_VALUE_F32: {
        float a = 0;
        float d = 0;
        memcpy(&a, base, 4);
        memcpy(&d, delta, 4);
        const float r = subtract ? a - d : a + d;
        memcpy(out, &r, 4);
        return true;
    }
    case HDL_VALUE_F64: {
        double a = 0;
        double d = 0;
        memcpy(&a, base, 8);
        memcpy(&d, delta, 8);
        const double r = subtract ? a - d : a + d;
        memcpy(out, &r, 8);
        return true;
    }
    default:
        return false;
    }
}

bool MatchCmp(int value_type, int cmp, const uint8_t* current, const uint8_t* previous,
              const uint8_t* value, size_t value_size) {
    switch (cmp) {
    case HDL_CMP_EXACT:
        return value && value_size && memcmp(current, value, value_size) == 0;
    case HDL_CMP_CHANGED:
        return previous && memcmp(current, previous, value_size) != 0;
    case HDL_CMP_UNCHANGED:
        return previous && memcmp(current, previous, value_size) == 0;
    case HDL_CMP_INCREASED:
        return previous && IsNumericType(value_type) &&
               CompareNumeric(value_type, current, previous) > 0;
    case HDL_CMP_DECREASED:
        return previous && IsNumericType(value_type) &&
               CompareNumeric(value_type, current, previous) < 0;
    case HDL_CMP_GREATER:
        return value && IsNumericType(value_type) && CompareNumeric(value_type, current, value) > 0;
    case HDL_CMP_LESS:
        return value && IsNumericType(value_type) && CompareNumeric(value_type, current, value) < 0;
    case HDL_CMP_INCREASED_BY:
    case HDL_CMP_DECREASED_BY: {
        if (!previous || !value || !IsNumericType(value_type)) {
            return false;
        }
        uint8_t expected[8]{};
        if (!AddNumeric(value_type, previous, value, expected, cmp == HDL_CMP_DECREASED_BY)) {
            return false;
        }
        return memcmp(current, expected, value_size) == 0;
    }
    default:
        return false;
    }
}

HdlStatus BuildScanFilter(uint32_t flags, const wchar_t* module_or_null, ScanFilter* out) {
    if (!out) {
        return HDL_E_INVALID_ARG;
    }
    *out = ScanFilter{};
    out->flags = flags;
    if (flags & HDL_SEARCH_MODULE) {
        if (!module_or_null || !module_or_null[0]) {
            return HDL_E_INVALID_ARG;
        }
        HMODULE mod = GetModuleHandleW(module_or_null);
        if (!mod) {
            HMODULE mods[1024];
            DWORD needed = 0;
            if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed)) {
                return HDL_E_NOT_FOUND;
            }
            const uint32_t count = needed / sizeof(HMODULE);
            for (uint32_t i = 0; i < count; ++i) {
                wchar_t path[MAX_PATH];
                if (!GetModuleFileNameW(mods[i], path, MAX_PATH)) {
                    continue;
                }
                const wchar_t* base = wcsrchr(path, L'\\');
                base = base ? base + 1 : path;
                if (_wcsicmp(base, module_or_null) == 0 || _wcsicmp(path, module_or_null) == 0) {
                    mod = mods[i];
                    break;
                }
            }
        }
        if (!mod) {
            return HDL_E_NOT_FOUND;
        }
        MODULEINFO mi{};
        if (!GetModuleInformation(GetCurrentProcess(), mod, &mi, sizeof(mi))) {
            return HDL_E_FAILED;
        }
        out->mod_base = reinterpret_cast<uint64_t>(mi.lpBaseOfDll);
        out->mod_end = out->mod_base + mi.SizeOfImage;
    }
    return HDL_OK;
}

bool RegionMatchesFilter(const MEMORY_BASIC_INFORMATION& mbi, const ScanFilter& f) {
    if (!RegionCommittedReadable(mbi)) {
        return false;
    }
    if (f.flags & HDL_SEARCH_IMAGE) {
        if (mbi.Type != MEM_IMAGE) {
            return false;
        }
    }
    if (f.flags & HDL_SEARCH_EXECUTABLE) {
        if (!IsExecutableProtect(mbi.Protect)) {
            return false;
        }
    }
    if (f.flags & HDL_SEARCH_MODULE) {
        const uint64_t b = reinterpret_cast<uint64_t>(mbi.BaseAddress);
        const uint64_t e = b + mbi.RegionSize;
        if (e <= f.mod_base || b >= f.mod_end) {
            return false;
        }
    }
    return true;
}

HdlStatus ScanPatternRange(SearchSession& s, uint64_t range_start, uint64_t range_size,
                           const CancelToken& token, bool unknown_fill) {
    if (range_size < s.elem_size) {
        return HDL_OK;
    }
    MEMORY_BASIC_INFORMATION mbi{};
    uint64_t addr = range_start;
    const uint64_t end = range_start + range_size;
    const uint32_t align = s.alignment ? s.alignment : 1;

    while (addr < end) {
        const HdlStatus cst = TokenCheck(token);
        if (cst != HDL_OK) {
            return cst;
        }
        if (VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == 0) {
            break;
        }
        const uint64_t region_base = reinterpret_cast<uint64_t>(mbi.BaseAddress);
        const uint64_t region_end = region_base + mbi.RegionSize;
        uint64_t scan_from = addr > region_base ? addr : region_base;
        const uint64_t scan_to = region_end < end ? region_end : end;

        if (RegionCommittedReadable(mbi) && scan_to > scan_from &&
            (scan_to - scan_from) >= s.elem_size) {
            if (align > 1) {
                const uint64_t rem = scan_from % align;
                if (rem) {
                    scan_from += align - rem;
                }
            }
            if (scan_from >= scan_to || (scan_to - scan_from) < s.elem_size) {
                addr = region_end;
                continue;
            }

            const uint8_t* data = reinterpret_cast<const uint8_t*>(scan_from);
            const size_t span = static_cast<size_t>(scan_to - scan_from);
            const size_t last = span - s.elem_size;

            if (unknown_fill) {
                for (size_t i = 0; i <= last; i += align) {
                    const HdlStatus check = TokenCheck(token);
                    if (check != HDL_OK) {
                        return check;
                    }
                    uint8_t tmp[16]{};
                    if (s.elem_size > sizeof(tmp)) {
                        return HDL_E_INVALID_ARG;
                    }
                    if (!SehReadBytes(data + i, tmp, s.elem_size)) {
                        continue;
                    }
                    if (!PushHit(s, scan_from + i, tmp, s.elem_size)) {
                        return AfterPushFail(s);
                    }
                }
            } else if (!s.mask.empty()) {
                size_t pivot = static_cast<size_t>(-1);
                for (size_t i = 0; i < s.needle.size(); ++i) {
                    if (s.mask[i]) {
                        pivot = i;
                        break;
                    }
                }
                size_t i = 0;
                while (i <= last) {
                    const HdlStatus check = TokenCheck(token);
                    if (check != HDL_OK) {
                        return check;
                    }
                    if (align > 1 && (i % align) != 0) {
                        ++i;
                        continue;
                    }
                    if (pivot != static_cast<size_t>(-1)) {
                        const void* hit = memchr(data + i + pivot, s.needle[pivot], last - i + 1);
                        if (!hit) {
                            break;
                        }
                        i = static_cast<const uint8_t*>(hit) - data - pivot;
                        if (i > last) {
                            break;
                        }
                        if (align > 1 && (i % align) != 0) {
                            ++i;
                            continue;
                        }
                    }
                    if (SehMatchAt(data + i, s.needle.data(), s.mask.data(), s.needle.size())) {
                        if (!PushHitFromMemory(s, scan_from + i, data + i, s.elem_size)) {
                            return AfterPushFail(s);
                        }
                    }
                    ++i;
                }
            } else {
                size_t i = 0;
                while (i <= last) {
                    const HdlStatus check = TokenCheck(token);
                    if (check != HDL_OK) {
                        return check;
                    }
                    if (align > 1 && (i % align) != 0) {
                        ++i;
                        continue;
                    }
                    const void* hit = memchr(data + i, s.needle[0], last - i + 1);
                    if (!hit) {
                        break;
                    }
                    i = static_cast<const uint8_t*>(hit) - data;
                    if (i > last) {
                        break;
                    }
                    if (align > 1 && (i % align) != 0) {
                        ++i;
                        continue;
                    }
                    if (SehBytesEqual(data + i, s.needle.data(), s.elem_size)) {
                        if (!PushHitFromMemory(s, scan_from + i, data + i, s.elem_size)) {
                            return AfterPushFail(s);
                        }
                    }
                    ++i;
                }
            }
        }

        if (region_end <= addr) {
            break;
        }
        addr = region_end;
    }
    return HDL_OK;
}

HdlStatus ScanAllReadable(SearchSession& s, uint64_t start, uint64_t size, const CancelToken& token,
                          bool unknown_fill, const ScanFilter& filter) {
    HdlStatus st = HDL_OK;
    if (start == 0 && size == 0) {
        uint8_t* addr = nullptr;
        MEMORY_BASIC_INFORMATION mbi{};
        while (VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            const HdlStatus cst = TokenCheck(token);
            if (cst != HDL_OK) {
                return cst;
            }
            if (RegionMatchesFilter(mbi, filter)) {
                uint64_t scan_base = reinterpret_cast<uint64_t>(mbi.BaseAddress);
                uint64_t scan_size = mbi.RegionSize;
                if (filter.flags & HDL_SEARCH_MODULE) {
                    if (scan_base < filter.mod_base) {
                        scan_size -= (filter.mod_base - scan_base);
                        scan_base = filter.mod_base;
                    }
                    if (scan_base + scan_size > filter.mod_end) {
                        scan_size = filter.mod_end - scan_base;
                    }
                }
                if (scan_size > 0) {
                    st = ScanPatternRange(s, scan_base, scan_size, token, unknown_fill);
                    if (st != HDL_OK || CapReached(s) || s.abort_status != HDL_OK) {
                        return st != HDL_OK ? st : AfterPushFail(s);
                    }
                }
            }
            const uintptr_t next = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            if (next <= reinterpret_cast<uintptr_t>(addr)) {
                break;
            }
            addr = reinterpret_cast<uint8_t*>(next);
        }
        return st;
    }
    uint8_t* addr = reinterpret_cast<uint8_t*>(start);
    const uint8_t* end_ptr = addr + size;
    MEMORY_BASIC_INFORMATION mbi{};
    while (addr < end_ptr && VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        const HdlStatus cst = TokenCheck(token);
        if (cst != HDL_OK) {
            return cst;
        }
        uint64_t region_base = reinterpret_cast<uint64_t>(mbi.BaseAddress);
        uint64_t region_end = region_base + mbi.RegionSize;
        uint64_t from = start > region_base ? start : region_base;
        uint64_t to = (start + size) < region_end ? (start + size) : region_end;
        if (to > from && RegionMatchesFilter(mbi, filter)) {
            st = ScanPatternRange(s, from, to - from, token, unknown_fill);
            if (st != HDL_OK || CapReached(s) || s.abort_status != HDL_OK) {
                return st != HDL_OK ? st : AfterPushFail(s);
            }
        }
        if (region_end <= reinterpret_cast<uint64_t>(addr)) {
            break;
        }
        addr = reinterpret_cast<uint8_t*>(region_end);
    }
    return st;
}

HdlStatus PrepareNeedle(SearchSession& s, int value_type, int cmp, const void* value,
                        size_t value_size) {
    s.needle.clear();
    s.mask.clear();
    s.value_type = value_type;
    s.last_cmp = cmp;

    if (value_type == HDL_VALUE_BYTES) {
        if (!value) {
            return HDL_E_INVALID_ARG;
        }
        const char* pattern = static_cast<const char*>(value);
        if (!ParseAobPattern(pattern, s.needle, s.mask)) {
            return HDL_E_INVALID_ARG;
        }
        s.elem_size = s.needle.size();
        return HDL_OK;
    }

    if (value_type == HDL_VALUE_STRING) {
        if (cmp == HDL_CMP_UNKNOWN) {
            return HDL_E_INVALID_ARG;
        }
        if (!value || value_size == 0) {
            return HDL_E_INVALID_ARG;
        }
        s.needle.assign(static_cast<const uint8_t*>(value),
                        static_cast<const uint8_t*>(value) + value_size);
        s.elem_size = value_size;
        return HDL_OK;
    }

    if (value_type == HDL_VALUE_WSTRING) {
        if (cmp == HDL_CMP_UNKNOWN) {
            return HDL_E_INVALID_ARG;
        }
        if (!value || value_size == 0 || (value_size % 2) != 0) {
            return HDL_E_INVALID_ARG;
        }
        s.needle.assign(static_cast<const uint8_t*>(value),
                        static_cast<const uint8_t*>(value) + value_size);
        s.elem_size = value_size;
        return HDL_OK;
    }

    const size_t width = ValueWidth(value_type);
    if (width == 0) {
        return HDL_E_INVALID_ARG;
    }
    s.elem_size = width;

    if (cmp == HDL_CMP_UNKNOWN) {
        return HDL_OK;
    }

    const bool needs_value = cmp == HDL_CMP_EXACT || cmp == HDL_CMP_GREATER ||
                             cmp == HDL_CMP_LESS || cmp == HDL_CMP_INCREASED_BY ||
                             cmp == HDL_CMP_DECREASED_BY;
    if (needs_value) {
        if (!value || value_size != width) {
            return HDL_E_INVALID_ARG;
        }
        s.needle.assign(static_cast<const uint8_t*>(value),
                        static_cast<const uint8_t*>(value) + width);
    }
    return HDL_OK;
}

HdlStatus SearchCreate(HdlSearchSession** out_session) {
    if (!out_session) {
        return HDL_E_INVALID_ARG;
    }
    SearchSession* s = nullptr;
    try {
        s = new SearchSession();
    } catch (const std::bad_alloc&) {
        return HDL_E_NO_MEM;
    }
    *out_session = reinterpret_cast<HdlSearchSession*>(s);
    return HDL_OK;
}

void SearchClose(HdlSearchSession* session) {
    delete AsSearch(session);
}

void SearchReset(HdlSearchSession* session) {
    auto* s = AsSearch(session);
    if (!s) {
        return;
    }
    s->active = false;
    s->addresses.clear();
    s->snapshots.clear();
    s->needle.clear();
    s->mask.clear();
    s->elem_size = 0;
    s->emitted_hits = 0;
    s->abort_status = HDL_OK;
}

void SearchSetHitHandler(HdlSearchSession* session, SearchHitFn fn, void* user) {
    auto* s = AsSearch(session);
    if (!s) {
        return;
    }
    s->on_hit = fn;
    s->on_hit_user = user;
}

void SearchSetRetainHits(HdlSearchSession* session, bool retain) {
    auto* s = AsSearch(session);
    if (!s) {
        return;
    }
    s->retain_hits = retain;
}

HdlStatus SearchFirst(HdlSearchSession* session, const HdlSearchDesc* desc, volatile int* cancel) {
    return SearchFirst(session, desc, MakeToken(cancel, nullptr));
}

HdlStatus SearchFirst(HdlSearchSession* session, const HdlSearchDesc* desc,
                      const CancelToken& token) {
    SearchSession* s = AsSearch(session);
    if (!s || !desc) {
        return HDL_E_INVALID_ARG;
    }

    SearchReset(session);

    if (desc->cmp != HDL_CMP_EXACT && desc->cmp != HDL_CMP_UNKNOWN &&
        desc->cmp != HDL_CMP_GREATER && desc->cmp != HDL_CMP_LESS) {
        return HDL_E_INVALID_ARG;
    }
    if (desc->cmp == HDL_CMP_UNKNOWN && !IsNumericType(desc->value_type)) {
        return HDL_E_INVALID_ARG;
    }

    const HdlStatus prep =
        PrepareNeedle(*s, desc->value_type, desc->cmp, desc->value, desc->value_size);
    if (prep != HDL_OK) {
        return prep;
    }

    s->max_results = desc->max_results;
    s->alignment = desc->alignment ? desc->alignment : NaturalAlignment(desc->value_type);
    if (s->alignment == 0) {
        s->alignment = 1;
    }

    ScanFilter filter{};
    const HdlStatus fst = BuildScanFilter(desc->flags, desc->module_or_null, &filter);
    if (fst != HDL_OK) {
        return fst;
    }

    const bool unknown_fill = (desc->cmp == HDL_CMP_UNKNOWN) || (desc->cmp == HDL_CMP_GREATER) ||
                              (desc->cmp == HDL_CMP_LESS);

    if (unknown_fill && IsNumericType(desc->value_type)) {
        SearchSession probe;
        probe.value_type = desc->value_type;
        probe.elem_size = s->elem_size;
        probe.alignment = s->alignment;
        probe.max_results = s->max_results;
        probe.retain_hits = true;
        probe.on_hit = (desc->cmp == HDL_CMP_UNKNOWN) ? s->on_hit : nullptr;
        probe.on_hit_user = s->on_hit_user;
        probe.active = true;

        HdlStatus st = ScanAllReadable(probe, desc->start, desc->size, token, true, filter);
        if (st != HDL_OK) {
            return st;
        }

        if (desc->cmp == HDL_CMP_UNKNOWN) {
            if (s->retain_hits) {
                s->addresses.swap(probe.addresses);
                s->snapshots.swap(probe.snapshots);
            }
            s->emitted_hits = probe.emitted_hits;
            s->active = true;
            return HDL_OK;
        }

        for (size_t i = 0; i < probe.addresses.size(); ++i) {
            const uint8_t* cur = probe.snapshots.data() + i * s->elem_size;
            if (MatchCmp(s->value_type, desc->cmp, cur, nullptr, s->needle.data(), s->elem_size)) {
                if (!PushHit(*s, probe.addresses[i], cur, s->elem_size)) {
                    s->active = true;
                    return AfterPushFail(*s);
                }
            }
        }
        s->active = true;
        return HDL_OK;
    }

    if (desc->cmp != HDL_CMP_EXACT) {
        return HDL_E_INVALID_ARG;
    }

    const HdlStatus st = ScanAllReadable(*s, desc->start, desc->size, token, false, filter);
    if (st != HDL_OK) {
        SearchReset(session);
        return st;
    }
    s->active = true;
    return HDL_OK;
}

HdlStatus SearchNext(HdlSearchSession* session, int cmp, const void* value, size_t value_size,
                     volatile int* cancel) {
    return SearchNext(session, cmp, value, value_size, MakeToken(cancel, nullptr));
}

HdlStatus SearchNext(HdlSearchSession* session, int cmp, const void* value, size_t value_size,
                     const CancelToken& token) {
    SearchSession* s = AsSearch(session);
    if (!s || !s->active) {
        return HDL_E_INVALID_ARG;
    }
    if (cmp == HDL_CMP_UNKNOWN) {
        return HDL_E_INVALID_ARG;
    }

    const bool needs_value = cmp == HDL_CMP_EXACT || cmp == HDL_CMP_GREATER ||
                             cmp == HDL_CMP_LESS || cmp == HDL_CMP_INCREASED_BY ||
                             cmp == HDL_CMP_DECREASED_BY;
    std::vector<uint8_t> needle;
    if (s->value_type == HDL_VALUE_BYTES) {
        if (cmp != HDL_CMP_EXACT && cmp != HDL_CMP_CHANGED && cmp != HDL_CMP_UNCHANGED) {
            return HDL_E_INVALID_ARG;
        }
        if (cmp == HDL_CMP_EXACT) {
            if (!value) {
                return HDL_E_INVALID_ARG;
            }
            std::vector<uint8_t> mask;
            if (!ParseAobPattern(static_cast<const char*>(value), needle, mask)) {
                return HDL_E_INVALID_ARG;
            }
            if (needle.size() != s->elem_size) {
                return HDL_E_INVALID_ARG;
            }
            s->mask = std::move(mask);
        }
    } else if (s->value_type == HDL_VALUE_STRING || s->value_type == HDL_VALUE_WSTRING) {
        if (cmp != HDL_CMP_EXACT && cmp != HDL_CMP_CHANGED && cmp != HDL_CMP_UNCHANGED) {
            return HDL_E_INVALID_ARG;
        }
        if (cmp == HDL_CMP_EXACT) {
            if (!value || value_size != s->elem_size) {
                return HDL_E_INVALID_ARG;
            }
            needle.assign(static_cast<const uint8_t*>(value),
                          static_cast<const uint8_t*>(value) + value_size);
        }
    } else {
        if (needs_value) {
            if (!value || value_size != s->elem_size) {
                return HDL_E_INVALID_ARG;
            }
            needle.assign(static_cast<const uint8_t*>(value),
                          static_cast<const uint8_t*>(value) + value_size);
        }
        if ((cmp == HDL_CMP_INCREASED || cmp == HDL_CMP_DECREASED || cmp == HDL_CMP_INCREASED_BY ||
             cmp == HDL_CMP_DECREASED_BY || cmp == HDL_CMP_GREATER || cmp == HDL_CMP_LESS) &&
            !IsNumericType(s->value_type)) {
            return HDL_E_INVALID_ARG;
        }
    }

    s->last_cmp = cmp;
    if (!needle.empty()) {
        s->needle = needle;
    }

    std::vector<uint64_t> next_addrs;
    std::vector<uint8_t> next_snaps;
    next_addrs.reserve(s->addresses.size());
    next_snaps.reserve(s->snapshots.size());

    std::vector<uint8_t> current(s->elem_size);
    for (size_t i = 0; i < s->addresses.size(); ++i) {
        const HdlStatus cst = TokenCheck(token);
        if (cst != HDL_OK) {
            s->addresses.swap(next_addrs);
            s->snapshots.swap(next_snaps);
            return cst;
        }
        const uint64_t address = s->addresses[i];
        const uint8_t* prev = s->snapshots.data() + i * s->elem_size;
        if (!SehReadBytes(reinterpret_cast<const void*>(address), current.data(), s->elem_size)) {
            continue;
        }

        bool match = false;
        if (s->value_type == HDL_VALUE_BYTES && cmp == HDL_CMP_EXACT && !s->mask.empty()) {
            match = true;
            for (size_t b = 0; b < s->elem_size; ++b) {
                if (s->mask[b] && current[b] != s->needle[b]) {
                    match = false;
                    break;
                }
            }
        } else {
            const uint8_t* val = needs_value ? s->needle.data() : nullptr;
            match = MatchCmp(s->value_type, cmp, current.data(), prev, val, s->elem_size);
        }

        if (match) {
            next_addrs.push_back(address);
            next_snaps.insert(next_snaps.end(), current.begin(), current.end());
        }
    }

    s->addresses.swap(next_addrs);
    s->snapshots.swap(next_snaps);
    return HDL_OK;
}

HdlStatus SearchGetCount(const HdlSearchSession* session, uint32_t* out_count) {
    const SearchSession* s = AsSearch(session);
    if (!s || !out_count) {
        return HDL_E_INVALID_ARG;
    }
    *out_count = static_cast<uint32_t>(HitCount(*s));
    return HDL_OK;
}

HdlStatus SearchGetHits(const HdlSearchSession* session, uint64_t* out_hits,
                        uint32_t* inout_count) {
    const SearchSession* s = AsSearch(session);
    if (!s || !inout_count) {
        return HDL_E_INVALID_ARG;
    }
    const uint32_t needed = static_cast<uint32_t>(s->addresses.size());
    if (!out_hits || *inout_count < needed) {
        *inout_count = needed;
        return HDL_E_BUFFER_SMALL;
    }
    if (needed) {
        memcpy(out_hits, s->addresses.data(), needed * sizeof(uint64_t));
    }
    *inout_count = needed;
    return HDL_OK;
}

} // namespace hdl
