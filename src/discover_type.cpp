#include "discover_internal.hpp"

#include "graph.hpp"
#include "locate.hpp"
#include "resolve.hpp"

#include <Psapi.h>

namespace hdl {
namespace {

bool IsReadableProtect(DWORD protect) {
    protect &= 0xFF;
    switch (protect) {
    case PAGE_READONLY:
    case PAGE_READWRITE:
    case PAGE_WRITECOPY:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return true;
    default:
        return false;
    }
}

bool IsExecutableProtect(DWORD protect) {
    protect &= 0xFF;
    switch (protect) {
    case PAGE_EXECUTE:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return true;
    default:
        return false;
    }
}

} // namespace

bool PtrLooksReadable(uint64_t p) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(reinterpret_cast<LPCVOID>(p), &mbi, sizeof(mbi)) != sizeof(mbi)) {
        return false;
    }
    return mbi.State == MEM_COMMIT && IsReadableProtect(mbi.Protect) &&
           !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS));
}

bool PtrLooksExecutable(uint64_t p) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(reinterpret_cast<LPCVOID>(p), &mbi, sizeof(mbi)) != sizeof(mbi)) {
        return false;
    }
    return mbi.State == MEM_COMMIT && IsExecutableProtect(mbi.Protect);
}

HdlStatus ResolveModuleRange(uint32_t flags, const wchar_t* module_or_null, ModRange* out) {
    if (!out) {
        return HDL_E_INVALID_ARG;
    }
    *out = ModRange{};
    if (!(flags & HDL_SEARCH_MODULE)) {
        return HDL_OK;
    }
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
    out->base = reinterpret_cast<uint64_t>(mi.lpBaseOfDll);
    out->end = out->base + mi.SizeOfImage;
    return HDL_OK;
}

bool RegionOk(const MEMORY_BASIC_INFORMATION& mbi, uint32_t flags, const ModRange& mod) {
    if (mbi.State != MEM_COMMIT) {
        return false;
    }
    if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) {
        return false;
    }
    if (!IsReadableProtect(mbi.Protect)) {
        return false;
    }
    if (flags & HDL_SEARCH_IMAGE) {
        if (mbi.Type != MEM_IMAGE) {
            return false;
        }
    }
    if (flags & HDL_SEARCH_EXECUTABLE) {
        if (!IsExecutableProtect(mbi.Protect)) {
            return false;
        }
    }
    if (flags & HDL_SEARCH_MODULE) {
        const uint64_t b = reinterpret_cast<uint64_t>(mbi.BaseAddress);
        const uint64_t e = b + mbi.RegionSize;
        if (e <= mod.base || b >= mod.end) {
            return false;
        }
    }
    return true;
}

void FillModuleInfo(uint64_t addr, uint64_t* out_base, uint64_t* out_rva) {
    *out_base = 0;
    *out_rva = 0;
    HMODULE mods[1024];
    DWORD needed = 0;
    if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed)) {
        return;
    }
    const uint32_t count = needed / sizeof(HMODULE);
    for (uint32_t i = 0; i < count; ++i) {
        MODULEINFO mi{};
        if (!GetModuleInformation(GetCurrentProcess(), mods[i], &mi, sizeof(mi))) {
            continue;
        }
        const uint64_t b = reinterpret_cast<uint64_t>(mi.lpBaseOfDll);
        if (addr >= b && addr < b + mi.SizeOfImage) {
            *out_base = b;
            *out_rva = addr - b;
            return;
        }
    }
}

void SetTag(char* dst, size_t n, const char* tag) {
    if (!dst || n == 0) {
        return;
    }
    dst[0] = 0;
    if (!tag) {
        return;
    }
    strncpy_s(dst, n, tag, _TRUNCATE);
}

bool ReadI32(uint64_t addr, int32_t* out) {
    size_t got = 0;
    return ReadMemory(addr, out, sizeof(*out), &got) == HDL_OK && got == sizeof(*out);
}

bool ReadU64(uint64_t addr, uint64_t* out) {
    size_t got = 0;
    return ReadMemory(addr, out, sizeof(*out), &got) == HDL_OK && got == sizeof(*out);
}

bool PredHolds(uint64_t base, const HdlFieldPred& p) {
    const uint64_t addr = base + static_cast<uint64_t>(static_cast<int64_t>(p.offset));
    switch (p.kind) {
    case HDL_PRED_EQ_I32: {
        int32_t v = 0;
        if (!ReadI32(addr, &v)) {
            return false;
        }
        return v == static_cast<int32_t>(p.a);
    }
    case HDL_PRED_EQ_F32: {
        uint32_t v = 0;
        size_t got = 0;
        if (ReadMemory(addr, &v, 4, &got) != HDL_OK || got != 4) {
            return false;
        }
        return v == static_cast<uint32_t>(p.a);
    }
    case HDL_PRED_RANGE_I32: {
        int32_t v = 0;
        if (!ReadI32(addr, &v)) {
            return false;
        }
        return v >= static_cast<int32_t>(p.a) && v <= static_cast<int32_t>(p.b);
    }
    case HDL_PRED_LE_I32: {
        int32_t left = 0;
        int32_t right = 0;
        const uint64_t other = base + static_cast<uint64_t>(static_cast<int64_t>(p.offset) + p.a);
        if (!ReadI32(addr, &left) || !ReadI32(other, &right)) {
            return false;
        }
        return left <= right;
    }
    case HDL_PRED_PTR: {
        uint64_t v = 0;
        if (!ReadU64(addr, &v) || !v) {
            return false;
        }
        return PtrLooksReadable(v);
    }
    case HDL_PRED_VTABLE: {
        uint64_t v = 0;
        if (!ReadU64(addr, &v) || !v) {
            return false;
        }
        if (PtrLooksExecutable(v)) {
            return true;
        }
        if (PtrLooksReadable(v)) {
            uint64_t first = 0;
            if (ReadU64(v, &first) && PtrLooksExecutable(first)) {
                return true;
            }
        }
        return false;
    }
    case HDL_PRED_EQ_U64: {
        uint64_t v = 0;
        if (!ReadU64(addr, &v)) {
            return false;
        }
        return v == static_cast<uint64_t>(p.a);
    }
    default:
        return false;
    }
}

std::string BytesToAob(const uint8_t* bytes, const uint8_t* mask, size_t n) {
    std::string s;
    s.reserve(n * 3);
    for (size_t i = 0; i < n; ++i) {
        if (i) {
            s.push_back(' ');
        }
        if (!mask[i]) {
            s += "??";
        } else {
            char buf[8];
            snprintf(buf, sizeof(buf), "%02X", bytes[i]);
            s += buf;
        }
    }
    return s;
}

uint32_t CountPatternHits(const char* pattern, uint32_t flags, const wchar_t* module_or_null,
                          uint32_t max_hits, volatile int* cancel) {
    HdlSearchSession* session = nullptr;
    if (SearchCreate(&session) != HDL_OK) {
        return 0;
    }
    HdlSearchDesc desc{};
    desc.value_type = HDL_VALUE_BYTES;
    desc.cmp = HDL_CMP_EXACT;
    desc.alignment = 1;
    desc.max_results = max_hits ? max_hits : 64;
    desc.value = pattern;
    desc.flags = flags;
    desc.module_or_null = module_or_null;
    const HdlStatus st = SearchFirst(session, &desc, cancel);
    uint32_t count = 0;
    if (st == HDL_OK) {
        SearchGetCount(session, &count);
    }
    SearchClose(session);
    return count;
}

bool PathResolvesTo(const HdlPointerPath& path, uint64_t expected) {
    if (path.depth == 0 || path.depth > 8) {
        return false;
    }
    uint64_t cur = path.static_base;
    for (uint32_t i = 0; i < path.depth; ++i) {
        uint64_t ptr = 0;
        if (!ReadU64(cur, &ptr) || !ptr) {
            return false;
        }
        cur = ptr + static_cast<uint64_t>(static_cast<int64_t>(path.offsets[i]));
    }
    return cur == expected;
}

bool WcsContainsI(const wchar_t* hay, const wchar_t* needle) {
    if (!hay || !needle || !needle[0]) {
        return false;
    }
    const size_t nlen = wcslen(needle);
    for (const wchar_t* p = hay; *p; ++p) {
        if (_wcsnicmp(p, needle, nlen) == 0) {
            return true;
        }
    }
    return false;
}

bool ShouldSkipFrame(uint64_t addr) {
    if (!addr) {
        return true;
    }
    HMODULE mod = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            reinterpret_cast<LPCWSTR>(addr), &mod) ||
        !mod) {
        return false;
    }
    wchar_t path[MAX_PATH]{};
    if (!GetModuleFileNameW(mod, path, MAX_PATH)) {
        return false;
    }
    return WcsContainsI(path, L"\\Windows\\System32\\") || WcsContainsI(path, L"\\SysWOW64\\") ||
           WcsContainsI(path, L"hdllib");
}

uint32_t PickDiffRunSize(const uint8_t* before, const uint8_t* after, uint32_t off, uint32_t n) {
    static const uint32_t kSizes[] = {8, 4, 2, 1};
    for (uint32_t sz : kSizes) {
        if (off % sz != 0 || off + sz > n) {
            continue;
        }
        bool all_diff = true;
        for (uint32_t i = 0; i < sz; ++i) {
            if (before[off + i] == after[off + i]) {
                all_diff = false;
                break;
            }
        }
        if (all_diff) {
            return sz;
        }
    }
    return 1;
}

/* ---------- Globals ---------- */

std::mutex g_sessions_mu;
std::unordered_set<Session*> g_sessions;

HdlCandidate MakeCand(Session* s, uint32_t kind, uint64_t address, const char* tag,
                      uint32_t confidence) {
    HdlCandidate c{};
    c.id = s->next_id++;
    c.kind = kind;
    c.confidence = confidence;
    c.address = address;
    FillModuleInfo(address, &c.module_base, &c.rva);
    SetTag(c.tag, sizeof(c.tag), tag);
    return c;
}

void RecordHookHit(ActionRecord& rec, const HdlHookHit& hit) {
    if (hit.timestamp_ms < rec.begin_ms) {
        return;
    }
    if (hit.caller) {
        rec.caller_hits[hit.caller] += 1;
    }

    auto add_frame = [&](uint64_t frame, uint32_t depth) {
        if (ShouldSkipFrame(frame)) {
            return;
        }
        HdlFunctionInfo fi{};
        if (ResolveFunction(frame, 0, nullptr, &fi, nullptr) != HDL_OK || !fi.start) {
            return;
        }
        const uint32_t weight = (std::max)(1u, 8u - depth);
        rec.frame_weights[fi.start] += weight;
    };

    if (hit.caller) {
        add_frame(hit.caller, 0);
    }
    for (uint32_t depth = 0; depth < hit.frame_count; ++depth) {
        add_frame(hit.frames[depth], depth + 1);
    }
}

HdlHeatField* FindHeatAtOffset(WatchedRegion& r, uint32_t offset) {
    for (auto& hf : r.heat) {
        if (hf.offset == offset) {
            return &hf;
        }
    }
    return nullptr;
}

void AccumulateRegionDiff(WatchedRegion& r, const uint8_t* before, const uint8_t* after,
                          uint32_t n) {
    uint32_t off = 0;
    while (off < n) {
        if (before[off] == after[off]) {
            ++off;
            continue;
        }
        const uint32_t run = PickDiffRunSize(before, after, off, n);
        HdlHeatField* hf = FindHeatAtOffset(r, off);
        if (!hf) {
            HdlHeatField fresh{};
            fresh.offset = off;
            fresh.changes = 1;
            fresh.reserved = run;
            memset(&fresh.last_value, 0, sizeof(fresh.last_value));
            memcpy(&fresh.last_value, after + off, run);
            HdlStructField fields[1]{};
            uint32_t fc = 1;
            if (ProbeStruct(r.base + off, run, fields, &fc) == HDL_OK && fc >= 1) {
                fresh.kind = fields[0].kind;
            }
            r.heat.push_back(fresh);
        } else {
            hf->changes += 1;
            if (run > hf->reserved) {
                hf->reserved = run;
            }
            memset(&hf->last_value, 0, sizeof(hf->last_value));
            memcpy(&hf->last_value, after + off, run);
            HdlStructField fields[1]{};
            uint32_t fc = 1;
            if (ProbeStruct(r.base + off, run, fields, &fc) == HDL_OK && fc >= 1) {
                hf->kind = fields[0].kind;
            }
        }
        off += run;
    }
}

HdlStatus DiscoverClusterType(HdlDiscoverSession* session, uint64_t seed_addr, uint32_t object_size,
                              uint32_t search_flags, const wchar_t* module_or_null,
                              uint32_t max_results, volatile int* cancel) {
    if (!session || !seed_addr || object_size < 8) {
        return HDL_E_INVALID_ARG;
    }
    if (object_size > 4096) {
        object_size = 4096;
    }
    if (max_results == 0) {
        max_results = 64;
    }

    uint64_t vt = 0;
    if (!ReadU64(seed_addr, &vt) || !vt) {
        return HDL_E_FAILED;
    }
    bool vt_ok = PtrLooksExecutable(vt);
    if (!vt_ok && PtrLooksReadable(vt)) {
        uint64_t first = 0;
        vt_ok = ReadU64(vt, &first) && PtrLooksExecutable(first);
    }
    if (!vt_ok) {
        return HDL_E_NOT_FOUND;
    }

    HdlFieldPred preds[1]{};
    preds[0].offset = 0;
    preds[0].kind = HDL_PRED_EQ_U64;
    preds[0].a = static_cast<int64_t>(vt);

    return DiscoverConstraintScan(session, object_size, preds, 1, search_flags, module_or_null,
                                  max_results, "cluster", cancel);
}

} // namespace hdl
