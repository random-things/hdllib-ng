#include "discover.hpp"

#include "graph.hpp"
#include "hooks.hpp"
#include "locate.hpp"
#include "memory.hpp"
#include "resolve.hpp"
#include "watch.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
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

struct ModRange {
    uint64_t base = 0;
    uint64_t end = 0;
};

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
    return WcsContainsI(path, L"\\Windows\\System32\\") ||
           WcsContainsI(path, L"\\SysWOW64\\") || WcsContainsI(path, L"hdllib");
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

void JsonEscapeAppend(std::string* out, const char* s) {
    if (!out || !s) {
        return;
    }
    for (; *s; ++s) {
        const char c = *s;
        switch (c) {
        case '\\':
            out->append("\\\\");
            break;
        case '"':
            out->append("\\\"");
            break;
        case '\n':
            out->append("\\n");
            break;
        case '\r':
            out->append("\\r");
            break;
        case '\t':
            out->append("\\t");
            break;
        default:
            if (static_cast<unsigned char>(c) < 0x20) {
                char buf[8];
                snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned>(c));
                out->append(buf);
            } else {
                out->push_back(c);
            }
            break;
        }
    }
}

bool JsonExtractString(const std::string& json, const char* key, std::string* out) {
    if (!out) {
        return false;
    }
    const std::string pat = std::string("\"") + key + "\"";
    size_t p = json.find(pat);
    if (p == std::string::npos) {
        return false;
    }
    p = json.find(':', p);
    if (p == std::string::npos) {
        return false;
    }
    ++p;
    while (p < json.size() && (json[p] == ' ' || json[p] == '\t' || json[p] == '\n' ||
                               json[p] == '\r')) {
        ++p;
    }
    if (p >= json.size() || json[p] != '"') {
        return false;
    }
    ++p;
    out->clear();
    while (p < json.size()) {
        if (json[p] == '\\' && p + 1 < json.size()) {
            out->push_back(json[p + 1]);
            p += 2;
            continue;
        }
        if (json[p] == '"') {
            return true;
        }
        out->push_back(json[p++]);
    }
    return false;
}

bool JsonExtractU64(const std::string& json, const char* key, uint64_t* out) {
    if (!out) {
        return false;
    }
    std::string s;
    if (JsonExtractString(json, key, &s)) {
        *out = _strtoui64(s.c_str(), nullptr, 0);
        return true;
    }
    const std::string pat = std::string("\"") + key + "\"";
    size_t p = json.find(pat);
    if (p == std::string::npos) {
        return false;
    }
    p = json.find(':', p);
    if (p == std::string::npos) {
        return false;
    }
    ++p;
    while (p < json.size() && (json[p] == ' ' || json[p] == '\t')) {
        ++p;
    }
    *out = _strtoui64(json.c_str() + p, nullptr, 0);
    return true;
}

bool JsonExtractU32(const std::string& json, const char* key, uint32_t* out) {
    uint64_t v = 0;
    if (!JsonExtractU64(json, key, &v)) {
        return false;
    }
    *out = static_cast<uint32_t>(v);
    return true;
}

std::vector<std::string> JsonSplitObjects(const std::string& arr) {
    std::vector<std::string> objs;
    int depth = 0;
    size_t start = std::string::npos;
    for (size_t i = 0; i < arr.size(); ++i) {
        const char c = arr[i];
        if (c == '{') {
            if (depth++ == 0) {
                start = i;
            }
        } else if (c == '}') {
            if (--depth == 0 && start != std::string::npos) {
                objs.push_back(arr.substr(start, i - start + 1));
                start = std::string::npos;
            }
        }
    }
    return objs;
}

struct WatchedRegion {
    uint64_t base = 0;
    uint32_t size = 0;
    std::vector<uint8_t> before;
    std::vector<HdlHeatField> heat;
};

struct ActionRecord {
    char name[48]{};
    uint64_t begin_ms = 0;
    uint64_t end_ms = 0;
    std::unordered_map<uint64_t, uint32_t> caller_hits; /* caller VA -> count */
    std::unordered_map<uint64_t, uint32_t> frame_weights; /* function start -> weight */
};

struct Session {
    std::mutex mu;
    uint64_t next_id = 1;
    std::vector<HdlCandidate> cands;
    std::vector<HdlHookHandle> watches;
    std::vector<WatchedRegion> regions;
    bool action_open = false;
    char action_name[48]{};
    uint64_t action_begin_ms = 0;
    std::vector<ActionRecord> actions;
    std::unordered_map<uint64_t, std::array<char, 160>> evidence;
};

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

    /* Prefer direct caller (user code); RtlCaptureStackBackTrace often lists hdllib first. */
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
            fresh.reserved = run; /* slot size in bytes */
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

}  // namespace

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
            (bytes[i + 1] == 0x8D || bytes[i + 1] == 0x8B) &&
            ((bytes[i + 2] & 0xC7) == 0x05)) {
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
        out->unique_hits =
            CountPatternHits(out->pattern, search_flags, module_or_null, 16, cancel);
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
    HdlStatus st = PointerScan(target_addr, max_depth, max_offset, max_results ? max_results : count,
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
                              const char* dll_name, const char* import_name,
                              uint32_t arg_count) {
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
    /* Accept seed if vt is executable or points at executable. */
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

HdlStatus DiscoverApplyWatchHits(HdlDiscoverSession* session, uint64_t object_base,
                                 uint32_t size) {
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

HdlStatus DiscoverExport(HdlDiscoverSession* session, char* buf, uint32_t* inout_size) {
    if (!session || !inout_size) {
        return HDL_E_INVALID_ARG;
    }
    constexpr uint32_t kMaxExport = 4u * 1024u * 1024u;

    auto* s = reinterpret_cast<Session*>(session);
    std::string json;
    json.reserve(4096);
    json += "{\"version\":1,\"actions\":[";
    {
        std::lock_guard<std::mutex> lock(s->mu);
        for (size_t i = 0; i < s->actions.size(); ++i) {
            if (i) {
                json += ',';
            }
            json += '"';
            JsonEscapeAppend(&json, s->actions[i].name);
            json += '"';
        }
        json += "],\"candidates\":[";
        for (size_t i = 0; i < s->cands.size(); ++i) {
            const auto& c = s->cands[i];
            if (i) {
                json += ',';
            }
            json += "{\"id\":";
            json += std::to_string(c.id);
            json += ",\"kind\":";
            json += std::to_string(c.kind);
            json += ",\"address\":";
            json += std::to_string(c.address);
            json += ",\"confidence\":";
            json += std::to_string(c.confidence);
            json += ",\"field_offset\":";
            json += std::to_string(c.field_offset);
            json += ",\"tag\":\"";
            JsonEscapeAppend(&json, c.tag);
            json += "\",\"evidence\":\"";
            const auto ev = s->evidence.find(c.id);
            if (ev != s->evidence.end()) {
                JsonEscapeAppend(&json, ev->second.data());
            }
            json += "\"}";
        }
        json += "],\"heat\":[";
        for (size_t ri = 0; ri < s->regions.size(); ++ri) {
            const auto& r = s->regions[ri];
            if (ri) {
                json += ',';
            }
            json += "{\"base\":";
            json += std::to_string(r.base);
            json += ",\"fields\":[";
            for (size_t fi = 0; fi < r.heat.size(); ++fi) {
                const auto& hf = r.heat[fi];
                if (fi) {
                    json += ',';
                }
                json += "{\"offset\":";
                json += std::to_string(hf.offset);
                json += ",\"changes\":";
                json += std::to_string(hf.changes);
                json += ",\"kind\":";
                json += std::to_string(hf.kind);
                json += ",\"size\":";
                json += std::to_string(hf.reserved);
                json += ",\"last_value\":";
                json += std::to_string(hf.last_value);
                json += "}";
            }
            json += "]}";
        }
        json += "]}";
    }

    const uint32_t need = static_cast<uint32_t>(json.size() + 1);
    if (need > kMaxExport) {
        return HDL_E_FAILED;
    }
    if (!buf || *inout_size < need) {
        *inout_size = need;
        return HDL_E_BUFFER_SMALL;
    }
    memcpy(buf, json.c_str(), need);
    *inout_size = need - 1;
    return HDL_OK;
}

HdlStatus DiscoverImport(HdlDiscoverSession* session, const char* json, uint32_t size) {
    if (!session || !json || size == 0) {
        return HDL_E_INVALID_ARG;
    }
    const std::string text(json, json + size);
    size_t cp = text.find("\"candidates\"");
    if (cp == std::string::npos) {
        return HDL_E_INVALID_ARG;
    }
    const size_t lb = text.find('[', cp);
    const size_t rb = text.find(']', lb);
    if (lb == std::string::npos || rb == std::string::npos || rb <= lb) {
        return HDL_E_INVALID_ARG;
    }

    auto* s = reinterpret_cast<Session*>(session);
    const auto objs = JsonSplitObjects(text.substr(lb, rb - lb + 1));
    uint32_t added = 0;
    std::lock_guard<std::mutex> lock(s->mu);
    for (const auto& obj : objs) {
        uint64_t address = 0;
        uint32_t kind = HDL_CAND_ADDRESS;
        uint32_t confidence = 50;
        uint32_t field_offset = 0;
        std::string tag;
        std::string evidence;
        if (!JsonExtractU64(obj, "address", &address) || !address) {
            continue;
        }
        JsonExtractU32(obj, "kind", &kind);
        JsonExtractU32(obj, "confidence", &confidence);
        JsonExtractU32(obj, "field_offset", &field_offset);
        JsonExtractString(obj, "tag", &tag);
        JsonExtractString(obj, "evidence", &evidence);
        if (kind != HDL_CAND_ADDRESS && kind != HDL_CAND_FUNCTION && kind != HDL_CAND_OBJECT &&
            kind != HDL_CAND_FIELD) {
            kind = HDL_CAND_ADDRESS;
        }
        HdlCandidate c = MakeCand(s, kind, address, tag.empty() ? nullptr : tag.c_str(), confidence);
        if (kind == HDL_CAND_FIELD) {
            c.field_offset = field_offset;
        }
        if (!evidence.empty()) {
            s->evidence[c.id] = {};
            strncpy_s(s->evidence[c.id].data(), s->evidence[c.id].size(), evidence.c_str(),
                      _TRUNCATE);
        }
        s->cands.push_back(c);
        ++added;
    }
    return added ? HDL_OK : HDL_E_NOT_FOUND;
}

}  // namespace hdl
