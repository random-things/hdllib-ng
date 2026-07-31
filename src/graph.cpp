#include "graph.hpp"
#include "disasm/backend.hpp"
#include "memory.hpp"
#include "pe_meta.hpp"
#include "resolve.hpp"

#include <algorithm>
#include <cstring>
#include <mutex>
#include <queue>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <Psapi.h>

namespace hdl {
namespace {

bool IsExec(DWORD p) {
    const DWORD x = p & 0xFF;
    return x == PAGE_EXECUTE || x == PAGE_EXECUTE_READ || x == PAGE_EXECUTE_READWRITE ||
           x == PAGE_EXECUTE_WRITECOPY;
}

bool IsLikelyFunctionPrologue(const uint8_t* raw, size_t size) {
    if (!raw || size < 4) {
        return false;
    }
    /* Keep this deliberately narrow. Broad prefixes such as 48 89 and 48 83
       occur throughout ordinary function bodies and fragment the index. */
    return raw[0] == 0x55 ||                                      /* push rbp */
           (raw[0] == 0x40 && raw[1] == 0x55) ||                  /* push rbp */
           (raw[0] == 0x48 && raw[1] == 0x89 && raw[2] == 0xE5) || /* mov rbp,rsp */
           (raw[0] == 0x48 && raw[1] == 0x8B && raw[2] == 0xEC) || /* mov rbp,rsp */
           (raw[0] == 0x48 && raw[1] == 0x83 && raw[2] == 0xEC) || /* sub rsp,imm8 */
           (raw[0] == 0x48 && raw[1] == 0x81 && raw[2] == 0xEC) || /* sub rsp,imm32 */
           (raw[0] == 0x48 && raw[1] == 0x8B && raw[2] == 0xC4) || /* mov rax,rsp */
           (raw[0] == 0x4C && raw[1] == 0x8B && raw[2] == 0xDC);   /* mov r11,rsp */
}

bool LookupRuntimeFunction(uint64_t addr, uint64_t module_start, uint64_t module_end,
                           HdlFunctionInfo* out) {
#if defined(_M_X64) || defined(__x86_64__)
    if (!addr || !out) {
        return false;
    }
    DWORD64 image_base = 0;
    const PRUNTIME_FUNCTION runtime =
        RtlLookupFunctionEntry(static_cast<DWORD64>(addr), &image_base, nullptr);
    if (!runtime || !image_base) {
        return false;
    }
    const uint64_t start = static_cast<uint64_t>(image_base) + runtime->BeginAddress;
    const uint64_t end = static_cast<uint64_t>(image_base) + runtime->EndAddress;
    if (start < module_start || end > module_end || start >= end || addr < start || addr >= end) {
        return false;
    }
    out->start = start;
    out->end = end;
    out->confidence = 100;
    out->flags = 0;
    return true;
#else
    (void)addr;
    (void)module_start;
    (void)module_end;
    (void)out;
    return false;
#endif
}

struct FnCacheKey {
    uint64_t base = 0;
    uint64_t size = 0;
    bool operator==(const FnCacheKey& o) const { return base == o.base && size == o.size; }
};

struct FnCacheKeyHash {
    size_t operator()(const FnCacheKey& k) const {
        return static_cast<size_t>(k.base ^ (k.size << 1));
    }
};

struct FnCacheEntry {
    std::vector<HdlFunctionInfo> fns;
};

std::mutex g_fn_cache_mu;
std::unordered_map<FnCacheKey, FnCacheEntry, FnCacheKeyHash> g_fn_cache;

bool ModuleRange(const wchar_t* module_or_null, uint64_t* out_start, uint64_t* out_end) {
    uint64_t base = 0;
    if (ModuleBase(module_or_null, &base) != HDL_OK) {
        return false;
    }
    MODULEINFO mi{};
    if (!GetModuleInformation(GetCurrentProcess(), reinterpret_cast<HMODULE>(base), &mi,
                              sizeof(mi))) {
        return false;
    }
    *out_start = base;
    *out_end = base + mi.SizeOfImage;
    return true;
}

uint64_t DecodeFnEnd(uint64_t start, uint64_t limit, volatile int* cancel) {
    uint64_t cur = start;
    uint64_t budget = 65536;
    uint32_t int3_run = 0;
    while (cur < limit && budget) {
        if (cancel && *cancel) {
            break;
        }
        disasm::DecodedInsn d{};
        if (disasm::DecodeAt(cur, &d) != HDL_OK || d.length == 0) {
            break;
        }
        uint8_t b = 0;
        size_t got = 0;
        if (ReadMemory(cur, &b, 1, &got) == HDL_OK && got == 1 && b == 0xCC) {
            ++int3_run;
            if (int3_run >= 2 && cur > start) {
                return cur;
            }
            cur += 1;
            budget -= 1;
            continue;
        }
        int3_run = 0;
        if (d.flags & HDL_INSN_RET) {
            return cur + d.length;
        }
        /* Unconditional jmp leaving the near region often ends a leaf. */
        if ((d.flags & HDL_INSN_JMP) && (d.flags & HDL_INSN_BRANCH) && d.branch_target &&
            (d.branch_target < start || d.branch_target >= limit)) {
            return cur + d.length;
        }
        cur += d.length;
        budget -= d.length;
    }
    return cur > start ? cur : 0;
}

HdlStatus BuildFunctionList(uint64_t scan_start, uint64_t scan_end, uint32_t /*search_flags*/,
                            uint32_t max_results, std::vector<HdlFunctionInfo>* out,
                            volatile int* cancel) {
    if (!out) {
        return HDL_E_INVALID_ARG;
    }
    out->clear();

    struct StartMeta {
        uint32_t flags = 0;
        uint32_t conf = 0;
    };
    std::unordered_map<uint64_t, StartMeta> starts;

    auto bump = [&](uint64_t va, uint32_t flags, uint32_t conf) {
        if (va < scan_start || va >= scan_end) {
            return;
        }
        auto& m = starts[va];
        m.flags |= flags;
        if (conf > m.conf) {
            m.conf = conf;
        }
    };

    uint32_t exp_n = 0;
    EnumExports(scan_start, nullptr, &exp_n);
    if (exp_n) {
        std::vector<HdlExportInfo> exps(exp_n);
        if (EnumExports(scan_start, exps.data(), &exp_n) == HDL_OK) {
            for (uint32_t i = 0; i < exp_n; ++i) {
                if (!exps[i].forwarder) {
                    bump(exps[i].va, HDL_FN_EXPORT, 90);
                }
            }
        }
    }

    uint8_t* addr = reinterpret_cast<uint8_t*>(scan_start);
    MEMORY_BASIC_INFORMATION mbi{};
    while (reinterpret_cast<uint64_t>(addr) < scan_end &&
           VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (cancel && *cancel) {
            return HDL_E_CANCELLED;
        }
        const uint64_t b = reinterpret_cast<uint64_t>(mbi.BaseAddress);
        const uint64_t e = b + mbi.RegionSize;
        if (mbi.State == MEM_COMMIT && IsExec(mbi.Protect)) {
            const uint64_t from = (std::max)(b, scan_start);
            const uint64_t to = (std::min)(e, scan_end);
            for (uint64_t cur = from; cur + 16 < to && starts.size() < max_results * 2;) {
                if (cancel && *cancel) {
                    return HDL_E_CANCELLED;
                }
                disasm::DecodedInsn d{};
                if (disasm::DecodeAt(cur, &d) != HDL_OK || d.length == 0) {
                    ++cur;
                    continue;
                }
                uint8_t raw[8]{};
                size_t got = 0;
                if (ReadMemory(cur, raw, sizeof(raw), &got) == HDL_OK) {
                    if (IsLikelyFunctionPrologue(raw, got)) {
                        bump(cur, HDL_FN_PROLOGUE, 45);
                    }
                }
                /* A conditional or local jump names a basic block, not a function. Calls are
                   instruction-aligned entry evidence; jump edges remain available via Xrefs*. */
                if ((d.flags & HDL_INSN_CALL) && (d.flags & HDL_INSN_BRANCH) &&
                    d.branch_target >= scan_start && d.branch_target < scan_end) {
                    bump(d.branch_target, HDL_FN_CALLED, 75);
                }
                cur += d.length;
            }
        }
        const uintptr_t next = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        if (next <= reinterpret_cast<uintptr_t>(addr)) {
            break;
        }
        addr = reinterpret_cast<uint8_t*>(next);
    }

    std::vector<uint64_t> sorted;
    sorted.reserve(starts.size());
    for (const auto& kv : starts) {
        sorted.push_back(kv.first);
    }
    std::sort(sorted.begin(), sorted.end());
    if (sorted.size() > max_results) {
        sorted.resize(max_results);
    }

    out->reserve(sorted.size());
    for (size_t i = 0; i < sorted.size(); ++i) {
        HdlFunctionInfo f{};
        f.start = sorted[i];
        const uint64_t next_start = (i + 1 < sorted.size()) ? sorted[i + 1] : scan_end;
        const uint64_t decoded_end = DecodeFnEnd(f.start, next_start, cancel);
        if (decoded_end && decoded_end <= next_start) {
            f.end = decoded_end;
        } else if (i + 1 < sorted.size()) {
            f.end = next_start;
        } else {
            f.end = decoded_end ? decoded_end : 0;
        }
        const StartMeta& m = starts[f.start];
        f.flags = m.flags;
        f.confidence = m.conf ? m.conf : 60;
        out->push_back(f);
    }
    return HDL_OK;
}

HdlStatus GetOrBuildModuleFns(uint64_t scan_start, uint64_t scan_end, uint32_t search_flags,
                              volatile int* cancel, const std::vector<HdlFunctionInfo>** out_ptr,
                              std::vector<HdlFunctionInfo>* scratch) {
    FnCacheKey key{scan_start, scan_end - scan_start};
    {
        std::lock_guard<std::mutex> lock(g_fn_cache_mu);
        auto it = g_fn_cache.find(key);
        if (it != g_fn_cache.end()) {
            *out_ptr = &it->second.fns;
            return HDL_OK;
        }
    }
    std::vector<HdlFunctionInfo> built;
    const HdlStatus st =
        BuildFunctionList(scan_start, scan_end, search_flags, 10000, &built, cancel);
    if (st != HDL_OK) {
        return st;
    }
    std::lock_guard<std::mutex> lock(g_fn_cache_mu);
    auto& entry = g_fn_cache[key];
    if (entry.fns.empty()) {
        entry.fns = std::move(built);
    }
    *out_ptr = &entry.fns;
    (void)scratch;
    return HDL_OK;
}

}  // namespace

HdlStatus InvalidateFunctionIndex(const wchar_t* module_or_null) {
    std::lock_guard<std::mutex> lock(g_fn_cache_mu);
    if (!module_or_null || !module_or_null[0]) {
        g_fn_cache.clear();
        return HDL_OK;
    }
    uint64_t start = 0, end = 0;
    if (!ModuleRange(module_or_null, &start, &end)) {
        return HDL_E_NOT_FOUND;
    }
    g_fn_cache.erase(FnCacheKey{start, end - start});
    return HDL_OK;
}

HdlStatus EnumFunctions(uint64_t start, uint64_t size, uint32_t search_flags,
                        const wchar_t* module_or_null, uint32_t max_results, HdlFunctionInfo* out,
                        uint32_t* inout_count, volatile int* cancel) {
    if (!inout_count) {
        return HDL_E_INVALID_ARG;
    }
    if (max_results == 0 || max_results > 100000) {
        max_results = 10000;
    }

    uint64_t scan_start = start;
    uint64_t scan_end = start && size ? start + size : 0;
    if (!scan_start || !size) {
        if (!ModuleRange(module_or_null, &scan_start, &scan_end)) {
            return HDL_E_NOT_FOUND;
        }
    }

    const bool use_cache = (!start || !size) && !(search_flags & ~HDL_SEARCH_MODULE);
    if (use_cache) {
        const std::vector<HdlFunctionInfo>* cached = nullptr;
        std::vector<HdlFunctionInfo> scratch;
        const HdlStatus cst =
            GetOrBuildModuleFns(scan_start, scan_end, search_flags, cancel, &cached, &scratch);
        if (cst != HDL_OK) {
            return cst;
        }
        uint32_t need = static_cast<uint32_t>(
            (std::min)(cached->size(), static_cast<size_t>(max_results)));
        if (!out || *inout_count < need) {
            *inout_count = need;
            return need ? HDL_E_BUFFER_SMALL : HDL_OK;
        }
        if (need) {
            memcpy(out, cached->data(), need * sizeof(HdlFunctionInfo));
        }
        *inout_count = need;
        return HDL_OK;
    }

    std::vector<HdlFunctionInfo> list;
    const HdlStatus st =
        BuildFunctionList(scan_start, scan_end, search_flags, max_results, &list, cancel);
    if (st != HDL_OK) {
        return st;
    }
    const uint32_t need = static_cast<uint32_t>(list.size());
    if (!out || *inout_count < need) {
        *inout_count = need;
        return need ? HDL_E_BUFFER_SMALL : HDL_OK;
    }
    if (need) {
        memcpy(out, list.data(), need * sizeof(HdlFunctionInfo));
    }
    *inout_count = need;
    return HDL_OK;
}

HdlStatus ResolveFunction(uint64_t addr, uint32_t search_flags, const wchar_t* module_or_null,
                          HdlFunctionInfo* out, volatile int* cancel) {
    if (!addr || !out) {
        return HDL_E_INVALID_ARG;
    }

    uint64_t scan_start = 0, scan_end = 0;
    if (module_or_null && module_or_null[0]) {
        if (!ModuleRange(module_or_null, &scan_start, &scan_end)) {
            return HDL_E_NOT_FOUND;
        }
    } else {
        /* Owning module via VirtualQuery + modules walk fallback: ModuleBase of main then search. */
        HMODULE mods[512];
        DWORD needed = 0;
        if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed)) {
            return HDL_E_FAILED;
        }
        const DWORD n = needed / sizeof(HMODULE);
        bool found = false;
        for (DWORD i = 0; i < n; ++i) {
            MODULEINFO mi{};
            if (!GetModuleInformation(GetCurrentProcess(), mods[i], &mi, sizeof(mi))) {
                continue;
            }
            const uint64_t b = reinterpret_cast<uint64_t>(mi.lpBaseOfDll);
            const uint64_t e = b + mi.SizeOfImage;
            if (addr >= b && addr < e) {
                scan_start = b;
                scan_end = e;
                found = true;
                break;
            }
        }
        if (!found) {
            return HDL_E_NOT_FOUND;
        }
    }

    if (addr < scan_start || addr >= scan_end) {
        return HDL_E_NOT_FOUND;
    }

    const std::vector<HdlFunctionInfo>* cached = nullptr;
    std::vector<HdlFunctionInfo> scratch;
    const HdlStatus cst =
        GetOrBuildModuleFns(scan_start, scan_end, search_flags, cancel, &cached, &scratch);
    if (cst != HDL_OK) {
        return cst;
    }

    /* Greatest start <= addr */
    const auto& fns = *cached;
    if (fns.empty()) {
        return HDL_E_NOT_FOUND;
    }

    /* On x64, compiler-authored unwind metadata is the strongest available
       instruction-aligned function boundary. It also accepts an arbitrary
       interior byte address, including a post-watchpoint RIP. */
    HdlFunctionInfo runtime{};
    if (LookupRuntimeFunction(addr, scan_start, scan_end, &runtime)) {
        const auto exact = std::lower_bound(
            fns.begin(), fns.end(), runtime.start,
            [](const HdlFunctionInfo& f, uint64_t start) { return f.start < start; });
        if (exact != fns.end() && exact->start == runtime.start) {
            runtime.flags = exact->flags;
        }
        *out = runtime;
        return HDL_OK;
    }

    size_t lo = 0, hi = fns.size();
    while (lo + 1 < hi) {
        const size_t mid = lo + (hi - lo) / 2;
        if (fns[mid].start <= addr) {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    if (fns[lo].start > addr) {
        return HDL_E_NOT_FOUND;
    }
    constexpr uint64_t kMaxBack = 64ull * 1024ull;
    if (addr - fns[lo].start > kMaxBack) {
        return HDL_E_NOT_FOUND;
    }
    if (fns[lo].end && addr >= fns[lo].end) {
        /* Past end of this function; try if next start still covers (gap). */
        if (lo + 1 >= fns.size() || fns[lo + 1].start > addr) {
            /* Still attribute to this start if within max-back of next? Prefer NOT_FOUND if clearly past end. */
            if (addr >= fns[lo].end + 16) {
                return HDL_E_NOT_FOUND;
            }
        }
    }
    *out = fns[lo];
    return HDL_OK;
}

HdlStatus XrefsFrom(uint64_t seed, uint32_t max_depth, uint32_t max_nodes, uint32_t kinds,
                    HdlXrefEdge* out, uint32_t* inout_count, volatile int* cancel) {
    if (!inout_count || !seed) {
        return HDL_E_INVALID_ARG;
    }
    if (max_depth == 0) {
        max_depth = 2;
    }
    if (max_nodes == 0 || max_nodes > 10000) {
        max_nodes = 256;
    }
    if (kinds == 0) {
        kinds = HDL_XREF_CALL | HDL_XREF_JMP;
    }

    std::vector<HdlXrefEdge> edges;
    std::unordered_set<uint64_t> visited;
    std::queue<std::pair<uint64_t, uint32_t>> q;
    q.push({seed, 0});
    visited.insert(seed);

    while (!q.empty() && edges.size() < max_nodes) {
        if (cancel && *cancel) {
            return HDL_E_CANCELLED;
        }
        const auto [fn, depth] = q.front();
        q.pop();
        if (depth >= max_depth) {
            continue;
        }
        uint64_t cur = fn;
        uint64_t budget = 4096;
        while (budget && edges.size() < max_nodes) {
            disasm::DecodedInsn d{};
            if (disasm::DecodeAt(cur, &d) != HDL_OK || d.length == 0) {
                break;
            }
            if (d.flags & HDL_INSN_RET) {
                break;
            }
            uint32_t kind = 0;
            if ((d.flags & HDL_INSN_CALL) && (kinds & HDL_XREF_CALL)) {
                kind = HDL_XREF_CALL;
            } else if ((d.flags & HDL_INSN_JMP) && (kinds & HDL_XREF_JMP)) {
                kind = HDL_XREF_JMP;
            } else if ((d.flags & HDL_INSN_RIP_REL) && (kinds & HDL_XREF_DATA)) {
                kind = HDL_XREF_DATA;
            }
            if (kind && (d.flags & HDL_INSN_BRANCH) && d.branch_target) {
                HdlXrefEdge e{};
                e.from = cur;
                e.to = d.branch_target;
                e.kind = kind;
                edges.push_back(e);
                if (kind != HDL_XREF_DATA && !visited.count(d.branch_target) &&
                    depth + 1 < max_depth) {
                    visited.insert(d.branch_target);
                    q.push({d.branch_target, depth + 1});
                }
            }
            cur += d.length;
            budget -= d.length;
        }
    }

    const uint32_t need = static_cast<uint32_t>(edges.size());
    if (!out || *inout_count < need) {
        *inout_count = need;
        return need ? HDL_E_BUFFER_SMALL : HDL_OK;
    }
    if (need) {
        memcpy(out, edges.data(), need * sizeof(HdlXrefEdge));
    }
    *inout_count = need;
    return HDL_OK;
}

HdlStatus XrefsTo(uint64_t target, uint32_t max_nodes, uint32_t kinds, uint32_t search_flags,
                  const wchar_t* module_or_null, HdlXrefEdge* out, uint32_t* inout_count,
                  volatile int* cancel) {
    if (!inout_count || !target) {
        return HDL_E_INVALID_ARG;
    }
    if (max_nodes == 0 || max_nodes > 10000) {
        max_nodes = 256;
    }
    if (kinds == 0) {
        kinds = HDL_XREF_CALL | HDL_XREF_JMP;
    }

    uint64_t scan_start = 0, scan_end = 0;
    if (module_or_null && module_or_null[0]) {
        if (!ModuleRange(module_or_null, &scan_start, &scan_end)) {
            return HDL_E_NOT_FOUND;
        }
    } else {
        HdlFunctionInfo fi{};
        if (ResolveFunction(target, search_flags, nullptr, &fi, cancel) == HDL_OK) {
            /* Scan the module that owns the target. */
            HMODULE mods[512];
            DWORD needed = 0;
            EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed);
            const DWORD n = needed / sizeof(HMODULE);
            for (DWORD i = 0; i < n; ++i) {
                MODULEINFO mi{};
                if (!GetModuleInformation(GetCurrentProcess(), mods[i], &mi, sizeof(mi))) {
                    continue;
                }
                const uint64_t b = reinterpret_cast<uint64_t>(mi.lpBaseOfDll);
                const uint64_t e = b + mi.SizeOfImage;
                if (target >= b && target < e) {
                    scan_start = b;
                    scan_end = e;
                    break;
                }
            }
        }
        if (!scan_start) {
            if (!ModuleRange(nullptr, &scan_start, &scan_end)) {
                return HDL_E_NOT_FOUND;
            }
        }
    }

    uint64_t fn_lo = target;
    uint64_t fn_hi = target + 1;
    if (kinds & HDL_XREF_FUNC) {
        HdlFunctionInfo fi{};
        if (ResolveFunction(target, search_flags, module_or_null, &fi, cancel) == HDL_OK) {
            fn_lo = fi.start;
            fn_hi = fi.end ? fi.end : (fi.start + 1);
        }
    }

    auto matches_target = [&](uint64_t branch_target) -> bool {
        if (branch_target == target) {
            return true;
        }
        if ((kinds & HDL_XREF_FUNC) && branch_target >= fn_lo && branch_target < fn_hi) {
            return true;
        }
        return false;
    };

    std::vector<HdlXrefEdge> edges;
    uint8_t* addr = reinterpret_cast<uint8_t*>(scan_start);
    MEMORY_BASIC_INFORMATION mbi{};
    while (reinterpret_cast<uint64_t>(addr) < scan_end && edges.size() < max_nodes &&
           VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (cancel && *cancel) {
            return HDL_E_CANCELLED;
        }
        const uint64_t b = reinterpret_cast<uint64_t>(mbi.BaseAddress);
        const uint64_t e = b + mbi.RegionSize;
        if (mbi.State == MEM_COMMIT && IsExec(mbi.Protect)) {
            const uint64_t from = (std::max)(b, scan_start);
            const uint64_t to = (std::min)(e, scan_end);
            for (uint64_t cur = from; cur + 16 < to && edges.size() < max_nodes;) {
                if (cancel && *cancel) {
                    return HDL_E_CANCELLED;
                }
                disasm::DecodedInsn d{};
                if (disasm::DecodeAt(cur, &d) != HDL_OK || d.length == 0) {
                    ++cur;
                    continue;
                }
                uint32_t kind = 0;
                if ((d.flags & HDL_INSN_CALL) && (kinds & HDL_XREF_CALL)) {
                    kind = HDL_XREF_CALL;
                } else if ((d.flags & HDL_INSN_JMP) && (kinds & HDL_XREF_JMP)) {
                    kind = HDL_XREF_JMP;
                } else if ((d.flags & HDL_INSN_RIP_REL) && (kinds & HDL_XREF_DATA) &&
                           (d.flags & HDL_INSN_BRANCH)) {
                    kind = HDL_XREF_DATA;
                }
                if (kind && (d.flags & HDL_INSN_BRANCH) && d.branch_target &&
                    matches_target(d.branch_target)) {
                    HdlXrefEdge edge{};
                    edge.from = cur;
                    edge.to = d.branch_target;
                    edge.kind = kind;
                    edges.push_back(edge);
                }
                cur += d.length;
            }
        }
        const uintptr_t next = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        if (next <= reinterpret_cast<uintptr_t>(addr)) {
            break;
        }
        addr = reinterpret_cast<uint8_t*>(next);
    }

    const uint32_t need = static_cast<uint32_t>(edges.size());
    if (!out || *inout_count < need) {
        *inout_count = need;
        return need ? HDL_E_BUFFER_SMALL : HDL_OK;
    }
    if (need) {
        memcpy(out, edges.data(), need * sizeof(HdlXrefEdge));
    }
    *inout_count = need;
    return HDL_OK;
}

}  // namespace hdl
