#include "hooks.hpp"
#include "health.hpp"
#include "log.hpp"
#include "pe_meta.hpp"
#include "resolve.hpp"

#include <MinHook.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <mutex>
#include <unordered_map>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

extern "C" void HdlTraceEntry(void);
extern "C" uint64_t HdlInvokeX64(void* fn, const uint64_t* gpr, const uint64_t* xmm,
                                 const uint64_t* stack_args, uint32_t stack_count);

struct TraceContext {
    void* trampoline = nullptr;
    uint64_t hook_id = 0;
    uint32_t arg_count = 0;
    uint32_t reserved = 0;
};

namespace hdl {
namespace {

struct HookEntry {
    void* target = nullptr;
    void* detour = nullptr;
    void* trampoline = nullptr;
    bool enabled = false;
    bool is_trace = false;
    void* stub_mem = nullptr;
    size_t stub_size = 0;
    TraceContext* trace_ctx = nullptr;
};

std::recursive_mutex g_mu;
std::unordered_map<void*, HookEntry> g_hooks;
bool g_mh_init = false;

std::mutex g_hit_mu;
std::condition_variable g_hit_cv;
std::deque<HdlHookHit> g_hits;
constexpr size_t kMaxHits = 256;
std::atomic<bool> g_hooks_alive{false};

HdlStatus HooksInitLocked() {
    if (g_mh_init) {
        return HDL_OK;
    }
    const MH_STATUS st = MH_Initialize();
    if (st != MH_OK && st != MH_ERROR_ALREADY_INITIALIZED) {
        HDL_LOG_ERROR("MH_Initialize failed: %d", static_cast<int>(st));
        return HDL_E_FAILED;
    }
    g_mh_init = true;
    g_hooks_alive.store(true);
    return HDL_OK;
}

void PushHitUnlocked(const HdlHookHit& hit) {
    if (g_hits.size() >= kMaxHits) {
        g_hits.pop_front();
    }
    g_hits.push_back(hit);
}

void* AllocStub(const uint8_t* bytes, size_t n) {
    void* mem = VirtualAlloc(nullptr, n, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) {
        return nullptr;
    }
    memcpy(mem, bytes, n);
    DWORD old = 0;
    if (!VirtualProtect(mem, n, PAGE_EXECUTE_READ, &old)) {
        VirtualFree(mem, 0, MEM_RELEASE);
        return nullptr;
    }
    FlushInstructionCache(GetCurrentProcess(), mem, n);
    return mem;
}

void* BuildTraceStub(TraceContext* ctx) {
    uint8_t code[32];
    size_t o = 0;
    code[o++] = 0x49;
    code[o++] = 0xBB; /* mov r11, imm64 */
    const uint64_t ctx_imm = reinterpret_cast<uint64_t>(ctx);
    memcpy(code + o, &ctx_imm, 8);
    o += 8;
    code[o++] = 0x48;
    code[o++] = 0xB8; /* mov rax, imm64 */
    const uint64_t entry = reinterpret_cast<uint64_t>(&HdlTraceEntry);
    memcpy(code + o, &entry, 8);
    o += 8;
    code[o++] = 0xFF;
    code[o++] = 0xE0; /* jmp rax */
    return AllocStub(code, o);
}

void FreeTraceResources(HookEntry& e) {
    if (e.stub_mem) {
        VirtualFree(e.stub_mem, 0, MEM_RELEASE);
        e.stub_mem = nullptr;
    }
    if (e.trace_ctx) {
        delete e.trace_ctx;
        e.trace_ctx = nullptr;
    }
}

}  // namespace

void RecordHookHit(const HdlHookHit& hit) {
    {
        std::lock_guard<std::mutex> lock(g_hit_mu);
        PushHitUnlocked(hit);
    }
    g_hit_cv.notify_all();

    HdlEvent ev{};
    ev.type = HDL_EVENT_HOOK;
    ev.code = 0;
    ev.timestamp_ms = hit.timestamp_ms;
    ev.address = hit.hook_id;
    ev.detail = hit.return_value;
    HealthPushEvent(&ev);
}

HdlStatus HooksInit() {
    std::lock_guard<std::recursive_mutex> lock(g_mu);
    return HooksInitLocked();
}

void HooksShutdown() {
    std::lock_guard<std::recursive_mutex> lock(g_mu);
    g_hooks_alive.store(false);
    g_hit_cv.notify_all();
    if (!g_mh_init) {
        return;
    }
    MH_DisableHook(MH_ALL_HOOKS);
    /* Let in-flight detours return before removing hooks / freeing stubs. */
    Sleep(1);
    for (auto& kv : g_hooks) {
        MH_RemoveHook(kv.second.target);
        FreeTraceResources(kv.second);
    }
    g_hooks.clear();
    {
        std::lock_guard<std::mutex> hlock(g_hit_mu);
        g_hits.clear();
    }
    MH_Uninitialize();
    g_mh_init = false;
}

HdlStatus Hook(void* target, void* detour, void** trampoline, HdlHookHandle* out_handle) {
    if (!target || !detour || !out_handle) {
        return HDL_E_INVALID_ARG;
    }
    *out_handle = nullptr;

    std::lock_guard<std::recursive_mutex> lock(g_mu);
    if (HooksInitLocked() != HDL_OK) {
        return HDL_E_FAILED;
    }
    if (g_hooks.count(target)) {
        return HDL_E_BUSY;
    }

    void* original = nullptr;
    MH_STATUS st = MH_CreateHook(target, detour, &original);
    if (st != MH_OK) {
        HDL_LOG_ERROR("MH_CreateHook failed: %d", static_cast<int>(st));
        return HDL_E_FAILED;
    }
    st = MH_EnableHook(target);
    if (st != MH_OK) {
        MH_RemoveHook(target);
        HDL_LOG_ERROR("MH_EnableHook failed: %d", static_cast<int>(st));
        return HDL_E_FAILED;
    }

    HookEntry entry;
    entry.target = target;
    entry.detour = detour;
    entry.trampoline = original;
    entry.enabled = true;
    g_hooks[target] = entry;

    if (trampoline) {
        *trampoline = original;
    }
    *out_handle = target;
    HDL_LOG_DEBUG("Hook installed at %p", target);
    return HDL_OK;
}

HdlStatus HookTrace(uint64_t target, uint32_t arg_count, HdlHookHandle* out) {
    if (!target || !out || arg_count > 8) {
        return HDL_E_INVALID_ARG;
    }
    *out = nullptr;
    void* t = reinterpret_cast<void*>(target);

    std::lock_guard<std::recursive_mutex> lock(g_mu);
    if (HooksInitLocked() != HDL_OK) {
        return HDL_E_FAILED;
    }
    if (g_hooks.count(t)) {
        return HDL_E_BUSY;
    }

    auto* ctx = new TraceContext();
    ctx->hook_id = target;
    ctx->arg_count = arg_count;
    ctx->trampoline = nullptr;

    void* stub = BuildTraceStub(ctx);
    if (!stub) {
        delete ctx;
        return HDL_E_NO_MEM;
    }

    void* original = nullptr;
    MH_STATUS st = MH_CreateHook(t, stub, &original);
    if (st != MH_OK) {
        VirtualFree(stub, 0, MEM_RELEASE);
        delete ctx;
        HDL_LOG_ERROR("MH_CreateHook (trace) failed: %d", static_cast<int>(st));
        return HDL_E_FAILED;
    }
    ctx->trampoline = original;
    st = MH_EnableHook(t);
    if (st != MH_OK) {
        MH_RemoveHook(t);
        VirtualFree(stub, 0, MEM_RELEASE);
        delete ctx;
        return HDL_E_FAILED;
    }

    HookEntry entry;
    entry.target = t;
    entry.detour = stub;
    entry.trampoline = original;
    entry.enabled = true;
    entry.is_trace = true;
    entry.stub_mem = stub;
    entry.stub_size = 32;
    entry.trace_ctx = ctx;
    g_hooks[t] = entry;
    *out = t;
    return HDL_OK;
}

HdlStatus EnableHook(HdlHookHandle handle, int enable) {
    if (!handle) {
        return HDL_E_INVALID_ARG;
    }
    std::lock_guard<std::recursive_mutex> lock(g_mu);
    auto it = g_hooks.find(handle);
    if (it == g_hooks.end()) {
        return HDL_E_NOT_FOUND;
    }
    MH_STATUS st = enable ? MH_EnableHook(it->second.target) : MH_DisableHook(it->second.target);
    if (st != MH_OK) {
        return HDL_E_FAILED;
    }
    it->second.enabled = enable != 0;
    return HDL_OK;
}

HdlStatus Unhook(HdlHookHandle handle) {
    if (!handle) {
        return HDL_E_INVALID_ARG;
    }
    std::lock_guard<std::recursive_mutex> lock(g_mu);
    auto it = g_hooks.find(handle);
    if (it == g_hooks.end()) {
        return HDL_E_NOT_FOUND;
    }
    MH_DisableHook(it->second.target);
    MH_RemoveHook(it->second.target);
    FreeTraceResources(it->second);
    g_hooks.erase(it);
    return HDL_OK;
}

HdlStatus PollHookHits(HdlHookHit* out, uint32_t* inout_count, uint32_t timeout_ms) {
    if (!inout_count) {
        return HDL_E_INVALID_ARG;
    }
    const uint32_t max_n = *inout_count;
    if (!out || max_n == 0) {
        *inout_count = 0;
        return HDL_E_INVALID_ARG;
    }

    std::unique_lock<std::mutex> lock(g_hit_mu);
    if (g_hits.empty() && timeout_ms > 0) {
        g_hit_cv.wait_for(lock, std::chrono::milliseconds(timeout_ms),
                          [] { return !g_hits.empty() || !g_hooks_alive.load(); });
    }
    uint32_t n = 0;
    while (n < max_n && !g_hits.empty()) {
        out[n++] = g_hits.front();
        g_hits.pop_front();
    }
    *inout_count = n;
    return HDL_OK;
}

bool ImportDllMatches(const char* module_field, const char* dll_name) {
    if (!module_field || !dll_name) {
        return false;
    }
    const char* base = strrchr(module_field, '\\');
    base = base ? base + 1 : module_field;
    const char* want = strrchr(dll_name, '\\');
    want = want ? want + 1 : dll_name;
    return _stricmp(base, want) == 0;
}

HdlStatus HookImport(const wchar_t* module_or_null, const char* dll_name, const char* import_name,
                     uint32_t arg_count, HdlHookHandle* out) {
    if (!dll_name || !import_name || !import_name[0] || !out) {
        return HDL_E_INVALID_ARG;
    }
    *out = nullptr;

    uint64_t mod_base = 0;
    if (module_or_null && module_or_null[0]) {
        const HdlStatus mb = ModuleBase(module_or_null, &mod_base);
        if (mb != HDL_OK) {
            return mb;
        }
    }

    uint32_t count = 0;
    HdlStatus st = EnumImports(mod_base, nullptr, &count);
    if (st != HDL_E_BUFFER_SMALL && st != HDL_OK) {
        return st;
    }
    if (count == 0) {
        return HDL_E_NOT_FOUND;
    }
    std::vector<HdlImportInfo> imports(count);
    st = EnumImports(mod_base, imports.data(), &count);
    if (st != HDL_OK) {
        return st;
    }

    for (uint32_t i = 0; i < count; ++i) {
        const HdlImportInfo& info = imports[i];
        if (!ImportDllMatches(info.module, dll_name)) {
            continue;
        }
        if (!info.name[0] || _stricmp(info.name, import_name) != 0) {
            continue;
        }
        if (!info.bound_va) {
            return HDL_E_NOT_FOUND;
        }
        return HookTrace(info.bound_va, arg_count, out);
    }
    return HDL_E_NOT_FOUND;
}

}  // namespace hdl

extern "C" uint64_t HdlTraceCapture(TraceContext* ctx, uint64_t caller, uint64_t a0, uint64_t a1,
                                    uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6,
                                    uint64_t a7) {
    if (!ctx || !ctx->trampoline) {
        return 0;
    }
    uint64_t args[8] = {a0, a1, a2, a3, a4, a5, a6, a7};
    uint64_t gpr[4] = {a0, a1, a2, a3};
    uint64_t xmm[4] = {};
    const uint32_t n = ctx->arg_count > 8 ? 8 : ctx->arg_count;
    std::vector<uint64_t> stack;
    if (n > 4) {
        for (uint32_t i = 4; i < n; ++i) {
            stack.push_back(args[i]);
        }
    }
    const uint64_t ret =
        HdlInvokeX64(ctx->trampoline, gpr, xmm, stack.empty() ? nullptr : stack.data(),
                     static_cast<uint32_t>(stack.size()));

    HdlHookHit hit{};
    hit.hook_id = ctx->hook_id;
    hit.timestamp_ms = GetTickCount64();
    hit.return_value = ret;
    hit.arg_count = n;
    hit.caller = caller;
    for (uint32_t i = 0; i < n; ++i) {
        hit.args[i] = args[i];
    }
    void* frames[HDL_HOOK_MAX_FRAMES + 1]{};
    const USHORT captured =
        RtlCaptureStackBackTrace(1, HDL_HOOK_MAX_FRAMES, frames, nullptr);
    hit.frame_count = captured;
    for (USHORT i = 0; i < captured; ++i) {
        hit.frames[i] = reinterpret_cast<uint64_t>(frames[i]);
    }
    hdl::RecordHookHit(hit);
    return ret;
}
