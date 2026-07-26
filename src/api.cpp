#include "hdllib/hdllib.h"

#include "alloc.hpp"
#include "call.hpp"
#include "code.hpp"
#include "core.hpp"
#include "disasm/backend.hpp"
#include "discover.hpp"
#include "fingerprint.hpp"
#include "graph.hpp"
#include "health.hpp"
#include "hooks.hpp"
#include "inject.hpp"
#include "inject/select.hpp"
#include "jobs.hpp"
#include "locate.hpp"
#include "log.hpp"
#include "memory.hpp"
#include "pe_meta.hpp"
#include "place.hpp"
#include "resolve.hpp"
#include "vtable.hpp"
#include "watch.hpp"

#include <string>

extern "C" {

HdlStatus HdlInit(void) {
    return hdl::CoreInit();
}

void HdlShutdown(void) {
    hdl::CoreShutdown();
}

int HdlIsInitialized(void) {
    return hdl::CoreIsInitialized() ? 1 : 0;
}

void HdlSetLogLevel(int level) {
    hdl::SetLogLevel(static_cast<hdl::LogLevel>(level));
}

HdlStatus HdlSetLogFile(const wchar_t* path_or_null) {
    return hdl::SetLogFile(path_or_null) ? HDL_OK : HDL_E_FAILED;
}

HdlStatus HdlSetHealthVeh(int enabled) {
    return hdl::SetHealthVeh(enabled != 0);
}

int HdlIsHealthVehEnabled(void) {
    return hdl::IsHealthVehEnabled() ? 1 : 0;
}

HdlStatus HdlStartIpc(void) {
    return hdl::StartIpc();
}

void HdlStopIpc(void) {
    hdl::StopIpc();
}

int HdlIsIpcRunning(void) {
    return hdl::IsIpcRunning() ? 1 : 0;
}

HdlStatus HdlInjectDll(uint32_t pid, const wchar_t* dll_path, uint64_t* out_base) {
    return hdl::InjectDll(pid, dll_path, out_base);
}

HdlStatus HdlInjectDllEx(uint32_t pid, const wchar_t* dll_path, int method,
                         const wchar_t* exe_path_or_null, const char* hook_export_or_null,
                         uint32_t* out_pid, uint64_t* out_base) {
    return hdl::InjectDllEx(pid, dll_path, method, exe_path_or_null, hook_export_or_null, out_pid,
                            out_base);
}

HdlStatus HdlUnloadDll(uint32_t pid, const wchar_t* dll_path, int reload, uint64_t* out_base) {
    return hdl::UnloadDll(pid, dll_path, reload, out_base);
}

HdlStatus HdlResolveTarget(const HdlTargetSpec* spec, uint32_t* out_pid, HWND* out_hwnd) {
    return hdl::inject::ResolveTarget(spec, out_pid, out_hwnd);
}

HdlStatus HdlRecommendInject(const HdlTargetSpec* spec, const wchar_t* dll_path_or_null,
                             const char* hook_export_or_null, HdlInjectCandidate* out,
                             uint32_t* inout_count) {
    if (!spec || !inout_count) {
        return HDL_E_INVALID_ARG;
    }
    uint32_t pid = 0;
    HWND hwnd = nullptr;
    const HdlStatus rst = hdl::inject::ResolveTarget(spec, &pid, &hwnd);
    if (rst != HDL_OK) {
        return rst;
    }
    const wchar_t* dll = nullptr;
    std::wstring full;
    if (dll_path_or_null && dll_path_or_null[0]) {
        full = hdl::inject::NormalizePath(dll_path_or_null);
        dll = full.c_str();
    }
    const hdl::inject::TargetProfile profile =
        hdl::inject::BuildTargetProfile(pid, hwnd, dll, hook_export_or_null);

    const uint32_t need = static_cast<uint32_t>(hdl::inject::kMethodCount);
    if (!out || *inout_count < need) {
        *inout_count = need;
        return HDL_E_BUFFER_SMALL;
    }
    hdl::inject::ScoreAllMethods(profile, out, inout_count);
    return HDL_OK;
}

LRESULT CALLBACK HdlHookProc(int code, WPARAM wParam, LPARAM lParam) {
    return CallNextHookEx(nullptr, code, wParam, lParam);
}

void CALLBACK HdlWinEventProc(HWINEVENTHOOK hook, DWORD event, HWND hwnd, LONG id_object,
                              LONG id_child, DWORD event_thread, DWORD event_time) {
    (void)hook;
    (void)event;
    (void)hwnd;
    (void)id_object;
    (void)id_child;
    (void)event_thread;
    (void)event_time;
}

HdlStatus HdlReadMemory(uint64_t address, void* buffer, size_t size, size_t* bytes_read) {
    return hdl::ReadMemory(address, buffer, size, bytes_read);
}

HdlStatus HdlWriteMemory(uint64_t address, const void* buffer, size_t size, size_t* bytes_written) {
    return hdl::WriteMemory(address, buffer, size, bytes_written);
}

HdlStatus HdlEnumRegions(HdlRegionInfo* out, uint32_t* inout_count) {
    return hdl::EnumRegions(out, inout_count);
}

HdlStatus HdlEnumModules(HdlModuleInfo* out, uint32_t* inout_count) {
    return hdl::EnumModules(out, inout_count);
}

HdlStatus HdlSearchMemory(uint64_t start, uint64_t size, const char* pattern, uint64_t* out_hits,
                          uint32_t* inout_hit_count, volatile int* cancel) {
    return hdl::SearchMemory(start, size, pattern, out_hits, inout_hit_count, cancel);
}

HdlStatus HdlSearchCreate(HdlSearchSession** out_session) {
    return hdl::SearchCreate(out_session);
}

void HdlSearchClose(HdlSearchSession* session) {
    hdl::SearchClose(session);
}

void HdlSearchReset(HdlSearchSession* session) {
    hdl::SearchReset(session);
}

HdlStatus HdlSearchFirst(HdlSearchSession* session, const HdlSearchDesc* desc, volatile int* cancel) {
    return hdl::SearchFirst(session, desc, cancel);
}

HdlStatus HdlSearchNext(HdlSearchSession* session, int cmp, const void* value, size_t value_size,
                        volatile int* cancel) {
    return hdl::SearchNext(session, cmp, value, value_size, cancel);
}

HdlStatus HdlSearchGetCount(const HdlSearchSession* session, uint32_t* out_count) {
    return hdl::SearchGetCount(session, out_count);
}

HdlStatus HdlSearchGetHits(const HdlSearchSession* session, uint64_t* out_hits,
                           uint32_t* inout_count) {
    return hdl::SearchGetHits(session, out_hits, inout_count);
}

HdlStatus HdlResolvePattern(const HdlPatternResolve* in, HdlPatternResult* out,
                            volatile int* cancel) {
    return hdl::ResolvePattern(in, out, cancel);
}

HdlStatus HdlFindStringXrefs(const void* string, size_t string_size, int is_wide,
                             uint32_t xref_flags, uint32_t search_flags,
                             const wchar_t* module_or_null, uint64_t* out_xrefs,
                             uint32_t* inout_count, volatile int* cancel) {
    return hdl::FindStringXrefs(string, string_size, is_wide, xref_flags, search_flags,
                                module_or_null, out_xrefs, inout_count, cancel);
}

HdlStatus HdlPointerScan(uint64_t target_addr, uint32_t max_depth, uint32_t max_offset,
                         uint32_t max_results, uint32_t search_flags, const wchar_t* module_or_null,
                         HdlPointerPath* out, uint32_t* inout_count, volatile int* cancel) {
    return hdl::PointerScan(target_addr, max_depth, max_offset, max_results, search_flags,
                            module_or_null, out, inout_count, cancel);
}

HdlStatus HdlProbeStruct(uint64_t addr, uint32_t size, HdlStructField* out, uint32_t* inout_count) {
    return hdl::ProbeStruct(addr, size, out, inout_count);
}

HdlStatus HdlGetHealth(HdlHealthInfo* out) {
    return hdl::GetHealth(out);
}

HdlStatus HdlEnumThreads(HdlThreadInfo* out, uint32_t* inout_count) {
    return hdl::EnumThreads(out, inout_count);
}

HdlStatus HdlEnumFingerprintTags(uint32_t scan_flags, HdlFingerprintTag* out,
                                 uint32_t* inout_count) {
    return hdl::EnumFingerprintTags(scan_flags, out, inout_count);
}

HdlStatus HdlClassifyFingerprint(const wchar_t* const* module_basenames, uint32_t module_count,
                                 const HdlFingerprintImport* imports, uint32_t import_count,
                                 uint16_t pe_subsystem, uint32_t scan_flags, HdlFingerprintTag* out,
                                 uint32_t* inout_count) {
    return hdl::ClassifyFingerprintApi(module_basenames, module_count, imports, import_count,
                                       pe_subsystem, scan_flags, out, inout_count);
}

HdlStatus HdlPollEvents(HdlEvent* out, uint32_t* inout_count, uint32_t timeout_ms) {
    if (!inout_count) {
        return HDL_E_INVALID_ARG;
    }
    const uint32_t max_events = *inout_count;
    if (!out || max_events == 0) {
        *inout_count = 0;
        return HDL_E_INVALID_ARG;
    }
    *inout_count = hdl::HealthPollEvents(out, max_events, timeout_ms);
    return HDL_OK;
}

HdlStatus HdlJobCreate(uint32_t timeout_ms, uint64_t* out_job_id) {
    if (!out_job_id) {
        return HDL_E_INVALID_ARG;
    }
    auto job = hdl::JobCreate(timeout_ms);
    *out_job_id = job->id;
    return HDL_OK;
}

HdlStatus HdlJobCancel(uint64_t job_id) {
    if (!job_id || !hdl::JobFind(job_id)) {
        return HDL_E_NOT_FOUND;
    }
    hdl::JobCancel(job_id);
    return HDL_OK;
}

void HdlJobClose(uint64_t job_id) {
    hdl::JobClose(job_id);
}

HdlStatus HdlAlloc(size_t size, uint32_t protect, uint64_t* out_addr) {
    return hdl::Alloc(size, protect, out_addr);
}

HdlStatus HdlAllocNear(uint64_t near_addr, uint64_t max_distance, size_t size, uint32_t protect,
                       uint64_t* out_addr) {
    return hdl::AllocNear(near_addr, max_distance, size, protect, out_addr);
}

HdlStatus HdlFree(uint64_t addr) {
    return hdl::Free(addr);
}

HdlStatus HdlFindCaves(const HdlCaveQuery* query, HdlCaveInfo* out, uint32_t* inout_count,
                       volatile int* cancel) {
    return hdl::FindCaves(query, out, inout_count, cancel);
}

HdlStatus HdlProtectMemory(uint64_t addr, size_t size, uint32_t protect, uint32_t* out_old) {
    return hdl::ProtectMemory(addr, size, protect, out_old);
}

HdlStatus HdlFlushICache(uint64_t addr, size_t size) {
    return hdl::FlushICache(addr, size);
}

HdlStatus HdlResolveRipRelative(uint64_t addr, uint32_t disp_offset, uint32_t instr_len,
                                uint64_t* out_addr) {
    return hdl::ResolveRipRelative(addr, disp_offset, instr_len, out_addr);
}

HdlStatus HdlFollowPointers(uint64_t base, const int64_t* offsets, uint32_t offset_count,
                            uint64_t* out_addr) {
    return hdl::FollowPointers(base, offsets, offset_count, out_addr);
}

HdlStatus HdlModuleBase(const wchar_t* module_or_null, uint64_t* out_base) {
    return hdl::ModuleBase(module_or_null, out_base);
}

HdlStatus HdlResolveExport(const wchar_t* module_or_null, const char* export_name,
                           uint64_t* out_addr) {
    return hdl::ResolveExport(module_or_null, export_name, out_addr);
}

HdlStatus HdlCall(const HdlCallDesc* desc, HdlCallResult* out, volatile int* cancel) {
    return hdl::Call(desc, out, cancel);
}

HdlStatus HdlCallExport(const wchar_t* module_or_null, const char* export_name,
                        const HdlCallArg* args, uint32_t arg_count, HdlCallResult* out,
                        uint32_t timeout_ms, volatile int* cancel) {
    return hdl::CallExport(module_or_null, export_name, args, arg_count, out, timeout_ms, cancel);
}

HdlStatus HdlCallVtable(uint64_t obj, uint32_t index, const HdlCallArg* args, uint32_t arg_count,
                        int prepend_this, uint32_t thread_mode, HdlCallResult* out,
                        uint32_t timeout_ms, volatile int* cancel) {
    return hdl::CallVtable(obj, index, args, arg_count, prepend_this, thread_mode, out, timeout_ms,
                           cancel);
}

HdlStatus HdlHook(void* target, void* detour, void** trampoline, HdlHookHandle* out_handle) {
    return hdl::Hook(target, detour, trampoline, out_handle);
}

HdlStatus HdlEnableHook(HdlHookHandle handle, int enable) {
    return hdl::EnableHook(handle, enable);
}

HdlStatus HdlUnhook(HdlHookHandle handle) {
    return hdl::Unhook(handle);
}

HdlStatus HdlHookTrace(uint64_t target, uint32_t arg_count, HdlHookHandle* out) {
    return hdl::HookTrace(target, arg_count, out);
}

HdlStatus HdlHookImport(const wchar_t* module_or_null, const char* dll_name, const char* import_name,
                        uint32_t arg_count, HdlHookHandle* out) {
    return hdl::HookImport(module_or_null, dll_name, import_name, arg_count, out);
}

HdlStatus HdlPollHookHits(HdlHookHit* out, uint32_t* inout_count, uint32_t timeout_ms) {
    return hdl::PollHookHits(out, inout_count, timeout_ms);
}

HdlStatus HdlDiscoverCreate(HdlDiscoverSession** out_session) {
    return hdl::DiscoverCreate(out_session);
}

void HdlDiscoverClose(HdlDiscoverSession* session) {
    hdl::DiscoverClose(session);
}

HdlStatus HdlDiscoverAddCandidate(HdlDiscoverSession* session, uint32_t kind, uint64_t address,
                                  const char* tag_or_null, uint64_t* out_id) {
    return hdl::DiscoverAddCandidate(session, kind, address, tag_or_null, out_id);
}

HdlStatus HdlDiscoverScanValue(HdlDiscoverSession* session, const HdlSearchDesc* desc,
                               const char* tag_or_null, volatile int* cancel) {
    return hdl::DiscoverScanValue(session, desc, tag_or_null, cancel);
}

HdlStatus HdlDiscoverConstraintScan(HdlDiscoverSession* session, uint32_t object_size,
                                    const HdlFieldPred* preds, uint32_t pred_count,
                                    uint32_t search_flags, const wchar_t* module_or_null,
                                    uint32_t max_results, const char* tag_or_null,
                                    volatile int* cancel) {
    return hdl::DiscoverConstraintScan(session, object_size, preds, pred_count, search_flags,
                                       module_or_null, max_results, tag_or_null, cancel);
}

HdlStatus HdlDiscoverSynthesizePattern(HdlDiscoverSession* session, uint64_t cand_id,
                                       uint32_t window_before, uint32_t window_after,
                                       uint32_t search_flags, const wchar_t* module_or_null,
                                       HdlSynthesizedPattern* out, volatile int* cancel) {
    return hdl::DiscoverSynthesizePattern(session, cand_id, window_before, window_after,
                                          search_flags, module_or_null, out, cancel);
}

HdlStatus HdlDiscoverPathConsensus(uint64_t target_addr, uint32_t max_depth, uint32_t max_offset,
                                   uint32_t max_results, uint32_t search_flags,
                                   const wchar_t* module_or_null, HdlPointerPath* out,
                                   uint32_t* inout_count, volatile int* cancel) {
    return hdl::DiscoverPathConsensus(target_addr, max_depth, max_offset, max_results, search_flags,
                                      module_or_null, out, inout_count, cancel);
}

HdlStatus HdlDiscoverPathValidate(HdlPointerPath* paths, uint32_t* inout_count,
                                  uint64_t expected_target) {
    return hdl::DiscoverPathValidate(paths, inout_count, expected_target);
}

HdlStatus HdlDiscoverWatch(HdlDiscoverSession* session, uint64_t fn_addr, uint32_t arg_count) {
    return hdl::DiscoverWatch(session, fn_addr, arg_count);
}

HdlStatus HdlDiscoverWatchImport(HdlDiscoverSession* session, const wchar_t* module_or_null,
                                 const char* dll_name, const char* import_name,
                                 uint32_t arg_count) {
    return hdl::DiscoverWatchImport(session, module_or_null, dll_name, import_name, arg_count);
}

HdlStatus HdlDiscoverUnwatchAll(HdlDiscoverSession* session) {
    return hdl::DiscoverUnwatchAll(session);
}

HdlStatus HdlDiscoverActionBegin(HdlDiscoverSession* session, const char* name) {
    return hdl::DiscoverActionBegin(session, name);
}

HdlStatus HdlDiscoverActionEnd(HdlDiscoverSession* session) {
    return hdl::DiscoverActionEnd(session);
}

HdlStatus HdlDiscoverWatchRegion(HdlDiscoverSession* session, uint64_t base, uint32_t size) {
    return hdl::DiscoverWatchRegion(session, base, size);
}

HdlStatus HdlDiscoverGetHeat(HdlDiscoverSession* session, uint64_t base, HdlHeatField* out,
                             uint32_t* inout_count) {
    return hdl::DiscoverGetHeat(session, base, out, inout_count);
}

HdlStatus HdlDiscoverRankFunctions(HdlDiscoverSession* session, const char* action_name,
                                   uint32_t flags, HdlCandidate* out, uint32_t* inout_count) {
    return hdl::DiscoverRankFunctions(session, action_name, flags, out, inout_count);
}

HdlStatus HdlDiscoverResetHeat(HdlDiscoverSession* session, uint64_t base) {
    return hdl::DiscoverResetHeat(session, base);
}

HdlStatus HdlDiscoverDiffObjects(HdlDiscoverSession* session, const uint64_t* addrs, uint32_t count,
                                 uint32_t max_size, HdlHeatField* out, uint32_t* inout_count) {
    return hdl::DiscoverDiffObjects(session, addrs, count, max_size, out, inout_count);
}

HdlStatus HdlDiscoverApplyWatchHits(HdlDiscoverSession* session, uint64_t object_base,
                                    uint32_t size) {
    return hdl::DiscoverApplyWatchHits(session, object_base, size);
}

HdlStatus HdlDiscoverGetCandidateEvidence(HdlDiscoverSession* session, uint64_t cand_id, char* buf,
                                          uint32_t cap) {
    return hdl::DiscoverGetCandidateEvidence(session, cand_id, buf, cap);
}

HdlStatus HdlDiscoverExport(HdlDiscoverSession* session, char* buf, uint32_t* inout_size) {
    return hdl::DiscoverExport(session, buf, inout_size);
}

HdlStatus HdlDiscoverImport(HdlDiscoverSession* session, const char* json, uint32_t size) {
    return hdl::DiscoverImport(session, json, size);
}

HdlStatus HdlDiscoverClusterType(HdlDiscoverSession* session, uint64_t seed_addr,
                                 uint32_t object_size, uint32_t search_flags,
                                 const wchar_t* module_or_null, uint32_t max_results,
                                 volatile int* cancel) {
    return hdl::DiscoverClusterType(session, seed_addr, object_size, search_flags, module_or_null,
                                    max_results, cancel);
}

HdlStatus HdlDiscoverGetCandidates(HdlDiscoverSession* session, HdlCandidate* out,
                                   uint32_t* inout_count) {
    return hdl::DiscoverGetCandidates(session, out, inout_count);
}

HdlStatus HdlDisasmEnumBackends(HdlDisasmBackendInfo* out, uint32_t* inout_count) {
    return hdl::disasm::EnumBackends(out, inout_count);
}

HdlStatus HdlDisasmGetBackend(int32_t* out_id) {
    return hdl::disasm::GetBackend(out_id);
}

HdlStatus HdlDisasmSetBackend(int32_t id) {
    return hdl::disasm::SetBackend(id);
}

HdlStatus HdlDisasmRegisterBackend(const HdlDisasmBackendFns* fns, int32_t* out_id) {
    return hdl::disasm::RegisterExternal(fns, out_id);
}

HdlStatus HdlDisasmUnregisterBackend(int32_t id) {
    return hdl::disasm::UnregisterExternal(id);
}

HdlStatus HdlInstrLen(uint64_t addr, uint32_t* out_len) {
    return hdl::InstrLen(addr, out_len);
}

HdlStatus HdlDisasm(uint64_t addr, uint32_t max_insns, HdlInsn* out, uint32_t* inout_count) {
    return hdl::DisasmRange(addr, max_insns, out, inout_count);
}

HdlStatus HdlBuildStub(const HdlStubDesc* desc, HdlStubResult* out) {
    return hdl::BuildStub(desc, out);
}

HdlStatus HdlPatchCreate(uint64_t addr, const void* bytes, size_t size, const char* name_or_null,
                         HdlPatchHandle* out) {
    return hdl::PatchCreate(addr, bytes, size, name_or_null, out);
}

HdlStatus HdlPatchEnable(HdlPatchHandle handle, int enable) {
    return hdl::PatchEnable(handle, enable);
}

HdlStatus HdlPatchRemove(HdlPatchHandle handle) {
    return hdl::PatchRemove(handle);
}

HdlStatus HdlPatchEnum(HdlPatchInfo* out, uint32_t* inout_count) {
    return hdl::PatchEnum(out, inout_count);
}

HdlStatus HdlEnumSections(uint64_t module_base_or_0, HdlSectionInfo* out, uint32_t* inout_count) {
    return hdl::EnumSections(module_base_or_0, out, inout_count);
}

HdlStatus HdlEnumExports(uint64_t module_base_or_0, HdlExportInfo* out, uint32_t* inout_count) {
    return hdl::EnumExports(module_base_or_0, out, inout_count);
}

HdlStatus HdlEnumImports(uint64_t module_base_or_0, HdlImportInfo* out, uint32_t* inout_count) {
    return hdl::EnumImports(module_base_or_0, out, inout_count);
}

HdlStatus HdlEnumFunctions(uint64_t start, uint64_t size, uint32_t search_flags,
                           const wchar_t* module_or_null, uint32_t max_results, HdlFunctionInfo* out,
                           uint32_t* inout_count, volatile int* cancel) {
    return hdl::EnumFunctions(start, size, search_flags, module_or_null, max_results, out,
                              inout_count, cancel);
}

HdlStatus HdlXrefsFrom(uint64_t seed, uint32_t max_depth, uint32_t max_nodes, uint32_t kinds,
                       HdlXrefEdge* out, uint32_t* inout_count, volatile int* cancel) {
    return hdl::XrefsFrom(seed, max_depth, max_nodes, kinds, out, inout_count, cancel);
}

HdlStatus HdlResolveFunction(uint64_t addr, uint32_t search_flags, const wchar_t* module_or_null,
                             HdlFunctionInfo* out, volatile int* cancel) {
    return hdl::ResolveFunction(addr, search_flags, module_or_null, out, cancel);
}

HdlStatus HdlXrefsTo(uint64_t target, uint32_t max_nodes, uint32_t kinds, uint32_t search_flags,
                     const wchar_t* module_or_null, HdlXrefEdge* out, uint32_t* inout_count,
                     volatile int* cancel) {
    return hdl::XrefsTo(target, max_nodes, kinds, search_flags, module_or_null, out, inout_count,
                        cancel);
}

HdlStatus HdlInvalidateFunctionIndex(const wchar_t* module_or_null) {
    return hdl::InvalidateFunctionIndex(module_or_null);
}

HdlStatus HdlWalkVtable(uint64_t obj_or_vtable, int is_object, uint64_t* out_slots,
                        uint32_t* inout_count) {
    return hdl::WalkVtable(obj_or_vtable, is_object, out_slots, inout_count);
}

HdlStatus HdlQueryRttiName(uint64_t obj_or_vtable, int is_object, char* out_name,
                           uint32_t name_cap) {
    return hdl::QueryRttiName(obj_or_vtable, is_object, out_name, name_cap);
}

HdlStatus HdlWatchHw(uint64_t addr, uint32_t size, uint32_t access, uint32_t tid,
                     HdlWatchHandle* out) {
    return hdl::WatchHw(addr, size, access, tid, out);
}

HdlStatus HdlWatchPage(uint64_t addr, size_t size, uint32_t mode, HdlWatchHandle* out) {
    return hdl::WatchPage(addr, size, mode, out);
}

HdlStatus HdlUnwatch(HdlWatchHandle handle) {
    return hdl::Unwatch(handle);
}

HdlStatus HdlEnumWatches(HdlWatchInfo* out, uint32_t* inout_count) {
    return hdl::EnumWatches(out, inout_count);
}

HdlStatus HdlWatchRefresh(void) {
    return hdl::WatchRefresh();
}

HdlStatus HdlPollWatchHits(HdlWatchHit* out, uint32_t* inout_count, uint32_t timeout_ms) {
    return hdl::PollWatchHits(out, inout_count, timeout_ms);
}

}  // extern "C"
