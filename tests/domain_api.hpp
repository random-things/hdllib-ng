#pragma once

/* In-process domain entry points for hdl_tests (HDL_DOMAIN_TESTS).
 * Prefer these over removed DLL control exports. */

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
#include "jobs.hpp"
#include "locate.hpp"
#include "log.hpp"
#include "memory.hpp"
#include "pe_meta.hpp"
#include "place.hpp"
#include "resolve.hpp"
#include "vtable.hpp"
#include "watch.hpp"

namespace hdl::testapi {

inline HdlStatus Init() {
    return CoreInit();
}
inline void Shutdown() {
    CoreShutdown();
}
inline bool IsInitialized() {
    return CoreIsInitialized();
}
inline void SetLogLevelInt(int level) {
    SetLogLevel(static_cast<LogLevel>(level));
}
inline HdlStatus Disasm(uint64_t addr, uint32_t max_insns, HdlInsn* out, uint32_t* inout_count) {
    return DisasmRange(addr, max_insns, out, inout_count);
}
inline HdlStatus DisasmEnumBackends(HdlDisasmBackendInfo* out, uint32_t* inout_count) {
    return disasm::EnumBackends(out, inout_count);
}
inline HdlStatus DisasmGetBackend(int32_t* out_id) {
    return disasm::GetBackend(out_id);
}
inline HdlStatus DisasmSetBackend(int32_t id) {
    return disasm::SetBackend(id);
}
inline HdlStatus DisasmRegisterBackend(const HdlDisasmBackendFns* fns, int32_t* out_id) {
    return disasm::RegisterExternal(fns, out_id);
}
inline HdlStatus DisasmUnregisterBackend(int32_t id) {
    return disasm::UnregisterExternal(id);
}
inline HdlStatus JobCreate(uint32_t timeout_ms, uint64_t* out_job_id) {
    if (!out_job_id) {
        return HDL_E_INVALID_ARG;
    }
    auto job = ::hdl::JobCreate(timeout_ms);
    if (!job) {
        return HDL_E_NO_MEM;
    }
    *out_job_id = job->id;
    return HDL_OK;
}
inline HdlStatus JobCancelStatus(uint64_t job_id) {
    if (!job_id || !::hdl::JobFind(job_id)) {
        return HDL_E_NOT_FOUND;
    }
    ::hdl::JobCancel(job_id);
    return HDL_OK;
}
inline void JobCloseId(uint64_t job_id) {
    ::hdl::JobClose(job_id);
}
inline HdlStatus PollEvents(HdlEvent* out, uint32_t* inout_count, uint32_t timeout_ms) {
    if (!inout_count) {
        return HDL_E_INVALID_ARG;
    }
    if (!out || *inout_count == 0) {
        *inout_count = 0;
        return HDL_E_INVALID_ARG;
    }
    const uint32_t max_events = *inout_count;
    *inout_count = HealthPollEvents(out, max_events, timeout_ms);
    return HDL_OK;
}
inline HdlStatus UnloadDllCompat(uint32_t pid, const wchar_t* dll_path, int reload,
                                 uint64_t* out_base) {
    return UnloadDll(pid, dll_path, reload, 0, out_base);
}

} // namespace hdl::testapi
