#pragma once

#include "hdllib/hdllib.h"

namespace hdl {

struct ManagedCallResult {
    HdlCallResult result{};
    HdlStatus status = HDL_E_FAILED;
    uint64_t call_id = 0;
    uint64_t blocking_call_id = 0;
    uint32_t phase = HDL_CALL_PHASE_QUEUED;
    bool orphaned = false;
    uint32_t unacknowledged_orphan_count = 0;
};

HdlStatus ResolveExport(const wchar_t* module_or_null, const char* export_name, uint64_t* out_addr);

HdlStatus Call(const HdlCallDesc* desc, HdlCallResult* out, volatile int* cancel);
ManagedCallResult CallTracked(const HdlCallDesc* desc, volatile int* cancel);

HdlStatus CallExport(const wchar_t* module_or_null, const char* export_name, const HdlCallArg* args,
                     uint32_t arg_count, HdlCallResult* out, uint32_t timeout_ms,
                     volatile int* cancel);
ManagedCallResult CallExportTracked(const wchar_t* module_or_null, const char* export_name,
                                    const HdlCallArg* args, uint32_t arg_count, uint32_t timeout_ms,
                                    volatile int* cancel);

HdlStatus CallVtable(uint64_t obj, uint32_t index, const HdlCallArg* args, uint32_t arg_count,
                     int prepend_this, uint32_t thread_mode, HdlCallResult* out,
                     uint32_t timeout_ms, volatile int* cancel);
ManagedCallResult CallVtableTracked(uint64_t obj, uint32_t index, const HdlCallArg* args,
                                    uint32_t arg_count, int prepend_this, uint32_t thread_mode,
                                    uint32_t timeout_ms, volatile int* cancel);

} // namespace hdl
