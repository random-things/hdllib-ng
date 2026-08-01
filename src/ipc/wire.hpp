#pragma once

#include "protocol.hpp"

#include "hdllib/hdllib.h"

#include <cstdint>
#include <cstring>
#include <vector>

namespace hdl {
namespace proto {

/* Field-wise little-endian wire codecs for public Hdl* structs.
 * Scalars are written via AppendPod (host is LE on supported Windows builds).
 * Fixed char/wchar arrays are emitted as explicit byte runs (no struct padding). */

inline void AppendFixedChars(std::vector<uint8_t>& buf, const char* s, size_t n) {
    AppendBytes(buf, s, n);
}

inline bool TakeFixedChars(Reader& r, char* s, size_t n) {
    return r.Take(s, n);
}

inline void AppendFixedWChars(std::vector<uint8_t>& buf, const wchar_t* s, size_t n) {
    AppendBytes(buf, s, n * sizeof(wchar_t));
}

inline bool TakeFixedWChars(Reader& r, wchar_t* s, size_t n) {
    return r.Take(s, n * sizeof(wchar_t));
}

#define HDL_WIRE_POD2(T, a, b)                                                                     \
    inline void Append##T(std::vector<uint8_t>& buf, const ::T& v) {                               \
        AppendPod(buf, v.a);                                                                       \
        AppendPod(buf, v.b);                                                                       \
    }                                                                                              \
    inline bool Take##T(Reader& r, ::T& v) {                                                       \
        return r.TakePod(v.a) && r.TakePod(v.b);                                                   \
    }

#define HDL_WIRE_POD3(T, a, b, c)                                                                  \
    inline void Append##T(std::vector<uint8_t>& buf, const ::T& v) {                               \
        AppendPod(buf, v.a);                                                                       \
        AppendPod(buf, v.b);                                                                       \
        AppendPod(buf, v.c);                                                                       \
    }                                                                                              \
    inline bool Take##T(Reader& r, ::T& v) {                                                       \
        return r.TakePod(v.a) && r.TakePod(v.b) && r.TakePod(v.c);                                 \
    }

#define HDL_WIRE_POD4(T, a, b, c, d)                                                               \
    inline void Append##T(std::vector<uint8_t>& buf, const ::T& v) {                               \
        AppendPod(buf, v.a);                                                                       \
        AppendPod(buf, v.b);                                                                       \
        AppendPod(buf, v.c);                                                                       \
        AppendPod(buf, v.d);                                                                       \
    }                                                                                              \
    inline bool Take##T(Reader& r, ::T& v) {                                                       \
        return r.TakePod(v.a) && r.TakePod(v.b) && r.TakePod(v.c) && r.TakePod(v.d);               \
    }

#define HDL_WIRE_POD5(T, a, b, c, d, e)                                                            \
    inline void Append##T(std::vector<uint8_t>& buf, const ::T& v) {                               \
        AppendPod(buf, v.a);                                                                       \
        AppendPod(buf, v.b);                                                                       \
        AppendPod(buf, v.c);                                                                       \
        AppendPod(buf, v.d);                                                                       \
        AppendPod(buf, v.e);                                                                       \
    }                                                                                              \
    inline bool Take##T(Reader& r, ::T& v) {                                                       \
        return r.TakePod(v.a) && r.TakePod(v.b) && r.TakePod(v.c) && r.TakePod(v.d) &&             \
               r.TakePod(v.e);                                                                     \
    }

#define HDL_WIRE_POD6(T, a, b, c, d, e, f)                                                         \
    inline void Append##T(std::vector<uint8_t>& buf, const ::T& v) {                               \
        AppendPod(buf, v.a);                                                                       \
        AppendPod(buf, v.b);                                                                       \
        AppendPod(buf, v.c);                                                                       \
        AppendPod(buf, v.d);                                                                       \
        AppendPod(buf, v.e);                                                                       \
        AppendPod(buf, v.f);                                                                       \
    }                                                                                              \
    inline bool Take##T(Reader& r, ::T& v) {                                                       \
        return r.TakePod(v.a) && r.TakePod(v.b) && r.TakePod(v.c) && r.TakePod(v.d) &&             \
               r.TakePod(v.e) && r.TakePod(v.f);                                                   \
    }

inline void AppendHdlRegionInfo(std::vector<uint8_t>& buf, const HdlRegionInfo& v) {
    AppendPod(buf, v.base);
    AppendPod(buf, v.size);
    AppendPod(buf, v.protect);
    AppendPod(buf, v.state);
    AppendPod(buf, v.type);
    AppendPod(buf, v.reserved);
}
inline bool TakeHdlRegionInfo(Reader& r, HdlRegionInfo& v) {
    return r.TakePod(v.base) && r.TakePod(v.size) && r.TakePod(v.protect) && r.TakePod(v.state) &&
           r.TakePod(v.type) && r.TakePod(v.reserved);
}

inline void AppendHdlModuleInfo(std::vector<uint8_t>& buf, const HdlModuleInfo& v) {
    AppendPod(buf, v.base);
    AppendPod(buf, v.size);
    AppendFixedWChars(buf, v.path, sizeof(v.path) / sizeof(v.path[0]));
}
inline bool TakeHdlModuleInfo(Reader& r, HdlModuleInfo& v) {
    return r.TakePod(v.base) && r.TakePod(v.size) &&
           TakeFixedWChars(r, v.path, sizeof(v.path) / sizeof(v.path[0]));
}

inline void AppendHdlPatternResult(std::vector<uint8_t>& buf, const HdlPatternResult& v) {
    AppendPod(buf, v.match_addr);
    AppendPod(buf, v.resolved_addr);
    AppendPod(buf, v.module_base);
    AppendPod(buf, v.rva);
}
inline bool TakeHdlPatternResult(Reader& r, HdlPatternResult& v) {
    return r.TakePod(v.match_addr) && r.TakePod(v.resolved_addr) && r.TakePod(v.module_base) &&
           r.TakePod(v.rva);
}

inline void AppendHdlPointerPath(std::vector<uint8_t>& buf, const HdlPointerPath& v) {
    AppendPod(buf, v.static_base);
    AppendPod(buf, v.depth);
    AppendPod(buf, v.reserved);
    AppendBytes(buf, v.offsets, sizeof(v.offsets));
}
inline bool TakeHdlPointerPath(Reader& r, HdlPointerPath& v) {
    return r.TakePod(v.static_base) && r.TakePod(v.depth) && r.TakePod(v.reserved) &&
           r.Take(v.offsets, sizeof(v.offsets));
}

inline void AppendHdlFieldPred(std::vector<uint8_t>& buf, const HdlFieldPred& v) {
    AppendPod(buf, v.offset);
    AppendPod(buf, v.kind);
    AppendPod(buf, v.a);
    AppendPod(buf, v.b);
}
inline bool TakeHdlFieldPred(Reader& r, HdlFieldPred& v) {
    return r.TakePod(v.offset) && r.TakePod(v.kind) && r.TakePod(v.a) && r.TakePod(v.b);
}

inline void AppendHdlStructField(std::vector<uint8_t>& buf, const HdlStructField& v) {
    AppendPod(buf, v.offset);
    AppendPod(buf, v.kind);
    AppendPod(buf, v.value);
}
inline bool TakeHdlStructField(Reader& r, HdlStructField& v) {
    return r.TakePod(v.offset) && r.TakePod(v.kind) && r.TakePod(v.value);
}

inline void AppendHdlCandidate(std::vector<uint8_t>& buf, const HdlCandidate& v) {
    AppendPod(buf, v.id);
    AppendPod(buf, v.kind);
    AppendPod(buf, v.confidence);
    AppendPod(buf, v.address);
    AppendPod(buf, v.module_base);
    AppendPod(buf, v.rva);
    AppendPod(buf, v.field_offset);
    AppendPod(buf, v.flags);
    AppendFixedChars(buf, v.tag, sizeof(v.tag));
}
inline bool TakeHdlCandidate(Reader& r, HdlCandidate& v) {
    return r.TakePod(v.id) && r.TakePod(v.kind) && r.TakePod(v.confidence) &&
           r.TakePod(v.address) && r.TakePod(v.module_base) && r.TakePod(v.rva) &&
           r.TakePod(v.field_offset) && r.TakePod(v.flags) &&
           TakeFixedChars(r, v.tag, sizeof(v.tag));
}

inline void AppendHdlSynthesizedPattern(std::vector<uint8_t>& buf, const HdlSynthesizedPattern& v) {
    AppendFixedChars(buf, v.pattern, sizeof(v.pattern));
    AppendPod(buf, v.pattern_offset);
    AppendPod(buf, v.rip_disp_offset);
    AppendPod(buf, v.rip_instr_len);
    AppendPod(buf, v.match_addr);
    AppendPod(buf, v.resolved_addr);
    AppendPod(buf, v.unique_hits);
    AppendPod(buf, v.reserved);
}
inline bool TakeHdlSynthesizedPattern(Reader& r, HdlSynthesizedPattern& v) {
    return TakeFixedChars(r, v.pattern, sizeof(v.pattern)) && r.TakePod(v.pattern_offset) &&
           r.TakePod(v.rip_disp_offset) && r.TakePod(v.rip_instr_len) && r.TakePod(v.match_addr) &&
           r.TakePod(v.resolved_addr) && r.TakePod(v.unique_hits) && r.TakePod(v.reserved);
}

inline void AppendHdlHeatField(std::vector<uint8_t>& buf, const HdlHeatField& v) {
    AppendPod(buf, v.offset);
    AppendPod(buf, v.changes);
    AppendPod(buf, v.kind);
    AppendPod(buf, v.reserved);
    AppendPod(buf, v.last_value);
}
inline bool TakeHdlHeatField(Reader& r, HdlHeatField& v) {
    return r.TakePod(v.offset) && r.TakePod(v.changes) && r.TakePod(v.kind) &&
           r.TakePod(v.reserved) && r.TakePod(v.last_value);
}

inline void AppendHdlHealthInfo(std::vector<uint8_t>& buf, const HdlHealthInfo& v) {
    AppendPod(buf, v.pid);
    AppendPod(buf, v.thread_count);
    AppendPod(buf, v.handle_count);
    AppendPod(buf, v.flags);
    AppendPod(buf, v.working_set);
    AppendPod(buf, v.private_bytes);
    AppendPod(buf, v.user_time_100ns);
    AppendPod(buf, v.kernel_time_100ns);
    AppendPod(buf, v.cpu_percent);
    AppendPod(buf, v.gui_hung);
    AppendPod(buf, v.last_exception_code);
    AppendPod(buf, v.reserved);
    AppendPod(buf, v.last_exception_addr);
    AppendPod(buf, v.last_exception_tick_ms);
}
inline bool TakeHdlHealthInfo(Reader& r, HdlHealthInfo& v) {
    return r.TakePod(v.pid) && r.TakePod(v.thread_count) && r.TakePod(v.handle_count) &&
           r.TakePod(v.flags) && r.TakePod(v.working_set) && r.TakePod(v.private_bytes) &&
           r.TakePod(v.user_time_100ns) && r.TakePod(v.kernel_time_100ns) &&
           r.TakePod(v.cpu_percent) && r.TakePod(v.gui_hung) && r.TakePod(v.last_exception_code) &&
           r.TakePod(v.reserved) && r.TakePod(v.last_exception_addr) &&
           r.TakePod(v.last_exception_tick_ms);
}

inline void AppendHdlThreadInfo(std::vector<uint8_t>& buf, const HdlThreadInfo& v) {
    AppendPod(buf, v.tid);
    AppendPod(buf, v.suspend_count);
    AppendPod(buf, v.user_time_100ns);
    AppendPod(buf, v.kernel_time_100ns);
    AppendPod(buf, v.start_address);
}
inline bool TakeHdlThreadInfo(Reader& r, HdlThreadInfo& v) {
    return r.TakePod(v.tid) && r.TakePod(v.suspend_count) && r.TakePod(v.user_time_100ns) &&
           r.TakePod(v.kernel_time_100ns) && r.TakePod(v.start_address);
}

inline void AppendHdlFingerprintTag(std::vector<uint8_t>& buf, const HdlFingerprintTag& v) {
    AppendPod(buf, v.category);
    AppendPod(buf, v.confidence);
    AppendPod(buf, v.flags);
    AppendPod(buf, v.reserved);
    AppendFixedChars(buf, v.id, sizeof(v.id));
    AppendFixedChars(buf, v.evidence, sizeof(v.evidence));
}
inline bool TakeHdlFingerprintTag(Reader& r, HdlFingerprintTag& v) {
    return r.TakePod(v.category) && r.TakePod(v.confidence) && r.TakePod(v.flags) &&
           r.TakePod(v.reserved) && TakeFixedChars(r, v.id, sizeof(v.id)) &&
           TakeFixedChars(r, v.evidence, sizeof(v.evidence));
}

inline void AppendHdlEvent(std::vector<uint8_t>& buf, const HdlEvent& v) {
    AppendPod(buf, v.type);
    AppendPod(buf, v.code);
    AppendPod(buf, v.timestamp_ms);
    AppendPod(buf, v.address);
    AppendPod(buf, v.detail);
}
inline bool TakeHdlEvent(Reader& r, HdlEvent& v) {
    return r.TakePod(v.type) && r.TakePod(v.code) && r.TakePod(v.timestamp_ms) &&
           r.TakePod(v.address) && r.TakePod(v.detail);
}

inline void AppendHdlCaveInfo(std::vector<uint8_t>& buf, const HdlCaveInfo& v) {
    AppendPod(buf, v.addr);
    AppendPod(buf, v.size);
    AppendPod(buf, v.region_base);
    AppendPod(buf, v.reserved);
}
inline bool TakeHdlCaveInfo(Reader& r, HdlCaveInfo& v) {
    return r.TakePod(v.addr) && r.TakePod(v.size) && r.TakePod(v.region_base) &&
           r.TakePod(v.reserved);
}

inline void AppendHdlCallResult(std::vector<uint8_t>& buf, const HdlCallResult& v) {
    AppendPod(buf, v.return_value);
    AppendPod(buf, v.last_error);
    AppendPod(buf, v.reserved);
}
inline bool TakeHdlCallResult(Reader& r, HdlCallResult& v) {
    return r.TakePod(v.return_value) && r.TakePod(v.last_error) && r.TakePod(v.reserved);
}

inline void AppendHdlHookHit(std::vector<uint8_t>& buf, const HdlHookHit& v) {
    AppendPod(buf, v.hook_id);
    AppendPod(buf, v.timestamp_ms);
    AppendPod(buf, v.return_value);
    AppendPod(buf, v.arg_count);
    AppendPod(buf, v.frame_count);
    AppendBytes(buf, v.args, sizeof(v.args));
    AppendPod(buf, v.caller);
    AppendBytes(buf, v.frames, sizeof(v.frames));
}
inline bool TakeHdlHookHit(Reader& r, HdlHookHit& v) {
    return r.TakePod(v.hook_id) && r.TakePod(v.timestamp_ms) && r.TakePod(v.return_value) &&
           r.TakePod(v.arg_count) && r.TakePod(v.frame_count) && r.Take(v.args, sizeof(v.args)) &&
           r.TakePod(v.caller) && r.Take(v.frames, sizeof(v.frames));
}

inline void AppendHdlDisasmBackendInfo(std::vector<uint8_t>& buf, const HdlDisasmBackendInfo& v) {
    AppendPod(buf, v.id);
    AppendFixedChars(buf, v.name, sizeof(v.name));
}
inline bool TakeHdlDisasmBackendInfo(Reader& r, HdlDisasmBackendInfo& v) {
    return r.TakePod(v.id) && TakeFixedChars(r, v.name, sizeof(v.name));
}

inline void AppendHdlInsn(std::vector<uint8_t>& buf, const HdlInsn& v) {
    AppendPod(buf, v.addr);
    AppendPod(buf, v.length);
    AppendPod(buf, v.flags);
    AppendPod(buf, v.branch_target);
    AppendPod(buf, v.rip_disp_offset);
    AppendPod(buf, v.rip_disp_size);
    AppendFixedChars(buf, v.mnemonic, sizeof(v.mnemonic));
    AppendFixedChars(buf, v.op_str, sizeof(v.op_str));
}
inline bool TakeHdlInsn(Reader& r, HdlInsn& v) {
    return r.TakePod(v.addr) && r.TakePod(v.length) && r.TakePod(v.flags) &&
           r.TakePod(v.branch_target) && r.TakePod(v.rip_disp_offset) &&
           r.TakePod(v.rip_disp_size) && TakeFixedChars(r, v.mnemonic, sizeof(v.mnemonic)) &&
           TakeFixedChars(r, v.op_str, sizeof(v.op_str));
}

inline void AppendHdlStubResult(std::vector<uint8_t>& buf, const HdlStubResult& v) {
    AppendPod(buf, v.stub_va);
    AppendPod(buf, v.stolen_bytes);
    AppendPod(buf, v.code_size);
    AppendBytes(buf, v.code, sizeof(v.code));
}
inline bool TakeHdlStubResult(Reader& r, HdlStubResult& v) {
    return r.TakePod(v.stub_va) && r.TakePod(v.stolen_bytes) && r.TakePod(v.code_size) &&
           r.Take(v.code, sizeof(v.code));
}

inline void AppendHdlPatchInfo(std::vector<uint8_t>& buf, const HdlPatchInfo& v) {
    AppendPod(buf, v.handle);
    AppendPod(buf, v.addr);
    AppendPod(buf, v.size);
    AppendPod(buf, v.enabled);
    AppendFixedChars(buf, v.name, sizeof(v.name));
}
inline bool TakeHdlPatchInfo(Reader& r, HdlPatchInfo& v) {
    return r.TakePod(v.handle) && r.TakePod(v.addr) && r.TakePod(v.size) && r.TakePod(v.enabled) &&
           TakeFixedChars(r, v.name, sizeof(v.name));
}

inline void AppendHdlSectionInfo(std::vector<uint8_t>& buf, const HdlSectionInfo& v) {
    AppendFixedChars(buf, v.name, sizeof(v.name));
    AppendPod(buf, v.va);
    AppendPod(buf, v.vsize);
    AppendPod(buf, v.raw_size);
    AppendPod(buf, v.characteristics);
}
inline bool TakeHdlSectionInfo(Reader& r, HdlSectionInfo& v) {
    return TakeFixedChars(r, v.name, sizeof(v.name)) && r.TakePod(v.va) && r.TakePod(v.vsize) &&
           r.TakePod(v.raw_size) && r.TakePod(v.characteristics);
}

inline void AppendHdlExportInfo(std::vector<uint8_t>& buf, const HdlExportInfo& v) {
    AppendFixedChars(buf, v.name, sizeof(v.name));
    AppendPod(buf, v.ordinal);
    AppendPod(buf, v.forwarder);
    AppendPod(buf, v.reserved);
    AppendPod(buf, v.rva);
    AppendPod(buf, v.va);
}
inline bool TakeHdlExportInfo(Reader& r, HdlExportInfo& v) {
    return TakeFixedChars(r, v.name, sizeof(v.name)) && r.TakePod(v.ordinal) &&
           r.TakePod(v.forwarder) && r.TakePod(v.reserved) && r.TakePod(v.rva) && r.TakePod(v.va);
}

inline void AppendHdlImportInfo(std::vector<uint8_t>& buf, const HdlImportInfo& v) {
    AppendFixedChars(buf, v.module, sizeof(v.module));
    AppendFixedChars(buf, v.name, sizeof(v.name));
    AppendPod(buf, v.ordinal);
    AppendPod(buf, v.reserved);
    AppendPod(buf, v.iat_va);
    AppendPod(buf, v.bound_va);
}
inline bool TakeHdlImportInfo(Reader& r, HdlImportInfo& v) {
    return TakeFixedChars(r, v.module, sizeof(v.module)) &&
           TakeFixedChars(r, v.name, sizeof(v.name)) && r.TakePod(v.ordinal) &&
           r.TakePod(v.reserved) && r.TakePod(v.iat_va) && r.TakePod(v.bound_va);
}

inline void AppendHdlFunctionInfo(std::vector<uint8_t>& buf, const HdlFunctionInfo& v) {
    AppendPod(buf, v.start);
    AppendPod(buf, v.end);
    AppendPod(buf, v.confidence);
    AppendPod(buf, v.flags);
}
inline bool TakeHdlFunctionInfo(Reader& r, HdlFunctionInfo& v) {
    return r.TakePod(v.start) && r.TakePod(v.end) && r.TakePod(v.confidence) && r.TakePod(v.flags);
}

inline void AppendHdlXrefEdge(std::vector<uint8_t>& buf, const HdlXrefEdge& v) {
    AppendPod(buf, v.from);
    AppendPod(buf, v.to);
    AppendPod(buf, v.kind);
    AppendPod(buf, v.reserved);
}
inline bool TakeHdlXrefEdge(Reader& r, HdlXrefEdge& v) {
    return r.TakePod(v.from) && r.TakePod(v.to) && r.TakePod(v.kind) && r.TakePod(v.reserved);
}

inline void AppendHdlWatchInfo(std::vector<uint8_t>& buf, const HdlWatchInfo& v) {
    AppendPod(buf, v.handle);
    AppendPod(buf, v.addr);
    AppendPod(buf, v.size);
    AppendPod(buf, v.kind);
    AppendPod(buf, v.type);
    AppendPod(buf, v.tid);
}
inline bool TakeHdlWatchInfo(Reader& r, HdlWatchInfo& v) {
    return r.TakePod(v.handle) && r.TakePod(v.addr) && r.TakePod(v.size) && r.TakePod(v.kind) &&
           r.TakePod(v.type) && r.TakePod(v.tid);
}

inline void AppendHdlWatchHit(std::vector<uint8_t>& buf, const HdlWatchHit& v) {
    AppendPod(buf, v.watch_handle);
    AppendPod(buf, v.timestamp_ms);
    AppendPod(buf, v.tid);
    AppendPod(buf, v.access);
    AppendPod(buf, v.rip);
    AppendPod(buf, v.accessed);
    AppendPod(buf, v.size);
    AppendPod(buf, v.reserved);
}
inline bool TakeHdlWatchHit(Reader& r, HdlWatchHit& v) {
    return r.TakePod(v.watch_handle) && r.TakePod(v.timestamp_ms) && r.TakePod(v.tid) &&
           r.TakePod(v.access) && r.TakePod(v.rip) && r.TakePod(v.accessed) && r.TakePod(v.size) &&
           r.TakePod(v.reserved);
}

/* Generic dispatch used by WriteStreamed. */
template <typename T> inline void AppendWire(std::vector<uint8_t>& buf, const T& v) {
    AppendBytes(buf, &v, sizeof(T));
}

template <>
inline void AppendWire<HdlRegionInfo>(std::vector<uint8_t>& buf, const HdlRegionInfo& v) {
    AppendHdlRegionInfo(buf, v);
}
template <>
inline void AppendWire<HdlModuleInfo>(std::vector<uint8_t>& buf, const HdlModuleInfo& v) {
    AppendHdlModuleInfo(buf, v);
}
template <>
inline void AppendWire<HdlFingerprintTag>(std::vector<uint8_t>& buf, const HdlFingerprintTag& v) {
    AppendHdlFingerprintTag(buf, v);
}
template <>
inline void AppendWire<HdlThreadInfo>(std::vector<uint8_t>& buf, const HdlThreadInfo& v) {
    AppendHdlThreadInfo(buf, v);
}
template <> inline void AppendWire<HdlEvent>(std::vector<uint8_t>& buf, const HdlEvent& v) {
    AppendHdlEvent(buf, v);
}
template <>
inline void AppendWire<HdlDisasmBackendInfo>(std::vector<uint8_t>& buf,
                                             const HdlDisasmBackendInfo& v) {
    AppendHdlDisasmBackendInfo(buf, v);
}
template <> inline void AppendWire<HdlInsn>(std::vector<uint8_t>& buf, const HdlInsn& v) {
    AppendHdlInsn(buf, v);
}
template <> inline void AppendWire<HdlPatchInfo>(std::vector<uint8_t>& buf, const HdlPatchInfo& v) {
    AppendHdlPatchInfo(buf, v);
}
template <>
inline void AppendWire<HdlSectionInfo>(std::vector<uint8_t>& buf, const HdlSectionInfo& v) {
    AppendHdlSectionInfo(buf, v);
}
template <>
inline void AppendWire<HdlExportInfo>(std::vector<uint8_t>& buf, const HdlExportInfo& v) {
    AppendHdlExportInfo(buf, v);
}
template <>
inline void AppendWire<HdlImportInfo>(std::vector<uint8_t>& buf, const HdlImportInfo& v) {
    AppendHdlImportInfo(buf, v);
}
template <>
inline void AppendWire<HdlFunctionInfo>(std::vector<uint8_t>& buf, const HdlFunctionInfo& v) {
    AppendHdlFunctionInfo(buf, v);
}
template <> inline void AppendWire<HdlXrefEdge>(std::vector<uint8_t>& buf, const HdlXrefEdge& v) {
    AppendHdlXrefEdge(buf, v);
}
template <> inline void AppendWire<HdlWatchInfo>(std::vector<uint8_t>& buf, const HdlWatchInfo& v) {
    AppendHdlWatchInfo(buf, v);
}
template <> inline void AppendWire<HdlWatchHit>(std::vector<uint8_t>& buf, const HdlWatchHit& v) {
    AppendHdlWatchHit(buf, v);
}
template <> inline void AppendWire<HdlCaveInfo>(std::vector<uint8_t>& buf, const HdlCaveInfo& v) {
    AppendHdlCaveInfo(buf, v);
}
template <> inline void AppendWire<HdlHookHit>(std::vector<uint8_t>& buf, const HdlHookHit& v) {
    AppendHdlHookHit(buf, v);
}
template <>
inline void AppendWire<HdlPointerPath>(std::vector<uint8_t>& buf, const HdlPointerPath& v) {
    AppendHdlPointerPath(buf, v);
}
template <>
inline void AppendWire<HdlStructField>(std::vector<uint8_t>& buf, const HdlStructField& v) {
    AppendHdlStructField(buf, v);
}
template <> inline void AppendWire<HdlHeatField>(std::vector<uint8_t>& buf, const HdlHeatField& v) {
    AppendHdlHeatField(buf, v);
}
template <> inline void AppendWire<HdlCandidate>(std::vector<uint8_t>& buf, const HdlCandidate& v) {
    AppendHdlCandidate(buf, v);
}

#undef HDL_WIRE_POD2
#undef HDL_WIRE_POD3
#undef HDL_WIRE_POD4
#undef HDL_WIRE_POD5
#undef HDL_WIRE_POD6

} // namespace proto
} // namespace hdl
