#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <Windows.h>
#  ifdef HDL_EXPORTS
#    define HDL_API __declspec(dllexport)
#  else
#    define HDL_API __declspec(dllimport)
#  endif
#else
#  define HDL_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef int32_t HdlStatus;

enum {
    HDL_OK              = 0,
    HDL_E_INVALID_ARG   = 1,
    HDL_E_ACCESS        = 2,
    HDL_E_NOT_FOUND     = 3,
    HDL_E_NO_MEM        = 4,
    HDL_E_BUSY          = 5,
    HDL_E_FAILED        = 6,
    HDL_E_BUFFER_SMALL  = 7,
    HDL_E_CANCELLED     = 8,
    HDL_E_NOT_INIT      = 9,
    HDL_E_TIMEOUT       = 10,
};

enum {
    HDL_LOG_OFF   = 0,
    HDL_LOG_ERROR = 1,
    HDL_LOG_INFO  = 2,
    HDL_LOG_DEBUG = 3,
};

/* Remote DLL injection technique. Default / legacy = CreateRemoteThread. */
enum {
    HDL_INJECT_CREATE_REMOTE_THREAD = 0,
    HDL_INJECT_NT_CREATE_THREAD_EX  = 1,
    HDL_INJECT_RTL_CREATE_USER_THREAD = 2,
    HDL_INJECT_QUEUE_USER_APC       = 3,
    HDL_INJECT_SET_WINDOWS_HOOK_EX  = 4,
    HDL_INJECT_THREAD_HIJACK        = 5,
    HDL_INJECT_MANUAL_MAP           = 6,
    HDL_INJECT_EARLY_BIRD_APC       = 7,
    HDL_INJECT_ATOM_BOMBING         = 8,
    HDL_INJECT_MODULE_STOMP         = 9,
    HDL_INJECT_SECTION_MAP          = 10,
    HDL_INJECT_WINDOW_SUBCLASS      = 11,
    HDL_INJECT_INSTRUMENTATION_CALLBACK = 12,
    HDL_INJECT_KERNEL_CALLBACK_TABLE = 13,
    HDL_INJECT_VEH                  = 14,
    HDL_INJECT_SET_WIN_EVENT_HOOK   = 15,
    HDL_INJECT_RTL_REMOTE_CALL      = 16,
    HDL_INJECT_SPECIAL_USER_APC     = 17,
    HDL_INJECT_THREAD_POOL          = 18,
    HDL_INJECT_ETW_CALLBACK         = 19,
    /* Auto-select via HdlRecommendInject (not a technique implementation). */
    HDL_INJECT_AUTO                 = -1,
};

/* HdlInjectCandidate.flags */
enum {
    HDL_INJECT_CAND_ELIGIBLE         = 1u,
    HDL_INJECT_CAND_NEEDS_ELEVATION  = 2u,
};

typedef struct HdlTargetSpec {
    uint32_t pid; /* 0 = resolve from window title/class */
    const wchar_t* window_title_or_null;
    const wchar_t* window_class_or_null;
} HdlTargetSpec;

typedef struct HdlInjectCandidate {
    int method;
    int confidence;    /* 0..100 */
    uint32_t flags;    /* HDL_INJECT_CAND_* */
    char reasons[256]; /* semicolon-separated tags */
} HdlInjectCandidate;

typedef struct HdlRegionInfo {
    uint64_t base;
    uint64_t size;
    uint32_t protect;
    uint32_t state;
    uint32_t type;
    uint32_t reserved;
} HdlRegionInfo;

typedef struct HdlModuleInfo {
    uint64_t base;
    uint64_t size;
    wchar_t  path[260];
} HdlModuleInfo;

typedef void* HdlHookHandle;

/* Lifecycle */
HDL_API HdlStatus HdlInit(void);
HDL_API void      HdlShutdown(void);
HDL_API int       HdlIsInitialized(void);

/* Logging */
HDL_API void HdlSetLogLevel(int level);
HDL_API HdlStatus HdlSetLogFile(const wchar_t* path_or_null);

/*
 * Exception VEH backing health events. Off by default after HdlInit / inject.
 * Enable with this API or env HDL_HEALTH_VEH=1. HdlPollEvents also enables on first use.
 */
HDL_API HdlStatus HdlSetHealthVeh(int enabled);
HDL_API int       HdlIsHealthVehEnabled(void);

/* IPC */
HDL_API HdlStatus HdlStartIpc(void);
HDL_API void      HdlStopIpc(void);
HDL_API int       HdlIsIpcRunning(void);

/*
 * Inject: pid==0 => current process (LoadLibraryW; method ignored except EARLY_BIRD).
 * HDL_INJECT_EARLY_BIRD_APC: creates suspended process from exe_path (required), queues
 * APC, resumes; pid ignored; out_pid receives new PID when non-null.
 * HDL_INJECT_SET_WINDOWS_HOOK_EX: DLL must export hook_export (default "HdlHookProc").
 * HDL_INJECT_SET_WIN_EVENT_HOOK: DLL must export hook_export (default "HdlWinEventProc").
 * Returns module base via out_base when possible (may be null / truncated).
 */
HDL_API HdlStatus HdlInjectDll(uint32_t pid, const wchar_t* dll_path, uint64_t* out_base);
HDL_API HdlStatus HdlInjectDllEx(
    uint32_t pid,
    const wchar_t* dll_path,
    int method,
    const wchar_t* exe_path_or_null,
    const char* hook_export_or_null,
    uint32_t* out_pid,
    uint64_t* out_base);

/*
 * Unload a DLL that has a module-list entry (LoadLibrary / most inject methods).
 * pid==0 => current process. Manual-map / module-stomp images without a list entry
 * are not supported (HDL_E_NOT_FOUND).
 * reload!=0 => after a successful unload, LoadLibraryW the same path again;
 * *out_base receives the new base (or 0 when reload==0).
 * Unloading the module that contains the calling code in-process returns HDL_E_BUSY;
 * eject that module from another process instead.
 */
HDL_API HdlStatus HdlUnloadDll(uint32_t pid, const wchar_t* dll_path, int reload,
                               uint64_t* out_base);

/*
 * Resolve pid/hwnd from HdlTargetSpec (pid and/or window title substring / class).
 * Multiple title/class matches => HDL_E_BUSY. HWND may be null when only pid is given
 * and the process has no top-level window.
 */
HDL_API HdlStatus HdlResolveTarget(const HdlTargetSpec* spec, uint32_t* out_pid, HWND* out_hwnd);

/*
 * Rank injection methods for a target without injecting. dll_path_or_null enables
 * export probes for hook / win-event methods. On HDL_E_BUFFER_SMALL, *inout_count is
 * the required entry count (currently 20).
 */
HDL_API HdlStatus HdlRecommendInject(
    const HdlTargetSpec* spec,
    const wchar_t* dll_path_or_null,
    const char* hook_export_or_null,
    HdlInjectCandidate* out,
    uint32_t* inout_count);

/* Memory R/W (current process) */
HDL_API HdlStatus HdlReadMemory(uint64_t address, void* buffer, size_t size, size_t* bytes_read);
HDL_API HdlStatus HdlWriteMemory(uint64_t address, const void* buffer, size_t size, size_t* bytes_written);

/* Enumeration (fill buffers; on HDL_E_BUFFER_SMALL, *inout_count is required size) */
HDL_API HdlStatus HdlEnumRegions(HdlRegionInfo* out, uint32_t* inout_count);
HDL_API HdlStatus HdlEnumModules(HdlModuleInfo* out, uint32_t* inout_count);

/*
 * AOB search. pattern: "48 8B ?? ?? 90" (spaces optional, ?? or ? = wildcard).
 * If start==0 && size==0, scan all committed readable regions.
 * cancel: optional volatile int*; set nonzero to abort (returns HDL_E_CANCELLED).
 */
HDL_API HdlStatus HdlSearchMemory(
    uint64_t start,
    uint64_t size,
    const char* pattern,
    uint64_t* out_hits,
    uint32_t* inout_hit_count,
    volatile int* cancel);

/* Typed value kinds for incremental searches. */
enum {
    HDL_VALUE_BYTES   = 0,  /* AOB pattern C string (same syntax as HdlSearchMemory) */
    HDL_VALUE_I8      = 1,
    HDL_VALUE_U8      = 2,
    HDL_VALUE_I16     = 3,
    HDL_VALUE_U16     = 4,
    HDL_VALUE_I32     = 5,
    HDL_VALUE_U32     = 6,
    HDL_VALUE_I64     = 7,
    HDL_VALUE_U64     = 8,
    HDL_VALUE_F32     = 9,
    HDL_VALUE_F64     = 10,
    HDL_VALUE_STRING  = 11, /* raw narrow bytes; value_size bytes, no NUL required */
    HDL_VALUE_WSTRING = 12, /* UTF-16LE code units; value_size must be even */
};

/* Comparison modes. First scan: EXACT or UNKNOWN. Next: any except UNKNOWN. */
enum {
    HDL_CMP_EXACT        = 0, /* equals value (bit-exact for floats) */
    HDL_CMP_UNKNOWN      = 1, /* first only: record every aligned slot of the type width */
    HDL_CMP_CHANGED      = 2, /* next: != previous snapshot */
    HDL_CMP_UNCHANGED    = 3, /* next: == previous snapshot */
    HDL_CMP_INCREASED    = 4, /* next: > previous (numeric types only) */
    HDL_CMP_DECREASED    = 5, /* next: < previous (numeric types only) */
    HDL_CMP_INCREASED_BY = 6, /* next: previous + value */
    HDL_CMP_DECREASED_BY = 7, /* next: previous - value */
    HDL_CMP_GREATER      = 8, /* current > value */
    HDL_CMP_LESS         = 9, /* current < value */
};

typedef struct HdlSearchSession HdlSearchSession;

typedef struct HdlSearchDesc {
    uint64_t    start;       /* with size==0 => all committed readable regions */
    uint64_t    size;
    int32_t     value_type;  /* HDL_VALUE_* */
    int32_t     cmp;         /* HDL_CMP_* */
    uint32_t    alignment;   /* 0 = natural for type; 1 = byte-unaligned */
    uint32_t    max_results; /* 0 = default (1e6); hard stop when reached */
    const void* value;       /* typed bytes, or AOB pattern C string for BYTES */
    size_t      value_size;  /* byte length; for BYTES may be 0 (uses strlen) */
    uint32_t    flags;       /* HDL_SEARCH_* */
    const wchar_t* module_or_null; /* when HDL_SEARCH_MODULE: module basename or path */
} HdlSearchDesc;

/* HdlSearchDesc.flags / scan scope */
enum {
    HDL_SEARCH_IMAGE      = 1u, /* MEM_IMAGE regions only */
    HDL_SEARCH_EXECUTABLE = 2u, /* executable protect only */
    HDL_SEARCH_MODULE     = 4u, /* restrict to module_or_null */
};

/*
 * Incremental typed search. Create a session, HdlSearchFirst, then repeatedly
 * HdlSearchNext to narrow candidates. Snapshots of prior values are kept for
 * changed/increased/decreased comparisons.
 */
HDL_API HdlStatus HdlSearchCreate(HdlSearchSession** out_session);
HDL_API void      HdlSearchClose(HdlSearchSession* session);
HDL_API void      HdlSearchReset(HdlSearchSession* session);

HDL_API HdlStatus HdlSearchFirst(
    HdlSearchSession* session,
    const HdlSearchDesc* desc,
    volatile int* cancel);

HDL_API HdlStatus HdlSearchNext(
    HdlSearchSession* session,
    int cmp,
    const void* value,
    size_t value_size,
    volatile int* cancel);

HDL_API HdlStatus HdlSearchGetCount(const HdlSearchSession* session, uint32_t* out_count);
HDL_API HdlStatus HdlSearchGetHits(
    const HdlSearchSession* session,
    uint64_t* out_hits,
    uint32_t* inout_count);

/* ---- Locate: pattern resolve, xrefs, pointer scan, struct probe ---- */

typedef struct HdlPatternResolve {
    const char*    pattern;          /* AOB */
    uint32_t       hit_index;        /* 0-based match to use */
    int32_t        pattern_offset;   /* added to match before RIP/follow */
    uint32_t       rip_disp_offset;  /* 0 + rip_instr_len==0 => skip RIP */
    uint32_t       rip_instr_len;
    const int64_t* follow_offsets;   /* optional multilevel after RIP */
    uint32_t       follow_count;
    uint32_t       flags;            /* HDL_SEARCH_* */
    const wchar_t* module_or_null;
    uint32_t       max_scan_hits;    /* 0 = default 256 */
} HdlPatternResolve;

typedef struct HdlPatternResult {
    uint64_t match_addr;    /* raw AOB hit */
    uint64_t resolved_addr; /* after offset / RIP / follows */
    uint64_t module_base;   /* 0 if unknown */
    uint64_t rva;           /* resolved_addr - module_base when base known */
} HdlPatternResult;

HDL_API HdlStatus HdlResolvePattern(
    const HdlPatternResolve* in,
    HdlPatternResult* out,
    volatile int* cancel);

/* HdlFindStringXrefs flags */
enum {
    HDL_XREF_ABSOLUTE = 1u, /* 8-byte absolute pointer to the string */
    HDL_XREF_RIP_REL  = 2u, /* RIP-relative disp resolving to the string */
};

/*
 * Locate string bytes, then find code/data references to those addresses.
 * string_size 0 with narrow/wide C string uses strlen/wcslen.
 */
HDL_API HdlStatus HdlFindStringXrefs(
    const void* string,
    size_t string_size,
    int is_wide,
    uint32_t xref_flags,
    uint32_t search_flags,
    const wchar_t* module_or_null,
    uint64_t* out_xrefs,
    uint32_t* inout_count,
    volatile int* cancel);

typedef struct HdlPointerPath {
    uint64_t static_base; /* address of the first pointer in static/image memory */
    uint32_t depth;       /* number of offsets used */
    uint32_t reserved;
    int32_t  offsets[8];  /* after each deref, add offsets[i]; final points at target */
} HdlPointerPath;

/*
 * CE-style pointer scan: find static paths that reach target_addr with
 * per-level offsets in [0, max_offset]. Typically use HDL_SEARCH_IMAGE.
 */
HDL_API HdlStatus HdlPointerScan(
    uint64_t target_addr,
    uint32_t max_depth,
    uint32_t max_offset,
    uint32_t max_results,
    uint32_t search_flags,
    const wchar_t* module_or_null,
    HdlPointerPath* out,
    uint32_t* inout_count,
    volatile int* cancel);

/* HdlStructField.kind */
enum {
    HDL_FIELD_UNKNOWN = 0,
    HDL_FIELD_PTR     = 1,
    HDL_FIELD_VTABLE  = 2, /* pointer into executable image */
    HDL_FIELD_ASCII   = 3,
    HDL_FIELD_FLOAT   = 4,
    HDL_FIELD_INT32   = 5,
    HDL_FIELD_INT64   = 6,
};

typedef struct HdlStructField {
    uint32_t offset;
    uint32_t kind;
    uint64_t value;
} HdlStructField;

/* Heuristic field classification over [addr, addr+size). size capped at 4096. */
HDL_API HdlStatus HdlProbeStruct(
    uint64_t addr,
    uint32_t size,
    HdlStructField* out,
    uint32_t* inout_count);

/* ---- Discover: automated find / stabilize / expand ---- */

enum {
    HDL_CAND_ADDRESS  = 1,
    HDL_CAND_FUNCTION = 2,
    HDL_CAND_OBJECT   = 3,
    HDL_CAND_FIELD    = 4,
};

typedef struct HdlCandidate {
    uint64_t id;
    uint32_t kind;       /* HDL_CAND_* */
    uint32_t confidence; /* 0..100 */
    uint64_t address;
    uint64_t module_base;
    uint64_t rva;
    uint32_t field_offset; /* HDL_CAND_FIELD */
    uint32_t flags;
    char     tag[48];
} HdlCandidate;

typedef struct HdlSynthesizedPattern {
    char     pattern[192]; /* AOB text with optional ?? wildcards */
    int32_t  pattern_offset; /* bytes from match to original address */
    uint32_t rip_disp_offset;
    uint32_t rip_instr_len;
    uint64_t match_addr;
    uint64_t resolved_addr;
    uint32_t unique_hits; /* matches of pattern in scan scope */
    uint32_t reserved;
} HdlSynthesizedPattern;

/* Structure-aware field predicates (relative to a candidate object base). */
enum {
    HDL_PRED_EQ_I32    = 1, /* *(i32*)(base+off) == (i32)a */
    HDL_PRED_EQ_F32    = 2, /* bit-exact f32; a holds IEEE bits in low 32 */
    HDL_PRED_RANGE_I32 = 3, /* a <= i32 <= b */
    HDL_PRED_LE_I32    = 4, /* i32(off) <= i32(off + (int32_t)a) */
    HDL_PRED_PTR       = 5, /* readable pointer */
    HDL_PRED_VTABLE    = 6, /* pointer into executable memory */
    HDL_PRED_EQ_U64    = 7, /* *(u64*)(base+off) == (u64)a */
};

typedef struct HdlFieldPred {
    int32_t offset;
    int32_t kind; /* HDL_PRED_* */
    int64_t a;
    int64_t b;
} HdlFieldPred;

typedef struct HdlHeatField {
    uint32_t offset;
    uint32_t changes; /* times the slot differed across action snapshots */
    uint32_t kind;    /* HDL_FIELD_* when classifiable */
    uint32_t reserved; /* repurposed as slot size in bytes (1/2/4/8) */
    uint64_t last_value;
} HdlHeatField;

typedef struct HdlDiscoverSession HdlDiscoverSession;

HDL_API HdlStatus HdlDiscoverCreate(HdlDiscoverSession** out_session);
HDL_API void      HdlDiscoverClose(HdlDiscoverSession* session);

/* Manually seed a candidate. tag may be null. out_id optional. */
HDL_API HdlStatus HdlDiscoverAddCandidate(
    HdlDiscoverSession* session,
    uint32_t kind,
    uint64_t address,
    const char* tag_or_null,
    uint64_t* out_id);

/*
 * Typed exact scan; each hit becomes an HDL_CAND_ADDRESS (tag applied).
 * desc.cmp should be HDL_CMP_EXACT (or UNKNOWN for all slots — not recommended).
 */
HDL_API HdlStatus HdlDiscoverScanValue(
    HdlDiscoverSession* session,
    const HdlSearchDesc* desc,
    const char* tag_or_null,
    volatile int* cancel);

/*
 * Find object bases of object_size where every predicate holds.
 * Adds HDL_CAND_OBJECT candidates. object_size capped at 4096; alignment 8.
 */
HDL_API HdlStatus HdlDiscoverConstraintScan(
    HdlDiscoverSession* session,
    uint32_t object_size,
    const HdlFieldPred* preds,
    uint32_t pred_count,
    uint32_t search_flags,
    const wchar_t* module_or_null,
    uint32_t max_results,
    const char* tag_or_null,
    volatile int* cancel);

/*
 * Build a module-unique AOB for cand_id's address. window_before/after bound the
 * bytes considered (each capped at 64). Prefer HDL_SEARCH_MODULE|IMAGE.
 */
HDL_API HdlStatus HdlDiscoverSynthesizePattern(
    HdlDiscoverSession* session,
    uint64_t cand_id,
    uint32_t window_before,
    uint32_t window_after,
    uint32_t search_flags,
    const wchar_t* module_or_null,
    HdlSynthesizedPattern* out,
    volatile int* cancel);

/*
 * Pointer-scan then keep only paths that still resolve to target_addr.
 * validate_rounds>=2 re-scans after each validate using the same target (useful
 * when the caller mutates memory between IPC round-trips via PathScan/PathValidate).
 * For a one-shot filter of an existing list, use HdlDiscoverPathValidate.
 */
HDL_API HdlStatus HdlDiscoverPathConsensus(
    uint64_t target_addr,
    uint32_t max_depth,
    uint32_t max_offset,
    uint32_t max_results,
    uint32_t search_flags,
    const wchar_t* module_or_null,
    HdlPointerPath* out,
    uint32_t* inout_count,
    volatile int* cancel);

/* Drop paths that do not currently resolve to expected_target. Compacts in place. */
HDL_API HdlStatus HdlDiscoverPathValidate(
    HdlPointerPath* paths,
    uint32_t* inout_count,
    uint64_t expected_target);

/* HookTrace watch; callers during actions are ranked as functions. */
HDL_API HdlStatus HdlDiscoverWatch(HdlDiscoverSession* session, uint64_t fn_addr, uint32_t arg_count);
HDL_API HdlStatus HdlDiscoverWatchImport(
    HdlDiscoverSession* session,
    const wchar_t* module_or_null,
    const char* dll_name,
    const char* import_name,
    uint32_t arg_count);
HDL_API HdlStatus HdlDiscoverUnwatchAll(HdlDiscoverSession* session);

/*
 * Action window: drains/associates hook hits and diffs watched regions.
 * name max 47 chars; Begin fails if another action is open.
 */
HDL_API HdlStatus HdlDiscoverActionBegin(HdlDiscoverSession* session, const char* name);
HDL_API HdlStatus HdlDiscoverActionEnd(HdlDiscoverSession* session);

/* Register [base, base+size) for change-heat across the next action window. */
HDL_API HdlStatus HdlDiscoverWatchRegion(
    HdlDiscoverSession* session,
    uint64_t base,
    uint32_t size);

HDL_API HdlStatus HdlDiscoverGetHeat(
    HdlDiscoverSession* session,
    uint64_t base,
    HdlHeatField* out,
    uint32_t* inout_count);

/*
 * Rank functions seen during a named action (frame-weighted by default).
 * Adds HDL_CAND_FUNCTION candidates. out optional snapshot of ranking.
 */
enum { HDL_RANK_CALLER_ONLY = 1u };

HDL_API HdlStatus HdlDiscoverRankFunctions(
    HdlDiscoverSession* session,
    const char* action_name,
    uint32_t flags,
    HdlCandidate* out,
    uint32_t* inout_count);

HDL_API HdlStatus HdlDiscoverResetHeat(HdlDiscoverSession* session, uint64_t base);

HDL_API HdlStatus HdlDiscoverDiffObjects(
    HdlDiscoverSession* session,
    const uint64_t* addrs,
    uint32_t count,
    uint32_t max_size,
    HdlHeatField* out,
    uint32_t* inout_count);

HDL_API HdlStatus HdlDiscoverApplyWatchHits(
    HdlDiscoverSession* session,
    uint64_t object_base,
    uint32_t size);

HDL_API HdlStatus HdlDiscoverGetCandidateEvidence(
    HdlDiscoverSession* session,
    uint64_t cand_id,
    char* buf,
    uint32_t cap);

/* UTF-8 JSON export (max 4 MiB): candidates, evidence, heat, action names. */
HDL_API HdlStatus HdlDiscoverExport(
    HdlDiscoverSession* session,
    char* buf,
    uint32_t* inout_size);

/* Best-effort import: AddCandidate for each candidate in JSON. */
HDL_API HdlStatus HdlDiscoverImport(
    HdlDiscoverSession* session,
    const char* json,
    uint32_t size);

/*
 * Find other bases with the same vtable pointer (offset 0) and compatible size.
 * seed must look like an object with a vtable. Adds HDL_CAND_OBJECT candidates.
 */
HDL_API HdlStatus HdlDiscoverClusterType(
    HdlDiscoverSession* session,
    uint64_t seed_addr,
    uint32_t object_size,
    uint32_t search_flags,
    const wchar_t* module_or_null,
    uint32_t max_results,
    volatile int* cancel);

HDL_API HdlStatus HdlDiscoverGetCandidates(
    HdlDiscoverSession* session,
    HdlCandidate* out,
    uint32_t* inout_count);

/* ---- Process / thread health ---- */

/* HdlHealthInfo.flags */
enum {
    HDL_HEALTH_OK               = 0,
    HDL_HEALTH_GUI_HUNG         = 1u,
    HDL_HEALTH_HIGH_CPU         = 2u,
    HDL_HEALTH_RECENT_EXCEPTION = 4u,
};

typedef struct HdlHealthInfo {
    uint32_t pid;
    uint32_t thread_count;
    uint32_t handle_count;
    uint32_t flags;          /* HDL_HEALTH_* */
    uint64_t working_set;
    uint64_t private_bytes;
    uint64_t user_time_100ns;
    uint64_t kernel_time_100ns;
    uint32_t cpu_percent;    /* recent sample 0..100 (best-effort) */
    uint32_t gui_hung;       /* 1 if a top-level window looks hung */
    uint32_t last_exception_code;
    uint32_t reserved;
    uint64_t last_exception_addr;
    uint64_t last_exception_tick_ms;
} HdlHealthInfo;

typedef struct HdlThreadInfo {
    uint32_t tid;
    uint32_t suspend_count;
    uint64_t user_time_100ns;
    uint64_t kernel_time_100ns;
    uint64_t start_address; /* best-effort; 0 if unknown */
} HdlThreadInfo;

HDL_API HdlStatus HdlGetHealth(HdlHealthInfo* out);
HDL_API HdlStatus HdlEnumThreads(HdlThreadInfo* out, uint32_t* inout_count);

/* ---- Process fingerprint (passive module / import / PE signals) ---- */

/* HdlFingerprintTag.category */
enum {
    HDL_FP_CAT_LANGUAGE  = 1,
    HDL_FP_CAT_RUNTIME   = 2,
    HDL_FP_CAT_TOOLCHAIN = 3,
    HDL_FP_CAT_UI        = 4,
    HDL_FP_CAT_GRAPHICS  = 5,
    HDL_FP_CAT_ENGINE    = 6,
    HDL_FP_CAT_WEBHOST   = 7,
    HDL_FP_CAT_AUDIO     = 8,
    HDL_FP_CAT_NETWORK   = 9,
    HDL_FP_CAT_TOOLING   = 10,
    HDL_FP_CAT_APP       = 11, /* subsystem / packaging hints */
};

/* HdlFingerprintTag.flags */
enum {
    HDL_FP_FROM_MODULE = 1u,
    HDL_FP_FROM_IMPORT = 2u,
    HDL_FP_FROM_PE     = 4u,
    HDL_FP_PRIMARY     = 8u, /* best-in-category */
};

/* HdlEnumFingerprintTags / HdlClassifyFingerprint scan_flags */
enum {
    HDL_FP_SCAN_MODULES = 1u,
    HDL_FP_SCAN_IMPORTS = 2u,
    HDL_FP_SCAN_PE      = 4u,
    HDL_FP_SCAN_DEFAULT = HDL_FP_SCAN_MODULES | HDL_FP_SCAN_IMPORTS | HDL_FP_SCAN_PE,
    /* HDL_FP_ACTIVE = 8u reserved for future active probes */
};

typedef struct HdlFingerprintTag {
    uint32_t category;     /* HDL_FP_CAT_* */
    uint32_t confidence;   /* 0..100 */
    uint32_t flags;        /* HDL_FP_* */
    uint32_t reserved;
    char     id[48];       /* e.g. "d3d11", "coreclr", "qt6" */
    char     evidence[192];/* "module:d3d11.dll; import:D3D11CreateDevice" */
} HdlFingerprintTag;

typedef struct HdlFingerprintImport {
    char module[64];
    char name[128];
} HdlFingerprintImport;

/*
 * Passive fingerprint of the current process (loaded modules + main IAT + PE subsystem).
 * Classic size-query: out==nullptr or too small => HDL_E_BUFFER_SMALL + needed count.
 */
HDL_API HdlStatus HdlEnumFingerprintTags(
    uint32_t scan_flags,
    HdlFingerprintTag* out,
    uint32_t* inout_count);

/*
 * Classify from caller-provided signals (no process walk). Useful for tests and offline dumps.
 * pe_subsystem: IMAGE_SUBSYSTEM_* (0 = unknown / skip PE rules unless SCAN_PE cleared).
 */
HDL_API HdlStatus HdlClassifyFingerprint(
    const wchar_t* const* module_basenames,
    uint32_t module_count,
    const HdlFingerprintImport* imports,
    uint32_t import_count,
    uint16_t pe_subsystem,
    uint32_t scan_flags,
    HdlFingerprintTag* out,
    uint32_t* inout_count);

/* ---- Events (exception / health notifications) ---- */

enum {
    HDL_EVENT_EXCEPTION = 1,
    HDL_EVENT_HEALTH    = 2,
    HDL_EVENT_JOB_DONE  = 3,
    HDL_EVENT_HOOK      = 4, /* wake-up; full payload via HdlPollHookHits */
    HDL_EVENT_WATCH     = 5, /* hardware / page watchpoint hit */
};

typedef struct HdlEvent {
    uint32_t type;           /* HDL_EVENT_* */
    uint32_t code;           /* exception code, health flags, or job status */
    uint64_t timestamp_ms;
    uint64_t address;        /* exception address or job id */
    uint64_t detail;         /* reserved / extra */
} HdlEvent;

/*
 * Drain queued events. Blocks up to timeout_ms (0 = non-blocking) until at least
 * one event is available or the timeout elapses (OK with *inout_count==0).
 */
HDL_API HdlStatus HdlPollEvents(HdlEvent* out, uint32_t* inout_count, uint32_t timeout_ms);

/* ---- Cooperative jobs (cancel / timeout across clients) ---- */

HDL_API HdlStatus HdlJobCreate(uint32_t timeout_ms, uint64_t* out_job_id);
HDL_API HdlStatus HdlJobCancel(uint64_t job_id);
HDL_API void      HdlJobClose(uint64_t job_id);

/* ---- Durable in-process allocation ---- */

HDL_API HdlStatus HdlAlloc(size_t size, uint32_t protect /* PAGE_* */, uint64_t* out_addr);
HDL_API HdlStatus HdlAllocNear(
    uint64_t near_addr,
    uint64_t max_distance,
    size_t size,
    uint32_t protect /* PAGE_* */,
    uint64_t* out_addr);
HDL_API HdlStatus HdlFree(uint64_t addr);

/* ---- Place: caves, protect, icache ---- */

typedef struct HdlCaveInfo {
    uint64_t addr;
    uint64_t size;
    uint64_t region_base;
    uint32_t reserved;
} HdlCaveInfo;

typedef struct HdlCaveQuery {
    uint32_t min_size;
    uint32_t fill_byte;      /* byte value to match (e.g. 0xCC or 0x00) */
    uint32_t search_flags;   /* HDL_SEARCH_* */
    uint32_t max_results;    /* 0 = default 4096 */
    uint64_t near_addr;      /* 0 = no proximity filter */
    uint64_t max_distance;   /* used when near_addr != 0; 0 => 0x7FFFFFFF (RIP-rel range) */
    const wchar_t* module_or_null;
} HdlCaveQuery;

HDL_API HdlStatus HdlFindCaves(
    const HdlCaveQuery* query,
    HdlCaveInfo* out,
    uint32_t* inout_count,
    volatile int* cancel);

HDL_API HdlStatus HdlProtectMemory(uint64_t addr, size_t size, uint32_t protect, uint32_t* out_old);
HDL_API HdlStatus HdlFlushICache(uint64_t addr, size_t size);

/* ---- Address resolution helpers ---- */

/*
 * RIP-relative: *out = addr + instr_len + *(int32_t*)(addr + disp_offset).
 * Typical LEA/CALL/JMP: disp_offset=3, instr_len=7 (or disp_offset=1, instr_len=5 for call/jmp).
 */
HDL_API HdlStatus HdlResolveRipRelative(
    uint64_t addr,
    uint32_t disp_offset,
    uint32_t instr_len,
    uint64_t* out_addr);

/* Multilevel pointer: start at base, then repeatedly read ptr and add offsets[i]. */
HDL_API HdlStatus HdlFollowPointers(
    uint64_t base,
    const int64_t* offsets,
    uint32_t offset_count,
    uint64_t* out_addr);

HDL_API HdlStatus HdlModuleBase(const wchar_t* module_or_null, uint64_t* out_base);

/* ---- In-process call (exports / absolute / vtable) ---- */

enum {
    HDL_CALL_ARG_U64  = 0,
    HDL_CALL_ARG_I64  = 1,
    HDL_CALL_ARG_PTR  = 2, /* ptr: pointer value passed as arg (buffer not copied) */
    HDL_CALL_ARG_BUF  = 3, /* ptr + size: copy-in, pass temp ptr, copy-out on success */
    HDL_CALL_ARG_CSTR = 4, /* NUL-terminated narrow; copied */
    HDL_CALL_ARG_WSTR = 5, /* NUL-terminated wide; copied */
    HDL_CALL_ARG_F32  = 6, /* u64 holds IEEE-754 bits in low 32 */
    HDL_CALL_ARG_F64  = 7, /* u64 holds IEEE-754 bits */
};

enum {
    HDL_CALL_THREAD_WORKER = 0, /* run on a helper thread (default) */
    HDL_CALL_THREAD_MAIN   = 1, /* sync run on primary UI thread; fails if no HWND */
};

typedef struct HdlCallArg {
    int32_t     kind; /* HDL_CALL_ARG_* */
    uint32_t    size; /* BUF byte length; ignored for U64/I64/CSTR/WSTR/F32/F64 */
    uint64_t    u64;  /* U64/I64/F32/F64 value, or ignored */
    const void* ptr;  /* PTR/BUF/CSTR/WSTR; BUF may be written back (inout) */
} HdlCallArg;

typedef struct HdlCallResult {
    uint64_t return_value;
    uint32_t last_error; /* GetLastError after the call */
    uint32_t reserved;
} HdlCallResult;

typedef struct HdlCallDesc {
    uint64_t          address;     /* absolute function address */
    const HdlCallArg* args;
    uint32_t          arg_count;   /* 0..16 */
    uint32_t          thread_mode; /* HDL_CALL_THREAD_* */
    uint32_t          timeout_ms;  /* 0 = wait forever */
    uint32_t          reserved;
} HdlCallDesc;

HDL_API HdlStatus HdlResolveExport(
    const wchar_t* module_or_null,
    const char* export_name,
    uint64_t* out_addr);

/*
 * Invoke an absolute address with up to 16 args (Microsoft x64 ABI, including floats).
 * On HDL_E_TIMEOUT / HDL_E_CANCELLED the callee may still be running.
 * BUF args are copied back into the caller's buffer on success.
 */
HDL_API HdlStatus HdlCall(const HdlCallDesc* desc, HdlCallResult* out, volatile int* cancel);

/*
 * Resolve export then HdlCall (thread_mode = WORKER).
 * module_or_null: NULL/empty => main EXE; otherwise LoadLibrary/GetModuleHandle name.
 */
HDL_API HdlStatus HdlCallExport(
    const wchar_t* module_or_null,
    const char* export_name,
    const HdlCallArg* args,
    uint32_t arg_count,
    HdlCallResult* out,
    uint32_t timeout_ms,
    volatile int* cancel);

/*
 * Read vtable from *obj, take slot index, then HdlCall.
 * If arg_count==0 or args[0] is not the object, a synthetic this (PTR to obj) is prepended
 * when prepend_this != 0. When prepend_this==0, args are passed as-is (caller supplies this).
 */
HDL_API HdlStatus HdlCallVtable(
    uint64_t obj,
    uint32_t index,
    const HdlCallArg* args,
    uint32_t arg_count,
    int prepend_this,
    uint32_t thread_mode,
    HdlCallResult* out,
    uint32_t timeout_ms,
    volatile int* cancel);

/* ---- Hooks (MinHook) ---- */

/* Custom detour; trampoline receives original if non-null. */
HDL_API HdlStatus HdlHook(void* target, void* detour, void** trampoline, HdlHookHandle* out_handle);
HDL_API HdlStatus HdlEnableHook(HdlHookHandle handle, int enable);
HDL_API HdlStatus HdlUnhook(HdlHookHandle handle);

/*
 * Install a capture-only hook: calls original, records up to 8 integer-view args + return
 * into the hook-hit queue (also wakes PollEvents with HDL_EVENT_HOOK).
 */
HDL_API HdlStatus HdlHookTrace(uint64_t target, uint32_t arg_count /* 0..8 */, HdlHookHandle* out);

HDL_API HdlStatus HdlHookImport(
    const wchar_t* module_or_null,
    const char* dll_name,
    const char* import_name,
    uint32_t arg_count,
    HdlHookHandle* out);

enum { HDL_HOOK_MAX_FRAMES = 8 };

typedef struct HdlHookHit {
    uint64_t hook_id; /* target address (same as HdlHookHandle value) */
    uint64_t timestamp_ms;
    uint64_t return_value;
    uint32_t arg_count;
    uint32_t frame_count; /* 0..HDL_HOOK_MAX_FRAMES */
    uint64_t args[8];
    uint64_t caller; /* return address into the calling code (0 if unknown) */
    uint64_t frames[HDL_HOOK_MAX_FRAMES]; /* stack frames (best-effort) */
} HdlHookHit;

HDL_API HdlStatus HdlPollHookHits(HdlHookHit* out, uint32_t* inout_count, uint32_t timeout_ms);

/*
 * Default SetWindowsHookEx callback exported by hdllib. Arbitrary inject targets should
 * export an equivalent LRESULT CALLBACK(int, WPARAM, LPARAM) that calls CallNextHookEx.
 */
HDL_API LRESULT CALLBACK HdlHookProc(int code, WPARAM wParam, LPARAM lParam);

/* Default SetWinEventHook (WINEVENT_INCONTEXT) callback. */
HDL_API void CALLBACK HdlWinEventProc(HWINEVENTHOOK hook, DWORD event, HWND hwnd, LONG id_object,
                                      LONG id_child, DWORD event_thread, DWORD event_time);

/* ---- Disasm backends (pluggable) ---- */

enum {
    HDL_DISASM_ZYDIS    = 1,
    HDL_DISASM_CAPSTONE = 2,
    HDL_DISASM_CUSTOM_BASE = 1000, /* external registrations use this range */
};

typedef struct HdlDisasmBackendInfo {
    int32_t id;
    char    name[32];
} HdlDisasmBackendInfo;

/*
 * Decode one instruction. Returns HDL_OK and fills out_*.
 * length is required; other outs optional.
 */
typedef HdlStatus (*HdlDisasmDecodeFn)(
    void* user,
    uint64_t va,
    const uint8_t* bytes,
    size_t len,
    uint32_t* out_length,
    char* out_mnemonic,      /* may be null; capacity mnemonic_cap */
    size_t mnemonic_cap,
    char* out_op_str,        /* may be null; capacity op_cap */
    size_t op_cap,
    uint32_t* out_flags,     /* HDL_INSN_* */
    uint64_t* out_branch,    /* branch/call target if known */
    int32_t* out_rip_disp_off, /* byte offset of rip-rel disp in insn, or -1 */
    uint32_t* out_rip_disp_size /* 4 typically; 0 if none */);

typedef struct HdlDisasmBackendFns {
    const char* name;
    HdlDisasmDecodeFn decode;
    void* user;
} HdlDisasmBackendFns;

enum {
    HDL_INSN_CALL    = 1u,
    HDL_INSN_JMP     = 2u,
    HDL_INSN_RET     = 4u,
    HDL_INSN_RIP_REL = 8u,
    HDL_INSN_BRANCH  = 16u, /* has resolvable branch/call target in out_branch */
};

HDL_API HdlStatus HdlDisasmEnumBackends(HdlDisasmBackendInfo* out, uint32_t* inout_count);
HDL_API HdlStatus HdlDisasmGetBackend(int32_t* out_id);
HDL_API HdlStatus HdlDisasmSetBackend(int32_t id);
HDL_API HdlStatus HdlDisasmRegisterBackend(const HdlDisasmBackendFns* fns, int32_t* out_id);
HDL_API HdlStatus HdlDisasmUnregisterBackend(int32_t id);

typedef struct HdlInsn {
    uint64_t addr;
    uint32_t length;
    uint32_t flags; /* HDL_INSN_* */
    uint64_t branch_target;
    int32_t  rip_disp_offset; /* -1 if none */
    uint32_t rip_disp_size;
    char     mnemonic[32];
    char     op_str[96];
} HdlInsn;

HDL_API HdlStatus HdlInstrLen(uint64_t addr, uint32_t* out_len);
HDL_API HdlStatus HdlDisasm(uint64_t addr, uint32_t max_insns, HdlInsn* out, uint32_t* inout_count);

enum {
    HDL_STUB_ABS_JMP    = 1, /* FF 25 / mov rax; jmp rax style absolute */
    HDL_STUB_REL_JMP32  = 2, /* E9 rel32 (requires destination in ±2GB) */
    HDL_STUB_MOV_RAX_JMP = 3, /* 48 B8 imm64; FF E0 */
    HDL_STUB_RAW        = 4, /* caller-supplied bytes */
};

typedef struct HdlStubDesc {
    int32_t     kind; /* HDL_STUB_* */
    uint32_t    flags;
    uint64_t    target;       /* jump/call destination for non-RAW */
    uint64_t    steal_from;   /* 0 = no steal; else copy insns from here until steal_min_bytes */
    uint32_t    steal_min_bytes;
    uint32_t    reserved;
    const uint8_t* raw;       /* HDL_STUB_RAW */
    uint32_t    raw_size;
    uint32_t    alloc_rx;     /* nonzero => allocate RX stub; out_stub_va set */
} HdlStubDesc;

typedef struct HdlStubResult {
    uint64_t stub_va;     /* allocated VA when alloc_rx; else 0 */
    uint32_t stolen_bytes;
    uint32_t code_size;
    uint8_t  code[256];
} HdlStubResult;

HDL_API HdlStatus HdlBuildStub(const HdlStubDesc* desc, HdlStubResult* out);

/* Patch ledger */
typedef uint64_t HdlPatchHandle;

HDL_API HdlStatus HdlPatchCreate(
    uint64_t addr,
    const void* bytes,
    size_t size,
    const char* name_or_null,
    HdlPatchHandle* out);
HDL_API HdlStatus HdlPatchEnable(HdlPatchHandle handle, int enable);
HDL_API HdlStatus HdlPatchRemove(HdlPatchHandle handle);

typedef struct HdlPatchInfo {
    uint64_t handle;
    uint64_t addr;
    uint32_t size;
    uint32_t enabled;
    char     name[48];
} HdlPatchInfo;

HDL_API HdlStatus HdlPatchEnum(HdlPatchInfo* out, uint32_t* inout_count);

/* ---- PE metadata ---- */

typedef struct HdlSectionInfo {
    char     name[16];
    uint64_t va;
    uint64_t vsize;
    uint32_t raw_size;
    uint32_t characteristics;
} HdlSectionInfo;

typedef struct HdlExportInfo {
    char     name[128];
    uint32_t ordinal;
    uint32_t forwarder; /* 1 if forwarded */
    uint32_t reserved;
    uint64_t rva;
    uint64_t va;
} HdlExportInfo;

typedef struct HdlImportInfo {
    char     module[64];
    char     name[128];
    uint32_t ordinal; /* if name empty */
    uint32_t reserved;
    uint64_t iat_va;
    uint64_t bound_va; /* current IAT value */
} HdlImportInfo;

HDL_API HdlStatus HdlEnumSections(uint64_t module_base_or_0, HdlSectionInfo* out, uint32_t* inout_count);
HDL_API HdlStatus HdlEnumExports(uint64_t module_base_or_0, HdlExportInfo* out, uint32_t* inout_count);
HDL_API HdlStatus HdlEnumImports(uint64_t module_base_or_0, HdlImportInfo* out, uint32_t* inout_count);

/* ---- Bounded functions / xrefs ---- */

typedef struct HdlFunctionInfo {
    uint64_t start;
    uint64_t end; /* 0 if unknown */
    uint32_t confidence; /* 0..100 */
    uint32_t flags;
} HdlFunctionInfo;

enum {
    HDL_XREF_CALL = 1,
    HDL_XREF_JMP  = 2,
    HDL_XREF_DATA = 4,
    HDL_XREF_FUNC = 8, /* XrefsTo: match branches into [fn.start, fn.end) */
};

/* HdlFunctionInfo.flags */
enum {
    HDL_FN_EXPORT   = 1u,
    HDL_FN_CALLED   = 2u,
    HDL_FN_PROLOGUE = 4u,
};

typedef struct HdlXrefEdge {
    uint64_t from;
    uint64_t to;
    uint32_t kind; /* HDL_XREF_* */
    uint32_t reserved;
} HdlXrefEdge;

HDL_API HdlStatus HdlEnumFunctions(
    uint64_t start,
    uint64_t size,
    uint32_t search_flags,
    const wchar_t* module_or_null,
    uint32_t max_results,
    HdlFunctionInfo* out,
    uint32_t* inout_count,
    volatile int* cancel);

HDL_API HdlStatus HdlXrefsFrom(
    uint64_t seed,
    uint32_t max_depth,
    uint32_t max_nodes,
    uint32_t kinds, /* HDL_XREF_* mask; 0 = call|jmp */
    HdlXrefEdge* out,
    uint32_t* inout_count,
    volatile int* cancel);

/*
 * Map addr into a function from EnumFunctions for the owning module (or given
 * module_or_null). out->end may be 0 if unknown.
 */
HDL_API HdlStatus HdlResolveFunction(
    uint64_t addr,
    uint32_t search_flags,
    const wchar_t* module_or_null,
    HdlFunctionInfo* out,
    volatile int* cancel);

/*
 * Find call/jmp (and optional DATA) sites that target `target`. With HDL_XREF_FUNC
 * also match branches into the resolved function body containing target.
 */
HDL_API HdlStatus HdlXrefsTo(
    uint64_t target,
    uint32_t max_nodes,
    uint32_t kinds,
    uint32_t search_flags,
    const wchar_t* module_or_null,
    HdlXrefEdge* out,
    uint32_t* inout_count,
    volatile int* cancel);

/* Drop cached EnumFunctions index for module (null = all). */
HDL_API HdlStatus HdlInvalidateFunctionIndex(const wchar_t* module_or_null);

/* ---- Vtable / RTTI ---- */

HDL_API HdlStatus HdlWalkVtable(uint64_t obj_or_vtable, int is_object, uint64_t* out_slots,
                                uint32_t* inout_count);
HDL_API HdlStatus HdlQueryRttiName(uint64_t obj_or_vtable, int is_object, char* out_name,
                                   uint32_t name_cap);

/* ---- Watchpoints ---- */

enum {
    HDL_WATCH_HW_EXEC = 1,
    HDL_WATCH_HW_WRITE = 2,
    HDL_WATCH_HW_RW = 3,
};

enum {
    HDL_WATCH_PAGE_GUARD = 1,
    HDL_WATCH_PAGE_NOACCESS = 2,
};

typedef uint64_t HdlWatchHandle;

typedef struct HdlWatchInfo {
    uint64_t handle;
    uint64_t addr;
    uint32_t size;
    uint32_t kind; /* HW_* or PAGE_* in high bit? use type field */
    uint32_t type; /* 1=hw 2=page */
    uint32_t tid;  /* 0 = all / process */
} HdlWatchInfo;

HDL_API HdlStatus HdlWatchHw(
    uint64_t addr,
    uint32_t size, /* 1,2,4,8 */
    uint32_t access, /* HDL_WATCH_HW_* */
    uint32_t tid, /* 0 = current / best-effort all */
    HdlWatchHandle* out);
HDL_API HdlStatus HdlWatchPage(uint64_t addr, size_t size, uint32_t mode, HdlWatchHandle* out);
HDL_API HdlStatus HdlUnwatch(HdlWatchHandle handle);
HDL_API HdlStatus HdlEnumWatches(HdlWatchInfo* out, uint32_t* inout_count);

/* Re-apply all HW watches to current process threads. */
HDL_API HdlStatus HdlWatchRefresh(void);

typedef struct HdlWatchHit {
    uint64_t watch_handle;
    uint64_t timestamp_ms;
    uint32_t tid;
    uint32_t access;   /* HDL_WATCH_HW_* or page mode */
    uint64_t rip;      /* ExceptionAddress */
    uint64_t accessed; /* fault VA when known, else watched addr */
    uint32_t size;     /* configured watch size */
    uint32_t reserved;
} HdlWatchHit;

/* Drain watch-hit queue (full payload). HDL_EVENT_WATCH is wake-only. */
HDL_API HdlStatus HdlPollWatchHits(HdlWatchHit* out, uint32_t* inout_count, uint32_t timeout_ms);

#ifdef __cplusplus
}
#endif
