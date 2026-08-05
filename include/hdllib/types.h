#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#ifdef HDL_DOMAIN_TESTS
#define HDL_API
#elif defined(HDL_EXPORTS)
#define HDL_API __declspec(dllexport)
#else
#define HDL_API __declspec(dllimport)
#endif
#else
#define HDL_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef int32_t HdlStatus;

enum {
    HDL_OK = 0,
    HDL_E_INVALID_ARG = 1,
    HDL_E_ACCESS = 2,
    HDL_E_NOT_FOUND = 3,
    HDL_E_NO_MEM = 4,
    HDL_E_BUSY = 5,
    HDL_E_FAILED = 6,
    HDL_E_BUFFER_SMALL = 7,
    HDL_E_CANCELLED = 8,
    HDL_E_NOT_INIT = 9,
    HDL_E_TIMEOUT = 10,
};

enum {
    HDL_LOG_OFF = 0,
    HDL_LOG_ERROR = 1,
    HDL_LOG_INFO = 2,
    HDL_LOG_DEBUG = 3,
};

/* Remote DLL injection technique. Default / legacy = CreateRemoteThread. */
enum {
    HDL_INJECT_CREATE_REMOTE_THREAD = 0,
    HDL_INJECT_NT_CREATE_THREAD_EX = 1,
    HDL_INJECT_RTL_CREATE_USER_THREAD = 2,
    HDL_INJECT_QUEUE_USER_APC = 3,
    HDL_INJECT_SET_WINDOWS_HOOK_EX = 4,
    HDL_INJECT_THREAD_HIJACK = 5,
    HDL_INJECT_MANUAL_MAP = 6,
    HDL_INJECT_EARLY_BIRD_APC = 7,
    HDL_INJECT_ATOM_BOMBING = 8,
    HDL_INJECT_MODULE_STOMP = 9,
    HDL_INJECT_SECTION_MAP = 10,
    HDL_INJECT_WINDOW_SUBCLASS = 11,
    HDL_INJECT_INSTRUMENTATION_CALLBACK = 12,
    HDL_INJECT_KERNEL_CALLBACK_TABLE = 13,
    HDL_INJECT_VEH = 14,
    HDL_INJECT_SET_WIN_EVENT_HOOK = 15,
    HDL_INJECT_RTL_REMOTE_CALL = 16,
    HDL_INJECT_SPECIAL_USER_APC = 17,
    HDL_INJECT_THREAD_POOL = 18,
    HDL_INJECT_ETW_CALLBACK = 19,
    /* Auto-select via HdlRecommendInject (not a technique implementation). */
    HDL_INJECT_AUTO = -1,
};

/* HdlInjectCandidate.flags */
enum {
    HDL_INJECT_CAND_ELIGIBLE = 1u,
    HDL_INJECT_CAND_NEEDS_ELEVATION = 2u,
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
    wchar_t path[260];
} HdlModuleInfo;

typedef void* HdlHookHandle;

/* Shutdown flags (RPC + domain). */
#define HDL_SHUTDOWN_UNLOAD_MODULES 1u

/*
 * Shared types/status/enums for the named-pipe control channel and domain code.
 * The DLL does not export a general C control ABI — drive an injected helper over
 * the pipe (see protocol / hdlclient). Exported callbacks below are for inject
 * techniques only (SetWindowsHookEx / SetWinEventHook).
 */

/* Scan scope flags (used by HdlSearchDesc, HdlPatternResolve, HdlCaveQuery). */
enum {
    HDL_SEARCH_IMAGE = 1u,      /* MEM_IMAGE regions only */
    HDL_SEARCH_EXECUTABLE = 2u, /* executable protect only */
    HDL_SEARCH_MODULE = 4u,     /* restrict to module_or_null */
};

/* Field classification kinds (used by HdlStructField, HdlHeatField). */
enum {
    HDL_FIELD_UNKNOWN = 0,
    HDL_FIELD_PTR = 1,
    HDL_FIELD_VTABLE = 2, /* pointer into executable image */
    HDL_FIELD_ASCII = 3,
    HDL_FIELD_FLOAT = 4,
    HDL_FIELD_INT32 = 5,
    HDL_FIELD_INT64 = 6,
};

#ifdef __cplusplus
}
#endif
