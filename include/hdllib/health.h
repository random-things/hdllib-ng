#pragma once

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Process / thread health ---- */

/* HdlHealthInfo.flags */
enum {
    HDL_HEALTH_OK = 0,
    HDL_HEALTH_GUI_HUNG = 1u,
    HDL_HEALTH_HIGH_CPU = 2u,
    HDL_HEALTH_RECENT_EXCEPTION = 4u,
};

typedef struct HdlHealthInfo {
    uint32_t pid;
    uint32_t thread_count;
    uint32_t handle_count;
    uint32_t flags; /* HDL_HEALTH_* */
    uint64_t working_set;
    uint64_t private_bytes;
    uint64_t user_time_100ns;
    uint64_t kernel_time_100ns;
    uint32_t cpu_percent; /* recent sample 0..100 (best-effort) */
    uint32_t gui_hung;    /* 1 if a top-level window looks hung */
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

/* ---- Process fingerprint (passive module / import / PE signals) ---- */

/* HdlFingerprintTag.category */
enum {
    HDL_FP_CAT_LANGUAGE = 1,
    HDL_FP_CAT_RUNTIME = 2,
    HDL_FP_CAT_TOOLCHAIN = 3,
    HDL_FP_CAT_UI = 4,
    HDL_FP_CAT_GRAPHICS = 5,
    HDL_FP_CAT_ENGINE = 6,
    HDL_FP_CAT_WEBHOST = 7,
    HDL_FP_CAT_AUDIO = 8,
    HDL_FP_CAT_NETWORK = 9,
    HDL_FP_CAT_TOOLING = 10,
    HDL_FP_CAT_APP = 11, /* subsystem / packaging hints */
};

/* HdlFingerprintTag.flags */
enum {
    HDL_FP_FROM_MODULE = 1u,
    HDL_FP_FROM_IMPORT = 2u,
    HDL_FP_FROM_PE = 4u,
    HDL_FP_PRIMARY = 8u, /* best-in-category */
};

/* HdlEnumFingerprintTags / HdlClassifyFingerprint scan_flags */
enum {
    HDL_FP_SCAN_MODULES = 1u,
    HDL_FP_SCAN_IMPORTS = 2u,
    HDL_FP_SCAN_PE = 4u,
    HDL_FP_SCAN_DEFAULT = HDL_FP_SCAN_MODULES | HDL_FP_SCAN_IMPORTS | HDL_FP_SCAN_PE,
    /* HDL_FP_ACTIVE = 8u reserved for future active probes */
};

typedef struct HdlFingerprintTag {
    uint32_t category;   /* HDL_FP_CAT_* */
    uint32_t confidence; /* 0..100 */
    uint32_t flags;      /* HDL_FP_* */
    uint32_t reserved;
    char id[48];        /* e.g. "d3d11", "coreclr", "qt6" */
    char evidence[192]; /* "module:d3d11.dll; import:D3D11CreateDevice" */
} HdlFingerprintTag;

typedef struct HdlFingerprintImport {
    char module[64];
    char name[128];
} HdlFingerprintImport;

/*
 * Passive fingerprint of the current process (loaded modules + main IAT + PE subsystem).
 * Classic size-query: out==nullptr or too small => HDL_E_BUFFER_SMALL + needed count.
 */

/*
 * Classify from caller-provided signals (no process walk). Useful for tests and offline dumps.
 * pe_subsystem: IMAGE_SUBSYSTEM_* (0 = unknown / skip PE rules unless SCAN_PE cleared).
 */

/* ---- Events (exception / health notifications) ---- */

enum {
    HDL_EVENT_EXCEPTION = 1,
    HDL_EVENT_HEALTH = 2,
    HDL_EVENT_JOB_DONE = 3,
    HDL_EVENT_HOOK = 4,  /* wake-up; full payload via HdlPollHookHits */
    HDL_EVENT_WATCH = 5, /* hardware / page watchpoint hit */
};

typedef struct HdlEvent {
    uint32_t type; /* HDL_EVENT_* */
    uint32_t code; /* exception code, health flags, or job status */
    uint64_t timestamp_ms;
    uint64_t address; /* exception address or job id */
    uint64_t detail;  /* reserved / extra */
} HdlEvent;

/*
 * Drain queued events. Blocks up to timeout_ms (0 = non-blocking) until at least
 * one event is available or the timeout elapses (OK with *inout_count==0).
 */

/* ---- Cooperative jobs (cancel / timeout across clients) ---- */

/* ---- Durable in-process allocation ---- */

#ifdef __cplusplus
}
#endif
