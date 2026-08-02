#pragma once

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

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

/* Re-apply all HW watches to current process threads. */

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

#ifdef __cplusplus
}
#endif
