#pragma once

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Locate: pattern resolve, xrefs, pointer scan, struct probe ---- */

typedef struct HdlPatternResolve {
    const char* pattern;      /* AOB */
    uint32_t hit_index;       /* 0-based match to use */
    int32_t pattern_offset;   /* added to match before RIP/follow */
    uint32_t rip_disp_offset; /* 0 + rip_instr_len==0 => skip RIP */
    uint32_t rip_instr_len;
    const int64_t* follow_offsets; /* optional multilevel after RIP */
    uint32_t follow_count;
    uint32_t flags; /* HDL_SEARCH_* */
    const wchar_t* module_or_null;
    uint32_t max_scan_hits; /* 0 = default 256 */
} HdlPatternResolve;

typedef struct HdlPatternResult {
    uint64_t match_addr;    /* raw AOB hit */
    uint64_t resolved_addr; /* after offset / RIP / follows */
    uint64_t module_base;   /* 0 if unknown */
    uint64_t rva;           /* resolved_addr - module_base when base known */
} HdlPatternResult;

/* HdlFindStringXrefs flags */
enum {
    HDL_XREF_ABSOLUTE = 1u, /* 8-byte absolute pointer to the string */
    HDL_XREF_RIP_REL = 2u,  /* RIP-relative disp resolving to the string */
};

/*
 * Locate string bytes, then find code/data references to those addresses.
 * string_size 0 with narrow/wide C string uses strlen/wcslen.
 */

typedef struct HdlPointerPath {
    uint64_t static_base; /* address of the first pointer in static/image memory */
    uint32_t depth;       /* number of offsets used */
    uint32_t reserved;
    int32_t offsets[8]; /* after each deref, add offsets[i]; final points at target */
} HdlPointerPath;

/*
 * CE-style pointer scan: find static paths that reach target_addr with
 * per-level offsets in [0, max_offset]. Typically use HDL_SEARCH_IMAGE.
 */

typedef struct HdlStructField {
    uint32_t offset;
    uint32_t kind; /* HDL_FIELD_* */
    uint64_t value;
} HdlStructField;

/* Heuristic field classification over [addr, addr+size). size capped at 4096. */

#ifdef __cplusplus
}
#endif
