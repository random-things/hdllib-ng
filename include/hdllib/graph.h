#pragma once

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Bounded functions / xrefs ---- */

typedef struct HdlFunctionInfo {
    uint64_t start;
    uint64_t end;        /* 0 if unknown */
    uint32_t confidence; /* 0..100 */
    uint32_t flags;
} HdlFunctionInfo;

enum {
    HDL_XREF_CALL = 1,
    HDL_XREF_JMP = 2,
    HDL_XREF_DATA = 4,
    HDL_XREF_FUNC = 8, /* XrefsTo: match branches into [fn.start, fn.end) */
};

/* HdlFunctionInfo.flags */
enum {
    HDL_FN_EXPORT = 1u,
    HDL_FN_CALLED = 2u,
    HDL_FN_PROLOGUE = 4u,
};

typedef struct HdlXrefEdge {
    uint64_t from;
    uint64_t to;
    uint32_t kind; /* HDL_XREF_* */
    uint32_t reserved;
} HdlXrefEdge;

/*
 * Map any interior byte address into an instruction-aligned function range for
 * the owning module (or given module_or_null). x64 unwind metadata is preferred;
 * the bounded function index is the fallback. out->end may be 0 if unknown.
 */

/*
 * Find call/jmp (and optional DATA) sites that target `target`. With HDL_XREF_FUNC
 * also match branches into the resolved function body containing target.
 */

/* Drop cached EnumFunctions index for module (null = all). */

#ifdef __cplusplus
}
#endif
