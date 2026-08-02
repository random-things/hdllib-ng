#pragma once

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Typed value kinds for incremental searches. */
enum {
    HDL_VALUE_BYTES = 0, /* AOB pattern C string (same syntax as HdlSearchMemory) */
    HDL_VALUE_I8 = 1,
    HDL_VALUE_U8 = 2,
    HDL_VALUE_I16 = 3,
    HDL_VALUE_U16 = 4,
    HDL_VALUE_I32 = 5,
    HDL_VALUE_U32 = 6,
    HDL_VALUE_I64 = 7,
    HDL_VALUE_U64 = 8,
    HDL_VALUE_F32 = 9,
    HDL_VALUE_F64 = 10,
    HDL_VALUE_STRING = 11,  /* raw narrow bytes; value_size bytes, no NUL required */
    HDL_VALUE_WSTRING = 12, /* UTF-16LE code units; value_size must be even */
};

/* Comparison modes. First scan: EXACT or UNKNOWN. Next: any except UNKNOWN. */
enum {
    HDL_CMP_EXACT = 0,        /* equals value (bit-exact for floats) */
    HDL_CMP_UNKNOWN = 1,      /* first only: record every aligned slot of the type width */
    HDL_CMP_CHANGED = 2,      /* next: != previous snapshot */
    HDL_CMP_UNCHANGED = 3,    /* next: == previous snapshot */
    HDL_CMP_INCREASED = 4,    /* next: > previous (numeric types only) */
    HDL_CMP_DECREASED = 5,    /* next: < previous (numeric types only) */
    HDL_CMP_INCREASED_BY = 6, /* next: previous + value */
    HDL_CMP_DECREASED_BY = 7, /* next: previous - value */
    HDL_CMP_GREATER = 8,      /* current > value */
    HDL_CMP_LESS = 9,         /* current < value */
};

typedef struct HdlSearchSession HdlSearchSession;

typedef struct HdlSearchDesc {
    uint64_t start; /* with size==0 => all committed readable regions */
    uint64_t size;
    int32_t value_type;            /* HDL_VALUE_* */
    int32_t cmp;                   /* HDL_CMP_* */
    uint32_t alignment;            /* 0 = natural for type; 1 = byte-unaligned */
    uint32_t max_results;          /* 0 = unlimited; nonzero = optional early stop */
    const void* value;             /* typed bytes, or AOB pattern C string for BYTES */
    size_t value_size;             /* byte length; for BYTES may be 0 (uses strlen) */
    uint32_t flags;                /* HDL_SEARCH_* */
    const wchar_t* module_or_null; /* when HDL_SEARCH_MODULE: module basename or path */
} HdlSearchDesc;

/*
 * Incremental typed search. Create a session, HdlSearchFirst, then repeatedly
 * HdlSearchNext to narrow candidates. Snapshots of prior values are kept for
 * changed/increased/decreased comparisons.
 */

#ifdef __cplusplus
}
#endif
