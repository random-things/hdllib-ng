#pragma once

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- In-process call (exports / absolute / vtable) ---- */

enum {
    HDL_CALL_ARG_U64 = 0,
    HDL_CALL_ARG_I64 = 1,
    HDL_CALL_ARG_PTR = 2,  /* ptr: pointer value passed as arg (buffer not copied) */
    HDL_CALL_ARG_BUF = 3,  /* ptr + size: copy-in, pass temp ptr, copy-out on success */
    HDL_CALL_ARG_CSTR = 4, /* NUL-terminated narrow; copied */
    HDL_CALL_ARG_WSTR = 5, /* NUL-terminated wide; copied */
    HDL_CALL_ARG_F32 = 6,  /* u64 holds IEEE-754 bits in low 32 */
    HDL_CALL_ARG_F64 = 7,  /* u64 holds IEEE-754 bits */
};

enum {
    HDL_CALL_THREAD_WORKER = 0, /* run on a helper thread (default) */
    HDL_CALL_THREAD_MAIN = 1,   /* sync run on primary UI thread; fails if no HWND */
};

typedef struct HdlCallArg {
    int32_t kind;    /* HDL_CALL_ARG_* */
    uint32_t size;   /* BUF byte length; ignored for U64/I64/CSTR/WSTR/F32/F64 */
    uint64_t u64;    /* U64/I64/F32/F64 value, or ignored */
    const void* ptr; /* PTR/BUF/CSTR/WSTR; BUF may be written back (inout) */
} HdlCallArg;

typedef struct HdlCallResult {
    uint64_t return_value;
    uint32_t last_error; /* GetLastError after the call */
    uint32_t reserved;
} HdlCallResult;

typedef struct HdlCallDesc {
    uint64_t address; /* absolute function address */
    const HdlCallArg* args;
    uint32_t arg_count;   /* 0..16 */
    uint32_t thread_mode; /* HDL_CALL_THREAD_* */
    uint32_t timeout_ms;  /* 0 = wait forever */
    uint32_t reserved;
} HdlCallDesc;

/*
 * Invoke an absolute address with up to 16 args (Microsoft x64 ABI, including floats).
 * On HDL_E_TIMEOUT / HDL_E_CANCELLED the callee may still be running.
 * BUF args are copied back into the caller's buffer on success.
 */

/*
 * Resolve export then HdlCall (thread_mode = WORKER).
 * module_or_null: NULL/empty => main EXE; otherwise LoadLibrary/GetModuleHandle name.
 */

/*
 * Read vtable from *obj, take slot index, then HdlCall.
 * If arg_count==0 or args[0] is not the object, a synthetic this (PTR to obj) is prepended
 * when prepend_this != 0. When prepend_this==0, args are passed as-is (caller supplies this).
 */

#ifdef __cplusplus
}
#endif
