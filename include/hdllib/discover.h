#pragma once

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Discover: automated find / stabilize / expand ---- */

enum {
    HDL_CAND_ADDRESS = 1,
    HDL_CAND_FUNCTION = 2,
    HDL_CAND_OBJECT = 3,
    HDL_CAND_FIELD = 4,
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
    char tag[48];
} HdlCandidate;

typedef struct HdlSynthesizedPattern {
    char pattern[192];      /* AOB text with optional ?? wildcards */
    int32_t pattern_offset; /* bytes from match to original address */
    uint32_t rip_disp_offset;
    uint32_t rip_instr_len;
    uint64_t match_addr;
    uint64_t resolved_addr;
    uint32_t unique_hits; /* matches of pattern in scan scope */
    uint32_t reserved;
} HdlSynthesizedPattern;

/* Structure-aware field predicates (relative to a candidate object base). */
enum {
    HDL_PRED_EQ_I32 = 1,    /* *(i32*)(base+off) == (i32)a */
    HDL_PRED_EQ_F32 = 2,    /* bit-exact f32; a holds IEEE bits in low 32 */
    HDL_PRED_RANGE_I32 = 3, /* a <= i32 <= b */
    HDL_PRED_LE_I32 = 4,    /* i32(off) <= i32(off + (int32_t)a) */
    HDL_PRED_PTR = 5,       /* readable pointer */
    HDL_PRED_VTABLE = 6,    /* pointer into executable memory */
    HDL_PRED_EQ_U64 = 7,    /* *(u64*)(base+off) == (u64)a */
};

typedef struct HdlFieldPred {
    int32_t offset;
    int32_t kind; /* HDL_PRED_* */
    int64_t a;
    int64_t b;
} HdlFieldPred;

typedef struct HdlHeatField {
    uint32_t offset;
    uint32_t changes;  /* times the slot differed across action snapshots */
    uint32_t kind;     /* HDL_FIELD_* when classifiable */
    uint32_t reserved; /* repurposed as slot size in bytes (1/2/4/8) */
    uint64_t last_value;
} HdlHeatField;

typedef struct HdlDiscoverSession HdlDiscoverSession;

/* Manually seed a candidate. tag may be null. out_id optional. */

/*
 * Typed exact scan; each hit becomes an HDL_CAND_ADDRESS (tag applied).
 * desc.cmp should be HDL_CMP_EXACT (or UNKNOWN for all slots — not recommended).
 */

/*
 * Find object bases of object_size where every predicate holds.
 * Adds HDL_CAND_OBJECT candidates. object_size capped at 4096; alignment 8.
 */

/*
 * Build a module-unique AOB for cand_id's address. window_before/after bound the
 * bytes considered (each capped at 64). Prefer HDL_SEARCH_MODULE|IMAGE.
 */

/*
 * Pointer-scan then keep only paths that still resolve to target_addr.
 * validate_rounds>=2 re-scans after each validate using the same target (useful
 * when the caller mutates memory between IPC round-trips via PathScan/PathValidate).
 * For a one-shot filter of an existing list, use HdlDiscoverPathValidate.
 */

/* Drop paths that do not currently resolve to expected_target. Compacts in place. */

/* HookTrace watch; callers during actions are ranked as functions. */

/*
 * Action window: drains/associates hook hits and diffs watched regions.
 * name max 47 chars; Begin fails if another action is open.
 */

/* Register [base, base+size) for change-heat across the next action window. */

/*
 * Rank functions seen during a named action (frame-weighted by default).
 * Adds HDL_CAND_FUNCTION candidates. out optional snapshot of ranking.
 */
enum { HDL_RANK_CALLER_ONLY = 1u };

/* UTF-8 JSON export (max 4 MiB): candidates, evidence, heat, action names. */

/* Best-effort import: AddCandidate for each candidate in JSON. */

/*
 * Find other bases with the same vtable pointer (offset 0) and compatible size.
 * seed must look like an object with a vtable. Adds HDL_CAND_OBJECT candidates.
 */

#ifdef __cplusplus
}
#endif
