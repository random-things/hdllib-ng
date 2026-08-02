#pragma once

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Place: caves, protect, icache ---- */

typedef struct HdlCaveInfo {
    uint64_t addr;
    uint64_t size;
    uint64_t region_base;
    uint32_t reserved;
} HdlCaveInfo;

typedef struct HdlCaveQuery {
    uint32_t min_size;
    uint32_t fill_byte;    /* byte value to match (e.g. 0xCC or 0x00) */
    uint32_t search_flags; /* HDL_SEARCH_* */
    uint32_t max_results;  /* 0 = default 4096 */
    uint64_t near_addr;    /* 0 = no proximity filter */
    uint64_t max_distance; /* used when near_addr != 0; 0 => 0x7FFFFFFF (RIP-rel range) */
    const wchar_t* module_or_null;
} HdlCaveQuery;

/* ---- Address resolution helpers ---- */

/*
 * RIP-relative: *out = addr + instr_len + *(int32_t*)(addr + disp_offset).
 * Typical LEA/CALL/JMP: disp_offset=3, instr_len=7 (or disp_offset=1, instr_len=5 for call/jmp).
 */

/* Multilevel pointer: start at base, then repeatedly read ptr and add offsets[i]. */

#ifdef __cplusplus
}
#endif
