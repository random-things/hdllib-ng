#pragma once

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Disasm backends (pluggable) ---- */

enum {
    HDL_DISASM_ZYDIS = 1,
    HDL_DISASM_CAPSTONE = 2,
    HDL_DISASM_CUSTOM_BASE = 1000, /* external registrations use this range */
};

typedef struct HdlDisasmBackendInfo {
    int32_t id;
    char name[32];
} HdlDisasmBackendInfo;

/*
 * Decode one instruction. Returns HDL_OK and fills out_*.
 * length is required; other outs optional.
 */
typedef HdlStatus (*HdlDisasmDecodeFn)(
    void* user, uint64_t va, const uint8_t* bytes, size_t len, uint32_t* out_length,
    char* out_mnemonic,                    /* may be null; capacity mnemonic_cap */
    size_t mnemonic_cap, char* out_op_str, /* may be null; capacity op_cap */
    size_t op_cap, uint32_t* out_flags,    /* HDL_INSN_* */
    uint64_t* out_branch,                  /* branch/call target if known */
    int32_t* out_rip_disp_off,             /* byte offset of rip-rel disp in insn, or -1 */
    uint32_t* out_rip_disp_size /* 4 typically; 0 if none */);

typedef struct HdlDisasmBackendFns {
    const char* name;
    HdlDisasmDecodeFn decode;
    void* user;
} HdlDisasmBackendFns;

enum {
    HDL_INSN_CALL = 1u,
    HDL_INSN_JMP = 2u,
    HDL_INSN_RET = 4u,
    HDL_INSN_RIP_REL = 8u,
    HDL_INSN_BRANCH = 16u, /* has resolvable branch/call target in out_branch */
};

typedef struct HdlInsn {
    uint64_t addr;
    uint32_t length;
    uint32_t flags; /* HDL_INSN_* */
    uint64_t branch_target;
    int32_t rip_disp_offset; /* -1 if none */
    uint32_t rip_disp_size;
    char mnemonic[32];
    char op_str[96];
} HdlInsn;

enum {
    HDL_STUB_ABS_JMP = 1,     /* FF 25 / mov rax; jmp rax style absolute */
    HDL_STUB_REL_JMP32 = 2,   /* E9 rel32 (requires destination in ±2GB) */
    HDL_STUB_MOV_RAX_JMP = 3, /* 48 B8 imm64; FF E0 */
    HDL_STUB_RAW = 4,         /* caller-supplied bytes */
};

typedef struct HdlStubDesc {
    int32_t kind; /* HDL_STUB_* */
    uint32_t flags;
    uint64_t target;     /* jump/call destination for non-RAW */
    uint64_t steal_from; /* 0 = no steal; else copy insns from here until steal_min_bytes */
    uint32_t steal_min_bytes;
    uint32_t reserved;
    const uint8_t* raw; /* HDL_STUB_RAW */
    uint32_t raw_size;
    uint32_t alloc_rx; /* nonzero => allocate RX stub; out_stub_va set */
} HdlStubDesc;

typedef struct HdlStubResult {
    uint64_t stub_va; /* allocated VA when alloc_rx; else 0 */
    uint32_t stolen_bytes;
    uint32_t code_size;
    uint8_t code[256];
} HdlStubResult;

/* Patch ledger */
typedef uint64_t HdlPatchHandle;

typedef struct HdlPatchInfo {
    uint64_t handle;
    uint64_t addr;
    uint32_t size;
    uint32_t enabled;
    char name[48];
} HdlPatchInfo;

#ifdef __cplusplus
}
#endif
