#pragma once

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- PE metadata ---- */

typedef struct HdlSectionInfo {
    char name[16];
    uint64_t va;
    uint64_t vsize;
    uint32_t raw_size;
    uint32_t characteristics;
} HdlSectionInfo;

typedef struct HdlExportInfo {
    char name[128];
    uint32_t ordinal;
    uint32_t forwarder; /* 1 if forwarded */
    uint32_t reserved;
    uint64_t rva;
    uint64_t va;
} HdlExportInfo;

typedef struct HdlImportInfo {
    char module[64];
    char name[128];
    uint32_t ordinal; /* if name empty */
    uint32_t reserved;
    uint64_t iat_va;
    uint64_t bound_va; /* current IAT value */
} HdlImportInfo;

#ifdef __cplusplus
}
#endif
