#pragma once

#include "memory.hpp"

#include "hdllib/hdllib.h"
#include "jobs.hpp"

#include <cstdint>
#include <cstring>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

namespace hdl {

struct SearchSession {
    int value_type = HDL_VALUE_BYTES;
    int last_cmp = HDL_CMP_EXACT;
    uint32_t alignment = 1;
    uint32_t max_results = 0;
    size_t elem_size = 0;
    bool active = false;
    bool retain_hits = true;
    uint32_t emitted_hits = 0;
    HdlStatus abort_status = HDL_OK;
    SearchHitFn on_hit = nullptr;
    void* on_hit_user = nullptr;
    std::vector<uint8_t> needle;
    std::vector<uint8_t> mask;
    std::vector<uint64_t> addresses;
    std::vector<uint8_t> snapshots;
};

inline SearchSession* AsSearch(HdlSearchSession* s) {
    return reinterpret_cast<SearchSession*>(s);
}
inline const SearchSession* AsSearch(const HdlSearchSession* s) {
    return reinterpret_cast<const SearchSession*>(s);
}

inline size_t HitCount(const SearchSession& s) {
    return s.retain_hits ? s.addresses.size() : static_cast<size_t>(s.emitted_hits);
}

inline bool CapReached(const SearchSession& s) {
    return s.max_results != 0 && HitCount(s) >= static_cast<size_t>(s.max_results);
}

inline HdlStatus AfterPushFail(const SearchSession& s) {
    return s.abort_status != HDL_OK ? s.abort_status : HDL_OK;
}

// Region helpers (defined in memory_rw.cpp)
bool IsReadableProtect(DWORD protect);
bool IsExecutableProtect(DWORD protect);
bool RegionCommittedReadable(const MEMORY_BASIC_INFORMATION& mbi);

// SEH helpers (defined in memory_rw.cpp)
size_t SehMemcpy(void* dst, const void* src, size_t size);
int SehMatchAt(const uint8_t* data, const uint8_t* bytes, const uint8_t* mask, size_t len);
int SehBytesEqual(const uint8_t* a, const uint8_t* b, size_t len);
int SehReadBytes(const void* src, void* dst, size_t size);

// Scan filter (defined in memory_search.cpp)
struct ScanFilter {
    uint32_t flags = 0;
    uint64_t mod_base = 0;
    uint64_t mod_end = 0;
};

HdlStatus BuildScanFilter(uint32_t flags, const wchar_t* module_or_null, ScanFilter* out);
bool RegionMatchesFilter(const MEMORY_BASIC_INFORMATION& mbi, const ScanFilter& f);

// Value helpers (defined in memory_search.cpp)
size_t ValueWidth(int value_type);
uint32_t NaturalAlignment(int value_type);
bool IsNumericType(int value_type);
int CompareNumeric(int value_type, const uint8_t* a, const uint8_t* b);
bool AddNumeric(int value_type, const uint8_t* base, const uint8_t* delta, uint8_t* out,
                bool subtract);
bool MatchCmp(int value_type, int cmp, const uint8_t* current, const uint8_t* previous,
              const uint8_t* value, size_t value_size);

// Hit helpers (defined in memory_search.cpp)
bool PushHit(SearchSession& s, uint64_t address, const uint8_t* data, size_t n);
bool PushHitFromMemory(SearchSession& s, uint64_t address, const uint8_t* data, size_t n);

// Scan engine (defined in memory_search.cpp)
HdlStatus ScanPatternRange(SearchSession& s, uint64_t range_start, uint64_t range_size,
                           const CancelToken& token, bool unknown_fill);
HdlStatus ScanAllReadable(SearchSession& s, uint64_t start, uint64_t size, const CancelToken& token,
                          bool unknown_fill, const ScanFilter& filter);
HdlStatus PrepareNeedle(SearchSession& s, int value_type, int cmp, const void* value,
                        size_t value_size);

// AOB parser (defined in memory_aob.cpp)
int HexNibble(char c);

} // namespace hdl
