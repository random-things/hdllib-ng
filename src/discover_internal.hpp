#pragma once

#include "discover.hpp"

#include "graph.hpp"
#include "hooks.hpp"
#include "locate.hpp"
#include "memory.hpp"
#include "resolve.hpp"
#include "watch.hpp"
#include "json/json.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <Psapi.h>
#include <Windows.h>

namespace hdl {

// ---- Memory probe helpers (discover_scan.cpp) ----

bool PtrLooksReadable(uint64_t p);
bool PtrLooksExecutable(uint64_t p);

// ---- Module range (discover_scan.cpp) ----

struct ModRange {
    uint64_t base = 0;
    uint64_t end = 0;
};

HdlStatus ResolveModuleRange(uint32_t flags, const wchar_t* module_or_null, ModRange* out);
bool RegionOk(const MEMORY_BASIC_INFORMATION& mbi, uint32_t flags, const ModRange& mod);

// ---- Utility helpers (discover_session.cpp) ----

void FillModuleInfo(uint64_t addr, uint64_t* out_base, uint64_t* out_rva);
void SetTag(char* dst, size_t n, const char* tag);
bool ReadI32(uint64_t addr, int32_t* out);
bool ReadU64(uint64_t addr, uint64_t* out);

// ---- Predicate / pattern helpers (discover_scan.cpp) ----

bool PredHolds(uint64_t base, const HdlFieldPred& p);
std::string BytesToAob(const uint8_t* bytes, const uint8_t* mask, size_t n);
uint32_t CountPatternHits(const char* pattern, uint32_t flags, const wchar_t* module_or_null,
                          uint32_t max_hits, volatile int* cancel);

// ---- Path helpers (discover_path.cpp) ----

bool PathResolvesTo(const HdlPointerPath& path, uint64_t expected);

// ---- Watch helpers (discover_watch.cpp) ----

bool WcsContainsI(const wchar_t* hay, const wchar_t* needle);
bool ShouldSkipFrame(uint64_t addr);
uint32_t PickDiffRunSize(const uint8_t* before, const uint8_t* after, uint32_t off, uint32_t n);

struct WatchedRegion {
    uint64_t base = 0;
    uint32_t size = 0;
    std::vector<uint8_t> before;
    std::vector<HdlHeatField> heat;
};

struct ActionRecord {
    char name[48]{};
    uint64_t begin_ms = 0;
    uint64_t end_ms = 0;
    std::unordered_map<uint64_t, uint32_t> caller_hits;
    std::unordered_map<uint64_t, uint32_t> frame_weights;
};

void RecordHookHit(ActionRecord& rec, const HdlHookHit& hit);
HdlHeatField* FindHeatAtOffset(WatchedRegion& r, uint32_t offset);
void AccumulateRegionDiff(WatchedRegion& r, const uint8_t* before, const uint8_t* after,
                          uint32_t n);

// ---- Session (shared state) ----

struct Session {
    std::mutex mu;
    uint64_t next_id = 1;
    std::vector<HdlCandidate> cands;
    std::vector<HdlHookHandle> watches;
    std::vector<WatchedRegion> regions;
    bool action_open = false;
    char action_name[48]{};
    uint64_t action_begin_ms = 0;
    std::vector<ActionRecord> actions;
    std::unordered_map<uint64_t, std::array<char, 160>> evidence;
};

extern std::mutex g_sessions_mu;
extern std::unordered_set<Session*> g_sessions;

HdlCandidate MakeCand(Session* s, uint32_t kind, uint64_t address, const char* tag,
                      uint32_t confidence);

} // namespace hdl
