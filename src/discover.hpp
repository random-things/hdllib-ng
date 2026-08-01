#pragma once

#include "hdllib/hdllib.h"
#include "jobs.hpp"

namespace hdl {

HdlStatus DiscoverCreate(HdlDiscoverSession** out_session);
void DiscoverClose(HdlDiscoverSession* session);
void DiscoverCloseAll();

HdlStatus DiscoverAddCandidate(HdlDiscoverSession* session, uint32_t kind, uint64_t address,
                               const char* tag_or_null, uint64_t* out_id);
HdlStatus DiscoverScanValue(HdlDiscoverSession* session, const HdlSearchDesc* desc,
                            const char* tag_or_null, volatile int* cancel);
HdlStatus DiscoverScanValue(HdlDiscoverSession* session, const HdlSearchDesc* desc,
                            const char* tag_or_null, const CancelToken& token);
HdlStatus DiscoverConstraintScan(HdlDiscoverSession* session, uint32_t object_size,
                                 const HdlFieldPred* preds, uint32_t pred_count,
                                 uint32_t search_flags, const wchar_t* module_or_null,
                                 uint32_t max_results, const char* tag_or_null,
                                 volatile int* cancel);
HdlStatus DiscoverSynthesizePattern(HdlDiscoverSession* session, uint64_t cand_id,
                                    uint32_t window_before, uint32_t window_after,
                                    uint32_t search_flags, const wchar_t* module_or_null,
                                    HdlSynthesizedPattern* out, volatile int* cancel);
HdlStatus DiscoverPathConsensus(uint64_t target_addr, uint32_t max_depth, uint32_t max_offset,
                                uint32_t max_results, uint32_t search_flags,
                                const wchar_t* module_or_null, HdlPointerPath* out,
                                uint32_t* inout_count, volatile int* cancel);
HdlStatus DiscoverPathValidate(HdlPointerPath* paths, uint32_t* inout_count,
                               uint64_t expected_target);
HdlStatus DiscoverWatch(HdlDiscoverSession* session, uint64_t fn_addr, uint32_t arg_count);
HdlStatus DiscoverWatchImport(HdlDiscoverSession* session, const wchar_t* module_or_null,
                              const char* dll_name, const char* import_name, uint32_t arg_count);
HdlStatus DiscoverUnwatchAll(HdlDiscoverSession* session);
HdlStatus DiscoverActionBegin(HdlDiscoverSession* session, const char* name);
HdlStatus DiscoverActionEnd(HdlDiscoverSession* session);
HdlStatus DiscoverWatchRegion(HdlDiscoverSession* session, uint64_t base, uint32_t size);
HdlStatus DiscoverGetHeat(HdlDiscoverSession* session, uint64_t base, HdlHeatField* out,
                          uint32_t* inout_count);
HdlStatus DiscoverRankFunctions(HdlDiscoverSession* session, const char* action_name,
                                uint32_t flags, HdlCandidate* out, uint32_t* inout_count);
HdlStatus DiscoverResetHeat(HdlDiscoverSession* session, uint64_t base);
HdlStatus DiscoverDiffObjects(HdlDiscoverSession* session, const uint64_t* addrs, uint32_t count,
                              uint32_t max_size, HdlHeatField* out, uint32_t* inout_count);
HdlStatus DiscoverApplyWatchHits(HdlDiscoverSession* session, uint64_t object_base,
                                 uint32_t size);
HdlStatus DiscoverGetCandidateEvidence(HdlDiscoverSession* session, uint64_t cand_id, char* buf,
                                       uint32_t cap);
HdlStatus DiscoverExport(HdlDiscoverSession* session, char* buf, uint32_t* inout_size);
HdlStatus DiscoverImport(HdlDiscoverSession* session, const char* json, uint32_t size);
HdlStatus DiscoverClusterType(HdlDiscoverSession* session, uint64_t seed_addr,
                              uint32_t object_size, uint32_t search_flags,
                              const wchar_t* module_or_null, uint32_t max_results,
                              volatile int* cancel);
HdlStatus DiscoverGetCandidates(HdlDiscoverSession* session, HdlCandidate* out,
                                uint32_t* inout_count);

}  // namespace hdl
