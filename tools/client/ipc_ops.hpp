#pragma once

#include "pipe_client.hpp"
#include "hdllib/hdllib.h"

#include <cstdint>
#include <string>
#include <vector>

namespace hdlcli {

struct IpcStatus {
    int32_t status = 0;
    explicit operator bool() const { return status == HDL_OK; }
};

IpcStatus Ping(PipeClient& c, uint32_t* out_pid = nullptr);

IpcStatus ModBase(PipeClient& c, const wchar_t* module_or_null, uint64_t* out_base);

IpcStatus ResolvePattern(PipeClient& c, const char* pattern, uint32_t hit_index,
                         int32_t pattern_offset, uint32_t rip_disp, uint32_t rip_len,
                         const std::vector<int64_t>& follows, uint32_t search_flags,
                         const wchar_t* module_or_null, HdlPatternResult* out);

IpcStatus FollowPointers(PipeClient& c, uint64_t base, const std::vector<int64_t>& offsets,
                         uint64_t* out_addr);

IpcStatus DiscoverCreate(PipeClient& c, uint64_t* out_id);
IpcStatus DiscoverClose(PipeClient& c, uint64_t id);
IpcStatus DiscoverWatch(PipeClient& c, uint64_t session, uint64_t fn, uint32_t args);
IpcStatus DiscoverUnwatchAll(PipeClient& c, uint64_t session);
IpcStatus DiscoverActionBegin(PipeClient& c, uint64_t session, const char* name);
IpcStatus DiscoverActionEnd(PipeClient& c, uint64_t session);
IpcStatus DiscoverWatchRegion(PipeClient& c, uint64_t session, uint64_t base, uint32_t size);
IpcStatus DiscoverRank(PipeClient& c, uint64_t session, const char* name,
                       std::vector<HdlCandidate>* out, uint32_t flags = 0);
IpcStatus DiscoverSynth(PipeClient& c, uint64_t session, uint64_t cand_id, uint32_t before,
                        uint32_t after, uint32_t search_flags, const wchar_t* module_or_null,
                        HdlSynthesizedPattern* out);
IpcStatus DiscoverConstraint(PipeClient& c, uint64_t session, uint32_t object_size,
                             const std::vector<HdlFieldPred>& preds, uint32_t search_flags,
                             const wchar_t* module_or_null, uint32_t max_results, const char* tag);
IpcStatus DiscoverGetCandidates(PipeClient& c, uint64_t session, std::vector<HdlCandidate>* out);
IpcStatus DiscoverCluster(PipeClient& c, uint64_t session, uint64_t seed, uint32_t object_size,
                          uint32_t search_flags, const wchar_t* module_or_null, uint32_t max_results);
IpcStatus DiscoverAddCandidate(PipeClient& c, uint64_t session, uint32_t kind, uint64_t addr,
                               const char* tag, uint64_t* out_cand_id);
IpcStatus PathConsensus(PipeClient& c, uint64_t target, uint32_t max_depth, uint32_t max_offset,
                        uint32_t max_results, uint32_t search_flags, const wchar_t* module_or_null,
                        std::vector<HdlPointerPath>* out);
IpcStatus PathValidate(PipeClient& c, uint64_t expected, std::vector<HdlPointerPath>* paths);
IpcStatus CallExport(PipeClient& c, const wchar_t* module, const char* name,
                     const std::vector<HdlCallArg>& args, uint32_t timeout_ms,
                     HdlCallResult* out);

IpcStatus FindCaves(PipeClient& c, const HdlCaveQuery& q, std::vector<HdlCaveInfo>* out);
IpcStatus AllocNear(PipeClient& c, uint64_t near_addr, uint64_t max_distance, uint64_t size,
                    uint32_t protect, uint64_t* out_addr);
IpcStatus BuildStub(PipeClient& c, const HdlStubDesc& desc, HdlStubResult* out);
IpcStatus PatchCreate(PipeClient& c, uint64_t addr, const uint8_t* bytes, uint32_t size,
                      const char* name, uint64_t* out_handle);
IpcStatus PatchEnable(PipeClient& c, uint64_t handle, int enable);
IpcStatus PatchRemove(PipeClient& c, uint64_t handle);
IpcStatus PatchEnum(PipeClient& c, std::vector<HdlPatchInfo>* out);
IpcStatus WatchHw(PipeClient& c, uint64_t addr, uint32_t size, uint32_t access, uint32_t tid,
                  uint64_t* out_handle);
IpcStatus WatchPage(PipeClient& c, uint64_t addr, uint64_t size, uint32_t mode, uint64_t* out_handle);
IpcStatus Unwatch(PipeClient& c, uint64_t handle);
IpcStatus ResolveExport(PipeClient& c, const wchar_t* module, const char* name, uint64_t* out_addr);

IpcStatus EnumImports(PipeClient& c, uint64_t module_base, std::vector<HdlImportInfo>* out);
IpcStatus Fingerprint(PipeClient& c, uint32_t scan_flags, std::vector<HdlFingerprintTag>* out);

}  // namespace hdlcli
