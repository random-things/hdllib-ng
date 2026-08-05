#pragma once

#include "common.hpp"
#include "protocol.hpp"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

namespace hdl {
namespace ipc {

bool HandlePing(HANDLE pipe, proto::Reader& r);
bool HandleSetLogLevel(HANDLE pipe, proto::Reader& r);
bool HandleSetLogFile(HANDLE pipe, proto::Reader& r);
bool HandleSetHealthVeh(HANDLE pipe, proto::Reader& r);
bool HandleGetHealthVeh(HANDLE pipe, proto::Reader& r);
bool HandleInjectDll(HANDLE pipe, proto::Reader& r);
bool HandleUnloadDll(HANDLE pipe, proto::Reader& r);
bool HandleShutdown(HANDLE pipe, proto::Reader& r);
bool HandleTrackLoadedDll(HANDLE pipe, proto::Reader& r);
bool HandleReadMemory(HANDLE pipe, proto::Reader& r);
bool HandleWriteMemory(HANDLE pipe, proto::Reader& r);
bool HandleEnumRegions(HANDLE pipe, proto::Reader& r);
bool HandleEnumModules(HANDLE pipe, proto::Reader& r);
bool HandleFingerprint(HANDLE pipe, proto::Reader& r);
bool HandleGetHealth(HANDLE pipe, proto::Reader& r);
bool HandleEnumThreads(HANDLE pipe, proto::Reader& r);
bool HandlePollEvents(HANDLE pipe, proto::Reader& r);

bool HandleSearchMemory(HANDLE pipe, proto::Reader& r);
bool HandleSearchCreate(HANDLE pipe, proto::Reader& r);
bool HandleSearchClose(HANDLE pipe, proto::Reader& r);
bool HandleSearchReset(HANDLE pipe, proto::Reader& r);
bool HandleSearchFirst(HANDLE pipe, proto::Reader& r);
bool HandleSearchNext(HANDLE pipe, proto::Reader& r);
bool HandleSearchGetHits(HANDLE pipe, proto::Reader& r);

bool HandleResolveExport(HANDLE pipe, proto::Reader& r);
bool HandleCallExport(HANDLE pipe, proto::Reader& r);
bool HandleCall(HANDLE pipe, proto::Reader& r);
bool HandleAlloc(HANDLE pipe, proto::Reader& r);
bool HandleFree(HANDLE pipe, proto::Reader& r);
bool HandleResolveRip(HANDLE pipe, proto::Reader& r);
bool HandleFollowPointers(HANDLE pipe, proto::Reader& r);
bool HandleModuleBase(HANDLE pipe, proto::Reader& r);
bool HandleCallVtable(HANDLE pipe, proto::Reader& r);

bool HandleHookTrace(HANDLE pipe, proto::Reader& r);
bool HandleHook(HANDLE pipe, proto::Reader& r);
bool HandleEnableHook(HANDLE pipe, proto::Reader& r);
bool HandleUnhook(HANDLE pipe, proto::Reader& r);
bool HandlePollHookHits(HANDLE pipe, proto::Reader& r);
bool HandleHookImport(HANDLE pipe, proto::Reader& r);

bool HandleResolvePattern(HANDLE pipe, proto::Reader& r);
bool HandleFindStringXrefs(HANDLE pipe, proto::Reader& r);
bool HandlePointerScan(HANDLE pipe, proto::Reader& r);
bool HandleProbeStruct(HANDLE pipe, proto::Reader& r);

bool HandleDiscoverCreate(HANDLE pipe, proto::Reader& r);
bool HandleDiscoverClose(HANDLE pipe, proto::Reader& r);
bool HandleDiscoverAddCandidate(HANDLE pipe, proto::Reader& r);
bool HandleDiscoverScanValue(HANDLE pipe, proto::Reader& r);
bool HandleDiscoverConstraintScan(HANDLE pipe, proto::Reader& r);
bool HandleDiscoverSynthesizePattern(HANDLE pipe, proto::Reader& r);
bool HandleDiscoverPathConsensus(HANDLE pipe, proto::Reader& r);
bool HandleDiscoverPathValidate(HANDLE pipe, proto::Reader& r);
bool HandleDiscoverWatch(HANDLE pipe, proto::Reader& r);
bool HandleDiscoverUnwatchAll(HANDLE pipe, proto::Reader& r);
bool HandleDiscoverActionBegin(HANDLE pipe, proto::Reader& r);
bool HandleDiscoverActionEnd(HANDLE pipe, proto::Reader& r);
bool HandleDiscoverWatchRegion(HANDLE pipe, proto::Reader& r);
bool HandleDiscoverGetHeat(HANDLE pipe, proto::Reader& r);
bool HandleDiscoverRankFunctions(HANDLE pipe, proto::Reader& r);
bool HandleDiscoverWatchImport(HANDLE pipe, proto::Reader& r);
bool HandleDiscoverResetHeat(HANDLE pipe, proto::Reader& r);
bool HandleDiscoverExport(HANDLE pipe, proto::Reader& r);
bool HandleDiscoverImport(HANDLE pipe, proto::Reader& r);
bool HandleDiscoverDiffObjects(HANDLE pipe, proto::Reader& r);
bool HandleDiscoverApplyWatchHits(HANDLE pipe, proto::Reader& r);
bool HandleDiscoverGetEvidence(HANDLE pipe, proto::Reader& r);
bool HandleDiscoverClusterType(HANDLE pipe, proto::Reader& r);
bool HandleDiscoverGetCandidates(HANDLE pipe, proto::Reader& r);

bool HandleFindCaves(HANDLE pipe, proto::Reader& r);
bool HandleAllocNear(HANDLE pipe, proto::Reader& r);
bool HandleProtectMemory(HANDLE pipe, proto::Reader& r);
bool HandleFlushICache(HANDLE pipe, proto::Reader& r);

bool HandleDisasmEnumBackends(HANDLE pipe, proto::Reader& r);
bool HandleDisasmGetBackend(HANDLE pipe, proto::Reader& r);
bool HandleDisasmSetBackend(HANDLE pipe, proto::Reader& r);
bool HandleInstrLen(HANDLE pipe, proto::Reader& r);
bool HandleDisasm(HANDLE pipe, proto::Reader& r);
bool HandleBuildStub(HANDLE pipe, proto::Reader& r);
bool HandlePatchCreate(HANDLE pipe, proto::Reader& r);
bool HandlePatchEnable(HANDLE pipe, proto::Reader& r);
bool HandlePatchRemove(HANDLE pipe, proto::Reader& r);
bool HandlePatchEnum(HANDLE pipe, proto::Reader& r);

bool HandleEnumSections(HANDLE pipe, proto::Reader& r);
bool HandleEnumExports(HANDLE pipe, proto::Reader& r);
bool HandleEnumImports(HANDLE pipe, proto::Reader& r);

bool HandleEnumFunctions(HANDLE pipe, proto::Reader& r);
bool HandleXrefsFrom(HANDLE pipe, proto::Reader& r);
bool HandleResolveFunction(HANDLE pipe, proto::Reader& r);
bool HandleXrefsTo(HANDLE pipe, proto::Reader& r);
bool HandleInvalidateFnIndex(HANDLE pipe, proto::Reader& r);

bool HandleWalkVtable(HANDLE pipe, proto::Reader& r);
bool HandleQueryRttiName(HANDLE pipe, proto::Reader& r);

bool HandleWatchHw(HANDLE pipe, proto::Reader& r);
bool HandleWatchPage(HANDLE pipe, proto::Reader& r);
bool HandleUnwatch(HANDLE pipe, proto::Reader& r);
bool HandleEnumWatches(HANDLE pipe, proto::Reader& r);
bool HandleWatchRefresh(HANDLE pipe, proto::Reader& r);
bool HandlePollWatchHits(HANDLE pipe, proto::Reader& r);

} // namespace ipc
} // namespace hdl
