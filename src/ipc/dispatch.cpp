#include "dispatch.hpp"
#include "handlers.hpp"
#include "protocol.hpp"

#include <vector>

namespace hdl {
namespace ipc {

bool HandleRequest(HANDLE pipe, const std::vector<uint8_t>& req) {
    using namespace proto;
    Reader r(req);
    uint32_t op = 0;
    if (!r.TakePod(op)) {
        std::vector<uint8_t> resp;
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }

    switch (op) {
    case OpPing:
        return HandlePing(pipe, r);
    case OpSetLogLevel:
        return HandleSetLogLevel(pipe, r);
    case OpSetLogFile:
        return HandleSetLogFile(pipe, r);
    case OpSetHealthVeh:
        return HandleSetHealthVeh(pipe, r);
    case OpGetHealthVeh:
        return HandleGetHealthVeh(pipe, r);
    case OpInjectDll:
        return HandleInjectDll(pipe, r);
    case OpUnloadDll:
        return HandleUnloadDll(pipe, r);
    case OpShutdown:
        return HandleShutdown(pipe, r);
    case OpTrackLoadedDll:
        return HandleTrackLoadedDll(pipe, r);
    case OpReadMemory:
        return HandleReadMemory(pipe, r);
    case OpWriteMemory:
        return HandleWriteMemory(pipe, r);
    case OpEnumRegions:
        return HandleEnumRegions(pipe, r);
    case OpEnumModules:
        return HandleEnumModules(pipe, r);
    case OpFingerprint:
        return HandleFingerprint(pipe, r);
    case OpSearchMemory:
        return HandleSearchMemory(pipe, r);
    case OpSearchCreate:
        return HandleSearchCreate(pipe, r);
    case OpSearchClose:
        return HandleSearchClose(pipe, r);
    case OpSearchFirst:
        return HandleSearchFirst(pipe, r);
    case OpSearchNext:
        return HandleSearchNext(pipe, r);
    case OpSearchGetHits:
        return HandleSearchGetHits(pipe, r);
    case OpSearchReset:
        return HandleSearchReset(pipe, r);
    case OpJobCreate:
        return HandleJobCreate(pipe, r);
    case OpJobCancel:
        return HandleJobCancel(pipe, r);
    case OpJobClose:
        return HandleJobClose(pipe, r);
    case OpGetHealth:
        return HandleGetHealth(pipe, r);
    case OpEnumThreads:
        return HandleEnumThreads(pipe, r);
    case OpPollEvents:
        return HandlePollEvents(pipe, r);
    case OpResolveExport:
        return HandleResolveExport(pipe, r);
    case OpCallExport:
        return HandleCallExport(pipe, r);
    case OpCall:
        return HandleCall(pipe, r);
    case OpAlloc:
        return HandleAlloc(pipe, r);
    case OpFree:
        return HandleFree(pipe, r);
    case OpResolveRip:
        return HandleResolveRip(pipe, r);
    case OpFollowPointers:
        return HandleFollowPointers(pipe, r);
    case OpModuleBase:
        return HandleModuleBase(pipe, r);
    case OpCallVtable:
        return HandleCallVtable(pipe, r);
    case OpHookTrace:
        return HandleHookTrace(pipe, r);
    case OpHook:
        return HandleHook(pipe, r);
    case OpEnableHook:
        return HandleEnableHook(pipe, r);
    case OpUnhook:
        return HandleUnhook(pipe, r);
    case OpPollHookHits:
        return HandlePollHookHits(pipe, r);
    case OpResolvePattern:
        return HandleResolvePattern(pipe, r);
    case OpFindStringXrefs:
        return HandleFindStringXrefs(pipe, r);
    case OpPointerScan:
        return HandlePointerScan(pipe, r);
    case OpProbeStruct:
        return HandleProbeStruct(pipe, r);
    case OpDiscoverCreate:
        return HandleDiscoverCreate(pipe, r);
    case OpDiscoverClose:
        return HandleDiscoverClose(pipe, r);
    case OpDiscoverAddCandidate:
        return HandleDiscoverAddCandidate(pipe, r);
    case OpDiscoverScanValue:
        return HandleDiscoverScanValue(pipe, r);
    case OpDiscoverConstraintScan:
        return HandleDiscoverConstraintScan(pipe, r);
    case OpDiscoverSynthesizePattern:
        return HandleDiscoverSynthesizePattern(pipe, r);
    case OpDiscoverPathConsensus:
        return HandleDiscoverPathConsensus(pipe, r);
    case OpDiscoverPathValidate:
        return HandleDiscoverPathValidate(pipe, r);
    case OpDiscoverWatch:
        return HandleDiscoverWatch(pipe, r);
    case OpDiscoverUnwatchAll:
        return HandleDiscoverUnwatchAll(pipe, r);
    case OpDiscoverActionBegin:
        return HandleDiscoverActionBegin(pipe, r);
    case OpDiscoverActionEnd:
        return HandleDiscoverActionEnd(pipe, r);
    case OpDiscoverWatchRegion:
        return HandleDiscoverWatchRegion(pipe, r);
    case OpDiscoverGetHeat:
        return HandleDiscoverGetHeat(pipe, r);
    case OpDiscoverRankFunctions:
        return HandleDiscoverRankFunctions(pipe, r);
    case OpDiscoverClusterType:
        return HandleDiscoverClusterType(pipe, r);
    case OpDiscoverGetCandidates:
        return HandleDiscoverGetCandidates(pipe, r);
    case OpFindCaves:
        return HandleFindCaves(pipe, r);
    case OpAllocNear:
        return HandleAllocNear(pipe, r);
    case OpProtectMemory:
        return HandleProtectMemory(pipe, r);
    case OpFlushICache:
        return HandleFlushICache(pipe, r);
    case OpDisasmEnumBackends:
        return HandleDisasmEnumBackends(pipe, r);
    case OpDisasmGetBackend:
        return HandleDisasmGetBackend(pipe, r);
    case OpDisasmSetBackend:
        return HandleDisasmSetBackend(pipe, r);
    case OpInstrLen:
        return HandleInstrLen(pipe, r);
    case OpDisasm:
        return HandleDisasm(pipe, r);
    case OpBuildStub:
        return HandleBuildStub(pipe, r);
    case OpPatchCreate:
        return HandlePatchCreate(pipe, r);
    case OpPatchEnable:
        return HandlePatchEnable(pipe, r);
    case OpPatchRemove:
        return HandlePatchRemove(pipe, r);
    case OpPatchEnum:
        return HandlePatchEnum(pipe, r);
    case OpEnumSections:
        return HandleEnumSections(pipe, r);
    case OpEnumExports:
        return HandleEnumExports(pipe, r);
    case OpEnumImports:
        return HandleEnumImports(pipe, r);
    case OpEnumFunctions:
        return HandleEnumFunctions(pipe, r);
    case OpXrefsFrom:
        return HandleXrefsFrom(pipe, r);
    case OpResolveFunction:
        return HandleResolveFunction(pipe, r);
    case OpXrefsTo:
        return HandleXrefsTo(pipe, r);
    case OpInvalidateFnIndex:
        return HandleInvalidateFnIndex(pipe, r);
    case OpWalkVtable:
        return HandleWalkVtable(pipe, r);
    case OpQueryRttiName:
        return HandleQueryRttiName(pipe, r);
    case OpWatchHw:
        return HandleWatchHw(pipe, r);
    case OpWatchPage:
        return HandleWatchPage(pipe, r);
    case OpUnwatch:
        return HandleUnwatch(pipe, r);
    case OpEnumWatches:
        return HandleEnumWatches(pipe, r);
    case OpWatchRefresh:
        return HandleWatchRefresh(pipe, r);
    case OpPollWatchHits:
        return HandlePollWatchHits(pipe, r);
    case OpHookImport:
        return HandleHookImport(pipe, r);
    case OpDiscoverWatchImport:
        return HandleDiscoverWatchImport(pipe, r);
    case OpDiscoverResetHeat:
        return HandleDiscoverResetHeat(pipe, r);
    case OpDiscoverExport:
        return HandleDiscoverExport(pipe, r);
    case OpDiscoverImport:
        return HandleDiscoverImport(pipe, r);
    case OpDiscoverDiffObjects:
        return HandleDiscoverDiffObjects(pipe, r);
    case OpDiscoverApplyWatchHits:
        return HandleDiscoverApplyWatchHits(pipe, r);
    case OpDiscoverGetEvidence:
        return HandleDiscoverGetEvidence(pipe, r);
    default: {
        std::vector<uint8_t> resp;
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    }
}

}  // namespace ipc
}  // namespace hdl
