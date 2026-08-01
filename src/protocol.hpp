#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace hdl {
namespace proto {

enum Op : uint32_t {
    OpPing          = 1,
    OpInjectDll     = 2,
    OpUnloadDll     = 92,
    OpReadMemory    = 3,
    OpWriteMemory   = 4,
    OpEnumRegions   = 5,
    OpEnumModules   = 6,
    OpSearchMemory  = 7,
    OpSetLogLevel   = 8,
    OpSearchCreate  = 9,
    OpSearchClose   = 10,
    OpSearchFirst   = 11,
    OpSearchNext    = 12,
    OpSearchGetHits = 13,
    OpSearchReset   = 14,
    OpJobCreate     = 15,
    OpJobCancel     = 16,
    OpJobClose      = 17,
    OpGetHealth     = 18,
    OpEnumThreads   = 19,
    OpPollEvents    = 20,
    OpResolveExport = 21,
    OpCallExport    = 22,
    OpCall          = 23,
    OpAlloc         = 24,
    OpFree          = 25,
    OpResolveRip    = 26,
    OpFollowPointers = 27,
    OpModuleBase    = 28,
    OpCallVtable    = 29,
    OpHookTrace     = 30,
    OpEnableHook    = 31,
    OpUnhook        = 32,
    OpPollHookHits  = 33,
    OpResolvePattern = 34,
    OpFindStringXrefs = 35,
    OpPointerScan   = 36,
    OpProbeStruct   = 37,
    OpDiscoverCreate = 38,
    OpDiscoverClose  = 39,
    OpDiscoverAddCandidate = 40,
    OpDiscoverConstraintScan = 41,
    OpDiscoverSynthesizePattern = 42,
    OpDiscoverPathConsensus = 43,
    OpDiscoverPathValidate = 44,
    OpDiscoverWatch = 45,
    OpDiscoverUnwatchAll = 46,
    OpDiscoverActionBegin = 47,
    OpDiscoverActionEnd = 48,
    OpDiscoverWatchRegion = 49,
    OpDiscoverGetHeat = 50,
    OpDiscoverRankFunctions = 51,
    OpDiscoverClusterType = 52,
    OpDiscoverGetCandidates = 53,
    /* Place */
    OpFindCaves = 54,
    OpAllocNear = 55,
    OpProtectMemory = 56,
    OpFlushICache = 57,
    /* Disasm backends */
    OpDisasmEnumBackends = 58,
    OpDisasmGetBackend = 59,
    OpDisasmSetBackend = 60,
    /* Code */
    OpInstrLen = 61,
    OpDisasm = 62,
    OpBuildStub = 63,
    OpPatchCreate = 64,
    OpPatchEnable = 65,
    OpPatchRemove = 66,
    OpPatchEnum = 67,
    /* PE */
    OpEnumSections = 68,
    OpEnumExports = 69,
    OpEnumImports = 70,
    /* Graph */
    OpEnumFunctions = 71,
    OpXrefsFrom = 72,
    /* Vtable / RTTI */
    OpWalkVtable = 73,
    OpQueryRttiName = 74,
    /* Watch */
    OpWatchHw = 75,
    OpWatchPage = 76,
    OpUnwatch = 77,
    OpEnumWatches = 78,
    /* Graph + watch extensions (smart RE platform) */
    OpResolveFunction = 79,
    OpXrefsTo = 80,
    OpWatchRefresh = 81,
    OpPollWatchHits = 82,
    OpHookImport = 83,
    OpDiscoverWatchImport = 84,
    OpInvalidateFnIndex = 85,
    OpDiscoverResetHeat = 86,
    OpDiscoverExport = 87,
    OpDiscoverImport = 88,
    OpDiscoverDiffObjects = 89,
    OpDiscoverApplyWatchHits = 90,
    OpDiscoverGetEvidence = 91,
    OpFingerprint = 93,
    OpShutdown = 94,
    OpTrackLoadedDll = 95,
    /* Pipe parity for former C-API-only controls */
    OpSetLogFile = 96,
    OpSetHealthVeh = 97,
    OpGetHealthVeh = 98,
    OpDiscoverScanValue = 99,
    OpHook = 100,
};

/* Optional request trailer / streaming response flags. */
enum : uint32_t {
    HDL_IPC_REQ_STREAM = 1u,
    HDL_IPC_MORE       = 1u,
};

inline void AppendBytes(std::vector<uint8_t>& buf, const void* data, size_t n) {
    const auto* p = static_cast<const uint8_t*>(data);
    buf.insert(buf.end(), p, p + n);
}

template <typename T>
inline void AppendPod(std::vector<uint8_t>& buf, const T& v) {
    AppendBytes(buf, &v, sizeof(T));
}

inline void AppendWString(std::vector<uint8_t>& buf, const wchar_t* s) {
    const uint32_t n = s ? static_cast<uint32_t>((wcslen(s) + 1) * sizeof(wchar_t)) : 0;
    AppendPod(buf, n);
    if (n) {
        AppendBytes(buf, s, n);
    }
}

inline void AppendString(std::vector<uint8_t>& buf, const char* s) {
    const uint32_t n = s ? static_cast<uint32_t>(strlen(s) + 1) : 0;
    AppendPod(buf, n);
    if (n) {
        AppendBytes(buf, s, n);
    }
}

struct Reader {
    const uint8_t* p = nullptr;
    size_t left = 0;

    explicit Reader(const std::vector<uint8_t>& buf) : p(buf.data()), left(buf.size()) {}
    Reader(const uint8_t* data, size_t n) : p(data), left(n) {}

    bool Take(void* out, size_t n) {
        if (left < n) {
            return false;
        }
        memcpy(out, p, n);
        p += n;
        left -= n;
        return true;
    }

    template <typename T>
    bool TakePod(T& out) {
        return Take(&out, sizeof(T));
    }

    bool TakeWString(std::wstring& out) {
        uint32_t n = 0;
        if (!TakePod(n) || n % sizeof(wchar_t) != 0 || left < n) {
            return false;
        }
        out.assign(reinterpret_cast<const wchar_t*>(p), n / sizeof(wchar_t));
        if (!out.empty() && out.back() == L'\0') {
            out.pop_back();
        }
        p += n;
        left -= n;
        return true;
    }

    bool TakeString(std::string& out) {
        uint32_t n = 0;
        if (!TakePod(n) || left < n) {
            return false;
        }
        out.assign(reinterpret_cast<const char*>(p), n ? n - 1 : 0);
        p += n;
        left -= n;
        return true;
    }
};

}  // namespace proto
}  // namespace hdl
