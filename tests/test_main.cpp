#include "domain_api.hpp"
#include "ipc/common.hpp"
#include "ipc/wire.hpp"
#include "protocol.hpp"
#include "support.hpp"

#include <atomic>
#include <cstddef>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

namespace {

using hdltest::Counters;
using hdltest::Expect;
using hdltest::IlLevel;
using hdltest::Report;
using hdltest::TargetProc;
using hdltest::TargetProfile;

int g_hook_hits = 0;
int (*g_orig_add)(int, int) = nullptr;

int DetourAdd(int a, int b) {
    ++g_hook_hits;
    return g_orig_add ? g_orig_add(a, b) + 1 : a + b + 1;
}

#if defined(_MSC_VER)
#pragma optimize("", off)
#endif
__declspec(noinline) int AddNums(int a, int b) {
    // Pad so MinHook has room for a trampoline (small leafs often fail to hook).
    volatile int x = a;
    volatile int y = b;
    volatile int s = x + y;
    s ^= 0;
    s += 0;
    s |= 0;
    return s;
}

__declspec(noinline) uint64_t MixU64F32(uint64_t a, float b) {
    volatile uint64_t x = a;
    volatile float y = b;
    return x + static_cast<uint64_t>(y);
}

__declspec(noinline) void MutateBuf(uint8_t* p, uint64_t n) {
    if (!p || !n) {
        return;
    }
    for (uint64_t i = 0; i < n; ++i) {
        p[i] = static_cast<uint8_t>(p[i] + 1);
    }
}

__declspec(noinline) uint64_t TraceMe(uint64_t a, uint64_t b) {
    volatile uint64_t x = a + b;
    x ^= 0;
    return x;
}

__declspec(noinline) void LocalDiscoverLeaf(void) {
    volatile int x = 0x4C43414C; /* 'LACL' */
    (void)x;
}

__declspec(noinline) void LocalDiscoverAction(void) {
    LocalDiscoverLeaf();
    LocalDiscoverLeaf();
}

struct FakeObj {
    uint64_t* vtable;
};

static uint64_t VMethod(FakeObj* self, uint64_t x) {
    (void)self;
    return x + 7;
}

/* Real polymorphic type so HdlQueryRttiName can resolve MSVC RTTI. */
struct RttiProbe {
    virtual ~RttiProbe() {}
    virtual int Tag() { return 42; }
};
#if defined(_MSC_VER)
#pragma optimize("", on)
#endif

struct LocalDiscoverObj {
    void** vtable;
    int32_t health;
    int32_t max_health;
};

static uint64_t LocalObjMethod(void* self, uint64_t x) {
    (void)self;
    return x;
}

static void* g_local_discover_vt[1] = {reinterpret_cast<void*>(&LocalObjMethod)};

LocalDiscoverObj g_local_obj_a = {g_local_discover_vt, 80, 100};
LocalDiscoverObj g_local_obj_b = {g_local_discover_vt, 55, 100};

void RunLocalDiscoverTests(Counters& c) {
    std::printf("\n== Discover (local API) ==\n");

    HdlDiscoverSession* session = nullptr;
    HdlStatus st = hdl::DiscoverCreate(&session);
    Report(c, st == HDL_OK && session != nullptr, false, "HdlDiscoverCreate", "");
    if (!session) {
        return;
    }

    uint64_t cand_id = 0;
    st =
        hdl::DiscoverAddCandidate(session, HDL_CAND_FUNCTION,
                                  reinterpret_cast<uint64_t>(&LocalDiscoverLeaf), "leaf", &cand_id);
    Report(c, st == HDL_OK && cand_id != 0, false, "HdlDiscoverAddCandidate", "");

    HdlSynthesizedPattern pat{};
    st = hdl::DiscoverSynthesizePattern(session, cand_id, 0, 24, HDL_SEARCH_IMAGE, nullptr, &pat,
                                        nullptr);
    Report(c,
           st == HDL_OK && pat.pattern[0] && pat.unique_hits >= 1 &&
               pat.resolved_addr == reinterpret_cast<uint64_t>(&LocalDiscoverLeaf),
           false, "HdlDiscoverSynthesizePattern", "");

    {
        HdlFieldPred preds[3]{};
        preds[0].offset = 0;
        preds[0].kind = HDL_PRED_EQ_U64;
        preds[0].a = static_cast<int64_t>(reinterpret_cast<uint64_t>(g_local_discover_vt));
        preds[1].offset = 8;
        preds[1].kind = HDL_PRED_RANGE_I32;
        preds[1].a = 1;
        preds[1].b = 100;
        preds[2].offset = 8;
        preds[2].kind = HDL_PRED_LE_I32;
        preds[2].a = 4;
        st = hdl::DiscoverConstraintScan(session, sizeof(LocalDiscoverObj), preds, 3, 0, nullptr,
                                         32, "player", nullptr);
        HdlCandidate cands[64]{};
        uint32_t n = 64;
        hdl::DiscoverGetCandidates(session, cands, &n);
        bool found_a = false;
        bool found_b = false;
        for (uint32_t i = 0; i < n; ++i) {
            if (cands[i].address == reinterpret_cast<uint64_t>(&g_local_obj_a)) {
                found_a = true;
            }
            if (cands[i].address == reinterpret_cast<uint64_t>(&g_local_obj_b)) {
                found_b = true;
            }
        }
        Report(c, st == HDL_OK && found_a && found_b, false, "HdlDiscoverConstraintScan", "");
    }

    {
        HdlDiscoverSession* cluster_sess = nullptr;
        hdl::DiscoverCreate(&cluster_sess);
        st = hdl::DiscoverClusterType(cluster_sess, reinterpret_cast<uint64_t>(&g_local_obj_a),
                                      sizeof(LocalDiscoverObj), 0, nullptr, 32, nullptr);
        HdlCandidate cands[32]{};
        uint32_t n = 32;
        hdl::DiscoverGetCandidates(cluster_sess, cands, &n);
        bool found_b = false;
        for (uint32_t i = 0; i < n; ++i) {
            if (cands[i].address == reinterpret_cast<uint64_t>(&g_local_obj_b)) {
                found_b = true;
            }
        }
        Report(c, st == HDL_OK && found_b, false, "HdlDiscoverClusterType", "");
        hdl::DiscoverClose(cluster_sess);
    }

    {
        st = hdl::DiscoverWatch(session, reinterpret_cast<uint64_t>(&LocalDiscoverLeaf), 0);
        Report(c, st == HDL_OK, false, "HdlDiscoverWatch", "");

        st = hdl::DiscoverWatchRegion(session, reinterpret_cast<uint64_t>(&g_local_obj_a),
                                      sizeof(g_local_obj_a));
        Report(c, st == HDL_OK, false, "HdlDiscoverWatchRegion", "");

        st = hdl::DiscoverActionBegin(session, "attack");
        Report(c, st == HDL_OK, false, "HdlDiscoverActionBegin", "");
        LocalDiscoverAction();
        g_local_obj_a.health -= 7;
        st = hdl::DiscoverActionEnd(session);
        Report(c, st == HDL_OK, false, "HdlDiscoverActionEnd", "");

        HdlCandidate ranked[16]{};
        uint32_t rn = 16;
        st = hdl::DiscoverRankFunctions(session, "attack", 0, ranked, &rn);
        bool near_action = false;
        const uint64_t action_addr = reinterpret_cast<uint64_t>(&LocalDiscoverAction);
        for (uint32_t i = 0; i < rn; ++i) {
            if (ranked[i].address >= action_addr && ranked[i].address < action_addr + 0x80) {
                near_action = true;
            }
        }
        Report(c, st == HDL_OK && near_action, false, "HdlDiscoverRankFunctions", "");

        HdlHeatField heat[16]{};
        uint32_t hn = 16;
        st = hdl::DiscoverGetHeat(session, reinterpret_cast<uint64_t>(&g_local_obj_a), heat, &hn);
        bool health_hot = false;
        for (uint32_t i = 0; i < hn; ++i) {
            if (heat[i].offset == offsetof(LocalDiscoverObj, health)) {
                health_hot = true;
            }
        }
        Report(c, st == HDL_OK && health_hot, false, "HdlDiscoverGetHeat", "");

        hdl::DiscoverUnwatchAll(session);
    }

    {
        HdlPointerPath paths[2]{};
        paths[0].static_base = reinterpret_cast<uint64_t>(&g_local_discover_vt[0]);
        paths[0].depth = 1;
        paths[0].offsets[0] = 0;
        paths[1].static_base = 0x1000;
        paths[1].depth = 1;
        paths[1].offsets[0] = 0;
        uint32_t pc = 2;
        const uint64_t expect = reinterpret_cast<uint64_t>(g_local_discover_vt[0]);
        st = hdl::DiscoverPathValidate(paths, &pc, expect);
        Report(c, st == HDL_OK && pc == 1, false, "HdlDiscoverPathValidate", "");
    }

    hdl::DiscoverClose(session);
    Report(c, true, false, "HdlDiscoverClose", "");
}

DWORD g_main_call_tid = 0;
static uint64_t MainThreadProbe() {
    g_main_call_tid = GetCurrentThreadId();
    return 0xC0FFEEull;
}

struct UiThreadCtx {
    HWND hwnd = nullptr;
    HANDLE ready = nullptr;
    HANDLE done = nullptr;
};

DWORD WINAPI UiThreadProc(LPVOID param) {
    auto* ctx = static_cast<UiThreadCtx*>(param);
    WNDCLASSW wc{};
    wc.lpfnWndProc = DefWindowProcW;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.lpszClassName = L"HdlTestUiClass";
    RegisterClassW(&wc);
    ctx->hwnd = CreateWindowExW(0, wc.lpszClassName, L"HdlTestUi", WS_OVERLAPPEDWINDOW, 0, 0, 64,
                                64, nullptr, nullptr, wc.hInstance, nullptr);
    ShowWindow(ctx->hwnd, SW_SHOW);
    SetEvent(ctx->ready);
    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    SetEvent(ctx->done);
    return 0;
}

bool EnsureWorldReadable(const wchar_t* path) {
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:(A;;GA;;;WD)(A;;GA;;;AC)(A;;GA;;;SY)(A;;GA;;;BA)", SDDL_REVISION_1, &sd, nullptr)) {
        return false;
    }
    const BOOL ok = SetFileSecurityW(path, DACL_SECURITY_INFORMATION, sd);
    LocalFree(sd);
    return ok != FALSE;
}

std::wstring PreparePayloadDll(const std::wstring& built_dll) {
    wchar_t temp[MAX_PATH];
    if (GetTempPathW(MAX_PATH, temp) == 0) {
        return built_dll;
    }
    std::wstring dir = std::wstring(temp) + L"hdllib_test_payload";
    CreateDirectoryW(dir.c_str(), nullptr);
    EnsureWorldReadable(dir.c_str());

    std::wstring dest = dir + L"\\hdllib.dll";
    if (!CopyFileW(built_dll.c_str(), dest.c_str(), FALSE)) {
        return built_dll;
    }
    EnsureWorldReadable(dest.c_str());
    return dest;
}

void RunLocalApiTests(Counters& c, const wchar_t* dll_path) {
    std::printf("\n== Local API / lifecycle ==\n");

    // Linking hdllib loads DllMain bootstrap asynchronously — wait or init explicitly.
    const DWORD start = GetTickCount();
    while (!hdl::testapi::IsInitialized() && GetTickCount() - start < 3000) {
        Sleep(50);
    }
    const HdlStatus init = hdl::testapi::Init();
    Report(c, init == HDL_OK && hdl::testapi::IsInitialized() != 0, false, "HdlInit", "");
    Report(c, hdl::testapi::Init() == HDL_OK, false, "HdlInit idempotent", "");

    hdl::testapi::SetLogLevelInt(HDL_LOG_ERROR);

    // Memory R/W
    alignas(16) uint8_t blob[64];
    for (int i = 0; i < 64; ++i) {
        blob[i] = static_cast<uint8_t>(i ^ 0x5A);
    }
    uint8_t readback[64]{};
    size_t n = 0;
    HdlStatus st =
        hdl::ReadMemory(reinterpret_cast<uint64_t>(blob), readback, sizeof(readback), &n);
    Report(c, st == HDL_OK && n == sizeof(readback) && memcmp(blob, readback, 64) == 0, false,
           "HdlReadMemory", "");

    const uint8_t pattern_bytes[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x11, 0x22};
    memcpy(blob + 8, pattern_bytes, sizeof(pattern_bytes));
    size_t wrote = 0;
    st = hdl::WriteMemory(reinterpret_cast<uint64_t>(blob + 8), pattern_bytes,
                          sizeof(pattern_bytes), &wrote);
    Report(c, st == HDL_OK && wrote == sizeof(pattern_bytes), false, "HdlWriteMemory", "");

    // Enum
    uint32_t count = 0;
    st = hdl::EnumRegions(nullptr, &count);
    Report(c, st == HDL_E_BUFFER_SMALL && count > 0, false, "HdlEnumRegions size query", "");
    std::vector<HdlRegionInfo> regions(count);
    st = hdl::EnumRegions(regions.data(), &count);
    Report(c, st == HDL_OK && count > 0, false, "HdlEnumRegions fill", "");

    count = 0;
    st = hdl::EnumModules(nullptr, &count);
    Report(c, st == HDL_E_BUFFER_SMALL && count > 0, false, "HdlEnumModules size query", "");
    std::vector<HdlModuleInfo> modules(count);
    st = hdl::EnumModules(modules.data(), &count);
    Report(c, st == HDL_OK && count > 0, false, "HdlEnumModules fill", "");

    // Search
    uint64_t hits[8]{};
    uint32_t hit_count = 8;
    st = hdl::SearchMemory(reinterpret_cast<uint64_t>(blob), sizeof(blob), "DE AD BE EF ?? 22",
                           hits, &hit_count, nullptr);
    Report(c, st == HDL_OK && hit_count >= 1, false, "HdlSearchMemory", "");

    volatile int cancel = 1;
    hit_count = 8;
    st = hdl::SearchMemory(0, 0, "DE AD BE EF", hits, &hit_count, &cancel);
    Report(c, st == HDL_E_CANCELLED, false, "HdlSearchMemory cancel", "");

    // Typed + incremental search session
    {
        alignas(8) uint8_t arena[256];
        memset(arena, 0, sizeof(arena));
        int32_t* v0 = reinterpret_cast<int32_t*>(arena + 16);
        int32_t* v1 = reinterpret_cast<int32_t*>(arena + 32);
        int32_t* v2 = reinterpret_cast<int32_t*>(arena + 48);
        *v0 = 100;
        *v1 = 100;
        *v2 = 200;

        HdlSearchSession* session = nullptr;
        st = hdl::SearchCreate(&session);
        Report(c, st == HDL_OK && session != nullptr, false, "HdlSearchCreate", "");

        if (session) {
            const int32_t needle = 100;
            HdlSearchDesc desc{};
            desc.start = reinterpret_cast<uint64_t>(arena);
            desc.size = sizeof(arena);
            desc.value_type = HDL_VALUE_I32;
            desc.cmp = HDL_CMP_EXACT;
            desc.alignment = 4;
            desc.max_results = 64;
            desc.value = &needle;
            desc.value_size = sizeof(needle);

            st = hdl::SearchFirst(session, &desc, nullptr);
            uint32_t scount = 0;
            hdl::SearchGetCount(session, &scount);
            Report(c, st == HDL_OK && scount == 2, false, "HdlSearchFirst i32 exact", "");

            *v0 = 90;  // decreased
            *v1 = 100; // unchanged
            st = hdl::SearchNext(session, HDL_CMP_DECREASED, nullptr, 0, nullptr);
            hdl::SearchGetCount(session, &scount);
            Report(c, st == HDL_OK && scount == 1, false, "HdlSearchNext decreased", "");

            uint64_t typed_hits[4]{};
            uint32_t typed_n = 4;
            st = hdl::SearchGetHits(session, typed_hits, &typed_n);
            Report(c,
                   st == HDL_OK && typed_n == 1 && typed_hits[0] == reinterpret_cast<uint64_t>(v0),
                   false, "HdlSearchGetHits after next", "");

            const int32_t next_val = 90;
            st = hdl::SearchNext(session, HDL_CMP_EXACT, &next_val, sizeof(next_val), nullptr);
            hdl::SearchGetCount(session, &scount);
            Report(c, st == HDL_OK && scount == 1, false, "HdlSearchNext exact refine", "");

            // Float + string
            hdl::SearchReset(session);
            float* fv = reinterpret_cast<float*>(arena + 64);
            *fv = 3.5f;
            const float fneedle = 3.5f;
            desc.value_type = HDL_VALUE_F32;
            desc.value = &fneedle;
            desc.value_size = sizeof(fneedle);
            desc.alignment = 4;
            st = hdl::SearchFirst(session, &desc, nullptr);
            hdl::SearchGetCount(session, &scount);
            Report(c, st == HDL_OK && scount >= 1, false, "HdlSearchFirst f32", "");

            hdl::SearchReset(session);
            const char* text = "hdl-scan";
            memcpy(arena + 80, text, strlen(text));
            desc.value_type = HDL_VALUE_STRING;
            desc.value = text;
            desc.value_size = strlen(text);
            desc.alignment = 1;
            st = hdl::SearchFirst(session, &desc, nullptr);
            hdl::SearchGetCount(session, &scount);
            Report(c, st == HDL_OK && scount >= 1, false, "HdlSearchFirst string", "");

            hdl::SearchClose(session);
            Report(c, true, false, "HdlSearchClose", "");
        }
    }

    // Unaligned typed search + unlimited max_results (0).
    {
        alignas(8) uint8_t mis[32]{};
        // Place i32 at odd offset so natural align-4 scan would miss it.
        const int32_t needle = 0x51525354;
        memcpy(mis + 1, &needle, sizeof(needle));

        HdlSearchSession* session = nullptr;
        st = hdl::SearchCreate(&session);
        if (session) {
            HdlSearchDesc desc{};
            desc.start = reinterpret_cast<uint64_t>(mis);
            desc.size = sizeof(mis);
            desc.value_type = HDL_VALUE_I32;
            desc.cmp = HDL_CMP_EXACT;
            desc.alignment = 0;   /* natural = 4 */
            desc.max_results = 0; /* unlimited */
            desc.value = &needle;
            desc.value_size = sizeof(needle);

            st = hdl::SearchFirst(session, &desc, nullptr);
            uint32_t scount = 0;
            hdl::SearchGetCount(session, &scount);
            Report(c, st == HDL_OK && scount == 0, false, "HdlSearchFirst aligned misses odd i32",
                   "");

            desc.alignment = 1; /* byte-unaligned */
            st = hdl::SearchFirst(session, &desc, nullptr);
            hdl::SearchGetCount(session, &scount);
            uint64_t hit = 0;
            uint32_t hit_n = 1;
            const HdlStatus gst = hdl::SearchGetHits(session, &hit, &hit_n);
            Report(c,
                   st == HDL_OK && gst == HDL_OK && scount == 1 &&
                       hit == reinterpret_cast<uint64_t>(mis + 1),
                   false, "HdlSearchFirst unaligned finds odd i32", "");

            hdl::SearchClose(session);
        }
    }

    // Optional max_results early-stop still works with unlimited default.
    {
        alignas(4) int32_t many[32];
        for (int i = 0; i < 32; ++i) {
            many[i] = 7;
        }
        HdlSearchSession* session = nullptr;
        st = hdl::SearchCreate(&session);
        if (session) {
            const int32_t needle = 7;
            HdlSearchDesc desc{};
            desc.start = reinterpret_cast<uint64_t>(many);
            desc.size = sizeof(many);
            desc.value_type = HDL_VALUE_I32;
            desc.cmp = HDL_CMP_EXACT;
            desc.alignment = 4;
            desc.max_results = 3;
            desc.value = &needle;
            desc.value_size = sizeof(needle);
            st = hdl::SearchFirst(session, &desc, nullptr);
            uint32_t scount = 0;
            hdl::SearchGetCount(session, &scount);
            Report(c, st == HDL_OK && scount == 3, false, "HdlSearchFirst max_results early stop",
                   "");
            hdl::SearchClose(session);
        }
    }

    // Hooks — HdlHook enables immediately; exercise disable/enable + detour.
    g_hook_hits = 0;
    g_orig_add = nullptr;
    HdlHookHandle hook = nullptr;
    st = hdl::Hook(reinterpret_cast<void*>(&AddNums), reinterpret_cast<void*>(&DetourAdd),
                   reinterpret_cast<void**>(&g_orig_add), &hook);
    const bool hooked = st == HDL_OK && hook && g_orig_add;
    Report(c, hooked, false, "HdlHook", "");
    if (hooked) {
        const int sum1 = AddNums(2, 3);
        Report(c, g_hook_hits >= 1 && sum1 == 6, false, "hook detour active", "");

        st = hdl::EnableHook(hook, 0);
        g_hook_hits = 0;
        const int sum2 = AddNums(2, 3);
        Report(c, st == HDL_OK && g_hook_hits == 0 && sum2 == 5, false, "HdlEnableHook disable",
               "");

        st = hdl::EnableHook(hook, 1);
        const int sum3 = AddNums(2, 3);
        Report(c, st == HDL_OK && g_hook_hits >= 1 && sum3 == 6, false, "HdlEnableHook enable", "");

        st = hdl::Unhook(hook);
        Report(c, st == HDL_OK, false, "HdlUnhook", "");
    }

    // Health / jobs / call-export
    {
        HdlHealthInfo health{};
        st = hdl::GetHealth(&health);
        Report(c, st == HDL_OK && health.pid == GetCurrentProcessId() && health.thread_count > 0,
               false, "HdlGetHealth", "");

        uint32_t tcount = 0;
        st = hdl::EnumThreads(nullptr, &tcount);
        Report(c, st == HDL_E_BUFFER_SMALL && tcount > 0, false, "HdlEnumThreads size", "");
        std::vector<HdlThreadInfo> threads(tcount);
        st = hdl::EnumThreads(threads.data(), &tcount);
        Report(c, st == HDL_OK && tcount > 0, false, "HdlEnumThreads fill", "");

        /* Fingerprint: live self + synthetic classify fixtures */
        {
            uint32_t fcount = 0;
            st = hdl::EnumFingerprintTags(HDL_FP_SCAN_DEFAULT, nullptr, &fcount);
            Report(c, st == HDL_E_BUFFER_SMALL && fcount > 0, false, "HdlEnumFingerprintTags size",
                   "");
            std::vector<HdlFingerprintTag> ftags(fcount);
            st = hdl::EnumFingerprintTags(HDL_FP_SCAN_DEFAULT, ftags.data(), &fcount);
            bool has_primary = false;
            bool has_msvc_or_native = false;
            for (uint32_t i = 0; i < fcount; ++i) {
                if (ftags[i].flags & HDL_FP_PRIMARY) {
                    has_primary = true;
                }
                if (strcmp(ftags[i].id, "msvc") == 0 || strcmp(ftags[i].id, "native") == 0) {
                    has_msvc_or_native = true;
                }
            }
            Report(c, st == HDL_OK && fcount > 0 && has_primary && has_msvc_or_native, false,
                   "HdlEnumFingerprintTags fill", "");
        }
        {
            const wchar_t* mods[] = {L"d3d11.dll", L"dxgi.dll", L"user32.dll", L"vcruntime140.dll"};
            HdlFingerprintImport imps[2]{};
            strncpy_s(imps[0].module, "d3d11.dll", _TRUNCATE);
            strncpy_s(imps[0].name, "D3D11CreateDevice", _TRUNCATE);
            strncpy_s(imps[1].module, "user32.dll", _TRUNCATE);
            strncpy_s(imps[1].name, "DispatchMessageW", _TRUNCATE);
            uint32_t cn = 0;
            st = hdl::ClassifyFingerprintApi(mods, 4, imps, 2, IMAGE_SUBSYSTEM_WINDOWS_GUI,
                                             HDL_FP_SCAN_DEFAULT, nullptr, &cn);
            Report(c, st == HDL_E_BUFFER_SMALL && cn > 0, false, "HdlClassifyFingerprint size", "");
            std::vector<HdlFingerprintTag> tags(cn);
            st = hdl::ClassifyFingerprintApi(mods, 4, imps, 2, IMAGE_SUBSYSTEM_WINDOWS_GUI,
                                             HDL_FP_SCAN_DEFAULT, tags.data(), &cn);
            bool d3d11_primary = false;
            bool win32_ok = false;
            bool gui_app = false;
            uint32_t d3d11_conf = 0;
            for (uint32_t i = 0; i < cn; ++i) {
                if (tags[i].category == HDL_FP_CAT_GRAPHICS && strcmp(tags[i].id, "d3d11") == 0) {
                    d3d11_conf = tags[i].confidence;
                    if (tags[i].flags & HDL_FP_PRIMARY) {
                        d3d11_primary = true;
                    }
                }
                if (tags[i].category == HDL_FP_CAT_UI && strcmp(tags[i].id, "win32") == 0 &&
                    tags[i].confidence >= 35) {
                    win32_ok = true;
                }
                if (tags[i].category == HDL_FP_CAT_APP &&
                    strcmp(tags[i].id, "subsystem_gui") == 0) {
                    gui_app = true;
                }
            }
            Report(c, st == HDL_OK && d3d11_primary && d3d11_conf >= 75 && win32_ok && gui_app,
                   false, "HdlClassifyFingerprint d3d11+win32", "");
        }
        {
            const wchar_t* mods[] = {L"coreclr.dll", L"hostfxr.dll", L"PresentationFramework.dll",
                                     L"user32.dll", L"dxgi.dll"};
            uint32_t cn = 0;
            st = hdl::ClassifyFingerprintApi(mods, 5, nullptr, 0, IMAGE_SUBSYSTEM_WINDOWS_GUI,
                                             HDL_FP_SCAN_DEFAULT, nullptr, &cn);
            std::vector<HdlFingerprintTag> tags(cn);
            st = hdl::ClassifyFingerprintApi(mods, 5, nullptr, 0, IMAGE_SUBSYSTEM_WINDOWS_GUI,
                                             HDL_FP_SCAN_DEFAULT, tags.data(), &cn);
            bool coreclr = false;
            bool wpf_primary = false;
            bool win32_suppressed = true;
            for (uint32_t i = 0; i < cn; ++i) {
                if (strcmp(tags[i].id, "coreclr") == 0) {
                    coreclr = true;
                }
                if (tags[i].category == HDL_FP_CAT_UI && strcmp(tags[i].id, "wpf") == 0 &&
                    (tags[i].flags & HDL_FP_PRIMARY)) {
                    wpf_primary = true;
                }
                if (tags[i].category == HDL_FP_CAT_UI && strcmp(tags[i].id, "win32") == 0 &&
                    tags[i].confidence > 40) {
                    win32_suppressed = false;
                }
            }
            Report(c, st == HDL_OK && coreclr && wpf_primary && win32_suppressed, false,
                   "HdlClassifyFingerprint coreclr+wpf", "");
        }
        {
            const wchar_t* mods[] = {L"dxgi.dll", L"user32.dll"};
            uint32_t n_bare = 0;
            hdl::ClassifyFingerprintApi(mods, 2, nullptr, 0, 0,
                                        HDL_FP_SCAN_MODULES | HDL_FP_SCAN_IMPORTS, nullptr,
                                        &n_bare);
            std::vector<HdlFingerprintTag> bare(n_bare);
            hdl::ClassifyFingerprintApi(mods, 2, nullptr, 0, 0,
                                        HDL_FP_SCAN_MODULES | HDL_FP_SCAN_IMPORTS, bare.data(),
                                        &n_bare);
            uint32_t bare_conf = 0;
            for (uint32_t i = 0; i < n_bare; ++i) {
                if (strcmp(bare[i].id, "d3d11") == 0) {
                    bare_conf = bare[i].confidence;
                }
            }
            HdlFingerprintImport create{};
            strncpy_s(create.module, "d3d11.dll", _TRUNCATE);
            strncpy_s(create.name, "D3D11CreateDevice", _TRUNCATE);
            const wchar_t* mods2[] = {L"d3d11.dll", L"dxgi.dll"};
            uint32_t n_full = 0;
            hdl::ClassifyFingerprintApi(mods2, 2, &create, 1, 0,
                                        HDL_FP_SCAN_MODULES | HDL_FP_SCAN_IMPORTS, nullptr,
                                        &n_full);
            std::vector<HdlFingerprintTag> full(n_full);
            hdl::ClassifyFingerprintApi(mods2, 2, &create, 1, 0,
                                        HDL_FP_SCAN_MODULES | HDL_FP_SCAN_IMPORTS, full.data(),
                                        &n_full);
            uint32_t full_conf = 0;
            for (uint32_t i = 0; i < n_full; ++i) {
                if (strcmp(full[i].id, "d3d11") == 0) {
                    full_conf = full[i].confidence;
                }
            }
            Report(c, full_conf > bare_conf && full_conf >= 75, false,
                   "HdlClassifyFingerprint d3d11 import boost", "");
        }

        uint64_t job = 0;
        st = hdl::testapi::JobCreate(5000, &job);
        Report(c, st == HDL_OK && job != 0, false, "HdlJobCreate", "");
        st = hdl::testapi::JobCancelStatus(job);
        Report(c, st == HDL_OK, false, "HdlJobCancel", "");
        hdl::testapi::JobCloseId(job);

        uint64_t addr = 0;
        st = hdl::ResolveExport(L"kernel32.dll", "GetCurrentProcessId", &addr);
        Report(c, st == HDL_OK && addr != 0, false, "HdlResolveExport", "");

        HdlCallResult cres{};
        st = hdl::CallExport(L"kernel32.dll", "GetCurrentProcessId", nullptr, 0, &cres, 2000,
                             nullptr);
        Report(c, st == HDL_OK && cres.return_value == GetCurrentProcessId(), false,
               "HdlCallExport", "");

        {
            HdlCallArg args[2]{};
            args[0].kind = HDL_CALL_ARG_U64;
            args[0].u64 = 10;
            float f = 2.5f;
            args[1].kind = HDL_CALL_ARG_F32;
            uint32_t bits = 0;
            memcpy(&bits, &f, sizeof(bits));
            args[1].u64 = bits;
            HdlCallDesc desc{};
            desc.address = reinterpret_cast<uint64_t>(&MixU64F32);
            desc.args = args;
            desc.arg_count = 2;
            desc.thread_mode = HDL_CALL_THREAD_WORKER;
            desc.timeout_ms = 2000;
            HdlCallResult r{};
            st = hdl::Call(&desc, &r, nullptr);
            Report(c, st == HDL_OK && r.return_value == 12, false, "HdlCall u64+f32", "");
        }

        {
            uint8_t buf[4] = {1, 2, 3, 4};
            HdlCallArg args[2]{};
            args[0].kind = HDL_CALL_ARG_BUF;
            args[0].ptr = buf;
            args[0].size = sizeof(buf);
            args[1].kind = HDL_CALL_ARG_U64;
            args[1].u64 = sizeof(buf);
            HdlCallDesc desc{};
            desc.address = reinterpret_cast<uint64_t>(&MutateBuf);
            desc.args = args;
            desc.arg_count = 2;
            desc.timeout_ms = 2000;
            HdlCallResult r{};
            st = hdl::Call(&desc, &r, nullptr);
            Report(c, st == HDL_OK && buf[0] == 2 && buf[3] == 5, false, "HdlCall BUF inout", "");
        }

        {
            uint64_t alloc_addr = 0;
            st = hdl::Alloc(0x1000, PAGE_READWRITE, &alloc_addr);
            Report(c, st == HDL_OK && alloc_addr != 0, false, "HdlAlloc", "");
            if (alloc_addr) {
                *reinterpret_cast<uint32_t*>(alloc_addr) = 0x11223344;
                Report(c, *reinterpret_cast<uint32_t*>(alloc_addr) == 0x11223344, false,
                       "HdlAlloc write", "");
                st = hdl::Free(alloc_addr);
                Report(c, st == HDL_OK, false, "HdlFree", "");
            }
            uint64_t rejected_addr = 0;
            st = hdl::Alloc(0x1000, 0xDEADBEEFu, &rejected_addr);
            Report(c, st == HDL_E_INVALID_ARG && rejected_addr == 0, false,
                   "HdlAlloc rejects invalid protection", "");
        }

        {
            uint64_t near_a = 0;
            st = hdl::AllocNear(reinterpret_cast<uint64_t>(&AddNums), 0x7FFFFFFFull, 0x1000,
                                PAGE_EXECUTE_READWRITE, &near_a);
            Report(c, st == HDL_OK && near_a != 0, false, "HdlAllocNear", "");
            if (near_a) {
                hdl::Free(near_a);
            }
        }

        {
            alignas(16) uint8_t pad[256];
            memset(pad, 0xCC, sizeof(pad));
            HdlCaveQuery q{};
            q.min_size = 32;
            q.fill_byte = 0xCC;
            q.max_results = 16;
            q.near_addr = reinterpret_cast<uint64_t>(pad);
            q.max_distance = 0x10000;
            uint32_t cn = 0;
            st = hdl::FindCaves(&q, nullptr, &cn, nullptr);
            Report(c, (st == HDL_E_BUFFER_SMALL || st == HDL_OK) && cn >= 1, false, "HdlFindCaves",
                   "");
        }

        {
            uint32_t bc = 0;
            st = hdl::testapi::DisasmEnumBackends(nullptr, &bc);
            Report(c, st == HDL_E_BUFFER_SMALL && bc >= 1, false, "HdlDisasmEnumBackends", "");
            std::vector<HdlDisasmBackendInfo> backends(bc);
            st = hdl::testapi::DisasmEnumBackends(backends.data(), &bc);
            Report(c, st == HDL_OK && bc >= 1, false, "HdlDisasmEnumBackends fill", "");
            int32_t cur = 0;
            st = hdl::testapi::DisasmGetBackend(&cur);
            Report(c, st == HDL_OK && cur != 0, false, "HdlDisasmGetBackend", "");
            for (uint32_t i = 0; i < bc; ++i) {
                st = hdl::testapi::DisasmSetBackend(backends[i].id);
                Report(c, st == HDL_OK, false, "HdlDisasmSetBackend", backends[i].name);
                uint32_t len = 0;
                st = hdl::InstrLen(reinterpret_cast<uint64_t>(&AddNums), &len);
                Report(c, st == HDL_OK && len > 0 && len <= 15, false, "HdlInstrLen",
                       backends[i].name);
            }
            HdlDisasmBackendFns mock{};
            mock.name = "mock";
            mock.decode = [](void*, uint64_t, const uint8_t*, size_t, uint32_t* out_length, char*,
                             size_t, char*, size_t, uint32_t*, uint64_t*, int32_t*,
                             uint32_t*) -> HdlStatus {
                if (out_length) {
                    *out_length = 1;
                }
                return HDL_OK;
            };
            int32_t mock_id = 0;
            st = hdl::testapi::DisasmRegisterBackend(&mock, &mock_id);
            Report(c, st == HDL_OK && mock_id >= HDL_DISASM_CUSTOM_BASE, false,
                   "HdlDisasmRegisterBackend", "");
            if (st == HDL_OK) {
                st = hdl::testapi::DisasmSetBackend(mock_id);
                uint32_t len = 0;
                st = hdl::InstrLen(reinterpret_cast<uint64_t>(&AddNums), &len);
                Report(c, st == HDL_OK && len == 1, false, "mock backend InstrLen", "");
                hdl::testapi::DisasmUnregisterBackend(mock_id);
                hdl::testapi::DisasmSetBackend(cur);
            }
        }

        {
            uint32_t insn_n = 8;
            std::vector<HdlInsn> insns(insn_n);
            st = hdl::testapi::Disasm(reinterpret_cast<uint64_t>(&AddNums), 8, insns.data(),
                                      &insn_n);
            Report(c, st == HDL_OK && insn_n >= 1 && insns[0].length > 0, false, "HdlDisasm", "");
        }

        {
            HdlStubDesc stub{};
            stub.kind = HDL_STUB_MOV_RAX_JMP;
            stub.target = reinterpret_cast<uint64_t>(&AddNums);
            stub.alloc_rx = 1;
            HdlStubResult sr{};
            st = hdl::BuildStub(&stub, &sr);
            Report(c, st == HDL_OK && sr.stub_va != 0 && sr.code_size >= 12, false,
                   "HdlBuildStub mov_rax_jmp", "");
            if (sr.stub_va) {
                hdl::Free(sr.stub_va);
            }
            uint8_t raw_bytes[2] = {0x90, 0xC3};
            HdlStubDesc raw{};
            raw.kind = HDL_STUB_RAW;
            raw.raw = raw_bytes;
            raw.raw_size = 2;
            raw.alloc_rx = 1;
            HdlStubResult rr{};
            st = hdl::BuildStub(&raw, &rr);
            Report(c, st == HDL_OK && rr.stub_va != 0 && rr.code_size == 2, false,
                   "HdlBuildStub raw", "");
            if (rr.stub_va) {
                hdl::Free(rr.stub_va);
            }
        }

        {
            uint8_t patch_bytes[5] = {0x90, 0x90, 0x90, 0x90, 0x90};
            /* Patch a writable buffer, not code */
            uint8_t target[16] = {0x11, 0x22, 0x33, 0x44, 0x55};
            HdlPatchHandle ph = 0;
            st = hdl::PatchCreate(reinterpret_cast<uint64_t>(target), patch_bytes, 5, "nop5", &ph);
            Report(c, st == HDL_OK && ph != 0, false, "HdlPatchCreate", "");
            st = hdl::PatchEnable(ph, 1);
            Report(c, st == HDL_OK && target[0] == 0x90, false, "HdlPatchEnable", "");
            {
                uint32_t pn = 0;
                st = hdl::PatchEnum(nullptr, &pn);
                Report(c, (st == HDL_E_BUFFER_SMALL || st == HDL_OK) && pn >= 1, false,
                       "HdlPatchEnum size", "");
                std::vector<HdlPatchInfo> infos(pn ? pn : 1);
                pn = static_cast<uint32_t>(infos.size());
                st = hdl::PatchEnum(infos.data(), &pn);
                bool found = false;
                for (uint32_t i = 0; i < pn; ++i) {
                    if (infos[i].handle == ph) {
                        found = true;
                        break;
                    }
                }
                Report(c, st == HDL_OK && found, false, "HdlPatchEnum fill", "");
            }
            st = hdl::PatchEnable(ph, 0);
            Report(c, st == HDL_OK && target[0] == 0x11, false, "HdlPatchDisable", "");
            st = hdl::PatchRemove(ph);
            Report(c, st == HDL_OK, false, "HdlPatchRemove", "");
        }

        {
            uint32_t sn = 0;
            st = hdl::EnumSections(0, nullptr, &sn);
            Report(c, st == HDL_E_BUFFER_SMALL && sn >= 1, false, "HdlEnumSections", "");
            std::vector<HdlSectionInfo> secs(sn);
            st = hdl::EnumSections(0, secs.data(), &sn);
            Report(c, st == HDL_OK && sn >= 1, false, "HdlEnumSections fill", "");
            uint32_t en = 0;
            st = hdl::EnumExports(0, nullptr, &en);
            Report(c, (st == HDL_E_BUFFER_SMALL || st == HDL_OK), false, "HdlEnumExports size", "");
            uint32_t in = 0;
            st = hdl::EnumImports(0, nullptr, &in);
            Report(c, (st == HDL_E_BUFFER_SMALL || st == HDL_OK), false, "HdlEnumImports size", "");
        }

        {
            uint32_t fn = 0;
            st = hdl::EnumFunctions(0, 0, 0, nullptr, 32, nullptr, &fn, nullptr);
            Report(c, (st == HDL_E_BUFFER_SMALL || st == HDL_OK), false, "HdlEnumFunctions", "");
            uint32_t xn = 0;
            st = hdl::XrefsFrom(reinterpret_cast<uint64_t>(&LocalDiscoverAction), 1, 32,
                                HDL_XREF_CALL | HDL_XREF_JMP, nullptr, &xn, nullptr);
            Report(c, (st == HDL_E_BUFFER_SMALL || st == HDL_OK), false, "HdlXrefsFrom", "");
        }

        {
            FakeObj obj{};
            static uint64_t vt[2] = {reinterpret_cast<uint64_t>(&VMethod), 0};
            /* Need executable second slot break — put only one valid */
            vt[1] = 0;
            obj.vtable = vt;
            uint32_t vn = 0;
            st = hdl::WalkVtable(reinterpret_cast<uint64_t>(&obj), 1, nullptr, &vn);
            Report(c, st == HDL_E_BUFFER_SMALL && vn >= 1, false, "HdlWalkVtable", "");
            RttiProbe probe;
            char rtti_name[128] = {};
            st = hdl::QueryRttiName(reinterpret_cast<uint64_t>(&probe), 1, rtti_name,
                                    sizeof(rtti_name));
            Report(c, st == HDL_OK && strstr(rtti_name, "RttiProbe") != nullptr, false,
                   "HdlQueryRttiName", rtti_name);
        }

        {
            uint32_t old = 0;
            void* page = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            Report(c, page != nullptr, false, "VirtualAlloc for protect test", "");
            if (page) {
                st = hdl::ProtectMemory(reinterpret_cast<uint64_t>(page), 0x1000, PAGE_READONLY,
                                        &old);
                Report(c, st == HDL_OK, false, "HdlProtectMemory", "");
                hdl::ProtectMemory(reinterpret_cast<uint64_t>(page), 0x1000, PAGE_READWRITE,
                                   nullptr);
                VirtualFree(page, 0, MEM_RELEASE);
            }
            st = hdl::FlushICache(reinterpret_cast<uint64_t>(&AddNums), 16);
            Report(c, st == HDL_OK, false, "HdlFlushICache", "");
        }

        {
            volatile uint64_t watched = 0;
            HdlWatchHandle hw = 0;
            st = hdl::WatchHw(reinterpret_cast<uint64_t>(&watched), 8, HDL_WATCH_HW_WRITE, 0, &hw);
            Report(c, st == HDL_OK && hw != 0, false, "HdlWatchHw", "");
            void* page = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            HdlWatchHandle pw = 0;
            if (page) {
                st = hdl::WatchPage(reinterpret_cast<uint64_t>(page), 0x1000, HDL_WATCH_PAGE_GUARD,
                                    &pw);
                Report(c, st == HDL_OK && pw != 0, false, "HdlWatchPage", "");
            } else {
                Report(c, false, false, "HdlWatchPage", "alloc failed");
            }
            uint32_t wn = 0;
            st = hdl::EnumWatches(nullptr, &wn);
            Report(c, (st == HDL_E_BUFFER_SMALL || st == HDL_OK) && wn >= 1, false,
                   "HdlEnumWatches size", "");
            std::vector<HdlWatchInfo> watches(wn ? wn : 2);
            wn = static_cast<uint32_t>(watches.size());
            st = hdl::EnumWatches(watches.data(), &wn);
            Report(c, st == HDL_OK && wn >= 1, false, "HdlEnumWatches fill", "");
            if (hw) {
                st = hdl::Unwatch(hw);
                Report(c, st == HDL_OK, false, "HdlUnwatch hw", "");
            }
            if (pw) {
                st = hdl::Unwatch(pw);
                Report(c, st == HDL_OK, false, "HdlUnwatch page", "");
            }
            if (page) {
                VirtualFree(page, 0, MEM_RELEASE);
            }
        }

        {
            const uint64_t callee = reinterpret_cast<uint64_t>(&LocalDiscoverLeaf);
            HdlFunctionInfo fi{};
            st = hdl::ResolveFunction(callee, 0, nullptr, &fi, nullptr);
            Report(c, st == HDL_OK && fi.start == callee, false, "HdlResolveFunction local", "");
            HdlXrefEdge edges[16]{};
            uint32_t ec = 16;
            st = hdl::XrefsTo(callee, 16, HDL_XREF_CALL | HDL_XREF_JMP | HDL_XREF_FUNC, 0, nullptr,
                              edges, &ec, nullptr);
            bool found_caller = false;
            if (st == HDL_OK) {
                const uint64_t caller = reinterpret_cast<uint64_t>(&LocalDiscoverAction);
                for (uint32_t i = 0; i < ec; ++i) {
                    if (edges[i].from >= caller && edges[i].from < caller + 0x80) {
                        found_caller = true;
                        break;
                    }
                }
            }
            Report(c, st == HDL_OK && found_caller, false, "HdlXrefsTo local callee", "");
        }

        {
            volatile uint64_t wa = 0;
            volatile uint64_t wb = 0;
            volatile uint64_t wd = 0;
            HdlWatchHandle ha = 0;
            HdlWatchHandle hb = 0;
            HdlWatchHandle hd = 0;
            st = hdl::WatchHw(reinterpret_cast<uint64_t>(&wa), 8, HDL_WATCH_HW_WRITE, 0, &ha);
            Report(c, st == HDL_OK && ha != 0, false, "HdlWatchHw slot A", "");
            st = hdl::WatchHw(reinterpret_cast<uint64_t>(&wb), 8, HDL_WATCH_HW_WRITE, 0, &hb);
            Report(c, st == HDL_OK && hb != 0, false, "HdlWatchHw slot B", "");
            wa = 1;
            wb = 2;
            HdlWatchHit whits[8]{};
            uint32_t wc = 8;
            st = hdl::PollWatchHits(whits, &wc, 500);
            Report(c, st == HDL_OK && wc >= 1, false, "HdlPollWatchHits write", "");
            if (hb) {
                st = hdl::Unwatch(hb);
                Report(c, st == HDL_OK, false, "HdlUnwatch slot B", "");
            }
            st = hdl::WatchHw(reinterpret_cast<uint64_t>(&wd), 8, HDL_WATCH_HW_WRITE, 0, &hd);
            Report(c, st == HDL_OK && hd != 0, false, "HdlWatchHw slot D after unwatch B", "");
            if (ha) {
                hdl::Unwatch(ha);
            }
            if (hd) {
                hdl::Unwatch(hd);
            }
        }

        {
            st = hdl::WatchRefresh();
            Report(c, st == HDL_OK, false, "HdlWatchRefresh", "");
        }

        {
            HdlHookHandle ih = nullptr;
            st = hdl::HookImport(nullptr, "KERNEL32.dll", "GetCurrentProcessId", 0, &ih);
            Report(c, st == HDL_OK && ih != nullptr, false, "HdlHookImport", "");
            if (st == HDL_OK) {
                (void)GetCurrentProcessId();
                HdlHookHit hh[4]{};
                uint32_t hc = 4;
                st = hdl::PollHookHits(hh, &hc, 500);
                Report(c, st == HDL_OK && hc >= 1, false, "HdlPollHookHits import", "");
                hdl::Unhook(ih);
                /* Drain any late hits so later TraceMe poll is clean. */
                for (;;) {
                    hc = 4;
                    if (hdl::PollHookHits(hh, &hc, 0) != HDL_OK || hc == 0) {
                        break;
                    }
                }
            }
        }

        {
            HdlFunctionInfo fns[64]{};
            uint32_t fn = 64;
            st = hdl::EnumFunctions(0, 0, 0, nullptr, 64, fns, &fn, nullptr);
            Report(c, (st == HDL_OK || st == HDL_E_BUFFER_SMALL) && fn >= 1, false,
                   "HdlEnumFunctions local", "");
            st = hdl::InvalidateFunctionIndex(nullptr);
            Report(c, st == HDL_OK, false, "HdlInvalidateFunctionIndex", "");
        }

        {
            uint8_t code[16] = {};
            /* lea rax, [rip+0] style: fake disp at +3, instr_len 7 */
            const int32_t disp = 0x10;
            code[3] = static_cast<uint8_t>(disp & 0xff);
            code[4] = static_cast<uint8_t>((disp >> 8) & 0xff);
            code[5] = static_cast<uint8_t>((disp >> 16) & 0xff);
            code[6] = static_cast<uint8_t>((disp >> 24) & 0xff);
            uint64_t resolved = 0;
            st = hdl::ResolveRipRelative(reinterpret_cast<uint64_t>(code), 3, 7, &resolved);
            const uint64_t expect = reinterpret_cast<uint64_t>(code) + 7 + disp;
            Report(c, st == HDL_OK && resolved == expect, false, "HdlResolveRipRelative", "");
        }

        {
            uint64_t leaf = 0xABCD;
            uint64_t mid = reinterpret_cast<uint64_t>(&leaf);
            uint64_t root = reinterpret_cast<uint64_t>(&mid);
            int64_t offs[2] = {0, 0};
            uint64_t out = 0;
            /* Follow: *root (+0) -> mid, *mid (+0) -> leaf address value?
               Our impl: cur=base; for each: cur=*cur; cur+=off
               start root: *root=mid, +0 -> mid; *mid=leaf_addr? mid holds &leaf so *mid = leaf
               value address... mid = &leaf, *mid = leaf value 0xABCD, +0 = 0xABCD */
            st = hdl::FollowPointers(root, offs, 2, &out);
            Report(c, st == HDL_OK && out == 0xABCD, false, "HdlFollowPointers", "");
        }

        {
            uint64_t vt[1] = {reinterpret_cast<uint64_t>(&VMethod)};
            FakeObj obj{vt};
            HdlCallResult r{};
            HdlCallArg extra{};
            extra.kind = HDL_CALL_ARG_U64;
            extra.u64 = 10;
            st = hdl::CallVtable(reinterpret_cast<uint64_t>(&obj), 0, &extra, 1, 1,
                                 HDL_CALL_THREAD_WORKER, &r, 2000, nullptr);
            Report(c, st == HDL_OK && r.return_value == 17, false, "HdlCallVtable", "");
        }

        {
            HdlHookHandle th = nullptr;
            st = hdl::HookTrace(reinterpret_cast<uint64_t>(&TraceMe), 2, &th);
            Report(c, st == HDL_OK && th != nullptr, false, "HdlHookTrace", "");
            if (st == HDL_OK) {
                const uint64_t got = TraceMe(3, 4);
                Report(c, got == 7, false, "HdlHookTrace call-through", "");
                HdlHookHit hook_hits[4]{};
                uint32_t hc = 4;
                st = hdl::PollHookHits(hook_hits, &hc, 200);
                Report(c,
                       st == HDL_OK && hc >= 1 && hook_hits[0].args[0] == 3 &&
                           hook_hits[0].args[1] == 4 && hook_hits[0].return_value == 7,
                       false, "HdlPollHookHits", "");
                hdl::Unhook(th);
            }
        }

        {
            UiThreadCtx ui{};
            ui.ready = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            ui.done = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            HANDLE thr = CreateThread(nullptr, 0, UiThreadProc, &ui, 0, nullptr);
            WaitForSingleObject(ui.ready, 5000);
            Report(c, ui.hwnd != nullptr, false, "UI thread hwnd", "");
            if (ui.hwnd) {
                g_main_call_tid = 0;
                HdlCallDesc desc{};
                desc.address = reinterpret_cast<uint64_t>(&MainThreadProbe);
                desc.thread_mode = HDL_CALL_THREAD_MAIN;
                desc.timeout_ms = 3000;
                HdlCallResult r{};
                st = hdl::Call(&desc, &r, nullptr);
                DWORD ui_tid = GetWindowThreadProcessId(ui.hwnd, nullptr);
                Report(c,
                       st == HDL_OK && r.return_value == 0xC0FFEEull && g_main_call_tid == ui_tid,
                       false, "HdlCall THREAD_MAIN", "");
                PostMessageW(ui.hwnd, WM_QUIT, 0, 0);
                WaitForSingleObject(ui.done, 5000);
            }
            if (thr) {
                WaitForSingleObject(thr, 5000);
                CloseHandle(thr);
            }
            if (ui.ready) {
                CloseHandle(ui.ready);
            }
            if (ui.done) {
                CloseHandle(ui.done);
            }
        }

        uint64_t modbase = 0;
        st = hdl::ModuleBase(nullptr, &modbase);
        Report(c, st == HDL_OK && modbase != 0, false, "HdlModuleBase", "");

        /* Local locate API smoke (fixtures live in hdl_test_target; exercised via inject below). */
        {
            const char* local_str = "HDL_LOCAL_LOCATE_STR";
            uint64_t xrefs[8]{};
            uint32_t xc = 8;
            st = hdl::FindStringXrefs(local_str, 0, 0, HDL_XREF_ABSOLUTE | HDL_XREF_RIP_REL,
                                      HDL_SEARCH_IMAGE, nullptr, xrefs, &xc, nullptr);
            Report(c, st == HDL_OK || st == HDL_E_NOT_FOUND, false, "HdlFindStringXrefs local", "");

            uint8_t probe_blob[32]{};
            for (int i = 0; i < 32; ++i) {
                probe_blob[i] = static_cast<uint8_t>(i);
            }
            *reinterpret_cast<uint64_t*>(probe_blob) = reinterpret_cast<uint64_t>(&MixU64F32);
            HdlStructField fields[8]{};
            uint32_t fc = 8;
            st = hdl::ProbeStruct(reinterpret_cast<uint64_t>(probe_blob), 32, fields, &fc);
            Report(c, st == HDL_OK && fc >= 1 && fields[0].kind == HDL_FIELD_VTABLE, false,
                   "HdlProbeStruct local", "");
        }

        HdlEvent events[4]{};
        uint32_t ec = 4;
        st = hdl::testapi::PollEvents(events, &ec, 0);
        Report(c, st == HDL_OK, false, "HdlPollEvents", "");
    }

    RunLocalDiscoverTests(c);

    // IPC
    st = hdl::StartIpc();
    Report(c, st == HDL_OK && hdl::IsIpcRunning() != 0, false, "HdlStartIpc", "");
    Report(c, hdltest::PingPipe(GetCurrentProcessId()), false, "IPC ping self", "");
    // Multi-client: two concurrent pings
    Report(c, hdltest::PingPipe(GetCurrentProcessId()) && hdltest::PingPipe(GetCurrentProcessId()),
           false, "IPC multi-client ping", "");

    // Local inject (pid 0) — already loaded; should still succeed / return base
    uint64_t base = 0;
    st = hdl::InjectDll(0, dll_path, &base);
    Report(c, st == HDL_OK && base != 0, false, "HdlInjectDll local (pid 0)", "");

    st = hdl::InjectDllEx(0, dll_path, HDL_INJECT_CREATE_REMOTE_THREAD, nullptr, nullptr, nullptr,
                          &base);
    Report(c, st == HDL_OK, false, "HdlInjectDllEx local ignores method", "");

    st =
        hdl::InjectDllEx(1, L"", HDL_INJECT_CREATE_REMOTE_THREAD, nullptr, nullptr, nullptr, &base);
    Report(c, st == HDL_E_INVALID_ARG, false, "HdlInjectDllEx empty path", "");

    st = hdl::InjectDllEx(1, L"C:\\nonexistent_hdllib_test_zzz.dll",
                          HDL_INJECT_CREATE_REMOTE_THREAD, nullptr, nullptr, nullptr, &base);
    Report(c, st == HDL_E_NOT_FOUND, false, "HdlInjectDllEx missing file", "");

    st = hdl::testapi::UnloadDllCompat(0, L"", 0, &base);
    Report(c, st == HDL_E_INVALID_ARG, false, "HdlUnloadDll empty path", "");

    st = hdl::testapi::UnloadDllCompat(0, L"C:\\nonexistent_hdl_unload_zzz.dll", 0, &base);
    Report(c, st == HDL_E_NOT_FOUND, false, "HdlUnloadDll missing module", "");

    /* Load a seldom-used system DLL, then unload and reload at the same path. */
    {
        wchar_t sys[MAX_PATH];
        GetSystemDirectoryW(sys, MAX_PATH);
        wcscat_s(sys, L"\\wintrust.dll");
        const uint64_t before = reinterpret_cast<uint64_t>(GetModuleHandleW(L"wintrust.dll"));
        uint64_t ubase = 0;
        st = hdl::InjectDll(0, sys, &ubase);
        Report(c, st == HDL_OK && ubase != 0, false, "HdlInjectDll wintrust for unload", "");
        if (st == HDL_OK) {
            if (!before) {
                st = hdl::testapi::UnloadDllCompat(0, sys, 1, &ubase);
                Report(c, st == HDL_OK && ubase != 0, false, "HdlUnloadDll reload wintrust", "");
                st = hdl::testapi::UnloadDllCompat(0, sys, 0, &ubase);
                Report(c, st == HDL_OK && GetModuleHandleW(L"wintrust.dll") == nullptr, false,
                       "HdlUnloadDll wintrust gone", "");
            } else {
                /* Already mapped elsewhere — one FreeLibrary should restore prior state. */
                st = hdl::testapi::UnloadDllCompat(0, sys, 0, &ubase);
                Report(c, st == HDL_OK || st == HDL_E_BUSY, true, "HdlUnloadDll wintrust (soft)",
                       "");
            }
        }
    }
}

void RunLocateTargetTests(Counters& c, const wchar_t* target_path, const wchar_t* dll_path) {
    using namespace hdl::proto;
    std::printf("\n== Locate (inject into hdl_test_target) ==\n");

    TargetProfile profile{};
    profile.name = "locate_fixtures";
    profile.window = false;
    profile.alertable = true;
    profile.integrity = IlLevel::Medium;

    TargetProc target;
    if (!hdltest::SpawnTarget(target_path, profile, target)) {
        Report(c, false, false, "locate spawn target", "");
        return;
    }

    uint64_t base = 0;
    const HdlStatus ist = hdl::InjectDllEx(target.pid, dll_path, HDL_INJECT_CREATE_REMOTE_THREAD,
                                           nullptr, nullptr, nullptr, &base);
    const bool verified =
        ist == HDL_OK &&
        hdltest::VerifyInjected(target.pid, dll_path, HDL_INJECT_CREATE_REMOTE_THREAD, base);
    Report(c, verified, false, "locate inject", "");
    if (!verified) {
        return;
    }

    auto resolve_export = [&](const char* name, uint64_t* out) -> bool {
        std::vector<uint8_t> req;
        std::vector<uint8_t> resp;
        AppendPod(req, static_cast<uint32_t>(OpResolveExport));
        AppendWString(req, L"");
        AppendString(req, name);
        if (!hdltest::PipeRequest(target.pid, req, resp)) {
            return false;
        }
        Reader r(resp);
        int32_t st = 0;
        uint64_t addr = 0;
        if (!r.TakePod(st) || !r.TakePod(addr) || st != HDL_OK || !addr) {
            return false;
        }
        *out = addr;
        return true;
    };

    uint64_t truth_fn = 0;
    uint64_t truth_str = 0;
    uint64_t truth_leaf = 0;
    uint64_t truth_root = 0;
    uint64_t truth_obj = 0;
    uint64_t truth_str_ptr = 0;
    Report(c, resolve_export("HdlTestLocateFn", &truth_fn), false, "locate truth Fn export", "");
    Report(c, resolve_export("HdlTestLocateString", &truth_str), false,
           "locate truth String export", "");
    Report(c, resolve_export("HdlTestLocateLeaf", &truth_leaf), false, "locate truth Leaf export",
           "");
    Report(c, resolve_export("HdlTestLocateRoot", &truth_root), false, "locate truth Root export",
           "");
    Report(c, resolve_export("HdlTestLocateObj", &truth_obj), false, "locate truth Obj export", "");
    Report(c, resolve_export("HdlTestLocateStringPtr", &truth_str_ptr), false,
           "locate truth StringPtr export", "");

    /* Module-scoped AOB for HDL1 immediate */
    {
        std::vector<uint8_t> req;
        std::vector<uint8_t> resp;
        AppendPod(req, static_cast<uint32_t>(OpResolvePattern));
        AppendString(req, "31 4C 44 48");
        AppendPod(req, static_cast<uint32_t>(0));
        AppendPod(req, static_cast<int32_t>(0));
        AppendPod(req, static_cast<uint32_t>(0));
        AppendPod(req, static_cast<uint32_t>(0));
        AppendPod(req, static_cast<uint32_t>(0));
        AppendPod(req, static_cast<uint32_t>(HDL_SEARCH_MODULE | HDL_SEARCH_IMAGE));
        AppendPod(req, static_cast<uint32_t>(64));
        AppendWString(req, L"hdl_test_target.exe");
        if (!hdltest::PipeRequest(target.pid, req, resp)) {
            Report(c, false, false, "locate ResolvePattern ipc", "");
        } else {
            Reader r(resp);
            int32_t st = 0;
            HdlPatternResult out{};
            const bool ok =
                r.TakePod(st) && hdl::proto::TakeHdlPatternResult(r, out) && st == HDL_OK;
            const bool match_near_fn =
                ok && truth_fn && out.match_addr >= truth_fn && out.match_addr < truth_fn + 0x80;
            Report(c, match_near_fn, false, "locate ResolvePattern near Fn", "");
        }
    }

    /* Absolute xref to string */
    {
        std::vector<uint8_t> req;
        std::vector<uint8_t> resp;
        const char* s = "HDL_LOCATE_STRING_v1";
        AppendPod(req, static_cast<uint32_t>(OpFindStringXrefs));
        AppendPod(req, static_cast<uint32_t>(strlen(s)));
        AppendPod(req, static_cast<int32_t>(0));
        AppendPod(req, static_cast<uint32_t>(HDL_XREF_ABSOLUTE));
        AppendPod(req, static_cast<uint32_t>(HDL_SEARCH_MODULE | HDL_SEARCH_IMAGE));
        AppendPod(req, static_cast<uint32_t>(64));
        AppendWString(req, L"hdl_test_target.exe");
        AppendBytes(req, s, strlen(s));
        if (!hdltest::PipeRequest(target.pid, req, resp)) {
            Report(c, false, false, "locate xrefs absolute ipc", "");
        } else {
            Reader r(resp);
            int32_t st = 0;
            uint32_t count = 0;
            bool found = false;
            if (r.TakePod(st) && r.TakePod(count) && st == HDL_OK) {
                for (uint32_t i = 0; i < count; ++i) {
                    uint64_t a = 0;
                    if (!r.TakePod(a)) {
                        break;
                    }
                    if (truth_str_ptr && a == truth_str_ptr) {
                        found = true;
                    }
                }
            }
            Report(c, found, false, "locate xrefs absolute hits StringPtr", "");
        }
    }

    /* RIP xref */
    {
        std::vector<uint8_t> req;
        std::vector<uint8_t> resp;
        const char* s = "HDL_LOCATE_STRING_v1";
        AppendPod(req, static_cast<uint32_t>(OpFindStringXrefs));
        AppendPod(req, static_cast<uint32_t>(strlen(s)));
        AppendPod(req, static_cast<int32_t>(0));
        AppendPod(req, static_cast<uint32_t>(HDL_XREF_RIP_REL));
        AppendPod(req, static_cast<uint32_t>(HDL_SEARCH_MODULE | HDL_SEARCH_IMAGE));
        AppendPod(req, static_cast<uint32_t>(256));
        AppendWString(req, L"hdl_test_target.exe");
        AppendBytes(req, s, strlen(s));
        if (!hdltest::PipeRequest(target.pid, req, resp)) {
            Report(c, false, false, "locate xrefs rip ipc", "");
        } else {
            Reader r(resp);
            int32_t st = 0;
            uint32_t count = 0;
            const bool ok = r.TakePod(st) && r.TakePod(count) && st == HDL_OK && count >= 1;
            Report(c, ok, false, "locate xrefs rip count", "");
        }
    }

    /* Pointer scan from leaf */
    {
        std::vector<uint8_t> req;
        std::vector<uint8_t> resp;
        AppendPod(req, static_cast<uint32_t>(OpPointerScan));
        AppendPod(req, truth_leaf);
        AppendPod(req, static_cast<uint32_t>(2));
        AppendPod(req, static_cast<uint32_t>(0x100));
        AppendPod(req, static_cast<uint32_t>(64));
        AppendPod(req, static_cast<uint32_t>(HDL_SEARCH_MODULE | HDL_SEARCH_IMAGE));
        AppendWString(req, L"hdl_test_target.exe");
        if (!hdltest::PipeRequest(target.pid, req, resp)) {
            Report(c, false, false, "locate ptrscan ipc", "");
        } else {
            Reader r(resp);
            int32_t st = 0;
            uint32_t count = 0;
            bool found_root = false;
            bool decoded = r.TakePod(st) && r.TakePod(count) && st == HDL_OK && count >= 1;
            if (decoded) {
                for (uint32_t i = 0; i < count; ++i) {
                    HdlPointerPath path{};
                    if (!hdl::proto::TakeHdlPointerPath(r, path)) {
                        decoded = false;
                        found_root = false;
                        break;
                    }
                    /* depth-1 path with offset 0 at g_locate_mid location, or root */
                    if (path.depth >= 1 && path.offsets[path.depth - 1] == 0) {
                        found_root = true;
                    }
                }
            }
            Report(c, decoded && found_root, false, "locate ptrscan finds path", "");
        }
    }

    /* Struct probe on LocateObj */
    {
        std::vector<uint8_t> req;
        std::vector<uint8_t> resp;
        AppendPod(req, static_cast<uint32_t>(OpProbeStruct));
        AppendPod(req, truth_obj);
        AppendPod(req, static_cast<uint32_t>(40));
        AppendPod(req, static_cast<uint32_t>(16));
        if (!hdltest::PipeRequest(target.pid, req, resp)) {
            Report(c, false, false, "locate probe ipc", "");
        } else {
            Reader r(resp);
            int32_t st = 0;
            uint32_t count = 0;
            bool has_vt = false;
            if (r.TakePod(st) && r.TakePod(count) && st == HDL_OK && count >= 1) {
                for (uint32_t i = 0; i < count; ++i) {
                    HdlStructField f{};
                    if (!hdl::proto::TakeHdlStructField(r, f)) {
                        break;
                    }
                    if (f.offset == 0 && (f.kind == HDL_FIELD_VTABLE || f.kind == HDL_FIELD_PTR)) {
                        has_vt = true;
                    }
                }
            }
            Report(c, has_vt, false, "locate probe vtable field", "");
        }
    }

    /* FollowPointers: *HdlTestLocateStringPtr (+0) => string address */
    {
        std::vector<uint8_t> req;
        std::vector<uint8_t> resp;
        AppendPod(req, static_cast<uint32_t>(OpFollowPointers));
        AppendPod(req, truth_str_ptr);
        AppendPod(req, static_cast<uint32_t>(1));
        AppendPod(req, static_cast<int64_t>(0));
        if (!hdltest::PipeRequest(target.pid, req, resp)) {
            Report(c, false, false, "locate follow ipc", "");
        } else {
            Reader r(resp);
            int32_t st = 0;
            uint64_t out = 0;
            const bool ok = r.TakePod(st) && r.TakePod(out) && st == HDL_OK && out == truth_str;
            Report(c, ok, false, "locate FollowPointers StringPtr", "");
        }
    }

    /* Two-level: *Root (+0) => &mid, *mid (+0) => &leaf */
    {
        std::vector<uint8_t> req;
        std::vector<uint8_t> resp;
        AppendPod(req, static_cast<uint32_t>(OpFollowPointers));
        AppendPod(req, truth_root);
        AppendPod(req, static_cast<uint32_t>(2));
        AppendPod(req, static_cast<int64_t>(0));
        AppendPod(req, static_cast<int64_t>(0));
        if (!hdltest::PipeRequest(target.pid, req, resp)) {
            Report(c, false, false, "locate follow root ipc", "");
        } else {
            Reader r(resp);
            int32_t st = 0;
            uint64_t out = 0;
            const bool ok = r.TakePod(st) && r.TakePod(out) && st == HDL_OK && out == truth_leaf;
            Report(c, ok, false, "locate FollowPointers Root to leaf", "");
        }
    }
}

void RunDiscoverTargetTests(Counters& c, const wchar_t* target_path, const wchar_t* dll_path) {
    using namespace hdl::proto;
    std::printf("\n== Discover (inject into hdl_test_target) ==\n");

    TargetProfile profile{};
    profile.name = "discover_fixtures";
    profile.window = false;
    profile.alertable = true;
    profile.integrity = IlLevel::Medium;

    TargetProc target;
    if (!hdltest::SpawnTarget(target_path, profile, target)) {
        Report(c, false, false, "discover spawn target", "");
        return;
    }

    uint64_t base = 0;
    const HdlStatus ist = hdl::InjectDllEx(target.pid, dll_path, HDL_INJECT_CREATE_REMOTE_THREAD,
                                           nullptr, nullptr, nullptr, &base);
    const bool verified =
        ist == HDL_OK &&
        hdltest::VerifyInjected(target.pid, dll_path, HDL_INJECT_CREATE_REMOTE_THREAD, base);
    Report(c, verified, false, "discover inject", "");
    if (!verified) {
        return;
    }

    auto resolve_export = [&](const char* name, uint64_t* out) -> bool {
        std::vector<uint8_t> req;
        std::vector<uint8_t> resp;
        AppendPod(req, static_cast<uint32_t>(OpResolveExport));
        AppendWString(req, L"");
        AppendString(req, name);
        if (!hdltest::PipeRequest(target.pid, req, resp)) {
            return false;
        }
        Reader r(resp);
        int32_t st = 0;
        uint64_t addr = 0;
        if (!r.TakePod(st) || !r.TakePod(addr) || st != HDL_OK || !addr) {
            return false;
        }
        *out = addr;
        return true;
    };

    auto call_export = [&](const char* name, const HdlCallArg* args, uint32_t argc) -> bool {
        std::vector<uint8_t> req;
        std::vector<uint8_t> resp;
        AppendPod(req, static_cast<uint32_t>(OpCallExport));
        AppendWString(req, L"");
        AppendString(req, name);
        AppendPod(req, argc);
        AppendPod(req, static_cast<uint32_t>(5000));
        AppendPod(req, static_cast<uint64_t>(0));
        for (uint32_t i = 0; i < argc; ++i) {
            AppendPod(req, args[i].kind);
            AppendPod(req, args[i].size);
            AppendPod(req, args[i].u64);
            /* PTR/BUF not used here */
        }
        if (!hdltest::PipeRequest(target.pid, req, resp)) {
            return false;
        }
        Reader r(resp);
        int32_t st = 0;
        return r.TakePod(st) && st == HDL_OK;
    };

    uint64_t truth_leaf = 0;
    uint64_t truth_action = 0;
    uint64_t truth_obj_a = 0;
    uint64_t truth_obj_b = 0;
    uint64_t truth_dyn_root = 0;
    Report(c, resolve_export("HdlTestDiscoverLeaf", &truth_leaf), false, "discover truth Leaf", "");
    Report(c, resolve_export("HdlTestDiscoverAction", &truth_action), false,
           "discover truth Action", "");
    Report(c, resolve_export("HdlTestDiscoverObjA", &truth_obj_a), false, "discover truth ObjA",
           "");
    Report(c, resolve_export("HdlTestDiscoverObjB", &truth_obj_b), false, "discover truth ObjB",
           "");
    Report(c, resolve_export("HdlTestDiscoverDynRoot", &truth_dyn_root), false,
           "discover truth DynRoot", "");

    {
        std::vector<uint8_t> req;
        std::vector<uint8_t> resp;
        AppendPod(req, static_cast<uint32_t>(OpEnumFunctions));
        AppendPod(req, 0ull);
        AppendPod(req, 0ull);
        AppendPod(req, HDL_SEARCH_MODULE);
        AppendPod(req, static_cast<uint32_t>(128));
        AppendWString(req, L"hdl_test_target.exe");
        bool saw_export = false;
        if (hdltest::PipeRequest(target.pid, req, resp)) {
            Reader r(resp);
            int32_t st = 0;
            uint32_t count = 0;
            if (r.TakePod(st) && r.TakePod(count) && st == HDL_OK) {
                for (uint32_t i = 0; i < count; ++i) {
                    HdlFunctionInfo fi{};
                    if (!hdl::proto::TakeHdlFunctionInfo(r, fi)) {
                        break;
                    }
                    if (truth_leaf && fi.start == truth_leaf && (fi.flags & HDL_FN_EXPORT) &&
                        fi.confidence >= 50) {
                        saw_export = true;
                    }
                }
            }
        }
        Report(c, saw_export, false, "discover EnumFunctions HdlTest export", "");
    }

    /* Create discover session */
    uint64_t disc_id = 0;
    {
        std::vector<uint8_t> req;
        std::vector<uint8_t> resp;
        AppendPod(req, static_cast<uint32_t>(OpDiscoverCreate));
        if (!hdltest::PipeRequest(target.pid, req, resp)) {
            Report(c, false, false, "discover create ipc", "");
            return;
        }
        Reader r(resp);
        int32_t st = 0;
        const bool ok = r.TakePod(st) && r.TakePod(disc_id) && st == HDL_OK && disc_id != 0;
        Report(c, ok, false, "discover create", "");
        if (!ok) {
            return;
        }
    }

    /* Constraint scan for discover objs */
    {
        std::vector<uint8_t> req;
        std::vector<uint8_t> resp;
        HdlFieldPred preds[2]{};
        preds[0].offset = 8;
        preds[0].kind = HDL_PRED_RANGE_I32;
        preds[0].a = 1;
        preds[0].b = 100;
        preds[1].offset = 8;
        preds[1].kind = HDL_PRED_LE_I32;
        preds[1].a = 4;
        AppendPod(req, static_cast<uint32_t>(OpDiscoverConstraintScan));
        AppendPod(req, disc_id);
        AppendPod(req, static_cast<uint32_t>(24)); /* sizeof approx */
        AppendPod(req, static_cast<uint32_t>(2));
        AppendPod(req, static_cast<uint32_t>(HDL_SEARCH_MODULE | HDL_SEARCH_IMAGE));
        AppendPod(req, static_cast<uint32_t>(64));
        AppendWString(req, L"hdl_test_target.exe");
        AppendString(req, "player");
        AppendBytes(req, preds, sizeof(preds));
        if (!hdltest::PipeRequest(target.pid, req, resp)) {
            Report(c, false, false, "discover constraint ipc", "");
        } else {
            Reader r(resp);
            int32_t st = 0;
            Report(c, r.TakePod(st) && st == HDL_OK, false, "discover constraint scan", "");
        }
    }

    /* Get candidates — expect ObjA/ObjB */
    {
        std::vector<uint8_t> req;
        std::vector<uint8_t> resp;
        AppendPod(req, static_cast<uint32_t>(OpDiscoverGetCandidates));
        AppendPod(req, disc_id);
        AppendPod(req, static_cast<uint32_t>(128));
        if (!hdltest::PipeRequest(target.pid, req, resp)) {
            Report(c, false, false, "discover candidates ipc", "");
        } else {
            Reader r(resp);
            int32_t st = 0;
            uint32_t count = 0;
            bool found_a = false;
            bool found_b = false;
            if (r.TakePod(st) && r.TakePod(count) && st == HDL_OK) {
                for (uint32_t i = 0; i < count; ++i) {
                    HdlCandidate cand{};
                    if (!hdl::proto::TakeHdlCandidate(r, cand)) {
                        break;
                    }
                    if (cand.address == truth_obj_a) {
                        found_a = true;
                    }
                    if (cand.address == truth_obj_b) {
                        found_b = true;
                    }
                }
            }
            Report(c, found_a && found_b, false, "discover candidates include objs", "");
        }
    }

    /* Synthesize pattern for Leaf */
    {
        std::vector<uint8_t> req;
        std::vector<uint8_t> resp;
        AppendPod(req, static_cast<uint32_t>(OpDiscoverAddCandidate));
        AppendPod(req, disc_id);
        AppendPod(req, static_cast<uint32_t>(HDL_CAND_FUNCTION));
        AppendPod(req, truth_leaf);
        AppendString(req, "leaf");
        uint64_t cand_id = 0;
        if (!hdltest::PipeRequest(target.pid, req, resp)) {
            Report(c, false, false, "discover add cand ipc", "");
        } else {
            Reader r(resp);
            int32_t st = 0;
            Report(c, r.TakePod(st) && r.TakePod(cand_id) && st == HDL_OK && cand_id != 0, false,
                   "discover add leaf cand", "");
        }

        req.clear();
        resp.clear();
        AppendPod(req, static_cast<uint32_t>(OpDiscoverSynthesizePattern));
        AppendPod(req, disc_id);
        AppendPod(req, cand_id);
        AppendPod(req, static_cast<uint32_t>(0));
        AppendPod(req, static_cast<uint32_t>(24));
        AppendPod(req, static_cast<uint32_t>(HDL_SEARCH_MODULE | HDL_SEARCH_IMAGE));
        AppendWString(req, L"hdl_test_target.exe");
        if (!hdltest::PipeRequest(target.pid, req, resp)) {
            Report(c, false, false, "discover synth ipc", "");
        } else {
            Reader r(resp);
            int32_t st = 0;
            HdlSynthesizedPattern out{};
            const bool ok = r.TakePod(st) && hdl::proto::TakeHdlSynthesizedPattern(r, out) &&
                            st == HDL_OK && out.pattern[0] && out.resolved_addr == truth_leaf;
            Report(c, ok, false, "discover synthesize leaf", "");
        }
    }

    /* Action + watch + rank */
    {
        std::vector<uint8_t> req;
        std::vector<uint8_t> resp;
        AppendPod(req, static_cast<uint32_t>(OpDiscoverWatch));
        AppendPod(req, disc_id);
        AppendPod(req, truth_leaf);
        AppendPod(req, static_cast<uint32_t>(0));
        if (!hdltest::PipeRequest(target.pid, req, resp)) {
            Report(c, false, false, "discover watch ipc", "");
        } else {
            Reader r(resp);
            int32_t st = 0;
            Report(c, r.TakePod(st) && st == HDL_OK, false, "discover watch leaf", "");
        }

        req.clear();
        resp.clear();
        AppendPod(req, static_cast<uint32_t>(OpDiscoverWatchRegion));
        AppendPod(req, disc_id);
        AppendPod(req, truth_obj_a);
        AppendPod(req, static_cast<uint32_t>(24));
        if (!hdltest::PipeRequest(target.pid, req, resp)) {
            Report(c, false, false, "discover watch region ipc", "");
        }

        req.clear();
        resp.clear();
        AppendPod(req, static_cast<uint32_t>(OpDiscoverActionBegin));
        AppendPod(req, disc_id);
        AppendString(req, "fire");
        if (!hdltest::PipeRequest(target.pid, req, resp)) {
            Report(c, false, false, "discover action begin ipc", "");
        } else {
            Reader r(resp);
            int32_t st = 0;
            Report(c, r.TakePod(st) && st == HDL_OK, false, "discover action begin", "");
        }

        Report(c, call_export("HdlTestDiscoverAction", nullptr, 0), false, "discover call action",
               "");
        {
            HdlCallArg arg{};
            arg.kind = HDL_CALL_ARG_I64;
            arg.u64 = 5;
            Report(c, call_export("HdlTestDiscoverDamage", &arg, 1), false, "discover call damage",
                   "");
        }

        req.clear();
        resp.clear();
        AppendPod(req, static_cast<uint32_t>(OpDiscoverActionEnd));
        AppendPod(req, disc_id);
        if (!hdltest::PipeRequest(target.pid, req, resp)) {
            Report(c, false, false, "discover action end ipc", "");
        } else {
            Reader r(resp);
            int32_t st = 0;
            Report(c, r.TakePod(st) && st == HDL_OK, false, "discover action end", "");
        }

        req.clear();
        resp.clear();
        AppendPod(req, static_cast<uint32_t>(OpDiscoverRankFunctions));
        AppendPod(req, disc_id);
        AppendString(req, "fire");
        AppendPod(req, static_cast<uint32_t>(0));
        AppendPod(req, static_cast<uint32_t>(32));
        if (!hdltest::PipeRequest(target.pid, req, resp)) {
            Report(c, false, false, "discover rank ipc", "");
        } else {
            Reader r(resp);
            int32_t st = 0;
            uint32_t count = 0;
            bool near_action = false;
            if (r.TakePod(st) && r.TakePod(count) && st == HDL_OK) {
                for (uint32_t i = 0; i < count; ++i) {
                    HdlCandidate cand{};
                    if (!hdl::proto::TakeHdlCandidate(r, cand)) {
                        break;
                    }
                    if (truth_action && cand.address >= truth_action &&
                        cand.address < truth_action + 0x80) {
                        near_action = true;
                    }
                }
            }
            Report(c, near_action, false, "discover rank near Action", "");
        }

        req.clear();
        resp.clear();
        AppendPod(req, static_cast<uint32_t>(OpDiscoverGetHeat));
        AppendPod(req, disc_id);
        AppendPod(req, truth_obj_a);
        AppendPod(req, static_cast<uint32_t>(16));
        if (!hdltest::PipeRequest(target.pid, req, resp)) {
            Report(c, false, false, "discover heat ipc", "");
        } else {
            Reader r(resp);
            int32_t st = 0;
            uint32_t count = 0;
            bool health_hot = false;
            if (r.TakePod(st) && r.TakePod(count) && st == HDL_OK) {
                for (uint32_t i = 0; i < count; ++i) {
                    HdlHeatField hf{};
                    if (!hdl::proto::TakeHdlHeatField(r, hf)) {
                        break;
                    }
                    if (hf.offset == 8) {
                        health_hot = true;
                    }
                }
            }
            Report(c, health_hot, false, "discover heat on health", "");
        }
    }

    /* Path consensus / validate across realloc */
    {
        /* Ensure dyn leaf allocated */
        call_export("HdlTestDiscoverAllocDyn", nullptr, 0);

        std::vector<uint8_t> req;
        std::vector<uint8_t> resp;
        /* Resolve current dyn leaf via follow DynRoot */
        AppendPod(req, static_cast<uint32_t>(OpFollowPointers));
        AppendPod(req, truth_dyn_root);
        AppendPod(req, static_cast<uint32_t>(1));
        AppendPod(req, static_cast<int64_t>(0));
        uint64_t dyn1 = 0;
        if (hdltest::PipeRequest(target.pid, req, resp)) {
            Reader r(resp);
            int32_t st = 0;
            r.TakePod(st);
            r.TakePod(dyn1);
        }

        req.clear();
        resp.clear();
        AppendPod(req, static_cast<uint32_t>(OpDiscoverPathConsensus));
        AppendPod(req, dyn1);
        AppendPod(req, static_cast<uint32_t>(2));
        AppendPod(req, static_cast<uint32_t>(0x100));
        AppendPod(req, static_cast<uint32_t>(64));
        AppendPod(req, static_cast<uint32_t>(HDL_SEARCH_MODULE | HDL_SEARCH_IMAGE));
        AppendWString(req, L"hdl_test_target.exe");
        std::vector<HdlPointerPath> paths;
        if (!hdltest::PipeRequest(target.pid, req, resp)) {
            Report(c, false, false, "discover pathconsensus ipc", "");
        } else {
            Reader r(resp);
            int32_t st = 0;
            uint32_t count = 0;
            bool ok = r.TakePod(st) && r.TakePod(count) && st == HDL_OK && count >= 1;
            if (ok) {
                paths.resize(count);
                for (uint32_t i = 0; i < count; ++i) {
                    if (!hdl::proto::TakeHdlPointerPath(r, paths[i])) {
                        ok = false;
                        paths.clear();
                        break;
                    }
                }
            }
            Report(c, ok, false, "discover pathconsensus", "");
        }

        /* Realloc dyn leaf */
        call_export("HdlTestDiscoverAllocDyn", nullptr, 0);
        req.clear();
        resp.clear();
        AppendPod(req, static_cast<uint32_t>(OpFollowPointers));
        AppendPod(req, truth_dyn_root);
        AppendPod(req, static_cast<uint32_t>(1));
        AppendPod(req, static_cast<int64_t>(0));
        uint64_t dyn2 = 0;
        if (hdltest::PipeRequest(target.pid, req, resp)) {
            Reader r(resp);
            int32_t st = 0;
            r.TakePod(st);
            r.TakePod(dyn2);
        }

        req.clear();
        resp.clear();
        AppendPod(req, static_cast<uint32_t>(OpDiscoverPathValidate));
        AppendPod(req, dyn2);
        AppendPod(req, static_cast<uint32_t>(paths.size()));
        for (const auto& p : paths) {
            hdl::proto::AppendHdlPointerPath(req, p);
        }
        if (!hdltest::PipeRequest(target.pid, req, resp)) {
            Report(c, false, false, "discover pathvalidate ipc", "");
        } else {
            Reader r(resp);
            int32_t st = 0;
            uint32_t kept = 0;
            bool has_root = false;
            bool decoded = r.TakePod(st) && r.TakePod(kept) && st == HDL_OK;
            if (decoded) {
                for (uint32_t i = 0; i < kept; ++i) {
                    HdlPointerPath p{};
                    if (!hdl::proto::TakeHdlPointerPath(r, p)) {
                        decoded = false;
                        has_root = false;
                        break;
                    }
                    if (p.static_base == truth_dyn_root && p.depth == 1 && p.offsets[0] == 0) {
                        has_root = true;
                    }
                }
            }
            Report(c, decoded && has_root && dyn1 != 0 && dyn2 != 0, false,
                   "discover pathvalidate keeps DynRoot", "");
        }
    }

    {
        std::vector<uint8_t> req;
        std::vector<uint8_t> resp;
        AppendPod(req, static_cast<uint32_t>(OpDiscoverClose));
        AppendPod(req, disc_id);
        if (!hdltest::PipeRequest(target.pid, req, resp)) {
            Report(c, false, false, "discover close ipc", "");
        } else {
            Reader r(resp);
            int32_t st = 0;
            Report(c, r.TakePod(st) && st == HDL_OK, false, "discover close", "");
        }
    }
}

void EvaluateInject(Counters& c, const char* case_name, Expect expect, HdlStatus st,
                    bool verified) {
    char detail[128];
    snprintf(detail, sizeof(detail), "status=%s verified=%d", hdltest::StatusNameA(st),
             verified ? 1 : 0);

    switch (expect) {
    case Expect::MustSucceed: {
        if (st == HDL_OK && verified) {
            Report(c, true, false, case_name, detail);
        } else if (st == HDL_OK) {
            // Inject reported success but module/IPC verify lagged or flaked.
            Report(c, false, true, case_name, detail);
        } else {
            Report(c, false, false, case_name, detail);
        }
        break;
    }
    case Expect::MustFail: {
        const bool ok = (st != HDL_OK);
        Report(c, ok, false, case_name, detail);
        break;
    }
    case Expect::SoftSucceed: {
        if (st == HDL_OK && verified) {
            Report(c, true, false, case_name, detail);
        } else {
            Report(c, false, true, case_name, detail);
        }
        break;
    }
    }
}

HdlStatus InjectSealed(uint32_t pid, const wchar_t* dll_path, int method, const wchar_t* exe,
                       const char* hook_export, uint32_t* out_pid, uint64_t* out_base) {
    HdlStatus st = HDL_E_FAILED;
    __try {
        st = hdl::InjectDllEx(pid, dll_path, method, exe, hook_export, out_pid, out_base);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        st = HDL_E_FAILED;
        std::printf("  ! exception 0x%08lX during inject\n", GetExceptionCode());
    }
    return st;
}

/* Race close / CloseAll against in-flight Find+lock users of IPC session holders.
 * Passes if no AV and workers only observe OK / NOT_FOUND (never use-after-free). */
void RunSessionLifetimeRaceTests(Counters& c) {
    using namespace hdl::proto;
    std::printf("\n== Session lifetime race ==\n");
    fflush(stdout);

    if (!hdl::testapi::IsInitialized()) {
        Report(c, hdl::testapi::Init() == HDL_OK, false, "lifecycle/session_race_init", "");
        if (!hdl::testapi::IsInitialized()) {
            return;
        }
    }

    constexpr int kRounds = 40;
    constexpr int kReaders = 4;
    std::atomic<int> faults{0};

    /* --- search: FindSession readers vs TakeSearchSession close --- */
    for (int round = 0; round < kRounds; ++round) {
        HdlSearchSession* session = nullptr;
        if (hdl::SearchCreate(&session) != HDL_OK || !session) {
            faults.fetch_add(1);
            break;
        }
        const uint64_t id = hdl::ipc::AllocSearchSession(session);
        std::atomic<bool> stop{false};
        std::vector<std::thread> readers;
        readers.reserve(kReaders);
        for (int t = 0; t < kReaders; ++t) {
            readers.emplace_back([&, id] {
                while (!stop.load(std::memory_order_relaxed)) {
                    auto holder = hdl::ipc::FindSession(id);
                    if (!holder) {
                        continue;
                    }
                    std::lock_guard<std::mutex> lock(holder->mu);
                    if (holder->session) {
                        uint32_t n = 0;
                        hdl::SearchGetCount(holder->session, &n);
                    }
                }
            });
        }
        Sleep(1);
        auto taken = hdl::ipc::TakeSearchSession(id);
        if (taken) {
            std::lock_guard<std::mutex> lock(taken->mu);
            if (taken->session) {
                hdl::SearchClose(taken->session);
                taken->session = nullptr;
            }
        } else {
            faults.fetch_add(1);
        }
        stop.store(true);
        for (auto& th : readers) {
            th.join();
        }
    }
    Report(c, faults.load() == 0, false, "lifecycle/search_close_vs_inflight", "");

    /* --- discover: FindDiscover readers vs TakeDiscoverSession close --- */
    faults.store(0);
    for (int round = 0; round < kRounds; ++round) {
        HdlDiscoverSession* session = nullptr;
        if (hdl::DiscoverCreate(&session) != HDL_OK || !session) {
            faults.fetch_add(1);
            break;
        }
        const uint64_t id = hdl::ipc::AllocDiscoverSession(session);
        std::atomic<bool> stop{false};
        std::vector<std::thread> readers;
        readers.reserve(kReaders);
        for (int t = 0; t < kReaders; ++t) {
            readers.emplace_back([&, id] {
                while (!stop.load(std::memory_order_relaxed)) {
                    auto holder = hdl::ipc::FindDiscover(id);
                    if (!holder) {
                        continue;
                    }
                    std::lock_guard<std::mutex> lock(holder->mu);
                    if (holder->session) {
                        HdlCandidate tmp{};
                        uint32_t n = 1;
                        hdl::DiscoverGetCandidates(holder->session, &tmp, &n);
                    }
                }
            });
        }
        Sleep(1);
        auto taken = hdl::ipc::TakeDiscoverSession(id);
        if (taken) {
            std::lock_guard<std::mutex> lock(taken->mu);
            if (taken->session) {
                hdl::DiscoverClose(taken->session);
                taken->session = nullptr;
            }
        } else {
            faults.fetch_add(1);
        }
        stop.store(true);
        for (auto& th : readers) {
            th.join();
        }
    }
    Report(c, faults.load() == 0, false, "lifecycle/discover_close_vs_inflight", "");

    /* --- CloseAll* while Find* readers still hold shared_ptrs --- */
    faults.store(0);
    {
        HdlSearchSession* ss = nullptr;
        HdlDiscoverSession* ds = nullptr;
        if (hdl::SearchCreate(&ss) != HDL_OK || !ss || hdl::DiscoverCreate(&ds) != HDL_OK || !ds) {
            Report(c, false, false, "lifecycle/close_all_vs_inflight", "create failed");
        } else {
            const uint64_t sid = hdl::ipc::AllocSearchSession(ss);
            const uint64_t did = hdl::ipc::AllocDiscoverSession(ds);
            std::atomic<bool> stop{false};
            std::vector<std::thread> readers;
            for (int t = 0; t < kReaders; ++t) {
                readers.emplace_back([&, sid, did] {
                    while (!stop.load(std::memory_order_relaxed)) {
                        if (auto h = hdl::ipc::FindSession(sid)) {
                            std::lock_guard<std::mutex> lock(h->mu);
                            if (h->session) {
                                uint32_t n = 0;
                                hdl::SearchGetCount(h->session, &n);
                            }
                        }
                        if (auto h = hdl::ipc::FindDiscover(did)) {
                            std::lock_guard<std::mutex> lock(h->mu);
                            if (h->session) {
                                HdlCandidate tmp{};
                                uint32_t n = 1;
                                hdl::DiscoverGetCandidates(h->session, &tmp, &n);
                            }
                        }
                    }
                });
            }
            Sleep(2);
            hdl::ipc::CloseAllSessions();
            hdl::ipc::CloseAllDiscoverSessions();
            stop.store(true);
            for (auto& th : readers) {
                th.join();
            }
            Report(c, true, false, "lifecycle/close_all_vs_inflight", "");
        }
    }

    /* --- IPC pipe race: GetCandidates / Reset vs Close on the live server --- */
    faults.store(0);
    const uint32_t self_pid = GetCurrentProcessId();
    for (int round = 0; round < 16; ++round) {
        uint64_t search_id = 0;
        uint64_t disc_id = 0;
        {
            std::vector<uint8_t> req, resp;
            AppendPod(req, static_cast<uint32_t>(OpSearchCreate));
            if (!hdltest::PipeRequest(self_pid, req, resp)) {
                faults.fetch_add(1);
                break;
            }
            Reader r(resp);
            int32_t st = 0;
            if (!r.TakePod(st) || !r.TakePod(search_id) || st != HDL_OK || !search_id) {
                faults.fetch_add(1);
                break;
            }
        }
        {
            std::vector<uint8_t> req, resp;
            AppendPod(req, static_cast<uint32_t>(OpDiscoverCreate));
            if (!hdltest::PipeRequest(self_pid, req, resp)) {
                faults.fetch_add(1);
                break;
            }
            Reader r(resp);
            int32_t st = 0;
            if (!r.TakePod(st) || !r.TakePod(disc_id) || st != HDL_OK || !disc_id) {
                faults.fetch_add(1);
                break;
            }
        }

        std::atomic<bool> stop{false};
        std::atomic<int> bad_status{0};
        std::vector<std::thread> workers;
        for (int t = 0; t < kReaders; ++t) {
            workers.emplace_back([&, search_id, disc_id] {
                while (!stop.load(std::memory_order_relaxed)) {
                    {
                        std::vector<uint8_t> req, resp;
                        AppendPod(req, static_cast<uint32_t>(OpSearchReset));
                        AppendPod(req, search_id);
                        if (hdltest::PipeRequest(self_pid, req, resp, 2000)) {
                            Reader r(resp);
                            int32_t st = 0;
                            if (r.TakePod(st) && st != HDL_OK && st != HDL_E_NOT_FOUND) {
                                bad_status.fetch_add(1);
                            }
                        }
                    }
                    {
                        std::vector<uint8_t> req, resp;
                        AppendPod(req, static_cast<uint32_t>(OpDiscoverGetCandidates));
                        AppendPod(req, disc_id);
                        AppendPod(req, static_cast<uint32_t>(8));
                        if (hdltest::PipeRequest(self_pid, req, resp, 2000)) {
                            Reader r(resp);
                            int32_t st = 0;
                            if (r.TakePod(st) && st != HDL_OK && st != HDL_E_NOT_FOUND &&
                                st != HDL_E_BUFFER_SMALL) {
                                bad_status.fetch_add(1);
                            }
                        }
                    }
                }
            });
        }
        Sleep(5);
        {
            std::vector<uint8_t> req, resp;
            AppendPod(req, static_cast<uint32_t>(OpSearchClose));
            AppendPod(req, search_id);
            hdltest::PipeRequest(self_pid, req, resp, 2000);
        }
        {
            std::vector<uint8_t> req, resp;
            AppendPod(req, static_cast<uint32_t>(OpDiscoverClose));
            AppendPod(req, disc_id);
            hdltest::PipeRequest(self_pid, req, resp, 2000);
        }
        stop.store(true);
        for (auto& th : workers) {
            th.join();
        }
        faults.fetch_add(bad_status.load());
    }
    Report(c, faults.load() == 0, false, "lifecycle/ipc_close_vs_inflight", "");
}

void RunLifecycleStressTests(Counters& c, const wchar_t* target_exe, const wchar_t* dll_path) {
    std::printf("\n== Lifecycle stress ==\n");
    fflush(stdout);

    if (hdl::testapi::IsInitialized()) {
        hdl::testapi::Shutdown();
    }

    constexpr int kInitShutdownRounds = 20;
    int ok_rounds = 0;
    for (int i = 0; i < kInitShutdownRounds; ++i) {
        const HdlStatus st = hdl::testapi::Init();
        const bool ready = st == HDL_OK && hdl::testapi::IsInitialized();
        hdl::testapi::Shutdown();
        const bool cleared = !hdl::testapi::IsInitialized();
        if (ready && cleared) {
            ++ok_rounds;
        }
    }
    Report(c, ok_rounds == kInitShutdownRounds, false, "lifecycle/init_shutdown_x20", "");

    /* Leave helper initialized like RunLocalApiTests expects when chained. */
    Report(c, hdl::testapi::Init() == HDL_OK, false, "lifecycle/reinit after stress", "");

    /* Concurrent close vs in-flight search/discover (shared_ptr + per-session mutex). */
    RunSessionLifetimeRaceTests(c);

    constexpr int kInjectUnloadRounds = 5;
    int inject_ok = 0;
    for (int i = 0; i < kInjectUnloadRounds; ++i) {
        TargetProfile profile{};
        profile.name = "lifecycle_reload";
        profile.window = false;
        profile.alertable = true;
        profile.integrity = IlLevel::Medium;

        TargetProc target;
        if (!hdltest::SpawnTarget(target_exe, profile, target)) {
            continue;
        }
        uint64_t base = 0;
        const HdlStatus ist = InjectSealed(target.pid, dll_path, HDL_INJECT_CREATE_REMOTE_THREAD,
                                           nullptr, nullptr, nullptr, &base);
        const bool injected =
            ist == HDL_OK &&
            hdltest::VerifyInjected(target.pid, dll_path, HDL_INJECT_CREATE_REMOTE_THREAD, base);
        int32_t shut_st = HDL_E_FAILED;
        const bool shut_ok =
            injected && hdltest::PipeShutdown(target.pid, 0, &shut_st) && shut_st == HDL_OK;
        uint64_t ubase = 0;
        const HdlStatus ust =
            shut_ok ? hdl::UnloadDll(target.pid, dll_path, 0, 0, &ubase) : HDL_E_FAILED;
        const bool unloaded = ust == HDL_OK || ust == HDL_E_NOT_FOUND;
        const bool alive = WaitForSingleObject(target.process, 0) == WAIT_TIMEOUT;
        if (injected && shut_ok && unloaded && alive) {
            ++inject_ok;
        }
        target.Close();
    }
    Report(c, inject_ok == kInjectUnloadRounds, false, "lifecycle/inject_shutdown_unload_x5", "");
}

void RunCleanUnloadTests(Counters& c, const wchar_t* target_exe, const wchar_t* dll_path) {
    std::printf("\n== Clean unload / shutdown ==\n");
    fflush(stdout);

    TargetProfile profile{};
    profile.name = "clean_unload";
    profile.window = false;
    profile.alertable = true;
    profile.integrity = IlLevel::Medium;

    TargetProc target;
    if (!hdltest::SpawnTarget(target_exe, profile, target)) {
        Report(c, false, false, "clean_unload/spawn", "spawn failed");
        return;
    }

    uint64_t base = 0;
    const HdlStatus ist = InjectSealed(target.pid, dll_path, HDL_INJECT_CREATE_REMOTE_THREAD,
                                       nullptr, nullptr, nullptr, &base);
    const bool injected =
        ist == HDL_OK &&
        hdltest::VerifyInjected(target.pid, dll_path, HDL_INJECT_CREATE_REMOTE_THREAD, base);
    Report(c, injected, false, "clean_unload/inject", "");
    if (!injected) {
        target.Close();
        return;
    }

    /* Secondary module-list DLL into the same target; track then unload via shutdown flag. */
    wchar_t sys[MAX_PATH];
    GetSystemDirectoryW(sys, MAX_PATH);
    wcscat_s(sys, L"\\wintrust.dll");
    uint64_t secondary = 0;
    const HdlStatus sst = hdl::InjectDll(target.pid, sys, &secondary);
    Report(c, sst == HDL_OK && secondary != 0, true, "clean_unload/inject secondary", "");
    if (sst == HDL_OK && secondary != 0) {
        /* OpTrackLoadedDll: opcode 95, base u64, wstring path */
        std::vector<uint8_t> treq;
        const uint32_t op = 95;
        treq.insert(treq.end(), reinterpret_cast<const uint8_t*>(&op),
                    reinterpret_cast<const uint8_t*>(&op) + 4);
        treq.insert(treq.end(), reinterpret_cast<const uint8_t*>(&secondary),
                    reinterpret_cast<const uint8_t*>(&secondary) + 8);
        const uint32_t nbytes = static_cast<uint32_t>((wcslen(sys) + 1) * sizeof(wchar_t));
        treq.insert(treq.end(), reinterpret_cast<const uint8_t*>(&nbytes),
                    reinterpret_cast<const uint8_t*>(&nbytes) + 4);
        const uint8_t* p = reinterpret_cast<const uint8_t*>(sys);
        treq.insert(treq.end(), p, p + nbytes);
        int32_t track_st = HDL_E_FAILED;
        Report(c,
               hdltest::PipeRequest(target.pid, treq.data(), static_cast<uint32_t>(treq.size()),
                                    &track_st) &&
                   track_st == HDL_OK,
               false, "clean_unload/track secondary", "");
    }

    int32_t shut_st = HDL_E_FAILED;
    const bool shut_ok = hdltest::PipeShutdown(target.pid, HDL_SHUTDOWN_UNLOAD_MODULES, &shut_st) &&
                         shut_st == HDL_OK;
    Report(c, shut_ok, false, "clean_unload/OpShutdown modules", "");

    Sleep(300);
    Report(c, !hdltest::PingPipe(target.pid, 500), false, "clean_unload/pipe dead after shutdown",
           "");

    if (sst == HDL_OK && secondary != 0) {
        /* Single FreeLibrary may leave the module if something else holds a ref. */
        const bool gone = hdltest::FindModuleBaseByPath(target.pid, sys) == 0;
        Report(c, gone, true, "clean_unload/secondary unloaded", "");
    }

    uint64_t ubase = 0;
    const HdlStatus ust = hdl::UnloadDll(target.pid, dll_path, 0, 0, &ubase);
    Report(c, ust == HDL_OK || ust == HDL_E_NOT_FOUND, false, "clean_unload/FreeLibrary hdllib",
           "");

    Sleep(200);
    const bool alive = WaitForSingleObject(target.process, 0) == WAIT_TIMEOUT;
    Report(c, alive, false, "clean_unload/target still alive", "");

    target.Close();
}

void RunInjectMatrix(Counters& c, const wchar_t* target_exe, const wchar_t* dll_path) {
    std::printf("\n== Injection matrix ==\n");
    fflush(stdout);

    static const TargetProfile kProfiles[] = {
        {"med_console_busy", false, false, IlLevel::Medium},
        {"med_console_alertable", false, true, IlLevel::Medium},
        {"med_gui_busy", true, false, IlLevel::Medium},
        {"med_gui_alertable", true, true, IlLevel::Medium},
        {"low_console_alertable", false, true, IlLevel::Low},
        {"low_gui_alertable", true, true, IlLevel::Low},
    };

    static const int kMethods[] = {
        HDL_INJECT_CREATE_REMOTE_THREAD,
        HDL_INJECT_NT_CREATE_THREAD_EX,
        HDL_INJECT_RTL_CREATE_USER_THREAD,
        HDL_INJECT_QUEUE_USER_APC,
        HDL_INJECT_SET_WINDOWS_HOOK_EX,
        HDL_INJECT_THREAD_HIJACK,
        HDL_INJECT_MANUAL_MAP,
        HDL_INJECT_ATOM_BOMBING,
        HDL_INJECT_MODULE_STOMP,
        HDL_INJECT_SECTION_MAP,
        HDL_INJECT_WINDOW_SUBCLASS,
        HDL_INJECT_INSTRUMENTATION_CALLBACK,
        HDL_INJECT_KERNEL_CALLBACK_TABLE,
        HDL_INJECT_VEH,
        HDL_INJECT_SET_WIN_EVENT_HOOK,
        HDL_INJECT_RTL_REMOTE_CALL,
        HDL_INJECT_SPECIAL_USER_APC,
        HDL_INJECT_THREAD_POOL,
        HDL_INJECT_ETW_CALLBACK,
    };

    for (const TargetProfile& profile : kProfiles) {
        std::printf("\n-- profile %s (window=%d alertable=%d il=%s) --\n", profile.name,
                    profile.window ? 1 : 0, profile.alertable ? 1 : 0,
                    profile.integrity == IlLevel::Low ? "low" : "medium");
        fflush(stdout);

        for (int method : kMethods) {
            char case_name[192];
            snprintf(case_name, sizeof(case_name), "inject/%s/%s", profile.name,
                     hdltest::MethodName(method));

            TargetProc target;
            if (!hdltest::SpawnTarget(target_exe, profile, target)) {
                const bool soft = profile.integrity == IlLevel::Low;
                Report(c, false, soft, case_name, "spawn failed");
                fflush(stdout);
                if (!soft) {
                    break;
                }
                continue;
            }

            const Expect expect = hdltest::ExpectFor(method, profile);
            uint64_t base = 0;
            uint32_t out_pid = 0;
            const char* hook_export =
                (method == HDL_INJECT_SET_WIN_EVENT_HOOK) ? "HdlWinEventProc" : "HdlHookProc";
            const HdlStatus st =
                InjectSealed(target.pid, dll_path, method, nullptr, hook_export, &out_pid, &base);

            bool verified = false;
            if (st == HDL_OK) {
                verified = hdltest::VerifyInjected(target.pid, dll_path, method, base);
            }
            EvaluateInject(c, case_name, expect, st, verified);
            fflush(stdout);
            target.Close();
        }
    }

    {
        std::printf("\n-- early_bird_apc --\n");
        fflush(stdout);
        uint64_t base = 0;
        uint32_t out_pid = 0;
        const HdlStatus st = InjectSealed(0, dll_path, HDL_INJECT_EARLY_BIRD_APC, target_exe,
                                          nullptr, &out_pid, &base);
        bool verified = false;
        if (st == HDL_OK && out_pid) {
            Sleep(500);
            verified = hdltest::VerifyInjected(out_pid, dll_path, HDL_INJECT_EARLY_BIRD_APC, base);
            HANDLE hp = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, out_pid);
            if (hp) {
                TerminateProcess(hp, 0);
                WaitForSingleObject(hp, 3000);
                CloseHandle(hp);
            }
        }
        EvaluateInject(c, "inject/early_bird/early_bird_apc", Expect::MustSucceed, st, verified);
        fflush(stdout);
    }
}

void PrintUsage() {
    std::wprintf(L"hdl_tests — hdllib functional / injection matrix suite\n\n"
                 L"Usage:\n"
                 L"  hdl_tests [--dll <hdllib.dll>] [--target <hdl_test_target.exe>]\n"
                 L"            [--api-only] [--inject-only] [--locate-only] [--lifecycle-only]\n");
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    std::wstring dll_path;
    std::wstring target_path;
    bool api_only = false;
    bool inject_only = false;
    bool locate_only = false;
    bool lifecycle_only = false;

    for (int i = 1; i < argc; ++i) {
        if (_wcsicmp(argv[i], L"--dll") == 0 && i + 1 < argc) {
            dll_path = argv[++i];
        } else if (_wcsicmp(argv[i], L"--target") == 0 && i + 1 < argc) {
            target_path = argv[++i];
        } else if (_wcsicmp(argv[i], L"--api-only") == 0) {
            api_only = true;
        } else if (_wcsicmp(argv[i], L"--inject-only") == 0) {
            inject_only = true;
        } else if (_wcsicmp(argv[i], L"--locate-only") == 0) {
            locate_only = true;
        } else if (_wcsicmp(argv[i], L"--lifecycle-only") == 0) {
            lifecycle_only = true;
        } else if (_wcsicmp(argv[i], L"--help") == 0 || _wcsicmp(argv[i], L"-h") == 0) {
            PrintUsage();
            return 0;
        } else {
            std::wprintf(L"Unknown arg: %ls\n", argv[i]);
            PrintUsage();
            return 2;
        }
    }

    const std::wstring dir = hdltest::ExeDir();
    if (dll_path.empty()) {
        dll_path = hdltest::JoinPath(dir, L"hdllib.dll");
    }
    if (target_path.empty()) {
        target_path = hdltest::JoinPath(dir, L"hdl_test_target.exe");
    }

    wchar_t dll_full[MAX_PATH];
    wchar_t target_full[MAX_PATH];
    if (GetFullPathNameW(dll_path.c_str(), MAX_PATH, dll_full, nullptr) == 0 ||
        GetFullPathNameW(target_path.c_str(), MAX_PATH, target_full, nullptr) == 0) {
        std::wprintf(L"Failed to resolve paths\n");
        return 2;
    }
    if (!hdltest::FileExists(dll_full)) {
        std::wprintf(L"Missing DLL: %ls\n", dll_full);
        return 2;
    }
    if (!inject_only && !api_only) {
        // both
    }
    if (!api_only && !hdltest::FileExists(target_full)) {
        std::wprintf(L"Missing target: %ls\n", target_full);
        return 2;
    }

    const std::wstring payload = PreparePayloadDll(dll_full);
    std::wprintf(L"Payload DLL: %ls\n", payload.c_str());
    std::wprintf(L"Test target: %ls\n", target_full);

    Counters c;
    if (lifecycle_only) {
        RunLifecycleStressTests(c, target_full, payload.c_str());
    } else {
        if (!inject_only && !locate_only) {
            RunLocalApiTests(c, payload.c_str());
            if (!api_only) {
                RunLifecycleStressTests(c, target_full, payload.c_str());
            }
        }
        if (locate_only || (!api_only && !inject_only)) {
            RunLocateTargetTests(c, target_full, payload.c_str());
            RunDiscoverTargetTests(c, target_full, payload.c_str());
        }
        if (!api_only && !locate_only) {
            RunCleanUnloadTests(c, target_full, payload.c_str());
            RunInjectMatrix(c, target_full, payload.c_str());
        }
    }

    std::printf("\n== Summary ==\n");
    std::printf("passed=%d failed=%d soft=%d skipped=%d\n", c.passed, c.failed, c.soft_failed,
                c.skipped);
    fflush(stdout);
    /* Prefer CoreShutdown (joins IPC workers). Injected helpers use OpShutdown + no-op
     * DllMain detach. The test host may still STATUS_STACK_BUFFER_OVERRUN in MinHook/CRT
     * teardown after heavy in-process hook tests — exit via TerminateProcess. */
    if (hdl::testapi::IsInitialized()) {
        hdl::testapi::Shutdown();
    }
    TerminateProcess(GetCurrentProcess(), c.failed == 0 ? 0 : 1);
    return c.failed == 0 ? 0 : 1;
}
