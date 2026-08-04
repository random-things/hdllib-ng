#include "domain_api.hpp"
#include "ipc/common.hpp"
#include "ipc/wire.hpp"
#include "protocol.hpp"
#include "support.hpp"
#include "test_runners.hpp"

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

} // namespace

void RunLocalApiTests(Counters& c, const wchar_t* dll_path, bool include_ui_thread_test,
                      bool include_process_region_scan_test) {
    std::printf("\n== Local API / lifecycle ==\n");

    // Linking hdllib loads DllMain bootstrap asynchronously â€” wait or init explicitly.
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
    std::vector<HdlRegionInfo> regions(count + 64);
    count = static_cast<uint32_t>(regions.size());
    st = hdl::EnumRegions(regions.data(), &count);
    Report(c, st == HDL_OK && count > 0, false, "HdlEnumRegions fill", "");

    count = 0;
    st = hdl::EnumModules(nullptr, &count);
    Report(c, st == HDL_E_BUFFER_SMALL && count > 0, false, "HdlEnumModules size query", "");
    std::vector<HdlModuleInfo> modules(count + 8);
    count = static_cast<uint32_t>(modules.size());
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

    // Hooks â€” HdlHook enables immediately; exercise disable/enable + detour.
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

        if (include_process_region_scan_test) {
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
            /* Need executable second slot break â€” put only one valid */
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

        if (include_ui_thread_test) {
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
        if (include_process_region_scan_test) {
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

    if (include_process_region_scan_test) {
        RunLocalDiscoverTests(c);
    }

    // IPC
    st = hdl::StartIpc();
    Report(c, st == HDL_OK && hdl::IsIpcRunning() != 0, false, "HdlStartIpc", "");
    Report(c, hdltest::PingPipe(GetCurrentProcessId()), false, "IPC ping self", "");
    // Multi-client: two concurrent pings
    Report(c, hdltest::PingPipe(GetCurrentProcessId()) && hdltest::PingPipe(GetCurrentProcessId()),
           false, "IPC multi-client ping", "");

    // Local inject (pid 0) â€” already loaded; should still succeed / return base
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
                /* Already mapped elsewhere â€” one FreeLibrary should restore prior state. */
                st = hdl::testapi::UnloadDllCompat(0, sys, 0, &ubase);
                Report(c, st == HDL_OK || st == HDL_E_BUSY, true, "HdlUnloadDll wintrust (soft)",
                       "");
            }
        }
    }
}
