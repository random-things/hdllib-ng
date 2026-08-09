#include "inject/select.hpp"
#include "inject/unload_policy.hpp"

#include <cstdio>
#include <cstring>

namespace {

struct Counters {
    int passed = 0;
    int failed = 0;
};

void Expect(Counters& c, bool ok, const char* name) {
    if (ok) {
        ++c.passed;
        std::printf("[PASS] %s\n", name);
    } else {
        ++c.failed;
        std::printf("[FAIL] %s\n", name);
    }
}

hdl::inject::TargetProfile MakeOpenHeadless() {
    hdl::inject::TargetProfile p{};
    p.pid = 1;
    p.process_openable = true;
    p.threads_openable = true;
    p.suspend_context_openable = true;
    p.has_hwnd = false;
    p.kct_nonzero = false;
    p.sacrificial_module = true;
    p.elevated_self = true;
    p.has_hook_export = true;
    p.has_winevent_export = true;
    p.api_nt_create_thread_ex = true;
    p.api_rtl_create_user_thread = true;
    p.api_nt_queue_apc = true;
    p.api_nt_queue_apc_ex2 = true;
    p.api_rtl_remote_call = true;
    p.api_tp = true;
    p.api_etw = true;
    p.api_nt_create_section = true;
    p.api_rtl_add_veh = true;
    p.api_nt_set_info_process = true;
    return p;
}

hdl::inject::TargetProfile MakeGuiOpen() {
    auto p = MakeOpenHeadless();
    p.has_hwnd = true;
    p.kct_nonzero = true;
    return p;
}

hdl::inject::TargetProfile MakeGuiNoAccess() {
    auto p = MakeGuiOpen();
    p.process_openable = false;
    p.threads_openable = false;
    p.suspend_context_openable = false;
    p.kct_nonzero = false;
    p.sacrificial_module = false;
    return p;
}

const HdlInjectCandidate* FindCand(const HdlInjectCandidate* c, uint32_t n, int method) {
    for (uint32_t i = 0; i < n; ++i) {
        if (c[i].method == method) {
            return &c[i];
        }
    }
    return nullptr;
}

} // namespace

int main() {
    Counters c{};

    {
        const auto profile = MakeOpenHeadless();
        HdlInjectCandidate cands[hdl::inject::kMethodCount];
        uint32_t n = hdl::inject::kMethodCount;
        hdl::inject::ScoreAllMethods(profile, cands, &n);

        const auto* early = FindCand(cands, n, HDL_INJECT_EARLY_BIRD_APC);
        Expect(c,
               early && early->confidence == 0 &&
                   strstr(early->reasons, "early_bird_not_attach") != nullptr,
               "headless: early_bird ineligible");

        const auto* hook = FindCand(cands, n, HDL_INJECT_SET_WINDOWS_HOOK_EX);
        Expect(c, hook && hook->confidence == 0 && strstr(hook->reasons, "needs_hwnd") != nullptr,
               "headless: hook needs_hwnd");

        const auto* crt = FindCand(cands, n, HDL_INJECT_CREATE_REMOTE_THREAD);
        Expect(c, crt && (crt->flags & HDL_INJECT_CAND_ELIGIBLE) && crt->confidence >= 40,
               "headless: CRT eligible");

        const int best = hdl::inject::PickBestMethod(profile);
        Expect(c,
               best >= 0 && best != HDL_INJECT_SET_WINDOWS_HOOK_EX &&
                   best != HDL_INJECT_WINDOW_SUBCLASS && best != HDL_INJECT_KERNEL_CALLBACK_TABLE &&
                   best != HDL_INJECT_EARLY_BIRD_APC,
               "headless: auto avoids GUI/early_bird");
    }

    {
        const auto profile = MakeGuiOpen();
        HdlInjectCandidate cands[hdl::inject::kMethodCount];
        uint32_t n = hdl::inject::kMethodCount;
        hdl::inject::ScoreAllMethods(profile, cands, &n);

        const auto* hook = FindCand(cands, n, HDL_INJECT_SET_WINDOWS_HOOK_EX);
        Expect(c, hook && (hook->flags & HDL_INJECT_CAND_ELIGIBLE) && hook->confidence >= 40,
               "gui: hook eligible");

        const auto* kct = FindCand(cands, n, HDL_INJECT_KERNEL_CALLBACK_TABLE);
        Expect(c, kct && (kct->flags & HDL_INJECT_CAND_ELIGIBLE) && kct->confidence >= 40,
               "gui: kct eligible");

        const auto* apc = FindCand(cands, n, HDL_INJECT_QUEUE_USER_APC);
        Expect(c,
               apc && (apc->flags & HDL_INJECT_CAND_ELIGIBLE) &&
                   strstr(apc->reasons, "alertable_unknown") != nullptr && apc->confidence < 70,
               "gui: classic APC soft-penalized");
    }

    {
        const auto profile = MakeGuiNoAccess();
        HdlInjectCandidate cands[hdl::inject::kMethodCount];
        uint32_t n = hdl::inject::kMethodCount;
        hdl::inject::ScoreAllMethods(profile, cands, &n);

        const auto* crt = FindCand(cands, n, HDL_INJECT_CREATE_REMOTE_THREAD);
        Expect(c, crt && crt->confidence == 0, "no-access: CRT ineligible");

        const auto* hook = FindCand(cands, n, HDL_INJECT_SET_WINDOWS_HOOK_EX);
        Expect(c, hook && (hook->flags & HDL_INJECT_CAND_ELIGIBLE) && hook->confidence >= 40,
               "no-access: hook still eligible");

        const auto* winevent = FindCand(cands, n, HDL_INJECT_SET_WIN_EVENT_HOOK);
        Expect(c,
               winevent && (winevent->flags & HDL_INJECT_CAND_ELIGIBLE) &&
                   winevent->confidence >= 40,
               "no-access: win-event still eligible");

        const int best = hdl::inject::PickBestMethod(profile);
        Expect(c, best == HDL_INJECT_SET_WINDOWS_HOOK_EX || best == HDL_INJECT_SET_WIN_EVENT_HOOK,
               "no-access: auto picks hook family");
    }

    {
        auto profile = MakeOpenHeadless();
        profile.elevated_self = false;
        HdlInjectCandidate etw{};
        const hdl::inject::MethodRequirement* req =
            hdl::inject::FindMethodRequirement(HDL_INJECT_ETW_CALLBACK);
        Expect(c, req != nullptr, "etw catalog present");
        if (req) {
            hdl::inject::ScoreMethod(*req, profile, &etw);
            Expect(c, etw.confidence == 0 && strstr(etw.reasons, "needs_elevation") != nullptr,
                   "etw requires elevation");
        }
    }

    {
        auto profile = MakeOpenHeadless();
        profile.prefer_stealth = true;
        const int best = hdl::inject::PickBestMethod(profile);
        Expect(c, best == HDL_INJECT_MANUAL_MAP || best == HDL_INJECT_MODULE_STOMP,
               "stealth: auto prefers map/stomp");

        HdlInjectCandidate cands[hdl::inject::kMethodCount];
        uint32_t n = hdl::inject::kMethodCount;
        hdl::inject::ScoreAllMethods(profile, cands, &n);
        const auto* map = FindCand(cands, n, HDL_INJECT_MANUAL_MAP);
        const auto* crt = FindCand(cands, n, HDL_INJECT_CREATE_REMOTE_THREAD);
        Expect(c, map && crt && map->confidence > crt->confidence,
               "stealth: manual_map outranks CRT");
    }

    {
        auto profile = MakeOpenHeadless();
        profile.wow64_target = true;
        const int best = hdl::inject::PickBestMethod(profile);
        Expect(c, best < 0, "wow64: no auto method");
    }

    {
        using Disposition = hdl::inject::ShutdownConnectDisposition;
        Expect(c,
               hdl::inject::ClassifyShutdownConnectFailure(ERROR_TIMEOUT, false,
                                                           ERROR_FILE_NOT_FOUND,
                                                           true) == Disposition::PreparedPipeGone,
               "unload: only absent probe confirms prior shutdown");
        Expect(c,
               hdl::inject::ClassifyShutdownConnectFailure(
                   ERROR_TIMEOUT, false, ERROR_FILE_NOT_FOUND, false) == Disposition::Busy,
               "unload: unconfirmed absence refuses with BUSY");
        Expect(c,
               hdl::inject::ClassifyShutdownConnectFailure(ERROR_TIMEOUT, false, ERROR_PIPE_BUSY,
                                                           false) == Disposition::Busy,
               "unload: busy pipe refuses with BUSY");
        Expect(c,
               hdl::inject::ClassifyShutdownConnectFailure(
                   ERROR_ACCESS_DENIED, false, ERROR_ACCESS_DENIED, false) == Disposition::Failed,
               "unload: access failure refuses with FAILED");
        Expect(c,
               hdl::inject::ClassifyShutdownConnectFailure(
                   ERROR_ACCESS_DENIED, false, ERROR_FILE_NOT_FOUND, true) == Disposition::Failed,
               "unload: access failure stays FAILED after pipe disappears");
        Expect(c,
               hdl::inject::ClassifyShutdownConnectFailure(
                   ERROR_REVISION_MISMATCH, true, ERROR_SUCCESS, false) == Disposition::Failed,
               "unload: negotiation failure on live pipe refuses with FAILED");
        Expect(c,
               hdl::inject::ClassifyShutdownConnectFailure(ERROR_REVISION_MISMATCH, false,
                                                           ERROR_FILE_NOT_FOUND,
                                                           true) == Disposition::Failed,
               "unload: negotiation failure stays FAILED after pipe disappears");
    }

    std::printf("\nSelect tests: %d passed, %d failed\n", c.passed, c.failed);
    return c.failed == 0 ? 0 : 1;
}
