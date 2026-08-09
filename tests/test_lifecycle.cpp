#include "domain_api.hpp"
#include "ipc/common.hpp"
#include "support.hpp"
#include "test_runners.hpp"

#include <atomic>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

using hdltest::Counters;
using hdltest::IlLevel;
using hdltest::Report;
using hdltest::TargetProc;
using hdltest::TargetProfile;

static void RunSessionLifetimeRaceTests(Counters& c) {
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
            hdl::rpc::v1::SearchCreateResponse response;
            int32_t status = HDL_E_FAILED;
            if (!hdltest::PipeUnary<hdl::rpc::Method::Search_SearchCreate>(
                    self_pid, hdl::rpc::v1::Empty{}, &response, &status) ||
                status != HDL_OK || !(search_id = response.session_id())) {
                faults.fetch_add(1);
                break;
            }
        }
        {
            hdl::rpc::v1::DiscoverCreateResponse response;
            int32_t status = HDL_E_FAILED;
            if (!hdltest::PipeUnary<hdl::rpc::Method::Discover_DiscoverCreate>(
                    self_pid, hdl::rpc::v1::Empty{}, &response, &status) ||
                status != HDL_OK || !(disc_id = response.session_id())) {
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
                        hdl::rpc::v1::SearchResetRequest request;
                        request.set_session_id(search_id);
                        hdl::rpc::v1::Empty response;
                        int32_t status = HDL_E_FAILED;
                        if (hdltest::PipeUnary<hdl::rpc::Method::Search_SearchReset>(
                                self_pid, request, &response, &status, 2000) &&
                            status != HDL_OK && status != HDL_E_NOT_FOUND)
                            bad_status.fetch_add(1);
                    }
                    {
                        hdl::rpc::v1::DiscoverGetCandidatesRequest request;
                        request.set_session_id(disc_id);
                        request.set_max_results(8);
                        int32_t status = HDL_E_FAILED;
                        if (hdltest::PipeStream<hdl::rpc::Method::Discover_DiscoverGetCandidates>(
                                self_pid, request, [](const auto&) { return true; }, &status,
                                2000) &&
                            status != HDL_OK && status != HDL_E_NOT_FOUND &&
                            status != HDL_E_BUFFER_SMALL)
                            bad_status.fetch_add(1);
                    }
                }
            });
        }
        Sleep(5);
        {
            hdl::rpc::v1::SearchCloseRequest request;
            request.set_session_id(search_id);
            hdl::rpc::v1::Empty response;
            hdltest::PipeUnary<hdl::rpc::Method::Search_SearchClose>(self_pid, request, &response,
                                                                     nullptr, 2000);
        }
        {
            hdl::rpc::v1::DiscoverCloseRequest request;
            request.set_session_id(disc_id);
            hdl::rpc::v1::Empty response;
            hdltest::PipeUnary<hdl::rpc::Method::Discover_DiscoverClose>(self_pid, request,
                                                                         &response, nullptr, 2000);
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

    constexpr int kConcurrentInitCallers = 8;
    const uint64_t attempt_before = hdl::testapi::InitDiagnostics().attempt_id;
    std::atomic<int> init_callers_ready{0};
    std::atomic<bool> release_init_callers{false};
    std::vector<HdlStatus> init_statuses(kConcurrentInitCallers, HDL_E_FAILED);
    std::vector<std::thread> init_callers;
    init_callers.reserve(kConcurrentInitCallers);
    for (int i = 0; i < kConcurrentInitCallers; ++i) {
        init_callers.emplace_back([&, i] {
            init_callers_ready.fetch_add(1);
            while (!release_init_callers.load()) {
                std::this_thread::yield();
            }
            init_statuses[static_cast<size_t>(i)] = hdl::testapi::Init();
        });
    }
    while (init_callers_ready.load() != kConcurrentInitCallers) {
        std::this_thread::yield();
    }
    release_init_callers.store(true);
    for (auto& caller : init_callers) {
        caller.join();
    }
    const hdl::CoreInitDiagnostics concurrent_diag = hdl::testapi::InitDiagnostics();
    bool concurrent_init_ok = hdl::testapi::IsInitialized() &&
                              concurrent_diag.attempt_id == attempt_before + 1 &&
                              concurrent_diag.last_status == HDL_OK;
    for (const HdlStatus status : init_statuses) {
        concurrent_init_ok &= status == HDL_OK;
    }
    char concurrent_detail[160];
    snprintf(concurrent_detail, sizeof(concurrent_detail),
             "attempt_before=%llu attempt_after=%llu phase=%s status=%s elapsed_ms=%llu",
             static_cast<unsigned long long>(attempt_before),
             static_cast<unsigned long long>(concurrent_diag.attempt_id),
             hdl::testapi::InitPhaseName(concurrent_diag.phase),
             hdltest::StatusNameA(concurrent_diag.last_status),
             static_cast<unsigned long long>(concurrent_diag.elapsed_ms));
    Report(c, concurrent_init_ok, false, "lifecycle/concurrent_init_x8", concurrent_detail);
    hdl::testapi::Shutdown();

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

        hdl::rpc::v1::CallExportRequest call_request;
        call_request.set_name("HdlTestLifecycleQuickCall");
        call_request.set_wait_timeout_ms(2000);
        hdl::rpc::v1::CallExportResponse call_response;
        int32_t call_st = HDL_E_FAILED;
        const bool completed_call =
            injected &&
            hdltest::PipeUnary<hdl::rpc::Method::Call_CallExport>(target.pid, call_request,
                                                                  &call_response, &call_st, 4000) &&
            call_st == HDL_OK && call_response.result().call_id() != 0 &&
            call_response.result().phase() == hdl::rpc::v1::CALL_PHASE_COMPLETED &&
            !call_response.result().orphaned() &&
            call_response.result().return_value() == 0x51AFC0DEull;
        int32_t shut_st = HDL_E_FAILED;
        const bool shut_ok =
            completed_call && hdltest::PipeShutdown(target.pid, 0, &shut_st) && shut_st == HDL_OK;
        uint64_t ubase = 0;
        const HdlStatus ust =
            shut_ok ? hdl::UnloadDll(target.pid, dll_path, 0, 0, &ubase) : HDL_E_FAILED;
        const bool unloaded = ust == HDL_OK || ust == HDL_E_NOT_FOUND;
        const bool alive = WaitForSingleObject(target.process, 0) == WAIT_TIMEOUT;
        if (injected && completed_call && shut_ok && unloaded && alive) {
            ++inject_ok;
        }
        target.Close();
    }
    Report(c, inject_ok == kInjectUnloadRounds, false,
           "lifecycle/completed_call_shutdown_unload_x5", "");
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
        /* Register the secondary DLL with the injected server before shutdown. */
        hdl::rpc::v1::TrackLoadedDllRequest request;
        request.set_base(secondary);
        std::string path;
        const int wide_length = static_cast<int>(wcslen(sys));
        const int needed = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, sys, wide_length,
                                               nullptr, 0, nullptr, nullptr);
        if (needed > 0) {
            path.resize(static_cast<size_t>(needed));
            WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, sys, wide_length, path.data(),
                                needed, nullptr, nullptr);
        }
        request.set_dll_path(std::move(path));
        hdl::rpc::v1::Empty response;
        int32_t track_st = HDL_E_FAILED;
        const bool tracked = hdltest::PipeUnary<hdl::rpc::Method::Injection_TrackLoadedDll>(
            target.pid, request, &response, &track_st);
        Report(c, tracked && track_st == HDL_OK, false, "clean_unload/track secondary", "");
    }

    int32_t shut_st = HDL_E_FAILED;
    const bool shut_ok = hdltest::PipeShutdown(target.pid, HDL_SHUTDOWN_UNLOAD_MODULES, &shut_st) &&
                         shut_st == HDL_OK;
    Report(c, shut_ok, false, "clean_unload/Control.Shutdown modules", "");

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
