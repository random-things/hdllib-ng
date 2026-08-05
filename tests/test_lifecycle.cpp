#include "domain_api.hpp"
#include "ipc/common.hpp"
#include "ipc/wire.hpp"
#include "protocol.hpp"
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
            PreparedRequest req;
            std::vector<uint8_t> resp;
            SetMethod(req, hdl::rpc::Method::SearchCreate);
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
            PreparedRequest req;
            std::vector<uint8_t> resp;
            SetMethod(req, hdl::rpc::Method::DiscoverCreate);
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
                        PreparedRequest req;
                        std::vector<uint8_t> resp;
                        SetMethod(req, hdl::rpc::Method::SearchReset);
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
                        PreparedRequest req;
                        std::vector<uint8_t> resp;
                        SetMethod(req, hdl::rpc::Method::DiscoverGetCandidates);
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
            PreparedRequest req;
            std::vector<uint8_t> resp;
            SetMethod(req, hdl::rpc::Method::SearchClose);
            AppendPod(req, search_id);
            hdltest::PipeRequest(self_pid, req, resp, 2000);
        }
        {
            PreparedRequest req;
            std::vector<uint8_t> resp;
            SetMethod(req, hdl::rpc::Method::DiscoverClose);
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
        /* Register the secondary DLL with the injected server before shutdown. */
        hdl::rpc::PreparedRequest treq;
        hdl::rpc::SetMethod(treq, hdl::rpc::Method::TrackLoadedDll);
        hdl::proto::AppendPod(treq, secondary);
        hdl::proto::AppendWString(treq, sys);
        std::vector<uint8_t> response;
        int32_t track_st = HDL_E_FAILED;
        const bool tracked =
            hdltest::PipeRequest(target.pid, treq, response) && response.size() >= sizeof(track_st);
        if (tracked) {
            memcpy(&track_st, response.data(), sizeof(track_st));
        }
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
