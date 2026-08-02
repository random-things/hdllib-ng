#include "domain_api.hpp"
#include "ipc/wire.hpp"
#include "protocol.hpp"
#include "support.hpp"
#include "test_runners.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using hdltest::Counters;
using hdltest::Expect;
using hdltest::IlLevel;
using hdltest::Report;
using hdltest::TargetProc;
using hdltest::TargetProfile;

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
