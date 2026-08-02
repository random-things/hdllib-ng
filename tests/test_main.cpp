#include "domain_api.hpp"
#include "support.hpp"
#include "test_runners.hpp"

#include <cstdio>
#include <string>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

namespace {

void PrintUsage() {
    std::wprintf(L"Usage:\n"
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

    hdltest::Counters c;
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
    if (hdl::testapi::IsInitialized()) {
        hdl::testapi::Shutdown();
    }
    TerminateProcess(GetCurrentProcess(), c.failed == 0 ? 0 : 1);
    return c.failed == 0 ? 0 : 1;
}
