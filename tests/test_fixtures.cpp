#include "domain_api.hpp"
#include "test_runners.hpp"

#include <cstdio>
#include <cstring>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <sddl.h>

using hdltest::Counters;
using hdltest::Expect;
using hdltest::Report;

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

static bool EnsureWorldReadable(const wchar_t* path) {
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
    const size_t separator = built_dll.find_last_of(L"\\/");
    if (separator == std::wstring::npos) {
        return built_dll;
    }
    const std::wstring dir = built_dll.substr(0, separator) + L"\\hdl_test_payload";
    if (!CreateDirectoryW(dir.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS) {
        return built_dll;
    }
    EnsureWorldReadable(dir.c_str());

    std::wstring dest = dir + L"\\hdllib.dll";
    if (!CopyFileW(built_dll.c_str(), dest.c_str(), FALSE)) {
        return built_dll;
    }
    EnsureWorldReadable(dest.c_str());
    return dest;
}
