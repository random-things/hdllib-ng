#include "inject/common.hpp"
#include "inject/techniques.hpp"
#include "win/raii.hpp"

#include <string>
#include <vector>

namespace hdl {
namespace inject {

HdlStatus EarlyBirdApcMethod(const wchar_t* exe_path, const wchar_t* dll_path, uint32_t* out_pid,
                             uint64_t* out_base) {
    if (!exe_path || !exe_path[0]) {
        return HDL_E_INVALID_ARG;
    }

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    std::wstring cmd = L"\"";
    cmd += exe_path;
    cmd += L"\"";

    std::vector<wchar_t> cmd_buf(cmd.begin(), cmd.end());
    cmd_buf.push_back(L'\0');

    if (!CreateProcessW(exe_path, cmd_buf.data(), nullptr, nullptr, FALSE, CREATE_SUSPENDED,
                        nullptr, nullptr, &si, &pi)) {
        HDL_LOG_ERROR("CreateProcessW failed: %lu", GetLastError());
        return HDL_E_FAILED;
    }

    win::unique_handle proc_handle(pi.hProcess);
    win::unique_handle thread_handle(pi.hThread);

    RemoteAlloc remote;
    HdlStatus st = WriteRemotePath(proc_handle.get(), dll_path, remote);
    if (st != HDL_OK) {
        TerminateProcess(proc_handle.get(), 1);
        return st;
    }

    auto load_library = reinterpret_cast<PAPCFUNC>(GetKernel32Proc("LoadLibraryW"));
    if (!QueueUserAPC(load_library, thread_handle.get(), reinterpret_cast<ULONG_PTR>(remote.ptr))) {
        HDL_LOG_ERROR("Early bird QueueUserAPC failed: %lu", GetLastError());
        TerminateProcess(proc_handle.get(), 1);
        return HDL_E_FAILED;
    }

    remote.Detach();
    ResumeThread(thread_handle.get());

    if (out_pid) {
        *out_pid = pi.dwProcessId;
    }

    st = PollForModule(pi.dwProcessId, dll_path, out_base);

    if (st == HDL_OK) {
        HDL_LOG_INFO("Early bird APC inject into new pid %lu ok", pi.dwProcessId);
    } else {
        HDL_LOG_ERROR("Early bird APC: process started but module not observed");
    }
    return st;
}

} // namespace inject
} // namespace hdl
