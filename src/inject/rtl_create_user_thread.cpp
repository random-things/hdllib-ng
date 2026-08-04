#include "inject/common.hpp"
#include "inject/techniques.hpp"
#include "win/raii.hpp"

namespace hdl {
namespace inject {
namespace {

struct ClientId {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
};

using RtlCreateUserThread_t = NTSTATUS(NTAPI*)(HANDLE ProcessHandle,
                                               PSECURITY_DESCRIPTOR SecurityDescriptor,
                                               BOOLEAN CreateSuspended, ULONG StackZeroBits,
                                               PULONG StackReserved, PULONG StackCommit,
                                               PVOID StartAddress, PVOID StartParameter,
                                               PHANDLE ThreadHandle, ClientId* ClientId);

} // namespace

HdlStatus RtlCreateUserThreadMethod(uint32_t pid, const wchar_t* dll_path, uint64_t* out_base) {
    auto rtl_create = reinterpret_cast<RtlCreateUserThread_t>(
        GetLoadedModuleProc(L"ntdll.dll", "RtlCreateUserThread"));
    if (!rtl_create) {
        return HDL_E_NOT_FOUND;
    }

    win::unique_handle process(OpenTargetProcess(pid));
    if (!process) {
        return HDL_E_ACCESS;
    }

    RemoteAlloc remote;
    HdlStatus st = WriteRemotePath(process.get(), dll_path, remote);
    if (st != HDL_OK) {
        return st;
    }

    void* load_library = reinterpret_cast<void*>(GetKernel32Proc("LoadLibraryW"));
    HANDLE raw_thread = nullptr;
    ClientId cid{};
    const NTSTATUS nt = rtl_create(process.get(), nullptr, FALSE, 0, nullptr, nullptr, load_library,
                                   remote.ptr, &raw_thread, &cid);
    win::unique_handle thread(raw_thread);
    if (nt < 0 || !thread) {
        HDL_LOG_ERROR("RtlCreateUserThread failed: 0x%08lX", static_cast<unsigned long>(nt));
        return HDL_E_FAILED;
    }

    st = WaitThreadAndBase(thread.get(), pid, dll_path, out_base);
    if (st == HDL_OK) {
        HDL_LOG_INFO("RtlCreateUserThread inject into pid %u ok", pid);
    }
    return st;
}

} // namespace inject
} // namespace hdl
