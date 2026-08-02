#include "inject/common.hpp"
#include "inject/techniques.hpp"
#include "win/raii.hpp"

namespace hdl {
namespace inject {
namespace {

using RtlRemoteCall_t = NTSTATUS(NTAPI*)(HANDLE Process, HANDLE Thread, PVOID CallSite,
                                         ULONG ArgumentCount, PULONG_PTR Arguments,
                                         BOOLEAN PassContext, BOOLEAN AlreadySuspended);

using NtContinue_t = NTSTATUS(NTAPI*)(PCONTEXT Context, BOOLEAN RaiseAlert);

#if defined(_M_X64) || defined(__x86_64__)

// LoadLibraryW(path) then NtContinue(saved_context) so RSP/RIP/regs match the pre-call thread
// state. This avoids brittle RtlRemoteCall post-return stack restore across Windows builds.
#pragma pack(push, 1)
struct RtlRemoteLoadStub {
    uint8_t sub_rsp[4] = {0x48, 0x83, 0xEC, 0x28};
    uint8_t mov_rcx[2] = {0x48, 0xB9};
    uint64_t path = 0;
    uint8_t mov_rax[2] = {0x48, 0xB8};
    uint64_t loadlib = 0;
    uint8_t call_rax[2] = {0xFF, 0xD0};
    uint8_t add_rsp[4] = {0x48, 0x83, 0xC4, 0x28};
    uint8_t mov_rcx_ctx[2] = {0x48, 0xB9};
    uint64_t context = 0;
    uint8_t xor_edx[2] = {0x31, 0xD2}; // RaiseAlert = FALSE
    uint8_t mov_rax_nt[2] = {0x48, 0xB8};
    uint64_t nt_continue = 0;
    uint8_t jmp_rax[2] = {0xFF, 0xE0};
};
#pragma pack(pop)

#endif

} // namespace

HdlStatus RtlRemoteCallMethod(uint32_t pid, const wchar_t* dll_path, uint64_t* out_base) {
#if !(defined(_M_X64) || defined(__x86_64__))
    (void)pid;
    (void)dll_path;
    (void)out_base;
    return HDL_E_FAILED;
#else
    auto rtl_remote = reinterpret_cast<RtlRemoteCall_t>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlRemoteCall"));
    auto nt_continue = reinterpret_cast<NtContinue_t>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtContinue"));
    auto load_library = GetKernel32Proc("LoadLibraryW");
    if (!rtl_remote || !nt_continue || !load_library) {
        return HDL_E_NOT_FOUND;
    }

    win::unique_handle process(OpenTargetProcess(pid));
    if (!process) {
        return HDL_E_ACCESS;
    }

    RemoteAlloc path_mem;
    HdlStatus st = WriteRemotePath(process.get(), dll_path, path_mem);
    if (st != HDL_OK) {
        return st;
    }

    const auto tids = EnumProcessThreads(pid);
    bool invoked = false;
    for (DWORD tid : tids) {
        win::unique_handle thread(OpenThread(THREAD_SET_CONTEXT | THREAD_GET_CONTEXT |
                                                 THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
                                             FALSE, tid));
        if (!thread) {
            continue;
        }

        if (SuspendThread(thread.get()) == static_cast<DWORD>(-1)) {
            continue;
        }

        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_FULL;
        if (!GetThreadContext(thread.get(), &ctx)) {
            ResumeThread(thread.get());
            continue;
        }

        RemoteAlloc ctx_mem;
        if (!ctx_mem.Alloc(process.get(), sizeof(CONTEXT)) ||
            !ctx_mem.Write(&ctx, sizeof(CONTEXT))) {
            ResumeThread(thread.get());
            continue;
        }

        RtlRemoteLoadStub stub{};
        stub.path = reinterpret_cast<uint64_t>(path_mem.ptr);
        stub.loadlib = reinterpret_cast<uint64_t>(load_library);
        stub.context = reinterpret_cast<uint64_t>(ctx_mem.ptr);
        stub.nt_continue = reinterpret_cast<uint64_t>(nt_continue);

        RemoteAlloc stub_mem;
        if (!stub_mem.Alloc(process.get(), sizeof(stub), PAGE_EXECUTE_READWRITE) ||
            !stub_mem.Write(&stub, sizeof(stub))) {
            ResumeThread(thread.get());
            continue;
        }

        NTSTATUS nt =
            rtl_remote(process.get(), thread.get(), stub_mem.ptr, 0, nullptr, FALSE, TRUE);
        if (nt < 0) {
            // Fallback: marshaled LoadLibraryW(path); relies on RtlRemoteCall return restore.
            ULONG_PTR args[1] = {reinterpret_cast<ULONG_PTR>(path_mem.ptr)};
            nt = rtl_remote(process.get(), thread.get(), reinterpret_cast<PVOID>(load_library), 1,
                            args, FALSE, TRUE);
        }

        if (nt < 0) {
            HDL_LOG_ERROR("RtlRemoteCall tid=%lu failed: 0x%08lX", tid,
                          static_cast<unsigned long>(nt));
            ResumeThread(thread.get());
            continue;
        }

        stub_mem.Detach();
        ctx_mem.Detach();
        ResumeThread(thread.get());
        invoked = true;
        break;
    }

    if (!invoked) {
        return HDL_E_FAILED;
    }

    st = PollForModule(pid, dll_path, out_base);
    path_mem.Detach();

    if (st == HDL_OK) {
        HDL_LOG_INFO("RtlRemoteCall inject into pid %u ok", pid);
    }
    return st;
#endif
}

} // namespace inject
} // namespace hdl
