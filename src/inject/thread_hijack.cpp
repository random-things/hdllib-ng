#include "inject/common.hpp"
#include "inject/techniques.hpp"
#include "win/raii.hpp"

namespace hdl {
namespace inject {

#if defined(_M_X64) || defined(__x86_64__)

namespace {

#pragma pack(push, 1)
struct HijackStub {
    uint8_t sub_rsp[4] = {0x48, 0x83, 0xEC, 0x28};
    uint8_t mov_rcx[2] = {0x48, 0xB9};
    uint64_t path_imm = 0;
    uint8_t mov_rax[2] = {0x48, 0xB8};
    uint64_t loadlib_imm = 0;
    uint8_t call_rax[2] = {0xFF, 0xD0};
    uint8_t add_rsp[4] = {0x48, 0x83, 0xC4, 0x28};
    uint8_t mov_rax2[2] = {0x48, 0xB8};
    uint64_t rip_imm = 0;
    uint8_t jmp_rax[2] = {0xFF, 0xE0};
};
#pragma pack(pop)

} // namespace

HdlStatus ThreadHijackMethod(uint32_t pid, const wchar_t* dll_path, uint64_t* out_base) {
    win::unique_handle process(OpenTargetProcess(pid));
    if (!process) {
        return HDL_E_ACCESS;
    }

    RemoteAlloc remote_path;
    HdlStatus st = WriteRemotePath(process.get(), dll_path, remote_path);
    if (st != HDL_OK) {
        return st;
    }

    const auto tids = EnumProcessThreads(pid);
    win::unique_handle thread;
    DWORD chosen_tid = 0;
    CONTEXT ctx{};
    for (DWORD tid : tids) {
        win::unique_handle t(OpenThread(THREAD_ALL_ACCESS, FALSE, tid));
        if (!t) {
            continue;
        }
        if (SuspendThread(t.get()) == static_cast<DWORD>(-1)) {
            continue;
        }
        CONTEXT try_ctx{};
        try_ctx.ContextFlags = CONTEXT_FULL;
        if (GetThreadContext(t.get(), &try_ctx)) {
            thread = std::move(t);
            chosen_tid = tid;
            ctx = try_ctx;
            break;
        }
        ResumeThread(t.get());
    }
    if (!thread) {
        return HDL_E_NOT_FOUND;
    }

    HijackStub stub{};
    stub.path_imm = reinterpret_cast<uint64_t>(remote_path.ptr);
    stub.loadlib_imm = reinterpret_cast<uint64_t>(GetKernel32Proc("LoadLibraryW"));
    stub.rip_imm = ctx.Rip;

    RemoteAlloc remote_stub;
    if (!remote_stub.Alloc(process.get(), sizeof(stub), PAGE_EXECUTE_READWRITE) ||
        !remote_stub.Write(&stub, sizeof(stub))) {
        ResumeThread(thread.get());
        return HDL_E_NO_MEM;
    }

    ctx.Rip = reinterpret_cast<DWORD64>(remote_stub.ptr);
    if (!SetThreadContext(thread.get(), &ctx)) {
        ResumeThread(thread.get());
        return HDL_E_FAILED;
    }

    ResumeThread(thread.get());
    thread.reset();

    st = PollForModule(pid, dll_path, out_base);

    // Keep stub + path alive; freeing while a thread may still execute is unsafe.
    remote_path.Detach();
    remote_stub.Detach();

    if (st == HDL_OK) {
        HDL_LOG_INFO("Thread hijack inject into pid %u (tid=%lu) ok", pid, chosen_tid);
    }
    return st;
}

#else

HdlStatus ThreadHijackMethod(uint32_t, const wchar_t*, uint64_t*) {
    return HDL_E_FAILED;
}

#endif

} // namespace inject
} // namespace hdl
