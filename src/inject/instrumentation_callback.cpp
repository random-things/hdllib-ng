#include "inject/common.hpp"
#include "inject/techniques.hpp"
#include "win/raii.hpp"

namespace hdl {
namespace inject {
namespace {

struct ProcessInstrumentationCallbackInfo {
    ULONG Version;
    ULONG Reserved;
    PVOID Callback;
};

// Runs in the target: NtSetInformationProcess(NtCurrentProcess(), 40, info, 16).
#pragma pack(push, 1)
struct RemoteSetCallbackStub {
    uint8_t sub_rsp[4] = {0x48, 0x83, 0xEC, 0x28};
    uint8_t mov_rcx_imm[7] = {0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t mov_edx[5] = {0xBA, 0x28, 0x00, 0x00, 0x00};
    uint8_t mov_r8[2] = {0x49, 0xB8};
    uint64_t info_ptr = 0;
    uint8_t mov_r9d[6] = {0x41, 0xB9, 0x10, 0x00, 0x00, 0x00};
    uint8_t mov_rax[2] = {0x48, 0xB8};
    uint64_t nt_set = 0;
    uint8_t call_rax[2] = {0xFF, 0xD0};
    uint8_t add_rsp[4] = {0x48, 0x83, 0xC4, 0x28};
    uint8_t ret[1] = {0xC3};
};
#pragma pack(pop)

// One-shot LoadLibrary with proper x64 stack alignment; return address in R10.
#pragma pack(push, 1)
struct InstrumentationStub {
    uint8_t push_r10[2] = {0x41, 0x52};
    uint8_t push_rax[1] = {0x50};
    // One-shot: xchg flag
    uint8_t mov_rax_flag[2] = {0x48, 0xB8};
    uint64_t done_flag = 0;
    uint8_t mov_al_1[2] = {0xB0, 0x01};
    uint8_t xchg_al[2] = {0x86, 0x00};
    uint8_t test_al[2] = {0x84, 0xC0};
    uint8_t jnz_skip[2] = {0x75, 0x00}; // → restore path
    // Align stack for call (ABI requires 16-byte alignment before CALL)
    uint8_t push_rbx[1] = {0x53};
    uint8_t mov_rbx_rsp[3] = {0x48, 0x89, 0xE3};
    uint8_t and_rsp[4] = {0x48, 0x83, 0xE4, 0xF0};
    uint8_t sub_rsp[4] = {0x48, 0x83, 0xEC, 0x20};
    uint8_t mov_rcx[2] = {0x48, 0xB9};
    uint64_t path = 0;
    uint8_t mov_rax_ll[2] = {0x48, 0xB8};
    uint64_t loadlib = 0;
    uint8_t call_rax[2] = {0xFF, 0xD0};
    uint8_t mov_rsp_rbx[3] = {0x48, 0x89, 0xDC};
    uint8_t pop_rbx[1] = {0x5B};
    // skip / restore:
    uint8_t pop_rax[1] = {0x58};
    uint8_t pop_r10[2] = {0x41, 0x5A};
    uint8_t jmp_r10[3] = {0x41, 0xFF, 0xE2};
};
#pragma pack(pop)

} // namespace

HdlStatus InstrumentationCallbackMethod(uint32_t pid, const wchar_t* dll_path, uint64_t* out_base) {
    auto nt_set = GetLoadedModuleProc(L"ntdll.dll", "NtSetInformationProcess");
    if (!nt_set) {
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

    RemoteAlloc flag_mem;
    uint8_t zero = 0;
    if (!flag_mem.Alloc(process.get(), 1) || !flag_mem.Write(&zero, 1)) {
        return HDL_E_NO_MEM;
    }

    InstrumentationStub cb{};
    cb.done_flag = reinterpret_cast<uint64_t>(flag_mem.ptr);
    cb.path = reinterpret_cast<uint64_t>(path_mem.ptr);
    cb.loadlib = reinterpret_cast<uint64_t>(GetKernel32Proc("LoadLibraryW"));
    // Bytes after jnz to skip label (pop_rax):
    // push_rbx(1)+mov_rbx_rsp(3)+and(4)+sub(4)+mov_rcx(10)+mov_rax(10)+call(2)+mov_rsp(3)+pop_rbx(1)
    // = 38
    cb.jnz_skip[1] = 38;

    RemoteAlloc cb_mem;
    if (!cb_mem.Alloc(process.get(), sizeof(cb), PAGE_EXECUTE_READWRITE) ||
        !cb_mem.Write(&cb, sizeof(cb))) {
        return HDL_E_NO_MEM;
    }

    ProcessInstrumentationCallbackInfo info{};
    info.Version = 0;
    info.Reserved = 0;
    info.Callback = cb_mem.ptr;
    RemoteAlloc info_mem;
    if (!info_mem.Alloc(process.get(), sizeof(info)) || !info_mem.Write(&info, sizeof(info))) {
        return HDL_E_NO_MEM;
    }

    RemoteSetCallbackStub set_stub{};
    set_stub.info_ptr = reinterpret_cast<uint64_t>(info_mem.ptr);
    set_stub.nt_set = reinterpret_cast<uint64_t>(nt_set);

    RemoteAlloc set_mem;
    if (!set_mem.Alloc(process.get(), sizeof(set_stub), PAGE_EXECUTE_READWRITE) ||
        !set_mem.Write(&set_stub, sizeof(set_stub))) {
        return HDL_E_NO_MEM;
    }

    win::unique_handle t(::CreateRemoteThread(process.get(), nullptr, 0,
                                              reinterpret_cast<LPTHREAD_START_ROUTINE>(set_mem.ptr),
                                              nullptr, 0, nullptr));
    if (!t) {
        return HDL_E_FAILED;
    }
    WaitForSingleObject(t.get(), 5000);
    DWORD exit_code = 0;
    GetExitCodeThread(t.get(), &exit_code);
    t.reset();

    if (static_cast<NTSTATUS>(exit_code) < 0) {
        info.Version = 1;
        info_mem.Write(&info, sizeof(info));
        t.reset(::CreateRemoteThread(process.get(), nullptr, 0,
                                     reinterpret_cast<LPTHREAD_START_ROUTINE>(set_mem.ptr), nullptr,
                                     0, nullptr));
        if (!t) {
            return HDL_E_FAILED;
        }
        WaitForSingleObject(t.get(), 5000);
        GetExitCodeThread(t.get(), &exit_code);
        t.reset();
        if (static_cast<NTSTATUS>(exit_code) < 0) {
            HDL_LOG_ERROR(
                "NtSetInformationProcess(InstrumentationCallback) remote self-set failed: "
                "0x%08lX",
                exit_code);
            return HDL_E_FAILED;
        }
    }

    auto sleep_fn = reinterpret_cast<LPTHREAD_START_ROUTINE>(GetKernel32Proc("Sleep"));
    win::unique_handle nudge(::CreateRemoteThread(process.get(), nullptr, 0, sleep_fn,
                                                  reinterpret_cast<void*>(1), 0, nullptr));
    if (nudge) {
        WaitForSingleObject(nudge.get(), 2000);
    }
    nudge.reset();

    st = PollForModule(pid, dll_path, out_base);

    info.Version = 0;
    info.Callback = nullptr;
    info_mem.Write(&info, sizeof(info));
    t.reset(::CreateRemoteThread(process.get(), nullptr, 0,
                                 reinterpret_cast<LPTHREAD_START_ROUTINE>(set_mem.ptr), nullptr, 0,
                                 nullptr));
    if (t) {
        WaitForSingleObject(t.get(), 2000);
    }
    t.reset();

    path_mem.Detach();
    flag_mem.Detach();
    cb_mem.Detach();
    info_mem.Detach();
    set_mem.Detach();

    if (st == HDL_OK) {
        HDL_LOG_INFO("InstrumentationCallback inject into pid %u ok", pid);
    } else {
        HDL_LOG_ERROR("InstrumentationCallback set but module not observed");
    }
    return st;
}

} // namespace inject
} // namespace hdl
