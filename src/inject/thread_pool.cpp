#include "inject/common.hpp"
#include "inject/techniques.hpp"
#include "win/raii.hpp"

namespace hdl {
namespace inject {
namespace {

using TpAllocWork_t = NTSTATUS(NTAPI*)(PVOID* WorkReturn, PVOID Callback, PVOID Context,
                                       PVOID CallbackEnviron);
using TpPostWork_t = VOID(NTAPI*)(PVOID Work);
using TpReleaseWork_t = VOID(NTAPI*)(PVOID Work);

// Work callback: VOID NTAPI (Instance, Context, Work) — Context = path.
#pragma pack(push, 1)
struct TpWorkStub {
    uint8_t sub_rsp[4] = {0x48, 0x83, 0xEC, 0x28};
    // mov rcx, rdx  (Context)
    uint8_t mov_rcx_rdx[3] = {0x48, 0x89, 0xD1};
    uint8_t mov_rax[2] = {0x48, 0xB8};
    uint64_t loadlib = 0;
    uint8_t call_rax[2] = {0xFF, 0xD0};
    uint8_t add_rsp[4] = {0x48, 0x83, 0xC4, 0x28};
    uint8_t ret[1] = {0xC3};
};
#pragma pack(pop)

// Remote thread args for TpAllocWork + TpPostWork.
struct TpRemoteArgs {
    uint64_t tp_alloc_work;
    uint64_t tp_post_work;
    uint64_t tp_release_work;
    uint64_t callback;
    uint64_t context;
    uint64_t work_out; // written by stub
};

#pragma pack(push, 1)
struct TpDriverStub {
    uint8_t sub_rsp[4] = {0x48, 0x83, 0xEC, 0x28};
    uint8_t mov_rsi[3] = {0x48, 0x89, 0xCE}; // rsi = args
    // lea rcx, [rsi+28h]  -> &work_out  (offset of work_out in TpRemoteArgs)
    uint8_t lea_rcx[4] = {0x48, 0x8D, 0x4E, 0x28};
    // mov rdx, [rsi+18h] callback
    uint8_t mov_rdx[4] = {0x48, 0x8B, 0x56, 0x18};
    // mov r8, [rsi+20h] context
    uint8_t mov_r8[4] = {0x4C, 0x8B, 0x46, 0x20};
    // xor r9d, r9d
    uint8_t xor_r9[3] = {0x45, 0x31, 0xC9};
    // mov rax, [rsi]
    uint8_t mov_rax1[3] = {0x48, 0x8B, 0x06};
    uint8_t call_rax1[2] = {0xFF, 0xD0};
    // test eax, eax (NTSTATUS)
    uint8_t test_eax[2] = {0x85, 0xC0};
    uint8_t js_out[2] = {0x78, 0x00}; // patch
    // mov rcx, [rsi+28h] work
    uint8_t mov_rcx_work[4] = {0x48, 0x8B, 0x4E, 0x28};
    // mov rax, [rsi+8] TpPostWork
    uint8_t mov_rax2[4] = {0x48, 0x8B, 0x46, 0x08};
    uint8_t call_rax2[2] = {0xFF, 0xD0};
    // mov rcx, [rsi+28h]
    uint8_t mov_rcx2[4] = {0x48, 0x8B, 0x4E, 0x28};
    // mov rax, [rsi+10h] TpReleaseWork
    uint8_t mov_rax3[4] = {0x48, 0x8B, 0x46, 0x10};
    uint8_t call_rax3[2] = {0xFF, 0xD0};
    // out:
    uint8_t xor_eax[2] = {0x31, 0xC0};
    uint8_t add_rsp[4] = {0x48, 0x83, 0xC4, 0x28};
    uint8_t ret[1] = {0xC3};
};
#pragma pack(pop)

} // namespace

HdlStatus ThreadPoolMethod(uint32_t pid, const wchar_t* dll_path, uint64_t* out_base) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto tp_alloc = reinterpret_cast<TpAllocWork_t>(GetProcAddress(ntdll, "TpAllocWork"));
    auto tp_post = reinterpret_cast<TpPostWork_t>(GetProcAddress(ntdll, "TpPostWork"));
    auto tp_release = reinterpret_cast<TpReleaseWork_t>(GetProcAddress(ntdll, "TpReleaseWork"));
    if (!tp_alloc || !tp_post || !tp_release) {
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

    TpWorkStub cb{};
    cb.loadlib = reinterpret_cast<uint64_t>(GetKernel32Proc("LoadLibraryW"));
    RemoteAlloc cb_mem;
    if (!cb_mem.Alloc(process.get(), sizeof(cb), PAGE_EXECUTE_READWRITE) ||
        !cb_mem.Write(&cb, sizeof(cb))) {
        return HDL_E_NO_MEM;
    }

    TpRemoteArgs args{};
    args.tp_alloc_work = reinterpret_cast<uint64_t>(tp_alloc);
    args.tp_post_work = reinterpret_cast<uint64_t>(tp_post);
    args.tp_release_work = reinterpret_cast<uint64_t>(tp_release);
    args.callback = reinterpret_cast<uint64_t>(cb_mem.ptr);
    args.context = reinterpret_cast<uint64_t>(path_mem.ptr);
    args.work_out = 0;

    RemoteAlloc args_mem;
    if (!args_mem.Alloc(process.get(), sizeof(args)) || !args_mem.Write(&args, sizeof(args))) {
        return HDL_E_NO_MEM;
    }

    TpDriverStub driver{};
    // js_out: skip post/release on failure — bytes until xor_eax
    // mov_rcx_work(4)+mov_rax2(4)+call(2)+mov_rcx2(4)+mov_rax3(4)+call(2) = 20
    driver.js_out[1] = 20;

    RemoteAlloc driver_mem;
    if (!driver_mem.Alloc(process.get(), sizeof(driver), PAGE_EXECUTE_READWRITE) ||
        !driver_mem.Write(&driver, sizeof(driver))) {
        return HDL_E_NO_MEM;
    }

    win::unique_handle t(::CreateRemoteThread(
        process.get(), nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(driver_mem.ptr),
        args_mem.ptr, 0, nullptr));
    if (!t) {
        return HDL_E_FAILED;
    }
    WaitForSingleObject(t.get(), 10000);
    t.reset();

    st = PollForModule(pid, dll_path, out_base);
    path_mem.Detach();
    cb_mem.Detach();
    args_mem.Detach();
    driver_mem.Detach();

    if (st == HDL_OK) {
        HDL_LOG_INFO("ThreadPool (TpAllocWork/TpPostWork) inject into pid %u ok", pid);
    }
    return st;
}

} // namespace inject
} // namespace hdl
