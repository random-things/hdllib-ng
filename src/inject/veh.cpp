#include "inject/common.hpp"
#include "inject/techniques.hpp"
#include "win/raii.hpp"

namespace hdl {
namespace inject {
namespace {

// VEH handler(EXCEPTION_POINTERS*): if EXCEPTION_BREAKPOINT -> LoadLibraryW(path); return -1
// LONG CALLBACK handler(PEXCEPTION_POINTERS ExceptionInfo)
#pragma pack(push, 1)
struct VehStub {
    // mov rax, [rcx]        ; ExceptionRecord
    uint8_t mov_rax_rcx[3] = {0x48, 0x8B, 0x01};
    // cmp dword ptr [rax], 80000003h  ; EXCEPTION_BREAKPOINT
    uint8_t cmp_code[6] = {0x81, 0x38, 0x03, 0x00, 0x00, 0x80};
    uint8_t jne_out[2] = {0x75, 0x00}; // patch
    uint8_t sub_rsp[4] = {0x48, 0x83, 0xEC, 0x28};
    uint8_t mov_rcx[2] = {0x48, 0xB9};
    uint64_t path = 0;
    uint8_t mov_rax_ll[2] = {0x48, 0xB8};
    uint64_t loadlib = 0;
    uint8_t call_rax[2] = {0xFF, 0xD0};
    uint8_t add_rsp[4] = {0x48, 0x83, 0xC4, 0x28};
    // mov eax, 0xFFFFFFFF ; EXCEPTION_CONTINUE_EXECUTION (-1)
    uint8_t mov_eax[5] = {0xB8, 0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t ret1[1] = {0xC3};
    // out: xor eax,eax ; ret  (EXCEPTION_CONTINUE_SEARCH = 0)
    uint8_t xor_eax[2] = {0x31, 0xC0};
    uint8_t ret2[1] = {0xC3};
};
#pragma pack(pop)

using AddVeh_t = PVOID(WINAPI*)(ULONG First, PVOID Handler);
using RemoveVeh_t = ULONG(WINAPI*)(PVOID Handle);
using RtlAddVectoredExceptionHandler_t = PVOID(NTAPI*)(ULONG, PVOID);

struct VehAddArgs {
    uint64_t add_veh;
    uint64_t handler;
    uint64_t out_handle; // written by stub
};

// Thread start: rcx = VehAddArgs*
#pragma pack(push, 1)
struct CallAddVehStub {
    uint8_t sub_rsp[4] = {0x48, 0x83, 0xEC, 0x28};
    uint8_t mov_rsi[3] = {0x48, 0x89, 0xCE};             // mov rsi, rcx
    uint8_t mov_ecx[5] = {0xB9, 0x01, 0x00, 0x00, 0x00}; // First=1
    // mov rdx, [rsi+8] handler
    uint8_t mov_rdx[4] = {0x48, 0x8B, 0x56, 0x08};
    // mov rax, [rsi]
    uint8_t mov_rax[3] = {0x48, 0x8B, 0x06};
    uint8_t call_rax[2] = {0xFF, 0xD0};
    // mov [rsi+10h], rax
    uint8_t store[4] = {0x48, 0x89, 0x46, 0x10};
    uint8_t add_rsp[4] = {0x48, 0x83, 0xC4, 0x28};
    uint8_t ret[1] = {0xC3};
};
#pragma pack(pop)

} // namespace

HdlStatus VehMethod(uint32_t pid, const wchar_t* dll_path, uint64_t* out_base) {
    win::unique_handle process(OpenTargetProcess(pid));
    if (!process) {
        return HDL_E_ACCESS;
    }

    auto add_veh = reinterpret_cast<void*>(
        GetLoadedModuleProc(L"ntdll.dll", "RtlAddVectoredExceptionHandler"));
    auto remove_veh = reinterpret_cast<RemoveVeh_t>(
        GetLoadedModuleProc(L"ntdll.dll", "RtlRemoveVectoredExceptionHandler"));
    auto debug_break = reinterpret_cast<LPTHREAD_START_ROUTINE>(GetKernel32Proc("DebugBreak"));
    if (!add_veh || !debug_break) {
        return HDL_E_NOT_FOUND;
    }

    RemoteAlloc path_mem;
    HdlStatus st = WriteRemotePath(process.get(), dll_path, path_mem);
    if (st != HDL_OK) {
        return st;
    }

    VehStub handler{};
    handler.path = reinterpret_cast<uint64_t>(path_mem.ptr);
    handler.loadlib = reinterpret_cast<uint64_t>(GetKernel32Proc("LoadLibraryW"));
    handler.jne_out[1] = 36;

    RemoteAlloc handler_mem;
    if (!handler_mem.Alloc(process.get(), sizeof(handler), PAGE_EXECUTE_READWRITE) ||
        !handler_mem.Write(&handler, sizeof(handler))) {
        return HDL_E_NO_MEM;
    }

    VehAddArgs args{};
    args.add_veh = reinterpret_cast<uint64_t>(add_veh);
    args.handler = reinterpret_cast<uint64_t>(handler_mem.ptr);
    args.out_handle = 0;
    RemoteAlloc args_mem;
    if (!args_mem.Alloc(process.get(), sizeof(args)) || !args_mem.Write(&args, sizeof(args))) {
        return HDL_E_NO_MEM;
    }

    CallAddVehStub add_stub{};
    RemoteAlloc add_stub_mem;
    if (!add_stub_mem.Alloc(process.get(), sizeof(add_stub), PAGE_EXECUTE_READWRITE) ||
        !add_stub_mem.Write(&add_stub, sizeof(add_stub))) {
        return HDL_E_NO_MEM;
    }

    win::unique_handle t(::CreateRemoteThread(
        process.get(), nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(add_stub_mem.ptr),
        args_mem.ptr, 0, nullptr));
    if (!t) {
        return HDL_E_FAILED;
    }
    WaitForSingleObject(t.get(), INFINITE);
    t.reset();

    VehAddArgs args_out{};
    ReadRemote(process.get(), args_mem.ptr, &args_out, sizeof(args_out));
    if (!args_out.out_handle) {
        HDL_LOG_ERROR("VEH: RtlAddVectoredExceptionHandler returned null");
        return HDL_E_FAILED;
    }

    win::unique_handle brk(
        ::CreateRemoteThread(process.get(), nullptr, 0, debug_break, nullptr, 0, nullptr));
    if (brk) {
        WaitForSingleObject(brk.get(), 5000);
    }
    brk.reset();

    st = PollForModule(pid, dll_path, out_base);

    if (remove_veh && args_out.out_handle) {
        // Best-effort remove via remote thread calling RtlRemoveVectoredExceptionHandler.
        ::CreateRemoteThread(process.get(), nullptr, 0,
                             reinterpret_cast<LPTHREAD_START_ROUTINE>(remove_veh),
                             reinterpret_cast<void*>(args_out.out_handle), 0, nullptr);
        // Don't wait forever if remove hangs — detach and continue.
    }

    path_mem.Detach();
    handler_mem.Detach();
    args_mem.Detach();
    add_stub_mem.Detach();

    if (st == HDL_OK) {
        HDL_LOG_INFO("VEH inject into pid %u ok", pid);
    }
    return st;
}

} // namespace inject
} // namespace hdl
