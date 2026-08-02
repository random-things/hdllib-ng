#include "inject/common.hpp"
#include "inject/techniques.hpp"
#include "win/raii.hpp"

#include <evntprov.h>
#include <evntrace.h>
#include <wmistr.h>

#include <vector>

#pragma comment(lib, "advapi32.lib")

namespace hdl {
namespace inject {
namespace {

// {B5A6F0C1-4E2D-4A91-9C3B-7D1E8F0A2B44}
constexpr GUID kHdlEtwProvider = {
    0xb5a6f0c1, 0x4e2d, 0x4a91, {0x9c, 0x3b, 0x7d, 0x1e, 0x8f, 0x0a, 0x2b, 0x44}};

using EtwEventRegister_t = ULONG(NTAPI*)(LPCGUID ProviderId, PVOID EnableCallback,
                                         PVOID CallbackContext, PREGHANDLE RegHandle);

// EnableCallback: if IsEnabled != 0 → LoadLibraryW(path_imm)
#pragma pack(push, 1)
struct EtwEnableStub {
    uint8_t test_edx[2] = {0x85, 0xD2};
    uint8_t jz_out[2] = {0x74, 0x00};
    uint8_t sub_rsp[4] = {0x48, 0x83, 0xEC, 0x28};
    uint8_t mov_rcx[2] = {0x48, 0xB9};
    uint64_t path = 0;
    uint8_t mov_rax[2] = {0x48, 0xB8};
    uint64_t loadlib = 0;
    uint8_t call_rax[2] = {0xFF, 0xD0};
    uint8_t add_rsp[4] = {0x48, 0x83, 0xC4, 0x28};
    uint8_t xor_eax[2] = {0x31, 0xC0};
    uint8_t ret[1] = {0xC3};
};
#pragma pack(pop)

struct EtwRegArgs {
    uint64_t event_register;
    uint64_t provider_guid;
    uint64_t enable_callback;
    uint64_t callback_context;
    uint64_t reg_handle_out;
};

#pragma pack(push, 1)
struct EtwRegStub {
    uint8_t sub_rsp[4] = {0x48, 0x83, 0xEC, 0x28};
    uint8_t mov_rsi[3] = {0x48, 0x89, 0xCE};
    uint8_t mov_rcx[4] = {0x48, 0x8B, 0x4E, 0x08};
    uint8_t mov_rdx[4] = {0x48, 0x8B, 0x56, 0x10};
    uint8_t mov_r8[4] = {0x4C, 0x8B, 0x46, 0x18};
    uint8_t lea_r9[4] = {0x4C, 0x8D, 0x4E, 0x20};
    uint8_t mov_rax[3] = {0x48, 0x8B, 0x06};
    uint8_t call_rax[2] = {0xFF, 0xD0};
    uint8_t add_rsp[4] = {0x48, 0x83, 0xC4, 0x28};
    uint8_t ret[1] = {0xC3};
};
#pragma pack(pop)

} // namespace

HdlStatus EtwCallbackMethod(uint32_t pid, const wchar_t* dll_path, uint64_t* out_base) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto etw_reg = reinterpret_cast<EtwEventRegister_t>(GetProcAddress(ntdll, "EtwEventRegister"));
    if (!etw_reg) {
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

    RemoteAlloc guid_mem;
    if (!guid_mem.Alloc(process.get(), sizeof(GUID)) ||
        !guid_mem.Write(&kHdlEtwProvider, sizeof(GUID))) {
        return HDL_E_NO_MEM;
    }

    EtwEnableStub cb{};
    cb.path = reinterpret_cast<uint64_t>(path_mem.ptr);
    cb.loadlib = reinterpret_cast<uint64_t>(GetKernel32Proc("LoadLibraryW"));
    // jz → xor_eax: sub(4)+mov_rcx(2)+path(8)+mov_rax(2)+ll(8)+call(2)+add(4) = 30
    cb.jz_out[1] = 30;

    RemoteAlloc cb_mem;
    if (!cb_mem.Alloc(process.get(), sizeof(cb), PAGE_EXECUTE_READWRITE) ||
        !cb_mem.Write(&cb, sizeof(cb))) {
        return HDL_E_NO_MEM;
    }

    EtwRegArgs args{};
    args.event_register = reinterpret_cast<uint64_t>(etw_reg);
    args.provider_guid = reinterpret_cast<uint64_t>(guid_mem.ptr);
    args.enable_callback = reinterpret_cast<uint64_t>(cb_mem.ptr);
    args.callback_context = reinterpret_cast<uint64_t>(path_mem.ptr);
    args.reg_handle_out = 0;

    RemoteAlloc args_mem;
    if (!args_mem.Alloc(process.get(), sizeof(args)) || !args_mem.Write(&args, sizeof(args))) {
        return HDL_E_NO_MEM;
    }

    EtwRegStub reg_stub{};
    RemoteAlloc reg_stub_mem;
    if (!reg_stub_mem.Alloc(process.get(), sizeof(reg_stub), PAGE_EXECUTE_READWRITE) ||
        !reg_stub_mem.Write(&reg_stub, sizeof(reg_stub))) {
        return HDL_E_NO_MEM;
    }

    win::unique_handle t(::CreateRemoteThread(
        process.get(), nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(reg_stub_mem.ptr),
        args_mem.ptr, 0, nullptr));
    if (!t) {
        return HDL_E_FAILED;
    }
    WaitForSingleObject(t.get(), 10000);
    t.reset();

    const ULONG buf_size = sizeof(EVENT_TRACE_PROPERTIES) + 64 * sizeof(wchar_t);
    std::vector<uint8_t> prop_buf(buf_size);
    auto* props = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(prop_buf.data());
    props->Wnode.BufferSize = buf_size;
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 1;
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    TRACEHANDLE session = 0;
    ULONG result = StartTraceW(&session, L"HDL_ETW_INJECT", props);
    if (result == ERROR_ALREADY_EXISTS) {
        ControlTraceW(0, L"HDL_ETW_INJECT", props, EVENT_TRACE_CONTROL_STOP);
        result = StartTraceW(&session, L"HDL_ETW_INJECT", props);
    }
    if (result == ERROR_SUCCESS) {
        EnableTraceEx2(session, &kHdlEtwProvider, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                       TRACE_LEVEL_VERBOSE, 0, 0, 0, nullptr);
        Sleep(300);
        EnableTraceEx2(session, &kHdlEtwProvider, EVENT_CONTROL_CODE_DISABLE_PROVIDER, 0, 0, 0, 0,
                       nullptr);
        ControlTraceW(session, nullptr, props, EVENT_TRACE_CONTROL_STOP);
    } else {
        HDL_LOG_ERROR("ETW StartTraceW failed: %lu", result);
    }

    st = PollForModule(pid, dll_path, out_base);
    path_mem.Detach();
    guid_mem.Detach();
    cb_mem.Detach();
    args_mem.Detach();
    reg_stub_mem.Detach();

    if (st == HDL_OK) {
        HDL_LOG_INFO("ETW enable-callback inject into pid %u ok", pid);
    }
    return st;
}

} // namespace inject
} // namespace hdl
