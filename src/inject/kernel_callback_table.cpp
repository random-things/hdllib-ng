#include "inject/common.hpp"
#include "inject/techniques.hpp"
#include "win/raii.hpp"

#include <vector>

namespace hdl {
namespace inject {
namespace {

constexpr ULONG ProcessBasicInformation = 0;
constexpr size_t kPebKernelCallbackTable = 0x58;
constexpr size_t kFnCopyDataIndex = 0;
constexpr size_t kMaxTableEntries = 128;

struct ProcessBasicInfo {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
};

using NtQueryInformationProcess_t = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

#pragma pack(push, 1)
struct KctStub {
    uint8_t mov_rax_flag[2] = {0x48, 0xB8};
    uint64_t done_flag = 0;
    uint8_t mov_al_1[2] = {0xB0, 0x01};
    uint8_t xchg_al[2] = {0x86, 0x00};
    uint8_t test_al[2] = {0x84, 0xC0};
    uint8_t jnz_orig[2] = {0x75, 0x00};
    uint8_t push_rcx[1] = {0x51};
    uint8_t push_rdx[1] = {0x52};
    uint8_t push_r8[2] = {0x41, 0x50};
    uint8_t push_r9[2] = {0x41, 0x51};
    uint8_t sub_rsp[4] = {0x48, 0x83, 0xEC, 0x28};
    uint8_t mov_rcx[2] = {0x48, 0xB9};
    uint64_t path = 0;
    uint8_t mov_rax[2] = {0x48, 0xB8};
    uint64_t loadlib = 0;
    uint8_t call_rax[2] = {0xFF, 0xD0};
    uint8_t add_rsp[4] = {0x48, 0x83, 0xC4, 0x28};
    uint8_t pop_r9[2] = {0x41, 0x59};
    uint8_t pop_r8[2] = {0x41, 0x58};
    uint8_t pop_rdx[1] = {0x5A};
    uint8_t pop_rcx[1] = {0x59};
    uint8_t mov_rax2[2] = {0x48, 0xB8};
    uint64_t original = 0;
    uint8_t jmp_rax[2] = {0xFF, 0xE0};
};
#pragma pack(pop)

// SendMessageTimeoutW(hwnd, msg, wp, lp, flags, timeout, &result)
struct SendTimeoutArgs {
    uint64_t send_fn = 0;
    uint64_t hwnd = 0;
    uint32_t msg = WM_COPYDATA;
    uint32_t flags = SMTO_ABORTIFHUNG | SMTO_NORMAL;
    uint64_t wparam = 0;
    uint64_t lparam = 0;
    uint32_t timeout_ms = 2000;
    uint32_t pad = 0;
};

#pragma pack(push, 1)
struct SendTimeoutStub {
    uint8_t push_rsi[1] = {0x56};
    uint8_t mov_rsi_rcx[3] = {0x48, 0x89, 0xCE};
    uint8_t sub_rsp[4] = {0x48, 0x83, 0xEC, 0x40};
    uint8_t mov_rcx[4] = {0x48, 0x8B, 0x4E, 0x08}; // hwnd
    uint8_t mov_edx[3] = {0x8B, 0x56, 0x10};       // msg
    uint8_t mov_r8[4] = {0x4C, 0x8B, 0x46, 0x18};  // wparam
    uint8_t mov_r9[4] = {0x4C, 0x8B, 0x4E, 0x20};  // lparam
    uint8_t mov_eax_flags[3] = {0x8B, 0x46, 0x14}; // flags @+0x14
    uint8_t mov_stk_flags[4] = {0x89, 0x44, 0x24, 0x20};
    uint8_t mov_eax_to[3] = {0x8B, 0x46, 0x28}; // timeout @+0x28
    uint8_t mov_stk_to[4] = {0x89, 0x44, 0x24, 0x28};
    uint8_t lea_rax[5] = {0x48, 0x8D, 0x44, 0x24, 0x38}; // &result scratch
    uint8_t mov_stk_res[5] = {0x48, 0x89, 0x44, 0x24, 0x30};
    uint8_t mov_rax[3] = {0x48, 0x8B, 0x06};
    uint8_t call_rax[2] = {0xFF, 0xD0};
    uint8_t add_rsp[4] = {0x48, 0x83, 0xC4, 0x40};
    uint8_t pop_rsi[1] = {0x5E};
    uint8_t ret[1] = {0xC3};
};
#pragma pack(pop)

FARPROC GetUser32Proc(const char* name) {
    HMODULE u32 = GetModuleHandleW(L"user32.dll");
    if (!u32) {
        u32 = LoadLibraryW(L"user32.dll");
    }
    return u32 ? GetProcAddress(u32, name) : nullptr;
}

size_t ProbeTableEntries(HANDLE process, uint64_t table_ptr) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQueryEx(process, reinterpret_cast<void*>(table_ptr), &mbi, sizeof(mbi)) == 0) {
        return 64;
    }
    const size_t bytes = reinterpret_cast<uint8_t*>(mbi.BaseAddress) + mbi.RegionSize -
                         reinterpret_cast<uint8_t*>(table_ptr);
    size_t entries = bytes / sizeof(uint64_t);
    if (entries < 8) {
        entries = 8;
    }
    if (entries > kMaxTableEntries) {
        entries = kMaxTableEntries;
    }
    return entries;
}

} // namespace

HdlStatus KernelCallbackTableMethod(uint32_t pid, const wchar_t* dll_path, uint64_t* out_base) {
    HWND hwnd = FindWindowForPid(pid);
    if (!hwnd) {
        HDL_LOG_ERROR("KernelCallbackTable: no window for pid %u (needs user32 callbacks)", pid);
        return HDL_E_NOT_FOUND;
    }

    auto nt_query = reinterpret_cast<NtQueryInformationProcess_t>(
        GetLoadedModuleProc(L"ntdll.dll", "NtQueryInformationProcess"));
    auto send_to = GetUser32Proc("SendMessageTimeoutW");
    auto load_library = GetKernel32Proc("LoadLibraryW");
    if (!nt_query || !send_to || !load_library) {
        return HDL_E_NOT_FOUND;
    }

    win::unique_handle process(OpenTargetProcess(pid));
    if (!process) {
        return HDL_E_ACCESS;
    }

    ProcessBasicInfo pbi{};
    ULONG ret_len = 0;
    NTSTATUS nt = nt_query(process.get(), ProcessBasicInformation, &pbi, sizeof(pbi), &ret_len);
    if (nt < 0 || !pbi.PebBaseAddress) {
        return HDL_E_FAILED;
    }

    uint64_t table_ptr = 0;
    auto* peb = static_cast<uint8_t*>(pbi.PebBaseAddress);
    if (!ReadRemote(process.get(), peb + kPebKernelCallbackTable, &table_ptr, sizeof(table_ptr)) ||
        table_ptr == 0) {
        HDL_LOG_ERROR("KernelCallbackTable: PEB table is null (user32 not initialized?)");
        return HDL_E_FAILED;
    }

    const size_t entries = ProbeTableEntries(process.get(), table_ptr);
    std::vector<uint64_t> table(entries, 0);
    if (!ReadRemote(process.get(), reinterpret_cast<void*>(table_ptr), table.data(),
                    entries * sizeof(uint64_t))) {
        HDL_LOG_ERROR("KernelCallbackTable: failed to read table (%zu entries)", entries);
        return HDL_E_FAILED;
    }

    if (kFnCopyDataIndex >= entries || table[kFnCopyDataIndex] == 0) {
        HDL_LOG_ERROR("KernelCallbackTable: __fnCOPYDATA slot empty");
        return HDL_E_FAILED;
    }
    const uint64_t original_fn = table[kFnCopyDataIndex];

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

    KctStub stub{};
    stub.done_flag = reinterpret_cast<uint64_t>(flag_mem.ptr);
    stub.path = reinterpret_cast<uint64_t>(path_mem.ptr);
    stub.loadlib = reinterpret_cast<uint64_t>(load_library);
    stub.original = original_fn;
    stub.jnz_orig[1] = 42;

    RemoteAlloc stub_mem;
    if (!stub_mem.Alloc(process.get(), sizeof(stub), PAGE_EXECUTE_READWRITE) ||
        !stub_mem.Write(&stub, sizeof(stub))) {
        return HDL_E_NO_MEM;
    }
    RegisterCfgCallTarget(process.get(), stub_mem.ptr);

    table[kFnCopyDataIndex] = reinterpret_cast<uint64_t>(stub_mem.ptr);
    RemoteAlloc new_table;
    if (!new_table.Alloc(process.get(), entries * sizeof(uint64_t)) ||
        !new_table.Write(table.data(), entries * sizeof(uint64_t))) {
        return HDL_E_NO_MEM;
    }

    const uint64_t new_table_addr = reinterpret_cast<uint64_t>(new_table.ptr);
    if (!WriteRemote(process.get(), peb + kPebKernelCallbackTable, &new_table_addr,
                     sizeof(new_table_addr))) {
        HDL_LOG_ERROR("KernelCallbackTable: failed to swap PEB pointer");
        return HDL_E_FAILED;
    }

    wchar_t payload[] = L"hdl";
    RemoteAlloc payload_mem;
    if (!payload_mem.Alloc(process.get(), sizeof(payload)) ||
        !payload_mem.Write(payload, sizeof(payload))) {
        WriteRemote(process.get(), peb + kPebKernelCallbackTable, &table_ptr, sizeof(table_ptr));
        return HDL_E_NO_MEM;
    }

    COPYDATASTRUCT cds{};
    cds.dwData = 1;
    cds.cbData = sizeof(payload);
    cds.lpData = payload_mem.ptr;
    RemoteAlloc cds_mem;
    if (!cds_mem.Alloc(process.get(), sizeof(cds)) || !cds_mem.Write(&cds, sizeof(cds))) {
        WriteRemote(process.get(), peb + kPebKernelCallbackTable, &table_ptr, sizeof(table_ptr));
        return HDL_E_NO_MEM;
    }

    SendTimeoutStub send_stub{};
    RemoteAlloc send_stub_mem;
    if (!send_stub_mem.Alloc(process.get(), sizeof(send_stub), PAGE_EXECUTE_READWRITE) ||
        !send_stub_mem.Write(&send_stub, sizeof(send_stub))) {
        WriteRemote(process.get(), peb + kPebKernelCallbackTable, &table_ptr, sizeof(table_ptr));
        return HDL_E_NO_MEM;
    }

    SendTimeoutArgs send_args{};
    send_args.send_fn = reinterpret_cast<uint64_t>(send_to);
    send_args.hwnd = reinterpret_cast<uint64_t>(hwnd);
    send_args.msg = WM_COPYDATA;
    send_args.flags = SMTO_ABORTIFHUNG | SMTO_NORMAL;
    send_args.wparam = reinterpret_cast<uint64_t>(hwnd);
    send_args.lparam = reinterpret_cast<uint64_t>(cds_mem.ptr);
    send_args.timeout_ms = 2000;
    RemoteAlloc send_args_mem;
    if (!send_args_mem.Alloc(process.get(), sizeof(send_args)) ||
        !send_args_mem.Write(&send_args, sizeof(send_args))) {
        WriteRemote(process.get(), peb + kPebKernelCallbackTable, &table_ptr, sizeof(table_ptr));
        return HDL_E_NO_MEM;
    }

    win::unique_handle t(::CreateRemoteThread(
        process.get(), nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(send_stub_mem.ptr),
        send_args_mem.ptr, 0, nullptr));
    if (t) {
        WaitForSingleObject(t.get(), 5000);
    }
    t.reset();

    // Same-IL path from injector (UIPI may block this for low IL).
    DWORD_PTR ignored = 0;
    COPYDATASTRUCT local_cds{};
    local_cds.dwData = 1;
    local_cds.cbData = sizeof(payload);
    local_cds.lpData = payload;
    SendMessageTimeoutW(hwnd, WM_COPYDATA, reinterpret_cast<WPARAM>(hwnd),
                        reinterpret_cast<LPARAM>(&local_cds), SMTO_ABORTIFHUNG | SMTO_NORMAL, 2000,
                        &ignored);

    st = PollForModule(pid, dll_path, out_base);

    WriteRemote(process.get(), peb + kPebKernelCallbackTable, &table_ptr, sizeof(table_ptr));

    path_mem.Detach();
    flag_mem.Detach();
    stub_mem.Detach();
    new_table.Detach();
    payload_mem.Detach();
    cds_mem.Detach();
    send_stub_mem.Detach();
    send_args_mem.Detach();

    if (st == HDL_OK) {
        HDL_LOG_INFO("KernelCallbackTable inject into pid %u ok", pid);
    } else {
        HDL_LOG_ERROR("KernelCallbackTable: swapped __fnCOPYDATA but module not observed");
    }
    return st;
}

} // namespace inject
} // namespace hdl
