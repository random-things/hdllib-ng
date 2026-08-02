#include "inject/common.hpp"
#include "inject/techniques.hpp"
#include "win/raii.hpp"

namespace hdl {
namespace inject {
namespace {

// One-shot WndProc: LoadLibraryW once, then CallWindowProcW(original, ...).
#pragma pack(push, 1)
struct WindowSubclassStub {
    uint8_t push_rcx[1] = {0x51};
    uint8_t push_rdx[1] = {0x52};
    uint8_t push_r8[2] = {0x41, 0x50};
    uint8_t push_r9[2] = {0x41, 0x51};

    uint8_t mov_rax_flag[2] = {0x48, 0xB8};
    uint64_t done_flag = 0;
    uint8_t mov_al_1[2] = {0xB0, 0x01};
    uint8_t xchg_al[2] = {0x86, 0x00};
    uint8_t test_al[2] = {0x84, 0xC0};
    uint8_t jnz_call[2] = {0x75, 0x00};

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
    uint8_t sub_rsp2[4] = {0x48, 0x83, 0xEC, 0x28};
    uint8_t mov_stack_lp[5] = {0x4C, 0x89, 0x4C, 0x24, 0x20};
    uint8_t mov_r9_r8[3] = {0x4D, 0x89, 0xC1};
    uint8_t mov_r8_rdx[3] = {0x49, 0x89, 0xD0};
    uint8_t mov_rdx_rcx[3] = {0x48, 0x89, 0xCA};
    uint8_t mov_rcx_imm[2] = {0x48, 0xB9};
    uint64_t original = 0;
    uint8_t mov_rax2[2] = {0x48, 0xB8};
    uint64_t call_wnd = 0;
    uint8_t call_rax2[2] = {0xFF, 0xD0};
    uint8_t add_rsp2[4] = {0x48, 0x83, 0xC4, 0x28};
    uint8_t ret[1] = {0xC3};
};
#pragma pack(pop)

struct SetWndProcArgs {
    uint64_t set_fn = 0;
    uint64_t hwnd = 0;
    int32_t index = GWLP_WNDPROC;
    uint32_t pad = 0;
    uint64_t new_proc = 0;
};

#pragma pack(push, 1)
struct SetWndProcStub {
    uint8_t push_rsi[1] = {0x56};
    uint8_t mov_rsi_rcx[3] = {0x48, 0x89, 0xCE};
    uint8_t sub_rsp[4] = {0x48, 0x83, 0xEC, 0x20};
    uint8_t mov_rcx[4] = {0x48, 0x8B, 0x4E, 0x08};
    uint8_t movsxd_rdx[4] = {0x48, 0x63, 0x56, 0x10};
    uint8_t mov_r8[4] = {0x4C, 0x8B, 0x46, 0x18};
    uint8_t mov_rax[3] = {0x48, 0x8B, 0x06};
    uint8_t call_rax[2] = {0xFF, 0xD0};
    uint8_t add_rsp[4] = {0x48, 0x83, 0xC4, 0x20};
    uint8_t pop_rsi[1] = {0x5E};
    uint8_t ret[1] = {0xC3};
};
#pragma pack(pop)

struct PostMsgArgs {
    uint64_t post_fn = 0;
    uint64_t hwnd = 0;
    uint32_t msg = WM_NULL;
    uint32_t pad = 0;
    uint64_t wparam = 0;
    uint64_t lparam = 0;
};

#pragma pack(push, 1)
struct PostMsgStub {
    uint8_t push_rsi[1] = {0x56};
    uint8_t mov_rsi_rcx[3] = {0x48, 0x89, 0xCE};
    uint8_t sub_rsp[4] = {0x48, 0x83, 0xEC, 0x20};
    uint8_t mov_rcx[4] = {0x48, 0x8B, 0x4E, 0x08};
    uint8_t mov_edx[3] = {0x8B, 0x56, 0x10};
    uint8_t mov_r8[4] = {0x4C, 0x8B, 0x46, 0x18};
    uint8_t mov_r9[4] = {0x4C, 0x8B, 0x4E, 0x20};
    uint8_t mov_rax[3] = {0x48, 0x8B, 0x06};
    uint8_t call_rax[2] = {0xFF, 0xD0};
    uint8_t add_rsp[4] = {0x48, 0x83, 0xC4, 0x20};
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

HdlStatus RunRemote(HANDLE process, void* stub, void* args, DWORD timeout_ms = 8000) {
    win::unique_handle t(::CreateRemoteThread(
        process, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(stub), args, 0, nullptr));
    if (!t) {
        return HDL_E_FAILED;
    }
    const DWORD wr = WaitForSingleObject(t.get(), timeout_ms);
    return wr == WAIT_OBJECT_0 ? HDL_OK : HDL_E_FAILED;
}

} // namespace

HdlStatus WindowSubclassMethod(uint32_t pid, const wchar_t* dll_path, uint64_t* out_base) {
    HWND hwnd = FindWindowForPid(pid);
    if (!hwnd) {
        HDL_LOG_ERROR("WindowSubclass: no window for pid %u", pid);
        return HDL_E_NOT_FOUND;
    }

    auto set_fn = GetUser32Proc("SetWindowLongPtrW");
    auto post_fn = GetUser32Proc("PostMessageW");
    auto call_wnd = GetUser32Proc("CallWindowProcW");
    auto def_wnd = GetUser32Proc("DefWindowProcW");
    auto load_library = GetKernel32Proc("LoadLibraryW");
    if (!set_fn || !post_fn || !call_wnd || !load_library) {
        return HDL_E_NOT_FOUND;
    }

    win::unique_handle process(OpenTargetProcess(pid));
    if (!process) {
        return HDL_E_ACCESS;
    }

    SetLastError(0);
    LONG_PTR original = GetWindowLongPtrW(hwnd, GWLP_WNDPROC);
    if (!original && def_wnd) {
        original = reinterpret_cast<LONG_PTR>(def_wnd);
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

    WindowSubclassStub wnd{};
    wnd.done_flag = reinterpret_cast<uint64_t>(flag_mem.ptr);
    wnd.path = reinterpret_cast<uint64_t>(path_mem.ptr);
    wnd.loadlib = reinterpret_cast<uint64_t>(load_library);
    wnd.original = static_cast<uint64_t>(original);
    wnd.call_wnd = reinterpret_cast<uint64_t>(call_wnd);
    wnd.jnz_call[1] = 30;

    RemoteAlloc stub_mem;
    if (!stub_mem.Alloc(process.get(), sizeof(wnd), PAGE_EXECUTE_READWRITE) ||
        !stub_mem.Write(&wnd, sizeof(wnd))) {
        return HDL_E_NO_MEM;
    }
    RegisterCfgCallTarget(process.get(), stub_mem.ptr);

    SetWndProcStub set_stub{};
    RemoteAlloc set_stub_mem;
    if (!set_stub_mem.Alloc(process.get(), sizeof(set_stub), PAGE_EXECUTE_READWRITE) ||
        !set_stub_mem.Write(&set_stub, sizeof(set_stub))) {
        return HDL_E_NO_MEM;
    }

    SetWndProcArgs set_args{};
    set_args.set_fn = reinterpret_cast<uint64_t>(set_fn);
    set_args.hwnd = reinterpret_cast<uint64_t>(hwnd);
    set_args.index = GWLP_WNDPROC;
    set_args.new_proc = reinterpret_cast<uint64_t>(stub_mem.ptr);
    RemoteAlloc set_args_mem;
    if (!set_args_mem.Alloc(process.get(), sizeof(set_args)) ||
        !set_args_mem.Write(&set_args, sizeof(set_args))) {
        return HDL_E_NO_MEM;
    }

    if (RunRemote(process.get(), set_stub_mem.ptr, set_args_mem.ptr) != HDL_OK) {
        HDL_LOG_ERROR("WindowSubclass: remote SetWindowLongPtrW failed");
        return HDL_E_FAILED;
    }

    // PostMessage does not wait on the UI thread (avoids SendMessage deadlocks).
    PostMsgStub post_stub{};
    RemoteAlloc post_stub_mem;
    if (!post_stub_mem.Alloc(process.get(), sizeof(post_stub), PAGE_EXECUTE_READWRITE) ||
        !post_stub_mem.Write(&post_stub, sizeof(post_stub))) {
        return HDL_E_NO_MEM;
    }
    PostMsgArgs post_args{};
    post_args.post_fn = reinterpret_cast<uint64_t>(post_fn);
    post_args.hwnd = reinterpret_cast<uint64_t>(hwnd);
    post_args.msg = WM_NULL;
    RemoteAlloc post_args_mem;
    if (!post_args_mem.Alloc(process.get(), sizeof(post_args)) ||
        !post_args_mem.Write(&post_args, sizeof(post_args))) {
        return HDL_E_NO_MEM;
    }
    RunRemote(process.get(), post_stub_mem.ptr, post_args_mem.ptr);
    PostMessageW(hwnd, WM_NULL, 0, 0);

    st = PollForModule(pid, dll_path, out_base);

    set_args.new_proc = static_cast<uint64_t>(original);
    set_args_mem.Write(&set_args, sizeof(set_args));
    RunRemote(process.get(), set_stub_mem.ptr, set_args_mem.ptr);

    path_mem.Detach();
    flag_mem.Detach();
    stub_mem.Detach();
    set_stub_mem.Detach();
    set_args_mem.Detach();
    post_stub_mem.Detach();
    post_args_mem.Detach();

    if (st == HDL_OK) {
        HDL_LOG_INFO("WindowSubclass inject into pid %u ok", pid);
    } else {
        HDL_LOG_ERROR("WindowSubclass: WndProc swapped but module not observed");
    }
    return st;
}

} // namespace inject
} // namespace hdl
