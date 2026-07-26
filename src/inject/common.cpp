#include "inject/common.hpp"

#include <cwctype>

namespace hdl {
namespace inject {

void RemoteAlloc::Free() {
    if (process && ptr) {
        VirtualFreeEx(process, ptr, 0, MEM_RELEASE);
    }
    ptr = nullptr;
    size = 0;
}

bool RemoteAlloc::Alloc(HANDLE proc, SIZE_T bytes, DWORD protect) {
    Free();
    process = proc;
    size = bytes;
    ptr = VirtualAllocEx(process, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, protect);
    return ptr != nullptr;
}

bool RemoteAlloc::Write(const void* data, SIZE_T bytes) const {
    SIZE_T written = 0;
    return WriteProcessMemory(process, ptr, data, bytes, &written) && written == bytes;
}

void* RemoteAlloc::Detach() {
    void* p = ptr;
    ptr = nullptr;
    size = 0;
    return p;
}

std::wstring NormalizePath(const wchar_t* path) {
    wchar_t full[MAX_PATH];
    const DWORD n = GetFullPathNameW(path, MAX_PATH, full, nullptr);
    if (n == 0 || n >= MAX_PATH) {
        return path ? path : L"";
    }
    return full;
}

bool PathsEqual(const wchar_t* a, const wchar_t* b) {
    if (!a || !b) {
        return false;
    }
    return _wcsicmp(a, b) == 0;
}

bool PathEndsWithFile(const wchar_t* full, const wchar_t* file) {
    if (!full || !file) {
        return false;
    }
    const wchar_t* base = wcsrchr(full, L'\\');
    base = base ? base + 1 : full;
    return _wcsicmp(base, file) == 0;
}

uint64_t FindModuleBaseByPath(DWORD pid, const wchar_t* dll_path) {
    const std::wstring want = NormalizePath(dll_path);
    const wchar_t* file = wcsrchr(want.c_str(), L'\\');
    file = file ? file + 1 : want.c_str();

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) {
        return 0;
    }
    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    uint64_t base = 0;
    if (Module32FirstW(snap, &me)) {
        do {
            if (PathsEqual(me.szExePath, want.c_str()) || PathEndsWithFile(me.szExePath, file)) {
                base = reinterpret_cast<uint64_t>(me.modBaseAddr);
                break;
            }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return base;
}

HANDLE OpenTargetProcess(DWORD pid, DWORD extra) {
    const DWORD access = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
                         PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_SUSPEND_RESUME | extra;
    return OpenProcess(access, FALSE, pid);
}

FARPROC GetKernel32Proc(const char* name) {
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    return k32 ? GetProcAddress(k32, name) : nullptr;
}

std::vector<DWORD> EnumProcessThreads(DWORD pid) {
    std::vector<DWORD> tids;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        return tids;
    }
    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                tids.push_back(te.th32ThreadID);
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return tids;
}

HdlStatus WriteRemotePath(HANDLE process, const wchar_t* dll_path, RemoteAlloc& remote) {
    const size_t bytes = (wcslen(dll_path) + 1) * sizeof(wchar_t);
    if (!remote.Alloc(process, bytes) || !remote.Write(dll_path, bytes)) {
        return HDL_E_NO_MEM;
    }
    return HDL_OK;
}

HdlStatus WaitThreadAndBase(HANDLE thread, DWORD pid, const wchar_t* dll_path, uint64_t* out_base) {
    WaitForSingleObject(thread, INFINITE);
    DWORD exit_code = 0;
    GetExitCodeThread(thread, &exit_code);
    if (exit_code == 0) {
        return HDL_E_FAILED;
    }
    if (out_base) {
        *out_base = FindModuleBaseByPath(pid, dll_path);
        if (!*out_base) {
            *out_base = static_cast<uint64_t>(exit_code);
        }
    }
    return HDL_OK;
}

HdlStatus PollForModule(DWORD pid, const wchar_t* dll_path, uint64_t* out_base, int attempts,
                        DWORD sleep_ms) {
    for (int i = 0; i < attempts; ++i) {
        const uint64_t base = FindModuleBaseByPath(pid, dll_path);
        if (base) {
            if (out_base) {
                *out_base = base;
            }
            return HDL_OK;
        }
        Sleep(sleep_ms);
    }
    return HDL_E_FAILED;
}

HdlStatus PollForModuleGone(DWORD pid, const wchar_t* dll_path, int attempts, DWORD sleep_ms) {
    for (int i = 0; i < attempts; ++i) {
        if (!FindModuleBaseByPath(pid, dll_path)) {
            return HDL_OK;
        }
        Sleep(sleep_ms);
    }
    return HDL_E_BUSY;
}

bool ReadRemote(HANDLE process, const void* addr, void* buf, size_t n) {
    SIZE_T got = 0;
    return ReadProcessMemory(process, addr, buf, n, &got) && got == n;
}

bool WriteRemote(HANDLE process, void* addr, const void* buf, size_t n) {
    SIZE_T wrote = 0;
    return WriteProcessMemory(process, addr, buf, n, &wrote) && wrote == n;
}

namespace {

struct EnumWindowCtx {
    DWORD pid = 0;
    HWND hwnd = nullptr;
};

BOOL CALLBACK EnumVisibleWindow(HWND hwnd, LPARAM lparam) {
    auto* ctx = reinterpret_cast<EnumWindowCtx*>(lparam);
    DWORD wnd_pid = 0;
    GetWindowThreadProcessId(hwnd, &wnd_pid);
    if (wnd_pid == ctx->pid && IsWindowVisible(hwnd)) {
        ctx->hwnd = hwnd;
        return FALSE;
    }
    return TRUE;
}

BOOL CALLBACK EnumAnyWindow(HWND hwnd, LPARAM lparam) {
    auto* ctx = reinterpret_cast<EnumWindowCtx*>(lparam);
    DWORD wnd_pid = 0;
    GetWindowThreadProcessId(hwnd, &wnd_pid);
    if (wnd_pid == ctx->pid) {
        ctx->hwnd = hwnd;
        return FALSE;
    }
    return TRUE;
}

}  // namespace

HWND FindWindowForPid(DWORD pid) {
    EnumWindowCtx ctx{pid, nullptr};
    EnumWindows(EnumVisibleWindow, reinterpret_cast<LPARAM>(&ctx));
    if (ctx.hwnd) {
        return ctx.hwnd;
    }
    EnumWindows(EnumAnyWindow, reinterpret_cast<LPARAM>(&ctx));
    return ctx.hwnd;
}

namespace {

struct EnumMatchCtx {
    DWORD pid_filter = 0;
    const wchar_t* title = nullptr;
    const wchar_t* class_name = nullptr;
    HWND hwnd = nullptr;
    DWORD matched_pid = 0;
    uint32_t count = 0;
};

bool TitleMatches(HWND hwnd, const wchar_t* substr) {
    if (!substr || !substr[0]) {
        return true;
    }
    wchar_t text[512];
    const int n = GetWindowTextW(hwnd, text, 512);
    if (n <= 0) {
        return false;
    }
    // Case-insensitive substring search.
    for (const wchar_t* p = text; *p; ++p) {
        const wchar_t* a = p;
        const wchar_t* b = substr;
        while (*a && *b && towlower(*a) == towlower(*b)) {
            ++a;
            ++b;
        }
        if (!*b) {
            return true;
        }
    }
    return false;
}

bool ClassMatches(HWND hwnd, const wchar_t* want) {
    if (!want || !want[0]) {
        return true;
    }
    wchar_t cls[256];
    if (GetClassNameW(hwnd, cls, 256) == 0) {
        return false;
    }
    return _wcsicmp(cls, want) == 0;
}

BOOL CALLBACK EnumMatchWindow(HWND hwnd, LPARAM lparam) {
    auto* ctx = reinterpret_cast<EnumMatchCtx*>(lparam);
    DWORD wnd_pid = 0;
    GetWindowThreadProcessId(hwnd, &wnd_pid);
    if (ctx->pid_filter != 0 && wnd_pid != ctx->pid_filter) {
        return TRUE;
    }
    if (!TitleMatches(hwnd, ctx->title) || !ClassMatches(hwnd, ctx->class_name)) {
        return TRUE;
    }
    ++ctx->count;
    if (ctx->count == 1) {
        ctx->hwnd = hwnd;
        ctx->matched_pid = wnd_pid;
    }
    return TRUE;
}

}  // namespace

HdlStatus FindWindowByTitleClass(DWORD pid, const wchar_t* title_substr_or_null,
                                 const wchar_t* class_name_or_null, HWND* out_hwnd,
                                 uint32_t* out_pid, uint32_t* out_count) {
    const bool has_title = title_substr_or_null && title_substr_or_null[0];
    const bool has_class = class_name_or_null && class_name_or_null[0];
    if (!has_title && !has_class && pid == 0) {
        return HDL_E_INVALID_ARG;
    }

    EnumMatchCtx ctx{};
    ctx.pid_filter = pid;
    ctx.title = has_title ? title_substr_or_null : nullptr;
    ctx.class_name = has_class ? class_name_or_null : nullptr;
    EnumWindows(EnumMatchWindow, reinterpret_cast<LPARAM>(&ctx));

    if (out_count) {
        *out_count = ctx.count;
    }
    if (ctx.count == 0) {
        return HDL_E_NOT_FOUND;
    }
    if (ctx.count > 1) {
        return HDL_E_BUSY;
    }
    if (out_hwnd) {
        *out_hwnd = ctx.hwnd;
    }
    if (out_pid) {
        *out_pid = ctx.matched_pid;
    }
    return HDL_OK;
}

NtQueueApcThread_t GetNtQueueApcThread() {
    static NtQueueApcThread_t fn = reinterpret_cast<NtQueueApcThread_t>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueueApcThread"));
    return fn;
}

HdlStatus AtomWriteW(HANDLE thread, ATOM atom, void* remote_dest, ULONG cch) {
    auto nt_q = GetNtQueueApcThread();
    // GlobalAddAtomW atoms must be read with GlobalGetAtomNameW (not GetAtomNameW).
    auto get_atom = GetKernel32Proc("GlobalGetAtomNameW");
    if (!nt_q || !get_atom) {
        return HDL_E_NOT_FOUND;
    }
    const NTSTATUS st =
        nt_q(thread, reinterpret_cast<PVOID>(get_atom), reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(atom)),
             remote_dest, reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(cch)));
    return st >= 0 ? HDL_OK : HDL_E_FAILED;
}

HdlStatus ApcMemsetWrite(HANDLE thread, void* remote_dest, const void* data, size_t size) {
    auto nt_q = GetNtQueueApcThread();
    auto memset_fn = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "memset");
    if (!nt_q || !memset_fn) {
        return HDL_E_NOT_FOUND;
    }
    const auto* bytes = static_cast<const uint8_t*>(data);
    auto* dest = static_cast<uint8_t*>(remote_dest);
    for (size_t i = 0; i < size; ++i) {
        const NTSTATUS st =
            nt_q(thread, reinterpret_cast<PVOID>(memset_fn), dest + i,
                 reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(bytes[i])), reinterpret_cast<PVOID>(1));
        if (st < 0) {
            return HDL_E_FAILED;
        }
    }
    return HDL_OK;
}

HANDLE OpenApcThread(DWORD pid, DWORD desired_access) {
    const auto tids = EnumProcessThreads(pid);
    for (DWORD tid : tids) {
        HANDLE thread = OpenThread(desired_access, FALSE, tid);
        if (thread) {
            return thread;
        }
    }
    return nullptr;
}

HdlStatus AllocLoadLibraryStub(HANDLE process, const wchar_t* dll_path, RemoteAlloc& path_mem,
                               RemoteAlloc& stub_mem) {
    HdlStatus st = WriteRemotePath(process, dll_path, path_mem);
    if (st != HDL_OK) {
        return st;
    }
    X64LoadLibraryStub stub{};
    stub.path = reinterpret_cast<uint64_t>(path_mem.ptr);
    stub.loadlib = reinterpret_cast<uint64_t>(GetKernel32Proc("LoadLibraryW"));
    if (!stub.loadlib) {
        return HDL_E_FAILED;
    }
    if (!stub_mem.Alloc(process, sizeof(stub), PAGE_EXECUTE_READWRITE) ||
        !stub_mem.Write(&stub, sizeof(stub))) {
        return HDL_E_NO_MEM;
    }
    return HDL_OK;
}

void RegisterCfgCallTarget(HANDLE process, void* stub) {
#ifndef CFG_CALL_TARGET_VALID
#  define CFG_CALL_TARGET_VALID 0x00000001u
#endif
    struct CfgCallTargetInfo {
        ULONG_PTR Offset;
        ULONG_PTR Flags;
    };
    using SetProcessValidCallTargets_t = BOOL(WINAPI*)(HANDLE, PVOID, SIZE_T, ULONG,
                                                       CfgCallTargetInfo*);

    auto set_cfg = reinterpret_cast<SetProcessValidCallTargets_t>(
        GetProcAddress(GetModuleHandleW(L"kernelbase.dll"), "SetProcessValidCallTargets"));
    if (!set_cfg) {
        set_cfg = reinterpret_cast<SetProcessValidCallTargets_t>(
            GetKernel32Proc("SetProcessValidCallTargets"));
    }
    if (!set_cfg || !stub) {
        return;
    }
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    const ULONG_PTR page = si.dwPageSize ? si.dwPageSize : 0x1000;
    auto* region = reinterpret_cast<uint8_t*>(reinterpret_cast<ULONG_PTR>(stub) & ~(page - 1));
    CfgCallTargetInfo info{};
    info.Offset = static_cast<ULONG_PTR>(reinterpret_cast<uint8_t*>(stub) - region);
    info.Flags = CFG_CALL_TARGET_VALID;
    set_cfg(process, region, page, 1, &info);
}

}  // namespace inject
}  // namespace hdl
