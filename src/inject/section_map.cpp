#include "inject/common.hpp"
#include "inject/techniques.hpp"
#include "win/raii.hpp"

#include <cstring>

namespace hdl {
namespace inject {
namespace {

using NtCreateSection_t = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, PVOID, PLARGE_INTEGER, ULONG,
                                           ULONG, HANDLE);
using NtMapViewOfSection_t = NTSTATUS(NTAPI*)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T,
                                              PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);
using NtUnmapViewOfSection_t = NTSTATUS(NTAPI*)(HANDLE, PVOID);

constexpr DWORD ViewUnmap = 2; // ViewUnmap

} // namespace

HdlStatus SectionMapMethod(uint32_t pid, const wchar_t* dll_path, uint64_t* out_base) {
    auto nt_create = reinterpret_cast<NtCreateSection_t>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateSection"));
    auto nt_map = reinterpret_cast<NtMapViewOfSection_t>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtMapViewOfSection"));
    auto nt_unmap = reinterpret_cast<NtUnmapViewOfSection_t>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtUnmapViewOfSection"));
    if (!nt_create || !nt_map || !nt_unmap) {
        return HDL_E_NOT_FOUND;
    }

    win::unique_handle process(OpenTargetProcess(pid));
    if (!process) {
        return HDL_E_ACCESS;
    }

    const size_t path_bytes = (wcslen(dll_path) + 1) * sizeof(wchar_t);
    LARGE_INTEGER max_size{};
    max_size.QuadPart = static_cast<LONGLONG>(path_bytes);

    HANDLE raw_section = nullptr;
    NTSTATUS nt = nt_create(&raw_section, SECTION_ALL_ACCESS, nullptr, &max_size, PAGE_READWRITE,
                            SEC_COMMIT, nullptr);
    if (nt < 0 || !raw_section) {
        HDL_LOG_ERROR("NtCreateSection failed: 0x%08lX", static_cast<unsigned long>(nt));
        return HDL_E_FAILED;
    }
    win::unique_handle section(raw_section);

    void* local_view = nullptr;
    SIZE_T local_size = 0;
    nt = nt_map(section.get(), GetCurrentProcess(), &local_view, 0, 0, nullptr, &local_size,
                ViewUnmap, 0, PAGE_READWRITE);
    if (nt < 0 || !local_view) {
        return HDL_E_FAILED;
    }
    auto unmap_local = win::make_scope_exit([&]() { nt_unmap(GetCurrentProcess(), local_view); });
    memcpy(local_view, dll_path, path_bytes);

    void* remote_view = nullptr;
    SIZE_T remote_size = 0;
    nt = nt_map(section.get(), process.get(), &remote_view, 0, 0, nullptr, &remote_size, ViewUnmap,
                0, PAGE_READWRITE);
    if (nt < 0 || !remote_view) {
        HDL_LOG_ERROR("NtMapViewOfSection(remote) failed: 0x%08lX", static_cast<unsigned long>(nt));
        return HDL_E_FAILED;
    }

    auto load_library = reinterpret_cast<LPTHREAD_START_ROUTINE>(GetKernel32Proc("LoadLibraryW"));
    win::unique_handle thread(
        ::CreateRemoteThread(process.get(), nullptr, 0, load_library, remote_view, 0, nullptr));
    if (!thread) {
        nt_unmap(process.get(), remote_view);
        return HDL_E_FAILED;
    }

    const HdlStatus st = WaitThreadAndBase(thread.get(), pid, dll_path, out_base);

    // Keep remote view mapped so late use is safe; local view and section handle cleaned up by
    // RAII.

    if (st == HDL_OK) {
        HDL_LOG_INFO("SectionMap inject into pid %u ok", pid);
    }
    return st;
}

} // namespace inject
} // namespace hdl
