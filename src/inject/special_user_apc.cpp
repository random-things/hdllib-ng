#include "inject/common.hpp"
#include "inject/techniques.hpp"
#include "win/raii.hpp"

namespace hdl {
namespace inject {
namespace {

// QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC = 0x1 (Win10 1809+)
constexpr ULONG kSpecialUserApc = 0x1;

using NtQueueApcThreadEx2_t = NTSTATUS(NTAPI*)(HANDLE ThreadHandle, HANDLE ReserveHandle,
                                               ULONG ApcFlags, PVOID ApcRoutine,
                                               PVOID SystemArgument1, PVOID SystemArgument2,
                                               PVOID SystemArgument3);

using NtQueueApcThreadEx_t = NTSTATUS(NTAPI*)(HANDLE ThreadHandle, HANDLE UserApcReserveHandle,
                                              PVOID ApcRoutine, PVOID Arg1, PVOID Arg2, PVOID Arg3);

} // namespace

HdlStatus SpecialUserApcMethod(uint32_t pid, const wchar_t* dll_path, uint64_t* out_base) {
    auto nt_q2 = reinterpret_cast<NtQueueApcThreadEx2_t>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueueApcThreadEx2"));
    auto nt_q_ex = reinterpret_cast<NtQueueApcThreadEx_t>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueueApcThreadEx"));
    auto load_library = GetKernel32Proc("LoadLibraryW");
    if (!load_library) {
        return HDL_E_FAILED;
    }
    if (!nt_q2 && !nt_q_ex) {
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
    int queued = 0;
    for (DWORD tid : tids) {
        win::unique_handle thread(OpenThread(THREAD_SET_CONTEXT, FALSE, tid));
        if (!thread) {
            continue;
        }

        NTSTATUS nt = static_cast<NTSTATUS>(0xC0000001);
        if (nt_q2) {
            nt = nt_q2(thread.get(), nullptr, kSpecialUserApc,
                       reinterpret_cast<PVOID>(load_library), path_mem.ptr, nullptr, nullptr);
        }
        // Older: NtQueueApcThreadEx without flags — still distinct from QueueUserAPC.
        if (nt < 0 && nt_q_ex) {
            nt = nt_q_ex(thread.get(), nullptr, reinterpret_cast<PVOID>(load_library), path_mem.ptr,
                         nullptr, nullptr);
        }
        if (nt >= 0) {
            ++queued;
        }
    }

    if (queued == 0) {
        HDL_LOG_ERROR("SpecialUserApc: failed to queue on any thread");
        return HDL_E_FAILED;
    }

    st = PollForModule(pid, dll_path, out_base);
    path_mem.Detach();

    if (st == HDL_OK) {
        HDL_LOG_INFO("SpecialUserApc inject into pid %u ok (queued=%d)", pid, queued);
    } else {
        HDL_LOG_ERROR("SpecialUserApc queued but module not observed");
    }
    return st;
}

} // namespace inject
} // namespace hdl
