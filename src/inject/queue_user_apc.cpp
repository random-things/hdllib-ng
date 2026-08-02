#include "inject/common.hpp"
#include "inject/techniques.hpp"
#include "win/raii.hpp"

namespace hdl {
namespace inject {

HdlStatus QueueUserApcMethod(uint32_t pid, const wchar_t* dll_path, uint64_t* out_base) {
    win::unique_handle process(OpenTargetProcess(pid));
    if (!process) {
        return HDL_E_ACCESS;
    }

    RemoteAlloc remote;
    HdlStatus st = WriteRemotePath(process.get(), dll_path, remote);
    if (st != HDL_OK) {
        return st;
    }

    auto load_library = reinterpret_cast<PAPCFUNC>(GetKernel32Proc("LoadLibraryW"));
    if (!load_library) {
        return HDL_E_FAILED;
    }

    const auto tids = EnumProcessThreads(pid);
    int queued = 0;
    for (DWORD tid : tids) {
        win::unique_handle thread(OpenThread(THREAD_SET_CONTEXT, FALSE, tid));
        if (!thread) {
            continue;
        }
        if (QueueUserAPC(load_library, thread.get(), reinterpret_cast<ULONG_PTR>(remote.ptr))) {
            ++queued;
        }
    }

    if (queued == 0) {
        HDL_LOG_ERROR("QueueUserAPC: no threads accepted APC");
        return HDL_E_FAILED;
    }

    st = PollForModule(pid, dll_path, out_base);
    // Keep path alive for late APC delivery.
    remote.Detach();

    if (st == HDL_OK) {
        HDL_LOG_INFO("QueueUserAPC inject into pid %u ok (queued=%d)", pid, queued);
    } else {
        HDL_LOG_ERROR("QueueUserAPC queued %d but module not observed", queued);
    }
    return st;
}

} // namespace inject
} // namespace hdl
