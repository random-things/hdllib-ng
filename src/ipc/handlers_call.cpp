#include "handlers.hpp"

#include "common.hpp"
#include "convert.hpp"

#include "alloc.hpp"
#include "call.hpp"
#include "resolve.hpp"

#include <thread>

namespace hdl::ipc {
namespace {

std::thread StartDeadlineWatcher(const std::shared_ptr<Job>& job, volatile int* cancel) {
    return std::thread([job, cancel] {
        while (!*cancel) {
            if (JobCheck(job) != HDL_OK) {
                *cancel = 1;
                break;
            }
            Sleep(20);
        }
    });
}

rpc::Status CallStatus(HdlStatus status) {
    rpc::Status result = rpc::Status::FromHdl(status);
    if (status == HDL_E_TIMEOUT || status == HDL_E_CANCELLED) {
        result.set_outcome_unknown(true);
    }
    return result;
}

} // namespace

rpc::Status HandleCall_ResolveExport(rpc::CallContext&,
                                     const rpc::v1::ResolveExportRequest& request,
                                     rpc::v1::ResolveExportResponse* response) {
    std::wstring module;
    if (!Utf8ToWide(request.module(), &module) || request.name().empty() ||
        request.name().find('\0') != std::string::npos) {
        return rpc::Status::FromHdl(HDL_E_INVALID_ARG);
    }
    uint64_t address = 0;
    const HdlStatus status =
        ResolveExport(module.empty() ? nullptr : module.c_str(), request.name().c_str(), &address);
    response->set_address(address);
    return rpc::Status::FromHdl(status);
}

rpc::Status HandleCall_CallExport(rpc::CallContext& context,
                                  const rpc::v1::CallExportRequest& request,
                                  rpc::v1::CallExportResponse* response) {
    std::wstring module;
    CallArguments arguments;
    if (!Utf8ToWide(request.module(), &module) || request.name().empty() ||
        request.name().find('\0') != std::string::npos || !arguments.Decode(request.arguments())) {
        return rpc::Status::FromHdl(HDL_E_INVALID_ARG);
    }
    if (context.deadline_exceeded()) {
        return rpc::Status::FromHdl(HDL_E_TIMEOUT);
    }
    const auto job = CurrentRequestJob();
    volatile int cancel = 0;
    std::thread watcher;
    if (job && job->deadline_tick) {
        watcher = StartDeadlineWatcher(job, &cancel);
    }
    HdlCallResult result{};
    const HdlStatus status =
        CallExport(module.empty() ? nullptr : module.c_str(), request.name().c_str(),
                   arguments.args.empty() ? nullptr : arguments.args.data(),
                   static_cast<uint32_t>(arguments.args.size()), &result,
                   context.remaining_timeout_ms(), watcher.joinable() ? &cancel : nullptr);
    if (watcher.joinable()) {
        cancel = 1;
        watcher.join();
    }
    arguments.SetResult(result, response->mutable_result());
    return CallStatus(status);
}

rpc::Status HandleCall_Call(rpc::CallContext& context, const rpc::v1::CallRequest& request,
                            rpc::v1::CallResponse* response) {
    CallArguments arguments;
    const int thread_mode = static_cast<int>(request.thread_mode());
    if (!request.address() || thread_mode < rpc::v1::CALL_THREAD_MODE_WORKER ||
        thread_mode > rpc::v1::CALL_THREAD_MODE_MAIN || !arguments.Decode(request.arguments())) {
        return rpc::Status::FromHdl(HDL_E_INVALID_ARG);
    }
    if (context.deadline_exceeded()) {
        return rpc::Status::FromHdl(HDL_E_TIMEOUT);
    }
    const auto job = CurrentRequestJob();
    volatile int cancel = 0;
    std::thread watcher;
    if (job && job->deadline_tick) {
        watcher = StartDeadlineWatcher(job, &cancel);
    }
    HdlCallDesc desc{};
    desc.address = request.address();
    desc.args = arguments.args.empty() ? nullptr : arguments.args.data();
    desc.arg_count = static_cast<uint32_t>(arguments.args.size());
    desc.thread_mode = static_cast<uint32_t>(thread_mode);
    desc.timeout_ms = context.remaining_timeout_ms();
    HdlCallResult result{};
    const HdlStatus status = Call(&desc, &result, watcher.joinable() ? &cancel : nullptr);
    if (watcher.joinable()) {
        cancel = 1;
        watcher.join();
    }
    arguments.SetResult(result, response->mutable_result());
    return CallStatus(status);
}

rpc::Status HandleCall_CallVtable(rpc::CallContext& context,
                                  const rpc::v1::CallVtableRequest& request,
                                  rpc::v1::CallVtableResponse* response) {
    CallArguments arguments;
    const int thread_mode = static_cast<int>(request.thread_mode());
    if (!request.object() || thread_mode < rpc::v1::CALL_THREAD_MODE_WORKER ||
        thread_mode > rpc::v1::CALL_THREAD_MODE_MAIN || !arguments.Decode(request.arguments())) {
        return rpc::Status::FromHdl(HDL_E_INVALID_ARG);
    }
    if (context.deadline_exceeded()) {
        return rpc::Status::FromHdl(HDL_E_TIMEOUT);
    }
    const auto job = CurrentRequestJob();
    volatile int cancel = 0;
    std::thread watcher;
    if (job && job->deadline_tick) {
        watcher = StartDeadlineWatcher(job, &cancel);
    }
    HdlCallResult result{};
    const HdlStatus status = CallVtable(
        request.object(), request.index(), arguments.args.empty() ? nullptr : arguments.args.data(),
        static_cast<uint32_t>(arguments.args.size()), request.prepend_this(),
        static_cast<uint32_t>(thread_mode), &result, context.remaining_timeout_ms(),
        watcher.joinable() ? &cancel : nullptr);
    if (watcher.joinable()) {
        cancel = 1;
        watcher.join();
    }
    arguments.SetResult(result, response->mutable_result());
    return CallStatus(status);
}

rpc::Status HandleMemory_Alloc(rpc::CallContext&, const rpc::v1::AllocRequest& request,
                               rpc::v1::AllocResponse* response) {
    uint64_t address = 0;
    const HdlStatus status =
        Alloc(static_cast<size_t>(request.size()), request.protection(), &address);
    response->set_address(address);
    return rpc::Status::FromHdl(status);
}

rpc::Status HandleMemory_Free(rpc::CallContext&, const rpc::v1::FreeRequest& request,
                              rpc::v1::Empty*) {
    return rpc::Status::FromHdl(Free(request.address()));
}

rpc::Status HandleLocate_ResolveRip(rpc::CallContext&, const rpc::v1::ResolveRipRequest& request,
                                    rpc::v1::ResolveRipResponse* response) {
    uint64_t address = 0;
    const HdlStatus status = ResolveRipRelative(request.address(), request.displacement_offset(),
                                                request.instruction_length(), &address);
    response->set_address(address);
    return rpc::Status::FromHdl(status);
}

rpc::Status HandleLocate_FollowPointers(rpc::CallContext&,
                                        const rpc::v1::FollowPointersRequest& request,
                                        rpc::v1::FollowPointersResponse* response) {
    if (request.offsets_size() > 64) {
        return rpc::Status::FromHdl(HDL_E_INVALID_ARG);
    }
    std::vector<int64_t> offsets(request.offsets().begin(), request.offsets().end());
    uint64_t address = 0;
    const HdlStatus status =
        FollowPointers(request.base(), offsets.empty() ? nullptr : offsets.data(),
                       static_cast<uint32_t>(offsets.size()), &address);
    response->set_address(address);
    return rpc::Status::FromHdl(status);
}

rpc::Status HandleLocate_ModuleBase(rpc::CallContext&, const rpc::v1::ModuleBaseRequest& request,
                                    rpc::v1::ModuleBaseResponse* response) {
    std::wstring module;
    if (!Utf8ToWide(request.module(), &module)) {
        return rpc::Status::FromHdl(HDL_E_INVALID_ARG);
    }
    uint64_t base = 0;
    const HdlStatus status = ModuleBase(module.empty() ? nullptr : module.c_str(), &base);
    response->set_base(base);
    return rpc::Status::FromHdl(status);
}

} // namespace hdl::ipc
