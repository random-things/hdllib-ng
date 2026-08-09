#include "handlers.hpp"

#include "common.hpp"
#include "convert.hpp"

#include "alloc.hpp"
#include "call.hpp"
#include "call_registry.hpp"
#include "resolve.hpp"

namespace hdl::ipc {
namespace {

constexpr uint32_t kReplyReserveMs = 250;

uint32_t ExecutionTimeout(const rpc::CallContext& context, bool has_wait_timeout,
                          uint32_t wait_timeout_ms) {
    if (!context.timeout_ms()) {
        return has_wait_timeout ? wait_timeout_ms : 0;
    }
    const uint32_t remaining = context.remaining_timeout_ms();
    const uint32_t bounded = remaining > kReplyReserveMs ? remaining - kReplyReserveMs : 1;
    if (!has_wait_timeout) {
        return bounded;
    }
    /* Never wait longer than the envelope deadline; this also limits explicit 0 (infinite)
       when the transport deadline is finite. */
    if (!wait_timeout_ms || wait_timeout_ms > bounded) {
        return bounded;
    }
    return wait_timeout_ms;
}

void SetManagedResult(const ManagedCallResult& managed, const CallArguments& arguments,
                      rpc::v1::CallResult* response) {
    response->set_return_value(managed.result.return_value);
    response->set_last_error(managed.result.last_error);
    response->set_call_id(managed.call_id);
    response->set_orphaned(managed.orphaned);
    response->set_blocking_call_id(managed.blocking_call_id);
    response->set_phase(static_cast<rpc::v1::CallPhase>(managed.phase));
    response->set_unacknowledged_orphan_count(managed.unacknowledged_orphan_count);
    if (managed.status == HDL_OK) {
        arguments.SetResult(managed.result, response);
    }
}

rpc::Status ManagedStatus(const ManagedCallResult& result) {
    rpc::Status status = rpc::Status::FromHdl(result.status);
    status.set_outcome_unknown(result.orphaned);
    return status;
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
    const ManagedCallResult result = CallExportTracked(
        module.empty() ? nullptr : module.c_str(), request.name().c_str(),
        arguments.args.empty() ? nullptr : arguments.args.data(),
        static_cast<uint32_t>(arguments.args.size()),
        ExecutionTimeout(context, request.has_wait_timeout_ms(), request.wait_timeout_ms()),
        nullptr);
    SetManagedResult(result, arguments, response->mutable_result());
    return ManagedStatus(result);
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
    HdlCallDesc desc{};
    desc.address = request.address();
    desc.args = arguments.args.empty() ? nullptr : arguments.args.data();
    desc.arg_count = static_cast<uint32_t>(arguments.args.size());
    desc.thread_mode = static_cast<uint32_t>(thread_mode);
    desc.timeout_ms =
        ExecutionTimeout(context, request.has_wait_timeout_ms(), request.wait_timeout_ms());
    const ManagedCallResult result = CallTracked(&desc, nullptr);
    SetManagedResult(result, arguments, response->mutable_result());
    return ManagedStatus(result);
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
    const ManagedCallResult result = CallVtableTracked(
        request.object(), request.index(), arguments.args.empty() ? nullptr : arguments.args.data(),
        static_cast<uint32_t>(arguments.args.size()), request.prepend_this(),
        static_cast<uint32_t>(thread_mode),
        ExecutionTimeout(context, request.has_wait_timeout_ms(), request.wait_timeout_ms()),
        nullptr);
    SetManagedResult(result, arguments, response->mutable_result());
    return ManagedStatus(result);
}

rpc::Status HandleCall_EnumOrphans(rpc::CallContext&, const rpc::v1::Empty&,
                                   rpc::ServerWriter<rpc::v1::EnumOrphansResponse>& writer) {
    std::vector<HdlCallInfo> calls;
    const HdlStatus status = EnumCallOrphans(&calls);
    return WriteBatches(status, calls, 32, writer,
                        [](const HdlCallInfo& call, rpc::v1::EnumOrphansResponse* response) {
                            ToProto(call, response->add_calls());
                            return true;
                        });
}

rpc::Status HandleCall_GetCallStatus(rpc::CallContext&,
                                     const rpc::v1::GetCallStatusRequest& request,
                                     rpc::v1::GetCallStatusResponse* response) {
    HdlCallInfo call{};
    const HdlStatus status = GetCallStatus(request.call_id(), &call);
    if (status == HDL_OK) {
        ToProto(call, response->mutable_call());
    }
    return rpc::Status::FromHdl(status);
}

rpc::Status HandleCall_AcknowledgeOrphan(rpc::CallContext&,
                                         const rpc::v1::AcknowledgeOrphanRequest& request,
                                         rpc::v1::AcknowledgeOrphanResponse* response) {
    HdlCallInfo call{};
    const HdlStatus status = AcknowledgeCallOrphan(request.call_id(), &call);
    if (status == HDL_OK) {
        ToProto(call, response->mutable_call());
    }
    return rpc::Status::FromHdl(status);
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
