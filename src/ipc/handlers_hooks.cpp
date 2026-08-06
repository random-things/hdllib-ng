#include "handlers.hpp"

#include "common.hpp"
#include "convert.hpp"

#include "hooks.hpp"

#include <vector>

namespace hdl::ipc {

rpc::Status HandleHook_HookTrace(rpc::CallContext&, const rpc::v1::HookTraceRequest& request,
                                 rpc::v1::HookTraceResponse* response) {
    HdlHookHandle handle = nullptr;
    const HdlStatus status = HookTrace(request.target(), request.argument_count(), &handle);
    response->set_handle(reinterpret_cast<uint64_t>(handle));
    return rpc::Status::FromHdl(status);
}

rpc::Status HandleHook_Hook(rpc::CallContext&, const rpc::v1::HookRequest& request,
                            rpc::v1::HookResponse* response) {
    if (!request.target() || !request.detour()) {
        return rpc::Status::FromHdl(HDL_E_INVALID_ARG);
    }
    void* trampoline = nullptr;
    HdlHookHandle handle = nullptr;
    const HdlStatus status = Hook(reinterpret_cast<void*>(request.target()),
                                  reinterpret_cast<void*>(request.detour()), &trampoline, &handle);
    response->set_handle(reinterpret_cast<uint64_t>(handle));
    response->set_trampoline(reinterpret_cast<uint64_t>(trampoline));
    return rpc::Status::FromHdl(status);
}

rpc::Status HandleHook_EnableHook(rpc::CallContext&, const rpc::v1::EnableHookRequest& request,
                                  rpc::v1::Empty*) {
    return rpc::Status::FromHdl(
        EnableHook(reinterpret_cast<HdlHookHandle>(request.handle()), request.enabled()));
}

rpc::Status HandleHook_Unhook(rpc::CallContext&, const rpc::v1::UnhookRequest& request,
                              rpc::v1::Empty*) {
    return rpc::Status::FromHdl(Unhook(reinterpret_cast<HdlHookHandle>(request.handle())));
}

rpc::Status HandleHook_PollHookHits(rpc::CallContext&, const rpc::v1::PollHookHitsRequest& request,
                                    rpc::ServerWriter<rpc::v1::PollHookHitsResponse>& writer) {
    uint32_t maximum = request.max_hits();
    if (!maximum || maximum > 64) {
        maximum = 64;
    }
    std::vector<HdlHookHit> hits(maximum);
    uint32_t count = maximum;
    const HdlStatus status = PollHookHits(hits.data(), &count, request.wait_timeout_ms());
    hits.resize(status == HDL_OK ? count : 0);
    return WriteBatches(status, hits, 16, writer,
                        [](const HdlHookHit& value, rpc::v1::PollHookHitsResponse* batch) {
                            ToProto(value, batch->add_hits());
                            return true;
                        });
}

rpc::Status HandleHook_HookImport(rpc::CallContext&, const rpc::v1::HookImportRequest& request,
                                  rpc::v1::HookImportResponse* response) {
    std::wstring module;
    if (!Utf8ToWide(request.module(), &module) || request.dll().empty() ||
        request.dll().find('\0') != std::string::npos || request.import_name().empty() ||
        request.import_name().find('\0') != std::string::npos) {
        return rpc::Status::FromHdl(HDL_E_INVALID_ARG);
    }
    HdlHookHandle handle = nullptr;
    const HdlStatus status =
        HookImport(module.empty() ? nullptr : module.c_str(), request.dll().c_str(),
                   request.import_name().c_str(), request.argument_count(), &handle);
    response->set_handle(reinterpret_cast<uint64_t>(handle));
    return rpc::Status::FromHdl(status);
}

} // namespace hdl::ipc
