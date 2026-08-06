#include "handlers.hpp"

#include "common.hpp"
#include "convert.hpp"

#include "core.hpp"
#include "fingerprint.hpp"
#include "health.hpp"
#include "inject.hpp"
#include "loaded_modules.hpp"
#include "log.hpp"
#include "memory.hpp"

#include <string>
#include <vector>

namespace hdl::ipc {

rpc::Status HandleControl_Ping(rpc::CallContext&, const rpc::v1::Empty&,
                               rpc::v1::PingResponse* response) {
    response->set_pid(GetCurrentProcessId());
    return rpc::Status::Ok();
}

rpc::Status HandleControl_SetLogLevel(rpc::CallContext&, const rpc::v1::SetLogLevelRequest& request,
                                      rpc::v1::Empty*) {
    const int level = static_cast<int>(request.level());
    if (level < HDL_LOG_OFF || level > HDL_LOG_DEBUG) {
        return rpc::Status::FromHdl(HDL_E_INVALID_ARG);
    }
    SetLogLevel(static_cast<LogLevel>(level));
    return rpc::Status::Ok();
}

rpc::Status HandleControl_SetLogFile(rpc::CallContext&, const rpc::v1::SetLogFileRequest& request,
                                     rpc::v1::Empty*) {
    std::wstring path;
    if (!Utf8ToWide(request.path(), &path)) {
        return rpc::Status::FromHdl(HDL_E_INVALID_ARG, "path must be valid UTF-8 without NUL");
    }
    const wchar_t* log_path = path.empty() ? nullptr : path.c_str();
    // codeql[cpp/path-injection]
    return rpc::Status::FromHdl(SetLogFile(log_path) ? HDL_OK : HDL_E_FAILED);
}

rpc::Status HandleControl_SetHealthVeh(rpc::CallContext&,
                                       const rpc::v1::SetHealthVehRequest& request,
                                       rpc::v1::Empty*) {
    return rpc::Status::FromHdl(SetHealthVeh(request.enabled()));
}

rpc::Status HandleControl_GetHealthVeh(rpc::CallContext&, const rpc::v1::Empty&,
                                       rpc::v1::GetHealthVehResponse* response) {
    response->set_enabled(IsHealthVehEnabled());
    return rpc::Status::Ok();
}

rpc::Status HandleControl_Shutdown(rpc::CallContext& context,
                                   const rpc::v1::ShutdownRequest& request, rpc::v1::Empty*) {
    CoreShutdownPrepare(request.flags());
    context.DeferAfterReply([] { CoreShutdownFinish(); });
    return rpc::Status::Ok();
}

rpc::Status HandleProcess_GetHealth(rpc::CallContext&, const rpc::v1::Empty&,
                                    rpc::v1::GetHealthResponse* response) {
    HdlHealthInfo info{};
    const HdlStatus status = GetHealth(&info);
    ToProto(info, response->mutable_health());
    return rpc::Status::FromHdl(status);
}

rpc::Status HandleProcess_EnumRegions(rpc::CallContext&, const rpc::v1::Empty&,
                                      rpc::ServerWriter<rpc::v1::EnumRegionsResponse>& writer) {
    std::vector<HdlRegionInfo> values;
    const HdlStatus status = EnumerateAll(&EnumRegions, &values);
    return WriteBatches(status, values, 64, writer,
                        [](const HdlRegionInfo& value, rpc::v1::EnumRegionsResponse* batch) {
                            ToProto(value, batch->add_regions());
                            return true;
                        });
}

rpc::Status HandleProcess_EnumModules(rpc::CallContext&, const rpc::v1::Empty&,
                                      rpc::ServerWriter<rpc::v1::EnumModulesResponse>& writer) {
    std::vector<HdlModuleInfo> values;
    const HdlStatus status = EnumerateAll(&EnumModules, &values);
    return WriteBatches(status, values, 16, writer,
                        [](const HdlModuleInfo& value, rpc::v1::EnumModulesResponse* batch) {
                            return ToProto(value, batch->add_modules());
                        });
}

rpc::Status HandleProcess_EnumThreads(rpc::CallContext&, const rpc::v1::Empty&,
                                      rpc::ServerWriter<rpc::v1::EnumThreadsResponse>& writer) {
    std::vector<HdlThreadInfo> values;
    const HdlStatus status = EnumerateAll(&EnumThreads, &values);
    return WriteBatches(status, values, 32, writer,
                        [](const HdlThreadInfo& value, rpc::v1::EnumThreadsResponse* batch) {
                            ToProto(value, batch->add_threads());
                            return true;
                        });
}

rpc::Status HandleProcess_PollEvents(rpc::CallContext&, const rpc::v1::PollEventsRequest& request,
                                     rpc::ServerWriter<rpc::v1::PollEventsResponse>& writer) {
    uint32_t maximum = request.max_events();
    if (!maximum || maximum > 64) {
        maximum = 64;
    }
    std::vector<HdlEvent> events(maximum);
    const uint32_t count = HealthPollEvents(events.data(), maximum, request.wait_timeout_ms());
    if (count) {
        rpc::v1::PollEventsResponse response;
        for (uint32_t index = 0; index < count; ++index) {
            ToProto(events[index], response.add_events());
        }
        if (!writer.Write(response)) {
            return rpc::Status::FromHdl(HDL_E_CANCELLED);
        }
    }
    return rpc::Status::Ok();
}

rpc::Status HandleProcess_Fingerprint(rpc::CallContext&, const rpc::v1::FingerprintRequest& request,
                                      rpc::ServerWriter<rpc::v1::FingerprintResponse>& writer) {
    const uint32_t scan_flags = request.scan_flags() ? request.scan_flags() : HDL_FP_SCAN_DEFAULT;
    uint32_t count = 0;
    HdlStatus status = EnumFingerprintTags(scan_flags, nullptr, &count);
    std::vector<HdlFingerprintTag> tags;
    if (status == HDL_E_BUFFER_SMALL && count) {
        tags.resize(count);
        status = EnumFingerprintTags(scan_flags, tags.data(), &count);
        tags.resize(status == HDL_OK ? count : 0);
    } else if (status == HDL_OK) {
        count = 0;
    }
    return WriteBatches(status, tags, 16, writer,
                        [](const HdlFingerprintTag& value, rpc::v1::FingerprintResponse* batch) {
                            ToProto(value, batch->add_tags());
                            return true;
                        });
}

rpc::Status HandleMemory_ReadMemory(rpc::CallContext&, const rpc::v1::ReadMemoryRequest& request,
                                    rpc::v1::ReadMemoryResponse* response) {
    if (request.size() > 16u * 1024u * 1024u) {
        return rpc::Status::FromHdl(HDL_E_INVALID_ARG);
    }
    std::vector<uint8_t> buffer(request.size());
    size_t read = 0;
    const HdlStatus status = ReadMemory(request.address(), buffer.data(), buffer.size(), &read);
    response->set_data(buffer.data(), read);
    return rpc::Status::FromHdl(status);
}

rpc::Status HandleMemory_WriteMemory(rpc::CallContext&, const rpc::v1::WriteMemoryRequest& request,
                                     rpc::v1::WriteMemoryResponse* response) {
    if (request.data().size() > 16u * 1024u * 1024u) {
        return rpc::Status::FromHdl(HDL_E_INVALID_ARG);
    }
    size_t written = 0;
    const HdlStatus status =
        WriteMemory(request.address(), request.data().data(), request.data().size(), &written);
    response->set_bytes_written(static_cast<uint32_t>(written));
    return rpc::Status::FromHdl(status);
}

rpc::Status HandleInjection_InjectDll(rpc::CallContext&, const rpc::v1::InjectDllRequest& request,
                                      rpc::v1::InjectDllResponse* response) {
    std::wstring dll_path;
    std::wstring executable_path;
    const int method = static_cast<int>(request.method());
    if (method < rpc::v1::INJECTION_METHOD_CREATE_REMOTE_THREAD ||
        method > rpc::v1::INJECTION_METHOD_ETW_CALLBACK ||
        !Utf8ToWide(request.dll_path(), &dll_path) || dll_path.empty() ||
        !Utf8ToWide(request.executable_path(), &executable_path) ||
        request.hook_export().find('\0') != std::string::npos) {
        return rpc::Status::FromHdl(HDL_E_INVALID_ARG);
    }
    uint64_t base = 0;
    uint32_t out_pid = 0;
    const HdlStatus status = InjectDllEx(
        request.pid(), dll_path.c_str(), method,
        executable_path.empty() ? nullptr : executable_path.c_str(),
        request.hook_export().empty() ? nullptr : request.hook_export().c_str(), &out_pid, &base);
    if (status == HDL_OK && base) {
        const DWORD self = GetCurrentProcessId();
        const uint32_t effective = out_pid ? out_pid : (request.pid() ? request.pid() : self);
        if (effective == self) {
            TrackLoadedModule(dll_path.c_str(), base);
        }
    }
    response->set_base(base);
    response->set_out_pid(out_pid);
    return rpc::Status::FromHdl(status);
}

rpc::Status HandleInjection_UnloadDll(rpc::CallContext&, const rpc::v1::UnloadDllRequest& request,
                                      rpc::v1::UnloadDllResponse* response) {
    std::wstring path;
    if (!Utf8ToWide(request.dll_path(), &path) || path.empty()) {
        return rpc::Status::FromHdl(HDL_E_INVALID_ARG);
    }
    uint64_t base = 0;
    const HdlStatus status = UnloadDll(request.pid(), path.c_str(), request.reload(), 0, &base);
    if (status == HDL_OK) {
        UntrackLoadedModule(path.c_str());
    }
    response->set_base(base);
    return rpc::Status::FromHdl(status);
}

rpc::Status HandleInjection_TrackLoadedDll(rpc::CallContext&,
                                           const rpc::v1::TrackLoadedDllRequest& request,
                                           rpc::v1::Empty*) {
    std::wstring path;
    if (!request.base() || !Utf8ToWide(request.dll_path(), &path) || path.empty()) {
        return rpc::Status::FromHdl(HDL_E_INVALID_ARG);
    }
    TrackLoadedModule(path.c_str(), request.base());
    return rpc::Status::Ok();
}

} // namespace hdl::ipc
