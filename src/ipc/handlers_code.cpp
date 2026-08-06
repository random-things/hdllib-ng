#include "handlers.hpp"

#include "common.hpp"
#include "convert.hpp"

#include "code.hpp"
#include "disasm/backend.hpp"
#include "graph.hpp"
#include "pe_meta.hpp"
#include "vtable.hpp"
#include "watch.hpp"

#include <vector>

namespace hdl::ipc {
namespace {

template <typename T, typename Query> HdlStatus QueryDynamic(Query query, std::vector<T>* values) {
    uint32_t count = 0;
    HdlStatus status = query(nullptr, &count);
    if (status == HDL_OK) {
        values->clear();
        return HDL_OK;
    }
    if (status != HDL_E_BUFFER_SMALL) {
        return status;
    }
    values->resize(count);
    status = query(values->data(), &count);
    values->resize(status == HDL_OK ? count : 0);
    return status;
}

} // namespace

rpc::Status
HandleCode_DisasmEnumBackends(rpc::CallContext&, const rpc::v1::Empty&,
                              rpc::ServerWriter<rpc::v1::DisasmEnumBackendsResponse>& writer) {
    std::vector<HdlDisasmBackendInfo> values;
    const HdlStatus status = QueryDynamic<HdlDisasmBackendInfo>(
        [](HdlDisasmBackendInfo* out, uint32_t* count) { return disasm::EnumBackends(out, count); },
        &values);
    return WriteBatches(
        status, values, 16, writer,
        [](const HdlDisasmBackendInfo& value, rpc::v1::DisasmEnumBackendsResponse* batch) {
            ToProto(value, batch->add_backends());
            return true;
        });
}

rpc::Status HandleCode_DisasmGetBackend(rpc::CallContext&, const rpc::v1::Empty&,
                                        rpc::v1::DisasmGetBackendResponse* response) {
    int32_t backend = 0;
    const HdlStatus status = disasm::GetBackend(&backend);
    response->set_backend_id(backend);
    return rpc::Status::FromHdl(status);
}

rpc::Status HandleCode_DisasmSetBackend(rpc::CallContext&,
                                        const rpc::v1::DisasmSetBackendRequest& request,
                                        rpc::v1::Empty*) {
    return rpc::Status::FromHdl(disasm::SetBackend(request.backend_id()));
}

rpc::Status HandleCode_InstrLen(rpc::CallContext&, const rpc::v1::InstrLenRequest& request,
                                rpc::v1::InstrLenResponse* response) {
    uint32_t length = 0;
    const HdlStatus status = InstrLen(request.address(), &length);
    response->set_length(length);
    return rpc::Status::FromHdl(status);
}

rpc::Status HandleCode_Disasm(rpc::CallContext&, const rpc::v1::DisasmRequest& request,
                              rpc::ServerWriter<rpc::v1::DisasmResponse>& writer) {
    std::vector<HdlInsn> values;
    const HdlStatus status = QueryDynamic<HdlInsn>(
        [&request](HdlInsn* out, uint32_t* count) {
            return DisasmRange(request.address(), request.max_instructions(), out, count);
        },
        &values);
    return WriteBatches(status, values, 64, writer,
                        [](const HdlInsn& value, rpc::v1::DisasmResponse* batch) {
                            ToProto(value, batch->add_instructions());
                            return true;
                        });
}

rpc::Status HandleCode_BuildStub(rpc::CallContext&, const rpc::v1::BuildStubRequest& request,
                                 rpc::v1::BuildStubResponse* response) {
    if (request.kind() < rpc::v1::STUB_KIND_ABSOLUTE_JUMP ||
        request.kind() > rpc::v1::STUB_KIND_RAW) {
        return rpc::Status::FromHdl(HDL_E_INVALID_ARG);
    }
    HdlStubDesc desc{};
    desc.kind = request.kind();
    desc.flags = request.flags();
    desc.target = request.target();
    desc.steal_from = request.steal_from();
    desc.steal_min_bytes = request.steal_min_bytes();
    desc.raw = reinterpret_cast<const uint8_t*>(request.raw().data());
    desc.raw_size = static_cast<uint32_t>(request.raw().size());
    desc.alloc_rx = request.allocate_rx();
    HdlStubResult result{};
    const HdlStatus status = BuildStub(&desc, &result);
    ToProto(result, response->mutable_result());
    return rpc::Status::FromHdl(status);
}

rpc::Status HandleCode_PatchCreate(rpc::CallContext&, const rpc::v1::PatchCreateRequest& request,
                                   rpc::v1::PatchCreateResponse* response) {
    if (request.name().find('\0') != std::string::npos || request.data().size() > UINT32_MAX) {
        return rpc::Status::FromHdl(HDL_E_INVALID_ARG);
    }
    HdlPatchHandle handle = 0;
    const HdlStatus status =
        PatchCreate(request.address(), reinterpret_cast<const uint8_t*>(request.data().data()),
                    static_cast<uint32_t>(request.data().size()),
                    request.name().empty() ? nullptr : request.name().c_str(), &handle);
    response->set_handle(handle);
    return rpc::Status::FromHdl(status);
}

rpc::Status HandleCode_PatchEnable(rpc::CallContext&, const rpc::v1::PatchEnableRequest& request,
                                   rpc::v1::Empty*) {
    return rpc::Status::FromHdl(PatchEnable(request.handle(), request.enabled()));
}

rpc::Status HandleCode_PatchRemove(rpc::CallContext&, const rpc::v1::PatchRemoveRequest& request,
                                   rpc::v1::Empty*) {
    return rpc::Status::FromHdl(PatchRemove(request.handle()));
}

rpc::Status HandleCode_PatchEnum(rpc::CallContext&, const rpc::v1::Empty&,
                                 rpc::ServerWriter<rpc::v1::PatchEnumResponse>& writer) {
    std::vector<HdlPatchInfo> values;
    const HdlStatus status = QueryDynamic<HdlPatchInfo>(
        [](HdlPatchInfo* out, uint32_t* count) { return PatchEnum(out, count); }, &values);
    return WriteBatches(status, values, 32, writer,
                        [](const HdlPatchInfo& value, rpc::v1::PatchEnumResponse* batch) {
                            ToProto(value, batch->add_patches());
                            return true;
                        });
}

rpc::Status HandlePe_EnumSections(rpc::CallContext&, const rpc::v1::EnumSectionsRequest& request,
                                  rpc::ServerWriter<rpc::v1::EnumSectionsResponse>& writer) {
    std::vector<HdlSectionInfo> values;
    const HdlStatus status = QueryDynamic<HdlSectionInfo>(
        [&request](HdlSectionInfo* out, uint32_t* count) {
            return EnumSections(request.module_base(), out, count);
        },
        &values);
    return WriteBatches(status, values, 32, writer,
                        [](const HdlSectionInfo& value, rpc::v1::EnumSectionsResponse* batch) {
                            ToProto(value, batch->add_sections());
                            return true;
                        });
}

rpc::Status HandlePe_EnumExports(rpc::CallContext&, const rpc::v1::EnumExportsRequest& request,
                                 rpc::ServerWriter<rpc::v1::EnumExportsResponse>& writer) {
    std::vector<HdlExportInfo> values;
    const HdlStatus status = QueryDynamic<HdlExportInfo>(
        [&request](HdlExportInfo* out, uint32_t* count) {
            return EnumExports(request.module_base(), out, count);
        },
        &values);
    return WriteBatches(status, values, 32, writer,
                        [](const HdlExportInfo& value, rpc::v1::EnumExportsResponse* batch) {
                            ToProto(value, batch->add_exports());
                            return true;
                        });
}

rpc::Status HandlePe_EnumImports(rpc::CallContext&, const rpc::v1::EnumImportsRequest& request,
                                 rpc::ServerWriter<rpc::v1::EnumImportsResponse>& writer) {
    std::vector<HdlImportInfo> values;
    const HdlStatus status = QueryDynamic<HdlImportInfo>(
        [&request](HdlImportInfo* out, uint32_t* count) {
            return EnumImports(request.module_base(), out, count);
        },
        &values);
    return WriteBatches(status, values, 32, writer,
                        [](const HdlImportInfo& value, rpc::v1::EnumImportsResponse* batch) {
                            ToProto(value, batch->add_imports());
                            return true;
                        });
}

rpc::Status HandleLocate_EnumFunctions(rpc::CallContext&,
                                       const rpc::v1::EnumFunctionsRequest& request,
                                       rpc::ServerWriter<rpc::v1::EnumFunctionsResponse>& writer) {
    std::wstring module;
    if (!Utf8ToWide(request.scope().module(), &module)) {
        return rpc::Status::FromHdl(HDL_E_INVALID_ARG);
    }
    volatile int cancel = 0;
    std::vector<HdlFunctionInfo> values;
    const HdlStatus status = QueryDynamic<HdlFunctionInfo>(
        [&request, &module, &cancel](HdlFunctionInfo* out, uint32_t* count) {
            return EnumFunctions(request.scope().start(), request.scope().size(),
                                 request.scope().flags(), module.empty() ? nullptr : module.c_str(),
                                 request.max_results(), out, count, &cancel);
        },
        &values);
    return WriteBatches(status, values, 64, writer,
                        [](const HdlFunctionInfo& value, rpc::v1::EnumFunctionsResponse* batch) {
                            ToProto(value, batch->add_functions());
                            return true;
                        });
}

rpc::Status HandleLocate_XrefsFrom(rpc::CallContext&, const rpc::v1::XrefsFromRequest& request,
                                   rpc::ServerWriter<rpc::v1::XrefsFromResponse>& writer) {
    volatile int cancel = 0;
    std::vector<HdlXrefEdge> values;
    const HdlStatus status = QueryDynamic<HdlXrefEdge>(
        [&request, &cancel](HdlXrefEdge* out, uint32_t* count) {
            return XrefsFrom(request.seed(), request.max_depth(), request.max_nodes(),
                             request.kinds(), out, count, &cancel);
        },
        &values);
    return WriteBatches(status, values, 64, writer,
                        [](const HdlXrefEdge& value, rpc::v1::XrefsFromResponse* batch) {
                            ToProto(value, batch->add_edges());
                            return true;
                        });
}

rpc::Status HandleLocate_WalkVtable(rpc::CallContext&, const rpc::v1::WalkVtableRequest& request,
                                    rpc::ServerWriter<rpc::v1::WalkVtableResponse>& writer) {
    std::vector<uint64_t> slots;
    const HdlStatus status = QueryDynamic<uint64_t>(
        [&request](uint64_t* out, uint32_t* count) {
            return WalkVtable(request.address(), request.is_object(), out, count);
        },
        &slots);
    if (status != HDL_OK) {
        return rpc::Status::FromHdl(status);
    }
    for (size_t offset = 0; offset < slots.size(); offset += 128) {
        rpc::v1::WalkVtableResponse response;
        const size_t end = (std::min)(slots.size(), offset + 128);
        for (size_t index = offset; index < end; ++index)
            response.add_slots(slots[index]);
        if (!writer.Write(response))
            return rpc::Status::FromHdl(HDL_E_CANCELLED);
    }
    return rpc::Status::Ok();
}

rpc::Status HandleLocate_QueryRttiName(rpc::CallContext&,
                                       const rpc::v1::QueryRttiNameRequest& request,
                                       rpc::v1::QueryRttiNameResponse* response) {
    char name[256]{};
    const HdlStatus status =
        QueryRttiName(request.address(), request.is_object(), name, sizeof(name));
    if (status == HDL_OK)
        response->set_name(name);
    return rpc::Status::FromHdl(status);
}

rpc::Status HandleLocate_ResolveFunction(rpc::CallContext&,
                                         const rpc::v1::ResolveFunctionRequest& request,
                                         rpc::v1::ResolveFunctionResponse* response) {
    std::wstring module;
    if (!Utf8ToWide(request.scope().module(), &module)) {
        return rpc::Status::FromHdl(HDL_E_INVALID_ARG);
    }
    volatile int cancel = 0;
    HdlFunctionInfo function{};
    const HdlStatus status =
        ResolveFunction(request.address(), request.scope().flags(),
                        module.empty() ? nullptr : module.c_str(), &function, &cancel);
    if (status == HDL_OK)
        ToProto(function, response->mutable_function());
    return rpc::Status::FromHdl(status);
}

rpc::Status HandleLocate_XrefsTo(rpc::CallContext&, const rpc::v1::XrefsToRequest& request,
                                 rpc::ServerWriter<rpc::v1::XrefsToResponse>& writer) {
    std::wstring module;
    if (!Utf8ToWide(request.scope().module(), &module)) {
        return rpc::Status::FromHdl(HDL_E_INVALID_ARG);
    }
    volatile int cancel = 0;
    std::vector<HdlXrefEdge> values;
    const HdlStatus status = QueryDynamic<HdlXrefEdge>(
        [&request, &module, &cancel](HdlXrefEdge* out, uint32_t* count) {
            return XrefsTo(request.target(), request.max_nodes(), request.kinds(),
                           request.scope().flags(), module.empty() ? nullptr : module.c_str(), out,
                           count, &cancel);
        },
        &values);
    return WriteBatches(status, values, 64, writer,
                        [](const HdlXrefEdge& value, rpc::v1::XrefsToResponse* batch) {
                            ToProto(value, batch->add_edges());
                            return true;
                        });
}

rpc::Status HandleLocate_InvalidateFnIndex(rpc::CallContext&,
                                           const rpc::v1::InvalidateFnIndexRequest& request,
                                           rpc::v1::Empty*) {
    std::wstring module;
    if (!Utf8ToWide(request.module(), &module)) {
        return rpc::Status::FromHdl(HDL_E_INVALID_ARG);
    }
    return rpc::Status::FromHdl(InvalidateFunctionIndex(module.empty() ? nullptr : module.c_str()));
}

rpc::Status HandleWatch_WatchHw(rpc::CallContext&, const rpc::v1::WatchHwRequest& request,
                                rpc::v1::WatchHwResponse* response) {
    if (request.access() < rpc::v1::WATCH_HARDWARE_ACCESS_EXECUTE ||
        request.access() > rpc::v1::WATCH_HARDWARE_ACCESS_READ_WRITE) {
        return rpc::Status::FromHdl(HDL_E_INVALID_ARG);
    }
    HdlWatchHandle handle = 0;
    const HdlStatus status =
        WatchHw(request.address(), request.size(), request.access(), request.thread_id(), &handle);
    response->set_handle(handle);
    return rpc::Status::FromHdl(status);
}

rpc::Status HandleWatch_WatchPage(rpc::CallContext&, const rpc::v1::WatchPageRequest& request,
                                  rpc::v1::WatchPageResponse* response) {
    if (request.mode() < rpc::v1::WATCH_PAGE_MODE_GUARD ||
        request.mode() > rpc::v1::WATCH_PAGE_MODE_NO_ACCESS) {
        return rpc::Status::FromHdl(HDL_E_INVALID_ARG);
    }
    HdlWatchHandle handle = 0;
    const HdlStatus status =
        WatchPage(request.address(), static_cast<size_t>(request.size()), request.mode(), &handle);
    response->set_handle(handle);
    return rpc::Status::FromHdl(status);
}

rpc::Status HandleWatch_Unwatch(rpc::CallContext&, const rpc::v1::UnwatchRequest& request,
                                rpc::v1::Empty*) {
    return rpc::Status::FromHdl(Unwatch(request.handle()));
}

rpc::Status HandleWatch_EnumWatches(rpc::CallContext&, const rpc::v1::Empty&,
                                    rpc::ServerWriter<rpc::v1::EnumWatchesResponse>& writer) {
    std::vector<HdlWatchInfo> values;
    const HdlStatus status = QueryDynamic<HdlWatchInfo>(
        [](HdlWatchInfo* out, uint32_t* count) { return EnumWatches(out, count); }, &values);
    return WriteBatches(status, values, 32, writer,
                        [](const HdlWatchInfo& value, rpc::v1::EnumWatchesResponse* batch) {
                            ToProto(value, batch->add_watches());
                            return true;
                        });
}

rpc::Status HandleWatch_WatchRefresh(rpc::CallContext&, const rpc::v1::Empty&, rpc::v1::Empty*) {
    return rpc::Status::FromHdl(WatchRefresh());
}

rpc::Status HandleWatch_PollWatchHits(rpc::CallContext&,
                                      const rpc::v1::PollWatchHitsRequest& request,
                                      rpc::ServerWriter<rpc::v1::PollWatchHitsResponse>& writer) {
    uint32_t maximum = request.max_hits();
    if (!maximum || maximum > 64)
        maximum = 64;
    std::vector<HdlWatchHit> hits(maximum);
    uint32_t count = maximum;
    const HdlStatus status = PollWatchHits(hits.data(), &count, request.wait_timeout_ms());
    hits.resize(status == HDL_OK ? count : 0);
    return WriteBatches(status, hits, 16, writer,
                        [](const HdlWatchHit& value, rpc::v1::PollWatchHitsResponse* batch) {
                            ToProto(value, batch->add_hits());
                            return true;
                        });
}

} // namespace hdl::ipc
