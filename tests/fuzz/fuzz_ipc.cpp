#include "hdl/rpc/v1/envelope.pb.h"
#include "hdl/rpc/v1/services.rpc.hpp"
#include "ipc/wire.hpp"

#include <cstddef>
#include <cstdint>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size > 64u * 1024u * 1024u) {
        return 0;
    }

    hdl::rpc::v1::Envelope envelope;
    if (!envelope.ParseFromArray(data, static_cast<int>(size)) || !envelope.has_request()) {
        return 0;
    }
    hdl::rpc::Method method{};
    (void)hdl::rpc::ParseMethod(envelope.request().method(), &method);

    hdl::rpc::v1::Payload payload;
    if (!payload.ParseFromString(envelope.request().payload())) {
        return 0;
    }
    hdl::proto::Reader reader(reinterpret_cast<const uint8_t*>(payload.value().data()),
                              payload.value().size());
    uint64_t id = 0;
    std::string narrow;
    std::wstring wide;
    (void)reader.TakePod(id);
    (void)reader.TakeString(narrow);
    (void)reader.TakeWString(wide);

    HdlRegionInfo region{};
    (void)hdl::proto::TakeHdlRegionInfo(reader, region);
    return 0;
}
