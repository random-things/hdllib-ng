#include "ipc/wire.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

namespace {

bool IsKnownOpcode(uint32_t opcode) {
    switch (opcode) {
#define HDL_OP(Name, Id, Handler, Cap, CliVerb) case hdl::proto::Op##Name:
#include "ipc/ops_manifest.inc"
        return true;
    default:
        return false;
    }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    uint32_t declared_size = 0;
    if (size < sizeof(declared_size)) {
        return 0;
    }
    std::memcpy(&declared_size, data, sizeof(declared_size));
    if (declared_size > 64u * 1024u * 1024u || declared_size > size - sizeof(declared_size)) {
        return 0;
    }

    hdl::proto::Reader reader(data + sizeof(declared_size), declared_size);
    uint32_t opcode = 0;
    uint64_t id = 0;
    std::string narrow;
    std::wstring wide;
    (void)reader.TakePod(opcode);
    (void)IsKnownOpcode(opcode);
    (void)reader.TakePod(id);
    (void)reader.TakeString(narrow);
    (void)reader.TakeWString(wide);

    HdlRegionInfo region{};
    (void)hdl::proto::TakeHdlRegionInfo(reader, region);
    return 0;
}
