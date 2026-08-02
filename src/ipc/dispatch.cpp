#include "dispatch.hpp"
#include "handlers.hpp"
#include "protocol.hpp"

#include <vector>

namespace hdl {
namespace ipc {

bool HandleRequest(HANDLE pipe, const std::vector<uint8_t>& req) {
    using namespace proto;
    Reader r(req);
    uint32_t op = 0;
    if (!r.TakePod(op)) {
        std::vector<uint8_t> resp;
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }

    switch (op) {
#define HDL_OP(Name, Id, Handler, Cap, CliVerb)                                                    \
    case Op##Name:                                                                                 \
        return Handler(pipe, r);
#include "ops_manifest.inc"
    default: {
        std::vector<uint8_t> resp;
        AppendPod(resp, static_cast<int32_t>(HDL_E_INVALID_ARG));
        return WriteFrame(pipe, resp);
    }
    }
}

} // namespace ipc
} // namespace hdl
