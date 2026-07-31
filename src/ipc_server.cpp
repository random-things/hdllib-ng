#include "ipc_server.hpp"

#include "ipc/framing.hpp"
#include "ipc/server.hpp"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

namespace hdl {

bool PipeReadFrame(void* handle, std::vector<uint8_t>& out) {
    return ipc::ReadFrame(static_cast<HANDLE>(handle), out);
}

bool PipeWriteFrame(void* handle, const void* data, uint32_t size) {
    return ipc::WriteFrameBytes(static_cast<HANDLE>(handle), data, size);
}

HdlStatus StartIpcServer() {
    return ipc::Start();
}

void StopIpcServer() {
    ipc::Stop();
}

void StopIpcServerNoJoin() {
    ipc::StopNoJoin();
}

bool IsIpcServerRunning() {
    return ipc::IsRunning();
}

}  // namespace hdl
