#pragma once

#include "hdllib/hdllib.h"

#include <vector>

namespace hdl {

HdlStatus StartIpcServer();
void StopIpcServer();
void StopIpcServerNoJoin();
bool IsIpcServerRunning();

// Shared with client tool
bool PipeReadFrame(void* handle, std::vector<uint8_t>& out);
bool PipeWriteFrame(void* handle, const void* data, uint32_t size);

}  // namespace hdl
