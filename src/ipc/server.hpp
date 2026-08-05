#pragma once

#include "hdllib/hdllib.h"

namespace hdl {
namespace ipc {

HdlStatus Start();
void Stop();
/* Signal stop without joining. keep_alive_pipe is not disconnected so an in-flight
 * reply (e.g. Control.Shutdown) can still be read by the client. */
void StopNoJoin(void* keep_alive_pipe = nullptr);
bool IsRunning();

} // namespace ipc
} // namespace hdl
