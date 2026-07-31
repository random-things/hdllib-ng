#pragma once

#include "hdllib/hdllib.h"

namespace hdl {
namespace ipc {

HdlStatus Start();
void Stop();
void StopNoJoin();
bool IsRunning();

}  // namespace ipc
}  // namespace hdl
