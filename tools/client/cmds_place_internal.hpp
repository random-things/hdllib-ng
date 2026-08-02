#pragma once

#include "cmd.hpp"
#include "cmd_fail.hpp"
#include "ipc/wire.hpp"
#include "json_out.hpp"
#include "protocol.hpp"
#include "util.hpp"

#include "hdllib/hdllib.h"

#include <cstdio>
#include <string>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

namespace cmds_place_detail {

using ::FailArg;
using ::FailBadResp;
using ::FailIpc;
using ::FailUsage;

inline CommandResult FinishStatus(CmdCtx& ctx, int32_t st) {
    return CmdStatus(ctx.cmd.c_str(), st, "{}");
}

} // namespace cmds_place_detail
