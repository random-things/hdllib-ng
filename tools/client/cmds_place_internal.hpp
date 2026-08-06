#pragma once

#include "cmd.hpp"
#include "cmd_fail.hpp"
#include "json_out.hpp"
#include "rpc_helpers.hpp"
#include "util.hpp"

#include "hdl/rpc/v1/services.rpc.hpp"
#include "hdllib/hdllib.h"

#include <algorithm>
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
