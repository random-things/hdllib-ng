#pragma once

#include "cmd.hpp"
#include "command_result.hpp"

/* Shared inline failure helpers — replaces per-file static Fail* duplicates. */

inline CommandResult FailUsage(CmdCtx& ctx) {
    return CmdFailUsage(ctx.cmd.c_str());
}
inline CommandResult FailIpc(CmdCtx& ctx) {
    return CmdFail(ctx.cmd.c_str(), HDL_E_FAILED, L"IPC request failed");
}
inline CommandResult FailBadResp(CmdCtx& ctx) {
    return CmdFail(ctx.cmd.c_str(), HDL_E_FAILED, L"Bad response");
}
inline CommandResult FailArg(CmdCtx& ctx, const wchar_t* hint) {
    return CmdFail(ctx.cmd.c_str(), HDL_E_INVALID_ARG, hint);
}
