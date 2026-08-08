#pragma once

#include "cmd.hpp"
#include "invocation.hpp"

/* Look up a normalized one-shot pipe command in the shared client registry. */
CmdHandler FindPipeCommand(const std::wstring& name);

/* Execute and render a validated invocation using an already-connected client. */
int DispatchPipeCommand(ParsedInvocation& invocation, PipeClient& client);
