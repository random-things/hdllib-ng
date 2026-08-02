#pragma once

#include "command_result.hpp"
#include "pipe_client.hpp"

#include "hdllib/hdllib.h"

#include <cstdint>
#include <string>

namespace hdlcli {
struct ControllerState;
}

// Pipe-command context: argv[0]=exe, argv[1]=pid, argv[2]=cmd, argv[3+]=args.
struct CmdCtx {
    int argc = 0;
    wchar_t** argv = nullptr;
    uint32_t pid = 0;
    std::wstring cmd;
    PipeClient& client;
    /* Non-null when invoked from REPL/TUI DispatchLine (interest store / last_*). */
    hdlcli::ControllerState* controller = nullptr;
    /* Global --json: structured envelope on stdout instead of human text. */
    bool json = false;
};

using CmdHandler = CommandResult (*)(CmdCtx& ctx);

struct CmdEntry {
    const wchar_t* name;
    CmdHandler handler;
};

CommandResult CmdPing(CmdCtx& ctx);
CommandResult CmdLog(CmdCtx& ctx);
CommandResult CmdLogFile(CmdCtx& ctx);
CommandResult CmdHealthVeh(CmdCtx& ctx);
CommandResult CmdModules(CmdCtx& ctx);
CommandResult CmdRegions(CmdCtx& ctx);
CommandResult CmdThreads(CmdCtx& ctx);
CommandResult CmdHealth(CmdCtx& ctx);
CommandResult CmdFingerprint(CmdCtx& ctx);
CommandResult CmdEvents(CmdCtx& ctx);
CommandResult CmdJob(CmdCtx& ctx);
CommandResult CmdRead(CmdCtx& ctx);
CommandResult CmdWrite(CmdCtx& ctx);
CommandResult CmdResolve(CmdCtx& ctx);
CommandResult CmdCall(CmdCtx& ctx);
CommandResult CmdVcall(CmdCtx& ctx);
CommandResult CmdAlloc(CmdCtx& ctx);
CommandResult CmdFree(CmdCtx& ctx);
CommandResult CmdHooktrace(CmdCtx& ctx);
CommandResult CmdHook(CmdCtx& ctx);
CommandResult CmdUnhook(CmdCtx& ctx);
CommandResult CmdHookEnable(CmdCtx& ctx);
CommandResult CmdHookhits(CmdCtx& ctx);
CommandResult CmdHookImport(CmdCtx& ctx);
CommandResult CmdRip(CmdCtx& ctx);
CommandResult CmdPtrchain(CmdCtx& ctx);
CommandResult CmdModbase(CmdCtx& ctx);
CommandResult CmdResolvePattern(CmdCtx& ctx);
CommandResult CmdXrefs(CmdCtx& ctx);
CommandResult CmdPtrscan(CmdCtx& ctx);
CommandResult CmdProbe(CmdCtx& ctx);
CommandResult CmdScan(CmdCtx& ctx);
CommandResult CmdInject(CmdCtx& ctx);
CommandResult CmdUnload(CmdCtx& ctx);
CommandResult CmdShutdown(CmdCtx& ctx);
CommandResult CmdDiscoverCreate(CmdCtx& ctx);
CommandResult CmdDiscoverClose(CmdCtx& ctx);
CommandResult CmdDiscoverAdd(CmdCtx& ctx);
CommandResult CmdDiscoverConstraint(CmdCtx& ctx);
CommandResult CmdDiscoverSynth(CmdCtx& ctx);
CommandResult CmdDiscoverPathscan(CmdCtx& ctx);
CommandResult CmdDiscoverPathValidate(CmdCtx& ctx);
CommandResult CmdDiscoverScan(CmdCtx& ctx);
CommandResult CmdDiscoverMisc(CmdCtx& ctx);

CommandResult CmdCaves(CmdCtx& ctx);
CommandResult CmdAllocNear(CmdCtx& ctx);
CommandResult CmdProtect(CmdCtx& ctx);
CommandResult CmdFlushICache(CmdCtx& ctx);
CommandResult CmdDisasmBackend(CmdCtx& ctx);
CommandResult CmdDisasm(CmdCtx& ctx);
CommandResult CmdInstrLen(CmdCtx& ctx);
CommandResult CmdSections(CmdCtx& ctx);
CommandResult CmdExports(CmdCtx& ctx);
CommandResult CmdImports(CmdCtx& ctx);
CommandResult CmdFunctions(CmdCtx& ctx);
CommandResult CmdXrefsFrom(CmdCtx& ctx);
CommandResult CmdResolveFunction(CmdCtx& ctx);
CommandResult CmdXrefsTo(CmdCtx& ctx);
CommandResult CmdInvalidateFnIndex(CmdCtx& ctx);
CommandResult CmdVtable(CmdCtx& ctx);
CommandResult CmdRtti(CmdCtx& ctx);
CommandResult CmdWatch(CmdCtx& ctx);
CommandResult CmdPatch(CmdCtx& ctx);
CommandResult CmdStub(CmdCtx& ctx);

bool ClientParsePred(const wchar_t* spec, HdlFieldPred* out);
const CmdEntry* GetCommandTable(size_t* out_count);
