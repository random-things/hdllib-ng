#pragma once

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
};

using CmdHandler = int (*)(CmdCtx& ctx);

struct CmdEntry {
    const wchar_t* name;
    CmdHandler handler;
};

int CmdPing(CmdCtx& ctx);
int CmdLog(CmdCtx& ctx);
int CmdModules(CmdCtx& ctx);
int CmdRegions(CmdCtx& ctx);
int CmdThreads(CmdCtx& ctx);
int CmdHealth(CmdCtx& ctx);
int CmdFingerprint(CmdCtx& ctx);
int CmdEvents(CmdCtx& ctx);
int CmdJob(CmdCtx& ctx);
int CmdRead(CmdCtx& ctx);
int CmdWrite(CmdCtx& ctx);
int CmdResolve(CmdCtx& ctx);
int CmdCall(CmdCtx& ctx);
int CmdVcall(CmdCtx& ctx);
int CmdAlloc(CmdCtx& ctx);
int CmdFree(CmdCtx& ctx);
int CmdHooktrace(CmdCtx& ctx);
int CmdUnhook(CmdCtx& ctx);
int CmdHookEnable(CmdCtx& ctx);
int CmdHookhits(CmdCtx& ctx);
int CmdHookImport(CmdCtx& ctx);
int CmdRip(CmdCtx& ctx);
int CmdPtrchain(CmdCtx& ctx);
int CmdModbase(CmdCtx& ctx);
int CmdResolvePattern(CmdCtx& ctx);
int CmdXrefs(CmdCtx& ctx);
int CmdPtrscan(CmdCtx& ctx);
int CmdProbe(CmdCtx& ctx);
int CmdScan(CmdCtx& ctx);
int CmdInject(CmdCtx& ctx);
int CmdUnload(CmdCtx& ctx);
int CmdDiscoverCreate(CmdCtx& ctx);
int CmdDiscoverClose(CmdCtx& ctx);
int CmdDiscoverAdd(CmdCtx& ctx);
int CmdDiscoverConstraint(CmdCtx& ctx);
int CmdDiscoverSynth(CmdCtx& ctx);
int CmdDiscoverPathscan(CmdCtx& ctx);
int CmdDiscoverPathValidate(CmdCtx& ctx);
int CmdDiscoverScan(CmdCtx& ctx);
int CmdDiscoverMisc(CmdCtx& ctx);

int CmdCaves(CmdCtx& ctx);
int CmdAllocNear(CmdCtx& ctx);
int CmdProtect(CmdCtx& ctx);
int CmdFlushICache(CmdCtx& ctx);
int CmdDisasmBackend(CmdCtx& ctx);
int CmdDisasm(CmdCtx& ctx);
int CmdInstrLen(CmdCtx& ctx);
int CmdSections(CmdCtx& ctx);
int CmdExports(CmdCtx& ctx);
int CmdImports(CmdCtx& ctx);
int CmdFunctions(CmdCtx& ctx);
int CmdXrefsFrom(CmdCtx& ctx);
int CmdResolveFunction(CmdCtx& ctx);
int CmdXrefsTo(CmdCtx& ctx);
int CmdInvalidateFnIndex(CmdCtx& ctx);
int CmdVtable(CmdCtx& ctx);
int CmdRtti(CmdCtx& ctx);
int CmdWatch(CmdCtx& ctx);
int CmdPatch(CmdCtx& ctx);
int CmdStub(CmdCtx& ctx);

bool ClientParsePred(const wchar_t* spec, HdlFieldPred* out);
const CmdEntry* GetCommandTable(size_t* out_count);
