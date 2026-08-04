#include "cmd.hpp"
#include "invocation.hpp"
#include "json_out.hpp"
#include "local_inject.hpp"
#include "usage.hpp"
#include "util.hpp"

#include "pipe_client.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static const CmdEntry kCommands[] = {
    {L"ping", CmdPing},
    {L"log", CmdLog},
    {L"log-file", CmdLogFile},
    {L"health-veh", CmdHealthVeh},
    {L"modules", CmdModules},
    {L"regions", CmdRegions},
    {L"threads", CmdThreads},
    {L"health", CmdHealth},
    {L"fingerprint", CmdFingerprint},
    {L"events", CmdEvents},
    {L"job", CmdJob},
    {L"read", CmdRead},
    {L"write", CmdWrite},
    {L"resolve", CmdResolve},
    {L"call", CmdCall},
    {L"vcall", CmdVcall},
    {L"alloc", CmdAlloc},
    {L"free", CmdFree},
    {L"hooktrace", CmdHooktrace},
    {L"hook", CmdHook},
    {L"unhook", CmdUnhook},
    {L"hook-enable", CmdHookEnable},
    {L"enablehook", CmdHookEnable},
    {L"henable", CmdHookEnable},
    {L"hookhits", CmdHookhits},
    {L"hook-import", CmdHookImport},
    {L"rip", CmdRip},
    {L"ptrchain", CmdPtrchain},
    {L"modbase", CmdModbase},
    {L"resolve-pattern", CmdResolvePattern},
    {L"rpat", CmdResolvePattern},
    {L"xrefs", CmdXrefs},
    {L"ptrscan", CmdPtrscan},
    {L"probe", CmdProbe},
    {L"scan", CmdScan},
    {L"inject", CmdInject},
    {L"unload", CmdUnload},
    {L"reload", CmdUnload},
    {L"shutdown", CmdShutdown},
    {L"discover-create", CmdDiscoverCreate},
    {L"dcreate", CmdDiscoverCreate},
    {L"discover-close", CmdDiscoverClose},
    {L"dclose", CmdDiscoverClose},
    {L"discover-add", CmdDiscoverAdd},
    {L"dadd", CmdDiscoverAdd},
    {L"discover-constraint", CmdDiscoverConstraint},
    {L"dconstraint", CmdDiscoverConstraint},
    {L"discover-synth", CmdDiscoverSynth},
    {L"dsynth", CmdDiscoverSynth},
    {L"discover-pathscan", CmdDiscoverPathscan},
    {L"dpathscan", CmdDiscoverPathscan},
    {L"discover-pathvalidate", CmdDiscoverPathValidate},
    {L"dpathvalidate", CmdDiscoverPathValidate},
    {L"discover-scan", CmdDiscoverScan},
    {L"dscan", CmdDiscoverScan},
    {L"discover-watch", CmdDiscoverMisc},
    {L"dwatch", CmdDiscoverMisc},
    {L"discover-action-begin", CmdDiscoverMisc},
    {L"dbegin", CmdDiscoverMisc},
    {L"discover-action-end", CmdDiscoverMisc},
    {L"dend", CmdDiscoverMisc},
    {L"discover-watch-region", CmdDiscoverMisc},
    {L"dregion", CmdDiscoverMisc},
    {L"discover-heat", CmdDiscoverMisc},
    {L"dheat", CmdDiscoverMisc},
    {L"discover-rank", CmdDiscoverMisc},
    {L"drank", CmdDiscoverMisc},
    {L"discover-cluster", CmdDiscoverMisc},
    {L"dcluster", CmdDiscoverMisc},
    {L"discover-cands", CmdDiscoverMisc},
    {L"dcands", CmdDiscoverMisc},
    {L"discover-unwatch", CmdDiscoverMisc},
    {L"dunwatch", CmdDiscoverMisc},
    {L"discover-watch-import", CmdDiscoverMisc},
    {L"discover-reset-heat", CmdDiscoverMisc},
    {L"discover-export", CmdDiscoverMisc},
    {L"discover-import", CmdDiscoverMisc},
    {L"discover-diff", CmdDiscoverMisc},
    {L"discover-apply-watch", CmdDiscoverMisc},
    {L"discover-evidence", CmdDiscoverMisc},
    {L"caves", CmdCaves},
    {L"alloc-near", CmdAllocNear},
    {L"protect", CmdProtect},
    {L"flush-icache", CmdFlushICache},
    {L"disasm-backend", CmdDisasmBackend},
    {L"disasm", CmdDisasm},
    {L"instrlen", CmdInstrLen},
    {L"sections", CmdSections},
    {L"exports", CmdExports},
    {L"imports", CmdImports},
    {L"functions", CmdFunctions},
    {L"xrefs-from", CmdXrefsFrom},
    {L"xrefs-to", CmdXrefsTo},
    {L"resolve-function", CmdResolveFunction},
    {L"invalidate-fn-index", CmdInvalidateFnIndex},
    {L"vtable", CmdVtable},
    {L"rtti", CmdRtti},
    {L"watch", CmdWatch},
    {L"patch", CmdPatch},
    {L"stub", CmdStub},
    {L"session", CmdSession},
    {L"store", CmdStore},
    {L"recipe", CmdRecipe},
    {L"stabilize", CmdStabilize},
};

const CmdEntry* GetCommandTable(size_t* out_count) {
    if (out_count) {
        *out_count = sizeof(kCommands) / sizeof(kCommands[0]);
    }
    return kCommands;
}

static CmdHandler FindCommand(const wchar_t* name) {
    for (const CmdEntry& e : kCommands) {
        if (wcscmp(e.name, name) == 0) {
            return e.handler;
        }
    }
    return nullptr;
}

static bool EqFlag(const wchar_t* a, const wchar_t* b) {
    return a && b && _wcsicmp(a, b) == 0;
}

int wmain(int argc, wchar_t** argv) {
    if (argc >= 2 && _wcsicmp(argv[1], L"inject") == 0) {
        if (argc >= 3 &&
            (EqFlag(argv[2], L"--help") || EqFlag(argv[2], L"-h") || wcscmp(argv[2], L"/?") == 0)) {
            PrintLocalInjectUsage();
            return 0;
        }
        return RunLocalInject(argc - 2, argv + 2);
    }

    if (argc >= 2 && (_wcsicmp(argv[1], L"unload") == 0 || _wcsicmp(argv[1], L"reload") == 0)) {
        const int reload_default = _wcsicmp(argv[1], L"reload") == 0 ? 1 : 0;
        if (argc >= 3 &&
            (EqFlag(argv[2], L"--help") || EqFlag(argv[2], L"-h") || wcscmp(argv[2], L"/?") == 0)) {
            PrintLocalUnloadUsage();
            return 0;
        }
        return RunLocalUnload(argc - 2, argv + 2, reload_default);
    }

    ParsedInvocation invocation = ParseInvocation(argc, argv);
    if (invocation.error == InvocationError::RemovedSurface) {
        wprintf(L"REPL/TUI removed; use one-shot verbs (session/store/recipe/stabilize).\n");
        PrintUsage();
        return 1;
    }
    if (invocation.error == InvocationError::InvalidPid) {
        wprintf(L"Invalid pid\n");
        return 1;
    }
    if (invocation.error != InvocationError::None) {
        PrintUsage();
        return 1;
    }

    const CmdHandler handler = FindCommand(invocation.command.c_str());
    if (!handler) {
        PrintUsage();
        return 1;
    }

    PipeClient client(invocation.pid);
    if (!client.Connect()) {
        return FailConnect(invocation.pid);
    }

    std::vector<wchar_t*> normalized_argv;
    normalized_argv.reserve(invocation.normalized_args.size());
    for (std::wstring& arg : invocation.normalized_args) {
        normalized_argv.push_back(arg.data());
    }

    CmdCtx ctx{static_cast<int>(normalized_argv.size()), normalized_argv.data(), invocation.pid,
               invocation.command.c_str(), client};
    ctx.json = invocation.json;
    ctx.store_path = invocation.store_path.empty() ? nullptr : invocation.store_path.c_str();
    return Render(ctx, handler(ctx));
}
