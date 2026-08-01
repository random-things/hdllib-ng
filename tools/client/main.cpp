#include "cmd.hpp"
#include "local_inject.hpp"
#include "repl.hpp"
#include "tui.hpp"
#include "usage.hpp"
#include "util.hpp"

#include "pipe_client.hpp"

#include <cstdio>
#include <cstring>
#include <cwctype>
#include <string>

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
    {L"hookhits", CmdHookhits},
    {L"hook-import", CmdHookImport},
    {L"rip", CmdRip},
    {L"ptrchain", CmdPtrchain},
    {L"modbase", CmdModbase},
    {L"resolve-pattern", CmdResolvePattern},
    {L"xrefs", CmdXrefs},
    {L"ptrscan", CmdPtrscan},
    {L"probe", CmdProbe},
    {L"scan", CmdScan},
    {L"inject", CmdInject},
    {L"unload", CmdUnload},
    {L"reload", CmdUnload},
    {L"shutdown", CmdShutdown},
    {L"discover-create", CmdDiscoverCreate},
    {L"discover-close", CmdDiscoverClose},
    {L"discover-add", CmdDiscoverAdd},
    {L"discover-constraint", CmdDiscoverConstraint},
    {L"discover-synth", CmdDiscoverSynth},
    {L"discover-pathscan", CmdDiscoverPathscan},
    {L"discover-pathvalidate", CmdDiscoverPathValidate},
    {L"discover-scan", CmdDiscoverScan},
    {L"discover-watch", CmdDiscoverMisc},
    {L"discover-action-begin", CmdDiscoverMisc},
    {L"discover-action-end", CmdDiscoverMisc},
    {L"discover-watch-region", CmdDiscoverMisc},
    {L"discover-heat", CmdDiscoverMisc},
    {L"discover-rank", CmdDiscoverMisc},
    {L"discover-cluster", CmdDiscoverMisc},
    {L"discover-cands", CmdDiscoverMisc},
    {L"discover-unwatch", CmdDiscoverMisc},
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
        if (argc >= 3 && (EqFlag(argv[2], L"--help") || EqFlag(argv[2], L"-h") ||
                          wcscmp(argv[2], L"/?") == 0)) {
            PrintLocalInjectUsage();
            return 0;
        }
        return RunLocalInject(argc - 2, argv + 2);
    }

    if (argc >= 2 && (_wcsicmp(argv[1], L"unload") == 0 || _wcsicmp(argv[1], L"reload") == 0)) {
        const int reload_default = _wcsicmp(argv[1], L"reload") == 0 ? 1 : 0;
        if (argc >= 3 && (EqFlag(argv[2], L"--help") || EqFlag(argv[2], L"-h") ||
                          wcscmp(argv[2], L"/?") == 0)) {
            PrintLocalUnloadUsage();
            return 0;
        }
        return RunLocalUnload(argc - 2, argv + 2, reload_default);
    }

    if (argc < 2) {
        PrintUsage();
        return 1;
    }

    const wchar_t* store_path = nullptr;
    bool want_tui = false;
    bool want_repl = false;
    bool want_json = false;
    int argi = 1;

    /* Optional global flags before pid: --store PATH --tui --json */
    while (argi < argc) {
        if (EqFlag(argv[argi], L"--store") && argi + 1 < argc) {
            store_path = argv[++argi];
            ++argi;
            continue;
        }
        if (EqFlag(argv[argi], L"--tui")) {
            want_tui = true;
            ++argi;
            continue;
        }
        if (EqFlag(argv[argi], L"--json")) {
            want_json = true;
            ++argi;
            continue;
        }
        break;
    }

    if (argi >= argc) {
        PrintUsage();
        return 1;
    }

    const uint32_t pid = static_cast<uint32_t>(_wtoi(argv[argi]));
    if (pid == 0) {
        wprintf(L"Invalid pid\n");
        return 1;
    }
    ++argi;

    while (argi < argc) {
        if (EqFlag(argv[argi], L"--store") && argi + 1 < argc) {
            store_path = argv[++argi];
            ++argi;
            continue;
        }
        if (EqFlag(argv[argi], L"--tui") || EqFlag(argv[argi], L"tui")) {
            want_tui = true;
            ++argi;
            continue;
        }
        if (EqFlag(argv[argi], L"--json")) {
            want_json = true;
            ++argi;
            continue;
        }
        if (EqFlag(argv[argi], L"repl")) {
            want_repl = true;
            ++argi;
            continue;
        }
        break;
    }

    /* No subcommand → REPL; explicit repl/tui as above */
    if (argi >= argc) {
        want_repl = true;
    }

    if (want_tui || want_repl) {
        PipeClient client(pid);
        if (!client.Connect()) {
            return FailConnect(pid);
        }
        if (want_tui) {
            return hdlcli::RunTui(pid, client, store_path);
        }
        return hdlcli::RunRepl(pid, client, store_path);
    }

    const CmdHandler handler = FindCommand(argv[argi]);
    if (!handler) {
        PrintUsage();
        return 1;
    }

    PipeClient client(pid);
    if (!client.Connect()) {
        return FailConnect(pid);
    }

    /* Rebuild argv so handlers still see: exe pid cmd args...
       Original layout already matches when flags were only after pid. */
    CmdCtx ctx{argc, argv, pid, argv[argi], client};
    ctx.json = want_json;
    /* If flags appeared before the command, shift so argv[2] is the command name.
       Handlers use argv[1]=pid and argv[2]=cmd — keep that contract by synthesizing. */
    if (argi != 2) {
        static wchar_t* syn[256];
        int n = 0;
        syn[n++] = argv[0];
        syn[n++] = argv[1]; /* may not be pid if --store preceded; fix below */
        /* Prefer the numeric pid token we parsed — find it in argv. */
        for (int i = 1; i < argc; ++i) {
            if (static_cast<uint32_t>(_wtoi(argv[i])) == pid && wcslen(argv[i]) > 0 &&
                iswdigit(argv[i][0])) {
                syn[1] = argv[i];
                break;
            }
        }
        for (int i = argi; i < argc && n < 255; ++i) {
            syn[n++] = argv[i];
        }
        ctx.argc = n;
        ctx.argv = syn;
        ctx.cmd = argv[argi];
    }
    return handler(ctx);
}
