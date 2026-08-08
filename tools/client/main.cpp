#include "command_dispatch.hpp"
#include "invocation.hpp"
#include "local_inject.hpp"
#include "usage.hpp"
#include "util.hpp"

#include "pipe_client.hpp"

#include <cstdio>
#include <cwchar>

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

    if (!FindPipeCommand(invocation.command)) {
        PrintUsage();
        return 1;
    }

    PipeClient client(invocation.pid);
    if (!client.Connect()) {
        return FailConnect(invocation.pid);
    }

    return DispatchPipeCommand(invocation, client);
}
