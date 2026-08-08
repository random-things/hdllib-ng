#include "invocation.hpp"

#include <cerrno>
#include <cwchar>
#include <limits>

namespace {

bool EqFlag(const wchar_t* a, const wchar_t* b) {
    return a && b && _wcsicmp(a, b) == 0;
}

bool IsRemovedSurface(const wchar_t* value) {
    return EqFlag(value, L"--tui") || EqFlag(value, L"tui") || EqFlag(value, L"repl");
}

const wchar_t* CanonicalCommand(const wchar_t* name) {
    static const struct {
        const wchar_t* alias;
        const wchar_t* canonical;
    } kAliases[] = {
        {L"dcreate", L"discover-create"},
        {L"dclose", L"discover-close"},
        {L"dadd", L"discover-add"},
        {L"dscan", L"discover-scan"},
        {L"dconstraint", L"discover-constraint"},
        {L"dsynth", L"discover-synth"},
        {L"dpathscan", L"discover-pathscan"},
        {L"dpathvalidate", L"discover-pathvalidate"},
        {L"dwatch", L"discover-watch"},
        {L"dunwatch", L"discover-unwatch"},
        {L"dbegin", L"discover-action-begin"},
        {L"dend", L"discover-action-end"},
        {L"dregion", L"discover-watch-region"},
        {L"dheat", L"discover-heat"},
        {L"drank", L"discover-rank"},
        {L"dcluster", L"discover-cluster"},
        {L"dcands", L"discover-cands"},
        {L"henable", L"hook-enable"},
        {L"enablehook", L"hook-enable"},
        {L"rpat", L"resolve-pattern"},
    };
    for (const auto& alias : kAliases) {
        if (wcscmp(name, alias.alias) == 0) {
            return alias.canonical;
        }
    }
    return name;
}

bool TakeGlobalFlags(int argc, wchar_t* const* argv, int* index, ParsedInvocation* out) {
    while (*index < argc) {
        const wchar_t* arg = argv[*index];
        if (EqFlag(arg, L"--store")) {
            if (*index + 1 >= argc) {
                out->error = InvocationError::Usage;
                return false;
            }
            out->store_path = argv[*index + 1];
            *index += 2;
            continue;
        }
        if (EqFlag(arg, L"--json")) {
            out->json = true;
            ++*index;
            continue;
        }
        if (IsRemovedSurface(arg)) {
            out->error = InvocationError::RemovedSurface;
            return false;
        }
        break;
    }
    return true;
}

bool ParsePid(const wchar_t* text, uint32_t* out) {
    if (!text || !text[0] || !out || text[0] == L'-') {
        return false;
    }
    errno = 0;
    wchar_t* end = nullptr;
    const unsigned long long value = wcstoull(text, &end, 10);
    if (errno == ERANGE || end == text || *end != L'\0' || value == 0 ||
        value > std::numeric_limits<uint32_t>::max()) {
        return false;
    }
    *out = static_cast<uint32_t>(value);
    return true;
}

} // namespace

ParsedInvocation ParseInvocation(int argc, wchar_t* const* argv) {
    ParsedInvocation out;
    if (argc < 2 || !argv) {
        out.error = InvocationError::Usage;
        return out;
    }

    int index = 1;
    if (!TakeGlobalFlags(argc, argv, &index, &out)) {
        return out;
    }
    if (index >= argc || !ParsePid(argv[index], &out.pid)) {
        out.error = InvocationError::InvalidPid;
        return out;
    }
    const std::wstring pid_arg = argv[index++];

    if (!TakeGlobalFlags(argc, argv, &index, &out)) {
        return out;
    }
    if (index >= argc) {
        out.error = InvocationError::Usage;
        return out;
    }
    if (IsRemovedSurface(argv[index])) {
        out.error = InvocationError::RemovedSurface;
        return out;
    }

    out.command = CanonicalCommand(argv[index]);
    out.normalized_args.reserve(static_cast<size_t>(argc - index + 2));
    out.normalized_args.emplace_back(argv[0]);
    out.normalized_args.push_back(pid_arg);
    out.normalized_args.push_back(out.command);
    for (int i = index + 1; i < argc; ++i) {
        out.normalized_args.emplace_back(argv[i]);
    }
    return out;
}

ParsedInvocation ParsePipeCommandTail(uint32_t pid, int argc, wchar_t* const* argv) {
    if (!pid || argc < 1 || !argv) {
        ParsedInvocation out;
        out.error = InvocationError::Usage;
        return out;
    }

    std::vector<std::wstring> owned;
    owned.reserve(static_cast<size_t>(argc) + 2);
    owned.emplace_back(L"hdlclient");
    owned.push_back(std::to_wstring(pid));
    for (int i = 0; i < argc; ++i) {
        owned.emplace_back(argv[i]);
    }

    std::vector<wchar_t*> synthetic_argv;
    synthetic_argv.reserve(owned.size());
    for (std::wstring& value : owned) {
        synthetic_argv.push_back(value.data());
    }
    return ParseInvocation(static_cast<int>(synthetic_argv.size()), synthetic_argv.data());
}
