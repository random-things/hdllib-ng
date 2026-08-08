#include "invocation.hpp"

#include <cstdio>
#include <initializer_list>
#include <string>
#include <vector>

namespace {

int failures = 0;

void Check(bool condition, const char* name) {
    std::printf("[%s] %s\n", condition ? "PASS" : "FAIL", name);
    if (!condition) {
        ++failures;
    }
}

ParsedInvocation Parse(std::initializer_list<const wchar_t*> args) {
    std::vector<std::wstring> owned;
    std::vector<wchar_t*> argv;
    owned.reserve(args.size());
    argv.reserve(args.size());
    for (const wchar_t* arg : args) {
        owned.emplace_back(arg);
    }
    for (std::wstring& arg : owned) {
        argv.push_back(arg.data());
    }
    return ParseInvocation(static_cast<int>(argv.size()), argv.data());
}

ParsedInvocation ParseTail(uint32_t pid, std::initializer_list<const wchar_t*> args) {
    std::vector<std::wstring> owned;
    std::vector<wchar_t*> argv;
    owned.reserve(args.size());
    argv.reserve(args.size());
    for (const wchar_t* arg : args) {
        owned.emplace_back(arg);
    }
    for (std::wstring& arg : owned) {
        argv.push_back(arg.data());
    }
    return ParsePipeCommandTail(pid, static_cast<int>(argv.size()), argv.data());
}

} // namespace

int main() {
    {
        const ParsedInvocation parsed = Parse({L"hdlclient", L"42", L"ping"});
        Check(parsed.error == InvocationError::None && parsed.pid == 42 &&
                  parsed.command == L"ping" && parsed.normalized_args.size() == 3,
              "basic invocation");
    }
    {
        const ParsedInvocation parsed =
            Parse({L"hdlclient", L"--json", L"--store", L"x.json", L"42", L"rpat", L"AA"});
        Check(parsed.error == InvocationError::None && parsed.json &&
                  parsed.store_path == L"x.json" && parsed.command == L"resolve-pattern" &&
                  parsed.normalized_args.size() == 4,
              "global flags and alias");
    }
    Check(Parse({L"hdlclient", L"0", L"ping"}).error == InvocationError::InvalidPid,
          "zero pid rejected");
    Check(Parse({L"hdlclient", L"12junk", L"ping"}).error == InvocationError::InvalidPid,
          "pid trailing junk rejected");
    Check(Parse({L"hdlclient", L"4294967296", L"ping"}).error == InvocationError::InvalidPid,
          "pid overflow rejected");
    Check(Parse({L"hdlclient", L"42", L"repl"}).error == InvocationError::RemovedSurface,
          "repl removal preserved");
    Check(Parse({L"hdlclient", L"--tui"}).error == InvocationError::RemovedSurface,
          "tui removal preserved");
    Check(Parse({L"hdlclient", L"--store"}).error == InvocationError::Usage,
          "missing store path rejected");

    {
        const ParsedInvocation parsed = ParseTail(77, {L"ping"});
        Check(parsed.error == InvocationError::None && parsed.pid == 77 &&
                  parsed.command == L"ping" && parsed.normalized_args.size() == 3,
              "pipe command tail");
    }
    {
        const ParsedInvocation parsed =
            ParseTail(77, {L"--json", L"--store", L"state.json", L"rpat", L"AA", L"BB"});
        Check(parsed.error == InvocationError::None && parsed.json &&
                  parsed.store_path == L"state.json" && parsed.command == L"resolve-pattern" &&
                  parsed.normalized_args.size() == 5 && parsed.normalized_args[3] == L"AA" &&
                  parsed.normalized_args[4] == L"BB",
              "pipe command tail flags args and alias");
    }
    Check(ParsePipeCommandTail(77, 0, nullptr).error == InvocationError::Usage,
          "empty pipe command tail rejected");

    return failures == 0 ? 0 : 1;
}
