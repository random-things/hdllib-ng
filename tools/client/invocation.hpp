#pragma once

#include <cstdint>
#include <string>
#include <vector>

enum class InvocationError {
    None,
    Usage,
    RemovedSurface,
    InvalidPid,
};

struct ParsedInvocation {
    uint32_t pid = 0;
    bool json = false;
    std::wstring store_path;
    std::wstring command;
    std::vector<std::wstring> normalized_args;
    InvocationError error = InvocationError::None;
};

/* Parse the one-shot command grammar without connecting to a pipe or executing a command. */
ParsedInvocation ParseInvocation(int argc, wchar_t* const* argv);

/* Parse a command tail as though it followed `hdlclient <pid>`. This is used by
 * local inject --then so global one-shot flags, aliases, and normalized argv stay
 * identical to a standalone invocation. */
ParsedInvocation ParsePipeCommandTail(uint32_t pid, int argc, wchar_t* const* argv);
