#include "env.hpp"
#include "log.hpp"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <cstdlib>
#include <cwctype>

namespace hdl {
namespace {

bool EqualsFlag(const wchar_t* v) {
    if (!v || !v[0]) {
        return false;
    }
    if (_wcsicmp(v, L"1") == 0 || _wcsicmp(v, L"true") == 0 || _wcsicmp(v, L"yes") == 0 ||
        _wcsicmp(v, L"on") == 0) {
        return true;
    }
    return false;
}

} // namespace

bool EnvFlag(const wchar_t* name) {
    wchar_t buf[64];
    const DWORD n = GetEnvironmentVariableW(name, buf, 64);
    if (n == 0 || n >= 64) {
        return false;
    }
    return EqualsFlag(buf);
}

int EnvInt(const wchar_t* name, int default_value) {
    wchar_t buf[64];
    const DWORD n = GetEnvironmentVariableW(name, buf, 64);
    if (n == 0 || n >= 64) {
        return default_value;
    }
    wchar_t* end = nullptr;
    const long v = wcstol(buf, &end, 10);
    if (end == buf) {
        return default_value;
    }
    return static_cast<int>(v);
}

void ApplyQuietLogDefaults() {
    const int level = EnvInt(L"HDL_LOG_LEVEL", -1);
    if (level >= 0 && level <= 3) {
        SetLogLevel(static_cast<LogLevel>(level));
    } else {
        SetLogLevel(LogLevel::Off);
    }

    wchar_t log_file[MAX_PATH];
    const DWORD log_file_length = GetEnvironmentVariableW(L"HDL_LOG_FILE", log_file, MAX_PATH);
    if (log_file_length > 0 && log_file_length < MAX_PATH && !SetLogFile(log_file)) {
        OutputDebugStringA("[ERROR] bootstrap HDL_LOG_FILE could not be opened\n");
    } else if (log_file_length >= MAX_PATH) {
        OutputDebugStringA("[ERROR] bootstrap HDL_LOG_FILE exceeds MAX_PATH\n");
    }
}

} // namespace hdl
