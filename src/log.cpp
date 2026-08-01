#include "log.hpp"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <cstdio>
#include <mutex>
#include <string>

namespace hdl {
namespace {

std::mutex g_mu;
LogLevel g_level = LogLevel::Off;
HANDLE g_file = INVALID_HANDLE_VALUE;

const char* LevelName(LogLevel level) {
    switch (level) {
    case LogLevel::Error: return "ERROR";
    case LogLevel::Info:  return "INFO";
    case LogLevel::Debug: return "DEBUG";
    default:              return "OFF";
    }
}

}  // namespace

void SetLogLevel(LogLevel level) {
    std::lock_guard<std::mutex> lock(g_mu);
    g_level = level;
}

bool SetLogFile(const wchar_t* path_or_null) {
    std::lock_guard<std::mutex> lock(g_mu);
    if (g_file != INVALID_HANDLE_VALUE) {
        CloseHandle(g_file);
        g_file = INVALID_HANDLE_VALUE;
    }
    if (!path_or_null || !path_or_null[0]) {
        return true;
    }
    const size_t len = wcslen(path_or_null);
    if (len >= MAX_PATH) {
        return false;
    }
    wchar_t full[MAX_PATH];
    const DWORD n = GetFullPathNameW(path_or_null, MAX_PATH, full, nullptr);
    if (n == 0 || n >= MAX_PATH) {
        return false;
    }
    // Trusted control-pipe clients may choose the log path (see HandleSetLogFile).
    // codeql[cpp/path-injection]
    g_file = CreateFileW(full, FILE_APPEND_DATA, FILE_SHARE_READ, nullptr, OPEN_ALWAYS,
                         FILE_ATTRIBUTE_NORMAL, nullptr);
    return g_file != INVALID_HANDLE_VALUE;
}

void LogV(LogLevel level, const char* fmt, va_list ap) {
    LogLevel current;
    HANDLE file;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        current = g_level;
        file = g_file;
    }
    if (static_cast<int>(level) > static_cast<int>(current) || level == LogLevel::Off) {
        return;
    }

    char body[1024];
    _vsnprintf_s(body, _TRUNCATE, fmt, ap);

    char line[1200];
    /* No product-name token — keeps OutputDebugString / file lines less fingerprintable. */
    _snprintf_s(line, _TRUNCATE, "[%s] %s\n", LevelName(level), body);

    OutputDebugStringA(line);

    if (file != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        WriteFile(file, line, static_cast<DWORD>(strlen(line)), &written, nullptr);
    }
}

void Log(LogLevel level, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    LogV(level, fmt, ap);
    va_end(ap);
}

}  // namespace hdl
