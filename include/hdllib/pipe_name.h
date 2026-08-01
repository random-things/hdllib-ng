#pragma once

/*
 * Shared named-pipe path for hdllib IPC (DLL server, hdlclient, tests).
 * Default name avoids the literal "hdllib" substring. Override with env HDL_PIPE:
 *   - Exact local pipe path: \\.\pipe\<name>
 *   - Or a swprintf format that expands to such a path with one unsigned pid
 *     conversion (e.g. "\\\\.\\pipe\\mine_%lu"). Other format conversions are rejected.
 * Resulting paths are validated as local \\.\pipe\... before use with CreateFileW.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <stdio.h>
#include <wchar.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

static inline uint32_t HdlPipeNameHash(uint32_t pid) {
    /* FNV-1a-ish mix; stable across processes for the same pid. */
    uint32_t h = 0x811c9dc5u ^ pid;
    h *= 0x01000193u;
    h ^= (pid << 13) | (pid >> 19);
    h *= 0x85ebca6bu;
    h ^= h >> 16;
    return h;
}

#ifdef _WIN32
/* True if path is a local named pipe: \\.\pipe\<non-empty single-segment name>. */
static inline int HdlIsLocalPipePath(const wchar_t* path) {
    static const wchar_t kPrefix[] = L"\\\\.\\pipe\\";
    enum { kPrefixLen = 9 };
    size_t i;
    const wchar_t* name;
    if (!path) {
        return 0;
    }
    for (i = 0; i < kPrefixLen; ++i) {
        wchar_t a = path[i];
        wchar_t b = kPrefix[i];
        if (b == L'\\' || b == L'.') {
            if (a != b) {
                return 0;
            }
            continue;
        }
        if (a >= L'A' && a <= L'Z') {
            a = (wchar_t)(a - L'A' + L'a');
        }
        if (b >= L'A' && b <= L'Z') {
            b = (wchar_t)(b - L'A' + L'a');
        }
        if (a != b) {
            return 0;
        }
    }
    name = path + kPrefixLen;
    if (!*name) {
        return 0;
    }
    for (; *name; ++name) {
        const wchar_t c = *name;
        if (c < 0x20 || c == L'/' || c == L'\\' || c == L':' || c == L'"' || c == L'|' ||
            c == L'<' || c == L'>' || c == L'*' || c == L'?') {
            return 0;
        }
        if (c == L'.' && name[1] == L'.') {
            return 0;
        }
    }
    if (wcslen(path) >= 256) {
        return 0;
    }
    return 1;
}

/* Allow at most one unsigned integer conversion for the pid; reject %n/%s/%p/etc. */
static inline int HdlPipeFormatIsSafe(const wchar_t* fmt) {
    int conversions = 0;
    const wchar_t* p;
    if (!fmt) {
        return 0;
    }
    for (p = fmt; *p; ++p) {
        if (*p != L'%') {
            continue;
        }
        ++p;
        if (*p == L'%') {
            continue;
        }
        if (*p == L'0') {
            ++p;
        }
        while (*p >= L'0' && *p <= L'9') {
            ++p;
        }
        if (*p == L'l' && (p[1] == L'u' || p[1] == L'x' || p[1] == L'X')) {
            ++conversions;
            ++p;
            continue;
        }
        if (*p == L'u' || *p == L'x' || *p == L'X') {
            ++conversions;
            continue;
        }
        return 0;
    }
    return conversions <= 1;
}
#endif

/* out_cch is wchar count including NUL. Returns 0 on success, non-zero on failure. */
static inline int HdlFormatPipeName(uint32_t pid, wchar_t* out, size_t out_cch) {
    if (!out || out_cch < 32) {
        return 1;
    }
#ifdef _WIN32
    wchar_t env[512];
    const DWORD n = GetEnvironmentVariableW(L"HDL_PIPE", env, 512);
    if (n > 0 && n < 512) {
        if (wcschr(env, L'%')) {
            if (!HdlPipeFormatIsSafe(env) ||
                swprintf_s(out, out_cch, env, (unsigned long)pid) < 0) {
                return 1;
            }
        } else if (wcscpy_s(out, out_cch, env) != 0) {
            return 1;
        }
        if (!HdlIsLocalPipePath(out)) {
            return 1;
        }
        return 0;
    }
#endif
    {
        const uint32_t tag = HdlPipeNameHash(pid);
        /* Bland system-ish name; no "hdllib" token. */
        if (swprintf_s(out, out_cch, L"\\\\.\\pipe\\RPCControl_%08X", (unsigned)tag) < 0) {
            return 1;
        }
    }
    return 0;
}

#ifdef __cplusplus
}
#endif
