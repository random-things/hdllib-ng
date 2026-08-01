#pragma once

/*
 * Shared named-pipe path for hdllib IPC (DLL server, hdlclient, tests).
 * Default name avoids the literal "hdllib" substring. Override with env HDL_PIPE:
 *   - Exact local pipe path: \\.\pipe\<name>
 *   - Or the same with one literal pid placeholder: %lu, %u, %x, %X, %08X, %08x
 *     (expanded by string replacement; never passed to swprintf as a format string).
 * The final CreateFileW path is always rebuilt as \\.\pipe\ + sanitized name.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

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
enum { HDL_PIPE_PREFIX_LEN = 9 }; /* \\.\pipe\ */

static inline int HdlPipeNameCharsOk(const wchar_t* name) {
    if (!name || !*name) {
        return 0;
    }
    for (; *name; ++name) {
        const wchar_t c = *name;
        if (c < 0x20 || c == L'/' || c == L'\\' || c == L':' || c == L'"' || c == L'|' ||
            c == L'<' || c == L'>' || c == L'*' || c == L'?' || c == L'%') {
            return 0;
        }
        if (c == L'.' && name[1] == L'.') {
            return 0;
        }
    }
    return 1;
}

/* True if path is a local named pipe: \\.\pipe\<non-empty single-segment name>. */
static inline int HdlIsLocalPipePath(const wchar_t* path) {
    static const wchar_t kPrefix[] = L"\\\\.\\pipe\\";
    size_t i;
    if (!path) {
        return 0;
    }
    for (i = 0; i < HDL_PIPE_PREFIX_LEN; ++i) {
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
    if (!HdlPipeNameCharsOk(path + HDL_PIPE_PREFIX_LEN)) {
        return 0;
    }
    if (wcslen(path) >= 256) {
        return 0;
    }
    return 1;
}

/* Return one validated pipe-name character, or NUL if it is unsafe. */
static inline wchar_t HdlSanitizePipeNameChar(const wchar_t* name, size_t index) {
    const wchar_t c = name ? name[index] : L'\0';
    if (c < 0x20 || c == L'/' || c == L'\\' || c == L':' || c == L'"' || c == L'|' || c == L'<' ||
        c == L'>' || c == L'*' || c == L'?' || c == L'%' ||
        (c == L'.' && name[index + 1] == L'.')) {
        return L'\0';
    }
    return c;
}

/* Rebuild \\.\pipe\<name> from individually sanitized characters. */
static inline int HdlWriteLocalPipePath(wchar_t* out, size_t out_cch, const wchar_t* pipe_name) {
    static const wchar_t kPrefix[HDL_PIPE_PREFIX_LEN] = {L'\\', L'\\', L'.', L'\\', L'p',
                                                         L'i',  L'p',  L'e', L'\\'};
    wchar_t clean_name[256 - HDL_PIPE_PREFIX_LEN];
    size_t nlen = 0;
    if (!out || !pipe_name) {
        return 1;
    }
    while (pipe_name[nlen]) {
        wchar_t clean;
        if (nlen + 1 >= sizeof(clean_name) / sizeof(clean_name[0])) {
            return 1;
        }
        clean = HdlSanitizePipeNameChar(pipe_name, nlen);
        if (!clean) {
            return 1;
        }
        clean_name[nlen++] = clean;
    }
    if (!nlen || nlen + HDL_PIPE_PREFIX_LEN + 1 > out_cch) {
        return 1;
    }
    clean_name[nlen] = L'\0';
    memcpy(out, kPrefix, HDL_PIPE_PREFIX_LEN * sizeof(wchar_t));
    memcpy(out + HDL_PIPE_PREFIX_LEN, clean_name, (nlen + 1) * sizeof(wchar_t));
    return 0;
}

/* Render pid with a string-literal format only. kind: 'u' decimal, 'x'/'X' hex, 8 => %08X. */
static inline int HdlFormatPidToken(wchar_t* dst, size_t dst_cch, uint32_t pid, wchar_t kind,
                                    int width8) {
    if (kind == L'u') {
        return swprintf_s(dst, dst_cch, L"%lu", (unsigned long)pid) < 0 ? 1 : 0;
    }
    if (kind == L'x') {
        return width8 ? (swprintf_s(dst, dst_cch, L"%08x", (unsigned)pid) < 0 ? 1 : 0)
                      : (swprintf_s(dst, dst_cch, L"%x", (unsigned)pid) < 0 ? 1 : 0);
    }
    if (kind == L'X') {
        return width8 ? (swprintf_s(dst, dst_cch, L"%08X", (unsigned)pid) < 0 ? 1 : 0)
                      : (swprintf_s(dst, dst_cch, L"%X", (unsigned)pid) < 0 ? 1 : 0);
    }
    return 1;
}

/*
 * Expand at most one literal placeholder (%lu / %u / %x / %X / %08X / %08x) by
 * concatenation. Never passes `tmpl` to swprintf as a format string.
 */
static inline int HdlExpandPipeTemplate(const wchar_t* tmpl, uint32_t pid, wchar_t* out,
                                        size_t out_cch) {
    const wchar_t* p;
    const wchar_t* token = NULL;
    size_t token_len = 0;
    wchar_t kind = 0;
    int width8 = 0;
    wchar_t pid_txt[32];
    wchar_t expanded[512];
    size_t prefix_len;
    size_t suffix_len;
    size_t pid_len;
    size_t total;

    if (!tmpl || !out) {
        return 1;
    }
    for (p = tmpl; *p; ++p) {
        size_t len = 0;
        wchar_t k = 0;
        int w8 = 0;
        if (*p != L'%') {
            continue;
        }
        if (wcsncmp(p, L"%08X", 4) == 0 || wcsncmp(p, L"%08x", 4) == 0) {
            len = 4;
            k = p[3];
            w8 = 1;
        } else if (wcsncmp(p, L"%lu", 3) == 0) {
            len = 3;
            k = L'u';
        } else if (p[1] == L'u' || p[1] == L'x' || p[1] == L'X') {
            len = 2;
            k = p[1];
        } else {
            return 1; /* unknown / unsafe % sequence */
        }
        if (token) {
            return 1; /* more than one placeholder */
        }
        token = p;
        token_len = len;
        kind = k;
        width8 = w8;
        p += len - 1;
    }
    if (!token) {
        return 1;
    }
    if (HdlFormatPidToken(pid_txt, sizeof(pid_txt) / sizeof(pid_txt[0]), pid, kind, width8) != 0) {
        return 1;
    }
    prefix_len = (size_t)(token - tmpl);
    suffix_len = wcslen(token + token_len);
    pid_len = wcslen(pid_txt);
    total = prefix_len + pid_len + suffix_len;
    if (total + 1 > sizeof(expanded) / sizeof(expanded[0])) {
        return 1;
    }
    memcpy(expanded, tmpl, prefix_len * sizeof(wchar_t));
    memcpy(expanded + prefix_len, pid_txt, pid_len * sizeof(wchar_t));
    memcpy(expanded + prefix_len + pid_len, token + token_len, (suffix_len + 1) * sizeof(wchar_t));
    if (!HdlIsLocalPipePath(expanded)) {
        return 1;
    }
    return HdlWriteLocalPipePath(out, out_cch, expanded + HDL_PIPE_PREFIX_LEN);
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
            return HdlExpandPipeTemplate(env, pid, out, out_cch);
        }
        if (!HdlIsLocalPipePath(env)) {
            return 1;
        }
        /* Copy only the validated pipe name; rebuild with a fixed prefix. */
        return HdlWriteLocalPipePath(out, out_cch, env + HDL_PIPE_PREFIX_LEN);
    }
#endif
    {
        wchar_t name[32];
        const uint32_t tag = HdlPipeNameHash(pid);
        if (swprintf_s(name, sizeof(name) / sizeof(name[0]), L"RPCControl_%08X", (unsigned)tag) <
            0) {
            return 1;
        }
        return HdlWriteLocalPipePath(out, out_cch, name);
    }
}

#ifdef _WIN32
/*
 * Open the local control pipe for `pid`. The path is always produced by
 * HdlFormatPipeName (fixed \\.\pipe\ prefix + character-validated name).
 */
static inline HANDLE HdlOpenLocalPipe(uint32_t pid) {
    wchar_t name[128];
    if (HdlFormatPipeName(pid, name, 128) != 0) {
        SetLastError(ERROR_INVALID_NAME);
        return INVALID_HANDLE_VALUE;
    }
    return CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
}

static inline BOOL HdlWaitLocalPipe(uint32_t pid, DWORD timeout_ms) {
    wchar_t name[128];
    if (HdlFormatPipeName(pid, name, 128) != 0) {
        return FALSE;
    }
    return WaitNamedPipeW(name, timeout_ms);
}
#endif

#ifdef __cplusplus
}
#endif
