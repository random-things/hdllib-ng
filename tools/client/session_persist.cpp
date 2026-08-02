#include "session_persist.hpp"

#include "util.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

namespace hdlcli {
namespace {

bool EqFlag(const wchar_t* a, const wchar_t* b) {
    return a && b && _wcsicmp(a, b) == 0;
}

} // namespace

std::wstring SessionSidecarPath(uint32_t pid, const wchar_t* store_path_or_null) {
    if (store_path_or_null && store_path_or_null[0]) {
        std::wstring p(store_path_or_null);
        p += L".session";
        return p;
    }
    wchar_t tmp[MAX_PATH];
    if (!GetTempPathW(MAX_PATH, tmp)) {
        return {};
    }
    wchar_t out[MAX_PATH];
    swprintf_s(out, L"%shdl_session_%u.txt", tmp, pid);
    return out;
}

bool ReadPersistedSession(uint32_t pid, const wchar_t* store_path_or_null, uint64_t* out_id) {
    if (!out_id) {
        return false;
    }
    *out_id = 0;
    const std::wstring path = SessionSidecarPath(pid, store_path_or_null);
    if (path.empty()) {
        return false;
    }
    FILE* f = nullptr;
    if (_wfopen_s(&f, path.c_str(), L"rb") != 0 || !f) {
        return false;
    }
    char buf[64] = {};
    const size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    if (!n) {
        return false;
    }
    *out_id = _strtoui64(buf, nullptr, 0);
    return *out_id != 0;
}

bool WritePersistedSession(uint32_t pid, const wchar_t* store_path_or_null, uint64_t id) {
    if (!id) {
        return false;
    }
    const std::wstring path = SessionSidecarPath(pid, store_path_or_null);
    if (path.empty()) {
        return false;
    }
    FILE* f = nullptr;
    if (_wfopen_s(&f, path.c_str(), L"wb") != 0 || !f) {
        return false;
    }
    char buf[32];
    sprintf_s(buf, "0x%llx", static_cast<unsigned long long>(id));
    const size_t n = strlen(buf);
    const bool ok = fwrite(buf, 1, n, f) == n;
    fclose(f);
    return ok;
}

bool ClearPersistedSession(uint32_t pid, const wchar_t* store_path_or_null) {
    const std::wstring path = SessionSidecarPath(pid, store_path_or_null);
    if (path.empty()) {
        return true;
    }
    if (DeleteFileW(path.c_str())) {
        return true;
    }
    const DWORD err = GetLastError();
    return err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND;
}

uint64_t ResolveSessionId(const CmdCtx& ctx) {
    for (int i = 3; i < ctx.argc; ++i) {
        if (EqFlag(ctx.argv[i], L"--session") && i + 1 < ctx.argc) {
            const uint64_t id = _wcstoui64(ctx.argv[++i], nullptr, 0);
            if (id) {
                return id;
            }
        }
    }
    wchar_t* env = nullptr;
    size_t env_len = 0;
    if (_wdupenv_s(&env, &env_len, L"HDL_SESSION") == 0 && env && env[0]) {
        const uint64_t id = _wcstoui64(env, nullptr, 0);
        free(env);
        if (id) {
            return id;
        }
    } else if (env) {
        free(env);
    }
    uint64_t id = 0;
    if (ReadPersistedSession(ctx.pid, ctx.store_path, &id) && id) {
        return id;
    }
    return 0;
}

bool PersistSessionId(const CmdCtx& ctx, uint64_t id) {
    if (!id) {
        return false;
    }
    return WritePersistedSession(ctx.pid, ctx.store_path, id);
}

} // namespace hdlcli
