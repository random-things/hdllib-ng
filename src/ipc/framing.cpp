#include "framing.hpp"

#include "hdllib/pipe_name.h"
#include "rpc/runtime.hpp"

#include <sddl.h>

#pragma comment(lib, "Advapi32.lib")

namespace hdl {
namespace ipc {

std::wstring PipeName() {
    wchar_t buf[128];
    if (HdlFormatPipeName(GetCurrentProcessId(), buf, 128) != 0) {
        swprintf_s(buf, L"\\\\.\\pipe\\RPCControl_%08X",
                   static_cast<unsigned>(HdlPipeNameHash(GetCurrentProcessId())));
    }
    return buf;
}

bool ReadExact(HANDLE pipe, void* buf, DWORD size) {
    uint8_t* p = static_cast<uint8_t*>(buf);
    DWORD remaining = size;
    while (remaining) {
        DWORD got = 0;
        if (!ReadFile(pipe, p, remaining, &got, nullptr) || got == 0) {
            return false;
        }
        p += got;
        remaining -= got;
    }
    return true;
}

bool WriteExact(HANDLE pipe, const void* buf, DWORD size) {
    const uint8_t* p = static_cast<const uint8_t*>(buf);
    DWORD remaining = size;
    while (remaining) {
        DWORD wrote = 0;
        if (!WriteFile(pipe, p, remaining, &wrote, nullptr) || wrote == 0) {
            return false;
        }
        p += wrote;
        remaining -= wrote;
    }
    return true;
}

SECURITY_ATTRIBUTES* BuildPipeSa(std::vector<uint8_t>& sd_storage) {
    // Allow SYSTEM, Administrators, and the current user — not Everyone.
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return nullptr;
    }
    DWORD needed = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &needed);
    std::vector<uint8_t> buf(needed ? needed : 1);
    TOKEN_USER* user = reinterpret_cast<TOKEN_USER*>(buf.data());
    if (!GetTokenInformation(token, TokenUser, user, static_cast<DWORD>(buf.size()), &needed)) {
        CloseHandle(token);
        return nullptr;
    }
    LPWSTR sid_str = nullptr;
    if (!ConvertSidToStringSidW(user->User.Sid, &sid_str)) {
        CloseHandle(token);
        return nullptr;
    }
    CloseHandle(token);

    wchar_t sddl[512];
    swprintf_s(sddl, L"D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;%s)", sid_str);
    LocalFree(sid_str);

    PSECURITY_DESCRIPTOR sd = nullptr;
    ULONG sd_size = 0;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &sd,
                                                              &sd_size)) {
        return nullptr;
    }
    sd_storage.assign(static_cast<uint8_t*>(sd), static_cast<uint8_t*>(sd) + sd_size);
    LocalFree(sd);

    // SECURITY_ATTRIBUTES must point at stable storage for the CreateNamedPipe call.
    static thread_local SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = FALSE;
    sa.lpSecurityDescriptor = sd_storage.data();
    return &sa;
}

bool ReadFrame(HANDLE pipe, std::vector<uint8_t>& out, bool* frame_too_large) {
    if (frame_too_large) {
        *frame_too_large = false;
    }
    uint32_t size = 0;
    if (!ReadExact(pipe, &size, sizeof(size))) {
        return false;
    }
    if (size > rpc::kMaxFrameBytes) {
        if (frame_too_large) {
            *frame_too_large = true;
        }
        return false;
    }
    out.resize(size);
    if (size == 0) {
        return true;
    }
    return ReadExact(pipe, out.data(), size);
}

bool WriteFrameBytes(HANDLE pipe, const void* data, uint32_t size) {
    if (!WriteExact(pipe, &size, sizeof(size))) {
        return false;
    }
    if (size == 0) {
        return true;
    }
    return WriteExact(pipe, data, size);
}

} // namespace ipc
} // namespace hdl
