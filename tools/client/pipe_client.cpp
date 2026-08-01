#include "pipe_client.hpp"
#include "protocol.hpp"
#include "hdllib/hdllib.h"
#include "hdllib/pipe_name.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <cstdio>

namespace {

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

bool ReadFrame(HANDLE pipe, std::vector<uint8_t>& resp) {
    uint32_t rsize = 0;
    if (!ReadExact(pipe, &rsize, sizeof(rsize))) {
        return false;
    }
    resp.resize(rsize);
    if (rsize && !ReadExact(pipe, resp.data(), rsize)) {
        return false;
    }
    return true;
}

}  // namespace

PipeClient::PipeClient(uint32_t pid) : pid_(pid) {}

PipeClient::~PipeClient() {
    Close();
}

bool PipeClient::Connect(DWORD timeout_ms) {
    Close();
    wchar_t name[128];
    if (HdlFormatPipeName(pid_, name, 128) != 0) {
        return false;
    }

    const DWORD start = GetTickCount();
    for (;;) {
        HANDLE h = CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            DWORD mode = PIPE_READMODE_BYTE | PIPE_WAIT;
            SetNamedPipeHandleState(h, &mode, nullptr, nullptr);
            handle_ = h;
            if (!Negotiate()) {
                Close();
                return false;
            }
            return true;
        }
        if (GetLastError() != ERROR_PIPE_BUSY && GetLastError() != ERROR_FILE_NOT_FOUND) {
            return false;
        }
        if (GetTickCount() - start > timeout_ms) {
            return false;
        }
        WaitNamedPipeW(name, 200);
        Sleep(50);
    }
}

void PipeClient::Close() {
    if (handle_) {
        CloseHandle(static_cast<HANDLE>(handle_));
        handle_ = nullptr;
    }
    proto_major_ = 0;
    proto_minor_ = 0;
    capabilities_ = 0;
}

bool PipeClient::Negotiate() {
    using namespace hdl::proto;
    negotiate_error_.clear();
    std::vector<uint8_t> req;
    AppendPod(req, static_cast<uint32_t>(OpHello));
    std::vector<uint8_t> resp;
    if (!Request(req, resp)) {
        negotiate_error_ = "OpHello failed (transport)";
        return false;
    }
    Reader r(resp);
    int32_t st = 0;
    uint32_t major = 0;
    uint32_t minor = 0;
    uint32_t endian = 0;
    std::string build;
    if (!r.TakePod(st) || st != HDL_OK || !r.TakePod(major) || !r.TakePod(minor) ||
        !r.TakePod(endian) || !r.TakeString(build)) {
        negotiate_error_ = "OpHello response malformed";
        return false;
    }
    if (endian != HDL_IPC_ENDIAN_LE) {
        negotiate_error_ = "unsupported wire endianness";
        return false;
    }
    if (major != HDL_IPC_PROTO_MAJOR) {
        negotiate_error_ = "IPC protocol major mismatch (DLL=" + std::to_string(major) +
                           " client=" + std::to_string(HDL_IPC_PROTO_MAJOR) + ")";
        return false;
    }
    proto_major_ = major;
    proto_minor_ = minor;

    req.clear();
    resp.clear();
    AppendPod(req, static_cast<uint32_t>(OpCapabilities));
    if (!Request(req, resp)) {
        negotiate_error_ = "OpCapabilities failed (transport)";
        return false;
    }
    Reader cr(resp);
    uint32_t caps = 0;
    if (!cr.TakePod(st) || st != HDL_OK || !cr.TakePod(caps)) {
        negotiate_error_ = "OpCapabilities response malformed";
        return false;
    }
    capabilities_ = caps;
    return true;
}

bool PipeClient::Request(const std::vector<uint8_t>& req, std::vector<uint8_t>& resp) {
    if (!handle_) {
        return false;
    }
    HANDLE pipe = static_cast<HANDLE>(handle_);
    const uint32_t size = static_cast<uint32_t>(req.size());
    if (!WriteExact(pipe, &size, sizeof(size))) {
        return false;
    }
    if (size && !WriteExact(pipe, req.data(), size)) {
        return false;
    }
    return ReadFrame(pipe, resp);
}

bool PipeClient::RequestStream(
    const std::vector<uint8_t>& req,
    const std::function<bool(int32_t, uint32_t, const uint8_t*, size_t)>& on_frame) {
    if (!handle_ || !on_frame) {
        return false;
    }
    HANDLE pipe = static_cast<HANDLE>(handle_);
    const uint32_t size = static_cast<uint32_t>(req.size());
    if (!WriteExact(pipe, &size, sizeof(size))) {
        return false;
    }
    if (size && !WriteExact(pipe, req.data(), size)) {
        return false;
    }

    for (;;) {
        std::vector<uint8_t> resp;
        if (!ReadFrame(pipe, resp)) {
            return false;
        }
        hdl::proto::Reader r(resp);
        int32_t status = 0;
        uint32_t flags = 0;
        if (!r.TakePod(status) || !r.TakePod(flags)) {
            return false;
        }
        if (!on_frame(status, flags, r.p, r.left)) {
            return false;
        }
        if ((flags & hdl::proto::HDL_IPC_MORE) == 0) {
            return true;
        }
    }
}
