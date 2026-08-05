#pragma once

#include "rpc/request.hpp"

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace hdl {
namespace proto {

/* Domain payload flags used by existing handlers, never as RPC identifiers. */
enum : uint32_t {
    HDL_IPC_REQ_STREAM = 1u,
    HDL_IPC_MORE = 1u,
};

inline void AppendBytes(std::vector<uint8_t>& buf, const void* data, size_t n) {
    const auto* p = static_cast<const uint8_t*>(data);
    buf.insert(buf.end(), p, p + n);
}

inline void AppendBytes(rpc::PreparedRequest& request, const void* data, size_t n) {
    AppendBytes(request.payload, data, n);
}

template <typename T> inline void AppendPod(std::vector<uint8_t>& buf, const T& v) {
    AppendBytes(buf, &v, sizeof(T));
}

template <typename T> inline void AppendPod(rpc::PreparedRequest& request, const T& value) {
    AppendPod(request.payload, value);
}

inline void AppendWString(std::vector<uint8_t>& buf, const wchar_t* s) {
    const uint32_t n = s ? static_cast<uint32_t>((wcslen(s) + 1) * sizeof(wchar_t)) : 0;
    AppendPod(buf, n);
    if (n) {
        AppendBytes(buf, s, n);
    }
}

inline void AppendWString(rpc::PreparedRequest& request, const wchar_t* value) {
    AppendWString(request.payload, value);
}

inline void AppendString(std::vector<uint8_t>& buf, const char* s) {
    const uint32_t n = s ? static_cast<uint32_t>(strlen(s) + 1) : 0;
    AppendPod(buf, n);
    if (n) {
        AppendBytes(buf, s, n);
    }
}

inline void AppendString(rpc::PreparedRequest& request, const char* value) {
    AppendString(request.payload, value);
}

using PreparedRequest = rpc::PreparedRequest;
using rpc::SetMethod;

struct Reader {
    const uint8_t* p = nullptr;
    size_t left = 0;

    explicit Reader(const std::vector<uint8_t>& buf) : p(buf.data()), left(buf.size()) {}
    Reader(const uint8_t* data, size_t n) : p(data), left(n) {}

    bool Take(void* out, size_t n) {
        if (left < n) {
            return false;
        }
        memcpy(out, p, n);
        p += n;
        left -= n;
        return true;
    }

    template <typename T> bool TakePod(T& out) { return Take(&out, sizeof(T)); }

    bool TakeWString(std::wstring& out) {
        uint32_t n = 0;
        if (!TakePod(n) || n % sizeof(wchar_t) != 0 || left < n) {
            return false;
        }
        out.assign(reinterpret_cast<const wchar_t*>(p), n / sizeof(wchar_t));
        if (!out.empty() && out.back() == L'\0') {
            out.pop_back();
        }
        p += n;
        left -= n;
        return true;
    }

    bool TakeString(std::string& out) {
        uint32_t n = 0;
        if (!TakePod(n) || left < n) {
            return false;
        }
        out.assign(reinterpret_cast<const char*>(p), n ? n - 1 : 0);
        p += n;
        left -= n;
        return true;
    }
};

} // namespace proto
} // namespace hdl
