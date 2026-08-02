#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace hdl {
namespace proto {

enum Op : uint32_t {
#define HDL_OP(Name, Id, Handler, Cap, CliVerb) Op##Name = Id,
#include "ipc/ops_manifest.inc"
};

/* Wire protocol version negotiated via OpHello. Major mismatch => refuse. */
constexpr uint32_t HDL_IPC_PROTO_MAJOR = 1;
constexpr uint32_t HDL_IPC_PROTO_MINOR = 0;
constexpr uint32_t HDL_IPC_ENDIAN_LE = 1;

/* OpCapabilities feature bits. */
enum : uint32_t {
    HDL_CAP_SEARCH = 1u << 0,
    HDL_CAP_DISCOVER = 1u << 1,
    HDL_CAP_WATCH = 1u << 2,
    HDL_CAP_HOOKS = 1u << 3,
    HDL_CAP_FINGERPRINT = 1u << 4,
    HDL_CAP_INJECT = 1u << 5,
    HDL_CAP_PLACE = 1u << 6,
    HDL_CAP_CODE = 1u << 7,
    HDL_CAP_CALL = 1u << 8,
    HDL_CAP_LOCATE = 1u << 9,
};

inline uint32_t DefaultCapabilityBits() {
    return HDL_CAP_SEARCH | HDL_CAP_DISCOVER | HDL_CAP_WATCH | HDL_CAP_HOOKS | HDL_CAP_FINGERPRINT |
           HDL_CAP_INJECT | HDL_CAP_PLACE | HDL_CAP_CODE | HDL_CAP_CALL | HDL_CAP_LOCATE;
}

/* Optional request trailer / streaming response flags. */
enum : uint32_t {
    HDL_IPC_REQ_STREAM = 1u,
    HDL_IPC_MORE = 1u,
};

inline void AppendBytes(std::vector<uint8_t>& buf, const void* data, size_t n) {
    const auto* p = static_cast<const uint8_t*>(data);
    buf.insert(buf.end(), p, p + n);
}

template <typename T> inline void AppendPod(std::vector<uint8_t>& buf, const T& v) {
    AppendBytes(buf, &v, sizeof(T));
}

inline void AppendWString(std::vector<uint8_t>& buf, const wchar_t* s) {
    const uint32_t n = s ? static_cast<uint32_t>((wcslen(s) + 1) * sizeof(wchar_t)) : 0;
    AppendPod(buf, n);
    if (n) {
        AppendBytes(buf, s, n);
    }
}

inline void AppendString(std::vector<uint8_t>& buf, const char* s) {
    const uint32_t n = s ? static_cast<uint32_t>(strlen(s) + 1) : 0;
    AppendPod(buf, n);
    if (n) {
        AppendBytes(buf, s, n);
    }
}

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
