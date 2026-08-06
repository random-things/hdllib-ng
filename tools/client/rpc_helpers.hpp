#pragma once

#include "rpc/status.hpp"

#include <string>
#include <string_view>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

inline bool WideToUtf8(std::wstring_view input, std::string* output) {
    if (!output || input.find(L'\0') != std::wstring_view::npos ||
        input.size() > static_cast<size_t>(INT_MAX)) {
        return false;
    }
    output->clear();
    if (input.empty())
        return true;
    const int needed =
        WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, input.data(),
                            static_cast<int>(input.size()), nullptr, 0, nullptr, nullptr);
    if (needed <= 0)
        return false;
    output->resize(static_cast<size_t>(needed));
    return WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, input.data(),
                               static_cast<int>(input.size()), output->data(), needed, nullptr,
                               nullptr) == needed;
}

inline bool Utf8ToWide(std::string_view input, std::wstring* output) {
    if (!output || input.find('\0') != std::string_view::npos ||
        input.size() > static_cast<size_t>(INT_MAX)) {
        return false;
    }
    output->clear();
    if (input.empty())
        return true;
    const int needed = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input.data(),
                                           static_cast<int>(input.size()), nullptr, 0);
    if (needed <= 0)
        return false;
    output->resize(static_cast<size_t>(needed));
    return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input.data(),
                               static_cast<int>(input.size()), output->data(), needed) == needed;
}

template <typename T> bool HasRpcResponse(const hdl::rpc::Result<T>& result) {
    return result.has_response;
}
