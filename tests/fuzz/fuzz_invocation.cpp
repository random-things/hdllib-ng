#include "invocation.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    std::vector<std::wstring> owned{L"hdlclient"};
    std::wstring current;
    for (size_t index = 0; index < size && owned.size() < 64; ++index) {
        if (data[index] == 0) {
            owned.push_back(current);
            current.clear();
        } else {
            current.push_back(static_cast<wchar_t>(data[index]));
        }
    }
    owned.push_back(current);

    std::vector<wchar_t*> argv;
    argv.reserve(owned.size());
    for (std::wstring& value : owned) {
        argv.push_back(value.data());
    }
    (void)ParseInvocation(static_cast<int>(argv.size()), argv.data());
    return 0;
}
