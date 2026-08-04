#include "memory.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    const size_t bounded_size = size < 4096 ? size : 4096;
    std::string pattern(reinterpret_cast<const char*>(data), bounded_size);
    pattern.push_back('\0');

    std::vector<uint8_t> bytes;
    std::vector<uint8_t> mask;
    (void)hdl::ParseAobPattern(pattern.c_str(), bytes, mask);

    HdlSearchDesc descriptor{};
    if (size >= 2) {
        descriptor.value_type = static_cast<int32_t>(data[0] % (HDL_VALUE_WSTRING + 2));
        descriptor.cmp = static_cast<int32_t>(data[1] % (HDL_CMP_LESS + 2));
    }
    descriptor.alignment = size >= 3 ? data[2] : 0;
    descriptor.flags = size >= 4 ? data[3] : 0;
    descriptor.value = descriptor.value_type == HDL_VALUE_BYTES
                           ? static_cast<const void*>(pattern.c_str())
                           : static_cast<const void*>(data);
    descriptor.value_size = bounded_size;

    std::vector<uint8_t> searchable(bounded_size + 128, 0);
    if (bounded_size != 0) {
        std::copy_n(data, bounded_size, searchable.data() + 64);
    }
    descriptor.start = reinterpret_cast<uint64_t>(searchable.data() + 64);
    descriptor.size = bounded_size ? bounded_size : 1;
    descriptor.max_results = 16;

    HdlSearchSession* session = nullptr;
    if (hdl::SearchCreate(&session) == HDL_OK && session) {
        (void)hdl::SearchFirst(session, &descriptor, static_cast<volatile int*>(nullptr));
        hdl::SearchClose(session);
    }
    return 0;
}
