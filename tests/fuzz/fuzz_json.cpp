#include "discover.hpp"
#include "store.hpp"
#include "json/json.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    const size_t bounded_size = size < (1024u * 1024u) ? size : (1024u * 1024u);
    const std::string input(reinterpret_cast<const char*>(data), bounded_size);

    std::string string_value;
    uint64_t number = 0;
    std::vector<std::string> strings;
    std::vector<std::string> objects;
    std::vector<std::pair<std::string, std::string>> fields;
    (void)hdl::json::ExtractString(input, "name", &string_value);
    (void)hdl::json::ExtractU64(input, "address", &number);
    (void)hdl::json::ExtractStringArray(input, "fields", &strings);
    (void)hdl::json::ExtractObjectArray(input, "interests", &objects);
    (void)hdl::json::ParseObjectFields(input, &fields);

    hdlcli::InterestStore store;
    (void)store.LoadJson(input);

    HdlDiscoverSession* session = nullptr;
    if (hdl::DiscoverCreate(&session) == HDL_OK && session) {
        (void)hdl::DiscoverImport(session, input.data(), static_cast<uint32_t>(input.size()));
        hdl::DiscoverClose(session);
    }
    return 0;
}
