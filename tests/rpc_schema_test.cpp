#include "hdl/rpc/v1/services.rpc.hpp"

#include <cstdio>
#include <set>
#include <string>

namespace {
int passed = 0, failed = 0;
#define CHECK(condition, ...)                                                                      \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            std::printf("FAIL: " __VA_ARGS__);                                                     \
            std::printf("\n");                                                                     \
            ++failed;                                                                              \
        } else                                                                                     \
            ++passed;                                                                              \
    } while (0)

void TestGeneratedInventory() {
    std::set<std::string> methods, services, handlers;
    size_t streams = 0;
    for (const auto& metadata : hdl::rpc::kMethods) {
        CHECK(!metadata.name.empty(), "generated RPC method has an empty name");
        CHECK(metadata.name.starts_with("hdl.rpc.v1."), "method outside hdl.rpc.v1: %.*s",
              static_cast<int>(metadata.name.size()), metadata.name.data());
        CHECK(methods.emplace(metadata.name).second, "duplicate method: %.*s",
              static_cast<int>(metadata.name.size()), metadata.name.data());
        CHECK(handlers.emplace(metadata.handler_name).second, "duplicate handler: %.*s",
              static_cast<int>(metadata.handler_name.size()), metadata.handler_name.data());
        CHECK(!metadata.request_type.ends_with(".Payload") &&
                  !metadata.response_type.ends_with(".Payload"),
              "legacy Payload remains: %.*s", static_cast<int>(metadata.name.size()),
              metadata.name.data());
        hdl::rpc::Method parsed{};
        CHECK(hdl::rpc::ParseMethod(metadata.name, &parsed) && parsed == metadata.method,
              "ParseMethod failed: %.*s", static_cast<int>(metadata.name.size()),
              metadata.name.data());
        const size_t slash = metadata.name.rfind('/');
        CHECK(slash != std::string_view::npos, "method has no service separator");
        if (slash != std::string_view::npos) {
            services.emplace(metadata.name.substr(0, slash));
            const size_t dot = metadata.name.rfind('.', slash);
            const std::string expected =
                "Handle" + std::string(metadata.name.substr(dot + 1, slash - dot - 1)) + "_" +
                std::string(metadata.name.substr(slash + 1));
            CHECK(metadata.handler_name == expected, "handler is not service-qualified: %.*s",
                  static_cast<int>(metadata.handler_name.size()), metadata.handler_name.data());
        }
        streams += metadata.server_streaming ? 1 : 0;
    }
    CHECK(std::size(hdl::rpc::kMethods) == 97, "expected 97 methods, got %zu",
          std::size(hdl::rpc::kMethods));
    CHECK(services.size() == 12, "expected 12 services, got %zu", services.size());
    CHECK(streams == 23, "expected 23 server streams, got %zu", streams);
}
} // namespace

int main() {
    TestGeneratedInventory();
    std::printf("\n%d passed, %d failed\n", passed, failed);
    return failed ? 1 : 0;
}
