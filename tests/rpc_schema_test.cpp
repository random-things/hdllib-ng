#include "hdl/rpc/v1/services.rpc.hpp"

#include <cstdio>
#include <cstring>
#include <set>
#include <string>

namespace {

int g_pass = 0;
int g_fail = 0;

#define CHECK(condition, ...)                                                                      \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            std::printf("FAIL: " __VA_ARGS__);                                                     \
            std::printf("\n");                                                                     \
            ++g_fail;                                                                              \
        } else {                                                                                   \
            ++g_pass;                                                                              \
        }                                                                                          \
    } while (0)

std::set<std::string> LoadDeclaredHandlers(const char* path) {
    std::set<std::string> out;
    FILE* file = nullptr;
    if (fopen_s(&file, path, "rb") != 0 || !file) {
        return out;
    }
    std::string text;
    char buffer[4096];
    while (const size_t size = fread(buffer, 1, sizeof(buffer), file)) {
        text.append(buffer, size);
    }
    fclose(file);

    const char* begin = text.c_str();
    const char* cursor = begin;
    while (const char* handle = std::strstr(cursor, "Handle")) {
        const char* scan = handle;
        while (scan > begin && (scan[-1] == ' ' || scan[-1] == '\t')) {
            --scan;
        }
        if (scan >= begin + 4 && std::strncmp(scan - 4, "bool", 4) == 0) {
            const char* end = handle;
            while ((*end >= 'A' && *end <= 'Z') || (*end >= 'a' && *end <= 'z') ||
                   (*end >= '0' && *end <= '9') || *end == '_') {
                ++end;
            }
            const char* open = end;
            while (*open == ' ' || *open == '\t') {
                ++open;
            }
            if (*open == '(' && end > handle) {
                out.emplace(handle, end);
            }
        }
        cursor = handle + 6;
    }
    return out;
}

void TestGeneratedInventory() {
    std::set<std::string> names;
    std::set<std::string> generated_handlers;
    for (const auto& method : hdl::rpc::kMethods) {
        CHECK(!method.name.empty(), "generated RPC method has an empty name");
        CHECK(method.name.starts_with("hdl.rpc.v1."), "method is outside hdl.rpc.v1: %.*s",
              static_cast<int>(method.name.size()), method.name.data());
        CHECK(names.emplace(method.name).second, "duplicate method: %.*s",
              static_cast<int>(method.name.size()), method.name.data());
        hdl::rpc::Method parsed{};
        CHECK(hdl::rpc::ParseMethod(method.name, &parsed) && parsed == method.method,
              "generated ParseMethod round-trip failed: %.*s", static_cast<int>(method.name.size()),
              method.name.data());
        const size_t slash = method.name.rfind('/');
        CHECK(slash != std::string_view::npos, "method has no service separator: %.*s",
              static_cast<int>(method.name.size()), method.name.data());
        if (slash != std::string_view::npos) {
            generated_handlers.emplace("Handle" + std::string(method.name.substr(slash + 1)));
        }
    }
    CHECK(!names.empty(), "protobuf schema generated no RPC methods");

#ifndef HDL_HANDLERS_HPP
#error "HDL_HANDLERS_HPP must name src/ipc/handlers.hpp"
#endif
    const auto declared = LoadDeclaredHandlers(HDL_HANDLERS_HPP);
    CHECK(!declared.empty(), "failed to parse handlers from %s", HDL_HANDLERS_HPP);
    for (const auto& handler : declared) {
        CHECK(generated_handlers.contains(handler), "handler absent from protobuf schema: %s",
              handler.c_str());
    }
    for (const auto& handler : generated_handlers) {
        CHECK(declared.contains(handler), "schema method has no handler: %s", handler.c_str());
    }
}

} // namespace

int main() {
    TestGeneratedInventory();
    std::printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
