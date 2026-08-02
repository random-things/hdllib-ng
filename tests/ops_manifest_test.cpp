#include "protocol.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <set>
#include <string>
#include <vector>

#ifdef _MSC_VER
#pragma warning(disable : 4127) /* conditional expression is constant (do-while-0, constant caps)  \
                                 */
#endif

using namespace hdl::proto;

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, ...)                                                                           \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            printf("FAIL: " __VA_ARGS__);                                                          \
            printf("\n");                                                                          \
            ++g_fail;                                                                              \
        } else {                                                                                   \
            ++g_pass;                                                                              \
        }                                                                                          \
    } while (0)

static void TestUniqueIds() {
    printf("--- TestUniqueIds ---\n");
    std::set<uint32_t> ids;

#define HDL_OP(Name, Id, Handler, Cap, CliVerb)                                                    \
    CHECK(ids.insert(Id).second, "Op" #Name " id %u is duplicate", static_cast<unsigned>(Id));
#include "ipc/ops_manifest.inc"
}

static void TestCapSubsetOfDefault() {
    printf("--- TestCapSubsetOfDefault ---\n");
    const uint32_t all = hdl::proto::DefaultCapabilityBits();

#define HDL_OP(Name, Id, Handler, Cap, CliVerb)                                                    \
    {                                                                                              \
        const uint32_t cap = static_cast<uint32_t>(Cap);                                           \
        CHECK(cap == 0 || (cap & all) == cap,                                                      \
              "Op" #Name " cap 0x%x not subset of DefaultCapabilityBits() 0x%x", cap, all);        \
    }
#include "ipc/ops_manifest.inc"
}

static void TestIdsNonZero() {
    printf("--- TestIdsNonZero ---\n");

#define HDL_OP(Name, Id, Handler, Cap, CliVerb) CHECK(Id != 0, "Op" #Name " has id 0 (reserved)");
#include "ipc/ops_manifest.inc"
}

static void TestEnumMatchesManifest() {
    printf("--- TestEnumMatchesManifest ---\n");
    using namespace hdl::proto;

#define HDL_OP(Name, Id, Handler, Cap, CliVerb)                                                    \
    CHECK(static_cast<uint32_t>(Op##Name) == static_cast<uint32_t>(Id),                            \
          "Op" #Name " enum value %u != manifest id %u", static_cast<unsigned>(Op##Name),          \
          static_cast<unsigned>(Id));
#include "ipc/ops_manifest.inc"
}

static void TestUniqueCliVerbs() {
    printf("--- TestUniqueCliVerbs ---\n");
    std::set<std::string> verbs;

#define HDL_OP(Name, Id, Handler, Cap, CliVerb)                                                    \
    {                                                                                              \
        const char* verb = CliVerb;                                                                \
        if (verb) {                                                                                \
            CHECK(verbs.insert(verb).second, "Op" #Name " CliVerb \"%s\" is duplicate", verb);     \
        }                                                                                          \
    }
#include "ipc/ops_manifest.inc"
}

/*
 * TestAllHandlersDeclared — ensures every Handle* function declared in
 * src/ipc/handlers.hpp appears as a Handler in the manifest. This catches
 * handlers that are declared but accidentally omitted from the manifest.
 * Declarations are parsed from handlers.hpp (path via HDL_HANDLERS_HPP).
 */
static std::set<std::string> LoadDeclaredHandlers(const char* path) {
    std::set<std::string> out;
    FILE* f = nullptr;
    if (fopen_s(&f, path, "rb") != 0 || !f) {
        return out;
    }
    std::string text;
    char buf[4096];
    while (size_t n = fread(buf, 1, sizeof(buf), f)) {
        text.append(buf, n);
    }
    fclose(f);

    /* Match: bool HandleName( */
    const char* begin = text.c_str();
    const char* p = begin;
    while (*p) {
        const char* h = strstr(p, "Handle");
        if (!h) {
            break;
        }
        /* Require preceding "bool " (allow whitespace). */
        const char* scan = h;
        while (scan > begin && (scan[-1] == ' ' || scan[-1] == '\t')) {
            --scan;
        }
        if (scan >= begin + 4 && strncmp(scan - 4, "bool", 4) == 0) {
            const char* name = h;
            const char* e = name;
            while ((*e >= 'A' && *e <= 'Z') || (*e >= 'a' && *e <= 'z') ||
                   (*e >= '0' && *e <= '9') || *e == '_') {
                ++e;
            }
            const char* q = e;
            while (*q == ' ' || *q == '\t') {
                ++q;
            }
            if (*q == '(' && e > name) {
                out.insert(std::string(name, e));
            }
        }
        p = h + 6;
    }
    return out;
}

static void TestAllHandlersDeclared() {
    printf("--- TestAllHandlersDeclared ---\n");

    std::set<std::string> manifest_handlers;

#define HDL_OP(Name, Id, Handler, Cap, CliVerb) manifest_handlers.insert(#Handler);
#include "ipc/ops_manifest.inc"

#ifndef HDL_HANDLERS_HPP
#error "HDL_HANDLERS_HPP must be defined to the path of src/ipc/handlers.hpp"
#endif
    const std::set<std::string> declared = LoadDeclaredHandlers(HDL_HANDLERS_HPP);
    CHECK(!declared.empty(), "failed to parse Handle* declarations from %s", HDL_HANDLERS_HPP);

    for (const auto& h : declared) {
        CHECK(manifest_handlers.count(h) == 1,
              "Handler %s declared in handlers.hpp but missing from ops_manifest.inc", h.c_str());
    }
    for (const auto& h : manifest_handlers) {
        CHECK(declared.count(h) == 1,
              "Handler %s in ops_manifest.inc but not declared in handlers.hpp", h.c_str());
    }
}

int main() {
    TestUniqueIds();
    TestCapSubsetOfDefault();
    TestIdsNonZero();
    TestEnumMatchesManifest();
    TestUniqueCliVerbs();
    TestAllHandlersDeclared();

    printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail > 0 ? 1 : 0;
}
