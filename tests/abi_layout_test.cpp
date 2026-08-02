#include <hdllib/hdllib.h>

#include <cstddef>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <set>
#include <string>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#endif

/* ================================================================
 * ABI layout: struct sizes (x64 MSVC)
 * ================================================================ */

static_assert(sizeof(HdlSearchDesc) == 64, "ABI break: HdlSearchDesc size");
static_assert(sizeof(HdlCandidate) == 96, "ABI break: HdlCandidate size");
static_assert(sizeof(HdlCallDesc) == 32, "ABI break: HdlCallDesc size");
static_assert(sizeof(HdlHookHit) == 168, "ABI break: HdlHookHit size");
static_assert(sizeof(HdlEvent) == 32, "ABI break: HdlEvent size");
static_assert(sizeof(HdlCallArg) == 24, "ABI break: HdlCallArg size");
static_assert(sizeof(HdlWatchHit) == 48, "ABI break: HdlWatchHit size");

/* Additional wire-facing / IPC structs */
static_assert(sizeof(HdlPatternResolve) == 56, "ABI break: HdlPatternResolve size");
static_assert(sizeof(HdlPatternResult) == 32, "ABI break: HdlPatternResult size");
static_assert(sizeof(HdlFieldPred) == 24, "ABI break: HdlFieldPred size");
static_assert(sizeof(HdlPointerPath) == 48, "ABI break: HdlPointerPath size");
static_assert(sizeof(HdlHealthInfo) == 80, "ABI break: HdlHealthInfo size");
static_assert(sizeof(HdlSynthesizedPattern) == 232, "ABI break: HdlSynthesizedPattern size");

/* ================================================================
 * ABI layout: field offsets (x64 MSVC)
 *   First / last-ish fields per struct to catch re-ordering and
 *   padding changes.
 * ================================================================ */

/* HdlSearchDesc */
static_assert(offsetof(HdlSearchDesc, start) == 0, "ABI break: HdlSearchDesc.start offset");
static_assert(offsetof(HdlSearchDesc, value) == 32, "ABI break: HdlSearchDesc.value offset");
static_assert(offsetof(HdlSearchDesc, module_or_null) == 56,
              "ABI break: HdlSearchDesc.module_or_null offset");

/* HdlCandidate */
static_assert(offsetof(HdlCandidate, id) == 0, "ABI break: HdlCandidate.id offset");
static_assert(offsetof(HdlCandidate, address) == 16, "ABI break: HdlCandidate.address offset");
static_assert(offsetof(HdlCandidate, tag) == 48, "ABI break: HdlCandidate.tag offset");

/* HdlCallDesc */
static_assert(offsetof(HdlCallDesc, address) == 0, "ABI break: HdlCallDesc.address offset");
static_assert(offsetof(HdlCallDesc, args) == 8, "ABI break: HdlCallDesc.args offset");
static_assert(offsetof(HdlCallDesc, timeout_ms) == 24, "ABI break: HdlCallDesc.timeout_ms offset");

/* HdlHookHit */
static_assert(offsetof(HdlHookHit, hook_id) == 0, "ABI break: HdlHookHit.hook_id offset");
static_assert(offsetof(HdlHookHit, args) == 32, "ABI break: HdlHookHit.args offset");
static_assert(offsetof(HdlHookHit, caller) == 96, "ABI break: HdlHookHit.caller offset");
static_assert(offsetof(HdlHookHit, frames) == 104, "ABI break: HdlHookHit.frames offset");

/* HdlEvent */
static_assert(offsetof(HdlEvent, type) == 0, "ABI break: HdlEvent.type offset");
static_assert(offsetof(HdlEvent, timestamp_ms) == 8, "ABI break: HdlEvent.timestamp_ms offset");
static_assert(offsetof(HdlEvent, detail) == 24, "ABI break: HdlEvent.detail offset");

/* HdlCallArg */
static_assert(offsetof(HdlCallArg, kind) == 0, "ABI break: HdlCallArg.kind offset");
static_assert(offsetof(HdlCallArg, u64) == 8, "ABI break: HdlCallArg.u64 offset");
static_assert(offsetof(HdlCallArg, ptr) == 16, "ABI break: HdlCallArg.ptr offset");

/* HdlWatchHit */
static_assert(offsetof(HdlWatchHit, watch_handle) == 0,
              "ABI break: HdlWatchHit.watch_handle offset");
static_assert(offsetof(HdlWatchHit, rip) == 24, "ABI break: HdlWatchHit.rip offset");
static_assert(offsetof(HdlWatchHit, size) == 40, "ABI break: HdlWatchHit.size offset");

/* HdlPatternResolve */
static_assert(offsetof(HdlPatternResolve, pattern) == 0,
              "ABI break: HdlPatternResolve.pattern offset");
static_assert(offsetof(HdlPatternResolve, follow_offsets) == 24,
              "ABI break: HdlPatternResolve.follow_offsets offset");
static_assert(offsetof(HdlPatternResolve, module_or_null) == 40,
              "ABI break: HdlPatternResolve.module_or_null offset");

/* HdlPatternResult */
static_assert(offsetof(HdlPatternResult, match_addr) == 0,
              "ABI break: HdlPatternResult.match_addr offset");
static_assert(offsetof(HdlPatternResult, rva) == 24, "ABI break: HdlPatternResult.rva offset");

/* HdlFieldPred */
static_assert(offsetof(HdlFieldPred, offset) == 0, "ABI break: HdlFieldPred.offset offset");
static_assert(offsetof(HdlFieldPred, a) == 8, "ABI break: HdlFieldPred.a offset");
static_assert(offsetof(HdlFieldPred, b) == 16, "ABI break: HdlFieldPred.b offset");

/* HdlPointerPath */
static_assert(offsetof(HdlPointerPath, static_base) == 0,
              "ABI break: HdlPointerPath.static_base offset");
static_assert(offsetof(HdlPointerPath, depth) == 8, "ABI break: HdlPointerPath.depth offset");
static_assert(offsetof(HdlPointerPath, offsets) == 16, "ABI break: HdlPointerPath.offsets offset");

/* HdlHealthInfo */
static_assert(offsetof(HdlHealthInfo, pid) == 0, "ABI break: HdlHealthInfo.pid offset");
static_assert(offsetof(HdlHealthInfo, working_set) == 16,
              "ABI break: HdlHealthInfo.working_set offset");
static_assert(offsetof(HdlHealthInfo, last_exception_addr) == 64,
              "ABI break: HdlHealthInfo.last_exception_addr offset");

/* HdlSynthesizedPattern */
static_assert(offsetof(HdlSynthesizedPattern, pattern) == 0,
              "ABI break: HdlSynthesizedPattern.pattern offset");
static_assert(offsetof(HdlSynthesizedPattern, pattern_offset) == 192,
              "ABI break: HdlSynthesizedPattern.pattern_offset offset");
static_assert(offsetof(HdlSynthesizedPattern, match_addr) == 208,
              "ABI break: HdlSynthesizedPattern.match_addr offset");

/* ================================================================
 * Runtime helpers
 * ================================================================ */

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, msg)                                                                           \
    do {                                                                                           \
        if (cond) {                                                                                \
            ++g_pass;                                                                              \
        } else {                                                                                   \
            ++g_fail;                                                                              \
            std::fprintf(stderr, "FAIL: %s\n", (msg));                                             \
        }                                                                                          \
    } while (0)

static std::set<std::string> read_golden_set(const char* path) {
    std::set<std::string> names;
    std::ifstream f(path);
    std::string line;
    while (std::getline(f, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n' || line.back() == ' '))
            line.pop_back();
        if (!line.empty() && line[0] != '#')
            names.insert(line);
    }
    return names;
}

/* ================================================================
 * PE export-table parser — reads IMAGE_EXPORT_DIRECTORY from disk.
 * No LoadLibrary: avoids DllMain side-effects.
 * ================================================================ */

#ifdef _WIN32
static std::set<std::string> parse_pe_exports(const char* path) {
    std::set<std::string> names;
    FILE* f = nullptr;
    if (fopen_s(&f, path, "rb") != 0 || !f)
        return names;

    IMAGE_DOS_HEADER dos{};
    if (std::fread(&dos, sizeof(dos), 1, f) != 1 || dos.e_magic != IMAGE_DOS_SIGNATURE) {
        std::fclose(f);
        return names;
    }

    if (std::fseek(f, dos.e_lfanew, SEEK_SET) != 0) {
        std::fclose(f);
        return names;
    }

    DWORD pe_sig = 0;
    if (std::fread(&pe_sig, sizeof(pe_sig), 1, f) != 1 || pe_sig != IMAGE_NT_SIGNATURE) {
        std::fclose(f);
        return names;
    }

    IMAGE_FILE_HEADER fh{};
    if (std::fread(&fh, sizeof(fh), 1, f) != 1) {
        std::fclose(f);
        return names;
    }

    if (fh.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64)) {
        std::fclose(f);
        return names;
    }

    IMAGE_OPTIONAL_HEADER64 opt{};
    if (std::fread(&opt, sizeof(opt), 1, f) != 1) {
        std::fclose(f);
        return names;
    }

    if (opt.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT) {
        std::fclose(f);
        return names;
    }

    DWORD export_rva = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (export_rva == 0) {
        std::fclose(f);
        return names;
    }

    long sec_off = dos.e_lfanew + 4 + static_cast<long>(sizeof(IMAGE_FILE_HEADER)) +
                   static_cast<long>(fh.SizeOfOptionalHeader);
    std::fseek(f, sec_off, SEEK_SET);

    std::vector<IMAGE_SECTION_HEADER> secs(fh.NumberOfSections);
    if (std::fread(secs.data(), sizeof(IMAGE_SECTION_HEADER), secs.size(), f) != secs.size()) {
        std::fclose(f);
        return names;
    }

    auto rva_to_file = [&](DWORD rva) -> long {
        for (const auto& s : secs) {
            if (rva >= s.VirtualAddress && rva < s.VirtualAddress + s.SizeOfRawData)
                return static_cast<long>(s.PointerToRawData + (rva - s.VirtualAddress));
        }
        return -1;
    };

    long ed_off = rva_to_file(export_rva);
    if (ed_off < 0) {
        std::fclose(f);
        return names;
    }

    IMAGE_EXPORT_DIRECTORY ed{};
    std::fseek(f, ed_off, SEEK_SET);
    if (std::fread(&ed, sizeof(ed), 1, f) != 1) {
        std::fclose(f);
        return names;
    }

    if (ed.NumberOfNames == 0) {
        std::fclose(f);
        return names;
    }

    long np_off = rva_to_file(ed.AddressOfNames);
    if (np_off < 0) {
        std::fclose(f);
        return names;
    }

    std::vector<DWORD> name_rvas(ed.NumberOfNames);
    std::fseek(f, np_off, SEEK_SET);
    if (std::fread(name_rvas.data(), sizeof(DWORD), name_rvas.size(), f) != name_rvas.size()) {
        std::fclose(f);
        return names;
    }

    for (DWORD rva : name_rvas) {
        long off = rva_to_file(rva);
        if (off < 0)
            continue;
        std::fseek(f, off, SEEK_SET);
        char buf[256]{};
        if (std::fread(buf, 1, sizeof(buf) - 1, f) < 1)
            continue;
        buf[sizeof(buf) - 1] = '\0';
        names.insert(buf);
    }

    std::fclose(f);
    return names;
}

#endif /* _WIN32 */

/* ================================================================
 * Export snapshot test
 * ================================================================ */

static void test_export_snapshot() {
    const char* golden_path = "golden/hdllib_exports.txt";
    auto golden = read_golden_set(golden_path);
    CHECK(!golden.empty(), "golden file is readable and non-empty");

#ifdef _WIN32
    /*
     * Authoritative check: parse the PE export table from the DLL on disk.
     * This avoids LoadLibrary (DllMain starts the IPC server) and works in
     * CI without invoking external tools.
     */
    auto pe_exports = parse_pe_exports("hdllib.dll");
    CHECK(!pe_exports.empty(), "PE parse found exports in hdllib.dll");

    for (const auto& g : golden) {
        if (pe_exports.count(g)) {
            ++g_pass;
        } else {
            ++g_fail;
            std::fprintf(stderr, "FAIL: golden export '%s' missing from hdllib.dll\n", g.c_str());
        }
    }
    for (const auto& e : pe_exports) {
        if (!golden.count(e)) {
            ++g_fail;
            std::fprintf(stderr, "FAIL: unexpected export '%s' not in golden file\n", e.c_str());
        }
    }
#endif /* _WIN32 */
}

int main() {
    std::printf("ABI static_asserts compiled OK\n");
    test_export_snapshot();
    std::printf("%d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
