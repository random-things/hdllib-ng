#include "store.hpp"

#include "json/json.hpp"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <sstream>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

namespace hdlcli {
namespace {

using hdl::json::Escape;
using hdl::json::ExtractI32;
using hdl::json::ExtractObjectArray;
using hdl::json::ExtractString;
using hdl::json::ExtractStringArray;
using hdl::json::ExtractU64;

bool NormalizeUserFilePath(const wchar_t* path, wchar_t* full, size_t full_cch) {
    if (!path || !path[0] || !full || full_cch < 2) {
        return false;
    }
    const size_t len = wcslen(path);
    if (len == 0 || len >= full_cch) {
        return false;
    }
    const DWORD n = GetFullPathNameW(path, static_cast<DWORD>(full_cch), full, nullptr);
    return n > 0 && n < full_cch;
}

bool OpenInWide(const wchar_t* path, std::ifstream* out) {
    if (!path || !out) {
        return false;
    }
    wchar_t full[MAX_PATH];
    if (!NormalizeUserFilePath(path, full, MAX_PATH)) {
        return false;
    }
    // Local CLI --store path chosen by the operator running hdlclient.
    // codeql[cpp/path-injection]
    out->open(full, std::ios::binary);
    return static_cast<bool>(*out);
}

bool OpenOutWide(const wchar_t* path, std::ofstream* out) {
    if (!path || !out) {
        return false;
    }
    wchar_t full[MAX_PATH];
    if (!NormalizeUserFilePath(path, full, MAX_PATH)) {
        return false;
    }
    // codeql[cpp/path-injection]
    out->open(full, std::ios::binary);
    return static_cast<bool>(*out);
}

void WriteCommonTail(std::ostream& out, const Locator& loc) {
    out << ",\n          \"last_addr\": \"0x" << std::hex << loc.last_addr << std::dec
        << "\",\n          \"last_ok\": " << (loc.last_ok ? 1 : 0) << "\n        }";
}

} // namespace

bool InterestStore::Load(const wchar_t* file_path) {
    path = file_path ? file_path : L"";
    std::ifstream fin;
    if (!OpenInWide(file_path, &fin)) {
        return false;
    }
    std::ostringstream ss;
    ss << fin.rdbuf();
    const std::string json = ss.str();
    interests.clear();
    ExtractString(json, "module", &module);
    uint64_t ver = 1;
    ExtractU64(json, "version", &ver);
    version = static_cast<int>(ver);

    std::vector<std::string> objs;
    if (!ExtractObjectArray(json, "interests", &objs)) {
        if (json.find("\"interests\"") != std::string::npos) {
            return false; /* present but truncated/malformed */
        }
        return true; /* no interests key — empty store */
    }
    for (const auto& obj : objs) {
        Interest interest;
        ExtractString(obj, "name", &interest.name);
        ExtractString(obj, "kind", &interest.kind);
        ExtractString(obj, "tag", &interest.tag);
        if (version >= 3) {
            ExtractString(obj, "evidence", &interest.evidence);
            ExtractStringArray(obj, "struct_fields", &interest.struct_fields);
        }
        std::vector<std::string> locs;
        if (ExtractObjectArray(obj, "locators", &locs)) {
            for (const auto& lo : locs) {
                Locator loc;
                std::string typ;
                ExtractString(lo, "type", &typ);
                if (typ == "path") {
                    loc.type = Locator::Path;
                    ExtractU64(lo, "static_rva", &loc.path.static_rva);
                    ExtractString(lo, "module", &loc.path.module);
                    std::string offs;
                    if (ExtractString(lo, "offsets", &offs)) {
                        char* p = const_cast<char*>(offs.c_str());
                        while (*p) {
                            loc.path.offsets.push_back(static_cast<int32_t>(strtol(p, &p, 0)));
                            if (*p == ',') {
                                ++p;
                            }
                        }
                    }
                } else if (typ == "export") {
                    loc.type = Locator::Export;
                    ExtractString(lo, "module", &loc.exp.module);
                    ExtractString(lo, "name", &loc.exp.name);
                } else if (typ == "import") {
                    loc.type = Locator::Import;
                    ExtractString(lo, "module", &loc.imp.module);
                    ExtractString(lo, "dll", &loc.imp.dll);
                    ExtractString(lo, "name", &loc.imp.name);
                } else if (typ == "cave") {
                    loc.type = Locator::Cave;
                    ExtractString(lo, "module", &loc.cave.module);
                    ExtractU64(lo, "near_rva", &loc.cave.near_rva);
                    ExtractU64(lo, "near_abs", &loc.cave.near_abs);
                    int32_t tmp = 0;
                    if (ExtractI32(lo, "min_size", &tmp)) {
                        loc.cave.min_size = static_cast<uint32_t>(tmp);
                    }
                    if (ExtractI32(lo, "fill", &tmp)) {
                        loc.cave.fill = static_cast<uint32_t>(tmp);
                    }
                    ExtractU64(lo, "last_size", &loc.cave.last_size);
                } else if (typ == "patch") {
                    loc.type = Locator::Patch;
                    ExtractString(lo, "name", &loc.patch.name);
                    ExtractString(lo, "bytes_hex", &loc.patch.bytes_hex);
                    ExtractString(lo, "target_interest", &loc.patch.target_interest);
                    int32_t en = 1;
                    if (ExtractI32(lo, "enabled_intent", &en)) {
                        loc.patch.enabled_intent = en;
                    }
                    ExtractU64(lo, "last_handle", &loc.patch.last_handle);
                } else if (typ == "stub") {
                    loc.type = Locator::Stub;
                    int32_t k = HDL_STUB_MOV_RAX_JMP;
                    ExtractI32(lo, "kind", &k);
                    loc.stub.kind = k;
                    ExtractString(lo, "target_interest", &loc.stub.target_interest);
                    ExtractU64(lo, "target_abs", &loc.stub.target_abs);
                    int32_t sm = 0;
                    if (ExtractI32(lo, "steal_min", &sm)) {
                        loc.stub.steal_min = static_cast<uint32_t>(sm);
                    }
                    ExtractU64(lo, "last_stub_va", &loc.stub.last_stub_va);
                } else if (typ.empty() || typ == "pattern") {
                    loc.type = Locator::Pattern;
                    ExtractString(lo, "pattern", &loc.pattern.pattern);
                    ExtractI32(lo, "pattern_offset", &loc.pattern.pattern_offset);
                    int32_t tmp = 0;
                    if (ExtractI32(lo, "rip_disp", &tmp)) {
                        loc.pattern.rip_disp = static_cast<uint32_t>(tmp);
                    }
                    if (ExtractI32(lo, "rip_len", &tmp)) {
                        loc.pattern.rip_len = static_cast<uint32_t>(tmp);
                    }
                    ExtractString(lo, "module", &loc.pattern.module);
                } else {
                    fprintf(stderr, "store: ignoring unknown locator type '%s'\n", typ.c_str());
                    continue;
                }
                ExtractU64(lo, "last_addr", &loc.last_addr);
                uint64_t ok = 0;
                if (ExtractU64(lo, "last_ok", &ok)) {
                    loc.last_ok = ok != 0;
                }
                interest.locators.push_back(std::move(loc));
            }
        }
        if (!interest.name.empty()) {
            interests.push_back(std::move(interest));
        }
    }
    return true;
}

bool InterestStore::Save(const wchar_t* file_path) const {
    const wchar_t* use = file_path ? file_path : path.c_str();
    if (!use || !use[0]) {
        return false;
    }
    std::ofstream out;
    if (!OpenOutWide(use, &out)) {
        return false;
    }
    const int ver = version >= 3 ? version : 3;
    out << "{\n  \"version\": " << ver << ",\n  \"module\": \"" << Escape(module)
        << "\",\n  \"interests\": [\n";
    for (size_t i = 0; i < interests.size(); ++i) {
        const auto& in = interests[i];
        out << "    {\n      \"name\": \"" << Escape(in.name) << "\",\n      \"kind\": \""
            << Escape(in.kind) << "\",\n      \"tag\": \"" << Escape(in.tag) << "\"";
        if (ver >= 3 && !in.evidence.empty()) {
            out << ",\n      \"evidence\": \"" << Escape(in.evidence) << "\"";
        }
        if (ver >= 3 && !in.struct_fields.empty()) {
            out << ",\n      \"struct_fields\": [";
            for (size_t k = 0; k < in.struct_fields.size(); ++k) {
                if (k) {
                    out << ", ";
                }
                out << "\"" << Escape(in.struct_fields[k]) << "\"";
            }
            out << "]";
        }
        out << ",\n      \"locators\": [\n";
        for (size_t j = 0; j < in.locators.size(); ++j) {
            const auto& loc = in.locators[j];
            out << "        {\n";
            if (loc.type == Locator::Path) {
                out << "          \"type\": \"path\",\n          \"static_rva\": \"0x" << std::hex
                    << loc.path.static_rva << std::dec << "\",\n          \"module\": \""
                    << Escape(loc.path.module) << "\",\n          \"offsets\": \"";
                for (size_t k = 0; k < loc.path.offsets.size(); ++k) {
                    if (k) {
                        out << ',';
                    }
                    out << loc.path.offsets[k];
                }
                out << "\"";
            } else if (loc.type == Locator::Export) {
                out << "          \"type\": \"export\",\n          \"module\": \""
                    << Escape(loc.exp.module) << "\",\n          \"name\": \""
                    << Escape(loc.exp.name) << "\"";
            } else if (loc.type == Locator::Import) {
                out << "          \"type\": \"import\",\n          \"module\": \""
                    << Escape(loc.imp.module) << "\",\n          \"dll\": \"" << Escape(loc.imp.dll)
                    << "\",\n          \"name\": \"" << Escape(loc.imp.name) << "\"";
            } else if (loc.type == Locator::Cave) {
                out << "          \"type\": \"cave\",\n          \"module\": \""
                    << Escape(loc.cave.module) << "\",\n          \"near_rva\": \"0x" << std::hex
                    << loc.cave.near_rva << "\",\n          \"near_abs\": \"0x" << loc.cave.near_abs
                    << std::dec << "\",\n          \"min_size\": " << loc.cave.min_size
                    << ",\n          \"fill\": " << loc.cave.fill
                    << ",\n          \"last_size\": " << loc.cave.last_size;
            } else if (loc.type == Locator::Patch) {
                out << "          \"type\": \"patch\",\n          \"name\": \""
                    << Escape(loc.patch.name) << "\",\n          \"bytes_hex\": \""
                    << Escape(loc.patch.bytes_hex) << "\",\n          \"target_interest\": \""
                    << Escape(loc.patch.target_interest)
                    << "\",\n          \"enabled_intent\": " << loc.patch.enabled_intent
                    << ",\n          \"last_handle\": " << loc.patch.last_handle;
            } else if (loc.type == Locator::Stub) {
                out << "          \"type\": \"stub\",\n          \"kind\": " << loc.stub.kind
                    << ",\n          \"target_interest\": \"" << Escape(loc.stub.target_interest)
                    << "\",\n          \"target_abs\": \"0x" << std::hex << loc.stub.target_abs
                    << std::dec << "\",\n          \"steal_min\": " << loc.stub.steal_min
                    << ",\n          \"last_stub_va\": \"0x" << std::hex << loc.stub.last_stub_va
                    << std::dec << "\"";
            } else {
                out << "          \"type\": \"pattern\",\n          \"pattern\": \""
                    << Escape(loc.pattern.pattern)
                    << "\",\n          \"pattern_offset\": " << loc.pattern.pattern_offset
                    << ",\n          \"rip_disp\": " << loc.pattern.rip_disp
                    << ",\n          \"rip_len\": " << loc.pattern.rip_len
                    << ",\n          \"module\": \"" << Escape(loc.pattern.module) << "\"";
            }
            WriteCommonTail(out, loc);
            if (j + 1 < in.locators.size()) {
                out << ',';
            }
            out << '\n';
        }
        out << "      ]\n    }";
        if (i + 1 < interests.size()) {
            out << ',';
        }
        out << '\n';
    }
    out << "  ]\n}\n";
    return true;
}

Interest* InterestStore::Find(const char* name) {
    if (!name) {
        return nullptr;
    }
    for (auto& in : interests) {
        if (in.name == name) {
            return &in;
        }
    }
    return nullptr;
}

void InterestStore::AddOrReplace(Interest in) {
    if (Interest* e = Find(in.name.c_str())) {
        *e = std::move(in);
        return;
    }
    interests.push_back(std::move(in));
}

} // namespace hdlcli
