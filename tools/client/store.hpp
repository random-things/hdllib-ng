#pragma once

#include "hdllib/hdllib.h"

#include <cstdint>
#include <string>
#include <vector>

namespace hdlcli {

struct LocatorPattern {
    std::string pattern;
    int32_t pattern_offset = 0;
    uint32_t rip_disp = 0;
    uint32_t rip_len = 0;
    std::string module;
};

struct LocatorPath {
    uint64_t static_rva = 0;
    std::vector<int32_t> offsets;
    std::string module;
};

struct LocatorExport {
    std::string module;
    std::string name;
};

struct LocatorImport {
    std::string module;
    std::string dll;
    std::string name;
};

struct LocatorCave {
    std::string module;
    uint64_t near_rva = 0; /* 0 => use near_abs */
    uint64_t near_abs = 0;
    uint32_t min_size = 16;
    uint32_t fill = 0xCC;
    uint64_t last_size = 0;
};

struct LocatorPatch {
    std::string name;
    std::string bytes_hex;
    std::string target_interest; /* resolve sibling interest name for addr; empty => last_addr */
    int enabled_intent = 1;
    uint64_t last_handle = 0;
};

struct LocatorStub {
    int32_t kind = HDL_STUB_MOV_RAX_JMP;
    std::string target_interest;
    uint64_t target_abs = 0;
    uint32_t steal_min = 0;
    uint64_t last_stub_va = 0;
};

struct Locator {
    enum Type { Pattern, Path, Export, Import, Cave, Patch, Stub } type = Pattern;
    LocatorPattern pattern;
    LocatorPath path;
    LocatorExport exp;
    LocatorImport imp;
    LocatorCave cave;
    LocatorPatch patch;
    LocatorStub stub;
    uint64_t last_addr = 0;
    bool last_ok = false;
};

struct Interest {
    std::string name;
    std::string kind; /* address|function|object|field|patch|… */
    std::string tag;
    std::string evidence;                   /* v3 optional */
    std::vector<std::string> struct_fields; /* v3 optional */
    std::vector<Locator> locators;
};

struct InterestStore {
    int version = 3;
    std::string module;
    std::wstring path;
    std::vector<Interest> interests;

    bool Load(const wchar_t* file_path);
    bool LoadJson(const std::string& json);
    bool Save(const wchar_t* file_path = nullptr) const;
    Interest* Find(const char* name);
    void AddOrReplace(Interest in);
};

} // namespace hdlcli
