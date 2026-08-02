#include "log.hpp"
#include "memory_internal.hpp"

#include <Psapi.h>

#pragma comment(lib, "Psapi.lib")

namespace hdl {

bool IsReadableProtect(DWORD protect) {
    protect &= 0xFF;
    switch (protect) {
    case PAGE_READONLY:
    case PAGE_READWRITE:
    case PAGE_WRITECOPY:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return true;
    default:
        return false;
    }
}

bool IsExecutableProtect(DWORD protect) {
    protect &= 0xFF;
    switch (protect) {
    case PAGE_EXECUTE:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return true;
    default:
        return false;
    }
}

bool RegionCommittedReadable(const MEMORY_BASIC_INFORMATION& mbi) {
    if (mbi.State != MEM_COMMIT) {
        return false;
    }
    if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) {
        return false;
    }
    return IsReadableProtect(mbi.Protect);
}

size_t SehMemcpy(void* dst, const void* src, size_t size) {
    size_t copied = 0;
    __try {
        memcpy(dst, src, size);
        copied = size;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        copied = 0;
    }
    return copied;
}

int SehMatchAt(const uint8_t* data, const uint8_t* bytes, const uint8_t* mask, size_t len) {
    int ok = 0;
    __try {
        ok = 1;
        for (size_t i = 0; i < len; ++i) {
            if (mask[i] && data[i] != bytes[i]) {
                ok = 0;
                break;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ok = 0;
    }
    return ok;
}

int SehBytesEqual(const uint8_t* a, const uint8_t* b, size_t len) {
    int ok = 0;
    __try {
        ok = memcmp(a, b, len) == 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ok = 0;
    }
    return ok;
}

int SehReadBytes(const void* src, void* dst, size_t size) {
    return SehMemcpy(dst, src, size) == size ? 1 : 0;
}

HdlStatus ReadMemory(uint64_t address, void* buffer, size_t size, size_t* bytes_read) {
    if (!buffer || size == 0) {
        return HDL_E_INVALID_ARG;
    }
    if (bytes_read) {
        *bytes_read = 0;
    }

    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) == 0) {
        return HDL_E_ACCESS;
    }
    if (!RegionCommittedReadable(mbi)) {
        return HDL_E_ACCESS;
    }

    const uint64_t region_end = reinterpret_cast<uint64_t>(mbi.BaseAddress) + mbi.RegionSize;
    if (address >= region_end) {
        return HDL_E_ACCESS;
    }
    const size_t max_in_region = static_cast<size_t>(region_end - address);
    const size_t to_copy = size < max_in_region ? size : max_in_region;

    const size_t copied = SehMemcpy(buffer, reinterpret_cast<const void*>(address), to_copy);
    if (copied == 0) {
        return HDL_E_ACCESS;
    }
    if (bytes_read) {
        *bytes_read = copied;
    }
    return copied == size ? HDL_OK : HDL_E_ACCESS;
}

HdlStatus WriteMemory(uint64_t address, const void* buffer, size_t size, size_t* bytes_written) {
    if (!buffer || size == 0) {
        return HDL_E_INVALID_ARG;
    }
    if (bytes_written) {
        *bytes_written = 0;
    }

    DWORD old_protect = 0;
    if (!VirtualProtect(reinterpret_cast<LPVOID>(address), size, PAGE_EXECUTE_READWRITE,
                        &old_protect)) {
        return HDL_E_ACCESS;
    }

    const size_t copied = SehMemcpy(reinterpret_cast<void*>(address), buffer, size);

    DWORD unused = 0;
    VirtualProtect(reinterpret_cast<LPVOID>(address), size, old_protect, &unused);
    FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<LPCVOID>(address), size);

    if (copied == 0) {
        return HDL_E_ACCESS;
    }
    if (bytes_written) {
        *bytes_written = copied;
    }
    return HDL_OK;
}

HdlStatus EnumRegions(HdlRegionInfo* out, uint32_t* inout_count) {
    if (!inout_count) {
        return HDL_E_INVALID_ARG;
    }

    std::vector<HdlRegionInfo> regions;
    uint8_t* addr = nullptr;
    MEMORY_BASIC_INFORMATION mbi{};

    while (VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT) {
            HdlRegionInfo info{};
            info.base = reinterpret_cast<uint64_t>(mbi.BaseAddress);
            info.size = mbi.RegionSize;
            info.protect = mbi.Protect;
            info.state = mbi.State;
            info.type = mbi.Type;
            regions.push_back(info);
        }
        const uintptr_t next = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        if (next <= reinterpret_cast<uintptr_t>(addr)) {
            break;
        }
        addr = reinterpret_cast<uint8_t*>(next);
    }

    const uint32_t needed = static_cast<uint32_t>(regions.size());
    if (!out || *inout_count < needed) {
        *inout_count = needed;
        return HDL_E_BUFFER_SMALL;
    }
    memcpy(out, regions.data(), needed * sizeof(HdlRegionInfo));
    *inout_count = needed;
    return HDL_OK;
}

HdlStatus EnumModules(HdlModuleInfo* out, uint32_t* inout_count) {
    if (!inout_count) {
        return HDL_E_INVALID_ARG;
    }

    HMODULE mods[1024];
    DWORD needed = 0;
    if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed)) {
        return HDL_E_FAILED;
    }

    const uint32_t count = needed / sizeof(HMODULE);
    if (!out || *inout_count < count) {
        *inout_count = count;
        return HDL_E_BUFFER_SMALL;
    }

    for (uint32_t i = 0; i < count; ++i) {
        HdlModuleInfo info{};
        info.base = reinterpret_cast<uint64_t>(mods[i]);
        MODULEINFO mi{};
        if (GetModuleInformation(GetCurrentProcess(), mods[i], &mi, sizeof(mi))) {
            info.size = mi.SizeOfImage;
        }
        GetModuleFileNameW(mods[i], info.path, 260);
        out[i] = info;
    }
    *inout_count = count;
    return HDL_OK;
}

} // namespace hdl
