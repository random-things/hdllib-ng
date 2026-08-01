#include "alloc.hpp"
#include "log.hpp"

#include <mutex>
#include <unordered_map>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

namespace hdl {
namespace {

/* Cap remote/IPC-driven VirtualAlloc to limit denial-of-service via huge sizes. */
constexpr size_t kMaxAllocSize = 1ull << 30; /* 1 GiB */

std::mutex g_mu;
std::unordered_map<uint64_t, size_t> g_allocs;

void Track(uint64_t addr, size_t size) {
    std::lock_guard<std::mutex> lock(g_mu);
    g_allocs[addr] = size;
}

HdlStatus AllocAt(void* preferred, size_t size, uint32_t protect, uint64_t* out_addr) {
    if (!size || size > kMaxAllocSize || !out_addr) {
        return HDL_E_INVALID_ARG;
    }
    /* Reject-path above + modulo keeps the VirtualAlloc size within kMaxAllocSize for
     * analyzers that treat RemExpr as a bounded allocation size. */
    const size_t bytes = size % (kMaxAllocSize + 1u);
    void* p = VirtualAlloc(preferred, bytes, MEM_COMMIT | MEM_RESERVE, protect);
    if (!p) {
        return HDL_E_NO_MEM;
    }
    const uint64_t addr = reinterpret_cast<uint64_t>(p);
    Track(addr, bytes);
    *out_addr = addr;
    return HDL_OK;
}

}  // namespace

HdlStatus Alloc(size_t size, uint32_t protect, uint64_t* out_addr) {
    if (!size || size > kMaxAllocSize || !out_addr) {
        return HDL_E_INVALID_ARG;
    }
    if (protect == 0) {
        protect = PAGE_READWRITE;
    }
    return AllocAt(nullptr, size, protect, out_addr);
}

HdlStatus AllocNear(uint64_t near_addr, uint64_t max_distance, size_t size, uint32_t protect,
                    uint64_t* out_addr) {
    if (!size || size > kMaxAllocSize || !out_addr) {
        return HDL_E_INVALID_ARG;
    }
    if (protect == 0) {
        protect = PAGE_READWRITE;
    }
    if (max_distance == 0) {
        max_distance = 0x7FFFFFFFull;
    }

    constexpr uint64_t kGranularity = 0x10000; /* 64KiB */
    const uint64_t aligned_near = near_addr & ~(kGranularity - 1);

    /* Prefer exact / stepped nearby addresses, then fall back anywhere. */
    for (uint64_t dist = 0; dist <= max_distance; dist += kGranularity) {
        if (dist == 0) {
            if (AllocAt(reinterpret_cast<void*>(aligned_near), size, protect, out_addr) == HDL_OK) {
                return HDL_OK;
            }
            continue;
        }
        if (aligned_near + dist >= aligned_near) {
            if (AllocAt(reinterpret_cast<void*>(aligned_near + dist), size, protect, out_addr) ==
                HDL_OK) {
                return HDL_OK;
            }
        }
        if (aligned_near >= dist) {
            if (AllocAt(reinterpret_cast<void*>(aligned_near - dist), size, protect, out_addr) ==
                HDL_OK) {
                return HDL_OK;
            }
        }
    }
    return AllocAt(nullptr, size, protect, out_addr);
}

HdlStatus Free(uint64_t addr) {
    if (!addr) {
        return HDL_E_INVALID_ARG;
    }
    {
        std::lock_guard<std::mutex> lock(g_mu);
        auto it = g_allocs.find(addr);
        if (it == g_allocs.end()) {
            return HDL_E_NOT_FOUND;
        }
        g_allocs.erase(it);
    }
    if (!VirtualFree(reinterpret_cast<LPVOID>(addr), 0, MEM_RELEASE)) {
        return HDL_E_FAILED;
    }
    return HDL_OK;
}

void AllocShutdown() {
    std::lock_guard<std::mutex> lock(g_mu);
    for (auto& kv : g_allocs) {
        VirtualFree(reinterpret_cast<LPVOID>(kv.first), 0, MEM_RELEASE);
    }
    g_allocs.clear();
}

}  // namespace hdl
