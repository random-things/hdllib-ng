#include "inject/pe_relocs.hpp"

namespace hdl {
namespace inject {

bool WalkBaseRelocDirectory(
    const PeImageView& pe,
    const std::function<bool(uint32_t rva, uint16_t type)>& on_entry) {
    if (!on_entry) {
        return false;
    }
    const auto* nt = pe.nt();
    if (!nt) {
        return false;
    }
    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (!dir.VirtualAddress || !dir.Size) {
        return false;
    }

    uint32_t offset = 0;
    while (offset < dir.Size) {
        const auto* block = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(
            pe.SliceRva(dir.VirtualAddress + offset, sizeof(IMAGE_BASE_RELOCATION)));
        if (!block || block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) ||
            block->SizeOfBlock > dir.Size - offset) {
            return false;
        }
        if (!pe.SliceRva(dir.VirtualAddress + offset, block->SizeOfBlock)) {
            return false;
        }
        const DWORD count =
            (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
        const auto* entries = reinterpret_cast<const uint16_t*>(block + 1);
        for (DWORD i = 0; i < count; ++i) {
            const uint16_t type = entries[i] >> 12;
            const uint16_t off = entries[i] & 0x0FFF;
            if (!on_entry(block->VirtualAddress + off, type)) {
                return false;
            }
        }
        offset += block->SizeOfBlock;
    }
    return true;
}

bool ApplyRelocations(uint8_t* image, size_t image_bytes, const PeImageView& pe, uint64_t delta) {
    if (delta == 0) {
        return true;
    }
    const auto* nt = pe.nt();
    if (!image || !nt || image_bytes < nt->OptionalHeader.SizeOfImage) {
        return false;
    }
    return WalkBaseRelocDirectory(pe, [&](uint32_t rva, uint16_t type) {
        if (type == IMAGE_REL_BASED_DIR64) {
            if (!pe.VaInImage(rva, sizeof(uint64_t))) {
                return false;
            }
            auto* slot = reinterpret_cast<uint64_t*>(image + rva);
            *slot += delta;
            return true;
        }
        if (type == IMAGE_REL_BASED_ABSOLUTE || type == 0) {
            return true;
        }
        return false;
    });
}

}  // namespace inject
}  // namespace hdl
