#pragma once

#include "inject/pe_image_view.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>

namespace hdl {
namespace inject {

/* Walk IMAGE_DIRECTORY_ENTRY_BASERELOC. Fail-closed on truncated/malformed blocks
 * (SizeOfBlock too small, past remaining directory size, or not mapped in the file).
 * Returns false if the directory is missing/empty, malformed, or on_entry fails. */
bool WalkBaseRelocDirectory(const PeImageView& pe,
                            const std::function<bool(uint32_t rva, uint16_t type)>& on_entry);

/* Apply DIR64 base relocations into a local image buffer of at least SizeOfImage
 * bytes. Fail-closed on a malformed reloc directory. delta == 0 => success. */
bool ApplyRelocations(uint8_t* image, size_t image_bytes, const PeImageView& pe, uint64_t delta);

} // namespace inject
} // namespace hdl
