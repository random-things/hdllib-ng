#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

namespace hdl {
namespace inject {

/* Bounds-checked view over a PE file image in memory. Fail-closed on malformed input. */
class PeImageView {
  public:
    static constexpr size_t kMaxImageBytes = 256u * 1024u * 1024u;
    static constexpr size_t kMaxSections = 96;

    static bool TryOpen(std::span<const uint8_t> file, PeImageView* out);

    const uint8_t* data() const { return data_; }
    size_t size() const { return size_; }

    const IMAGE_DOS_HEADER* dos() const;
    const IMAGE_NT_HEADERS64* nt() const;
    uint16_t number_of_sections() const;
    const IMAGE_SECTION_HEADER* section(uint16_t index) const;

    /* Map RVA to file offset; require `need` bytes available. */
    bool RvaToOffset(uint32_t rva, size_t need, size_t* out_offset) const;
    const uint8_t* SliceRva(uint32_t rva, size_t need) const;
    bool ContainsFileRange(size_t offset, size_t need) const;
    bool VaInImage(uint32_t rva, size_t need) const;

  private:
    const uint8_t* data_ = nullptr;
    size_t size_ = 0;
    size_t nt_offset_ = 0;
    size_t sections_offset_ = 0;
    uint16_t section_count_ = 0;
};

} // namespace inject
} // namespace hdl
