#include "inject/pe_image_view.hpp"
#include "inject/pe_relocs.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    hdl::inject::PeImageView pe;
    if (!hdl::inject::PeImageView::TryOpen(std::span<const uint8_t>(data, size), &pe)) {
        return 0;
    }

    for (uint16_t index = 0; index < pe.number_of_sections(); ++index) {
        (void)pe.section(index);
    }
    (void)hdl::inject::WalkBaseRelocDirectory(
        pe, [&pe](uint32_t rva, uint16_t) { return pe.VaInImage(rva, 1); });
    return 0;
}
