#include "inject/pe_image_view.hpp"

#include <algorithm>
#include <cstring>

namespace hdl {
namespace inject {
namespace {

bool Fits(size_t size, size_t offset, size_t need) {
    return need <= size && offset <= size - need;
}

} // namespace

bool PeImageView::TryOpen(std::span<const uint8_t> file, PeImageView* out) {
    if (!out || file.size() < sizeof(IMAGE_DOS_HEADER) || file.size() > kMaxImageBytes) {
        return false;
    }
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(file.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0) {
        return false;
    }
    const size_t nt_off = static_cast<size_t>(dos->e_lfanew);
    if (!Fits(file.size(), nt_off, sizeof(IMAGE_NT_HEADERS64))) {
        return false;
    }
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(file.data() + nt_off);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        return false;
    }
    if (nt->FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64)) {
        return false;
    }
    const uint16_t nsec = nt->FileHeader.NumberOfSections;
    if (nsec == 0 || nsec > kMaxSections) {
        return false;
    }
    const size_t sec_off =
        nt_off + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) + nt->FileHeader.SizeOfOptionalHeader;
    const size_t sec_bytes = static_cast<size_t>(nsec) * sizeof(IMAGE_SECTION_HEADER);
    if (!Fits(file.size(), sec_off, sec_bytes)) {
        return false;
    }
    const uint32_t size_of_headers = nt->OptionalHeader.SizeOfHeaders;
    const uint32_t size_of_image = nt->OptionalHeader.SizeOfImage;
    if (size_of_headers == 0 || size_of_headers > file.size() || size_of_image == 0 ||
        size_of_image > kMaxImageBytes) {
        return false;
    }
    /* Non-zero EP must address a byte inside the image (reject one-past-end). */
    if (nt->OptionalHeader.AddressOfEntryPoint != 0 &&
        nt->OptionalHeader.AddressOfEntryPoint >= size_of_image) {
        return false;
    }

    const auto* sec = reinterpret_cast<const IMAGE_SECTION_HEADER*>(file.data() + sec_off);
    for (uint16_t i = 0; i < nsec; ++i, ++sec) {
        if (sec->SizeOfRawData == 0) {
            continue;
        }
        const uint64_t end = static_cast<uint64_t>(sec->PointerToRawData) + sec->SizeOfRawData;
        if (end > file.size()) {
            return false;
        }
        const uint64_t va_end = static_cast<uint64_t>(sec->VirtualAddress) +
                                (std::max)(sec->Misc.VirtualSize, sec->SizeOfRawData);
        if (va_end > size_of_image) {
            return false;
        }
    }

    out->data_ = file.data();
    out->size_ = file.size();
    out->nt_offset_ = nt_off;
    out->sections_offset_ = sec_off;
    out->section_count_ = nsec;
    return true;
}

const IMAGE_DOS_HEADER* PeImageView::dos() const {
    return reinterpret_cast<const IMAGE_DOS_HEADER*>(data_);
}

const IMAGE_NT_HEADERS64* PeImageView::nt() const {
    if (!data_ || !ContainsFileRange(nt_offset_, sizeof(IMAGE_NT_HEADERS64))) {
        return nullptr;
    }
    return reinterpret_cast<const IMAGE_NT_HEADERS64*>(data_ + nt_offset_);
}

uint16_t PeImageView::number_of_sections() const {
    return section_count_;
}

const IMAGE_SECTION_HEADER* PeImageView::section(uint16_t index) const {
    if (index >= section_count_) {
        return nullptr;
    }
    if (!data_ || !ContainsFileRange(nt_offset_, sizeof(IMAGE_NT_HEADERS64))) {
        return nullptr;
    }
    return reinterpret_cast<const IMAGE_SECTION_HEADER*>(data_ + sections_offset_) + index;
}

bool PeImageView::ContainsFileRange(size_t offset, size_t need) const {
    return Fits(size_, offset, need);
}

bool PeImageView::VaInImage(uint32_t rva, size_t need) const {
    const auto* headers = nt();
    if (!headers) {
        return false;
    }
    const uint64_t end = static_cast<uint64_t>(rva) + need;
    return end >= rva && end <= headers->OptionalHeader.SizeOfImage;
}

bool PeImageView::RvaToOffset(uint32_t rva, size_t need, size_t* out_offset) const {
    const auto* headers = nt();
    if (!out_offset || !headers || !VaInImage(rva, need ? need : 1)) {
        return false;
    }
    for (uint16_t i = 0; i < section_count_; ++i) {
        const auto* sec = section(i);
        if (!sec) {
            return false;
        }
        const uint32_t vsize = (std::max)(sec->Misc.VirtualSize, sec->SizeOfRawData);
        if (rva < sec->VirtualAddress || rva >= sec->VirtualAddress + vsize) {
            continue;
        }
        const uint32_t delta = rva - sec->VirtualAddress;
        if (delta > sec->SizeOfRawData) {
            return false;
        }
        const size_t off = static_cast<size_t>(sec->PointerToRawData) + delta;
        if (!ContainsFileRange(off, need)) {
            return false;
        }
        *out_offset = off;
        return true;
    }
    /* Headers / non-section RVA */
    if (rva < headers->OptionalHeader.SizeOfHeaders) {
        if (!ContainsFileRange(rva, need)) {
            return false;
        }
        *out_offset = rva;
        return true;
    }
    return false;
}

const uint8_t* PeImageView::SliceRva(uint32_t rva, size_t need) const {
    size_t off = 0;
    if (!RvaToOffset(rva, need, &off)) {
        return nullptr;
    }
    return data_ + off;
}

} // namespace inject
} // namespace hdl
