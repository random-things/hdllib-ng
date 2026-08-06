#include "hdl/rpc/v1/types.pb.h"
#include "inject/pe_image_view.hpp"
#include "inject/pe_relocs.hpp"
#include "rpc/runtime.hpp"

#include "hdllib/hdllib.h"

#include <cstdio>
#include <cstring>
#include <span>
#include <vector>

namespace {

int g_failed = 0;

void Expect(bool ok, const char* name) {
    if (ok) {
        std::printf("PASS %s\n", name);
    } else {
        std::printf("FAIL %s\n", name);
        ++g_failed;
    }
}

void TestMalformedPe() {
    using hdl::inject::PeImageView;
    PeImageView unset;
    Expect(!unset.VaInImage(0, 1), "pe/default_vainimage");
    Expect(unset.nt() == nullptr, "pe/default_nt_null");
    size_t off = 1;
    Expect(!unset.RvaToOffset(0, 1, &off), "pe/default_rva_to_offset");

    std::vector<uint8_t> empty;
    PeImageView pe;
    Expect(!PeImageView::TryOpen(empty, &pe), "pe/empty");

    std::vector<uint8_t> tiny(64, 0);
    Expect(!PeImageView::TryOpen(tiny, &pe), "pe/no_dos");

    IMAGE_DOS_HEADER dos{};
    dos.e_magic = IMAGE_DOS_SIGNATURE;
    dos.e_lfanew = 0x7fffffff;
    std::vector<uint8_t> bad_lfanew(sizeof(dos));
    std::memcpy(bad_lfanew.data(), &dos, sizeof(dos));
    Expect(!PeImageView::TryOpen(bad_lfanew, &pe), "pe/huge_e_lfanew");

    /* Minimal valid-looking headers with section past EOF. */
    std::vector<uint8_t> buf(0x400, 0);
    auto* d = reinterpret_cast<IMAGE_DOS_HEADER*>(buf.data());
    d->e_magic = IMAGE_DOS_SIGNATURE;
    d->e_lfanew = 0x80;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(buf.data() + 0x80);
    nt->Signature = IMAGE_NT_SIGNATURE;
    nt->FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    nt->FileHeader.NumberOfSections = 1;
    nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt->OptionalHeader.SizeOfHeaders = 0x200;
    nt->OptionalHeader.SizeOfImage = 0x2000;
    nt->OptionalHeader.AddressOfEntryPoint = 0x2000; /* one-past-end */
    auto* sec = IMAGE_FIRST_SECTION(nt);
    sec->VirtualAddress = 0x1000;
    sec->Misc.VirtualSize = 0x1000;
    sec->PointerToRawData = 0x200;
    sec->SizeOfRawData = 0x100; /* fits in file */
    Expect(!PeImageView::TryOpen(buf, &pe), "pe/ep_one_past_end");

    nt->OptionalHeader.AddressOfEntryPoint = 0x100; /* inside image */
    sec->PointerToRawData = 0x300;
    sec->SizeOfRawData = 0x200; /* 0x300+0x200 > 0x400 */
    Expect(!PeImageView::TryOpen(buf, &pe), "pe/section_past_eof");
}

/* Minimal PE that TryOpen accepts, with .reloc payload at file offset 0x200 / RVA 0x1000. */
std::vector<uint8_t> MakePeWithRelocBytes(const uint8_t* reloc, size_t reloc_len,
                                          uint32_t reloc_dir_size) {
    std::vector<uint8_t> buf(0x400, 0);
    auto* d = reinterpret_cast<IMAGE_DOS_HEADER*>(buf.data());
    d->e_magic = IMAGE_DOS_SIGNATURE;
    d->e_lfanew = 0x80;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(buf.data() + 0x80);
    nt->Signature = IMAGE_NT_SIGNATURE;
    nt->FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    nt->FileHeader.NumberOfSections = 1;
    nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt->OptionalHeader.SizeOfHeaders = 0x200;
    nt->OptionalHeader.SizeOfImage = 0x2000;
    nt->OptionalHeader.AddressOfEntryPoint = 0x1000;
    nt->OptionalHeader.ImageBase = 0x140000000ull;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0x1000;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = reloc_dir_size;
    auto* sec = IMAGE_FIRST_SECTION(nt);
    sec->VirtualAddress = 0x1000;
    sec->Misc.VirtualSize = 0x1000;
    sec->PointerToRawData = 0x200;
    sec->SizeOfRawData = 0x200;
    if (reloc && reloc_len) {
        std::memcpy(buf.data() + 0x200, reloc, reloc_len);
    }
    return buf;
}

void TestMalformedRelocs() {
    using hdl::inject::ApplyRelocations;
    using hdl::inject::PeImageView;
    using hdl::inject::WalkBaseRelocDirectory;

    /* SizeOfBlock smaller than the reloc header — fail closed. */
    {
        uint8_t reloc[8]{};
        auto* block = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reloc);
        block->VirtualAddress = 0x1000;
        block->SizeOfBlock = 4;
        auto buf = MakePeWithRelocBytes(reloc, sizeof(reloc), 8);
        PeImageView pe;
        Expect(PeImageView::TryOpen(buf, &pe), "pe/reloc_tiny_block_open");
        std::vector<uint8_t> image(pe.nt()->OptionalHeader.SizeOfImage, 0);
        Expect(!ApplyRelocations(image.data(), image.size(), pe, 0x1000),
               "pe/reloc_tiny_block_apply");
        Expect(!WalkBaseRelocDirectory(pe, [](uint32_t, uint16_t) { return true; }),
               "pe/reloc_tiny_block_walk");
    }

    /* SizeOfBlock claims more bytes than remain in the reloc directory. */
    {
        uint8_t reloc[16]{};
        auto* block = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reloc);
        block->VirtualAddress = 0x1000;
        block->SizeOfBlock = 0x100; /* dir.Size is only 16 */
        auto buf = MakePeWithRelocBytes(reloc, sizeof(reloc), 16);
        PeImageView pe;
        Expect(PeImageView::TryOpen(buf, &pe), "pe/reloc_oversize_block_open");
        std::vector<uint8_t> image(pe.nt()->OptionalHeader.SizeOfImage, 0);
        Expect(!ApplyRelocations(image.data(), image.size(), pe, 0x1000),
               "pe/reloc_oversize_block_apply");
    }

    /* Directory size claims a second block that is truncated (header incomplete). */
    {
        uint8_t reloc[12]{};
        auto* block = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reloc);
        block->VirtualAddress = 0x1000;
        block->SizeOfBlock = 8; /* empty first block */
        /* bytes 8..11 are only half of the next IMAGE_BASE_RELOCATION */
        auto buf = MakePeWithRelocBytes(reloc, sizeof(reloc), 12);
        PeImageView pe;
        Expect(PeImageView::TryOpen(buf, &pe), "pe/reloc_truncated_next_open");
        std::vector<uint8_t> image(pe.nt()->OptionalHeader.SizeOfImage, 0);
        Expect(!ApplyRelocations(image.data(), image.size(), pe, 0x1000),
               "pe/reloc_truncated_next_apply");
    }

    /* Well-formed single DIR64 reloc patches the local image. */
    {
        uint8_t reloc[12]{};
        auto* block = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reloc);
        block->VirtualAddress = 0x1000;
        block->SizeOfBlock = 12;
        auto* entry = reinterpret_cast<uint16_t*>(reloc + 8);
        *entry = static_cast<uint16_t>((IMAGE_REL_BASED_DIR64 << 12) | 0);
        auto buf = MakePeWithRelocBytes(reloc, sizeof(reloc), 12);
        PeImageView pe;
        Expect(PeImageView::TryOpen(buf, &pe), "pe/reloc_ok_open");
        std::vector<uint8_t> image(pe.nt()->OptionalHeader.SizeOfImage, 0);
        auto* slot = reinterpret_cast<uint64_t*>(image.data() + 0x1000);
        *slot = 0x140001000ull;
        Expect(ApplyRelocations(image.data(), image.size(), pe, 0x1000), "pe/reloc_ok_apply");
        Expect(*slot == 0x140002000ull, "pe/reloc_ok_value");
    }
}

void TestWireRoundTrip() {
    hdl::rpc::v1::RegionInfo region;
    region.set_base(0x1000);
    region.set_size(0x2000);
    region.set_protection(0x40);
    region.set_state(0x1000);
    region.set_type(0x20000);
    std::string bytes;
    Expect(region.SerializeToString(&bytes), "proto/region_serialize");
    hdl::rpc::v1::RegionInfo region_out;
    Expect(region_out.ParseFromString(bytes), "proto/region_parse");
    Expect(region_out.base() == region.base() && region_out.size() == region.size() &&
               region_out.protection() == region.protection() &&
               region_out.state() == region.state() && region_out.type() == region.type(),
           "proto/region_roundtrip");

    hdl::rpc::v1::ModuleInfo module;
    module.set_base(0x7ff00000);
    module.set_size(0x10000);
    module.set_path("C:\\Windows\\System32\\ntdll.dll");
    Expect(module.SerializeToString(&bytes), "proto/module_serialize");
    hdl::rpc::v1::ModuleInfo module_out;
    Expect(module_out.ParseFromString(bytes) && module_out.path() == module.path(),
           "proto/module_roundtrip");

    hdl::rpc::v1::FieldPredicate predicate;
    predicate.set_offset(8);
    predicate.mutable_range_i32()->set_minimum(0x1111);
    predicate.mutable_range_i32()->set_maximum(0x2222);
    Expect(predicate.SerializeToString(&bytes), "proto/predicate_serialize");
    hdl::rpc::v1::FieldPredicate predicate_out;
    Expect(predicate_out.ParseFromString(bytes) && predicate_out.has_range_i32() &&
               predicate_out.range_i32().maximum() == 0x2222,
           "proto/predicate_roundtrip");

    hdl::rpc::v1::PointerPath path;
    path.set_static_base(0x7ff00000);
    path.add_offsets(0x10);
    path.add_offsets(-4);
    Expect(path.SerializeToString(&bytes), "proto/path_serialize");
    hdl::rpc::v1::PointerPath path_out;
    Expect(path_out.ParseFromString(bytes) && path_out.static_base() == path.static_base() &&
               path_out.offsets_size() == 2 && path_out.offsets(1) == -4,
           "proto/path_roundtrip");
    Expect(hdl::rpc::kProtocolMajor == 1, "proto/major_is_1");
}

} // namespace

int main() {
    TestMalformedPe();
    TestMalformedRelocs();
    TestWireRoundTrip();
    std::printf("pe_image_test failed=%d\n", g_failed);
    return g_failed == 0 ? 0 : 1;
}
