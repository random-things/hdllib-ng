#include "inject/pe_image_view.hpp"
#include "inject/pe_relocs.hpp"
#include "ipc/wire.hpp"
#include "protocol.hpp"
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
    using namespace hdl::proto;
    HdlRegionInfo in{};
    in.base = 0x1000;
    in.size = 0x2000;
    in.protect = 0x40;
    in.state = 0x1000;
    in.type = 0x20000;
    in.reserved = 7;
    std::vector<uint8_t> buf;
    AppendHdlRegionInfo(buf, in);
    Reader r(buf);
    HdlRegionInfo out{};
    Expect(TakeHdlRegionInfo(r, out) && r.left == 0, "wire/region_take");
    Expect(out.base == in.base && out.size == in.size && out.protect == in.protect &&
               out.state == in.state && out.type == in.type && out.reserved == in.reserved,
           "wire/region_roundtrip");

    HdlModuleInfo min{};
    min.base = 0x7ff00000;
    min.size = 0x10000;
    wcsncpy_s(min.path, L"C:\\Windows\\System32\\ntdll.dll", _TRUNCATE);
    buf.clear();
    AppendHdlModuleInfo(buf, min);
    Reader mr(buf);
    HdlModuleInfo mout{};
    Expect(TakeHdlModuleInfo(mr, mout) && mr.left == 0, "wire/module_take");
    Expect(mout.base == min.base && mout.size == min.size && wcscmp(mout.path, min.path) == 0,
           "wire/module_roundtrip");

    HdlFieldPred pred{};
    pred.offset = 8;
    pred.kind = HDL_PRED_EQ_I32;
    pred.a = 0x1111;
    pred.b = 0x2222;
    buf.clear();
    AppendHdlFieldPred(buf, pred);
    Reader pr(buf);
    HdlFieldPred pout{};
    Expect(TakeHdlFieldPred(pr, pout) && pr.left == 0, "wire/field_pred_take");
    Expect(pout.offset == pred.offset && pout.kind == pred.kind && pout.a == pred.a &&
               pout.b == pred.b,
           "wire/field_pred_roundtrip");

    HdlPointerPath path{};
    path.static_base = 0x7ff00000;
    path.depth = 2;
    path.offsets[0] = 0x10;
    path.offsets[1] = -4;
    buf.clear();
    AppendHdlPointerPath(buf, path);
    Reader path_r(buf);
    HdlPointerPath path_out{};
    Expect(TakeHdlPointerPath(path_r, path_out) && path_r.left == 0, "wire/pointer_path_take");
    Expect(path_out.static_base == path.static_base && path_out.depth == path.depth &&
               path_out.offsets[0] == path.offsets[0] && path_out.offsets[1] == path.offsets[1],
           "wire/pointer_path_roundtrip");

    Expect(hdl::rpc::kProtocolMajor == 1, "wire/proto_major_is_1");
    Expect(hdl::rpc::kProtocolMajor != 99, "wire/forced_mismatch_constant");
}

} // namespace

int main() {
    TestMalformedPe();
    TestMalformedRelocs();
    TestWireRoundTrip();
    std::printf("pe_image_test failed=%d\n", g_failed);
    return g_failed == 0 ? 0 : 1;
}
