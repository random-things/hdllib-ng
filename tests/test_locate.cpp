#include "domain_api.hpp"
#include "ipc/wire.hpp"
#include "protocol.hpp"
#include "support.hpp"
#include "test_runners.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using hdltest::Counters;
using hdltest::IlLevel;
using hdltest::Report;
using hdltest::TargetProc;
using hdltest::TargetProfile;

void RunLocateTargetTests(Counters& c, const wchar_t* target_path, const wchar_t* dll_path) {
    using namespace hdl::proto;
    std::printf("\n== Locate (inject into hdl_test_target) ==\n");

    TargetProfile profile{};
    profile.name = "locate_fixtures";
    profile.window = false;
    profile.alertable = true;
    profile.integrity = IlLevel::Medium;

    TargetProc target;
    if (!hdltest::SpawnTarget(target_path, profile, target)) {
        Report(c, false, false, "locate spawn target", "");
        return;
    }

    uint64_t base = 0;
    const HdlStatus ist = hdl::InjectDllEx(target.pid, dll_path, HDL_INJECT_CREATE_REMOTE_THREAD,
                                           nullptr, nullptr, nullptr, &base);
    const bool verified =
        ist == HDL_OK &&
        hdltest::VerifyInjected(target.pid, dll_path, HDL_INJECT_CREATE_REMOTE_THREAD, base);
    Report(c, verified, false, "locate inject", "");
    if (!verified) {
        return;
    }

    auto resolve_export = [&](const char* name, uint64_t* out) -> bool {
        std::vector<uint8_t> req;
        std::vector<uint8_t> resp;
        AppendPod(req, static_cast<uint32_t>(OpResolveExport));
        AppendWString(req, L"");
        AppendString(req, name);
        if (!hdltest::PipeRequest(target.pid, req, resp)) {
            return false;
        }
        Reader r(resp);
        int32_t st = 0;
        uint64_t addr = 0;
        if (!r.TakePod(st) || !r.TakePod(addr) || st != HDL_OK || !addr) {
            return false;
        }
        *out = addr;
        return true;
    };

    uint64_t truth_fn = 0;
    uint64_t truth_str = 0;
    uint64_t truth_leaf = 0;
    uint64_t truth_root = 0;
    uint64_t truth_obj = 0;
    uint64_t truth_str_ptr = 0;
    Report(c, resolve_export("HdlTestLocateFn", &truth_fn), false, "locate truth Fn export", "");
    Report(c, resolve_export("HdlTestLocateString", &truth_str), false,
           "locate truth String export", "");
    Report(c, resolve_export("HdlTestLocateLeaf", &truth_leaf), false, "locate truth Leaf export",
           "");
    Report(c, resolve_export("HdlTestLocateRoot", &truth_root), false, "locate truth Root export",
           "");
    Report(c, resolve_export("HdlTestLocateObj", &truth_obj), false, "locate truth Obj export", "");
    Report(c, resolve_export("HdlTestLocateStringPtr", &truth_str_ptr), false,
           "locate truth StringPtr export", "");

    /* Module-scoped AOB for HDL1 immediate */
    {
        std::vector<uint8_t> req;
        std::vector<uint8_t> resp;
        AppendPod(req, static_cast<uint32_t>(OpResolvePattern));
        AppendString(req, "31 4C 44 48");
        AppendPod(req, static_cast<uint32_t>(0));
        AppendPod(req, static_cast<int32_t>(0));
        AppendPod(req, static_cast<uint32_t>(0));
        AppendPod(req, static_cast<uint32_t>(0));
        AppendPod(req, static_cast<uint32_t>(0));
        AppendPod(req, static_cast<uint32_t>(HDL_SEARCH_MODULE | HDL_SEARCH_IMAGE));
        AppendPod(req, static_cast<uint32_t>(64));
        AppendWString(req, L"hdl_test_target.exe");
        if (!hdltest::PipeRequest(target.pid, req, resp)) {
            Report(c, false, false, "locate ResolvePattern ipc", "");
        } else {
            Reader r(resp);
            int32_t st = 0;
            HdlPatternResult out{};
            const bool ok =
                r.TakePod(st) && hdl::proto::TakeHdlPatternResult(r, out) && st == HDL_OK;
            const bool match_near_fn =
                ok && truth_fn && out.match_addr >= truth_fn && out.match_addr < truth_fn + 0x80;
            Report(c, match_near_fn, false, "locate ResolvePattern near Fn", "");
        }
    }

    /* Absolute xref to string */
    {
        std::vector<uint8_t> req;
        std::vector<uint8_t> resp;
        const char* s = "HDL_LOCATE_STRING_v1";
        AppendPod(req, static_cast<uint32_t>(OpFindStringXrefs));
        AppendPod(req, static_cast<uint32_t>(strlen(s)));
        AppendPod(req, static_cast<int32_t>(0));
        AppendPod(req, static_cast<uint32_t>(HDL_XREF_ABSOLUTE));
        AppendPod(req, static_cast<uint32_t>(HDL_SEARCH_MODULE | HDL_SEARCH_IMAGE));
        AppendPod(req, static_cast<uint32_t>(64));
        AppendWString(req, L"hdl_test_target.exe");
        AppendBytes(req, s, strlen(s));
        if (!hdltest::PipeRequest(target.pid, req, resp)) {
            Report(c, false, false, "locate xrefs absolute ipc", "");
        } else {
            Reader r(resp);
            int32_t st = 0;
            uint32_t count = 0;
            bool found = false;
            if (r.TakePod(st) && r.TakePod(count) && st == HDL_OK) {
                for (uint32_t i = 0; i < count; ++i) {
                    uint64_t a = 0;
                    if (!r.TakePod(a)) {
                        break;
                    }
                    if (truth_str_ptr && a == truth_str_ptr) {
                        found = true;
                    }
                }
            }
            Report(c, found, false, "locate xrefs absolute hits StringPtr", "");
        }
    }

    /* RIP xref */
    {
        std::vector<uint8_t> req;
        std::vector<uint8_t> resp;
        const char* s = "HDL_LOCATE_STRING_v1";
        AppendPod(req, static_cast<uint32_t>(OpFindStringXrefs));
        AppendPod(req, static_cast<uint32_t>(strlen(s)));
        AppendPod(req, static_cast<int32_t>(0));
        AppendPod(req, static_cast<uint32_t>(HDL_XREF_RIP_REL));
        AppendPod(req, static_cast<uint32_t>(HDL_SEARCH_MODULE | HDL_SEARCH_IMAGE));
        AppendPod(req, static_cast<uint32_t>(256));
        AppendWString(req, L"hdl_test_target.exe");
        AppendBytes(req, s, strlen(s));
        if (!hdltest::PipeRequest(target.pid, req, resp)) {
            Report(c, false, false, "locate xrefs rip ipc", "");
        } else {
            Reader r(resp);
            int32_t st = 0;
            uint32_t count = 0;
            const bool ok = r.TakePod(st) && r.TakePod(count) && st == HDL_OK && count >= 1;
            Report(c, ok, false, "locate xrefs rip count", "");
        }
    }

    /* Pointer scan from leaf */
    {
        std::vector<uint8_t> req;
        std::vector<uint8_t> resp;
        AppendPod(req, static_cast<uint32_t>(OpPointerScan));
        AppendPod(req, truth_leaf);
        AppendPod(req, static_cast<uint32_t>(2));
        AppendPod(req, static_cast<uint32_t>(0x100));
        AppendPod(req, static_cast<uint32_t>(64));
        AppendPod(req, static_cast<uint32_t>(HDL_SEARCH_MODULE | HDL_SEARCH_IMAGE));
        AppendWString(req, L"hdl_test_target.exe");
        if (!hdltest::PipeRequest(target.pid, req, resp)) {
            Report(c, false, false, "locate ptrscan ipc", "");
        } else {
            Reader r(resp);
            int32_t st = 0;
            uint32_t count = 0;
            bool found_root = false;
            bool decoded = r.TakePod(st) && r.TakePod(count) && st == HDL_OK && count >= 1;
            if (decoded) {
                for (uint32_t i = 0; i < count; ++i) {
                    HdlPointerPath path{};
                    if (!hdl::proto::TakeHdlPointerPath(r, path)) {
                        decoded = false;
                        found_root = false;
                        break;
                    }
                    /* depth-1 path with offset 0 at g_locate_mid location, or root */
                    if (path.depth >= 1 && path.offsets[path.depth - 1] == 0) {
                        found_root = true;
                    }
                }
            }
            Report(c, decoded && found_root, false, "locate ptrscan finds path", "");
        }
    }

    /* Struct probe on LocateObj */
    {
        std::vector<uint8_t> req;
        std::vector<uint8_t> resp;
        AppendPod(req, static_cast<uint32_t>(OpProbeStruct));
        AppendPod(req, truth_obj);
        AppendPod(req, static_cast<uint32_t>(40));
        AppendPod(req, static_cast<uint32_t>(16));
        if (!hdltest::PipeRequest(target.pid, req, resp)) {
            Report(c, false, false, "locate probe ipc", "");
        } else {
            Reader r(resp);
            int32_t st = 0;
            uint32_t count = 0;
            bool has_vt = false;
            if (r.TakePod(st) && r.TakePod(count) && st == HDL_OK && count >= 1) {
                for (uint32_t i = 0; i < count; ++i) {
                    HdlStructField f{};
                    if (!hdl::proto::TakeHdlStructField(r, f)) {
                        break;
                    }
                    if (f.offset == 0 && (f.kind == HDL_FIELD_VTABLE || f.kind == HDL_FIELD_PTR)) {
                        has_vt = true;
                    }
                }
            }
            Report(c, has_vt, false, "locate probe vtable field", "");
        }
    }

    /* FollowPointers: *HdlTestLocateStringPtr (+0) => string address */
    {
        std::vector<uint8_t> req;
        std::vector<uint8_t> resp;
        AppendPod(req, static_cast<uint32_t>(OpFollowPointers));
        AppendPod(req, truth_str_ptr);
        AppendPod(req, static_cast<uint32_t>(1));
        AppendPod(req, static_cast<int64_t>(0));
        if (!hdltest::PipeRequest(target.pid, req, resp)) {
            Report(c, false, false, "locate follow ipc", "");
        } else {
            Reader r(resp);
            int32_t st = 0;
            uint64_t out = 0;
            const bool ok = r.TakePod(st) && r.TakePod(out) && st == HDL_OK && out == truth_str;
            Report(c, ok, false, "locate FollowPointers StringPtr", "");
        }
    }

    /* Two-level: *Root (+0) => &mid, *mid (+0) => &leaf */
    {
        std::vector<uint8_t> req;
        std::vector<uint8_t> resp;
        AppendPod(req, static_cast<uint32_t>(OpFollowPointers));
        AppendPod(req, truth_root);
        AppendPod(req, static_cast<uint32_t>(2));
        AppendPod(req, static_cast<int64_t>(0));
        AppendPod(req, static_cast<int64_t>(0));
        if (!hdltest::PipeRequest(target.pid, req, resp)) {
            Report(c, false, false, "locate follow root ipc", "");
        } else {
            Reader r(resp);
            int32_t st = 0;
            uint64_t out = 0;
            const bool ok = r.TakePod(st) && r.TakePod(out) && st == HDL_OK && out == truth_leaf;
            Report(c, ok, false, "locate FollowPointers Root to leaf", "");
        }
    }
}
