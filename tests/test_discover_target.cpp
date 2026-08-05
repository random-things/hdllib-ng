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

void RunDiscoverTargetTests(Counters& c, const wchar_t* target_path, const wchar_t* dll_path) {
    using namespace hdl::proto;
    std::printf("\n== Discover (inject into hdl_test_target) ==\n");

    TargetProfile profile{};
    profile.name = "discover_fixtures";
    profile.window = false;
    profile.alertable = true;
    profile.integrity = IlLevel::Medium;

    TargetProc target;
    if (!hdltest::SpawnTarget(target_path, profile, target)) {
        Report(c, false, false, "discover spawn target", "");
        return;
    }

    uint64_t base = 0;
    const HdlStatus ist = hdl::InjectDllEx(target.pid, dll_path, HDL_INJECT_CREATE_REMOTE_THREAD,
                                           nullptr, nullptr, nullptr, &base);
    const bool verified =
        ist == HDL_OK &&
        hdltest::VerifyInjected(target.pid, dll_path, HDL_INJECT_CREATE_REMOTE_THREAD, base);
    Report(c, verified, false, "discover inject", "");
    if (!verified) {
        return;
    }

    auto resolve_export = [&](const char* name, uint64_t* out) -> bool {
        PreparedRequest req;
        std::vector<uint8_t> resp;
        SetMethod(req, hdl::rpc::Method::ResolveExport);
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

    auto call_export = [&](const char* name, const HdlCallArg* args, uint32_t argc) -> bool {
        PreparedRequest req;
        std::vector<uint8_t> resp;
        SetMethod(req, hdl::rpc::Method::CallExport);
        AppendWString(req, L"");
        AppendString(req, name);
        AppendPod(req, argc);
        AppendPod(req, static_cast<uint32_t>(5000));
        AppendPod(req, static_cast<uint64_t>(0));
        for (uint32_t i = 0; i < argc; ++i) {
            AppendPod(req, args[i].kind);
            AppendPod(req, args[i].size);
            AppendPod(req, args[i].u64);
            /* PTR/BUF not used here */
        }
        if (!hdltest::PipeRequest(target.pid, req, resp)) {
            return false;
        }
        Reader r(resp);
        int32_t st = 0;
        return r.TakePod(st) && st == HDL_OK;
    };

    uint64_t truth_leaf = 0;
    uint64_t truth_action = 0;
    uint64_t truth_obj_a = 0;
    uint64_t truth_obj_b = 0;
    uint64_t truth_dyn_root = 0;
    Report(c, resolve_export("HdlTestDiscoverLeaf", &truth_leaf), false, "discover truth Leaf", "");
    Report(c, resolve_export("HdlTestDiscoverAction", &truth_action), false,
           "discover truth Action", "");
    Report(c, resolve_export("HdlTestDiscoverObjA", &truth_obj_a), false, "discover truth ObjA",
           "");
    Report(c, resolve_export("HdlTestDiscoverObjB", &truth_obj_b), false, "discover truth ObjB",
           "");
    Report(c, resolve_export("HdlTestDiscoverDynRoot", &truth_dyn_root), false,
           "discover truth DynRoot", "");

    {
        PreparedRequest req;
        std::vector<uint8_t> resp;
        SetMethod(req, hdl::rpc::Method::EnumFunctions);
        AppendPod(req, 0ull);
        AppendPod(req, 0ull);
        AppendPod(req, HDL_SEARCH_MODULE);
        AppendPod(req, static_cast<uint32_t>(128));
        AppendWString(req, L"hdl_test_target.exe");
        bool saw_export = false;
        if (hdltest::PipeRequest(target.pid, req, resp)) {
            Reader r(resp);
            int32_t st = 0;
            uint32_t count = 0;
            if (r.TakePod(st) && r.TakePod(count) && st == HDL_OK) {
                for (uint32_t i = 0; i < count; ++i) {
                    HdlFunctionInfo fi{};
                    if (!hdl::proto::TakeHdlFunctionInfo(r, fi)) {
                        break;
                    }
                    if (truth_leaf && fi.start == truth_leaf && (fi.flags & HDL_FN_EXPORT) &&
                        fi.confidence >= 50) {
                        saw_export = true;
                    }
                }
            }
        }
        Report(c, saw_export, false, "discover EnumFunctions HdlTest export", "");
    }

    /* Create discover session */
    uint64_t disc_id = 0;
    {
        PreparedRequest req;
        std::vector<uint8_t> resp;
        SetMethod(req, hdl::rpc::Method::DiscoverCreate);
        if (!hdltest::PipeRequest(target.pid, req, resp)) {
            Report(c, false, false, "discover create ipc", "");
            return;
        }
        Reader r(resp);
        int32_t st = 0;
        const bool ok = r.TakePod(st) && r.TakePod(disc_id) && st == HDL_OK && disc_id != 0;
        Report(c, ok, false, "discover create", "");
        if (!ok) {
            return;
        }
    }

    /* Constraint scan for discover objs */
    {
        PreparedRequest req;
        std::vector<uint8_t> resp;
        HdlFieldPred preds[2]{};
        preds[0].offset = 8;
        preds[0].kind = HDL_PRED_RANGE_I32;
        preds[0].a = 1;
        preds[0].b = 100;
        preds[1].offset = 8;
        preds[1].kind = HDL_PRED_LE_I32;
        preds[1].a = 4;
        SetMethod(req, hdl::rpc::Method::DiscoverConstraintScan);
        AppendPod(req, disc_id);
        AppendPod(req, static_cast<uint32_t>(24)); /* sizeof approx */
        AppendPod(req, static_cast<uint32_t>(2));
        AppendPod(req, static_cast<uint32_t>(HDL_SEARCH_MODULE | HDL_SEARCH_IMAGE));
        AppendPod(req, static_cast<uint32_t>(64));
        AppendWString(req, L"hdl_test_target.exe");
        AppendString(req, "player");
        AppendBytes(req, preds, sizeof(preds));
        if (!hdltest::PipeRequest(target.pid, req, resp)) {
            Report(c, false, false, "discover constraint ipc", "");
        } else {
            Reader r(resp);
            int32_t st = 0;
            Report(c, r.TakePod(st) && st == HDL_OK, false, "discover constraint scan", "");
        }
    }

    /* Get candidates â€” expect ObjA/ObjB */
    {
        PreparedRequest req;
        std::vector<uint8_t> resp;
        SetMethod(req, hdl::rpc::Method::DiscoverGetCandidates);
        AppendPod(req, disc_id);
        AppendPod(req, static_cast<uint32_t>(128));
        if (!hdltest::PipeRequest(target.pid, req, resp)) {
            Report(c, false, false, "discover candidates ipc", "");
        } else {
            Reader r(resp);
            int32_t st = 0;
            uint32_t count = 0;
            bool found_a = false;
            bool found_b = false;
            if (r.TakePod(st) && r.TakePod(count) && st == HDL_OK) {
                for (uint32_t i = 0; i < count; ++i) {
                    HdlCandidate cand{};
                    if (!hdl::proto::TakeHdlCandidate(r, cand)) {
                        break;
                    }
                    if (cand.address == truth_obj_a) {
                        found_a = true;
                    }
                    if (cand.address == truth_obj_b) {
                        found_b = true;
                    }
                }
            }
            Report(c, found_a && found_b, false, "discover candidates include objs", "");
        }
    }

    /* Synthesize pattern for Leaf */
    {
        PreparedRequest req;
        std::vector<uint8_t> resp;
        SetMethod(req, hdl::rpc::Method::DiscoverAddCandidate);
        AppendPod(req, disc_id);
        AppendPod(req, static_cast<uint32_t>(HDL_CAND_FUNCTION));
        AppendPod(req, truth_leaf);
        AppendString(req, "leaf");
        uint64_t cand_id = 0;
        if (!hdltest::PipeRequest(target.pid, req, resp)) {
            Report(c, false, false, "discover add cand ipc", "");
        } else {
            Reader r(resp);
            int32_t st = 0;
            Report(c, r.TakePod(st) && r.TakePod(cand_id) && st == HDL_OK && cand_id != 0, false,
                   "discover add leaf cand", "");
        }

        req.clear();
        resp.clear();
        SetMethod(req, hdl::rpc::Method::DiscoverSynthesizePattern);
        AppendPod(req, disc_id);
        AppendPod(req, cand_id);
        AppendPod(req, static_cast<uint32_t>(0));
        AppendPod(req, static_cast<uint32_t>(24));
        AppendPod(req, static_cast<uint32_t>(HDL_SEARCH_MODULE | HDL_SEARCH_IMAGE));
        AppendWString(req, L"hdl_test_target.exe");
        if (!hdltest::PipeRequest(target.pid, req, resp)) {
            Report(c, false, false, "discover synth ipc", "");
        } else {
            Reader r(resp);
            int32_t st = 0;
            HdlSynthesizedPattern out{};
            const bool ok = r.TakePod(st) && hdl::proto::TakeHdlSynthesizedPattern(r, out) &&
                            st == HDL_OK && out.pattern[0] && out.resolved_addr == truth_leaf;
            Report(c, ok, false, "discover synthesize leaf", "");
        }
    }

    /* Action + watch + rank */
    {
        PreparedRequest req;
        std::vector<uint8_t> resp;
        SetMethod(req, hdl::rpc::Method::DiscoverWatch);
        AppendPod(req, disc_id);
        AppendPod(req, truth_leaf);
        AppendPod(req, static_cast<uint32_t>(0));
        if (!hdltest::PipeRequest(target.pid, req, resp)) {
            Report(c, false, false, "discover watch ipc", "");
        } else {
            Reader r(resp);
            int32_t st = 0;
            Report(c, r.TakePod(st) && st == HDL_OK, false, "discover watch leaf", "");
        }

        req.clear();
        resp.clear();
        SetMethod(req, hdl::rpc::Method::DiscoverWatchRegion);
        AppendPod(req, disc_id);
        AppendPod(req, truth_obj_a);
        AppendPod(req, static_cast<uint32_t>(24));
        if (!hdltest::PipeRequest(target.pid, req, resp)) {
            Report(c, false, false, "discover watch region ipc", "");
        }

        req.clear();
        resp.clear();
        SetMethod(req, hdl::rpc::Method::DiscoverActionBegin);
        AppendPod(req, disc_id);
        AppendString(req, "fire");
        if (!hdltest::PipeRequest(target.pid, req, resp)) {
            Report(c, false, false, "discover action begin ipc", "");
        } else {
            Reader r(resp);
            int32_t st = 0;
            Report(c, r.TakePod(st) && st == HDL_OK, false, "discover action begin", "");
        }

        Report(c, call_export("HdlTestDiscoverAction", nullptr, 0), false, "discover call action",
               "");
        {
            HdlCallArg arg{};
            arg.kind = HDL_CALL_ARG_I64;
            arg.u64 = 5;
            Report(c, call_export("HdlTestDiscoverDamage", &arg, 1), false, "discover call damage",
                   "");
        }

        req.clear();
        resp.clear();
        SetMethod(req, hdl::rpc::Method::DiscoverActionEnd);
        AppendPod(req, disc_id);
        if (!hdltest::PipeRequest(target.pid, req, resp)) {
            Report(c, false, false, "discover action end ipc", "");
        } else {
            Reader r(resp);
            int32_t st = 0;
            Report(c, r.TakePod(st) && st == HDL_OK, false, "discover action end", "");
        }

        req.clear();
        resp.clear();
        SetMethod(req, hdl::rpc::Method::DiscoverRankFunctions);
        AppendPod(req, disc_id);
        AppendString(req, "fire");
        AppendPod(req, static_cast<uint32_t>(0));
        AppendPod(req, static_cast<uint32_t>(32));
        if (!hdltest::PipeRequest(target.pid, req, resp)) {
            Report(c, false, false, "discover rank ipc", "");
        } else {
            Reader r(resp);
            int32_t st = 0;
            uint32_t count = 0;
            bool near_action = false;
            if (r.TakePod(st) && r.TakePod(count) && st == HDL_OK) {
                for (uint32_t i = 0; i < count; ++i) {
                    HdlCandidate cand{};
                    if (!hdl::proto::TakeHdlCandidate(r, cand)) {
                        break;
                    }
                    if (truth_action && cand.address >= truth_action &&
                        cand.address < truth_action + 0x80) {
                        near_action = true;
                    }
                }
            }
            Report(c, near_action, false, "discover rank near Action", "");
        }

        req.clear();
        resp.clear();
        SetMethod(req, hdl::rpc::Method::DiscoverGetHeat);
        AppendPod(req, disc_id);
        AppendPod(req, truth_obj_a);
        AppendPod(req, static_cast<uint32_t>(16));
        if (!hdltest::PipeRequest(target.pid, req, resp)) {
            Report(c, false, false, "discover heat ipc", "");
        } else {
            Reader r(resp);
            int32_t st = 0;
            uint32_t count = 0;
            bool health_hot = false;
            if (r.TakePod(st) && r.TakePod(count) && st == HDL_OK) {
                for (uint32_t i = 0; i < count; ++i) {
                    HdlHeatField hf{};
                    if (!hdl::proto::TakeHdlHeatField(r, hf)) {
                        break;
                    }
                    if (hf.offset == 8) {
                        health_hot = true;
                    }
                }
            }
            Report(c, health_hot, false, "discover heat on health", "");
        }
    }

    /* Path consensus / validate across realloc */
    {
        /* Ensure dyn leaf allocated */
        call_export("HdlTestDiscoverAllocDyn", nullptr, 0);

        PreparedRequest req;
        std::vector<uint8_t> resp;
        /* Resolve current dyn leaf via follow DynRoot */
        SetMethod(req, hdl::rpc::Method::FollowPointers);
        AppendPod(req, truth_dyn_root);
        AppendPod(req, static_cast<uint32_t>(1));
        AppendPod(req, static_cast<int64_t>(0));
        uint64_t dyn1 = 0;
        if (hdltest::PipeRequest(target.pid, req, resp)) {
            Reader r(resp);
            int32_t st = 0;
            r.TakePod(st);
            r.TakePod(dyn1);
        }

        req.clear();
        resp.clear();
        SetMethod(req, hdl::rpc::Method::DiscoverPathConsensus);
        AppendPod(req, dyn1);
        AppendPod(req, static_cast<uint32_t>(2));
        AppendPod(req, static_cast<uint32_t>(0x100));
        AppendPod(req, static_cast<uint32_t>(64));
        AppendPod(req, static_cast<uint32_t>(HDL_SEARCH_MODULE | HDL_SEARCH_IMAGE));
        AppendWString(req, L"hdl_test_target.exe");
        std::vector<HdlPointerPath> paths;
        if (!hdltest::PipeRequest(target.pid, req, resp)) {
            Report(c, false, false, "discover pathconsensus ipc", "");
        } else {
            Reader r(resp);
            int32_t st = 0;
            uint32_t count = 0;
            bool ok = r.TakePod(st) && r.TakePod(count) && st == HDL_OK && count >= 1;
            if (ok) {
                paths.resize(count);
                for (uint32_t i = 0; i < count; ++i) {
                    if (!hdl::proto::TakeHdlPointerPath(r, paths[i])) {
                        ok = false;
                        paths.clear();
                        break;
                    }
                }
            }
            Report(c, ok, false, "discover pathconsensus", "");
        }

        /* Realloc dyn leaf */
        call_export("HdlTestDiscoverAllocDyn", nullptr, 0);
        req.clear();
        resp.clear();
        SetMethod(req, hdl::rpc::Method::FollowPointers);
        AppendPod(req, truth_dyn_root);
        AppendPod(req, static_cast<uint32_t>(1));
        AppendPod(req, static_cast<int64_t>(0));
        uint64_t dyn2 = 0;
        if (hdltest::PipeRequest(target.pid, req, resp)) {
            Reader r(resp);
            int32_t st = 0;
            r.TakePod(st);
            r.TakePod(dyn2);
        }

        req.clear();
        resp.clear();
        SetMethod(req, hdl::rpc::Method::DiscoverPathValidate);
        AppendPod(req, dyn2);
        AppendPod(req, static_cast<uint32_t>(paths.size()));
        for (const auto& p : paths) {
            hdl::proto::AppendHdlPointerPath(req.payload, p);
        }
        if (!hdltest::PipeRequest(target.pid, req, resp)) {
            Report(c, false, false, "discover pathvalidate ipc", "");
        } else {
            Reader r(resp);
            int32_t st = 0;
            uint32_t kept = 0;
            bool has_root = false;
            bool decoded = r.TakePod(st) && r.TakePod(kept) && st == HDL_OK;
            if (decoded) {
                for (uint32_t i = 0; i < kept; ++i) {
                    HdlPointerPath p{};
                    if (!hdl::proto::TakeHdlPointerPath(r, p)) {
                        decoded = false;
                        has_root = false;
                        break;
                    }
                    if (p.static_base == truth_dyn_root && p.depth == 1 && p.offsets[0] == 0) {
                        has_root = true;
                    }
                }
            }
            Report(c, decoded && has_root && dyn1 != 0 && dyn2 != 0, false,
                   "discover pathvalidate keeps DynRoot", "");
        }
    }

    {
        PreparedRequest req;
        std::vector<uint8_t> resp;
        SetMethod(req, hdl::rpc::Method::DiscoverClose);
        AppendPod(req, disc_id);
        if (!hdltest::PipeRequest(target.pid, req, resp)) {
            Report(c, false, false, "discover close ipc", "");
        } else {
            Reader r(resp);
            int32_t st = 0;
            Report(c, r.TakePod(st) && st == HDL_OK, false, "discover close", "");
        }
    }
}
