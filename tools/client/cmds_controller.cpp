#include "cmd.hpp"
#include "cmd_fail.hpp"
#include "json_out.hpp"
#include "recipes.hpp"
#include "session_persist.hpp"
#include "store.hpp"
#include "usage.hpp"
#include "util.hpp"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <string>
#include <thread>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

namespace {

bool EqFlag(const wchar_t* a, const wchar_t* b) {
    return a && b && _wcsicmp(a, b) == 0;
}

void CollectLog(std::vector<std::wstring>* lines, const std::wstring& s) {
    if (lines) {
        lines->push_back(s);
    }
}

std::string LinesJson(const std::vector<std::wstring>& lines) {
    JsonWriter w;
    w.BeginArray();
    for (const auto& l : lines) {
        w.Str(l);
    }
    w.EndArray();
    return w.Take();
}

CommandResult NeedStore(CmdCtx& ctx) {
    return FailArg(ctx, L"--store PATH required for this command");
}

CommandResult NeedSession(CmdCtx& ctx) {
    return FailArg(ctx, L"--session ID (or HDL_SESSION / store sidecar) required");
}

bool InitController(CmdCtx& ctx, hdlcli::ControllerState* st, bool require_store) {
    if (!st) {
        return false;
    }
    st->client = &ctx.client;
    st->pid = ctx.pid;
    st->persist_session = true;
    if (ctx.store_path && ctx.store_path[0]) {
        st->store_path = ctx.store_path;
    } else if (require_store) {
        return false;
    }
    const uint64_t sid = hdlcli::ResolveSessionId(ctx);
    if (sid) {
        st->discover_session = sid;
    }
    return true;
}

bool LoadStoreTx(hdlcli::ControllerState& st, std::wstring* err) {
    if (st.store_path.empty()) {
        if (err) {
            *err = L"--store PATH required";
        }
        return false;
    }
    /* Missing file is OK for first write — start empty. */
    if (GetFileAttributesW(st.store_path.c_str()) == INVALID_FILE_ATTRIBUTES) {
        st.store = hdlcli::InterestStore{};
        st.store.path = st.store_path;
        return true;
    }
    if (!st.store.Load(st.store_path.c_str())) {
        if (err) {
            *err = L"store load failed";
        }
        return false;
    }
    return true;
}

bool SaveStoreTx(hdlcli::ControllerState& st, std::wstring* err) {
    if (st.store_path.empty()) {
        if (err) {
            *err = L"--store PATH required";
        }
        return false;
    }
    if (!st.store.Save(st.store_path.c_str())) {
        if (err) {
            *err = L"store save failed";
        }
        return false;
    }
    return true;
}

bool AttachPathLocatorFromPath(hdlcli::ControllerState& st, hdlcli::Interest* in,
                               const HdlPointerPath& path, const wchar_t* module_or_null,
                               std::wstring* err) {
    if (!in || path.depth == 0) {
        if (err) {
            *err = L"store-add path: empty path";
        }
        return false;
    }
    hdlcli::Locator loc;
    loc.type = hdlcli::Locator::Path;
    if (module_or_null && module_or_null[0]) {
        loc.path.module = WideToUtf8(module_or_null);
    } else if (!st.store.module.empty()) {
        loc.path.module = st.store.module;
    }
    uint64_t mod_base = 0;
    const std::wstring modw = Utf8ToWide(loc.path.module);
    auto mb = hdlcli::ModBase(*st.client, modw.empty() ? nullptr : modw.c_str(), &mod_base);
    if (!mb || !mod_base) {
        if (err) {
            *err = L"store-add path: modbase failed";
        }
        return false;
    }
    if (path.static_base < mod_base) {
        if (err) {
            *err = L"store-add path: static_base outside module";
        }
        return false;
    }
    loc.path.static_rva = path.static_base - mod_base;
    for (uint32_t i = 0; i < path.depth && i < 8; ++i) {
        loc.path.offsets.push_back(path.offsets[i]);
    }
    loc.last_ok = false;
    loc.last_addr = 0;
    in->locators.push_back(std::move(loc));
    return true;
}

CommandResult OkWithLines(CmdCtx& ctx, hdlcli::ControllerState& st,
                          const std::vector<std::wstring>& lines,
                          const std::function<void(JsonWriter&)>& extra) {
    JsonWriter w;
    w.BeginObject();
    w.Key("session");
    w.HexStr(st.discover_session);
    w.Key("pid");
    w.Num(ctx.pid);
    if (!st.store_path.empty()) {
        w.Key("store");
        w.Str(st.store_path);
    }
    if (extra) {
        extra(w);
    }
    w.Key("lines");
    w.BeginArray();
    for (const auto& l : lines) {
        w.Str(l);
    }
    w.EndArray();
    w.EndObject();
    return CmdOk(ctx.cmd.c_str(), w.Take());
}

} // namespace

namespace hdlcli {

bool StoreAddPathInterest(ControllerState& st, const char* name, const HdlPointerPath& path,
                          const wchar_t* module_or_null, std::wstring* err) {
    if (!name || !name[0]) {
        if (err) {
            *err = L"store-add: empty name";
        }
        return false;
    }
    Interest in;
    if (Interest* existing = st.store.Find(name)) {
        in = *existing;
    } else {
        in.name = name;
        in.kind = "object";
    }
    /* Replace existing path locator or append. */
    Interest tmp;
    if (!AttachPathLocatorFromPath(st, &tmp, path, module_or_null, err)) {
        return false;
    }
    bool replaced = false;
    for (auto& loc : in.locators) {
        if (loc.type == Locator::Path) {
            loc = tmp.locators[0];
            replaced = true;
            break;
        }
    }
    if (!replaced) {
        in.locators.push_back(std::move(tmp.locators[0]));
    }
    st.store.AddOrReplace(std::move(in));
    return true;
}

} // namespace hdlcli

CommandResult CmdSession(CmdCtx& ctx) {
    if (ctx.argc < 4) {
        return FailUsage(ctx);
    }
    hdlcli::ControllerState st;
    if (!InitController(ctx, &st, false)) {
        return FailArg(ctx, L"controller init failed");
    }
    ctx.controller = &st;
    const std::wstring sub = ctx.argv[3];

    if (sub == L"new") {
        if (st.discover_session) {
            hdlcli::DiscoverClose(*st.client, st.discover_session);
            st.discover_session = 0;
        }
        std::vector<std::wstring> lines;
        auto log = [&](const std::wstring& s) { CollectLog(&lines, s); };
        if (!hdlcli::EnsureDiscoverSession(st, log)) {
            return CmdFail(ctx.cmd.c_str(), HDL_E_FAILED, L"session new failed");
        }
        if (!hdlcli::PersistSessionId(ctx, st.discover_session)) {
            return CmdFail(ctx.cmd.c_str(), HDL_E_FAILED, L"session sidecar write failed");
        }
        JsonWriter w;
        w.BeginObject();
        w.Key("session");
        w.HexStr(st.discover_session);
        w.Key("pid");
        w.Num(ctx.pid);
        if (ctx.store_path) {
            w.Key("store");
            w.Str(ctx.store_path);
        }
        w.Key("lines");
        w.BeginArray();
        for (const auto& l : lines) {
            w.Str(l);
        }
        w.EndArray();
        w.EndObject();
        return CmdOk(ctx.cmd.c_str(), w.Take());
    }

    if (sub == L"show") {
        const uint64_t id = hdlcli::ResolveSessionId(ctx);
        if (!id) {
            return NeedSession(ctx);
        }
        JsonWriter w;
        w.BeginObject();
        w.Key("session");
        w.HexStr(id);
        w.Key("pid");
        w.Num(ctx.pid);
        if (ctx.store_path) {
            w.Key("store");
            w.Str(ctx.store_path);
        }
        w.EndObject();
        return CmdOk(ctx.cmd.c_str(), w.Take());
    }

    if (sub == L"close") {
        uint64_t id = hdlcli::ResolveSessionId(ctx);
        if (!id) {
            return NeedSession(ctx);
        }
        auto s = hdlcli::DiscoverClose(ctx.client, id);
        if (s) {
            if (!hdlcli::ClearPersistedSession(ctx.pid, ctx.store_path)) {
                return CmdFail(ctx.cmd.c_str(), HDL_E_FAILED, L"session sidecar clear failed");
            }
        }
        JsonWriter w;
        w.BeginObject();
        w.Key("session");
        w.HexStr(id);
        w.Key("pid");
        w.Num(ctx.pid);
        w.EndObject();
        return CmdStatus(ctx.cmd.c_str(), s.status, w.Take());
    }

    return FailUsage(ctx);
}

CommandResult CmdStore(CmdCtx& ctx) {
    if (ctx.argc < 4) {
        return FailUsage(ctx);
    }
    if (!ctx.store_path || !ctx.store_path[0]) {
        return NeedStore(ctx);
    }
    hdlcli::ControllerState st;
    if (!InitController(ctx, &st, true)) {
        return NeedStore(ctx);
    }
    ctx.controller = &st;
    std::wstring err;
    if (!LoadStoreTx(st, &err)) {
        return CmdFail(ctx.cmd.c_str(), HDL_E_FAILED, err.c_str());
    }

    const std::wstring sub = ctx.argv[3];

    if (sub == L"list") {
        JsonWriter w;
        w.BeginObject();
        w.Key("store");
        w.Str(st.store_path);
        w.Key("interests");
        w.BeginArray();
        for (const auto& in : st.store.interests) {
            w.BeginObject();
            w.Key("name");
            w.Str(Utf8ToWide(in.name));
            w.Key("kind");
            w.Str(Utf8ToWide(in.kind));
            w.Key("locators");
            w.Num(static_cast<uint32_t>(in.locators.size()));
            w.EndObject();
        }
        w.EndArray();
        w.EndObject();
        return CmdOk(ctx.cmd.c_str(), w.Take());
    }

    if (sub == L"revalidate") {
        std::vector<std::wstring> lines;
        auto log = [&](const std::wstring& s) { CollectLog(&lines, s); };
        const int n = hdlcli::RevalidateStore(st, log);
        if (!SaveStoreTx(st, &err)) {
            return CmdFail(ctx.cmd.c_str(), HDL_E_FAILED, err.c_str());
        }
        JsonWriter w;
        w.BeginObject();
        w.Key("store");
        w.Str(st.store_path);
        w.Key("ok");
        w.Num(n);
        w.Key("lines");
        w.BeginArray();
        for (const auto& l : lines) {
            w.Str(l);
        }
        w.EndArray();
        w.EndObject();
        return CmdOk(ctx.cmd.c_str(), w.Take());
    }

    if (sub == L"add" && ctx.argc >= 5) {
        hdlcli::Interest in;
        in.name = WideToUtf8(ctx.argv[4]);
        in.kind = "function";
        std::string export_name;
        const std::string added_name = in.name;
        bool have_export = false;
        uint64_t cave_addr = 0;
        uint64_t cave_size = 0;
        uint64_t stub_va = 0;
        uint64_t stub_target = 0;
        uint64_t patch_handle = 0;
        uint64_t patch_addr = 0;
        std::string patch_bytes;
        std::string pattern;
        int32_t pattern_offset = 0;
        uint32_t rip_disp = 0;
        uint32_t rip_len = 0;
        uint64_t pattern_addr = 0;
        bool have_pattern = false;
        bool have_cave = false;
        bool have_stub = false;
        bool have_patch = false;

        for (int i = 5; i < ctx.argc; ++i) {
            if (EqFlag(ctx.argv[i], L"--kind") && i + 1 < ctx.argc) {
                in.kind = WideToUtf8(ctx.argv[++i]);
            } else if (EqFlag(ctx.argv[i], L"export") && i + 1 < ctx.argc) {
                have_export = true;
                export_name = WideToUtf8(ctx.argv[++i]);
            } else if (EqFlag(ctx.argv[i], L"--pattern") && i + 1 < ctx.argc) {
                have_pattern = true;
                pattern = WideToUtf8(ctx.argv[++i]);
            } else if (EqFlag(ctx.argv[i], L"--pattern-offset") && i + 1 < ctx.argc) {
                pattern_offset = _wtoi(ctx.argv[++i]);
            } else if (EqFlag(ctx.argv[i], L"--rip-disp") && i + 1 < ctx.argc) {
                rip_disp = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
            } else if (EqFlag(ctx.argv[i], L"--rip-len") && i + 1 < ctx.argc) {
                rip_len = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
            } else if (EqFlag(ctx.argv[i], L"--addr") && i + 1 < ctx.argc) {
                pattern_addr = _wcstoui64(ctx.argv[++i], nullptr, 0);
            } else if (EqFlag(ctx.argv[i], L"--cave-addr") && i + 1 < ctx.argc) {
                have_cave = true;
                cave_addr = _wcstoui64(ctx.argv[++i], nullptr, 0);
            } else if (EqFlag(ctx.argv[i], L"--cave-size") && i + 1 < ctx.argc) {
                cave_size = _wcstoui64(ctx.argv[++i], nullptr, 0);
            } else if (EqFlag(ctx.argv[i], L"--stub-va") && i + 1 < ctx.argc) {
                have_stub = true;
                stub_va = _wcstoui64(ctx.argv[++i], nullptr, 0);
            } else if (EqFlag(ctx.argv[i], L"--stub-target") && i + 1 < ctx.argc) {
                stub_target = _wcstoui64(ctx.argv[++i], nullptr, 0);
            } else if (EqFlag(ctx.argv[i], L"--patch-handle") && i + 1 < ctx.argc) {
                have_patch = true;
                patch_handle = _wcstoui64(ctx.argv[++i], nullptr, 0);
            } else if (EqFlag(ctx.argv[i], L"--patch-addr") && i + 1 < ctx.argc) {
                patch_addr = _wcstoui64(ctx.argv[++i], nullptr, 0);
            } else if (EqFlag(ctx.argv[i], L"--patch-bytes") && i + 1 < ctx.argc) {
                patch_bytes = WideToUtf8(ctx.argv[++i]);
            } else if (EqFlag(ctx.argv[i], L"synth") || EqFlag(ctx.argv[i], L"path") ||
                       EqFlag(ctx.argv[i], L"cave") || EqFlag(ctx.argv[i], L"stub") ||
                       EqFlag(ctx.argv[i], L"patch")) {
                return FailArg(ctx, L"bare synth|path|cave|stub|patch removed; use explicit flags "
                                    L"or --store-add on the producing verb");
            }
        }

        if (have_export && !export_name.empty()) {
            hdlcli::Locator loc;
            loc.type = hdlcli::Locator::Export;
            loc.exp.module = st.store.module;
            loc.exp.name = export_name;
            in.locators.push_back(std::move(loc));
        } else if (have_pattern && !pattern.empty()) {
            hdlcli::Locator loc;
            loc.type = hdlcli::Locator::Pattern;
            loc.pattern.pattern = pattern;
            loc.pattern.pattern_offset = pattern_offset;
            loc.pattern.rip_disp = rip_disp;
            loc.pattern.rip_len = rip_len;
            loc.pattern.module = st.store.module;
            loc.last_addr = pattern_addr;
            loc.last_ok = pattern_addr != 0;
            in.locators.push_back(std::move(loc));
        } else if (have_cave && cave_addr) {
            hdlcli::Locator loc;
            loc.type = hdlcli::Locator::Cave;
            loc.cave.module = st.store.module;
            loc.cave.near_abs = cave_addr;
            loc.cave.last_size = cave_size;
            loc.last_addr = cave_addr;
            loc.last_ok = true;
            in.locators.push_back(std::move(loc));
        } else if (have_stub && stub_va) {
            hdlcli::Locator loc;
            loc.type = hdlcli::Locator::Stub;
            loc.stub.last_stub_va = stub_va;
            loc.stub.target_abs = stub_target;
            loc.last_addr = stub_va;
            loc.last_ok = true;
            in.locators.push_back(std::move(loc));
        } else if (have_patch && patch_handle) {
            hdlcli::Locator loc;
            loc.type = hdlcli::Locator::Patch;
            loc.patch.last_handle = patch_handle;
            loc.patch.bytes_hex = patch_bytes;
            loc.last_addr = patch_addr;
            loc.last_ok = true;
            in.locators.push_back(std::move(loc));
        } else {
            return FailArg(ctx, L"store add needs export NAME | --pattern AOB | --cave-addr | "
                                L"--stub-va | --patch-handle (or use --store-add / stabilize)");
        }

        st.store.AddOrReplace(std::move(in));
        if (!SaveStoreTx(st, &err)) {
            return CmdFail(ctx.cmd.c_str(), HDL_E_FAILED, err.c_str());
        }
        JsonWriter w;
        w.BeginObject();
        w.Key("store");
        w.Str(st.store_path);
        w.Key("name");
        w.Str(Utf8ToWide(added_name));
        w.Key("added");
        w.Bool(true);
        w.EndObject();
        return CmdOk(ctx.cmd.c_str(), w.Take());
    }

    return FailUsage(ctx);
}

CommandResult CmdRecipe(CmdCtx& ctx) {
    if (ctx.argc < 4) {
        return FailUsage(ctx);
    }
    const std::wstring sub = ctx.argv[3];
    const bool needs_store = sub == L"place" || sub == L"stitch" || sub == L"action";
    if (needs_store && (!ctx.store_path || !ctx.store_path[0])) {
        return NeedStore(ctx);
    }

    hdlcli::ControllerState st;
    if (!InitController(ctx, &st, needs_store)) {
        return needs_store ? NeedStore(ctx) : FailArg(ctx, L"controller init failed");
    }
    ctx.controller = &st;
    std::wstring err;
    if (needs_store && !LoadStoreTx(st, &err)) {
        return CmdFail(ctx.cmd.c_str(), HDL_E_FAILED, err.c_str());
    }

    std::vector<std::wstring> lines;
    auto log = [&](const std::wstring& s) { CollectLog(&lines, s); };

    if (sub == L"suggest") {
        const int rc = hdlcli::RecipeSuggest(st, log);
        if (rc != 0) {
            return CmdFail(ctx.cmd.c_str(), HDL_E_FAILED, L"recipe suggest failed");
        }
        return OkWithLines(ctx, st, lines, nullptr);
    }

    if (sub == L"action") {
        /* recipe action <name> <watch_hex> --wait-ms N | --signal FILE */
        if (ctx.argc < 6) {
            return FailUsage(ctx);
        }
        std::string action_owned = WideToUtf8(ctx.argv[4]);
        const char* action_name = action_owned.c_str();
        const uint64_t watch = _wcstoui64(ctx.argv[5], nullptr, 0);
        int wait_ms = -1;
        const wchar_t* signal_file = nullptr;
        for (int i = 6; i < ctx.argc; ++i) {
            if (EqFlag(ctx.argv[i], L"--wait-ms") && i + 1 < ctx.argc) {
                wait_ms = _wtoi(ctx.argv[++i]);
            } else if (EqFlag(ctx.argv[i], L"--signal") && i + 1 < ctx.argc) {
                signal_file = ctx.argv[++i];
            } else if (EqFlag(ctx.argv[i], L"--signal")) {
                return FailArg(ctx, L"--signal requires a FILE path (wait until file exists)");
            }
        }
        if (wait_ms < 0 && !signal_file) {
            return FailArg(ctx, L"recipe action requires --wait-ms N or --signal FILE");
        }
        if (!st.discover_session) {
            if (!hdlcli::EnsureDiscoverSession(st, log)) {
                return CmdFail(ctx.cmd.c_str(), HDL_E_FAILED, L"no discover session");
            }
        } else if (!hdlcli::PersistSessionId(ctx, st.discover_session)) {
            return CmdFail(ctx.cmd.c_str(), HDL_E_FAILED, L"session sidecar write failed");
        }
        std::function<bool()> wait;
        if (signal_file) {
            const std::wstring sig(signal_file);
            wait = [&log, sig]() {
                wchar_t buf[512];
                swprintf_s(buf, L"waiting for signal file %ls ...", sig.c_str());
                log(buf);
                for (int i = 0; i < 6000; ++i) {
                    if (GetFileAttributesW(sig.c_str()) != INVALID_FILE_ATTRIBUTES) {
                        return true;
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }
                return false;
            };
        } else {
            wait = [wait_ms, &log]() {
                wchar_t buf[64];
                swprintf_s(buf, L"waiting %d ms...", wait_ms);
                log(buf);
                std::this_thread::sleep_for(std::chrono::milliseconds(wait_ms));
                return true;
            };
        }
        const hdlcli::StabilizeResult stab =
            hdlcli::RecipeAction(st, action_name, watch, log, wait);
        if (stab.rc != 0) {
            return CmdFail(ctx.cmd.c_str(), HDL_E_FAILED, L"recipe action failed");
        }
        if (!SaveStoreTx(st, &err)) {
            return CmdFail(ctx.cmd.c_str(), HDL_E_FAILED, err.c_str());
        }
        return OkWithLines(ctx, st, lines, [&](JsonWriter& w) {
            w.Key("action");
            w.Str(Utf8ToWide(action_owned));
            w.Key("watch");
            w.HexStr(watch);
            if (!stab.interest_name.empty()) {
                w.Key("interest");
                w.Str(Utf8ToWide(stab.interest_name));
            }
            if (st.last_synth.pattern[0]) {
                w.Key("pattern");
                w.Str(Utf8ToWide(std::string(st.last_synth.pattern)));
                w.Key("resolved");
                w.HexStr(st.last_synth.resolved_addr);
            }
            if (!st.last_rank.empty()) {
                w.Key("cand_id");
                w.HexStr(st.last_rank[0].id);
            }
        });
    }

    if (sub == L"constrain") {
        if (ctx.argc < 6) {
            return FailUsage(ctx);
        }
        const uint32_t object_size = static_cast<uint32_t>(_wtoi(ctx.argv[4]));
        std::vector<HdlFieldPred> preds;
        for (int i = 5; i < ctx.argc; ++i) {
            if (EqFlag(ctx.argv[i], L"--session") && i + 1 < ctx.argc) {
                ++i;
                continue;
            }
            HdlFieldPred p{};
            if (!ClientParsePred(ctx.argv[i], &p)) {
                return FailArg(ctx, L"bad pred");
            }
            preds.push_back(p);
        }
        if (preds.empty()) {
            return FailUsage(ctx);
        }
        if (!st.discover_session && !hdlcli::EnsureDiscoverSession(st, log)) {
            return CmdFail(ctx.cmd.c_str(), HDL_E_FAILED, L"no discover session");
        }
        if (!hdlcli::PersistSessionId(ctx, st.discover_session)) {
            return CmdFail(ctx.cmd.c_str(), HDL_E_FAILED, L"session sidecar write failed");
        }
        const int rc =
            hdlcli::RecipeConstrain(st, object_size, preds, HDL_SEARCH_IMAGE, nullptr, log);
        if (rc != 0) {
            return CmdFail(ctx.cmd.c_str(), HDL_E_FAILED, L"recipe constrain failed");
        }
        return OkWithLines(ctx, st, lines, [&](JsonWriter& w) {
            w.Key("object");
            w.HexStr(st.last_object);
            w.Key("object_size");
            w.Num(object_size);
        });
    }

    if (sub == L"place") {
        if (ctx.argc < 6) {
            return FailUsage(ctx);
        }
        const std::string interest = WideToUtf8(ctx.argv[4]);
        const uint64_t near_addr = _wcstoui64(ctx.argv[5], nullptr, 0);
        const int rc = hdlcli::RecipePlace(st, interest.c_str(), near_addr, nullptr, log);
        if (rc != 0) {
            return CmdFail(ctx.cmd.c_str(), HDL_E_FAILED, L"recipe place failed");
        }
        if (!SaveStoreTx(st, &err)) {
            return CmdFail(ctx.cmd.c_str(), HDL_E_FAILED, err.c_str());
        }
        return OkWithLines(ctx, st, lines, [&](JsonWriter& w) {
            w.Key("interest");
            w.Str(Utf8ToWide(interest));
            w.Key("cave_addr");
            w.HexStr(st.last_cave_addr);
        });
    }

    if (sub == L"expand") {
        if (ctx.argc < 6) {
            return FailUsage(ctx);
        }
        const uint64_t base = _wcstoui64(ctx.argv[4], nullptr, 0);
        const uint32_t sz = static_cast<uint32_t>(_wcstoui64(ctx.argv[5], nullptr, 0));
        if (!st.discover_session && !hdlcli::EnsureDiscoverSession(st, log)) {
            return CmdFail(ctx.cmd.c_str(), HDL_E_FAILED, L"no discover session");
        }
        if (!hdlcli::PersistSessionId(ctx, st.discover_session)) {
            return CmdFail(ctx.cmd.c_str(), HDL_E_FAILED, L"session sidecar write failed");
        }
        const int rc = hdlcli::RecipeExpandStruct(st, base, sz, log);
        if (rc != 0) {
            return CmdFail(ctx.cmd.c_str(), HDL_E_FAILED, L"recipe expand failed");
        }
        return OkWithLines(ctx, st, lines, [&](JsonWriter& w) {
            w.Key("base");
            w.HexStr(base);
            w.Key("size");
            w.Num(sz);
        });
    }

    if (sub == L"stitch") {
        if (ctx.argc < 5) {
            return FailUsage(ctx);
        }
        const std::string interest = WideToUtf8(ctx.argv[4]);
        uint64_t target = 0;
        int32_t kind = HDL_STUB_MOV_RAX_JMP;
        uint32_t steal_min = 5;
        for (int i = 5; i < ctx.argc; ++i) {
            if (EqFlag(ctx.argv[i], L"--target") && i + 1 < ctx.argc) {
                target = _wcstoui64(ctx.argv[++i], nullptr, 0);
            } else if (EqFlag(ctx.argv[i], L"--kind") && i + 1 < ctx.argc) {
                ++i;
                if (EqFlag(ctx.argv[i], L"abs_jmp")) {
                    kind = HDL_STUB_ABS_JMP;
                } else if (EqFlag(ctx.argv[i], L"rel_jmp32")) {
                    kind = HDL_STUB_REL_JMP32;
                } else {
                    kind = HDL_STUB_MOV_RAX_JMP;
                }
            } else if (EqFlag(ctx.argv[i], L"--steal-min") && i + 1 < ctx.argc) {
                steal_min = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
            }
        }
        if (!target) {
            return FailArg(ctx, L"recipe stitch needs --target HEX");
        }
        const int rc = hdlcli::RecipeStitch(st, interest.c_str(), target, kind, steal_min, log);
        if (rc != 0) {
            return CmdFail(ctx.cmd.c_str(), HDL_E_FAILED, L"recipe stitch failed");
        }
        if (!SaveStoreTx(st, &err)) {
            return CmdFail(ctx.cmd.c_str(), HDL_E_FAILED, err.c_str());
        }
        return OkWithLines(ctx, st, lines, [&](JsonWriter& w) {
            w.Key("interest");
            w.Str(Utf8ToWide(interest));
            w.Key("stub_va");
            w.HexStr(st.last_stub_va);
            w.Key("patch_handle");
            w.HexStr(st.last_patch_handle);
        });
    }

    return FailUsage(ctx);
}

CommandResult CmdStabilize(CmdCtx& ctx) {
    if (ctx.argc < 4) {
        return FailUsage(ctx);
    }
    if (!ctx.store_path || !ctx.store_path[0]) {
        return NeedStore(ctx);
    }
    hdlcli::ControllerState st;
    if (!InitController(ctx, &st, true)) {
        return NeedStore(ctx);
    }
    if (!st.discover_session) {
        return NeedSession(ctx);
    }
    ctx.controller = &st;
    std::wstring err;
    if (!LoadStoreTx(st, &err)) {
        return CmdFail(ctx.cmd.c_str(), HDL_E_FAILED, err.c_str());
    }
    const uint64_t cand_id = _wcstoui64(ctx.argv[3], nullptr, 0);
    std::vector<std::wstring> lines;
    auto log = [&](const std::wstring& s) { CollectLog(&lines, s); };
    const hdlcli::StabilizeResult stab = hdlcli::StabilizeCandidate(st, cand_id, nullptr, log);
    if (stab.rc != 0) {
        return CmdFail(ctx.cmd.c_str(), HDL_E_FAILED, L"stabilize failed");
    }
    if (!SaveStoreTx(st, &err)) {
        return CmdFail(ctx.cmd.c_str(), HDL_E_FAILED, err.c_str());
    }
    return OkWithLines(ctx, st, lines, [&](JsonWriter& w) {
        w.Key("cand_id");
        w.HexStr(cand_id);
        if (!stab.interest_name.empty()) {
            w.Key("interest");
            w.Str(Utf8ToWide(stab.interest_name));
        }
        if (st.last_synth.pattern[0]) {
            w.Key("pattern");
            w.Str(Utf8ToWide(std::string(st.last_synth.pattern)));
            w.Key("resolved");
            w.HexStr(st.last_synth.resolved_addr);
        }
    });
}
