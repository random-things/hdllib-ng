#include "repl.hpp"

#include "util.hpp"

#include <cstdio>
#include <string>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

namespace hdlcli {

namespace {

std::vector<std::wstring> Tokenize(const std::wstring& line) {
    std::vector<std::wstring> toks;
    std::wstring cur;
    bool in_q = false;
    for (wchar_t c : line) {
        if (c == L'"') {
            in_q = !in_q;
            continue;
        }
        if (!in_q && (c == L' ' || c == L'\t')) {
            if (!cur.empty()) {
                toks.push_back(cur);
                cur.clear();
            }
            continue;
        }
        cur.push_back(c);
    }
    if (!cur.empty()) {
        toks.push_back(cur);
    }
    return toks;
}

void DefaultLog(const std::wstring& s) {
    wprintf(L"%ls\n", s.c_str());
}

bool AttachPathLocator(ControllerState& st, Interest* in, LogFn log) {
    if (!in || !st.last_path_valid || st.last_path.depth == 0) {
        log(L"store add path: no last pathscan/ptrscan result");
        return false;
    }
    Locator loc;
    loc.type = Locator::Path;
    loc.path.module = !st.last_path_module.empty() ? st.last_path_module : st.store.module;

    uint64_t mod_base = 0;
    const std::wstring modw = Utf8ToWide(loc.path.module);
    auto mb = ModBase(*st.client, modw.empty() ? nullptr : modw.c_str(), &mod_base);
    if (!mb || !mod_base) {
        log(L"store add path: modbase failed");
        return false;
    }
    if (st.last_path.static_base < mod_base) {
        log(L"store add path: static_base outside module");
        return false;
    }
    loc.path.static_rva = st.last_path.static_base - mod_base;
    for (uint32_t i = 0; i < st.last_path.depth && i < 8; ++i) {
        loc.path.offsets.push_back(st.last_path.offsets[i]);
    }
    loc.last_ok = false;
    loc.last_addr = 0;
    in->locators.push_back(std::move(loc));
    return true;
}

}  // namespace

int DispatchLine(ControllerState& st, uint32_t pid, const std::wstring& line, LogFn log) {
    if (!log) {
        log = DefaultLog;
    }
    auto toks = Tokenize(line);
    if (toks.empty()) {
        return 0;
    }
    const std::wstring& cmd = toks[0];

    if (cmd == L"help" || cmd == L"?") {
        log(L"Controller: store load|save|list|revalidate|add <name> [--kind K] [synth|path|export N|cave|stub|patch],");
        log(L"  session new|show|close,");
        log(L"  recipe action <name> <watch_hex>, recipe constrain <size> <pred>...,");
        log(L"  recipe place <interest> <near_hex>, recipe expand <base_hex> <size>,");
        log(L"  recipe stitch <interest> --target HEX [--kind …],");
        log(L"  recipe suggest,");
        log(L"  stabilize <cand_id>, quit — plus all pipe cmds");
        return 0;
    }
    if (cmd == L"quit" || cmd == L"exit") {
        return -1;
    }

    if (cmd == L"session") {
        if (toks.size() < 2) {
            return 1;
        }
        if (toks[1] == L"new") {
            if (st.discover_session) {
                DiscoverClose(*st.client, st.discover_session);
                st.discover_session = 0;
            }
            return EnsureDiscoverSession(st, log) ? 0 : 1;
        }
        if (toks[1] == L"show") {
            wchar_t buf[256];
            swprintf_s(buf, L"pid=%u discover_session=%llu store=%ls", pid,
                       static_cast<unsigned long long>(st.discover_session), st.store_path.c_str());
            log(buf);
            return 0;
        }
        if (toks[1] == L"close" && st.discover_session) {
            DiscoverClose(*st.client, st.discover_session);
            st.discover_session = 0;
        }
        return 0;
    }

    if (cmd == L"store") {
        if (toks.size() < 2) {
            return 1;
        }
        if (toks[1] == L"load") {
            const wchar_t* p = toks.size() >= 3 ? toks[2].c_str() : st.store_path.c_str();
            if (!st.store.Load(p)) {
                log(L"store load failed");
                return 1;
            }
            st.store_path = p;
            log(L"store loaded");
            return 0;
        }
        if (toks[1] == L"save") {
            const wchar_t* p = toks.size() >= 3 ? toks[2].c_str() : st.store_path.c_str();
            st.store_path = p;
            if (!st.store.Save(p)) {
                log(L"store save failed");
                return 1;
            }
            log(L"store saved");
            return 0;
        }
        if (toks[1] == L"list") {
            for (const auto& in : st.store.interests) {
                wchar_t buf[512];
                swprintf_s(buf, L"  %ls kind=%ls locators=%u", Utf8ToWide(in.name).c_str(),
                           Utf8ToWide(in.kind).c_str(),
                           static_cast<unsigned>(in.locators.size()));
                log(buf);
            }
            return 0;
        }
        if (toks[1] == L"revalidate") {
            const int n = RevalidateStore(st, log);
            wchar_t buf[64];
            swprintf_s(buf, L"revalidate ok=%d", n);
            log(buf);
            return 0;
        }
        if (toks[1] == L"add" && toks.size() >= 3) {
            Interest in;
            in.name = WideToUtf8(toks[2]);
            in.kind = "function";
            std::string source = "synth";
            std::string export_name;
            for (size_t i = 3; i < toks.size(); ++i) {
                if (toks[i] == L"--kind" && i + 1 < toks.size()) {
                    in.kind = WideToUtf8(toks[++i]);
                } else if (toks[i] == L"synth" || toks[i] == L"path" || toks[i] == L"cave" ||
                           toks[i] == L"stub" || toks[i] == L"patch") {
                    source = WideToUtf8(toks[i]);
                } else if (toks[i] == L"export" && i + 1 < toks.size()) {
                    source = "export";
                    export_name = WideToUtf8(toks[++i]);
                }
            }
            if (source == "synth" && st.last_synth.pattern[0]) {
                Locator loc;
                loc.type = Locator::Pattern;
                loc.pattern.pattern = st.last_synth.pattern;
                loc.pattern.pattern_offset = st.last_synth.pattern_offset;
                loc.pattern.rip_disp = st.last_synth.rip_disp_offset;
                loc.pattern.rip_len = st.last_synth.rip_instr_len;
                loc.pattern.module = st.store.module;
                loc.last_addr = st.last_synth.resolved_addr;
                loc.last_ok = true;
                in.locators.push_back(std::move(loc));
            } else if (source == "path") {
                if (!AttachPathLocator(st, &in, log)) {
                    return 1;
                }
            } else if (source == "export" && !export_name.empty()) {
                Locator loc;
                loc.type = Locator::Export;
                loc.exp.module = st.store.module;
                loc.exp.name = export_name;
                in.locators.push_back(std::move(loc));
            } else if (source == "cave" && st.last_cave_addr) {
                Locator loc;
                loc.type = Locator::Cave;
                loc.cave.module = st.store.module;
                loc.cave.near_abs = st.last_cave_addr;
                loc.cave.last_size = st.last_cave_size;
                loc.last_addr = st.last_cave_addr;
                loc.last_ok = true;
                in.locators.push_back(std::move(loc));
            } else if (source == "stub" && st.last_stub_va) {
                Locator loc;
                loc.type = Locator::Stub;
                loc.stub.last_stub_va = st.last_stub_va;
                loc.stub.target_abs = st.last_patch_addr;
                loc.last_addr = st.last_stub_va;
                loc.last_ok = true;
                in.locators.push_back(std::move(loc));
            } else if (source == "patch" && st.last_patch_handle) {
                Locator loc;
                loc.type = Locator::Patch;
                loc.patch.last_handle = st.last_patch_handle;
                loc.patch.bytes_hex = st.last_patch_bytes_hex;
                loc.last_addr = st.last_patch_addr;
                loc.last_ok = true;
                in.locators.push_back(std::move(loc));
            }
            st.store.AddOrReplace(std::move(in));
            log(L"store add ok");
            return 0;
        }
        return 1;
    }

    if (cmd == L"recipe") {
        if (toks.size() < 2) {
            return 1;
        }
        if (toks[1] == L"suggest") {
            return RecipeSuggest(st, log);
        }
        if (toks[1] == L"action" && toks.size() >= 4) {
            auto wait = st.wait_enter;
            if (!wait) {
                wait = [&]() {
                    log(L"Press Enter after triggering the action...");
                    return WaitEnterWide();
                };
            }
            return RecipeAction(st, WideToUtf8(toks[2]).c_str(),
                               _wcstoui64(toks[3].c_str(), nullptr, 0), log, wait);
        }
        if (toks[1] == L"constrain" && toks.size() >= 4) {
            std::vector<HdlFieldPred> preds;
            for (size_t i = 3; i < toks.size(); ++i) {
                HdlFieldPred p{};
                if (!ClientParsePred(toks[i].c_str(), &p)) {
                    log(L"bad pred");
                    return 1;
                }
                preds.push_back(p);
            }
            return RecipeConstrain(st, static_cast<uint32_t>(_wtoi(toks[2].c_str())), preds,
                                  HDL_SEARCH_IMAGE, nullptr, log);
        }
        if (toks[1] == L"place" && toks.size() >= 4) {
            const uint64_t near_addr = _wcstoui64(toks[3].c_str(), nullptr, 0);
            return RecipePlace(st, WideToUtf8(toks[2]).c_str(), near_addr, nullptr, log);
        }
        if (toks[1] == L"expand" && toks.size() >= 4) {
            const uint64_t base = _wcstoui64(toks[2].c_str(), nullptr, 0);
            const uint32_t sz = static_cast<uint32_t>(_wcstoui64(toks[3].c_str(), nullptr, 0));
            return RecipeExpandStruct(st, base, sz, log);
        }
        if (toks[1] == L"stitch" && toks.size() >= 3) {
            uint64_t target = 0;
            int32_t kind = HDL_STUB_MOV_RAX_JMP;
            uint32_t steal_min = 5;
            for (size_t i = 3; i < toks.size(); ++i) {
                if (toks[i] == L"--target" && i + 1 < toks.size()) {
                    target = _wcstoui64(toks[++i].c_str(), nullptr, 0);
                } else if (toks[i] == L"--kind" && i + 1 < toks.size()) {
                    ++i;
                    if (toks[i] == L"abs_jmp") {
                        kind = HDL_STUB_ABS_JMP;
                    } else if (toks[i] == L"rel_jmp32") {
                        kind = HDL_STUB_REL_JMP32;
                    } else {
                        kind = HDL_STUB_MOV_RAX_JMP;
                    }
                } else if (toks[i] == L"--steal-min" && i + 1 < toks.size()) {
                    steal_min = static_cast<uint32_t>(_wtoi(toks[++i].c_str()));
                }
            }
            if (!target) {
                log(L"recipe stitch needs --target HEX");
                return 1;
            }
            return RecipeStitch(st, WideToUtf8(toks[2]).c_str(), target, kind, steal_min, log);
        }
        return 1;
    }

    if (cmd == L"stabilize" && toks.size() >= 2) {
        return StabilizeCandidate(st, _wcstoui64(toks[1].c_str(), nullptr, 0), nullptr, log);
    }

    /* Short REPL aliases → long CLI verbs */
    static const struct {
        const wchar_t* alias;
        const wchar_t* canon;
    } kAliases[] = {
        {L"dcreate", L"discover-create"},
        {L"dclose", L"discover-close"},
        {L"dadd", L"discover-add"},
        {L"dscan", L"discover-scan"},
        {L"dconstraint", L"discover-constraint"},
        {L"dsynth", L"discover-synth"},
        {L"dpathscan", L"discover-pathscan"},
        {L"dpathvalidate", L"discover-pathvalidate"},
        {L"dwatch", L"discover-watch"},
        {L"dunwatch", L"discover-unwatch"},
        {L"dbegin", L"discover-action-begin"},
        {L"dend", L"discover-action-end"},
        {L"dregion", L"discover-watch-region"},
        {L"dheat", L"discover-heat"},
        {L"drank", L"discover-rank"},
        {L"dcluster", L"discover-cluster"},
        {L"dcands", L"discover-cands"},
        {L"henable", L"hook-enable"},
        {L"rpat", L"resolve-pattern"},
    };
    std::wstring resolved = cmd;
    for (const auto& a : kAliases) {
        if (cmd == a.alias) {
            resolved = a.canon;
            break;
        }
    }

    size_t ncmd = 0;
    const CmdEntry* table = GetCommandTable(&ncmd);
    CmdHandler handler = nullptr;
    for (size_t i = 0; i < ncmd; ++i) {
        if (wcscmp(table[i].name, resolved.c_str()) == 0) {
            handler = table[i].handler;
            break;
        }
    }
    if (!handler) {
        log(L"unknown command");
        return 1;
    }

    std::vector<std::wstring> storage;
    storage.push_back(L"hdlclient");
    wchar_t pidbuf[32];
    swprintf_s(pidbuf, L"%u", pid);
    storage.push_back(pidbuf);
    storage.push_back(resolved);
    bool want_json = false;
    for (size_t i = 1; i < toks.size(); ++i) {
        if (toks[i] == L"--json") {
            want_json = true;
            continue;
        }
        storage.push_back(toks[i]);
    }
    std::vector<wchar_t*> argv;
    argv.reserve(storage.size());
    for (auto& s : storage) {
        argv.push_back(s.data());
    }
    CmdCtx ctx{static_cast<int>(argv.size()), argv.data(), pid, resolved, *st.client, &st};
    ctx.json = want_json;
    return handler(ctx);
}

int RunRepl(uint32_t pid, PipeClient& client, const wchar_t* store_path_or_null) {
    ControllerState st;
    st.client = &client;
    if (store_path_or_null && store_path_or_null[0]) {
        st.store_path = store_path_or_null;
        st.store.Load(store_path_or_null);
    }
    wprintf(L"hdlclient REPL pid=%u  (help, quit)\n", pid);
    for (;;) {
        wprintf(L"hdl:%u> ", pid);
        fflush(stdout);
        std::wstring line;
        if (!ReadLineWide(&line)) {
            break;
        }
        const int rc = DispatchLine(st, pid, line, DefaultLog);
        if (rc < 0) {
            break;
        }
    }
    if (st.discover_session) {
        DiscoverClose(client, st.discover_session);
    }
    return 0;
}

}  // namespace hdlcli
