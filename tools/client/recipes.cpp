#include "recipes.hpp"

#include "session_persist.hpp"
#include "util.hpp"

#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <sstream>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

namespace hdlcli {
namespace {

void Wlog(LogFn& log, const wchar_t* fmt, ...) {
    wchar_t buf[1024];
    va_list ap;
    va_start(ap, fmt);
    _vsnwprintf_s(buf, _TRUNCATE, fmt, ap);
    va_end(ap);
    if (log) {
        log(buf);
    } else {
        wprintf(L"%ls\n", buf);
    }
}

std::wstring Widen(const char* s) {
    return Utf8ToWide(s ? s : "");
}

std::string HexOf(const uint8_t* p, size_t n) {
    std::ostringstream ss;
    ss << std::hex;
    for (size_t i = 0; i < n; ++i) {
        if (i) {
            ss << ' ';
        }
        ss << std::setw(2) << std::setfill('0') << static_cast<unsigned>(p[i]);
    }
    return ss.str();
}

uint64_t Dist(uint64_t a, uint64_t b) {
    return a >= b ? a - b : b - a;
}

uint64_t ResolveInterestAddr(ControllerState& st, const char* name) {
    if (!name || !name[0]) {
        return 0;
    }
    Interest* in = st.store.Find(name);
    if (!in) {
        return 0;
    }
    for (const auto& loc : in->locators) {
        if (loc.last_ok && loc.last_addr) {
            return loc.last_addr;
        }
    }
    return 0;
}

Locator* FindSiblingStub(Interest& in) {
    for (auto& loc : in.locators) {
        if (loc.type == Locator::Stub) {
            return &loc;
        }
    }
    return nullptr;
}

const Locator* FindSiblingStub(const Interest& in) {
    for (const auto& loc : in.locators) {
        if (loc.type == Locator::Stub) {
            return &loc;
        }
    }
    return nullptr;
}

bool EncodeJmpToStub(PipeClient& client, uint64_t stub_va, uint32_t steal_min,
                     std::vector<uint8_t>* out, LogFn& log) {
    if (!out || !stub_va) {
        return false;
    }
    HdlStubDesc jmp{};
    jmp.kind = HDL_STUB_MOV_RAX_JMP;
    jmp.target = stub_va;
    jmp.alloc_rx = 0;
    HdlStubResult jmp_bytes{};
    auto s = BuildStub(client, jmp, &jmp_bytes);
    if (!s || !jmp_bytes.code_size) {
        Wlog(log, L"jmp stub encode failed status=%ls", StatusName(s.status));
        return false;
    }
    const uint32_t patch_len =
        steal_min ? (std::max)(steal_min, jmp_bytes.code_size) : jmp_bytes.code_size;
    out->assign(patch_len, 0x90);
    memcpy(out->data(), jmp_bytes.code, jmp_bytes.code_size);
    return true;
}

bool CreateAndMaybeEnablePatch(PipeClient& client, uint64_t addr, const uint8_t* bytes,
                               uint32_t size, const char* name, int enabled_intent,
                               uint64_t* out_handle, LogFn& log) {
    if (!bytes || !size || !out_handle) {
        return false;
    }
    uint64_t handle = 0;
    auto s = PatchCreate(client, addr, bytes, size, name, &handle);
    if (!s) {
        Wlog(log, L"PatchCreate failed status=%ls", StatusName(s.status));
        return false;
    }
    if (enabled_intent) {
        s = PatchEnable(client, handle, 1);
        if (!s) {
            Wlog(log, L"PatchEnable failed status=%ls", StatusName(s.status));
            return false;
        }
    }
    *out_handle = handle;
    return true;
}

} // namespace

void RememberPath(ControllerState* st, const HdlPointerPath& path, const wchar_t* module_or_null) {
    if (!st) {
        return;
    }
    st->last_path = path;
    st->last_path_valid = path.depth > 0 && path.depth <= 8;
    if (module_or_null && module_or_null[0]) {
        st->last_path_module = WideToUtf8(module_or_null);
    } else if (!st->store.module.empty()) {
        st->last_path_module = st->store.module;
    } else {
        st->last_path_module.clear();
    }
}

size_t ScoreBestCave(const std::vector<HdlCaveInfo>& caves, uint64_t near_addr) {
    if (caves.empty()) {
        return static_cast<size_t>(-1);
    }
    size_t best = 0;
    for (size_t i = 1; i < caves.size(); ++i) {
        const uint64_t da = Dist(caves[i].addr, near_addr);
        const uint64_t db = Dist(caves[best].addr, near_addr);
        if (da < db || (da == db && caves[i].size > caves[best].size)) {
            best = i;
        }
    }
    return best;
}

bool EnsureDiscoverSession(ControllerState& st, LogFn log) {
    if (!st.client) {
        return false;
    }
    if (st.discover_session) {
        return true;
    }
    uint64_t id = 0;
    auto s = DiscoverCreate(*st.client, &id);
    if (!s) {
        Wlog(log, L"discover-create failed status=%ls", StatusName(s.status));
        return false;
    }
    st.discover_session = id;
    if (st.persist_session && st.pid) {
        if (!WritePersistedSession(st.pid, st.store_path.empty() ? nullptr : st.store_path.c_str(),
                                   id)) {
            Wlog(log, L"session sidecar write failed");
            return false;
        }
    }
    Wlog(log, L"discover session=%llu", static_cast<unsigned long long>(id));
    return true;
}

int RevalidateStore(ControllerState& st, LogFn log, bool apply) {
    if (!st.client) {
        return 0;
    }
    int ok = 0;

    auto revalidate_non_patch = [&](Interest& in, Locator& loc) {
        loc.last_ok = false;
        loc.last_addr = 0;
        if (loc.type == Locator::Pattern) {
            std::wstring mod = Widen(loc.pattern.module.c_str());
            HdlPatternResult pr{};
            auto s = ResolvePattern(*st.client, loc.pattern.pattern.c_str(), 0,
                                    loc.pattern.pattern_offset, loc.pattern.rip_disp,
                                    loc.pattern.rip_len, {},
                                    HDL_SEARCH_IMAGE | (mod.empty() ? 0u : HDL_SEARCH_MODULE),
                                    mod.empty() ? nullptr : mod.c_str(), &pr);
            if (s) {
                loc.last_addr = pr.resolved_addr;
                loc.last_ok = true;
                ++ok;
                Wlog(log, L"[OK] %hs pattern -> %016llx", in.name.c_str(),
                     static_cast<unsigned long long>(pr.resolved_addr));
            } else {
                Wlog(log, L"[FAIL] %hs pattern status=%ls", in.name.c_str(), StatusName(s.status));
            }
        } else if (loc.type == Locator::Path) {
            std::wstring mod = Widen(loc.path.module.c_str());
            uint64_t base = 0;
            auto mb = ModBase(*st.client, mod.empty() ? nullptr : mod.c_str(), &base);
            if (!mb || !base) {
                Wlog(log, L"[FAIL] %hs path modbase", in.name.c_str());
                return;
            }
            std::vector<int64_t> offs;
            for (int32_t o : loc.path.offsets) {
                offs.push_back(o);
            }
            uint64_t addr = 0;
            auto s = FollowPointers(*st.client, base + loc.path.static_rva, offs, &addr);
            if (s) {
                loc.last_addr = addr;
                loc.last_ok = true;
                ++ok;
                Wlog(log, L"[OK] %hs path -> %016llx", in.name.c_str(),
                     static_cast<unsigned long long>(addr));
            } else {
                Wlog(log, L"[FAIL] %hs path status=%ls", in.name.c_str(), StatusName(s.status));
            }
        } else if (loc.type == Locator::Export) {
            std::wstring mod = Widen(loc.exp.module.c_str());
            uint64_t addr = 0;
            auto s = ResolveExport(*st.client, mod.empty() ? nullptr : mod.c_str(),
                                   loc.exp.name.c_str(), &addr);
            if (s && addr) {
                loc.last_addr = addr;
                loc.last_ok = true;
                ++ok;
                Wlog(log, L"[OK] %hs export %hs -> %016llx", in.name.c_str(), loc.exp.name.c_str(),
                     static_cast<unsigned long long>(addr));
            } else {
                Wlog(log, L"[FAIL] %hs export status=%ls", in.name.c_str(), StatusName(s.status));
            }
        } else if (loc.type == Locator::Import) {
            std::wstring mod = Widen(loc.imp.module.c_str());
            uint64_t base = 0;
            if (!loc.imp.module.empty()) {
                auto mb = ModBase(*st.client, mod.c_str(), &base);
                if (!mb || !base) {
                    Wlog(log, L"[FAIL] %hs import modbase", in.name.c_str());
                    return;
                }
            }
            std::vector<HdlImportInfo> imports;
            auto s = EnumImports(*st.client, base, &imports);
            bool found = false;
            if (s) {
                for (const auto& info : imports) {
                    if (_stricmp(info.module, loc.imp.dll.c_str()) != 0) {
                        std::string want = loc.imp.dll;
                        if (want.find('.') == std::string::npos) {
                            want += ".dll";
                        }
                        if (_stricmp(info.module, want.c_str()) != 0) {
                            continue;
                        }
                    }
                    if (!info.name[0] || _stricmp(info.name, loc.imp.name.c_str()) != 0) {
                        continue;
                    }
                    if (info.bound_va) {
                        loc.last_addr = info.bound_va;
                        loc.last_ok = true;
                        ++ok;
                        found = true;
                        Wlog(log, L"[OK] %hs import %hs!%hs -> %016llx", in.name.c_str(),
                             loc.imp.dll.c_str(), loc.imp.name.c_str(),
                             static_cast<unsigned long long>(info.bound_va));
                        break;
                    }
                }
            }
            if (!found) {
                Wlog(log, L"[FAIL] %hs import %hs!%hs status=%ls", in.name.c_str(),
                     loc.imp.dll.c_str(), loc.imp.name.c_str(), StatusName(s.status));
            }
        } else if (loc.type == Locator::Cave) {
            uint64_t near_addr = loc.cave.near_abs;
            if (!near_addr && loc.cave.near_rva) {
                std::wstring mod = Widen(loc.cave.module.c_str());
                uint64_t base = 0;
                if (ModBase(*st.client, mod.empty() ? nullptr : mod.c_str(), &base)) {
                    near_addr = base + loc.cave.near_rva;
                }
            }
            HdlCaveQuery q{};
            q.min_size = loc.cave.min_size ? loc.cave.min_size : 16;
            q.fill_byte = loc.cave.fill;
            q.max_results = 64;
            q.near_addr = near_addr;
            q.max_distance = near_addr ? 0x7FFFFFFFull : 0;
            std::wstring mod = Widen(loc.cave.module.c_str());
            q.module_or_null = mod.empty() ? nullptr : mod.c_str();
            if (!mod.empty()) {
                q.search_flags = HDL_SEARCH_MODULE | HDL_SEARCH_IMAGE;
            }
            std::vector<HdlCaveInfo> caves;
            auto s = FindCaves(*st.client, q, &caves);
            const size_t bi = ScoreBestCave(caves, near_addr ? near_addr : 0);
            if (s && bi != static_cast<size_t>(-1)) {
                loc.last_addr = caves[bi].addr;
                loc.cave.last_size = caves[bi].size;
                loc.last_ok = true;
                ++ok;
                Wlog(log, L"[OK] %hs cave -> %016llx size=%llu", in.name.c_str(),
                     static_cast<unsigned long long>(caves[bi].addr),
                     static_cast<unsigned long long>(caves[bi].size));
            } else {
                Wlog(log, L"[FAIL] %hs cave status=%ls", in.name.c_str(), StatusName(s.status));
            }
        } else if (loc.type == Locator::Stub) {
            uint64_t target = loc.stub.target_abs;
            if (!target && !loc.stub.target_interest.empty()) {
                target = ResolveInterestAddr(st, loc.stub.target_interest.c_str());
            }
            if (!target) {
                Wlog(log, L"[FAIL] %hs stub no target", in.name.c_str());
                return;
            }
            HdlStubDesc desc{};
            desc.kind = loc.stub.kind;
            desc.target = target;
            desc.steal_from = loc.stub.steal_min ? target : 0;
            desc.steal_min_bytes = loc.stub.steal_min;
            desc.alloc_rx = 1;
            HdlStubResult result{};
            auto s = BuildStub(*st.client, desc, &result);
            if (s && result.stub_va) {
                loc.stub.last_stub_va = result.stub_va;
                loc.last_addr = result.stub_va;
                loc.last_ok = true;
                ++ok;
                Wlog(log, L"[OK] %hs stub -> %016llx", in.name.c_str(),
                     static_cast<unsigned long long>(result.stub_va));
            } else {
                Wlog(log, L"[FAIL] %hs stub status=%ls", in.name.c_str(), StatusName(s.status));
            }
        }
    };

    auto revalidate_patch = [&](Interest& in, Locator& loc) {
        const uint64_t prev_addr = loc.last_addr;
        loc.last_ok = false;
        loc.last_addr = 0;

        uint64_t addr = prev_addr;
        if (!loc.patch.target_interest.empty()) {
            const uint64_t t = ResolveInterestAddr(st, loc.patch.target_interest.c_str());
            if (t) {
                addr = t;
            }
        }
        if (!addr) {
            if (const Locator* stub = FindSiblingStub(in)) {
                if (stub->stub.target_abs) {
                    addr = stub->stub.target_abs;
                }
            }
        }
        if (!addr) {
            Wlog(log, L"[FAIL] %hs patch no target addr", in.name.c_str());
            return;
        }

        if (!apply) {
            loc.last_addr = addr;
            loc.last_ok = true;
            ++ok;
            Wlog(log, L"[OK] %hs patch target -> %016llx (not applied)", in.name.c_str(),
                 static_cast<unsigned long long>(addr));
            return;
        }

        std::vector<uint8_t> patch_bytes;
        const Locator* stub = FindSiblingStub(in);
        if (stub && stub->stub.last_stub_va) {
            if (!EncodeJmpToStub(*st.client, stub->stub.last_stub_va, stub->stub.steal_min,
                                 &patch_bytes, log)) {
                Wlog(log, L"[FAIL] %hs patch restitch encode", in.name.c_str());
                return;
            }
        } else {
            const std::wstring hex = Utf8ToWide(loc.patch.bytes_hex);
            if (!ParseHexBytes(hex.c_str(), patch_bytes) || patch_bytes.empty()) {
                Wlog(log, L"[FAIL] %hs patch bad bytes_hex", in.name.c_str());
                return;
            }
        }

        const char* patch_name = !loc.patch.name.empty() ? loc.patch.name.c_str() : in.name.c_str();
        uint64_t handle = 0;
        if (!CreateAndMaybeEnablePatch(*st.client, addr, patch_bytes.data(),
                                       static_cast<uint32_t>(patch_bytes.size()), patch_name,
                                       loc.patch.enabled_intent, &handle, log)) {
            Wlog(log, L"[FAIL] %hs patch apply", in.name.c_str());
            return;
        }

        loc.patch.bytes_hex = HexOf(patch_bytes.data(), patch_bytes.size());
        loc.patch.last_handle = handle;
        loc.last_addr = addr;
        loc.last_ok = true;
        ++ok;
        st.last_patch_handle = handle;
        st.last_patch_addr = addr;
        st.last_patch_bytes_hex = loc.patch.bytes_hex;
        if (loc.patch.enabled_intent) {
            Wlog(log, L"[OK] %hs patch applied+enabled handle=%llu at %016llx", in.name.c_str(),
                 static_cast<unsigned long long>(handle), static_cast<unsigned long long>(addr));
        } else {
            Wlog(log, L"[OK] %hs patch created (disabled) handle=%llu at %016llx", in.name.c_str(),
                 static_cast<unsigned long long>(handle), static_cast<unsigned long long>(addr));
        }
    };

    /* Pass 1: resolve/rebuild everything except patches so stub VAs and
     * target_interest addresses are fresh before apply. */
    for (auto& in : st.store.interests) {
        for (auto& loc : in.locators) {
            if (loc.type == Locator::Patch) {
                continue;
            }
            revalidate_non_patch(in, loc);
        }
    }
    /* Pass 2: patches (address-only or apply). */
    for (auto& in : st.store.interests) {
        for (auto& loc : in.locators) {
            if (loc.type != Locator::Patch) {
                continue;
            }
            revalidate_patch(in, loc);
        }
    }
    return ok;
}

StabilizeResult RecipeAction(ControllerState& st, const char* action_name, uint64_t watch_fn,
                             LogFn log, const std::function<bool()>& wait_user) {
    StabilizeResult fail;
    if (!EnsureDiscoverSession(st, log) || !watch_fn || !action_name) {
        return fail;
    }
    auto s = DiscoverWatch(*st.client, st.discover_session, watch_fn, 0);
    if (!s) {
        Wlog(log, L"watch failed status=%ls", StatusName(s.status));
        return fail;
    }
    s = DiscoverActionBegin(*st.client, st.discover_session, action_name);
    if (!s) {
        Wlog(log, L"action-begin failed status=%ls", StatusName(s.status));
        return fail;
    }
    Wlog(log, L"Action '%hs' open — trigger in target, then continue", action_name);
    if (wait_user && !wait_user()) {
        DiscoverActionEnd(*st.client, st.discover_session);
        return fail;
    }
    s = DiscoverActionEnd(*st.client, st.discover_session);
    if (!s) {
        Wlog(log, L"action-end failed status=%ls", StatusName(s.status));
        return fail;
    }
    st.last_rank.clear();
    s = DiscoverRank(*st.client, st.discover_session, action_name, &st.last_rank);
    if (!s || st.last_rank.empty()) {
        Wlog(log, L"rank failed or empty status=%ls", StatusName(s.status));
        return fail;
    }
    for (size_t i = 0; i < st.last_rank.size() && i < 8; ++i) {
        const auto& c = st.last_rank[i];
        Wlog(log, L"  rank[%zu] id=%llu conf=%u addr=%016llx tag=%hs", i,
             static_cast<unsigned long long>(c.id), c.confidence,
             static_cast<unsigned long long>(c.address), c.tag);
    }
    return StabilizeCandidate(st, st.last_rank[0].id, nullptr, log);
}

int RecipeConstrain(ControllerState& st, uint32_t object_size,
                    const std::vector<HdlFieldPred>& preds, uint32_t search_flags,
                    const wchar_t* module, LogFn log) {
    if (!EnsureDiscoverSession(st, log) || preds.empty()) {
        return 1;
    }
    auto s = DiscoverConstraint(*st.client, st.discover_session, object_size, preds, search_flags,
                                module, 64, "constrain");
    if (!s) {
        Wlog(log, L"constraint scan failed status=%ls", StatusName(s.status));
        return 1;
    }
    std::vector<HdlCandidate> cands;
    s = DiscoverGetCandidates(*st.client, st.discover_session, &cands);
    if (!s) {
        return 1;
    }
    uint32_t n = 0;
    for (const auto& c : cands) {
        if (c.kind == HDL_CAND_OBJECT) {
            Wlog(log, L"  obj id=%llu addr=%016llx tag=%hs", static_cast<unsigned long long>(c.id),
                 static_cast<unsigned long long>(c.address), c.tag);
            if (!st.last_object) {
                st.last_object = c.address;
            }
            ++n;
        }
    }
    Wlog(log, L"constraint objects=%u", n);
    if (st.last_object) {
        DiscoverCluster(*st.client, st.discover_session, st.last_object, object_size, search_flags,
                        module, 64);
    }
    return n ? 0 : 1;
}

int RecipePlace(ControllerState& st, const char* interest_name, uint64_t near_addr,
                const wchar_t* module, LogFn log) {
    if (!st.client || !interest_name || !near_addr) {
        return 1;
    }
    HdlCaveQuery q{};
    q.min_size = 16;
    q.fill_byte = 0xCC;
    q.max_results = 64;
    q.near_addr = near_addr;
    q.max_distance = 0x7FFFFFFFull;
    q.module_or_null = module;
    if (module && module[0]) {
        q.search_flags = HDL_SEARCH_MODULE | HDL_SEARCH_IMAGE | HDL_SEARCH_EXECUTABLE;
    } else {
        q.search_flags = HDL_SEARCH_IMAGE | HDL_SEARCH_EXECUTABLE;
    }
    std::vector<HdlCaveInfo> caves;
    auto s = FindCaves(*st.client, q, &caves);
    Interest in;
    if (Interest* existing = st.store.Find(interest_name)) {
        in = *existing;
    } else {
        in.name = interest_name;
        in.kind = "function";
    }

    Locator cave_loc;
    cave_loc.type = Locator::Cave;
    if (module) {
        char mb[260];
        WideCharToMultiByte(CP_UTF8, 0, module, -1, mb, sizeof(mb), nullptr, nullptr);
        cave_loc.cave.module = mb;
    }
    cave_loc.cave.near_abs = near_addr;
    cave_loc.cave.min_size = 16;
    cave_loc.cave.fill = 0xCC;

    const size_t bi = ScoreBestCave(caves, near_addr);
    if (s && bi != static_cast<size_t>(-1)) {
        cave_loc.last_addr = caves[bi].addr;
        cave_loc.cave.last_size = caves[bi].size;
        cave_loc.last_ok = true;
        st.last_cave_addr = caves[bi].addr;
        st.last_cave_size = caves[bi].size;
        Wlog(log, L"place cave %016llx size=%llu (dist=%llu)",
             static_cast<unsigned long long>(caves[bi].addr),
             static_cast<unsigned long long>(caves[bi].size),
             static_cast<unsigned long long>(Dist(caves[bi].addr, near_addr)));
    } else {
        uint64_t alloc = 0;
        auto as =
            AllocNear(*st.client, near_addr, 0x7FFFFFFFull, 0x1000, PAGE_EXECUTE_READWRITE, &alloc);
        if (!as || !alloc) {
            Wlog(log, L"place: no cave and AllocNear failed status=%ls", StatusName(as.status));
            return 1;
        }
        cave_loc.last_addr = alloc;
        cave_loc.cave.last_size = 0x1000;
        cave_loc.last_ok = true;
        st.last_cave_addr = alloc;
        st.last_cave_size = 0x1000;
        Wlog(log, L"place AllocNear fallback %016llx", static_cast<unsigned long long>(alloc));
    }

    /* Replace existing cave locator or append */
    bool replaced = false;
    for (auto& loc : in.locators) {
        if (loc.type == Locator::Cave) {
            loc = cave_loc;
            replaced = true;
            break;
        }
    }
    if (!replaced) {
        in.locators.push_back(std::move(cave_loc));
    }
    st.store.AddOrReplace(std::move(in));
    Wlog(log, L"store updated interest '%hs' with cave/alloc locator", interest_name);
    return 0;
}

int RecipeStitch(ControllerState& st, const char* interest_name, uint64_t target_addr, int32_t kind,
                 uint32_t steal_min, LogFn log) {
    if (!st.client || !interest_name || !target_addr) {
        return 1;
    }
    HdlStubDesc desc{};
    desc.kind = kind ? kind : HDL_STUB_MOV_RAX_JMP;
    desc.target = target_addr;
    desc.steal_from = steal_min ? target_addr : 0;
    desc.steal_min_bytes = steal_min;
    desc.alloc_rx = 1;
    HdlStubResult stub{};
    auto s = BuildStub(*st.client, desc, &stub);
    if (!s || !stub.stub_va) {
        Wlog(log, L"BuildStub failed status=%ls", StatusName(s.status));
        return 1;
    }
    st.last_stub = stub;
    st.last_stub_va = stub.stub_va;
    Wlog(log, L"stub_va=%016llx stolen=%u", static_cast<unsigned long long>(stub.stub_va),
         stub.stolen_bytes);

    std::vector<uint8_t> patch;
    if (!EncodeJmpToStub(*st.client, stub.stub_va, steal_min, &patch, log)) {
        return 1;
    }

    uint64_t handle = 0;
    if (!CreateAndMaybeEnablePatch(*st.client, target_addr, patch.data(),
                                   static_cast<uint32_t>(patch.size()), interest_name, 1, &handle,
                                   log)) {
        return 1;
    }
    st.last_patch_handle = handle;
    st.last_patch_addr = target_addr;
    st.last_patch_bytes_hex = HexOf(patch.data(), patch.size());
    Wlog(log, L"patch handle=%llu enabled at %016llx", static_cast<unsigned long long>(handle),
         static_cast<unsigned long long>(target_addr));

    Interest in;
    if (Interest* existing = st.store.Find(interest_name)) {
        in = *existing;
    } else {
        in.name = interest_name;
        in.kind = "function";
    }

    Locator stub_loc;
    stub_loc.type = Locator::Stub;
    stub_loc.stub.kind = desc.kind;
    stub_loc.stub.target_abs = target_addr;
    stub_loc.stub.steal_min = steal_min;
    stub_loc.stub.last_stub_va = stub.stub_va;
    stub_loc.last_addr = stub.stub_va;
    stub_loc.last_ok = true;

    Locator patch_loc;
    patch_loc.type = Locator::Patch;
    patch_loc.patch.name = interest_name;
    patch_loc.patch.bytes_hex = st.last_patch_bytes_hex;
    patch_loc.patch.enabled_intent = 1;
    patch_loc.patch.last_handle = handle;
    patch_loc.last_addr = target_addr;
    patch_loc.last_ok = true;

    auto upsert = [&](Locator&& neu) {
        for (auto& loc : in.locators) {
            if (loc.type == neu.type) {
                loc = std::move(neu);
                return;
            }
        }
        in.locators.push_back(std::move(neu));
    };
    upsert(std::move(stub_loc));
    upsert(std::move(patch_loc));
    st.store.AddOrReplace(std::move(in));
    Wlog(log, L"store updated interest '%hs' with stub+patch", interest_name);
    return 0;
}

int RecipeExpandStruct(ControllerState& st, uint64_t base, uint32_t size, LogFn log) {
    if (!EnsureDiscoverSession(st, log) || !base || !size) {
        return 1;
    }
    auto s = DiscoverWatchRegion(*st.client, st.discover_session, base, size);
    if (!s) {
        Wlog(log, L"watch-region failed status=%ls", StatusName(s.status));
        return 1;
    }
    Wlog(log, L"watch-region on %016llx size=%u (session=%llu)",
         static_cast<unsigned long long>(base), size,
         static_cast<unsigned long long>(st.discover_session));
    Wlog(log, L"Next: discover-action-begin --session %llu --name <act>",
         static_cast<unsigned long long>(st.discover_session));
    Wlog(log, L"      trigger writes in target, discover-action-end, then:");
    Wlog(log, L"      discover-heat --session %llu --addr %016llx",
         static_cast<unsigned long long>(st.discover_session),
         static_cast<unsigned long long>(base));
    return 0;
}

StabilizeResult StabilizeCandidate(ControllerState& st, uint64_t cand_id, const wchar_t* module,
                                   LogFn log) {
    StabilizeResult out;
    if (!EnsureDiscoverSession(st, log) || !cand_id) {
        return out;
    }
    memset(&st.last_synth, 0, sizeof(st.last_synth));
    auto s =
        DiscoverSynth(*st.client, st.discover_session, cand_id, 0, 24,
                      HDL_SEARCH_IMAGE | (module ? HDL_SEARCH_MODULE : 0), module, &st.last_synth);
    if (!s) {
        Wlog(log, L"synth failed status=%ls", StatusName(s.status));
        return out;
    }
    Wlog(log, L"synth hits=%u resolved=%016llx\n  %hs", st.last_synth.unique_hits,
         static_cast<unsigned long long>(st.last_synth.resolved_addr), st.last_synth.pattern);

    std::string name = "cand";
    std::string kind = "function";
    std::string tag;
    for (const auto& c : st.last_rank) {
        if (c.id == cand_id) {
            if (c.tag[0]) {
                name = c.tag;
                tag = c.tag;
            } else {
                char buf[64];
                snprintf(buf, sizeof(buf), "cand_%llu", static_cast<unsigned long long>(c.id));
                name = buf;
            }
            if (c.kind == HDL_CAND_OBJECT) {
                kind = "object";
            } else if (c.kind == HDL_CAND_FIELD) {
                kind = "field";
            } else if (c.kind == HDL_CAND_ADDRESS) {
                kind = "address";
            }
            break;
        }
    }
    if (name == "cand") {
        char buf[64];
        snprintf(buf, sizeof(buf), "cand_%llu", static_cast<unsigned long long>(cand_id));
        name = buf;
    }

    Interest in;
    in.name = name;
    in.kind = kind;
    in.tag = tag;
    Locator loc;
    loc.type = Locator::Pattern;
    loc.pattern.pattern = st.last_synth.pattern;
    loc.pattern.pattern_offset = st.last_synth.pattern_offset;
    loc.pattern.rip_disp = st.last_synth.rip_disp_offset;
    loc.pattern.rip_len = st.last_synth.rip_instr_len;
    loc.pattern.module = st.store.module;
    if (module) {
        char mb[260];
        WideCharToMultiByte(CP_UTF8, 0, module, -1, mb, sizeof(mb), nullptr, nullptr);
        loc.pattern.module = mb;
    }
    loc.last_addr = st.last_synth.resolved_addr;
    loc.last_ok = true;
    in.locators.push_back(std::move(loc));
    st.store.AddOrReplace(std::move(in));
    Wlog(log, L"store add/replace '%hs' from stabilize", name.c_str());
    out.rc = 0;
    out.interest_name = std::move(name);
    return out;
}

static const HdlFingerprintTag* PrimaryOf(const std::vector<HdlFingerprintTag>& tags,
                                          uint32_t category) {
    for (const auto& t : tags) {
        if (t.category == category && (t.flags & HDL_FP_PRIMARY)) {
            return &t;
        }
    }
    return nullptr;
}

int RecipeSuggest(ControllerState& st, LogFn log) {
    if (!st.client) {
        Wlog(log, L"no client");
        return 1;
    }
    std::vector<HdlFingerprintTag> tags;
    const IpcStatus s = Fingerprint(*st.client, HDL_FP_SCAN_DEFAULT, &tags);
    if (!s) {
        Wlog(log, L"fingerprint failed status=%d", s.status);
        return 1;
    }
    Wlog(log, L"fingerprint: %u tags", static_cast<unsigned>(tags.size()));
    for (const auto& t : tags) {
        if (!(t.flags & HDL_FP_PRIMARY)) {
            continue;
        }
        Wlog(log, L"  primary cat=%u id=%hs conf=%u  %hs", t.category, t.id, t.confidence,
             t.evidence);
    }

    const HdlFingerprintTag* ui = PrimaryOf(tags, HDL_FP_CAT_UI);
    const HdlFingerprintTag* gfx = PrimaryOf(tags, HDL_FP_CAT_GRAPHICS);
    const HdlFingerprintTag* rt = PrimaryOf(tags, HDL_FP_CAT_RUNTIME);
    const HdlFingerprintTag* eng = PrimaryOf(tags, HDL_FP_CAT_ENGINE);
    const HdlFingerprintTag* app = PrimaryOf(tags, HDL_FP_CAT_APP);
    const HdlFingerprintTag* lang = PrimaryOf(tags, HDL_FP_CAT_LANGUAGE);

    Wlog(log, L"suggestions (copy/paste; not auto-run):");

    if (ui && strcmp(ui->id, "win32") == 0) {
        Wlog(log, L"  discover-watch-import --dll user32.dll --import DispatchMessageW --args 1");
        Wlog(log, L"  call --main --module user32.dll ...   (UI thread for windowed targets)");
    }
    if (ui && (strcmp(ui->id, "wpf") == 0 || strcmp(ui->id, "winforms") == 0 ||
               strcmp(ui->id, "winui") == 0)) {
        Wlog(log,
             L"  managed UI: prefer import/watch over native RTTI; JIT heaps make AOB brittle");
    }
    if (ui && (strcmp(ui->id, "qt5") == 0 || strcmp(ui->id, "qt6") == 0)) {
        Wlog(log, L"  scope scans with --module Qt5Core.dll / Qt6Core.dll (or Gui/Widgets)");
    }

    if (gfx && strcmp(gfx->id, "d3d11") == 0) {
        Wlog(log, L"  discover-watch-import --dll dxgi.dll --import Present --args 2");
        Wlog(log, L"  (or Present1 on IDXGISwapChain1; resolve via exports/imports first)");
    }
    if (gfx && strcmp(gfx->id, "d3d12") == 0) {
        Wlog(log, L"  frame sync often via DXGI Present; also watch D3D12 command queues");
        Wlog(log, L"  discover-watch-import --dll dxgi.dll --import Present --args 2");
    }
    if (gfx && strcmp(gfx->id, "d3d9") == 0) {
        Wlog(log, L"  discover-watch-import --dll d3d9.dll --import Direct3DCreate9 --args 1");
        Wlog(log, L"  then rank around EndScene/Present on the device vtable");
    }
    if (gfx && strcmp(gfx->id, "opengl") == 0) {
        Wlog(log, L"  discover-watch-import --dll opengl32.dll --import wglSwapBuffers --args 1");
    }
    if (gfx && strcmp(gfx->id, "vulkan") == 0) {
        Wlog(log, L"  vulkan: prefer module-scoped scans; Present is often via swapchain fn table");
        Wlog(log, L"  modules / exports --module vulkan-1.dll  then discover-watch on resolved VA");
    }

    if (rt && (strcmp(rt->id, "coreclr") == 0 || strcmp(rt->id, "dotnet_framework") == 0 ||
               strcmp(rt->id, "mono") == 0)) {
        Wlog(log, L"  managed runtime: avoid native RTTI; use imports/exports and discover-watch");
        Wlog(log, L"  AOB on JIT code heaps is unstable across runs");
    }
    if (rt && (strcmp(rt->id, "electron") == 0 || strcmp(rt->id, "nodejs") == 0 ||
               strcmp(rt->id, "cef") == 0)) {
        Wlog(log, L"  web/host runtime: UI is Chromium; prefer CEF/Electron modules for --module");
    }

    if (eng && strcmp(eng->id, "unity") == 0) {
        Wlog(log, L"  unity: --module GameAssembly.dll or UnityPlayer.dll for scans/recipes");
    }
    if (eng && strcmp(eng->id, "unreal") == 0) {
        Wlog(log, L"  unreal: scope to *-Win64-Shipping.exe / UnrealEditor modules");
    }
    if (eng && strcmp(eng->id, "godot") == 0) {
        Wlog(log, L"  godot: scope scans to the godot module / exe basename");
    }

    if (app && strcmp(app->id, "subsystem_gui") == 0) {
        Wlog(log, L"  GUI subsystem: prefer call --main for UI-thread APIs");
    }
    if (lang && strcmp(lang->id, "native") == 0 && !rt && !eng) {
        Wlog(log, L"  native: vtable/RTTI helpers and discover-constrain are fair game");
    }

    Wlog(log, L"  fingerprint          # full tag dump");
    Wlog(log, L"  recipe action <name> <watch_hex>   # after you pick a watch target");
    return 0;
}

} // namespace hdlcli
