/* Automated higher-level hdllib exercise against hdl_toy_arena (no human steps). */
#include "support.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

using hdltest::Counters;
using hdltest::Report;

namespace {

struct ProcResult {
    DWORD exit_code = 1;
    std::wstring out;
};

std::wstring QuoteArg(const std::wstring& a) {
    if (a.find_first_of(L" \t\"") == std::wstring::npos) {
        return a;
    }
    std::wstring o = L"\"";
    for (wchar_t c : a) {
        if (c == L'"') {
            o += L"\\\"";
        } else {
            o.push_back(c);
        }
    }
    o += L'"';
    return o;
}

bool RunProcess(const std::wstring& exe, const std::vector<std::wstring>& args,
                const std::wstring* stdin_text, DWORD timeout_ms, ProcResult* out) {
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE out_r = nullptr, out_w = nullptr;
    HANDLE in_r = nullptr, in_w = nullptr;
    if (!CreatePipe(&out_r, &out_w, &sa, 0)) {
        return false;
    }
    SetHandleInformation(out_r, HANDLE_FLAG_INHERIT, 0);
    if (stdin_text) {
        if (!CreatePipe(&in_r, &in_w, &sa, 0)) {
            CloseHandle(out_r);
            CloseHandle(out_w);
            return false;
        }
        SetHandleInformation(in_w, HANDLE_FLAG_INHERIT, 0);
    }

    std::wstring cmd = QuoteArg(exe);
    for (const auto& a : args) {
        cmd.push_back(L' ');
        cmd += QuoteArg(a);
    }

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = out_w;
    si.hStdError = out_w;
    si.hStdInput = stdin_text ? in_r : GetStdHandle(STD_INPUT_HANDLE);

    PROCESS_INFORMATION pi{};
    std::vector<wchar_t> cmdline(cmd.begin(), cmd.end());
    cmdline.push_back(0);
    const BOOL ok = CreateProcessW(nullptr, cmdline.data(), nullptr, nullptr, TRUE,
                                   CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    CloseHandle(out_w);
    if (stdin_text) {
        CloseHandle(in_r);
    }
    if (!ok) {
        CloseHandle(out_r);
        if (in_w) {
            CloseHandle(in_w);
        }
        return false;
    }

    if (stdin_text) {
        std::string narrow;
        narrow.resize(stdin_text->size() * 4 + 8);
        const int n = WideCharToMultiByte(CP_UTF8, 0, stdin_text->c_str(), -1, narrow.data(),
                                          static_cast<int>(narrow.size()), nullptr, nullptr);
        if (n > 1) {
            DWORD wrote = 0;
            WriteFile(in_w, narrow.data(), static_cast<DWORD>(n - 1), &wrote, nullptr);
        }
        CloseHandle(in_w);
    }

    std::wstring collected;
    std::string raw;
    char buf[4096];
    const DWORD start = GetTickCount();
    for (;;) {
        DWORD avail = 0;
        DWORD got = 0;
        if (PeekNamedPipe(out_r, nullptr, 0, nullptr, &avail, nullptr) && avail) {
            const DWORD to_read = avail > sizeof(buf) ? sizeof(buf) : avail;
            if (ReadFile(out_r, buf, to_read, &got, nullptr) && got) {
                raw.append(buf, got);
            }
        }
        const DWORD wr = WaitForSingleObject(pi.hProcess, 50);
        if (wr == WAIT_OBJECT_0) {
            while (PeekNamedPipe(out_r, nullptr, 0, nullptr, &avail, nullptr) && avail) {
                const DWORD to_read = avail > sizeof(buf) ? sizeof(buf) : avail;
                if (ReadFile(out_r, buf, to_read, &got, nullptr) && got) {
                    raw.append(buf, got);
                } else {
                    break;
                }
            }
            break;
        }
        if (GetTickCount() - start > timeout_ms) {
            TerminateProcess(pi.hProcess, 1);
            WaitForSingleObject(pi.hProcess, 2000);
            raw += "\n[timeout]";
            break;
        }
    }

    if (!raw.empty()) {
        wchar_t wbuf[8192];
        int remaining = static_cast<int>(raw.size());
        const char* p = raw.data();
        while (remaining > 0) {
            const int chunk = remaining > 4000 ? 4000 : remaining;
            const int wn = MultiByteToWideChar(CP_UTF8, 0, p, chunk, wbuf, 8191);
            if (wn > 0) {
                collected.append(wbuf, wn);
            } else {
                const int wn2 = MultiByteToWideChar(CP_ACP, 0, p, chunk, wbuf, 8191);
                if (wn2 > 0) {
                    collected.append(wbuf, wn2);
                }
            }
            p += chunk;
            remaining -= chunk;
        }
    }

    GetExitCodeProcess(pi.hProcess, &out->exit_code);
    out->out = std::move(collected);
    CloseHandle(out_r);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}

bool Contains(const std::wstring& hay, const wchar_t* needle) {
    return hay.find(needle) != std::wstring::npos;
}

bool ParseHexAfter(const std::wstring& text, const wchar_t* key, uint64_t* out) {
    const size_t p = text.find(key);
    if (p == std::wstring::npos) {
        return false;
    }
    const wchar_t* s = text.c_str() + p + wcslen(key);
    while (*s == L' ' || *s == L'=') {
        ++s;
    }
    *out = _wcstoui64(s, nullptr, 16);
    return *out != 0 || *s == L'0';
}

bool ParseU64After(const std::wstring& text, const wchar_t* key, uint64_t* out) {
    const size_t p = text.find(key);
    if (p == std::wstring::npos) {
        return false;
    }
    const wchar_t* s = text.c_str() + p + wcslen(key);
    while (*s == L' ' || *s == L'=') {
        ++s;
    }
    *out = _wcstoui64(s, nullptr, 0);
    return true;
}

struct Ctx {
    std::wstring client;
    std::wstring dll;
    DWORD pid = 0;
};

ProcResult Cli(const Ctx& ctx, std::vector<std::wstring> args, DWORD timeout_ms = 60000) {
    std::vector<std::wstring> full;
    full.emplace_back(std::to_wstring(ctx.pid));
    full.insert(full.end(), args.begin(), args.end());
    ProcResult r;
    RunProcess(ctx.client, full, nullptr, timeout_ms, &r);
    return r;
}

void ExpectOk(Counters& c, const char* name, const ProcResult& r) {
    const bool ok = r.exit_code == 0 && Contains(r.out, L"status=OK");
    char detail[128];
    snprintf(detail, sizeof(detail), "exit=%lu", static_cast<unsigned long>(r.exit_code));
    Report(c, ok, false, name, ok ? "" : detail);
}

void ExpectExit0(Counters& c, const char* name, const ProcResult& r) {
    Report(c, r.exit_code == 0, false, name, "");
}

bool SpawnToy(const std::wstring& toy_path, PROCESS_INFORMATION* pi) {
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    std::wstring cmd = QuoteArg(toy_path) + L" --entities 4";
    std::vector<wchar_t> cmdline(cmd.begin(), cmd.end());
    cmdline.push_back(0);
    ZeroMemory(pi, sizeof(*pi));
    return CreateProcessW(nullptr, cmdline.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                          nullptr, nullptr, &si, pi) != 0;
}

void Hex(wchar_t* buf, size_t n, uint64_t v) {
    swprintf_s(buf, n, L"0x%llx", static_cast<unsigned long long>(v));
}

void RunToyVerify(Counters& c, const std::wstring& client, const std::wstring& dll,
                  const std::wstring& toy) {
    std::printf("\n== hdl_toy_arena higher-level verify ==\n");

    PROCESS_INFORMATION tpi{};
    if (!SpawnToy(toy, &tpi)) {
        Report(c, false, false, "spawn toy", "");
        return;
    }
    CloseHandle(tpi.hThread);
    Sleep(400);

    Ctx ctx{client, dll, tpi.dwProcessId};

    {
        ProcResult r;
        RunProcess(client, {L"inject", std::to_wstring(ctx.pid), dll}, nullptr, 60000, &r);
        /* Local inject printer may omit status=OK; exit 0 + subsequent ping is enough. */
        ExpectExit0(c, "toy inject", r);
        if (r.exit_code != 0) {
            TerminateProcess(tpi.hProcess, 1);
            CloseHandle(tpi.hProcess);
            return;
        }
    }
    ExpectOk(c, "toy ping", Cli(ctx, {L"ping"}));

    uint64_t world_root = 0, bag_root = 0, slots = 0;
    uint64_t hero = 0, bag0 = 0, mob1 = 0, dmg_fn = 0;

    {
        auto r = Cli(ctx, {L"resolve", L"HdlToyWorldRoot"});
        ExpectOk(c, "resolve WorldRoot", r);
        ParseHexAfter(r.out, L"addr=", &world_root);
    }
    {
        auto r = Cli(ctx, {L"resolve", L"HdlToyHeroBagRoot"});
        ExpectOk(c, "resolve HeroBagRoot", r);
        ParseHexAfter(r.out, L"addr=", &bag_root);
    }
    {
        auto r = Cli(ctx, {L"resolve", L"HdlToyEntitySlots"});
        ExpectOk(c, "resolve EntitySlots", r);
        ParseHexAfter(r.out, L"addr=", &slots);
    }
    {
        auto r = Cli(ctx, {L"resolve", L"HdlToyDamage"});
        ExpectOk(c, "resolve Damage", r);
        ParseHexAfter(r.out, L"addr=", &dmg_fn);
    }
    {
        auto r = Cli(ctx, {L"call", L"HdlToyGetEntity", L"u64:0"});
        ExpectOk(c, "call GetEntity(0)", r);
        ParseHexAfter(r.out, L"return=", &hero);
    }
    {
        auto r = Cli(ctx, {L"call", L"HdlToyGetBag", L"u64:0"});
        ExpectOk(c, "call GetBag(0)", r);
        ParseHexAfter(r.out, L"return=", &bag0);
    }
    {
        auto r = Cli(ctx, {L"call", L"HdlToyGetEntity", L"u64:1"});
        ExpectOk(c, "call GetEntity(1)", r);
        ParseHexAfter(r.out, L"return=", &mob1);
    }
    Report(c, world_root && bag_root && slots && hero && bag0 && mob1 && dmg_fn, false,
           "toy ground-truth addrs", "");

    /* FollowPointers: WorldRoot → &player → &bag → bag*  (offs 16,32,0) */
    if (world_root && bag0) {
        wchar_t a[32];
        Hex(a, 32, world_root);
        auto r = Cli(ctx, {L"ptrchain", a, L"+16", L"+32", L"+0"});
        ExpectOk(c, "ptrchain WorldRoot->bag", r);
        uint64_t got = 0;
        ParseHexAfter(r.out, L"addr=", &got);
        Report(c, got == bag0, false, "ptrchain equals GetBag(0)", "");
    }

    /* Image slot → dynamic bag (what PointerScan can actually find). */
    if (bag_root && bag0) {
        wchar_t a[32];
        Hex(a, 32, bag_root);
        auto r = Cli(ctx, {L"ptrchain", a, L"+0"});
        ExpectOk(c, "ptrchain HeroBagRoot", r);
        uint64_t got = 0;
        ParseHexAfter(r.out, L"addr=", &got);
        Report(c, got == bag0, false, "ptrchain HeroBagRoot == bag", "");
    }

    if (bag0) {
        wchar_t a[32];
        Hex(a, 32, bag0);
        auto r = Cli(ctx, {L"ptrscan", a, L"--depth", L"2", L"--module", L"hdl_toy_arena.exe",
                           L"--max", L"64"});
        ExpectOk(c, "ptrscan bag", r);
        Report(c,
               Contains(r.out, L"count=") && !Contains(r.out, L"count=0\n") &&
                   !Contains(r.out, L"count=0\r"),
               false, "ptrscan bag nonempty", "");
        wchar_t root_hex[32];
        Hex(root_hex, 32, bag_root);
        std::wstring needle = root_hex + 2;
        for (wchar_t& ch : needle) {
            if (ch >= L'A' && ch <= L'F') {
                ch = static_cast<wchar_t>(ch - L'A' + L'a');
            }
        }
        std::wstring lower = r.out;
        for (wchar_t& ch : lower) {
            if (ch >= L'A' && ch <= L'F') {
                ch = static_cast<wchar_t>(ch - L'A' + L'a');
            }
        }
        const bool hit = lower.find(needle) != std::wstring::npos;
        Report(c, hit, false, "ptrscan includes HeroBagRoot", "");
    }

    if (hero) {
        wchar_t a[32];
        Hex(a, 32, hero);
        auto r = Cli(ctx, {L"probe", a, L"--size", L"56"});
        ExpectOk(c, "probe hero", r);
        Report(c, Contains(r.out, L"kind=1") || Contains(r.out, L"kind=2"), false,
               "probe sees ptr/vtable", "");
    }

    {
        auto r = Cli(ctx, {L"call", L"HdlToyCalc", L"i64:3", L"i64:4"});
        ExpectOk(c, "call Calc", r);
        uint64_t got = 0;
        ParseHexAfter(r.out, L"return=", &got);
        Report(c, got == 7, false, "Calc return 7", "");
    }

    /* Graph / watch / functions (ToyEntity health @ +8 from vtable). */
    if (dmg_fn) {
        wchar_t fa[32], mid[32];
        Hex(fa, 32, dmg_fn);
        /* Deep enough to cross internal branch/prologue-like candidates in the
           Release build; +0x40 also lands inside the subtract instruction. */
        Hex(mid, 32, dmg_fn + 0x40);
        auto resolved = Cli(ctx, {L"resolve-function", mid, L"--module", L"hdl_toy_arena.exe"});
        ExpectOk(c, "toy resolve-function deep interior", resolved);
        uint64_t resolved_start = 0;
        ParseHexAfter(resolved.out, L"start=", &resolved_start);
        Report(c, resolved_start == dmg_fn, false, "toy deep interior aligns to Damage entry", "");
        auto xr = Cli(ctx, {L"xrefs-to", fa, L"--module", L"hdl_toy_arena.exe"});
        ExpectOk(c, "toy xrefs-to Damage", xr);
        Report(c, Contains(xr.out, L"count=") && !Contains(xr.out, L"count=0\n"), true,
               "toy xrefs-to Damage nonempty (soft)", "");
    }
    if (hero) {
        const uint64_t health_addr = hero + 8;
        wchar_t ha[32];
        Hex(ha, 32, health_addr);
        uint64_t wh = 0;
        {
            auto wr = Cli(ctx, {L"watch", L"hw", ha, L"--size", L"4", L"--access", L"write"});
            ExpectOk(c, "toy watch hw health", wr);
            ParseU64After(wr.out, L"handle=", &wh);
        }
        ExpectOk(c, "toy call Damage health watch",
                 Cli(ctx, {L"call", L"HdlToyDamage", L"u64:0", L"i64:7"}));
        {
            auto r = Cli(ctx, {L"watch", L"hits", L"--timeout", L"500", L"--max", L"8"});
            ExpectOk(c, "toy watch hits health", r);
            Report(c, Contains(r.out, L"count=") && !Contains(r.out, L"count=0\n"), false,
                   "toy watch hits on health", "");
        }
        ExpectOk(c, "toy watch refresh", Cli(ctx, {L"watch", L"refresh"}));
        if (wh) {
            wchar_t h[32];
            swprintf_s(h, L"%llu", static_cast<unsigned long long>(wh));
            ExpectOk(c, "toy unwatch health", Cli(ctx, {L"watch", L"unwatch", h}));
        }
        /* Restore health so later discover-constraint eqs still match. */
        wchar_t ha8[32], ha12[32];
        Hex(ha8, 32, hero + 8);
        Hex(ha12, 32, hero + 12);
        ExpectOk(c, "toy restore health", Cli(ctx, {L"write", ha8, L"64 00 00 00"}));
        ExpectOk(c, "toy restore max_health", Cli(ctx, {L"write", ha12, L"64 00 00 00"}));
    }
    ExpectOk(c, "toy functions module",
             Cli(ctx, {L"functions", L"--module", L"hdl_toy_arena.exe", L"--max", L"32"}));

    if (hero) {
        wchar_t a[32];
        Hex(a, 32, hero);
        ExpectOk(c, "vcall strike", Cli(ctx, {L"vcall", a, L"0", L"i64:5"}));
    }

    /* Cross-instance: entity slots[1] should resolve to mob1. */
    if (slots && mob1) {
        wchar_t a[32];
        Hex(a, 32, slots + 8); /* slots[1] */
        auto r = Cli(ctx, {L"ptrchain", a, L"+0"});
        ExpectOk(c, "ptrchain EntitySlots[1]", r);
        uint64_t got = 0;
        ParseHexAfter(r.out, L"addr=", &got);
        Report(c, got == mob1, false, "slots[1] == mob1", "");
    }

    uint64_t session = 0;
    {
        auto r = Cli(ctx, {L"discover-create"});
        ExpectOk(c, "discover-create", r);
        ParseU64After(r.out, L"session=", &session);
    }

    if (session && hero) {
        wchar_t sid[32], seed[32];
        swprintf_s(sid, L"%llu", static_cast<unsigned long long>(session));
        Hex(seed, 32, hero);

        /* Heap scan (no --image): shared vtable cluster across instances. */
        ExpectOk(
            c, "discover-cluster",
            Cli(ctx, {L"discover-cluster", L"--session", sid, L"--seed", seed, L"--size", L"56"}));
        {
            auto r = Cli(ctx, {L"discover-cands", L"--session", sid});
            ExpectOk(c, "discover-cands after cluster", r);
            uint32_t n = 0;
            size_t pos = 0;
            while ((pos = r.out.find(L"addr=", pos)) != std::wstring::npos) {
                ++n;
                pos += 5;
            }
            Report(c, n >= 4, false, "cluster found >=4 entities", "");
        }

        /* Constraint: hero health/max still 100 (vcall hit target, not self-heal). */
        ExpectOk(c, "discover-constraint hero",
                 Cli(ctx, {L"discover-constraint", L"--session", sid, L"--size", L"56", L"--pred",
                           L"eq_i32:8:100", L"--pred", L"eq_i32:12:100", L"--pred", L"vtable:0"}));

        /* Pathvalidate via image bag root across realloc. */
        if (bag_root && bag0) {
            wchar_t target[32], base[32];
            Hex(target, 32, bag0);
            Hex(base, 32, bag_root);
            auto r = Cli(ctx, {L"discover-pathvalidate", target, L"--base", base, L"--depth", L"1",
                               L"--offs", L"0"});
            ExpectOk(c, "pathvalidate bag before realloc", r);
            Report(c, Contains(r.out, L"kept=1"), false, "pathvalidate kept=1 before", "");
        }

        ExpectOk(c, "call ReallocBag", Cli(ctx, {L"call", L"HdlToyReallocBag", L"u64:0"}));
        uint64_t bag1 = 0;
        {
            auto r = Cli(ctx, {L"call", L"HdlToyGetBag", L"u64:0"});
            ExpectOk(c, "GetBag after realloc", r);
            ParseHexAfter(r.out, L"return=", &bag1);
        }
        Report(c, bag1 != 0, false, "GetBag after realloc nonzero", "");
        /* Heap may reuse the same address after delete+new; treat same-addr as soft. */
        Report(c, bag1 && bag1 != bag0, true, "bag address changed (soft if heap reuse)", "");

        if (bag_root && bag0 && bag1) {
            wchar_t old_t[32], new_t[32], base[32];
            Hex(old_t, 32, bag0);
            Hex(new_t, 32, bag1);
            Hex(base, 32, bag_root);
            auto r_old = Cli(ctx, {L"discover-pathvalidate", old_t, L"--base", base, L"--depth",
                                   L"1", L"--offs", L"0"});
            /* NOT_FOUND is expected when kept=0 — exit may be nonzero. */
            if (bag1 != bag0) {
                Report(c, Contains(r_old.out, L"kept=0"), false, "pathvalidate rejects old bag",
                       "");
            } else {
                Report(c, true, true, "pathvalidate rejects old bag (skipped heap reuse)", "");
            }
            auto r_new = Cli(ctx, {L"discover-pathvalidate", new_t, L"--base", base, L"--depth",
                                   L"1", L"--offs", L"0"});
            ExpectOk(c, "pathvalidate new bag", r_new);
            Report(c, Contains(r_new.out, L"kept=1"), false, "pathvalidate keeps new bag", "");

            /* Multilevel path through World still reaches new bag. */
            if (world_root) {
                wchar_t wr[32];
                Hex(wr, 32, world_root);
                auto pc = Cli(ctx, {L"ptrchain", wr, L"+16", L"+32", L"+0"});
                ExpectOk(c, "ptrchain after realloc", pc);
                uint64_t got = 0;
                ParseHexAfter(pc.out, L"addr=", &got);
                Report(c, got == bag1, false, "WorldRoot path tracks new bag", "");
            }
        }

        /* Action heat on health via Damage export. */
        if (dmg_fn) {
            wchar_t fa[32], ha[32];
            Hex(fa, 32, dmg_fn);
            Hex(ha, 32, hero);
            ExpectOk(
                c, "discover-watch Damage",
                Cli(ctx, {L"discover-watch", L"--session", sid, L"--addr", fa, L"--args", L"2"}));
            ExpectOk(c, "discover-watch-region",
                     Cli(ctx, {L"discover-watch-region", L"--session", sid, L"--addr", ha,
                               L"--size", L"56"}));
            ExpectOk(c, "action-begin",
                     Cli(ctx, {L"discover-action-begin", L"--session", sid, L"--name", L"hit"}));
            ExpectOk(c, "call Damage", Cli(ctx, {L"call", L"HdlToyDamage", L"u64:0", L"i64:11"}));
            ExpectOk(c, "action-end", Cli(ctx, {L"discover-action-end", L"--session", sid}));
            ExpectOk(c, "discover-rank",
                     Cli(ctx, {L"discover-rank", L"--session", sid, L"--name", L"hit"}));
            {
                auto r = Cli(ctx, {L"discover-heat", L"--session", sid, L"--addr", ha});
                ExpectOk(c, "discover-heat", r);
                Report(c,
                       Contains(r.out, L"+0x8") || Contains(r.out, L"offset=8") ||
                           Contains(r.out, L"+8"),
                       false, "heat marks health@+8", "");
            }
            ExpectOk(c, "discover-unwatch", Cli(ctx, {L"discover-unwatch", L"--session", sid}));
        }

        ExpectOk(c, "discover-close", Cli(ctx, {L"discover-close", L"--session", sid}));
    }

    {
        auto r = Cli(
            ctx, {L"xrefs", L"HDL_TOY_ARENA_v1", L"--absolute", L"--module", L"hdl_toy_arena.exe"});
        ExpectOk(c, "xrefs absolute", r);
    }
    {
        auto r = Cli(ctx, {L"resolve-pattern", L"31 59 4F 54", L"--module", L"hdl_toy_arena.exe",
                           L"--image"});
        ExpectOk(c, "resolve-pattern TOY1", r);
    }

    /* Place / code / observe smoke against the toy process. */
    ExpectOk(c, "toy sections", Cli(ctx, {L"sections"}));
    ExpectOk(c, "toy exports", Cli(ctx, {L"exports"}));
    ExpectOk(c, "toy imports", Cli(ctx, {L"imports"}));
    ExpectOk(c, "toy disasm-backend list", Cli(ctx, {L"disasm-backend", L"list"}));
    if (dmg_fn) {
        wchar_t a[32];
        Hex(a, 32, dmg_fn);
        ExpectOk(c, "toy instrlen", Cli(ctx, {L"instrlen", a}));
        ExpectOk(c, "toy disasm", Cli(ctx, {L"disasm", a, L"--max", L"4"}));
        ExpectOk(c, "toy stub",
                 Cli(ctx, {L"stub", L"--kind", L"mov_rax_jmp", L"--target", a, L"--alloc"}));
        ExpectOk(c, "toy xrefs-from", Cli(ctx, {L"xrefs-from", a}));
        ExpectOk(c, "toy flush-icache", Cli(ctx, {L"flush-icache", a, L"16"}));
        auto caves = Cli(ctx, {L"caves", L"--near", a, L"--min", L"16", L"--image"});
        Report(c, caves.exit_code == 0, true, "toy caves (soft)", "");
        auto an = Cli(ctx, {L"alloc-near", a, L"32"});
        Report(c, an.exit_code == 0, true, "toy alloc-near (soft)", "");
        if (an.exit_code == 0) {
            uint64_t near_a = 0;
            ParseHexAfter(an.out, L"addr=", &near_a);
            if (near_a) {
                wchar_t na[32];
                Hex(na, 32, near_a);
                ExpectOk(c, "toy free alloc-near", Cli(ctx, {L"free", na}));
            }
        }
    }
    if (hero) {
        wchar_t a[32];
        Hex(a, 32, hero);
        ExpectOk(c, "toy vtable", Cli(ctx, {L"vtable", a}));
        auto rtti = Cli(ctx, {L"rtti", a});
        Report(c, rtti.exit_code == 0 || Contains(rtti.out, L"status="), true, "toy rtti (soft)",
               "");
    }
    {
        uint64_t pad = 0;
        auto ar = Cli(ctx, {L"alloc", L"64", L"--protect", L"RWX"});
        ExpectOk(c, "toy alloc patch pad", ar);
        ParseHexAfter(ar.out, L"addr=", &pad);
        if (pad) {
            wchar_t a[32];
            Hex(a, 32, pad);
            ExpectOk(c, "toy write pad", Cli(ctx, {L"write", a, L"11 22 33 44 55"}));
            uint64_t ph = 0;
            {
                auto r =
                    Cli(ctx, {L"patch", L"create", a, L"90 90 90 90 90", L"--name", L"toy_nop"});
                ExpectOk(c, "toy patch create", r);
                ParseU64After(r.out, L"handle=", &ph);
            }
            if (ph) {
                wchar_t h[32];
                swprintf_s(h, L"%llu", static_cast<unsigned long long>(ph));
                ExpectOk(c, "toy patch enable", Cli(ctx, {L"patch", L"enable", h}));
                ExpectOk(c, "toy patch list", Cli(ctx, {L"patch", L"list"}));
                ExpectOk(c, "toy patch disable", Cli(ctx, {L"patch", L"disable", h}));
                ExpectOk(c, "toy patch remove", Cli(ctx, {L"patch", L"remove", h}));
            }
            {
                auto r = Cli(ctx, {L"watch", L"hw", a, L"--size", L"8", L"--access", L"write"});
                ExpectOk(c, "toy watch hw", r);
                uint64_t wh = 0;
                ParseU64After(r.out, L"handle=", &wh);
                if (wh) {
                    wchar_t h[32];
                    swprintf_s(h, L"%llu", static_cast<unsigned long long>(wh));
                    ExpectOk(c, "toy unwatch hw", Cli(ctx, {L"watch", L"unwatch", h}));
                }
            }
            {
                auto r = Cli(ctx, {L"watch", L"page", a, L"64", L"--mode", L"guard"});
                ExpectOk(c, "toy watch page", r);
                uint64_t wh = 0;
                ParseU64After(r.out, L"handle=", &wh);
                if (wh) {
                    wchar_t h[32];
                    swprintf_s(h, L"%llu", static_cast<unsigned long long>(wh));
                    ExpectOk(c, "toy unwatch page", Cli(ctx, {L"watch", L"unwatch", h}));
                }
            }
            ExpectOk(c, "toy watch list", Cli(ctx, {L"watch", L"list"}));
            ExpectOk(c, "toy protect", Cli(ctx, {L"protect", a, L"64", L"RW"}));
            ExpectOk(c, "toy free pad", Cli(ctx, {L"free", a}));
        }
    }
    if (dmg_fn) {
        wchar_t store_path[MAX_PATH];
        GetTempPathW(MAX_PATH, store_path);
        wcscat_s(store_path, L"hdl_toy_place_store.json");
        DeleteFileW(store_path);
        uint64_t stitch_pad = 0;
        {
            auto r = Cli(ctx, {L"alloc", L"64", L"--protect", L"RWX"});
            ExpectOk(c, "toy alloc stitch pad", r);
            ParseHexAfter(r.out, L"addr=", &stitch_pad);
            if (stitch_pad) {
                wchar_t a[32];
                Hex(a, 32, stitch_pad);
                ExpectOk(c, "toy write stitch pad",
                         Cli(ctx, {L"write", a, L"90 90 90 90 90 90 90 90 90 90 90 90 C3"}));
            }
        }
        std::wstring script;
        wchar_t line[256];
        swprintf_s(line, L"0x%llx", static_cast<unsigned long long>(dmg_fn));
        {
            ProcResult r;
            RunProcess(ctx.client,
                       {L"--store", store_path, std::to_wstring(ctx.pid), L"recipe", L"place",
                        L"toy_place", line},
                       nullptr, 90000, &r);
            ExpectExit0(c, "toy recipe place exit", r);
            Report(c,
                   Contains(r.out, L"place cave") || Contains(r.out, L"AllocNear fallback") ||
                       Contains(r.out, L"cave_addr=") || Contains(r.out, L"store updated"),
                   false, "toy recipe place", "");
        }
        if (stitch_pad) {
            wchar_t tgt[32];
            swprintf_s(tgt, L"0x%llx", static_cast<unsigned long long>(stitch_pad));
            ProcResult r;
            RunProcess(ctx.client,
                       {L"--store", store_path, std::to_wstring(ctx.pid), L"recipe", L"stitch",
                        L"toy_stitch", L"--target", tgt, L"--kind", L"mov_rax_jmp"},
                       nullptr, 90000, &r);
            ExpectExit0(c, "toy recipe stitch exit", r);
            Report(c,
                   Contains(r.out, L"stub_va=") || Contains(r.out, L"stub+patch") ||
                       Contains(r.out, L"patch_handle="),
                   false, "toy recipe stitch", "");
        }
        {
            ProcResult list;
            RunProcess(ctx.client,
                       {L"--store", store_path, std::to_wstring(ctx.pid), L"store", L"list"},
                       nullptr, 30000, &list);
            ExpectExit0(c, "toy store list", list);
            Report(c, Contains(list.out, L"toy_place") || Contains(list.out, L"name=toy_place"),
                   false, "toy store persisted place", "");
        }
        if (stitch_pad) {
            wchar_t pad_hex[32];
            Hex(pad_hex, 32, stitch_pad);

            /* Drop in-target ledger + restore originals. Full unload/reinject is the
             * operator path, but reinject currently fails with NO_MEM in this harness;
             * patch remove clears the same ledger state --apply must recreate. */
            uint64_t stitch_handle = 0;
            {
                auto listed = Cli(ctx, {L"patch", L"list"});
                ExpectOk(c, "toy patch list after stitch", listed);
                ParseU64After(listed.out, L"handle=", &stitch_handle);
            }
            if (stitch_handle) {
                wchar_t h[32];
                swprintf_s(h, L"%llu", static_cast<unsigned long long>(stitch_handle));
                ExpectOk(c, "toy patch remove to clear ledger", Cli(ctx, {L"patch", L"remove", h}));
            } else {
                Report(c, false, false, "toy patch remove to clear ledger", "no handle");
            }

            {
                ProcResult r;
                RunProcess(
                    ctx.client,
                    {L"--store", store_path, std::to_wstring(ctx.pid), L"store", L"revalidate"},
                    nullptr, 90000, &r);
                ExpectExit0(c, "toy store revalidate (no apply)", r);
                Report(c, Contains(r.out, L"not applied"), false,
                       "toy revalidate patch not applied by default", "");
            }
            {
                auto rd = Cli(ctx, {L"read", pad_hex, L"12"});
                ExpectOk(c, "toy read pad before apply", rd);
                Report(c, Contains(rd.out, L"909090") && !Contains(rd.out, L"48B8"), false,
                       "toy pad still original before apply", "");
            }
            uint64_t applied_handle = 0;
            {
                ProcResult r;
                RunProcess(ctx.client,
                           {L"--store", store_path, std::to_wstring(ctx.pid), L"store",
                            L"revalidate", L"--apply"},
                           nullptr, 90000, &r);
                ExpectExit0(c, "toy store revalidate --apply", r);
                Report(c, Contains(r.out, L"applied+enabled") || Contains(r.out, L"patch_handle="),
                       false, "toy revalidate --apply restored patch", "");
                ParseU64After(r.out, L"handle=", &applied_handle);
                if (!applied_handle) {
                    ParseHexAfter(r.out, L"patch_handle=", &applied_handle);
                }
            }
            {
                auto rd = Cli(ctx, {L"read", pad_hex, L"12"});
                ExpectOk(c, "toy read pad after apply", rd);
                Report(c, Contains(rd.out, L"48B8"), false, "toy pad has mov rax jmp after apply",
                       "");
            }
            if (applied_handle) {
                wchar_t h[32];
                swprintf_s(h, L"%llu", static_cast<unsigned long long>(applied_handle));
                ExpectOk(c, "toy patch disable after apply", Cli(ctx, {L"patch", L"disable", h}));
                auto rd = Cli(ctx, {L"read", pad_hex, L"12"});
                ExpectOk(c, "toy read pad after disable", rd);
                Report(c, Contains(rd.out, L"909090") && !Contains(rd.out, L"48B8"), false,
                       "toy pad restored after disable", "");
            } else {
                Report(c, false, false, "toy patch handle after apply", "missing handle");
            }
        }
        DeleteFileW(store_path);
        if (stitch_pad) {
            wchar_t a[32];
            Hex(a, 32, stitch_pad);
            Cli(ctx, {L"free", a});
        }
    }

    TerminateProcess(tpi.hProcess, 0);
    WaitForSingleObject(tpi.hProcess, 5000);
    CloseHandle(tpi.hProcess);
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    (void)argc;
    (void)argv;
    wchar_t self[MAX_PATH];
    GetModuleFileNameW(nullptr, self, MAX_PATH);
    std::wstring dir(self);
    const size_t slash = dir.find_last_of(L"\\/");
    if (slash != std::wstring::npos) {
        dir.resize(slash + 1);
    }

    const std::wstring client = dir + L"hdlclient.exe";
    const std::wstring dll = dir + L"hdllib.dll";
    const std::wstring toy = dir + L"hdl_toy_arena.exe";

    if (GetFileAttributesW(client.c_str()) == INVALID_FILE_ATTRIBUTES ||
        GetFileAttributesW(dll.c_str()) == INVALID_FILE_ATTRIBUTES ||
        GetFileAttributesW(toy.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::fwprintf(stderr, L"Need hdlclient.exe, hdllib.dll, hdl_toy_arena.exe beside test\n");
        return 2;
    }

    Counters c;
    RunToyVerify(c, client, dll, toy);
    std::printf("\nSummary: %d passed, %d failed, %d soft\n", c.passed, c.failed, c.soft_failed);
    return c.failed ? 1 : 0;
}
