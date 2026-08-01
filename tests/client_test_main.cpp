/* End-to-end hdlclient tests against hdl_test_target (parity with hdl_tests locate/discover). */
#include "support.hpp"
#include "store.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

using hdltest::Counters;
using hdltest::IlLevel;
using hdltest::Report;
using hdltest::TargetProc;
using hdltest::TargetProfile;

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
    const BOOL ok =
        CreateProcessW(nullptr, cmdline.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr,
                       nullptr, &si, &pi);
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
    DWORD got = 0;
    const DWORD start = GetTickCount();

    auto append_chunk = [&](const char* data, DWORD n) {
        if (!n) {
            return;
        }
        raw.append(data, n);
    };

    auto flush_raw_to_wide = [&]() {
        if (raw.empty()) {
            return;
        }
        size_t start = 0;
        if (raw.size() >= 2 && static_cast<unsigned char>(raw[0]) == 0xFF &&
            static_cast<unsigned char>(raw[1]) == 0xFE) {
            start = 2;
        }
        const size_t nbytes = raw.size() - start;
        bool as_utf16 = false;
        if (nbytes >= 2 && (nbytes % 2) == 0) {
            size_t nul_odd = 0;
            size_t samples = 0;
            for (size_t i = start + 1; i < raw.size() && samples < 256; i += 2, ++samples) {
                if (raw[i] == 0) {
                    ++nul_odd;
                }
            }
            as_utf16 = samples > 0 && nul_odd * 2 >= samples;
        }
        if (as_utf16) {
            const wchar_t* w = reinterpret_cast<const wchar_t*>(raw.data() + start);
            collected.append(w, nbytes / sizeof(wchar_t));
        } else {
            wchar_t wbuf[8192];
            int remaining = static_cast<int>(raw.size());
            const char* p = raw.data();
            while (remaining > 0) {
                const int chunk = remaining > 4000 ? 4000 : remaining;
                const int wn =
                    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, p, chunk, wbuf, 8191);
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
        raw.clear();
    };

    for (;;) {
        DWORD avail = 0;
        if (PeekNamedPipe(out_r, nullptr, 0, nullptr, &avail, nullptr) && avail) {
            const DWORD to_read = avail > sizeof(buf) ? sizeof(buf) : avail;
            if (ReadFile(out_r, buf, to_read, &got, nullptr) && got) {
                append_chunk(buf, got);
            }
        }
        const DWORD wr = WaitForSingleObject(pi.hProcess, 50);
        if (wr == WAIT_OBJECT_0) {
            while (PeekNamedPipe(out_r, nullptr, 0, nullptr, &avail, nullptr) && avail) {
                const DWORD to_read = avail > sizeof(buf) ? sizeof(buf) : avail;
                if (ReadFile(out_r, buf, to_read, &got, nullptr) && got) {
                    append_chunk(buf, got);
                } else {
                    break;
                }
            }
            flush_raw_to_wide();
            break;
        }
        if (GetTickCount() - start > timeout_ms) {
            TerminateProcess(pi.hProcess, 1);
            WaitForSingleObject(pi.hProcess, 2000);
            flush_raw_to_wide();
            CloseHandle(out_r);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            out->exit_code = 1;
            out->out = collected + L"\n[timeout]";
            return true;
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
    return true;
}

struct ClientCtx {
    std::wstring client;
    std::wstring dll;
    DWORD pid = 0;
};

ProcResult Cli(const ClientCtx& ctx, std::vector<std::wstring> args, DWORD timeout_ms = 30000) {
    std::vector<std::wstring> full;
    full.emplace_back(std::to_wstring(ctx.pid));
    full.insert(full.end(), args.begin(), args.end());
    ProcResult r;
    RunProcess(ctx.client, full, nullptr, timeout_ms, &r);
    return r;
}

ProcResult CliInject(const ClientCtx& ctx) {
    ProcResult r;
    RunProcess(ctx.client, {L"inject", std::to_wstring(ctx.pid), ctx.dll}, nullptr, 60000, &r);
    return r;
}

ProcResult CliRepl(const ClientCtx& ctx, const std::wstring& script, DWORD timeout_ms = 60000) {
    ProcResult r;
    RunProcess(ctx.client, {std::to_wstring(ctx.pid), L"repl"}, &script, timeout_ms, &r);
    return r;
}

void ExpectOk(Counters& c, const char* name, const ProcResult& r) {
    const bool ok = r.exit_code == 0 && Contains(r.out, L"status=OK");
    char detail[256];
    if (!ok) {
        snprintf(detail, sizeof(detail), "exit=%lu", static_cast<unsigned long>(r.exit_code));
    } else {
        detail[0] = 0;
    }
    Report(c, ok, false, name, detail);
}

void ExpectExit0(Counters& c, const char* name, const ProcResult& r) {
    Report(c, r.exit_code == 0, false, name, "");
}

void RunStoreUnit(Counters& c) {
    std::printf("\n== Client store (unit) ==\n");
    wchar_t tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp);
    wcscat_s(tmp, L"hdl_client_store_roundtrip.json");

    hdlcli::InterestStore a;
    a.module = "hdl_test_target.exe";
    hdlcli::Interest in;
    in.name = "leaf";
    in.kind = "object";
    hdlcli::Locator loc;
    loc.type = hdlcli::Locator::Pattern;
    loc.pattern.pattern = "BE BA FE CA 0D F0 0D D0";
    loc.pattern.module = "hdl_test_target.exe";
    loc.last_addr = 0x1000;
    loc.last_ok = true;
    in.locators.push_back(loc);
    a.AddOrReplace(std::move(in));
    Report(c, a.Save(tmp), false, "store save", "");
    hdlcli::InterestStore b;
    Report(c, b.Load(tmp), false, "store load", "");
    Report(c, b.interests.size() == 1 && b.interests[0].name == "leaf" &&
                   b.interests[0].locators.size() == 1 &&
                   b.interests[0].locators[0].pattern.pattern.find("BE BA") != std::string::npos,
           false, "store roundtrip fields", "");
    DeleteFileW(tmp);
}

void RunClientLiveTests(Counters& c, const wchar_t* client_path, const wchar_t* target_path,
                        const wchar_t* dll_path) {
    std::printf("\n== hdlclient vs hdl_test_target ==\n");

    TargetProfile profile{};
    profile.name = "client_live";
    profile.window = false;
    profile.alertable = true;
    profile.integrity = IlLevel::Medium;

    TargetProc target;
    if (!hdltest::SpawnTarget(target_path, profile, target)) {
        Report(c, false, false, "client spawn target", "");
        return;
    }

    ClientCtx ctx;
    ctx.client = client_path;
    ctx.dll = dll_path;
    ctx.pid = target.pid;

    /* Local inject via hdlclient */
    {
        const ProcResult inj = CliInject(ctx);
        const bool ok = inj.exit_code == 0 && hdltest::PingPipe(ctx.pid, 10000);
        Report(c, ok, false, "client inject + ping", "");
        if (!ok) {
            return;
        }
    }

    ExpectOk(c, "client ping", Cli(ctx, {L"ping"}));
    ExpectOk(c, "client log", Cli(ctx, {L"log", L"1"}));
    {
        wchar_t tmp[MAX_PATH];
        GetTempPathW(MAX_PATH, tmp);
        wcscat_s(tmp, L"hdl_client_logfile.txt");
        ExpectOk(c, "client log-file set", Cli(ctx, {L"log-file", tmp}));
        ExpectOk(c, "client log-file clear", Cli(ctx, {L"log-file"}));
        DeleteFileW(tmp);
    }
    ExpectOk(c, "client health-veh on", Cli(ctx, {L"health-veh", L"on"}));
    {
        auto r = Cli(ctx, {L"health-veh", L"status"});
        ExpectOk(c, "client health-veh status", r);
        Report(c, Contains(r.out, L"enabled=1"), false, "client health-veh enabled", "");
    }
    ExpectOk(c, "client health-veh off", Cli(ctx, {L"health-veh", L"off"}));
    ExpectOk(c, "client modules", Cli(ctx, {L"modules"}));
    ExpectOk(c, "client regions", Cli(ctx, {L"regions"}));
    ExpectOk(c, "client threads", Cli(ctx, {L"threads"}));
    ExpectOk(c, "client health", Cli(ctx, {L"health"}));
    ExpectOk(c, "client events", Cli(ctx, {L"events", L"--timeout", L"50", L"--max", L"4"}));
    ExpectOk(c, "client modbase", Cli(ctx, {L"modbase", L"--module", L"hdl_test_target.exe"}));

    uint64_t fn = 0, leaf = 0, root = 0, obj = 0, str = 0, str_ptr = 0;
    uint64_t action = 0, dleaf = 0, obj_a = 0, dyn_root = 0;

    {
        auto r = Cli(ctx, {L"resolve", L"HdlTestLocateFn"});
        ExpectOk(c, "client resolve LocateFn", r);
        ParseHexAfter(r.out, L"addr=", &fn);
    }
    {
        auto r = Cli(ctx, {L"resolve", L"HdlTestLocateLeaf"});
        ExpectOk(c, "client resolve LocateLeaf", r);
        ParseHexAfter(r.out, L"addr=", &leaf);
    }
    {
        auto r = Cli(ctx, {L"resolve", L"HdlTestLocateRoot"});
        ExpectOk(c, "client resolve LocateRoot", r);
        ParseHexAfter(r.out, L"addr=", &root);
    }
    {
        auto r = Cli(ctx, {L"resolve", L"HdlTestLocateObj"});
        ExpectOk(c, "client resolve LocateObj", r);
        ParseHexAfter(r.out, L"addr=", &obj);
    }
    {
        auto r = Cli(ctx, {L"resolve", L"HdlTestLocateString"});
        ExpectOk(c, "client resolve LocateString", r);
        ParseHexAfter(r.out, L"addr=", &str);
    }
    {
        auto r = Cli(ctx, {L"resolve", L"HdlTestLocateStringPtr"});
        ExpectOk(c, "client resolve LocateStringPtr", r);
        ParseHexAfter(r.out, L"addr=", &str_ptr);
    }
    {
        auto r = Cli(ctx, {L"resolve", L"HdlTestDiscoverAction"});
        ExpectOk(c, "client resolve DiscoverAction", r);
        ParseHexAfter(r.out, L"addr=", &action);
    }
    {
        auto r = Cli(ctx, {L"resolve", L"HdlTestDiscoverLeaf"});
        ExpectOk(c, "client resolve DiscoverLeaf", r);
        ParseHexAfter(r.out, L"addr=", &dleaf);
    }
    {
        auto r = Cli(ctx, {L"resolve", L"HdlTestDiscoverObjA"});
        ExpectOk(c, "client resolve DiscoverObjA", r);
        ParseHexAfter(r.out, L"addr=", &obj_a);
    }
    {
        auto r = Cli(ctx, {L"resolve", L"HdlTestDiscoverDynRoot"});
        ExpectOk(c, "client resolve DiscoverDynRoot", r);
        ParseHexAfter(r.out, L"addr=", &dyn_root);
    }

    Report(c, fn && leaf && root && obj && str && str_ptr && action && dleaf && obj_a && dyn_root,
           false, "client resolve all fixtures", "");

    /* Call / read / write / alloc */
    if (fn) {
        wchar_t a[32];
        swprintf_s(a, L"0x%llx", static_cast<unsigned long long>(fn));
        ExpectOk(c, "client call LocateFn",
                 Cli(ctx, {L"call", L"--addr", a, L"i64:3", L"i64:4"}));
    }
    ExpectOk(c, "client call export LocateFn",
             Cli(ctx, {L"call", L"HdlTestLocateFn", L"i64:1", L"i64:2"}));

    uint64_t scratch = 0;
    {
        auto r = Cli(ctx, {L"alloc", L"64"});
        ExpectOk(c, "client alloc", r);
        ParseHexAfter(r.out, L"addr=", &scratch);
    }
    if (scratch) {
        wchar_t a[32];
        swprintf_s(a, L"0x%llx", static_cast<unsigned long long>(scratch));
        ExpectOk(c, "client write", Cli(ctx, {L"write", a, L"DE AD BE EF 01 02 03 04"}));
        {
            auto r = Cli(ctx, {L"read", a, L"8"});
            ExpectOk(c, "client read", r);
            Report(c, Contains(r.out, L"DE") && Contains(r.out, L"AD") && Contains(r.out, L"BE"),
                   false, "client read matches write", "");
        }
        ExpectOk(c, "client free", Cli(ctx, {L"free", a}));
    }

    /* Place / code smoke */
    ExpectOk(c, "client disasm-backend list", Cli(ctx, {L"disasm-backend", L"list"}));
    ExpectOk(c, "client disasm-backend set zydis",
             Cli(ctx, {L"disasm-backend", L"set", L"1"}));
    if (fn) {
        wchar_t a[32];
        swprintf_s(a, L"0x%llx", static_cast<unsigned long long>(fn));
        ExpectOk(c, "client instrlen", Cli(ctx, {L"instrlen", a}));
        ExpectOk(c, "client disasm", Cli(ctx, {L"disasm", a, L"--max", L"4"}));
        {
            auto r = Cli(ctx, {L"stub", L"--kind", L"mov_rax_jmp", L"--target", a, L"--alloc"});
            ExpectOk(c, "client stub", r);
        }
    }
    if (scratch) {
        /* re-alloc scratch for patch round-trip */
        uint64_t pad = 0;
        {
            auto r = Cli(ctx, {L"alloc", L"64"});
            ExpectOk(c, "client alloc for patch", r);
            ParseHexAfter(r.out, L"addr=", &pad);
        }
        if (pad) {
            wchar_t a[32];
            swprintf_s(a, L"0x%llx", static_cast<unsigned long long>(pad));
            ExpectOk(c, "client write pad", Cli(ctx, {L"write", a, L"11 22 33 44 55"}));
            uint64_t ph = 0;
            {
                auto r = Cli(ctx, {L"patch", L"create", a, L"90 90 90 90 90", L"--name", L"nop5"});
                ExpectOk(c, "client patch create", r);
                ParseU64After(r.out, L"handle=", &ph);
            }
            if (ph) {
                wchar_t h[32];
                swprintf_s(h, L"%llu", static_cast<unsigned long long>(ph));
                ExpectOk(c, "client patch enable", Cli(ctx, {L"patch", L"enable", h}));
                ExpectOk(c, "client patch list", Cli(ctx, {L"patch", L"list"}));
                ExpectOk(c, "client patch disable", Cli(ctx, {L"patch", L"disable", h}));
                ExpectOk(c, "client patch remove", Cli(ctx, {L"patch", L"remove", h}));
            }
            ExpectOk(c, "client free pad", Cli(ctx, {L"free", a}));
        }
    }
    ExpectOk(c, "client sections", Cli(ctx, {L"sections"}));
    ExpectOk(c, "client exports", Cli(ctx, {L"exports"}));
    ExpectOk(c, "client imports", Cli(ctx, {L"imports"}));
    ExpectOk(c, "client functions",
             Cli(ctx, {L"functions", L"--module", L"hdl_test_target.exe", L"--max", L"16"}));
    if (fn) {
        wchar_t a[32];
        swprintf_s(a, L"0x%llx", static_cast<unsigned long long>(fn));
        ExpectOk(c, "client xrefs-from", Cli(ctx, {L"xrefs-from", a}));
        ExpectOk(c, "client flush-icache", Cli(ctx, {L"flush-icache", a, L"16"}));
    }
    if (obj) {
        wchar_t a[32];
        swprintf_s(a, L"0x%llx", static_cast<unsigned long long>(obj));
        ExpectOk(c, "client vtable", Cli(ctx, {L"vtable", a}));
        auto rtti = Cli(ctx, {L"rtti", a});
        /* Fake C vtable fixture has no MSVC RTTI — accept OK or NOT_FOUND. */
        Report(c, rtti.exit_code == 0 || Contains(rtti.out, L"status=NOT_FOUND") ||
                      Contains(rtti.out, L"status=FAILED"),
               false, "client rtti", "");
    }
    {
        uint64_t prot_pad = 0;
        auto ar = Cli(ctx, {L"alloc", L"4096"});
        ExpectOk(c, "client alloc for protect", ar);
        ParseHexAfter(ar.out, L"addr=", &prot_pad);
        if (prot_pad) {
            wchar_t a[32];
            swprintf_s(a, L"0x%llx", static_cast<unsigned long long>(prot_pad));
            ExpectOk(c, "client protect", Cli(ctx, {L"protect", a, L"4096", L"R"}));
            ExpectOk(c, "client protect restore", Cli(ctx, {L"protect", a, L"4096", L"RW"}));
            ExpectOk(c, "client free protect pad", Cli(ctx, {L"free", a}));
        }
    }
    {
        uint64_t watch_pad = 0;
        auto ar = Cli(ctx, {L"alloc", L"4096"});
        ExpectOk(c, "client alloc for watch", ar);
        ParseHexAfter(ar.out, L"addr=", &watch_pad);
        if (watch_pad) {
            wchar_t a[32];
            swprintf_s(a, L"0x%llx", static_cast<unsigned long long>(watch_pad));
            uint64_t wh = 0, ph = 0;
            {
                auto r = Cli(ctx, {L"watch", L"hw", a, L"--size", L"8", L"--access", L"write"});
                ExpectOk(c, "client watch hw", r);
                ParseU64After(r.out, L"handle=", &wh);
            }
            {
                auto r = Cli(ctx, {L"watch", L"page", a, L"4096", L"--mode", L"guard"});
                ExpectOk(c, "client watch page", r);
                ParseU64After(r.out, L"handle=", &ph);
            }
            ExpectOk(c, "client watch list", Cli(ctx, {L"watch", L"list"}));
            if (wh) {
                wchar_t h[32];
                swprintf_s(h, L"%llu", static_cast<unsigned long long>(wh));
                ExpectOk(c, "client unwatch hw", Cli(ctx, {L"watch", L"unwatch", h}));
            }
            if (ph) {
                wchar_t h[32];
                swprintf_s(h, L"%llu", static_cast<unsigned long long>(ph));
                ExpectOk(c, "client unwatch page", Cli(ctx, {L"watch", L"unwatch", h}));
            }
            ExpectOk(c, "client free watch pad", Cli(ctx, {L"free", a}));
        } else {
            ExpectOk(c, "client watch list", Cli(ctx, {L"watch", L"list"}));
        }
    }
    /* Soft place path: caves/alloc-near near fn (empty caves is ok on tiny PE). */
    if (fn) {
        wchar_t a[32];
        swprintf_s(a, L"0x%llx", static_cast<unsigned long long>(fn));
        auto caves = Cli(ctx, {L"caves", L"--near", a, L"--min", L"16", L"--image"});
        Report(c, caves.exit_code == 0, true, "client caves near fn (soft)", "");
        auto an = Cli(ctx, {L"alloc-near", a, L"32"});
        Report(c, an.exit_code == 0, true, "client alloc-near (soft)", "");
        if (an.exit_code == 0) {
            uint64_t near_a = 0;
            ParseHexAfter(an.out, L"addr=", &near_a);
            if (near_a) {
                wchar_t na[32];
                swprintf_s(na, L"0x%llx", static_cast<unsigned long long>(near_a));
                ExpectOk(c, "client free alloc-near", Cli(ctx, {L"free", na}));
            }
        }
    }

    /* Jobs */
    uint64_t job = 0;
    {
        auto r = Cli(ctx, {L"job", L"create", L"--timeout", L"5000"});
        ExpectOk(c, "client job create", r);
        ParseU64After(r.out, L"job=", &job);
    }
    if (job) {
        wchar_t j[32];
        swprintf_s(j, L"%llu", static_cast<unsigned long long>(job));
        ExpectOk(c, "client job cancel", Cli(ctx, {L"job", L"cancel", j}));
        ExpectOk(c, "client job close", Cli(ctx, {L"job", L"close", j}));
    }

    /* Locate CLI */
    ExpectOk(c, "client resolve-pattern",
             Cli(ctx, {L"resolve-pattern", L"31 4C 44 48", L"--module", L"hdl_test_target.exe",
                       L"--image"}));
    ExpectOk(c, "client xrefs",
             Cli(ctx, {L"xrefs", L"HDL_LOCATE_STRING_v1", L"--absolute", L"--module",
                       L"hdl_test_target.exe", L"--image"}));
    if (leaf) {
        wchar_t a[32];
        swprintf_s(a, L"0x%llx", static_cast<unsigned long long>(leaf));
        ExpectOk(c, "client ptrscan",
                 Cli(ctx, {L"ptrscan", a, L"--depth", L"2", L"--module", L"hdl_test_target.exe"}));
    }
    if (obj) {
        wchar_t a[32];
        swprintf_s(a, L"0x%llx", static_cast<unsigned long long>(obj));
        ExpectOk(c, "client probe", Cli(ctx, {L"probe", a, L"--size", L"40"}));
    }
    if (str_ptr && str) {
        wchar_t a[32];
        swprintf_s(a, L"0x%llx", static_cast<unsigned long long>(str_ptr));
        auto r = Cli(ctx, {L"ptrchain", a, L"+0"});
        ExpectOk(c, "client ptrchain", r);
        uint64_t got = 0;
        ParseHexAfter(r.out, L"addr=", &got);
        Report(c, got == str, false, "client ptrchain -> string", "");
    }
    if (root && leaf) {
        wchar_t a[32];
        swprintf_s(a, L"0x%llx", static_cast<unsigned long long>(root));
        auto r = Cli(ctx, {L"ptrchain", a, L"+0", L"+0"});
        ExpectOk(c, "client ptrchain root", r);
        uint64_t got = 0;
        ParseHexAfter(r.out, L"addr=", &got);
        Report(c, got == leaf, false, "client ptrchain root -> leaf", "");
    }

    /* Scan */
    {
        auto r = Cli(ctx, {L"scan", L"--pattern", L"31 4C 44 48", L"--module", L"hdl_test_target.exe",
                           L"--image", L"--max", L"8"});
        ExpectOk(c, "client scan pattern", r);
    }
    uint64_t scan_sess = 0;
    {
        auto r = Cli(ctx, {L"scan", L"--type", L"i32", L"--value", L"80", L"--module",
                           L"hdl_test_target.exe", L"--image", L"--max", L"64"});
        ExpectOk(c, "client scan typed", r);
        ParseU64After(r.out, L"session=", &scan_sess);
    }
    if (scan_sess) {
        wchar_t s[32];
        swprintf_s(s, L"%llu", static_cast<unsigned long long>(scan_sess));
        ExpectOk(c, "client scan hits", Cli(ctx, {L"scan", L"--hits", L"--session", s, L"--max", L"16"}));
        ExpectOk(c, "client scan close", Cli(ctx, {L"scan", L"--close", L"--session", s}));
    }

    /* Hooks: trace + enable/disable + hits + unhook */
    if (fn) {
        wchar_t a[32];
        swprintf_s(a, L"0x%llx", static_cast<unsigned long long>(fn));
        uint64_t handle = 0;
        {
            auto r = Cli(ctx, {L"hooktrace", a, L"--args", L"2"});
            ExpectOk(c, "client hooktrace", r);
            ParseHexAfter(r.out, L"handle=", &handle);
        }
        if (handle) {
            wchar_t h[32];
            swprintf_s(h, L"0x%llx", static_cast<unsigned long long>(handle));
            ExpectOk(c, "client hook-enable 0", Cli(ctx, {L"hook-enable", h, L"0"}));
            ExpectOk(c, "client enablehook 1", Cli(ctx, {L"enablehook", h, L"1"}));
            ExpectOk(c, "client call while hooked",
                     Cli(ctx, {L"call", L"HdlTestLocateFn", L"i64:5", L"i64:6"}));
            {
                auto r = Cli(ctx, {L"hookhits", L"--timeout", L"500", L"--max", L"8"});
                ExpectOk(c, "client hookhits", r);
                Report(c, Contains(r.out, L"count=") && !Contains(r.out, L"count=0\n"), false,
                       "client hookhits nonempty", "");
            }
            ExpectOk(c, "client unhook", Cli(ctx, {L"unhook", h}));
        }

        /* Pipe-native OpHook: place a stub that jumps to leaf, then hook fn -> stub. */
        if (leaf) {
            wchar_t tgt_s[32], leaf_s[32];
            swprintf_s(tgt_s, L"0x%llx", static_cast<unsigned long long>(fn));
            swprintf_s(leaf_s, L"0x%llx", static_cast<unsigned long long>(leaf));
            auto stub = Cli(ctx, {L"stub", L"--kind", L"mov_rax_jmp", L"--target", leaf_s, L"--alloc"});
            ExpectOk(c, "client hook-by-va stub", stub);
            uint64_t detour = 0;
            ParseHexAfter(stub.out, L"stub_va=", &detour);
            if (detour) {
                wchar_t det_s[32];
                swprintf_s(det_s, L"0x%llx", static_cast<unsigned long long>(detour));
                auto hr = Cli(ctx, {L"hook", tgt_s, det_s});
                ExpectOk(c, "client hook-by-va", hr);
                uint64_t hh = 0;
                ParseHexAfter(hr.out, L"handle=", &hh);
                Report(c, hh != 0 && Contains(hr.out, L"trampoline="), false,
                       "client hook-by-va trampoline", "");
                if (hh) {
                    wchar_t h2[32];
                    swprintf_s(h2, L"0x%llx", static_cast<unsigned long long>(hh));
                    ExpectOk(c, "client hook-by-va unhook", Cli(ctx, {L"unhook", h2}));
                }
            }
        }
    }

    /* Graph / watch / hook-import / functions */
    if (dleaf) {
        wchar_t a[32], mid[32];
        swprintf_s(a, L"0x%llx", static_cast<unsigned long long>(dleaf));
        swprintf_s(mid, L"0x%llx", static_cast<unsigned long long>(dleaf + 4));
        ExpectOk(c, "client resolve-function leaf",
                 Cli(ctx, {L"resolve-function", mid, L"--module", L"hdl_test_target.exe"}));
        auto xr = Cli(ctx, {L"xrefs-to", a, L"--module", L"hdl_test_target.exe"});
        ExpectOk(c, "client xrefs-to leaf", xr);
        Report(c, Contains(xr.out, L"count=") && !Contains(xr.out, L"count=0\n"), false,
               "client xrefs-to leaf nonempty", "");
    }
    {
        uint64_t pad = 0;
        auto ar = Cli(ctx, {L"alloc", L"64", L"--protect", L"RW"});
        ExpectOk(c, "client alloc watch pad", ar);
        ParseHexAfter(ar.out, L"addr=", &pad);
        if (pad) {
            wchar_t a[32];
            swprintf_s(a, L"0x%llx", static_cast<unsigned long long>(pad));
            uint64_t wh = 0;
            {
                auto wr = Cli(ctx, {L"watch", L"hw", a, L"--size", L"8", L"--access", L"write"});
                ExpectOk(c, "client watch hw", wr);
                ParseU64After(wr.out, L"handle=", &wh);
            }
            ExpectOk(c, "client write watch pad", Cli(ctx, {L"write", a, L"DEADBEEFCAFEBABE"}));
            {
                auto r = Cli(ctx, {L"watch", L"hits", L"--timeout", L"500", L"--max", L"8"});
                ExpectOk(c, "client watch hits", r);
                Report(c, Contains(r.out, L"count=") && !Contains(r.out, L"count=0\n"), false,
                       "client watch hits nonempty", "");
            }
            ExpectOk(c, "client watch refresh", Cli(ctx, {L"watch", L"refresh"}));
            if (wh) {
                wchar_t h[32];
                swprintf_s(h, L"%llu", static_cast<unsigned long long>(wh));
                ExpectOk(c, "client unwatch hw", Cli(ctx, {L"watch", L"unwatch", h}));
            }
            ExpectOk(c, "client free watch pad", Cli(ctx, {L"free", a}));
        }
    }
    {
        uint64_t handle = 0;
        auto r = Cli(ctx, {L"hook-import", L"KERNEL32.dll!Sleep", L"--module",
                           L"hdl_test_target.exe", L"--args", L"1"});
        ExpectOk(c, "client hook-import Sleep", r);
        ParseHexAfter(r.out, L"handle=", &handle);
        if (handle) {
            wchar_t h[32];
            swprintf_s(h, L"0x%llx", static_cast<unsigned long long>(handle));
            ExpectOk(c, "client call Sleep",
                     Cli(ctx, {L"call", L"--module", L"KERNEL32.dll", L"Sleep", L"u64:1"}));
            auto hits = Cli(ctx, {L"hookhits", L"--timeout", L"500", L"--max", L"8"});
            ExpectOk(c, "client hook-import hits", hits);
            ExpectOk(c, "client hook-import unhook", Cli(ctx, {L"unhook", h}));
        }
    }
    ExpectOk(c, "client functions module",
             Cli(ctx, {L"functions", L"--module", L"hdl_test_target.exe", L"--max", L"32"}));

    /* Discover pipeline via CLI */
    uint64_t session = 0;
    {
        auto r = Cli(ctx, {L"discover-create"});
        ExpectOk(c, "client discover-create", r);
        ParseU64After(r.out, L"session=", &session);
    }
    if (session) {
        wchar_t sid[32];
        swprintf_s(sid, L"%llu", static_cast<unsigned long long>(session));

        ExpectOk(c, "client discover-constraint",
                 Cli(ctx, {L"discover-constraint", L"--session", sid, L"--size", L"24",
                           L"--pred", L"eq_i32:8:80", L"--pred", L"eq_i32:12:100", L"--module",
                           L"hdl_test_target.exe", L"--image"}));
        ExpectOk(c, "client discover-cands", Cli(ctx, {L"discover-cands", L"--session", sid}));

        if (dleaf) {
            wchar_t a[32];
            swprintf_s(a, L"0x%llx", static_cast<unsigned long long>(dleaf));
            auto r = Cli(ctx, {L"discover-add", L"--session", sid, L"--kind", L"function", L"--addr",
                               a, L"--tag", L"leaf"});
            ExpectOk(c, "client discover-add", r);
            uint64_t cand = 0;
            ParseU64After(r.out, L"cand=", &cand);
            if (cand) {
                wchar_t cid[32];
                swprintf_s(cid, L"%llu", static_cast<unsigned long long>(cand));
                ExpectOk(c, "client discover-synth",
                         Cli(ctx, {L"discover-synth", L"--session", sid, L"--cand", cid, L"--module",
                                   L"hdl_test_target.exe"}));
            }
        }

        if (obj_a) {
            wchar_t a[32];
            swprintf_s(a, L"0x%llx", static_cast<unsigned long long>(obj_a));
            ExpectOk(c, "client discover-scan",
                     Cli(ctx, {L"discover-scan", L"--session", sid, L"--type", L"i32", L"--value",
                               L"80", L"--module", L"hdl_test_target.exe", L"--image", L"--tag",
                               L"health"}));
        }

        if (leaf) {
            wchar_t a[32];
            swprintf_s(a, L"0x%llx", static_cast<unsigned long long>(leaf));
            ExpectOk(c, "client discover-pathscan",
                     Cli(ctx, {L"discover-pathscan", a, L"--depth", L"2", L"--module",
                               L"hdl_test_target.exe"}));
        }

        /* pathvalidate: DynRoot export → mid → leaf needs depth 2 */
        if (dyn_root) {
            auto call = Cli(ctx, {L"call", L"HdlTestDiscoverDynLeaf"});
            uint64_t dyn_leaf = 0;
            ParseHexAfter(call.out, L"return=", &dyn_leaf);
            if (dyn_leaf) {
                wchar_t target_a[32], base_a[32];
                swprintf_s(target_a, L"0x%llx", static_cast<unsigned long long>(dyn_leaf));
                swprintf_s(base_a, L"0x%llx", static_cast<unsigned long long>(dyn_root));
                auto r = Cli(ctx, {L"discover-pathvalidate", target_a, L"--base", base_a,
                                   L"--depth", L"2", L"--offs", L"0,0"});
                ExpectOk(c, "client discover-pathvalidate", r);
                Report(c, Contains(r.out, L"kept=1") || Contains(r.out, L"kept=2"), false,
                       "client discover-pathvalidate kept", "");
            } else {
                Report(c, false, false, "client discover-pathvalidate prep", "");
            }
        }

        if (action) {
            wchar_t a[32];
            swprintf_s(a, L"0x%llx", static_cast<unsigned long long>(action));
            ExpectOk(c, "client discover-watch",
                     Cli(ctx, {L"discover-watch", L"--session", sid, L"--addr", a, L"--args", L"0"}));
            if (obj_a) {
                wchar_t oa[32];
                swprintf_s(oa, L"0x%llx", static_cast<unsigned long long>(obj_a));
                ExpectOk(c, "client discover-watch-region",
                         Cli(ctx, {L"discover-watch-region", L"--session", sid, L"--addr", oa,
                                   L"--size", L"24"}));
            }
            ExpectOk(c, "client discover-action-begin",
                     Cli(ctx, {L"discover-action-begin", L"--session", sid, L"--name", L"act"}));
            ExpectOk(c, "client call DiscoverAction", Cli(ctx, {L"call", L"HdlTestDiscoverAction"}));
            ExpectOk(c, "client call DiscoverDamage",
                     Cli(ctx, {L"call", L"HdlTestDiscoverDamage", L"i64:1"}));
            ExpectOk(c, "client discover-action-end",
                     Cli(ctx, {L"discover-action-end", L"--session", sid}));
            auto rank_r = Cli(ctx, {L"discover-rank", L"--session", sid, L"--name", L"act"});
            ExpectOk(c, "client discover-rank", rank_r);
            uint64_t top_cand = 0;
            ParseU64After(rank_r.out, L"id=", &top_cand);
            if (top_cand) {
                wchar_t cid[32];
                swprintf_s(cid, L"%llu", static_cast<unsigned long long>(top_cand));
                ExpectOk(c, "client discover-evidence",
                         Cli(ctx, {L"discover-evidence", L"--session", sid, L"--id", cid}));
            }
            if (obj_a) {
                wchar_t oa[32];
                swprintf_s(oa, L"0x%llx", static_cast<unsigned long long>(obj_a));
                ExpectOk(c, "client discover-heat",
                         Cli(ctx, {L"discover-heat", L"--session", sid, L"--addr", oa}));
            }
            ExpectOk(c, "client discover-unwatch",
                     Cli(ctx, {L"discover-unwatch", L"--session", sid}));
        }

        if (obj_a) {
            wchar_t a[32];
            swprintf_s(a, L"0x%llx", static_cast<unsigned long long>(obj_a));
            ExpectOk(c, "client discover-cluster",
                     Cli(ctx, {L"discover-cluster", L"--session", sid, L"--seed", a, L"--size", L"24",
                               L"--module", L"hdl_test_target.exe"}));
        }

        ExpectOk(c, "client discover-close", Cli(ctx, {L"discover-close", L"--session", sid}));
    }

    /* REPL: aliases + store + recipe constrain/place/stitch */
    {
        wchar_t store_path[MAX_PATH];
        GetTempPathW(MAX_PATH, store_path);
        wcscat_s(store_path, L"hdl_client_repl_store.json");
        DeleteFileW(store_path);

        uint64_t stitch_pad = 0;
        {
            auto r = Cli(ctx, {L"alloc", L"64", L"--protect", L"RWX"});
            ExpectOk(c, "client alloc stitch pad", r);
            ParseHexAfter(r.out, L"addr=", &stitch_pad);
            if (stitch_pad) {
                wchar_t a[32];
                swprintf_s(a, L"0x%llx", static_cast<unsigned long long>(stitch_pad));
                ExpectOk(c, "client write stitch pad",
                         Cli(ctx, {L"write", a, L"90 90 90 90 90 90 90 90 90 90 90 90 C3"}));
            }
        }

        std::wstring script;
        script += L"help\n";
        script += L"ping\n";
        script += L"dcreate\n";
        script += L"session show\n";
        if (obj_a) {
            script += L"recipe constrain 24 eq_i32:8:80 eq_i32:12:100\n";
        }
        script += L"store add health --kind field\n";
        if (fn) {
            wchar_t line[192];
            swprintf_s(line, L"recipe place placed_fn 0x%llx\n",
                       static_cast<unsigned long long>(fn));
            script += line;
        }
        if (stitch_pad) {
            wchar_t line[256];
            swprintf_s(line, L"recipe stitch stitched --target 0x%llx --kind mov_rax_jmp\n",
                       static_cast<unsigned long long>(stitch_pad));
            script += line;
        }
        script += L"store add export_fn --kind function export HdlTestLocateFn\n";
        script += L"store save ";
        script += store_path;
        script += L"\n";
        script += L"store list\n";
        script += L"store revalidate\n";
        script += L"quit\n";

        ProcResult r;
        std::vector<std::wstring> args = {L"--store", store_path, std::to_wstring(ctx.pid), L"repl"};
        RunProcess(ctx.client, args, &script, 90000, &r);
        ExpectExit0(c, "client REPL script exit", r);
        Report(c, Contains(r.out, L"status=OK") || Contains(r.out, L"remote_pid="), false,
               "client REPL ping output", "");
        Report(c, Contains(r.out, L"discover session=") || Contains(r.out, L"session="), false,
               "client REPL dcreate", "");
        Report(c, Contains(r.out, L"store saved") || Contains(r.out, L"store add"), false,
               "client REPL store", "");
        Report(c, Contains(r.out, L"place cave") || Contains(r.out, L"AllocNear fallback") ||
                      Contains(r.out, L"store updated interest"),
               false, "client REPL recipe place", "");
        Report(c, !stitch_pad || Contains(r.out, L"stub_va=") ||
                      Contains(r.out, L"stub+patch") || Contains(r.out, L"patch handle="),
               false, "client REPL recipe stitch", "");

        hdlcli::InterestStore loaded;
        Report(c, loaded.Load(store_path), false, "client REPL store file load", "");
        if (fn) {
            Report(c, loaded.Find("placed_fn") != nullptr, false, "client store has placed_fn", "");
        }
        DeleteFileW(store_path);
        if (stitch_pad) {
            wchar_t a[32];
            swprintf_s(a, L"0x%llx", static_cast<unsigned long long>(stitch_pad));
            Cli(ctx, {L"free", a});
        }
    }

    /* --json structured output + actionable error hints */
    {
        ProcResult r;
        RunProcess(ctx.client, {L"--json", std::to_wstring(ctx.pid), L"ping"}, nullptr, 30000, &r);
        Report(c,
               r.exit_code == 0 && Contains(r.out, L"\"ok\":true") &&
                   Contains(r.out, L"\"cmd\":\"ping\"") && Contains(r.out, L"\"remote_pid\"") &&
                   Contains(r.out, L"\"error\":null"),
               false, "client --json ping envelope", "");

        ProcResult mods;
        RunProcess(ctx.client, {L"--json", std::to_wstring(ctx.pid), L"modules"}, nullptr, 30000,
                   &mods);
        Report(c,
               mods.exit_code == 0 && Contains(mods.out, L"\"ok\":true") &&
                   Contains(mods.out, L"\"modules\"") && Contains(mods.out, L"\"base\""),
               false, "client --json modules array", "");

        ProcResult failj;
        RunProcess(ctx.client,
                   {L"--json", std::to_wstring(ctx.pid), L"call", L"--addr", L"0", L"--main"},
                   nullptr, 30000, &failj);
        Report(c,
               failj.exit_code != 0 && Contains(failj.out, L"\"ok\":false") &&
                   Contains(failj.out, L"\"error\"") && Contains(failj.out, L"\"code\"") &&
                   Contains(failj.out, L"\"name\"") && Contains(failj.out, L"\"hint\"") &&
                   failj.out.find(L"\"hint\":\"\"") == std::wstring::npos,
               false, "client --json call --main error hint", "");

        ProcResult failt;
        RunProcess(ctx.client, {std::to_wstring(ctx.pid), L"call", L"--addr", L"0", L"--main"},
                   nullptr, 30000, &failt);
        Report(c,
               failt.exit_code != 0 && Contains(failt.out, L"status=") &&
                   Contains(failt.out, L"hint:"),
               false, "client text call --main prints hint", "");
    }

    /* Usage documents new surfaces */
    {
        ProcResult r;
        RunProcess(ctx.client, {}, nullptr, 10000, &r);
        Report(c,
               r.out.find(L"discover-scan") != std::wstring::npos &&
                   r.out.find(L"hook-enable") != std::wstring::npos &&
                   r.out.find(L"--tui") != std::wstring::npos &&
                   r.out.find(L"--json") != std::wstring::npos &&
                   r.out.find(L"write <hex-address>") != std::wstring::npos &&
                   r.out.find(L"discover-pathvalidate") != std::wstring::npos &&
                   r.out.find(L"stub") != std::wstring::npos &&
                   r.out.find(L"recipe place") != std::wstring::npos,
               false, "client usage documents controller", "");
    }

    /* --tui flag is recognized (do not enter curses — invalid pid before connect fails early) */
    {
        ProcResult r;
        RunProcess(ctx.client, {L"--tui", L"1"}, nullptr, 10000, &r);
        Report(c, r.exit_code != 0 && !Contains(r.out, L"requires HDL_CLIENT_TUI"), false,
               "client --tui linked (connect fail on bad pid)", "");
    }
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    std::wstring dll_path;
    std::wstring target_path;
    std::wstring client_path;

    for (int i = 1; i < argc; ++i) {
        if (_wcsicmp(argv[i], L"--dll") == 0 && i + 1 < argc) {
            dll_path = argv[++i];
        } else if (_wcsicmp(argv[i], L"--target") == 0 && i + 1 < argc) {
            target_path = argv[++i];
        } else if (_wcsicmp(argv[i], L"--client") == 0 && i + 1 < argc) {
            client_path = argv[++i];
        } else if (_wcsicmp(argv[i], L"--help") == 0 || _wcsicmp(argv[i], L"-h") == 0) {
            std::wprintf(L"hdl_client_tests — hdlclient E2E vs hdl_test_target\n"
                         L"  [--dll PATH] [--target PATH] [--client PATH]\n");
            return 0;
        }
    }

    const std::wstring dir = hdltest::ExeDir();
    if (dll_path.empty()) {
        dll_path = hdltest::JoinPath(dir, L"hdllib.dll");
    }
    if (target_path.empty()) {
        target_path = hdltest::JoinPath(dir, L"hdl_test_target.exe");
    }
    if (client_path.empty()) {
        client_path = hdltest::JoinPath(dir, L"hdlclient.exe");
    }

    wchar_t dll_full[MAX_PATH], target_full[MAX_PATH], client_full[MAX_PATH];
    GetFullPathNameW(dll_path.c_str(), MAX_PATH, dll_full, nullptr);
    GetFullPathNameW(target_path.c_str(), MAX_PATH, target_full, nullptr);
    GetFullPathNameW(client_path.c_str(), MAX_PATH, client_full, nullptr);

    if (!hdltest::FileExists(dll_full) || !hdltest::FileExists(target_full) ||
        !hdltest::FileExists(client_full)) {
        std::wprintf(L"Missing dll/target/client under %ls\n", dir.c_str());
        return 2;
    }

    std::wprintf(L"client=%ls\ndll=%ls\ntarget=%ls\n", client_full, dll_full, target_full);

    Counters c;
    RunStoreUnit(c);
    RunClientLiveTests(c, client_full, target_full, dll_full);

    std::printf("\n== Summary ==\n");
    std::printf("passed=%d failed=%d soft=%d skipped=%d\n", c.passed, c.failed, c.soft_failed,
                c.skipped);
    return c.failed == 0 ? 0 : 1;
}
