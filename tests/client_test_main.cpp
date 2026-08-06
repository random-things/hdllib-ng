/* End-to-end hdlclient tests against hdl_test_target (parity with hdl_tests locate/discover). */
#include "hdllib/hdllib.h"
#include "hdllib/pipe_name.h"
#include "pipe_client.hpp"
#include "rpc/runtime.hpp"
#include "store.hpp"
#include "support.hpp"
#include "json/json.hpp"

#include <atomic>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

using hdltest::Counters;
using hdltest::IlLevel;
using hdltest::Report;
using hdltest::TargetProc;
using hdltest::TargetProfile;

namespace {

std::string ToNarrow(const std::wstring& w) {
    if (w.empty())
        return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), nullptr, 0,
                                      nullptr, nullptr);
    if (n <= 0)
        return {};
    std::string s(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), s.data(), n, nullptr,
                        nullptr);
    return s;
}

bool LoadFileUtf8(const char* path, std::string* out) {
    if (!path || !out) {
        return false;
    }
    FILE* f = nullptr;
    if (fopen_s(&f, path, "rb") != 0 || !f) {
        return false;
    }
    out->clear();
    char buf[4096];
    while (size_t n = fread(buf, 1, sizeof(buf), f)) {
        out->append(buf, n);
    }
    fclose(f);
    return true;
}

bool ValidateCandidateFile(const wchar_t* path, uint64_t* out_count) {
    if (!path || !out_count) {
        return false;
    }
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }
    uint8_t header[24]{};
    DWORD read = 0;
    LARGE_INTEGER file_size{};
    const bool read_ok = ReadFile(file, header, sizeof(header), &read, nullptr) &&
                         read == sizeof(header) && GetFileSizeEx(file, &file_size);
    CloseHandle(file);
    if (!read_ok || std::memcmp(header, "HDLCAND1", 8) != 0) {
        return false;
    }
    uint32_t version = 0;
    uint32_t record_size = 0;
    uint64_t count = 0;
    std::memcpy(&version, header + 8, sizeof(version));
    std::memcpy(&record_size, header + 12, sizeof(record_size));
    std::memcpy(&count, header + 16, sizeof(count));
    if (version != 1 || record_size != sizeof(uint64_t) ||
        count > (INT64_MAX - sizeof(header)) / sizeof(uint64_t) ||
        file_size.QuadPart != static_cast<LONGLONG>(sizeof(header) + count * sizeof(uint64_t))) {
        return false;
    }
    *out_count = count;
    return true;
}

/* Golden fixtures use "*" for any non-absent value (string/number/array/object/bool). */
bool GoldenFieldMatches(const std::string& live, const std::string& golden, const char* key) {
    std::string gval;
    if (!hdl::json::ExtractString(golden, key, &gval)) {
        /* Try as presence-only: key must exist in live when present in golden text. */
        if (golden.find(std::string("\"") + key + "\"") == std::string::npos) {
            return true;
        }
        /* Numeric / bool / null / nested — require key present in live. */
        return live.find(std::string("\"") + key + "\"") != std::string::npos;
    }
    if (gval == "*") {
        /* Wildcard: accept any present value for this key. */
        return live.find(std::string("\"") + key + "\"") != std::string::npos;
    }
    std::string lval;
    return hdl::json::ExtractString(live, key, &lval) && lval == gval;
}

bool MatchEnvelopeGolden(const std::string& live, const std::string& golden_path) {
    std::string golden;
    if (!LoadFileUtf8(golden_path.c_str(), &golden)) {
        return false;
    }
    /* Required envelope keys always present in fixtures. */
    if (!GoldenFieldMatches(live, golden, "cmd")) {
        return false;
    }
    const bool g_ok_true = golden.find("\"ok\":true") != std::string::npos;
    const bool g_ok_false = golden.find("\"ok\":false") != std::string::npos;
    const bool l_ok_true = live.find("\"ok\":true") != std::string::npos;
    const bool l_ok_false = live.find("\"ok\":false") != std::string::npos;
    if (g_ok_true && !l_ok_true) {
        return false;
    }
    if (g_ok_false && !l_ok_false) {
        return false;
    }
    if (golden.find("\"error\":null") != std::string::npos) {
        if (live.find("\"error\":null") == std::string::npos) {
            return false;
        }
    } else if (golden.find("\"error\":{") != std::string::npos) {
        if (live.find("\"error\":{") == std::string::npos) {
            return false;
        }
        if (!GoldenFieldMatches(live, golden, "name")) {
            return false;
        }
        if (!GoldenFieldMatches(live, golden, "hint")) {
            return false;
        }
        /* code may be wildcard via "*" string — fixtures use numeric "*"? ours use "*" as string
         * in name/hint; code is numeric in fixture as "*"-string under error — ExtractString works
         * only for quoted. Our error golden has "code": "*" as string? Looking at fixture - "code":
         * "*" is invalid JSON if unquoted. We used "code": "*" as JSON string. Live has numeric
         * code. So for code, just require presence. */
        if (live.find("\"code\"") == std::string::npos) {
            return false;
        }
    }
    if (golden.find("\"remote_pid\"") != std::string::npos) {
        uint64_t pid = 0;
        if (!hdl::json::ExtractU64(live, "remote_pid", &pid) || pid == 0) {
            return false;
        }
    }
    if (golden.find("\"modules\"") != std::string::npos) {
        if (live.find("\"modules\"") == std::string::npos) {
            return false;
        }
    }
    int32_t status = -1;
    if (!hdl::json::ExtractI32(live, "status", &status)) {
        return false;
    }
    if (g_ok_true && status != HDL_OK) {
        return false;
    }
    if (g_ok_false && status == HDL_OK) {
        return false;
    }
    return true;
}

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
            /* Copy UTF-16LE bytes into wchar_t storage (Windows wchar_t is 2 bytes). */
            std::wstring w(nbytes / sizeof(wchar_t), L'\0');
            memcpy(w.data(), raw.data() + start, nbytes);
            collected.append(w);
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

/* True when stdout is exactly one top-level JSON object (optional trailing whitespace). */
bool IsSingleJsonEnvelope(const std::wstring& out) {
    const std::string n = ToNarrow(out);
    const size_t a = n.find_first_not_of(" \t\r\n");
    if (a == std::string::npos || n[a] != '{') {
        return false;
    }
    const size_t b = n.find_last_not_of(" \t\r\n");
    if (b == std::string::npos || n[b] != '}') {
        return false;
    }
    const std::string body = n.substr(a, b - a + 1);
    std::vector<std::pair<std::string, std::string>> fields;
    if (!hdl::json::ParseObjectFields(body, &fields)) {
        return false;
    }
    int depth = 0;
    bool in_str = false;
    bool esc = false;
    size_t end = std::string::npos;
    for (size_t i = 0; i < body.size(); ++i) {
        const char ch = body[i];
        if (in_str) {
            if (esc) {
                esc = false;
            } else if (ch == '\\') {
                esc = true;
            } else if (ch == '"') {
                in_str = false;
            }
            continue;
        }
        if (ch == '"') {
            in_str = true;
        } else if (ch == '{') {
            ++depth;
        } else if (ch == '}') {
            --depth;
            if (depth == 0) {
                end = i;
                break;
            }
        }
    }
    return end != std::string::npos && end + 1 == body.size();
}

/* True when stdout is one envelope with top-level ok:true. */
bool JsonEnvelopeOk(const std::wstring& out) {
    if (!IsSingleJsonEnvelope(out)) {
        return false;
    }
    const std::string n = ToNarrow(out);
    const size_t a = n.find_first_not_of(" \t\r\n");
    const size_t b = n.find_last_not_of(" \t\r\n");
    const std::string body = n.substr(a, b - a + 1);
    std::vector<std::pair<std::string, std::string>> fields;
    if (!hdl::json::ParseObjectFields(body, &fields)) {
        return false;
    }
    for (const auto& f : fields) {
        if (f.first == "ok" && f.second == "true") {
            return true;
        }
    }
    return false;
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
    const std::string detail = r.exit_code == 0 ? std::string{} : ToNarrow(r.out);
    Report(c, r.exit_code == 0, false, name, detail.c_str());
}

bool PipeReadExact(HANDLE pipe, void* buf, DWORD size) {
    auto* p = static_cast<uint8_t*>(buf);
    DWORD remaining = size;
    while (remaining) {
        DWORD got = 0;
        if (!ReadFile(pipe, p, remaining, &got, nullptr) || got == 0) {
            return false;
        }
        p += got;
        remaining -= got;
    }
    return true;
}

bool PipeWriteExact(HANDLE pipe, const void* buf, DWORD size) {
    const auto* p = static_cast<const uint8_t*>(buf);
    DWORD remaining = size;
    while (remaining) {
        DWORD wrote = 0;
        if (!WriteFile(pipe, p, remaining, &wrote, nullptr) || wrote == 0) {
            return false;
        }
        p += wrote;
        remaining -= wrote;
    }
    return true;
}

bool ReadTestEnvelope(HANDLE pipe, hdl::rpc::v1::Envelope* envelope) {
    uint32_t size = 0;
    if (!PipeReadExact(pipe, &size, sizeof(size)) || size > hdl::rpc::kMaxFrameBytes) {
        return false;
    }
    std::vector<uint8_t> bytes(size);
    return (!size || PipeReadExact(pipe, bytes.data(), size)) &&
           hdl::rpc::ParseEnvelope(bytes.data(), bytes.size(), envelope);
}

bool WriteTestEnvelope(HANDLE pipe, const hdl::rpc::v1::Envelope& envelope) {
    std::vector<uint8_t> bytes;
    if (!hdl::rpc::SerializeEnvelope(envelope, &bytes)) {
        return false;
    }
    const uint32_t size = static_cast<uint32_t>(bytes.size());
    return PipeWriteExact(pipe, &size, sizeof(size)) &&
           (!size || PipeWriteExact(pipe, bytes.data(), size));
}

enum class TestPeerFault {
    WrongRequestId,
    InvalidUnaryPayload,
    WrongStreamSequence,
    AbortStream,
    TerminalStreamError,
    PartialFailure
};

void RunClientResponseValidation(Counters& c, TestPeerFault fault, uint32_t pid,
                                 const char* test_name) {
    wchar_t name[128];
    if (HdlFormatPipeName(pid, name, 128) != 0) {
        Report(c, false, false, test_name, "pipe name format failed");
        return;
    }
    HANDLE pipe =
        CreateNamedPipeW(name, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                         1, 4096, 4096, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) {
        Report(c, false, false, test_name, "CreateNamedPipe failed");
        return;
    }

    const bool streaming = fault == TestPeerFault::WrongStreamSequence ||
                           fault == TestPeerFault::AbortStream ||
                           fault == TestPeerFault::TerminalStreamError;
    std::atomic<bool> served{false};
    std::thread server([&] {
        const BOOL connected =
            ConnectNamedPipe(pipe, nullptr) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        char preface[hdl::rpc::kConnectionPrefaceSize]{};
        hdl::rpc::v1::Envelope envelope;
        if (!connected || !PipeReadExact(pipe, preface, static_cast<DWORD>(sizeof(preface))) ||
            std::memcmp(preface, hdl::rpc::kConnectionPreface, sizeof(preface)) != 0 ||
            !ReadTestEnvelope(pipe, &envelope) || !envelope.has_client_hello()) {
            return;
        }
        envelope.Clear();
        auto* hello = envelope.mutable_server_hello();
        hello->set_protocol_major(hdl::rpc::kProtocolMajor);
        hello->set_protocol_minor(hdl::rpc::kProtocolMinor);
        auto* limits = hello->mutable_limits();
        limits->set_max_frame_bytes(hdl::rpc::kMaxFrameBytes);
        limits->set_max_in_flight(1);
        limits->set_max_stream_chunk_bytes(hdl::rpc::kMaxStreamChunkBytes);
        auto* method = hello->add_methods();
        method->set_name(streaming ? "hdl.rpc.v1.Process/EnumRegions" : "hdl.rpc.v1.Control/Ping");
        method->set_server_streaming(streaming);
        if (!WriteTestEnvelope(pipe, envelope) || !ReadTestEnvelope(pipe, &envelope) ||
            !envelope.has_request()) {
            return;
        }
        const uint64_t request_id = envelope.request().request_id();
        envelope.Clear();
        auto* response = envelope.mutable_response();
        response->set_request_id(fault == TestPeerFault::WrongRequestId ? request_id + 1
                                                                        : request_id);
        response->set_sequence(fault == TestPeerFault::WrongStreamSequence ? 1 : 0);
        response->set_end_stream(!streaming || fault == TestPeerFault::WrongStreamSequence ||
                                 fault == TestPeerFault::TerminalStreamError);
        const int32_t response_status =
            fault == TestPeerFault::PartialFailure
                ? HDL_E_BUFFER_SMALL
                : (fault == TestPeerFault::TerminalStreamError ? HDL_E_TIMEOUT : HDL_OK);
        hdl::rpc::SetRpcStatus(response_status, response->mutable_status());
        if (fault == TestPeerFault::InvalidUnaryPayload) {
            response->set_payload("\x80", 1);
        } else if (fault == TestPeerFault::AbortStream) {
            hdl::rpc::v1::EnumRegionsResponse batch;
            batch.add_regions()->set_base(0x1000);
            if (!batch.SerializeToString(response->mutable_payload())) {
                return;
            }
        } else if (!streaming) {
            hdl::rpc::v1::PingResponse reply;
            reply.set_pid(1);
            if (!reply.SerializeToString(response->mutable_payload())) {
                return;
            }
        }
        served.store(WriteTestEnvelope(pipe, envelope));
    });

    PipeClient client(pid);
    bool valid = false;
    if (client.Connect(3000)) {
        if (streaming) {
            hdl::rpc::ProcessClient service(&client);
            hdl::rpc::v1::Empty request;
            const hdl::rpc::Status status = service.EnumRegions(
                request, [](const hdl::rpc::v1::EnumRegionsResponse&) { return false; });
            valid = fault == TestPeerFault::AbortStream
                        ? status.hdl_status() == HDL_E_CANCELLED
                        : (fault == TestPeerFault::TerminalStreamError
                               ? status.hdl_status() == HDL_E_TIMEOUT
                               : status.code() == hdl::rpc::v1::RPC_CODE_UNAVAILABLE);
        } else {
            hdl::rpc::ControlClient service(&client);
            hdl::rpc::v1::Empty request;
            const auto result = service.Ping(request);
            valid = fault == TestPeerFault::PartialFailure
                        ? !result.status.ok() && result.status.hdl_status() == HDL_E_BUFFER_SMALL &&
                              result.has_response && result.response.pid() == 1
                        : result.status.code() == hdl::rpc::v1::RPC_CODE_UNAVAILABLE;
        }
    }
    server.join();
    Report(c, valid && served.load(), false, test_name,
           valid ? "response contract handled as expected" : "unexpected response handling");
    CloseHandle(pipe);
}

void RunOneInFlightValidation(Counters& c) {
    constexpr uint32_t pid = 0x71C0FFE5u;
    wchar_t name[128];
    if (HdlFormatPipeName(pid, name, 128) != 0) {
        Report(c, false, false, "ipc/one_in_flight", "pipe name format failed");
        return;
    }
    HANDLE pipe =
        CreateNamedPipeW(name, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                         1, 4096, 4096, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) {
        Report(c, false, false, "ipc/one_in_flight", "CreateNamedPipe failed");
        return;
    }

    std::atomic<bool> served{false};
    std::atomic<bool> second_buffered{false};
    std::thread server([&] {
        const BOOL connected =
            ConnectNamedPipe(pipe, nullptr) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        char preface[hdl::rpc::kConnectionPrefaceSize]{};
        hdl::rpc::v1::Envelope envelope;
        if (!connected || !PipeReadExact(pipe, preface, static_cast<DWORD>(sizeof(preface))) ||
            std::memcmp(preface, hdl::rpc::kConnectionPreface, sizeof(preface)) != 0 ||
            !ReadTestEnvelope(pipe, &envelope) || !envelope.has_client_hello()) {
            return;
        }
        envelope.Clear();
        auto* hello = envelope.mutable_server_hello();
        hello->set_protocol_major(hdl::rpc::kProtocolMajor);
        hello->set_protocol_minor(hdl::rpc::kProtocolMinor);
        hello->mutable_limits()->set_max_frame_bytes(hdl::rpc::kMaxFrameBytes);
        hello->mutable_limits()->set_max_in_flight(1);
        hello->mutable_limits()->set_max_stream_chunk_bytes(hdl::rpc::kMaxStreamChunkBytes);
        auto* method = hello->add_methods();
        method->set_name("hdl.rpc.v1.Control/Ping");
        method->set_server_streaming(false);
        if (!WriteTestEnvelope(pipe, envelope) || !ReadTestEnvelope(pipe, &envelope) ||
            !envelope.has_request()) {
            return;
        }

        auto reply = [&](uint64_t request_id) {
            hdl::rpc::v1::Envelope response_envelope;
            auto* response = response_envelope.mutable_response();
            response->set_request_id(request_id);
            response->set_sequence(0);
            response->set_end_stream(true);
            hdl::rpc::SetRpcStatus(HDL_OK, response->mutable_status());
            hdl::rpc::v1::PingResponse ping;
            ping.set_pid(pid);
            return ping.SerializeToString(response->mutable_payload()) &&
                   WriteTestEnvelope(pipe, response_envelope);
        };

        const uint64_t first_id = envelope.request().request_id();
        Sleep(150);
        DWORD available = 0;
        if (PeekNamedPipe(pipe, nullptr, 0, nullptr, &available, nullptr)) {
            second_buffered.store(available != 0);
        }
        if (!reply(first_id) || !ReadTestEnvelope(pipe, &envelope) || !envelope.has_request() ||
            !reply(envelope.request().request_id())) {
            return;
        }
        served.store(true);
    });

    PipeClient client(pid);
    std::atomic<int> successful{0};
    if (client.Connect(3000)) {
        auto ping = [&] {
            hdl::rpc::ControlClient control(&client);
            const auto result = control.Ping(hdl::rpc::v1::Empty{});
            if (result.status.ok() && result.has_response && result.response.pid() == pid) {
                successful.fetch_add(1);
            }
        };
        std::thread first(ping);
        std::thread second(ping);
        first.join();
        second.join();
    }
    server.join();
    Report(c, served.load() && successful.load() == 2 && !second_buffered.load(), false,
           "ipc/one_in_flight", "one PipeClient serializes concurrent calls");
    CloseHandle(pipe);
}

HANDLE OpenNegotiatedPipe(uint32_t pid) {
    HANDLE pipe = HdlOpenLocalPipe(pid);
    if (pipe == INVALID_HANDLE_VALUE) {
        return INVALID_HANDLE_VALUE;
    }
    DWORD mode = PIPE_READMODE_BYTE | PIPE_WAIT;
    SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr);
    hdl::rpc::v1::Envelope envelope;
    envelope.mutable_client_hello()->set_protocol_major(hdl::rpc::kProtocolMajor);
    envelope.mutable_client_hello()->set_protocol_minor(hdl::rpc::kProtocolMinor);
    envelope.mutable_client_hello()->set_client_name("hdl_client_tests");
    if (!PipeWriteExact(pipe, hdl::rpc::kConnectionPreface,
                        static_cast<DWORD>(hdl::rpc::kConnectionPrefaceSize)) ||
        !WriteTestEnvelope(pipe, envelope) || !ReadTestEnvelope(pipe, &envelope) ||
        !envelope.has_server_hello()) {
        CloseHandle(pipe);
        return INVALID_HANDLE_VALUE;
    }
    return pipe;
}

void RunLiveTransportValidation(Counters& c, uint32_t pid) {
    hdl::rpc::v1::Empty empty;
    int32_t status = HDL_E_FAILED;
    const bool unknown = hdltest::PipeCall(
        pid, "hdl.rpc.v1.Control/Unknown", empty, [](std::string_view) { return true; }, &status,
        5000);
    Report(c, unknown && status == HDL_E_NOT_FOUND, false, "ipc/unknown_method",
           "unknown method returns UNIMPLEMENTED/HDL_E_NOT_FOUND");

    HANDLE pipe = OpenNegotiatedPipe(pid);
    bool malformed_rejected = false;
    if (pipe != INVALID_HANDLE_VALUE) {
        hdl::rpc::v1::Envelope envelope;
        auto* request = envelope.mutable_request();
        request->set_request_id(1);
        request->set_method("hdl.rpc.v1.Control/Ping");
        request->set_payload("\x80", 1);
        if (WriteTestEnvelope(pipe, envelope) && ReadTestEnvelope(pipe, &envelope) &&
            envelope.has_response()) {
            const auto& response = envelope.response();
            malformed_rejected =
                response.request_id() == 1 && response.end_stream() && response.has_status() &&
                response.status().code() == hdl::rpc::v1::RPC_CODE_INVALID_ARGUMENT;
        }
        CloseHandle(pipe);
    }
    Report(c, malformed_rejected, false, "ipc/malformed_method_payload",
           "malformed typed payload returns INVALID_ARGUMENT");

    pipe = OpenNegotiatedPipe(pid);
    bool oversized_rejected = false;
    if (pipe != INVALID_HANDLE_VALUE) {
        hdl::rpc::v1::Envelope envelope;
        const uint32_t oversized = hdl::rpc::kMaxFrameBytes + 1;
        if (PipeWriteExact(pipe, &oversized, sizeof(oversized)) &&
            ReadTestEnvelope(pipe, &envelope) && envelope.has_go_away()) {
            oversized_rejected =
                envelope.go_away().status().code() == hdl::rpc::v1::RPC_CODE_RESOURCE_EXHAUSTED &&
                envelope.go_away().status().reason() == "FRAME_TOO_LARGE";
        }
        CloseHandle(pipe);
    }
    Report(c, oversized_rejected, false, "ipc/oversized_frame",
           "oversized request frame receives GoAway");
}

/* Peer that answers ClientHello with an incompatible major so PipeClient::Negotiate rejects. */
void RunNegotiateMismatch(Counters& c) {
    const uint32_t pid = 0x71C0FFEEu;
    wchar_t name[128];
    if (HdlFormatPipeName(pid, name, 128) != 0) {
        Report(c, false, false, "ipc/reject_major_mismatch", "pipe name format failed");
        return;
    }

    HANDLE pipe =
        CreateNamedPipeW(name, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                         1, 4096, 4096, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) {
        Report(c, false, false, "ipc/reject_major_mismatch", "CreateNamedPipe failed");
        return;
    }

    std::atomic<bool> served{false};
    std::thread server([&] {
        const BOOL connected =
            ConnectNamedPipe(pipe, nullptr) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (!connected) {
            return;
        }
        char preface[hdl::rpc::kConnectionPrefaceSize]{};
        if (!PipeReadExact(pipe, preface, static_cast<DWORD>(sizeof(preface))) ||
            std::memcmp(preface, hdl::rpc::kConnectionPreface, sizeof(preface)) != 0) {
            return;
        }
        uint32_t rsize = 0;
        if (!PipeReadExact(pipe, &rsize, sizeof(rsize))) {
            return;
        }
        std::vector<uint8_t> req(rsize);
        if (rsize && !PipeReadExact(pipe, req.data(), rsize)) {
            return;
        }
        hdl::rpc::v1::Envelope request;
        if (!hdl::rpc::ParseEnvelope(req.data(), req.size(), &request) ||
            !request.has_client_hello()) {
            return;
        }
        hdl::rpc::v1::Envelope response;
        auto* hello = response.mutable_server_hello();
        hello->set_protocol_major(99); /* incompatible major */
        hello->set_protocol_minor(0);
        hello->set_server_name("mismatch-peer");
        hello->set_server_build("test");
        std::vector<uint8_t> resp;
        if (!hdl::rpc::SerializeEnvelope(response, &resp)) {
            return;
        }
        const uint32_t wsize = static_cast<uint32_t>(resp.size());
        if (!PipeWriteExact(pipe, &wsize, sizeof(wsize)) ||
            !PipeWriteExact(pipe, resp.data(), wsize)) {
            return;
        }
        served.store(true);
    });

    PipeClient client(pid);
    const bool connected = client.Connect(3000);
    const std::string& err = client.NegotiateError();
    server.join();
    const bool rejected = !connected && err.find("mismatch") != std::string::npos && served.load();
    Report(c, rejected, false, "ipc/reject_major_mismatch",
           rejected ? "PipeClient::Negotiate refuses incompatible major" : err.c_str());

    CloseHandle(pipe);
}

void RunClientDeadlineValidation(Counters& c) {
    constexpr DWORD timeout_ms = 150;

    {
        constexpr uint32_t pid = 0x71C0FFD1u;
        wchar_t name[128];
        HANDLE pipe = INVALID_HANDLE_VALUE;
        if (HdlFormatPipeName(pid, name, 128) == 0) {
            pipe = CreateNamedPipeW(name, PIPE_ACCESS_DUPLEX,
                                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, 4096, 4096,
                                    0, nullptr);
        }
        if (pipe == INVALID_HANDLE_VALUE) {
            Report(c, false, false, "ipc/connect_deadline", "CreateNamedPipe failed");
        } else {
            HANDLE release = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            std::atomic<bool> hello_received{false};
            std::thread server([&] {
                const BOOL connected = ConnectNamedPipe(pipe, nullptr)
                                           ? TRUE
                                           : (GetLastError() == ERROR_PIPE_CONNECTED);
                char preface[hdl::rpc::kConnectionPrefaceSize]{};
                hdl::rpc::v1::Envelope hello;
                if (connected &&
                    PipeReadExact(pipe, preface, static_cast<DWORD>(sizeof(preface))) &&
                    ReadTestEnvelope(pipe, &hello) && hello.has_client_hello()) {
                    hello_received.store(true);
                    WaitForSingleObject(release, 2000);
                }
            });

            PipeClient client(pid);
            const ULONGLONG start = GetTickCount64();
            const bool connected = client.Connect(timeout_ms);
            const ULONGLONG elapsed = GetTickCount64() - start;
            SetEvent(release);
            server.join();
            const bool bounded = !connected && hello_received.load() && elapsed >= timeout_ms / 2 &&
                                 elapsed < 1000 &&
                                 client.NegotiateError().find("deadline") != std::string::npos;
            Report(c, bounded, false, "ipc/connect_deadline",
                   bounded ? "stalled ServerHello cancelled at deadline"
                           : "connect did not honor its end-to-end deadline");
            CloseHandle(release);
            CloseHandle(pipe);
        }
    }

    {
        constexpr uint32_t pid = 0x71C0FFD2u;
        wchar_t name[128];
        HANDLE pipe = INVALID_HANDLE_VALUE;
        if (HdlFormatPipeName(pid, name, 128) == 0) {
            pipe = CreateNamedPipeW(name, PIPE_ACCESS_DUPLEX,
                                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, 4096, 4096,
                                    0, nullptr);
        }
        if (pipe == INVALID_HANDLE_VALUE) {
            Report(c, false, false, "ipc/unary_deadline", "CreateNamedPipe failed");
        } else {
            HANDLE release = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            std::atomic<bool> request_received{false};
            std::thread server([&] {
                const BOOL connected = ConnectNamedPipe(pipe, nullptr)
                                           ? TRUE
                                           : (GetLastError() == ERROR_PIPE_CONNECTED);
                char preface[hdl::rpc::kConnectionPrefaceSize]{};
                hdl::rpc::v1::Envelope envelope;
                if (!connected ||
                    !PipeReadExact(pipe, preface, static_cast<DWORD>(sizeof(preface))) ||
                    !ReadTestEnvelope(pipe, &envelope) || !envelope.has_client_hello()) {
                    return;
                }
                envelope.Clear();
                auto* hello = envelope.mutable_server_hello();
                hello->set_protocol_major(hdl::rpc::kProtocolMajor);
                hello->set_protocol_minor(hdl::rpc::kProtocolMinor);
                hello->mutable_limits()->set_max_frame_bytes(hdl::rpc::kMaxFrameBytes);
                hello->mutable_limits()->set_max_in_flight(1);
                hello->mutable_limits()->set_max_stream_chunk_bytes(hdl::rpc::kMaxStreamChunkBytes);
                auto* method = hello->add_methods();
                method->set_name("hdl.rpc.v1.Control/Ping");
                method->set_server_streaming(false);
                if (WriteTestEnvelope(pipe, envelope) && ReadTestEnvelope(pipe, &envelope) &&
                    envelope.has_request()) {
                    request_received.store(true);
                    WaitForSingleObject(release, 2000);
                }
            });

            PipeClient client(pid);
            bool bounded = false;
            if (client.Connect(1000)) {
                hdl::rpc::ControlClient control(&client);
                const ULONGLONG start = GetTickCount64();
                const auto result =
                    control.Ping(hdl::rpc::v1::Empty{}, hdl::rpc::CallOptions{timeout_ms});
                const ULONGLONG elapsed = GetTickCount64() - start;
                bounded = request_received.load() &&
                          result.status.code() == hdl::rpc::v1::RPC_CODE_DEADLINE_EXCEEDED &&
                          result.status.hdl_status() == HDL_E_TIMEOUT &&
                          result.status.outcome_unknown() && elapsed >= timeout_ms / 2 &&
                          elapsed < 1000;
            }
            SetEvent(release);
            server.join();
            Report(c, bounded, false, "ipc/unary_deadline",
                   bounded ? "stalled response cancelled at deadline"
                           : "unary call did not cancel stalled pipe I/O");
            CloseHandle(release);
            CloseHandle(pipe);
        }
    }

    {
        constexpr uint32_t pid = 0x71C0FFD3u;
        wchar_t name[128];
        HANDLE pipe = INVALID_HANDLE_VALUE;
        if (HdlFormatPipeName(pid, name, 128) == 0) {
            pipe = CreateNamedPipeW(name, PIPE_ACCESS_DUPLEX,
                                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, 1, 4096, 4096,
                                    0, nullptr);
        }
        if (pipe == INVALID_HANDLE_VALUE) {
            Report(c, false, false, "ipc/raw_helper_deadline", "CreateNamedPipe failed");
        } else {
            HANDLE release = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            std::atomic<bool> request_received{false};
            std::thread server([&] {
                const BOOL connected = ConnectNamedPipe(pipe, nullptr)
                                           ? TRUE
                                           : (GetLastError() == ERROR_PIPE_CONNECTED);
                char preface[hdl::rpc::kConnectionPrefaceSize]{};
                hdl::rpc::v1::Envelope envelope;
                if (!connected ||
                    !PipeReadExact(pipe, preface, static_cast<DWORD>(sizeof(preface))) ||
                    !ReadTestEnvelope(pipe, &envelope) || !envelope.has_client_hello()) {
                    return;
                }
                envelope.Clear();
                auto* hello = envelope.mutable_server_hello();
                hello->set_protocol_major(hdl::rpc::kProtocolMajor);
                hello->set_protocol_minor(hdl::rpc::kProtocolMinor);
                hello->mutable_limits()->set_max_frame_bytes(hdl::rpc::kMaxFrameBytes);
                hello->mutable_limits()->set_max_in_flight(1);
                hello->mutable_limits()->set_max_stream_chunk_bytes(hdl::rpc::kMaxStreamChunkBytes);
                if (WriteTestEnvelope(pipe, envelope) && ReadTestEnvelope(pipe, &envelope) &&
                    envelope.has_request()) {
                    request_received.store(true);
                    WaitForSingleObject(release, 2000);
                }
            });

            int32_t status = HDL_E_FAILED;
            const ULONGLONG start = GetTickCount64();
            const bool called = hdltest::PipeCall(
                pid, "hdl.rpc.v1.Control/Ping", hdl::rpc::v1::Empty{},
                [](std::string_view) { return true; }, &status, timeout_ms);
            const ULONGLONG elapsed = GetTickCount64() - start;
            SetEvent(release);
            server.join();
            const bool bounded =
                !called && request_received.load() && elapsed >= timeout_ms / 2 && elapsed < 1000;
            Report(c, bounded, false, "ipc/raw_helper_deadline",
                   bounded ? "test helper cancelled stalled response at deadline"
                           : "test helper did not cancel stalled pipe I/O");
            CloseHandle(release);
            CloseHandle(pipe);
        }
    }
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
    Report(c,
           b.interests.size() == 1 && b.interests[0].name == "leaf" &&
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

    RunLiveTransportValidation(c, ctx.pid);
    {
        PipeClient first(ctx.pid);
        PipeClient second(ctx.pid);
        const bool connected = first.Connect(3000) && second.Connect(3000);
        std::atomic<int> successful{0};
        auto ping = [&](PipeClient* client) {
            hdl::rpc::ControlClient control(client);
            const auto result = control.Ping(hdl::rpc::v1::Empty{});
            if (result.status.ok() && result.has_response && result.response.pid() == ctx.pid) {
                successful.fetch_add(1);
            }
        };
        if (connected) {
            std::thread first_call(ping, &first);
            std::thread second_call(ping, &second);
            first_call.join();
            second_call.join();
        }
        Report(c, connected && successful.load() == 2, false, "ipc/independent_connections",
               "concurrent independent pipe connections complete");
    }

    ExpectOk(c, "client ping", Cli(ctx, {L"ping"}));
    ExpectOk(c, "client log", Cli(ctx, {L"log", L"1"}));
    {
        wchar_t tmp[MAX_PATH];
        const DWORD tmp_len = GetTempPathW(MAX_PATH, tmp);
        const bool path_ok =
            tmp_len != 0 && tmp_len <= MAX_PATH && wcscat_s(tmp, L"hdl_client_logfile.txt") == 0;
        Report(c, path_ok, false, "client log-file path", "");
        if (path_ok) {
            ExpectOk(c, "client log-file set", Cli(ctx, {L"log-file", tmp}));
            ExpectOk(c, "client log-file clear", Cli(ctx, {L"log-file"}));
            DeleteFileW(tmp);
        }
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
        ExpectOk(c, "client call LocateFn", Cli(ctx, {L"call", L"--addr", a, L"i64:3", L"i64:4"}));
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
#if defined(HDL_HAS_ZYDIS)
    ExpectOk(c, "client disasm-backend set zydis", Cli(ctx, {L"disasm-backend", L"set", L"1"}));
#elif defined(HDL_HAS_CAPSTONE)
    ExpectOk(c, "client disasm-backend set capstone", Cli(ctx, {L"disasm-backend", L"set", L"2"}));
#endif
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
        Report(c,
               rtti.exit_code == 0 || Contains(rtti.out, L"status=NOT_FOUND") ||
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
        auto r = Cli(ctx, {L"scan", L"--pattern", L"31 4C 44 48", L"--module",
                           L"hdl_test_target.exe", L"--image", L"--max", L"8"});
        ExpectOk(c, "client scan pattern", r);
    }
    {
        wchar_t temp[MAX_PATH]{};
        wchar_t candidates[MAX_PATH]{};
        const DWORD temp_size = GetTempPathW(MAX_PATH, temp);
        const bool have_path = temp_size != 0 && temp_size < MAX_PATH &&
                               swprintf_s(candidates, L"%shdl_client_candidates_%lu.bin", temp,
                                          GetCurrentProcessId()) > 0;
        if (have_path) {
            DeleteFileW(candidates);
            auto r = Cli(ctx, {L"scan", L"--pattern", L"31 4C 44 48", L"--module",
                               L"hdl_test_target.exe", L"--image", L"--max", L"0", L"--candidates",
                               candidates});
            ExpectOk(c, "client scan candidate file", r);
            uint64_t candidate_count = 0;
            Report(c, ValidateCandidateFile(candidates, &candidate_count) && candidate_count != 0,
                   false, "client scan candidate file format", "");
            DeleteFileW(candidates);
        } else {
            Report(c, false, false, "client scan candidate file path", "GetTempPath failed");
        }
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
        ExpectOk(c, "client scan hits",
                 Cli(ctx, {L"scan", L"--hits", L"--session", s, L"--max", L"16"}));
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

        /* Pipe-native Hook.Hook: place a stub that jumps to leaf, then hook fn -> stub. */
        if (leaf) {
            wchar_t tgt_s[32], leaf_s[32];
            swprintf_s(tgt_s, L"0x%llx", static_cast<unsigned long long>(fn));
            swprintf_s(leaf_s, L"0x%llx", static_cast<unsigned long long>(leaf));
            auto stub =
                Cli(ctx, {L"stub", L"--kind", L"mov_rax_jmp", L"--target", leaf_s, L"--alloc"});
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
                 Cli(ctx, {L"discover-constraint", L"--session", sid, L"--size", L"24", L"--pred",
                           L"eq_i32:8:80", L"--pred", L"eq_i32:12:100", L"--module",
                           L"hdl_test_target.exe", L"--image"}));
        ExpectOk(c, "client discover-cands", Cli(ctx, {L"discover-cands", L"--session", sid}));

        if (dleaf) {
            wchar_t a[32];
            swprintf_s(a, L"0x%llx", static_cast<unsigned long long>(dleaf));
            auto r = Cli(ctx, {L"discover-add", L"--session", sid, L"--kind", L"function",
                               L"--addr", a, L"--tag", L"leaf"});
            ExpectOk(c, "client discover-add", r);
            uint64_t cand = 0;
            ParseU64After(r.out, L"cand=", &cand);
            if (cand) {
                wchar_t cid[32];
                swprintf_s(cid, L"%llu", static_cast<unsigned long long>(cand));
                ExpectOk(c, "client discover-synth",
                         Cli(ctx, {L"discover-synth", L"--session", sid, L"--cand", cid,
                                   L"--module", L"hdl_test_target.exe"}));
            }
        }

        if (obj_a) {
            wchar_t a[32];
            swprintf_s(a, L"0x%llx", static_cast<unsigned long long>(obj_a));
            ExpectOk(
                c, "client discover-scan",
                Cli(ctx, {L"discover-scan", L"--session", sid, L"--type", L"i32", L"--value", L"80",
                          L"--module", L"hdl_test_target.exe", L"--image", L"--tag", L"health"}));
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
            ExpectOk(
                c, "client discover-watch",
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
            ExpectOk(c, "client call DiscoverAction",
                     Cli(ctx, {L"call", L"HdlTestDiscoverAction"}));
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
                     Cli(ctx, {L"discover-cluster", L"--session", sid, L"--seed", a, L"--size",
                               L"24", L"--module", L"hdl_test_target.exe"}));
        }

        ExpectOk(c, "client discover-close", Cli(ctx, {L"discover-close", L"--session", sid}));
    }

    /* One-shot controller parity gate */
    {
        wchar_t store_path[MAX_PATH];
        GetTempPathW(MAX_PATH, store_path);
        wcscat_s(store_path, L"hdl_client_ctrl_store.json");
        DeleteFileW(store_path);
        DeleteFileW((std::wstring(store_path) + L".session").c_str());

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

        uint64_t session_id = 0;
        {
            ProcResult r;
            RunProcess(
                ctx.client,
                {L"--store", store_path, L"--json", std::to_wstring(ctx.pid), L"session", L"new"},
                nullptr, 30000, &r);
            ExpectExit0(c, "client session new exit", r);
            Report(c, IsSingleJsonEnvelope(r.out), false, "client session new single JSON", "");
            const std::string j = ToNarrow(r.out);
            Report(c, hdl::json::ExtractU64(j, "session", &session_id) && session_id != 0, false,
                   "client session new has session id", "");
        }
        {
            ProcResult r;
            RunProcess(
                ctx.client,
                {L"--store", store_path, L"--json", std::to_wstring(ctx.pid), L"session", L"show"},
                nullptr, 30000, &r);
            ExpectExit0(c, "client session show cross-process", r);
            Report(c, IsSingleJsonEnvelope(r.out), false, "client session show single JSON", "");
            uint64_t shown = 0;
            Report(c,
                   hdl::json::ExtractU64(ToNarrow(r.out), "session", &shown) && shown == session_id,
                   false, "client session show matches", "");
        }
        {
            wchar_t sidbuf[32];
            swprintf_s(sidbuf, L"0x%llx", static_cast<unsigned long long>(session_id));
            SetEnvironmentVariableW(L"HDL_SESSION", sidbuf);
            ProcResult r;
            RunProcess(ctx.client, {L"--json", std::to_wstring(ctx.pid), L"session", L"show"},
                       nullptr, 30000, &r);
            SetEnvironmentVariableW(L"HDL_SESSION", nullptr);
            ExpectExit0(c, "client HDL_SESSION session show", r);
            uint64_t shown = 0;
            Report(c,
                   hdl::json::ExtractU64(ToNarrow(r.out), "session", &shown) && shown == session_id,
                   false, "client HDL_SESSION resolves", "");
        }
        {
            auto r = Cli(ctx, {L"dcreate"});
            ExpectOk(c, "client dcreate alias", r);
        }
        {
            wchar_t a[32];
            swprintf_s(a, L"0x%llx", static_cast<unsigned long long>(fn ? fn : 1));
            ProcResult r;
            RunProcess(ctx.client,
                       {L"--store", store_path, std::to_wstring(ctx.pid), L"dwatch", L"--addr", a,
                        L"--args", L"0"},
                       nullptr, 30000, &r);
            Report(c, !Contains(r.out, L"Unknown discover command"), false,
                   "client dwatch alias canonical", "");
        }
        {
            auto r = Cli(ctx, {L"dcands"});
            Report(c, !Contains(r.out, L"Unknown discover command"), false,
                   "client dcands alias canonical", "");
        }
        {
            auto r = Cli(ctx, {L"rpat", L"DE AD BE EF"});
            Report(c,
                   !Contains(r.out, L"unknown command") &&
                       r.out.find(L"status=") != std::wstring::npos,
                   false, "client rpat alias resolves", "");
        }
        {
            ProcResult r;
            RunProcess(ctx.client,
                       {L"--store", store_path, L"--json", std::to_wstring(ctx.pid), L"recipe",
                        L"suggest"},
                       nullptr, 60000, &r);
            ExpectExit0(c, "client recipe suggest exit", r);
            Report(c, JsonEnvelopeOk(r.out), false, "client recipe suggest JSON ok", "");
        }
        if (obj_a) {
            ProcResult r;
            RunProcess(ctx.client,
                       {L"--store", store_path, L"--json", std::to_wstring(ctx.pid), L"recipe",
                        L"constrain", L"24", L"eq_i32:8:50", L"eq_i32:12:100", L"--module",
                        L"hdl_test_target.exe"},
                       nullptr, 60000, &r);
            ExpectExit0(c, "client recipe constrain exit", r);
            Report(c, JsonEnvelopeOk(r.out), false, "client recipe constrain JSON ok", "");
            wchar_t base_hex[32];
            swprintf_s(base_hex, L"0x%llx", static_cast<unsigned long long>(obj_a));
            RunProcess(ctx.client,
                       {L"--store", store_path, L"--json", std::to_wstring(ctx.pid), L"recipe",
                        L"expand", base_hex, L"24"},
                       nullptr, 60000, &r);
            ExpectExit0(c, "client recipe expand exit", r);
            Report(c, JsonEnvelopeOk(r.out), false, "client recipe expand JSON ok", "");
        }
        if (fn) {
            wchar_t near_hex[32];
            swprintf_s(near_hex, L"0x%llx", static_cast<unsigned long long>(fn));
            ProcResult r;
            RunProcess(ctx.client,
                       {L"--store", store_path, L"--json", std::to_wstring(ctx.pid), L"recipe",
                        L"place", L"placed_fn", near_hex},
                       nullptr, 60000, &r);
            ExpectExit0(c, "client recipe place exit", r);
            Report(c, JsonEnvelopeOk(r.out), false, "client recipe place JSON ok", "");
        }
        if (stitch_pad) {
            wchar_t tgt[32];
            swprintf_s(tgt, L"0x%llx", static_cast<unsigned long long>(stitch_pad));
            ProcResult r;
            RunProcess(ctx.client,
                       {L"--store", store_path, L"--json", std::to_wstring(ctx.pid), L"recipe",
                        L"stitch", L"stitched", L"--target", tgt, L"--kind", L"mov_rax_jmp"},
                       nullptr, 60000, &r);
            ExpectExit0(c, "client recipe stitch exit", r);
            Report(c, JsonEnvelopeOk(r.out), false, "client recipe stitch JSON ok", "");
        }
        if (action) {
            wchar_t watch_hex[32];
            swprintf_s(watch_hex, L"0x%llx", static_cast<unsigned long long>(action));
            /*
             * No fixed pre-delay: run recipe action on one thread and repeatedly call the
             * watched exports for its whole lifetime so triggers overlap the open window.
             */
            std::atomic<bool> action_done{false};
            std::atomic<int> ok_calls{0};
            ProcResult r;
            std::thread action_thr([&] {
                RunProcess(ctx.client,
                           {L"--store", store_path, L"--json", std::to_wstring(ctx.pid), L"recipe",
                            L"action", L"parity_act", watch_hex, L"--wait-ms", L"3000"},
                           nullptr, 90000, &r);
                action_done.store(true);
            });
            std::thread trigger([&] {
                while (!action_done.load()) {
                    ProcResult cr;
                    if (RunProcess(ctx.client,
                                   {std::to_wstring(ctx.pid), L"call", L"HdlTestDiscoverAction"},
                                   nullptr, 30000, &cr) &&
                        cr.exit_code == 0) {
                        ok_calls.fetch_add(1);
                    }
                    ProcResult dr;
                    RunProcess(
                        ctx.client,
                        {std::to_wstring(ctx.pid), L"call", L"HdlTestDiscoverDamage", L"i64:1"},
                        nullptr, 30000, &dr);
                    Sleep(50);
                }
            });
            action_thr.join();
            trigger.join();
            Report(c, ok_calls.load() >= 1, false, "client recipe action trigger succeeded", "");
            ExpectExit0(c, "client recipe action --wait-ms exit", r);
            Report(c, JsonEnvelopeOk(r.out), false, "client recipe action JSON ok", "");
            Report(c, !Contains(r.out, L"Press Enter"), false,
                   "client recipe action no Enter prompt", "");
            std::string interest;
            Report(c,
                   hdl::json::ExtractString(ToNarrow(r.out), "interest", &interest) &&
                       !interest.empty(),
                   false, "client recipe action interest field", "");
            if (!interest.empty()) {
                hdlcli::InterestStore chk;
                Report(c, chk.Load(store_path) && chk.Find(interest.c_str()) != nullptr, false,
                       "client recipe action interest persisted", "");
            }
        }
        if (fn) {
            wchar_t cand_hex[32];
            uint64_t cand_id = 0;
            {
                wchar_t a[32];
                swprintf_s(a, L"0x%llx", static_cast<unsigned long long>(fn));
                ProcResult add;
                RunProcess(ctx.client,
                           {L"--store", store_path, L"--json", std::to_wstring(ctx.pid),
                            L"discover-add", L"--kind", L"function", L"--addr", a, L"--tag",
                            L"parity_fn"},
                           nullptr, 30000, &add);
                ExpectExit0(c, "client discover-add for stabilize", add);
                Report(c, JsonEnvelopeOk(add.out), false, "client discover-add JSON ok", "");
                uint64_t sid_out = 0;
                Report(c,
                       hdl::json::ExtractU64(ToNarrow(add.out), "session", &sid_out) &&
                           sid_out != 0,
                       false, "client discover-add returns session", "");
                Report(c,
                       hdl::json::ExtractU64(ToNarrow(add.out), "cand", &cand_id) && cand_id != 0,
                       false, "client discover-add returns cand", "");
            }
            if (cand_id) {
                swprintf_s(cand_hex, L"0x%llx", static_cast<unsigned long long>(cand_id));
                ProcResult r;
                RunProcess(ctx.client,
                           {L"--store", store_path, L"--json", std::to_wstring(ctx.pid),
                            L"stabilize", cand_hex},
                           nullptr, 60000, &r);
                ExpectExit0(c, "client stabilize exit", r);
                Report(c, JsonEnvelopeOk(r.out), false, "client stabilize JSON ok", "");
                Report(c, Contains(r.out, L"interest") || Contains(r.out, L"pattern"), false,
                       "client stabilize interest/pattern", "");
            } else {
                Report(c, false, false, "client stabilize skipped (no cand)", "");
            }
        }
        if (leaf) {
            wchar_t leaf_hex[32];
            swprintf_s(leaf_hex, L"0x%llx", static_cast<unsigned long long>(leaf));
            ProcResult r;
            RunProcess(ctx.client,
                       {L"--store", store_path, L"--json", std::to_wstring(ctx.pid),
                        L"discover-pathscan", leaf_hex, L"--depth", L"2", L"--store-add",
                        L"path_interest"},
                       nullptr, 90000, &r);
            ExpectExit0(c, "client pathscan --store-add exit", r);
            Report(c, JsonEnvelopeOk(r.out), false, "client pathscan store-add JSON ok", "");
            hdlcli::InterestStore chk;
            Report(c, chk.Load(store_path) && chk.Find("path_interest") != nullptr, false,
                   "client store-add persisted path interest", "");
        }
        {
            ProcResult r;
            RunProcess(ctx.client,
                       {L"--store", store_path, L"--json", std::to_wstring(ctx.pid), L"store",
                        L"add", L"export_fn", L"--kind", L"function", L"export",
                        L"HdlTestLocateFn"},
                       nullptr, 30000, &r);
            ExpectExit0(c, "client store add export", r);
            Report(c, JsonEnvelopeOk(r.out), false, "client store add JSON ok", "");
        }
        {
            ProcResult r;
            RunProcess(
                ctx.client,
                {L"--store", store_path, L"--json", std::to_wstring(ctx.pid), L"store", L"list"},
                nullptr, 30000, &r);
            ExpectExit0(c, "client store list json", r);
            Report(c, JsonEnvelopeOk(r.out) && Contains(r.out, L"interests"), false,
                   "client store list single envelope", "");
        }
        {
            ProcResult r;
            RunProcess(ctx.client,
                       {L"--store", store_path, L"--json", std::to_wstring(ctx.pid), L"store",
                        L"revalidate"},
                       nullptr, 60000, &r);
            ExpectExit0(c, "client store revalidate", r);
            Report(c, JsonEnvelopeOk(r.out), false, "client store revalidate JSON ok", "");
        }

        hdlcli::InterestStore loaded;
        Report(c, loaded.Load(store_path), false, "client store file load", "");
        if (fn) {
            Report(c, loaded.Find("placed_fn") != nullptr, false, "client store has placed_fn", "");
        }
        Report(c, loaded.Find("export_fn") != nullptr, false, "client store has export_fn", "");

        {
            ProcResult r;
            RunProcess(ctx.client, {std::to_wstring(ctx.pid)}, nullptr, 10000, &r);
            Report(c, r.exit_code != 0, false, "client pid-only prints usage", "");
        }
        {
            ProcResult r;
            RunProcess(ctx.client, {std::to_wstring(ctx.pid), L"repl"}, nullptr, 10000, &r);
            Report(c, r.exit_code != 0 && Contains(r.out, L"REPL/TUI removed"), false,
                   "client rejects repl", "");
        }
        {
            ProcResult r;
            RunProcess(ctx.client, {L"--tui", std::to_wstring(ctx.pid)}, nullptr, 10000, &r);
            Report(c, r.exit_code != 0 && Contains(r.out, L"REPL/TUI removed"), false,
                   "client rejects --tui", "");
        }
        {
            ProcResult r;
            RunProcess(ctx.client, {std::to_wstring(ctx.pid), L"tui"}, nullptr, 10000, &r);
            Report(c, r.exit_code != 0 && Contains(r.out, L"REPL/TUI removed"), false,
                   "client rejects bare tui", "");
        }
        {
            auto r = Cli(ctx, {L"henable", L"0", L"0"});
            Report(c, r.exit_code != 0 || Contains(r.out, L"status="), false,
                   "client henable alias resolves", "");
        }

        {
            ProcResult r;
            RunProcess(
                ctx.client,
                {L"--store", store_path, L"--json", std::to_wstring(ctx.pid), L"session", L"close"},
                nullptr, 30000, &r);
            ExpectExit0(c, "client session close exit", r);
            Report(c, IsSingleJsonEnvelope(r.out), false, "client session close single JSON", "");
        }
        {
            ProcResult r;
            RunProcess(ctx.client,
                       {L"--store", store_path, std::to_wstring(ctx.pid), L"session", L"show"},
                       nullptr, 30000, &r);
            Report(c, r.exit_code != 0, false, "client session show fails after close", "");
        }
        DeleteFileW(store_path);
        DeleteFileW((std::wstring(store_path) + L".session").c_str());
        if (stitch_pad) {
            wchar_t a[32];
            swprintf_s(a, L"0x%llx", static_cast<unsigned long long>(stitch_pad));
            Cli(ctx, {L"free", a});
        }
    }

    /* --json structured output + actionable error hints (golden fixtures + parse checks) */
    {
        ProcResult r;
        RunProcess(ctx.client, {L"--json", std::to_wstring(ctx.pid), L"ping"}, nullptr, 30000, &r);
        const std::string pj = ToNarrow(r.out);
        {
            const bool ping_ok =
                r.exit_code == 0 && MatchEnvelopeGolden(pj, "golden/ping_envelope.json");
            Report(c, ping_ok, false, "client --json ping golden envelope", "");
            uint64_t remote_pid = 0;
            const bool has_pid = hdl::json::ExtractU64(pj, "remote_pid", &remote_pid);
            Report(c, has_pid && remote_pid == ctx.pid, false,
                   "client --json ping remote_pid matches", "");
        }

        ProcResult mods;
        RunProcess(ctx.client, {L"--json", std::to_wstring(ctx.pid), L"modules"}, nullptr, 30000,
                   &mods);
        {
            const std::string mj = ToNarrow(mods.out);
            Report(c,
                   mods.exit_code == 0 && MatchEnvelopeGolden(mj, "golden/modules_envelope.json"),
                   false, "client --json modules golden envelope", "");
        }

        ProcResult failj;
        RunProcess(ctx.client,
                   {L"--json", std::to_wstring(ctx.pid), L"call", L"--addr", L"0", L"--main"},
                   nullptr, 30000, &failj);
        {
            const std::string fj = ToNarrow(failj.out);
            Report(c, failj.exit_code != 0 && MatchEnvelopeGolden(fj, "golden/error_envelope.json"),
                   false, "client --json call --main error golden envelope", "");
        }

        ProcResult failt;
        RunProcess(ctx.client, {std::to_wstring(ctx.pid), L"call", L"--addr", L"0", L"--main"},
                   nullptr, 30000, &failt);
        Report(c,
               failt.exit_code != 0 && Contains(failt.out, L"status=") &&
                   Contains(failt.out, L"hint:"),
               false, "client text call --main prints hint", "");
    }

    /* Usage documents controller surfaces */
    {
        ProcResult r;
        RunProcess(ctx.client, {}, nullptr, 10000, &r);
        Report(c,
               r.out.find(L"discover-scan") != std::wstring::npos &&
                   r.out.find(L"hook-enable") != std::wstring::npos &&
                   r.out.find(L"--json") != std::wstring::npos &&
                   r.out.find(L"write <hex-address>") != std::wstring::npos &&
                   r.out.find(L"discover-pathvalidate") != std::wstring::npos &&
                   r.out.find(L"stub") != std::wstring::npos &&
                   r.out.find(L"recipe place") != std::wstring::npos &&
                   r.out.find(L"session new") != std::wstring::npos,
               false, "client usage documents controller", "");
    }
}

} // namespace

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
    Report(c, hdl::rpc::kProtocolMajor == 1, false, "ipc/proto_major_v1", "");

    /* HDL_PIPE must stay under \\.\pipe\; reject file/device path overrides. */
    {
        wchar_t prev[512];
        const DWORD prev_n = GetEnvironmentVariableW(L"HDL_PIPE", prev, 512);
        wchar_t name[128];
        SetEnvironmentVariableW(L"HDL_PIPE", L"C:\\Windows\\System32\\notepad.exe");
        Report(c, HdlFormatPipeName(1, name, 128) != 0, false, "ipc/reject_non_pipe_hdl_pipe", "");
        SetEnvironmentVariableW(L"HDL_PIPE", L"\\\\.\\pipe\\%s");
        Report(c, HdlFormatPipeName(1, name, 128) != 0, false, "ipc/reject_format_string_hdl_pipe",
               "");
        SetEnvironmentVariableW(L"HDL_PIPE", L"\\\\.\\pipe\\hdl_test_%n");
        Report(c, HdlFormatPipeName(1, name, 128) != 0, false, "ipc/reject_percent_n_hdl_pipe", "");
        SetEnvironmentVariableW(L"HDL_PIPE", L"\\\\.\\pipe\\hdl_test_%lu");
        Report(c,
               HdlFormatPipeName(0xABCDu, name, 128) == 0 &&
                   wcscmp(name, L"\\\\.\\pipe\\hdl_test_43981") == 0,
               false, "ipc/accept_safe_pipe_format", "");
        SetEnvironmentVariableW(L"HDL_PIPE", L"\\\\.\\pipe\\ExactPipeName");
        Report(c,
               HdlFormatPipeName(1, name, 128) == 0 &&
                   wcscmp(name, L"\\\\.\\pipe\\ExactPipeName") == 0,
               false, "ipc/accept_exact_pipe_rebuild", "");
        if (prev_n > 0 && prev_n < 512) {
            SetEnvironmentVariableW(L"HDL_PIPE", prev);
        } else {
            SetEnvironmentVariableW(L"HDL_PIPE", nullptr);
        }
    }

    RunNegotiateMismatch(c);
    RunClientDeadlineValidation(c);
    RunClientResponseValidation(c, TestPeerFault::WrongRequestId, 0x71C0FFE1u,
                                "ipc/reject_wrong_request_id");
    RunClientResponseValidation(c, TestPeerFault::InvalidUnaryPayload, 0x71C0FFE2u,
                                "ipc/reject_invalid_unary_payload");
    RunClientResponseValidation(c, TestPeerFault::WrongStreamSequence, 0x71C0FFE3u,
                                "ipc/reject_wrong_stream_sequence");
    RunClientResponseValidation(c, TestPeerFault::AbortStream, 0x71C0FFE4u,
                                "ipc/callback_abort_closes_stream");
    RunClientResponseValidation(c, TestPeerFault::TerminalStreamError, 0x71C0FFE7u,
                                "ipc/terminal_stream_error");
    RunClientResponseValidation(c, TestPeerFault::PartialFailure, 0x71C0FFE6u,
                                "ipc/unary_partial_failure");
    RunOneInFlightValidation(c);
    RunStoreUnit(c);
    RunClientLiveTests(c, client_full, target_full, dll_full);

    std::printf("\n== Summary ==\n");
    std::printf("passed=%d failed=%d soft=%d skipped=%d\n", c.passed, c.failed, c.soft_failed,
                c.skipped);
    return c.failed == 0 ? 0 : 1;
}
