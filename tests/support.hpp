#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <TlHelp32.h>
#include <sddl.h>

#include "hdl/rpc/v1/services.rpc.hpp"
#include "hdllib/hdllib.h"
#include "hdllib/pipe_name.h"
#include "rpc/pipe_io.hpp"
#include "rpc/runtime.hpp"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#pragma comment(lib, "advapi32.lib")

namespace hdltest {

enum class Expect {
    MustSucceed,
    MustFail,
    SoftSucceed,
};

enum class IlLevel { Medium, Low };

struct TargetProfile {
    const char* name = nullptr;
    bool window = false;
    bool alertable = false;
    IlLevel integrity = IlLevel::Medium;
};

struct TargetProc {
    HANDLE process = nullptr;
    DWORD pid = 0;
    HANDLE ready_event = nullptr;
    HANDLE exit_event = nullptr;

    void Close() {
        if (exit_event) {
            SetEvent(exit_event);
        }
        if (process) {
            if (WaitForSingleObject(process, 3000) == WAIT_TIMEOUT) {
                TerminateProcess(process, 1);
                WaitForSingleObject(process, 2000);
            }
            CloseHandle(process);
            process = nullptr;
        }
        if (ready_event) {
            CloseHandle(ready_event);
            ready_event = nullptr;
        }
        if (exit_event) {
            CloseHandle(exit_event);
            exit_event = nullptr;
        }
        pid = 0;
    }

    ~TargetProc() { Close(); }

    TargetProc() = default;
    TargetProc(const TargetProc&) = delete;
    TargetProc& operator=(const TargetProc&) = delete;
    TargetProc(TargetProc&& o) noexcept { *this = std::move(o); }
    TargetProc& operator=(TargetProc&& o) noexcept {
        if (this != &o) {
            Close();
            process = o.process;
            pid = o.pid;
            ready_event = o.ready_event;
            exit_event = o.exit_event;
            o.process = nullptr;
            o.ready_event = nullptr;
            o.exit_event = nullptr;
            o.pid = 0;
        }
        return *this;
    }
};

struct Counters {
    int passed = 0;
    int failed = 0;
    int soft_failed = 0;
    int skipped = 0;
};

inline const wchar_t* StatusName(HdlStatus st) {
    switch (st) {
    case HDL_OK:
        return L"OK";
    case HDL_E_INVALID_ARG:
        return L"INVALID_ARG";
    case HDL_E_ACCESS:
        return L"ACCESS";
    case HDL_E_NOT_FOUND:
        return L"NOT_FOUND";
    case HDL_E_NO_MEM:
        return L"NO_MEM";
    case HDL_E_BUSY:
        return L"BUSY";
    case HDL_E_FAILED:
        return L"FAILED";
    case HDL_E_BUFFER_SMALL:
        return L"BUFFER_SMALL";
    case HDL_E_CANCELLED:
        return L"CANCELLED";
    case HDL_E_NOT_INIT:
        return L"NOT_INIT";
    default:
        return L"?";
    }
}

inline void Report(Counters& c, bool ok, bool soft, const char* name, const char* detail) {
    if (ok) {
        ++c.passed;
        std::printf("[PASS] %s%s%s\n", name, detail && detail[0] ? " - " : "",
                    detail ? detail : "");
    } else if (soft) {
        ++c.soft_failed;
        std::printf("[SOFT] %s%s%s\n", name, detail && detail[0] ? " - " : "",
                    detail ? detail : "");
    } else {
        ++c.failed;
        std::printf("[FAIL] %s%s%s\n", name, detail && detail[0] ? " - " : "",
                    detail ? detail : "");
    }
}

inline std::wstring ExeDir() {
    wchar_t path[MAX_PATH];
    const DWORD n = GetModuleFileNameW(nullptr, path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) {
        return L".";
    }
    wchar_t* slash = wcsrchr(path, L'\\');
    if (slash) {
        *slash = L'\0';
    }
    return path;
}

inline std::wstring JoinPath(const std::wstring& dir, const wchar_t* file) {
    if (dir.empty()) {
        return file;
    }
    if (dir.back() == L'\\' || dir.back() == L'/') {
        return dir + file;
    }
    return dir + L"\\" + file;
}

inline bool FileExists(const wchar_t* path) {
    return GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES;
}

inline bool PathsEqual(const wchar_t* a, const wchar_t* b) {
    return a && b && _wcsicmp(a, b) == 0;
}

inline uint64_t FindModuleBaseByPath(DWORD pid, const wchar_t* dll_path) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) {
        return 0;
    }
    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    uint64_t base = 0;
    if (Module32FirstW(snap, &me)) {
        do {
            if (PathsEqual(me.szExePath, dll_path)) {
                base = reinterpret_cast<uint64_t>(me.modBaseAddr);
                break;
            }
            const wchar_t* file = wcsrchr(dll_path, L'\\');
            file = file ? file + 1 : dll_path;
            if (_wcsicmp(me.szModule, file) == 0) {
                base = reinterpret_cast<uint64_t>(me.modBaseAddr);
                break;
            }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return base;
}

inline bool CreateLowIlToken(HANDLE* out_token) {
    *out_token = nullptr;
    HANDLE proc_token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT |
                              TOKEN_ASSIGN_PRIMARY,
                          &proc_token)) {
        return false;
    }

    HANDLE token = nullptr;
    if (!DuplicateTokenEx(proc_token, MAXIMUM_ALLOWED, nullptr, SecurityImpersonation, TokenPrimary,
                          &token)) {
        CloseHandle(proc_token);
        return false;
    }
    CloseHandle(proc_token);

    PSID low_sid = nullptr;
    if (!ConvertStringSidToSidW(L"S-1-16-4096", &low_sid)) {
        CloseHandle(token);
        return false;
    }

    TOKEN_MANDATORY_LABEL label{};
    label.Label.Attributes = SE_GROUP_INTEGRITY;
    label.Label.Sid = low_sid;
    const BOOL ok = SetTokenInformation(token, TokenIntegrityLevel, &label,
                                        sizeof(label) + GetLengthSid(low_sid));
    LocalFree(low_sid);
    if (!ok) {
        CloseHandle(token);
        return false;
    }
    *out_token = token;
    return true;
}

inline bool SpawnTarget(const wchar_t* target_exe, const TargetProfile& profile, TargetProc& out) {
    out.Close();

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    out.ready_event = CreateEventW(&sa, TRUE, FALSE, nullptr);
    out.exit_event = CreateEventW(&sa, TRUE, FALSE, nullptr);
    if (!out.ready_event || !out.exit_event) {
        out.Close();
        return false;
    }

    wchar_t cmd[1024];
    swprintf_s(cmd, L"\"%ls\" --ready-handle %llu --exit-handle %llu%s%s%s", target_exe,
               static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(out.ready_event)),
               static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(out.exit_event)),
               profile.window ? L" --window" : L"", profile.alertable ? L" --alertable" : L"",
               profile.integrity == IlLevel::Low ? L" --integrity low" : L"");

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    BOOL created = FALSE;
    if (profile.integrity == IlLevel::Low) {
        HANDLE low_token = nullptr;
        if (!CreateLowIlToken(&low_token)) {
            out.Close();
            return false;
        }
        created = CreateProcessAsUserW(low_token, nullptr, cmd, nullptr, nullptr, TRUE, 0, nullptr,
                                       nullptr, &si, &pi);
        CloseHandle(low_token);
    } else {
        created =
            CreateProcessW(nullptr, cmd, nullptr, nullptr, TRUE, 0, nullptr, nullptr, &si, &pi);
    }

    if (!created) {
        out.Close();
        return false;
    }

    CloseHandle(pi.hThread);
    out.process = pi.hProcess;
    out.pid = pi.dwProcessId;

    if (WaitForSingleObject(out.ready_event, 15000) != WAIT_OBJECT_0) {
        out.Close();
        return false;
    }
    Sleep(150);
    return true;
}

inline bool PipeCall(uint32_t pid, std::string_view method,
                     const google::protobuf::MessageLite& request,
                     const std::function<bool(std::string_view)>& on_payload, int32_t* out_status,
                     DWORD timeout_ms = 15000);

template <hdl::rpc::Method M>
bool PipeUnary(uint32_t pid, const typename hdl::rpc::MethodTraits<M>::Request& request,
               typename hdl::rpc::MethodTraits<M>::Response* response,
               int32_t* out_status = nullptr, DWORD timeout_ms = 15000) {
    bool parsed = false;
    return PipeCall(
               pid, hdl::rpc::MethodName(M), request,
               [response, &parsed](std::string_view bytes) {
                   parsed = response &&
                            response->ParseFromArray(bytes.data(), static_cast<int>(bytes.size()));
                   return parsed;
               },
               out_status, timeout_ms) &&
           parsed;
}

template <hdl::rpc::Method M, typename Callback>
bool PipeStream(uint32_t pid, const typename hdl::rpc::MethodTraits<M>::Request& request,
                Callback&& callback, int32_t* out_status = nullptr, DWORD timeout_ms = 15000) {
    return PipeCall(
        pid, hdl::rpc::MethodName(M), request,
        [&callback](std::string_view bytes) {
            typename hdl::rpc::MethodTraits<M>::Response response;
            return response.ParseFromArray(bytes.data(), static_cast<int>(bytes.size())) &&
                   callback(response);
        },
        out_status, timeout_ms);
}

inline bool PingPipe(uint32_t pid, DWORD timeout_ms = 8000) {
    hdl::rpc::v1::PingResponse response;
    int32_t status = HDL_E_FAILED;
    return PipeUnary<hdl::rpc::Method::Control_Ping>(pid, hdl::rpc::v1::Empty{}, &response, &status,
                                                     timeout_ms) &&
           status == HDL_OK;
}

inline bool PipeShutdown(uint32_t pid, uint32_t flags, int32_t* out_status = nullptr) {
    hdl::rpc::v1::ShutdownRequest request;
    request.set_flags(flags);
    hdl::rpc::v1::Empty response;
    int32_t status = HDL_E_FAILED;
    const bool ok = PipeUnary<hdl::rpc::Method::Control_Shutdown>(pid, request, &response, &status);
    if (out_status)
        *out_status = status;
    return ok;
}

inline bool VerifyInjected(uint32_t pid, const wchar_t* dll_path, int method, uint64_t base) {
    if (base == 0) {
        return false;
    }
    // DllMain bootstraps IPC on a background thread — retry briefly.
    const DWORD start = GetTickCount();
    while (GetTickCount() - start < 10000) {
        const bool listed =
            method == HDL_INJECT_MANUAL_MAP || FindModuleBaseByPath(pid, dll_path) != 0;
        if (listed && PingPipe(pid, 1000)) {
            return true;
        }
        Sleep(100);
    }
    return false;
}

inline const char* StatusNameA(HdlStatus st) {
    switch (st) {
    case HDL_OK:
        return "OK";
    case HDL_E_INVALID_ARG:
        return "INVALID_ARG";
    case HDL_E_ACCESS:
        return "ACCESS";
    case HDL_E_NOT_FOUND:
        return "NOT_FOUND";
    case HDL_E_NO_MEM:
        return "NO_MEM";
    case HDL_E_BUSY:
        return "BUSY";
    case HDL_E_FAILED:
        return "FAILED";
    case HDL_E_BUFFER_SMALL:
        return "BUFFER_SMALL";
    case HDL_E_CANCELLED:
        return "CANCELLED";
    case HDL_E_NOT_INIT:
        return "NOT_INIT";
    default:
        return "?";
    }
}

inline Expect ExpectFor(int method, const TargetProfile& profile) {
    const bool gui = profile.window;
    const bool alert = profile.alertable;

    switch (method) {
    case HDL_INJECT_QUEUE_USER_APC:
        return alert ? Expect::MustSucceed : Expect::MustFail;
    case HDL_INJECT_ATOM_BOMBING:
        // Expected fail without alertable; success path still flaky vs classic APC.
        return alert ? Expect::SoftSucceed : Expect::MustFail;
    case HDL_INJECT_SET_WINDOWS_HOOK_EX:
        return gui ? Expect::MustSucceed : Expect::MustFail;
    case HDL_INJECT_WINDOW_SUBCLASS:
    case HDL_INJECT_KERNEL_CALLBACK_TABLE:
        return gui ? Expect::MustSucceed : Expect::MustFail;
    case HDL_INJECT_SET_WIN_EVENT_HOOK:
        return gui ? Expect::MustSucceed : Expect::MustFail;
    case HDL_INJECT_THREAD_HIJACK:
    case HDL_INJECT_RTL_REMOTE_CALL:
        // More reliable when a GUI/message thread exists; console remains soft.
        return gui ? Expect::MustSucceed : Expect::SoftSucceed;
    case HDL_INJECT_SPECIAL_USER_APC:
        return Expect::MustSucceed;
    case HDL_INJECT_ETW_CALLBACK:
        return Expect::SoftSucceed;
    case HDL_INJECT_MANUAL_MAP:
    case HDL_INJECT_INSTRUMENTATION_CALLBACK:
        return Expect::MustSucceed;
    case HDL_INJECT_EARLY_BIRD_APC:
        return Expect::MustSucceed;
    default:
        return Expect::MustSucceed;
    }
}

inline const char* MethodName(int method) {
    switch (method) {
    case HDL_INJECT_CREATE_REMOTE_THREAD:
        return "create_remote_thread";
    case HDL_INJECT_NT_CREATE_THREAD_EX:
        return "nt_create_thread_ex";
    case HDL_INJECT_RTL_CREATE_USER_THREAD:
        return "rtl_create_user_thread";
    case HDL_INJECT_QUEUE_USER_APC:
        return "queue_user_apc";
    case HDL_INJECT_SET_WINDOWS_HOOK_EX:
        return "set_windows_hook_ex";
    case HDL_INJECT_THREAD_HIJACK:
        return "thread_hijack";
    case HDL_INJECT_MANUAL_MAP:
        return "manual_map";
    case HDL_INJECT_EARLY_BIRD_APC:
        return "early_bird_apc";
    case HDL_INJECT_ATOM_BOMBING:
        return "atom_bombing";
    case HDL_INJECT_MODULE_STOMP:
        return "module_stomp";
    case HDL_INJECT_SECTION_MAP:
        return "section_map";
    case HDL_INJECT_WINDOW_SUBCLASS:
        return "window_subclass";
    case HDL_INJECT_INSTRUMENTATION_CALLBACK:
        return "instrumentation_callback";
    case HDL_INJECT_KERNEL_CALLBACK_TABLE:
        return "kernel_callback_table";
    case HDL_INJECT_VEH:
        return "veh";
    case HDL_INJECT_SET_WIN_EVENT_HOOK:
        return "set_win_event_hook";
    case HDL_INJECT_RTL_REMOTE_CALL:
        return "rtl_remote_call";
    case HDL_INJECT_SPECIAL_USER_APC:
        return "special_user_apc";
    case HDL_INJECT_THREAD_POOL:
        return "thread_pool";
    case HDL_INJECT_ETW_CALLBACK:
        return "etw_callback";
    default:
        return "?";
    }
}

inline bool PipeCall(uint32_t pid, std::string_view method,
                     const google::protobuf::MessageLite& input,
                     const std::function<bool(std::string_view)>& on_payload, int32_t* out_status,
                     DWORD timeout_ms) {
    const hdl::rpc::PipeDeadline deadline(timeout_ms);
    HANDLE pipe = INVALID_HANDLE_VALUE;
    HANDLE completion_port = nullptr;
    if (hdl::rpc::ConnectLocalPipe(pid, deadline, &pipe, &completion_port) !=
        hdl::rpc::PipeIoResult::Ok) {
        return false;
    }
    struct PipeHandles {
        HANDLE pipe;
        HANDLE completion_port;
        ~PipeHandles() {
            CloseHandle(pipe);
            CloseHandle(completion_port);
        }
    } handles{pipe, completion_port};

    auto write_exact = [pipe, completion_port, &deadline](const void* data, DWORD size) {
        return hdl::rpc::WritePipeExact(pipe, completion_port, data, size, deadline) ==
               hdl::rpc::PipeIoResult::Ok;
    };
    auto read_frame = [pipe, completion_port, &deadline](std::vector<uint8_t>* frame) {
        uint32_t size = 0;
        if (hdl::rpc::ReadPipeExact(pipe, completion_port, &size, sizeof(size), deadline) !=
                hdl::rpc::PipeIoResult::Ok ||
            size > hdl::rpc::kMaxFrameBytes) {
            return false;
        }
        frame->resize(size);
        return !size || hdl::rpc::ReadPipeExact(pipe, completion_port, frame->data(), size,
                                                deadline) == hdl::rpc::PipeIoResult::Ok;
    };

    if (!write_exact(hdl::rpc::kConnectionPreface,
                     static_cast<DWORD>(hdl::rpc::kConnectionPrefaceSize))) {
        return false;
    }
    hdl::rpc::v1::Envelope hello;
    hello.mutable_client_hello()->set_protocol_major(hdl::rpc::kProtocolMajor);
    hello.mutable_client_hello()->set_protocol_minor(hdl::rpc::kProtocolMinor);
    hello.mutable_client_hello()->set_client_name("hdl_tests");
    std::vector<uint8_t> frame;
    if (!hdl::rpc::SerializeEnvelope(hello, &frame)) {
        return false;
    }
    uint32_t frame_size = static_cast<uint32_t>(frame.size());
    if (!write_exact(&frame_size, sizeof(frame_size)) || !write_exact(frame.data(), frame_size) ||
        !read_frame(&frame) || !hdl::rpc::ParseEnvelope(frame.data(), frame.size(), &hello) ||
        !hello.has_server_hello() ||
        hello.server_hello().protocol_major() != hdl::rpc::kProtocolMajor) {
        return false;
    }

    hdl::rpc::v1::Envelope envelope;
    auto* request = envelope.mutable_request();
    request->set_request_id(1);
    request->set_method(method.data(), method.size());
    request->set_timeout_ms(timeout_ms);
    if (!input.SerializeToString(request->mutable_payload()) ||
        !hdl::rpc::SerializeEnvelope(envelope, &frame)) {
        return false;
    }
    frame_size = static_cast<uint32_t>(frame.size());
    if (!write_exact(&frame_size, sizeof(frame_size)) || !write_exact(frame.data(), frame_size)) {
        return false;
    }
    uint32_t sequence = 0;
    bool terminal = false;
    while (!terminal) {
        if (!read_frame(&frame) ||
            !hdl::rpc::ParseEnvelope(frame.data(), frame.size(), &envelope) ||
            !envelope.has_response() || envelope.response().request_id() != 1 ||
            envelope.response().sequence() != sequence++) {
            return false;
        }
        const auto& response = envelope.response();
        if (response.has_payload() && !on_payload(response.payload())) {
            return false;
        }
        terminal = response.end_stream();
        if (terminal && response.has_status() && out_status)
            *out_status = static_cast<int32_t>(response.status().hdl_status());
    }
    return true;
}

} // namespace hdltest
