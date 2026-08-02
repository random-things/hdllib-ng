#include "cmd.hpp"
#include "cmd_fail.hpp"
#include "json_out.hpp"
#include "usage.hpp"
#include "util.hpp"

#include "hdllib/hdllib.h"
#include "ipc/wire.hpp"
#include "protocol.hpp"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

bool EncodeCallArg(const wchar_t* s, int32_t* kind, uint32_t* size, uint64_t* u64,
                   std::vector<uint8_t>* blob) {
    if (!s || !kind || !size || !u64 || !blob) {
        return false;
    }
    *size = 0;
    *u64 = 0;
    blob->clear();
    if (wcsncmp(s, L"u64:", 4) == 0) {
        *kind = HDL_CALL_ARG_U64;
        *u64 = _wcstoui64(s + 4, nullptr, 0);
        return true;
    }
    if (wcsncmp(s, L"i64:", 4) == 0) {
        *kind = HDL_CALL_ARG_I64;
        *u64 = static_cast<uint64_t>(_wcstoi64(s + 4, nullptr, 0));
        return true;
    }
    if (wcsncmp(s, L"f32:", 4) == 0) {
        *kind = HDL_CALL_ARG_F32;
        float f = static_cast<float>(_wtof(s + 4));
        uint32_t bits = 0;
        memcpy(&bits, &f, sizeof(bits));
        *u64 = bits;
        return true;
    }
    if (wcsncmp(s, L"f64:", 4) == 0) {
        *kind = HDL_CALL_ARG_F64;
        double d = _wtof(s + 4);
        memcpy(u64, &d, sizeof(d));
        return true;
    }
    if (wcsncmp(s, L"ptr:", 4) == 0) {
        *kind = HDL_CALL_ARG_PTR;
        *u64 = _wcstoui64(s + 4, nullptr, 0);
        return true;
    }
    if (wcsncmp(s, L"cstr:", 5) == 0) {
        *kind = HDL_CALL_ARG_CSTR;
        char buf[1024];
        WideCharToMultiByte(CP_UTF8, 0, s + 5, -1, buf, sizeof(buf), nullptr, nullptr);
        blob->assign(reinterpret_cast<uint8_t*>(buf),
                     reinterpret_cast<uint8_t*>(buf) + strlen(buf) + 1);
        return true;
    }
    if (wcsncmp(s, L"wstr:", 5) == 0) {
        *kind = HDL_CALL_ARG_WSTR;
        const size_t n = (wcslen(s + 5) + 1) * sizeof(wchar_t);
        blob->resize(n);
        memcpy(blob->data(), s + 5, n);
        return true;
    }
    if (wcsncmp(s, L"buf:", 4) == 0) {
        *kind = HDL_CALL_ARG_BUF;
        if (!ParseHexBytes(s + 4, *blob) || blob->empty()) {
            return false;
        }
        *size = static_cast<uint32_t>(blob->size());
        return true;
    }
    return false;
}

void AppendCallArg(std::vector<uint8_t>& req, int32_t kind, uint32_t size, uint64_t u64,
                   const std::vector<uint8_t>& blob) {
    using namespace hdl::proto;
    AppendPod(req, kind);
    AppendPod(req, size);
    AppendPod(req, u64);
    if (kind == HDL_CALL_ARG_CSTR || kind == HDL_CALL_ARG_WSTR || kind == HDL_CALL_ARG_BUF) {
        AppendPod(req, static_cast<uint32_t>(blob.size()));
        AppendBytes(req, blob.data(), blob.size());
    }
}

static CommandResult PrintCallReply(CmdCtx& ctx, const wchar_t* verb,
                                    const std::vector<uint8_t>& resp) {
    using namespace hdl::proto;
    Reader r(resp);
    int32_t st = 0;
    HdlCallResult result{};
    if (!r.TakePod(st) || !hdl::proto::TakeHdlCallResult(r, result)) {
        return FailBadResp(ctx);
    }

    struct BufDump {
        uint32_t idx = 0;
        std::string hex;
    };
    std::vector<BufDump> bufs;
    uint32_t buf_n = 0;
    if (r.TakePod(buf_n)) {
        for (uint32_t i = 0; i < buf_n; ++i) {
            uint32_t idx = 0;
            uint32_t sz = 0;
            if (!r.TakePod(idx) || !r.TakePod(sz) || r.left < sz) {
                return FailBadResp(ctx);
            }
            BufDump bd;
            bd.idx = idx;
            bd.hex.reserve(sz * 2);
            for (uint32_t b = 0; b < sz; ++b) {
                char tmp[3];
                snprintf(tmp, sizeof(tmp), "%02x", r.p[b]);
                bd.hex += tmp;
            }
            bufs.push_back(std::move(bd));
            r.p += sz;
            r.left -= sz;
        }
    }

    JsonWriter w;
    w.BeginObject();
    w.Key("return");
    w.HexStr(result.return_value);
    w.Key("last_error");
    w.Num(result.last_error);
    if (!bufs.empty()) {
        w.Key("bufs");
        w.BeginArray();
        for (const auto& bd : bufs) {
            w.BeginObject();
            w.Key("index");
            w.Num(bd.idx);
            w.Key("hex");
            w.Str(bd.hex);
            w.EndObject();
        }
        w.EndArray();
    }
    w.EndObject();

    for (const auto& bd : bufs) {
        wchar_t prefix[32];
        swprintf_s(prefix, L"buf[%u]=", bd.idx);
        for (size_t i = 0; i < bd.hex.size(); i += 2) {
            wchar_t pair[4];
            swprintf_s(pair, L"%lc%lc", bd.hex[i], bd.hex[i + 1]);
        }
    }
    return CmdStatus(verb, st, w.Take());
}

CommandResult CmdResolve(CmdCtx& ctx) {
    using namespace hdl::proto;
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;

    std::wstring module;
    const wchar_t* export_name = nullptr;
    for (int i = 3; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--module") == 0 && i + 1 < ctx.argc) {
            module = ctx.argv[++i];
        } else if (!export_name) {
            export_name = ctx.argv[i];
        }
    }
    if (!export_name) {
        return FailUsage(ctx);
    }
    char name[256];
    WideCharToMultiByte(CP_UTF8, 0, export_name, -1, name, sizeof(name), nullptr, nullptr);
    AppendPod(req, static_cast<uint32_t>(OpResolveExport));
    AppendWString(req, module.c_str());
    AppendString(req, name);
    if (!ctx.client.Request(req, resp)) {
        return FailIpc(ctx);
    }
    Reader r(resp);
    int32_t st = 0;
    uint64_t addr = 0;
    if (!r.TakePod(st) || !r.TakePod(addr)) {
        return FailBadResp(ctx);
    }
    JsonWriter w;
    w.BeginObject();
    w.Key("addr");
    w.HexStr(addr);
    w.EndObject();
    return CmdStatus(L"resolve", st, w.Take());
}

CommandResult CmdCall(CmdCtx& ctx) {
    using namespace hdl::proto;
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;

    std::wstring module;
    const wchar_t* export_name = nullptr;
    uint64_t addr = 0;
    bool have_addr = false;
    bool main_thread = false;
    uint32_t timeout_ms = 0;
    uint64_t job_id = 0;
    std::vector<std::wstring> arg_texts;
    for (int i = 3; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--module") == 0 && i + 1 < ctx.argc) {
            module = ctx.argv[++i];
        } else if (wcscmp(ctx.argv[i], L"--addr") == 0 && i + 1 < ctx.argc) {
            addr = _wcstoui64(ctx.argv[++i], nullptr, 0);
            have_addr = true;
        } else if (wcscmp(ctx.argv[i], L"--main") == 0) {
            main_thread = true;
        } else if (wcscmp(ctx.argv[i], L"--timeout") == 0 && i + 1 < ctx.argc) {
            timeout_ms = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
        } else if (wcscmp(ctx.argv[i], L"--job") == 0 && i + 1 < ctx.argc) {
            job_id = _wcstoui64(ctx.argv[++i], nullptr, 0);
        } else if (!have_addr && !export_name) {
            export_name = ctx.argv[i];
        } else {
            arg_texts.push_back(ctx.argv[i]);
        }
    }
    if (!have_addr && !export_name) {
        return FailUsage(ctx);
    }

    if (have_addr) {
        AppendPod(req, static_cast<uint32_t>(OpCall));
        AppendPod(req, addr);
        AppendPod(req, static_cast<uint32_t>(arg_texts.size()));
        AppendPod(req, static_cast<uint32_t>(main_thread ? HDL_CALL_THREAD_MAIN
                                                         : HDL_CALL_THREAD_WORKER));
        AppendPod(req, timeout_ms);
        AppendPod(req, job_id);
    } else {
        char name[256];
        WideCharToMultiByte(CP_UTF8, 0, export_name, -1, name, sizeof(name), nullptr, nullptr);
        AppendPod(req, static_cast<uint32_t>(OpCallExport));
        AppendWString(req, module.c_str());
        AppendString(req, name);
        AppendPod(req, static_cast<uint32_t>(arg_texts.size()));
        AppendPod(req, timeout_ms);
        AppendPod(req, job_id);
    }
    for (const auto& t : arg_texts) {
        int32_t kind = 0;
        uint32_t size = 0;
        uint64_t u64 = 0;
        std::vector<uint8_t> blob;
        if (!EncodeCallArg(t.c_str(), &kind, &size, &u64, &blob)) {
            return FailArg(ctx, t.c_str());
        }
        if (kind == HDL_CALL_ARG_PTR) {
            AppendPod(req, kind);
            AppendPod(req, size);
            AppendPod(req, u64);
        } else {
            AppendCallArg(req, kind, size, u64, blob);
        }
    }
    if (!ctx.client.Request(req, resp)) {
        return FailIpc(ctx);
    }
    return PrintCallReply(ctx, L"call", resp);
}

CommandResult CmdVcall(CmdCtx& ctx) {
    using namespace hdl::proto;
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;

    if (ctx.argc < 5) {
        return FailUsage(ctx);
    }
    const uint64_t obj = _wcstoui64(ctx.argv[3], nullptr, 0);
    const uint32_t index = static_cast<uint32_t>(_wtoi(ctx.argv[4]));
    bool main_thread = false;
    int32_t prepend_this = 1;
    uint32_t timeout_ms = 0;
    uint64_t job_id = 0;
    std::vector<std::wstring> arg_texts;
    for (int i = 5; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--main") == 0) {
            main_thread = true;
        } else if (wcscmp(ctx.argv[i], L"--no-this") == 0) {
            prepend_this = 0;
        } else if (wcscmp(ctx.argv[i], L"--timeout") == 0 && i + 1 < ctx.argc) {
            timeout_ms = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
        } else if (wcscmp(ctx.argv[i], L"--job") == 0 && i + 1 < ctx.argc) {
            job_id = _wcstoui64(ctx.argv[++i], nullptr, 0);
        } else {
            arg_texts.push_back(ctx.argv[i]);
        }
    }
    AppendPod(req, static_cast<uint32_t>(OpCallVtable));
    AppendPod(req, obj);
    AppendPod(req, index);
    AppendPod(req, static_cast<uint32_t>(arg_texts.size()));
    AppendPod(req, prepend_this);
    AppendPod(req,
              static_cast<uint32_t>(main_thread ? HDL_CALL_THREAD_MAIN : HDL_CALL_THREAD_WORKER));
    AppendPod(req, timeout_ms);
    AppendPod(req, job_id);
    for (const auto& t : arg_texts) {
        int32_t kind = 0;
        uint32_t size = 0;
        uint64_t u64 = 0;
        std::vector<uint8_t> blob;
        if (!EncodeCallArg(t.c_str(), &kind, &size, &u64, &blob)) {
            return FailArg(ctx, t.c_str());
        }
        if (kind == HDL_CALL_ARG_PTR) {
            AppendPod(req, kind);
            AppendPod(req, size);
            AppendPod(req, u64);
        } else {
            AppendCallArg(req, kind, size, u64, blob);
        }
    }
    if (!ctx.client.Request(req, resp)) {
        return FailIpc(ctx);
    }
    return PrintCallReply(ctx, L"vcall", resp);
}

CommandResult CmdAlloc(CmdCtx& ctx) {
    using namespace hdl::proto;
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;

    if (ctx.argc < 4) {
        return FailUsage(ctx);
    }
    const uint64_t size = _wcstoui64(ctx.argv[3], nullptr, 0);
    uint32_t protect = PAGE_READWRITE;
    for (int i = 4; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--protect") == 0 && i + 1 < ctx.argc) {
            ++i;
            if (_wcsicmp(ctx.argv[i], L"RWX") == 0 || _wcsicmp(ctx.argv[i], L"rwx") == 0) {
                protect = PAGE_EXECUTE_READWRITE;
            } else {
                protect = PAGE_READWRITE;
            }
        }
    }
    AppendPod(req, static_cast<uint32_t>(OpAlloc));
    AppendPod(req, size);
    AppendPod(req, protect);
    if (!ctx.client.Request(req, resp)) {
        return FailIpc(ctx);
    }
    Reader r(resp);
    int32_t st = 0;
    uint64_t addr = 0;
    if (!r.TakePod(st) || !r.TakePod(addr)) {
        return FailBadResp(ctx);
    }
    JsonWriter w;
    w.BeginObject();
    w.Key("addr");
    w.HexStr(addr);
    w.EndObject();
    return CmdStatus(L"alloc", st, w.Take());
}

CommandResult CmdFree(CmdCtx& ctx) {
    using namespace hdl::proto;
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;

    if (ctx.argc < 4) {
        return FailUsage(ctx);
    }
    const uint64_t addr = _wcstoui64(ctx.argv[3], nullptr, 0);
    AppendPod(req, static_cast<uint32_t>(OpFree));
    AppendPod(req, addr);
    if (!ctx.client.Request(req, resp)) {
        return FailIpc(ctx);
    }
    Reader r(resp);
    int32_t st = 0;
    r.TakePod(st);
    return CmdStatus(L"free", st, "{}");
}
