#include "cmd.hpp"
#include "json_out.hpp"
#include "usage.hpp"
#include "util.hpp"

#include "protocol.hpp"
#include "hdllib/hdllib.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static int FailIpc(CmdCtx& ctx) {
    if (ctx.json) {
        EmitError(ctx, HDL_E_FAILED, ctx.cmd.c_str(), L"IPC request failed");
    }
    return 1;
}

static int FailArg(CmdCtx& ctx, const wchar_t* hint) {
    if (ctx.json) {
        EmitError(ctx, HDL_E_INVALID_ARG, ctx.cmd.c_str(), hint);
    } else {
        wprintf(L"%ls\n", hint);
    }
    return 1;
}

static void EmitHitsJson(CmdCtx& ctx, int32_t st, uint64_t session, bool have_session,
                         uint32_t total, const std::vector<uint64_t>& hits) {
    JsonWriter w;
    w.BeginObject();
    if (have_session) {
        w.Key("session");
        w.HexStr(session);
    }
    w.Key("total");
    w.Num(total);
    w.Key("hits");
    w.BeginArray();
    for (uint64_t h : hits) {
        w.HexStr(h);
    }
    w.EndArray();
    w.EndObject();
    EmitEnvelope(ctx, st, ctx.cmd.c_str(), w.Take());
}

bool ParseValueType(const wchar_t* s, int32_t* out) {
    if (!s || !out) return false;
    if (_wcsicmp(s, L"bytes") == 0 || _wcsicmp(s, L"aob") == 0) {
        *out = HDL_VALUE_BYTES;
    } else if (_wcsicmp(s, L"i8") == 0) {
        *out = HDL_VALUE_I8;
    } else if (_wcsicmp(s, L"u8") == 0) {
        *out = HDL_VALUE_U8;
    } else if (_wcsicmp(s, L"i16") == 0) {
        *out = HDL_VALUE_I16;
    } else if (_wcsicmp(s, L"u16") == 0) {
        *out = HDL_VALUE_U16;
    } else if (_wcsicmp(s, L"i32") == 0) {
        *out = HDL_VALUE_I32;
    } else if (_wcsicmp(s, L"u32") == 0) {
        *out = HDL_VALUE_U32;
    } else if (_wcsicmp(s, L"i64") == 0) {
        *out = HDL_VALUE_I64;
    } else if (_wcsicmp(s, L"u64") == 0) {
        *out = HDL_VALUE_U64;
    } else if (_wcsicmp(s, L"f32") == 0 || _wcsicmp(s, L"float") == 0) {
        *out = HDL_VALUE_F32;
    } else if (_wcsicmp(s, L"f64") == 0 || _wcsicmp(s, L"double") == 0) {
        *out = HDL_VALUE_F64;
    } else if (_wcsicmp(s, L"string") == 0) {
        *out = HDL_VALUE_STRING;
    } else if (_wcsicmp(s, L"wstring") == 0) {
        *out = HDL_VALUE_WSTRING;
    } else {
        return false;
    }
    return true;
}

bool ParseCmp(const wchar_t* s, int32_t* out) {
    if (!s || !out) return false;
    if (_wcsicmp(s, L"exact") == 0) {
        *out = HDL_CMP_EXACT;
    } else if (_wcsicmp(s, L"unknown") == 0) {
        *out = HDL_CMP_UNKNOWN;
    } else if (_wcsicmp(s, L"changed") == 0) {
        *out = HDL_CMP_CHANGED;
    } else if (_wcsicmp(s, L"unchanged") == 0) {
        *out = HDL_CMP_UNCHANGED;
    } else if (_wcsicmp(s, L"increased") == 0) {
        *out = HDL_CMP_INCREASED;
    } else if (_wcsicmp(s, L"decreased") == 0) {
        *out = HDL_CMP_DECREASED;
    } else if (_wcsicmp(s, L"increased_by") == 0) {
        *out = HDL_CMP_INCREASED_BY;
    } else if (_wcsicmp(s, L"decreased_by") == 0) {
        *out = HDL_CMP_DECREASED_BY;
    } else if (_wcsicmp(s, L"greater") == 0) {
        *out = HDL_CMP_GREATER;
    } else if (_wcsicmp(s, L"less") == 0) {
        *out = HDL_CMP_LESS;
    } else {
        return false;
    }
    return true;
}

size_t ValueTypeWidth(int32_t type) {
    switch (type) {
    case HDL_VALUE_I8:
    case HDL_VALUE_U8:
        return 1;
    case HDL_VALUE_I16:
    case HDL_VALUE_U16:
        return 2;
    case HDL_VALUE_I32:
    case HDL_VALUE_U32:
    case HDL_VALUE_F32:
        return 4;
    case HDL_VALUE_I64:
    case HDL_VALUE_U64:
    case HDL_VALUE_F64:
        return 8;
    default:
        return 0;
    }
}

bool EncodeTypedValue(int32_t type, const wchar_t* text, std::vector<uint8_t>& out) {
    out.clear();
    if (!text) {
        return false;
    }
    if (type == HDL_VALUE_BYTES) {
        char buf[1024];
        if (!WideCharToMultiByte(CP_UTF8, 0, text, -1, buf, sizeof(buf), nullptr, nullptr)) {
            return false;
        }
        out.assign(reinterpret_cast<uint8_t*>(buf),
                   reinterpret_cast<uint8_t*>(buf) + strlen(buf) + 1);
        return true;
    }
    if (type == HDL_VALUE_STRING) {
        char buf[1024];
        const int n =
            WideCharToMultiByte(CP_UTF8, 0, text, -1, buf, sizeof(buf), nullptr, nullptr);
        if (n <= 1) {
            return false;
        }
        out.assign(reinterpret_cast<uint8_t*>(buf), reinterpret_cast<uint8_t*>(buf) + (n - 1));
        return true;
    }
    if (type == HDL_VALUE_WSTRING) {
        const size_t n = wcslen(text) * sizeof(wchar_t);
        out.resize(n);
        memcpy(out.data(), text, n);
        return n > 0;
    }

    const size_t width = ValueTypeWidth(type);
    if (width == 0) {
        return false;
    }
    out.resize(width);
    wchar_t* end = nullptr;
    if (type == HDL_VALUE_F32) {
        const float v = static_cast<float>(wcstod(text, &end));
        if (end == text) return false;
        memcpy(out.data(), &v, 4);
        return true;
    }
    if (type == HDL_VALUE_F64) {
        const double v = wcstod(text, &end);
        if (end == text) return false;
        memcpy(out.data(), &v, 8);
        return true;
    }
    if (type == HDL_VALUE_I8 || type == HDL_VALUE_I16 || type == HDL_VALUE_I32 ||
        type == HDL_VALUE_I64) {
        const int64_t v = _wcstoi64(text, &end, 0);
        if (end == text) return false;
        memcpy(out.data(), &v, width);
        return true;
    }
    const uint64_t v = _wcstoui64(text, &end, 0);
    if (end == text) return false;
    memcpy(out.data(), &v, width);
    return true;
}

bool IpcCreateSession(CmdCtx& ctx, uint64_t* out_id) {
    using namespace hdl::proto;
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;
    AppendPod(req, static_cast<uint32_t>(OpSearchCreate));
    if (!ctx.client.Request(req, resp)) {
        if (ctx.json) {
            EmitError(ctx, HDL_E_FAILED, ctx.cmd.c_str(), L"IPC request failed");
        }
        return false;
    }
    Reader r(resp);
    int32_t st = 0;
    if (!r.TakePod(st) || !r.TakePod(*out_id) || st != HDL_OK) {
        if (ctx.json) {
            EmitError(ctx, st != HDL_OK ? st : HDL_E_FAILED, ctx.cmd.c_str(), nullptr);
        } else {
            wprintf(L"scan-create status=%ls\n", StatusName(st));
            PrintStatusHint(ctx.cmd, st);
        }
        return false;
    }
    return true;
}

/* Growable collector for search frames: total, count, u64[count] (no offset). */
bool CollectStreamedHits(PipeClient& client, const std::vector<uint8_t>& req, int32_t* out_st,
                         uint32_t* out_total, std::vector<uint64_t>* out_hits) {
    using namespace hdl::proto;
    if (!out_st || !out_total || !out_hits) {
        return false;
    }
    out_hits->clear();
    *out_st = HDL_E_FAILED;
    *out_total = 0;
    return client.RequestStream(req, [&](int32_t st, uint32_t flags, const uint8_t* p, size_t n) {
        Reader r(p, n);
        uint32_t total = 0;
        uint32_t count = 0;
        if (!r.TakePod(total) || !r.TakePod(count)) {
            return false;
        }
        const size_t need = out_hits->size() + count;
        if (out_hits->capacity() < need) {
            size_t cap = out_hits->capacity() ? out_hits->capacity() : 256;
            while (cap < need) {
                cap *= 2;
            }
            out_hits->reserve(cap);
        }
        for (uint32_t i = 0; i < count; ++i) {
            uint64_t hit = 0;
            if (!r.TakePod(hit)) {
                return false;
            }
            out_hits->push_back(hit);
        }
        if ((flags & HDL_IPC_MORE) == 0) {
            *out_st = st;
            *out_total = total ? total : static_cast<uint32_t>(out_hits->size());
        }
        return true;
    });
}

void PrintHitList(const std::vector<uint64_t>& hits, uint32_t max_print) {
    const uint32_t n =
        (max_print && max_print < hits.size()) ? max_print : static_cast<uint32_t>(hits.size());
    for (uint32_t i = 0; i < n; ++i) {
        wprintf(L"  %016llx\n", static_cast<unsigned long long>(hits[i]));
    }
    if (max_print && hits.size() > max_print) {
        wprintf(L"  ... (%zu more)\n", hits.size() - max_print);
    }
}

int PrintScanHits(CmdCtx& ctx, uint64_t session, uint32_t max_hits) {
    using namespace hdl::proto;
    std::vector<uint8_t> req;
    AppendPod(req, static_cast<uint32_t>(OpSearchGetHits));
    AppendPod(req, session);
    AppendPod(req, max_hits);
    AppendPod(req, static_cast<uint64_t>(0));
    AppendPod(req, static_cast<uint32_t>(0));
    AppendPod(req, static_cast<uint32_t>(HDL_IPC_REQ_STREAM)); /* always streamed */

    int32_t st = 0;
    uint32_t total = 0;
    std::vector<uint64_t> hits;
    if (!CollectStreamedHits(ctx.client, req, &st, &total, &hits)) {
        return FailIpc(ctx);
    }
    if (ctx.json) {
        EmitHitsJson(ctx, st, session, true, total, hits);
        return st == HDL_OK ? 0 : 1;
    }
    wprintf(L"status=%ls total=%u session=%llu\n", StatusName(st), total,
            static_cast<unsigned long long>(session));
    PrintHitList(hits, 0);
    PrintStatusHint(ctx.cmd, st);
    return st == HDL_OK ? 0 : 1;
}

int CmdScan(CmdCtx& ctx) {
    using namespace hdl::proto;
    std::vector<uint8_t> req;
    std::vector<uint8_t> resp;

    const char* pattern = nullptr;
    std::string pattern_storage;
    std::wstring value_text;
    bool have_value = false;
    bool do_next = false;
    bool do_hits = false;
    bool do_close = false;
    bool do_reset = false;
    bool unaligned = false;
    int32_t value_type = -1;
    int32_t cmp = HDL_CMP_EXACT;
    bool have_cmp = false;
    uint64_t start = 0;
    uint64_t size = 0;
    uint64_t session = 0;
    bool have_session = false;
    uint64_t job_id = 0;
    uint32_t timeout_ms = 0;
    uint32_t max_hits = 0; /* 0 = unlimited */

    for (int i = 3; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--pattern") == 0 && i + 1 < ctx.argc) {
            ++i;
            char buf[512];
            WideCharToMultiByte(CP_UTF8, 0, ctx.argv[i], -1, buf, sizeof(buf), nullptr, nullptr);
            pattern_storage = buf;
            pattern = pattern_storage.c_str();
            value_type = HDL_VALUE_BYTES;
        } else if (wcscmp(ctx.argv[i], L"--type") == 0 && i + 1 < ctx.argc) {
            if (!ParseValueType(ctx.argv[++i], &value_type)) {
                return FailArg(ctx, L"Unknown --type");
            }
        } else if (wcscmp(ctx.argv[i], L"--value") == 0 && i + 1 < ctx.argc) {
            value_text = ctx.argv[++i];
            have_value = true;
        } else if (wcscmp(ctx.argv[i], L"--cmp") == 0 && i + 1 < ctx.argc) {
            if (!ParseCmp(ctx.argv[++i], &cmp)) {
                return FailArg(ctx, L"Unknown --cmp");
            }
            have_cmp = true;
        } else if (wcscmp(ctx.argv[i], L"--start") == 0 && i + 1 < ctx.argc) {
            ParseHexU64(ctx.argv[++i], &start);
        } else if (wcscmp(ctx.argv[i], L"--size") == 0 && i + 1 < ctx.argc) {
            ParseHexU64(ctx.argv[++i], &size);
        } else if (wcscmp(ctx.argv[i], L"--max") == 0 && i + 1 < ctx.argc) {
            max_hits = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
        } else if (wcscmp(ctx.argv[i], L"--session") == 0 && i + 1 < ctx.argc) {
            session = _wcstoui64(ctx.argv[++i], nullptr, 0);
            have_session = true;
        } else if (wcscmp(ctx.argv[i], L"--job") == 0 && i + 1 < ctx.argc) {
            job_id = _wcstoui64(ctx.argv[++i], nullptr, 0);
        } else if (wcscmp(ctx.argv[i], L"--timeout") == 0 && i + 1 < ctx.argc) {
            timeout_ms = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
        } else if (wcscmp(ctx.argv[i], L"--next") == 0) {
            do_next = true;
        } else if (wcscmp(ctx.argv[i], L"--hits") == 0) {
            do_hits = true;
        } else if (wcscmp(ctx.argv[i], L"--close") == 0) {
            do_close = true;
        } else if (wcscmp(ctx.argv[i], L"--reset") == 0) {
            do_reset = true;
        } else if (wcscmp(ctx.argv[i], L"--unaligned") == 0) {
            unaligned = true;
        } else if (wcscmp(ctx.argv[i], L"--stream") == 0) {
            /* Search always streams; flag kept for compatibility. */
        }
    }

    auto append_job_trailer = [&](std::vector<uint8_t>& out, uint32_t flags = 0) {
        AppendPod(out, job_id);
        AppendPod(out, timeout_ms);
        AppendPod(out, flags);
    };

    // Legacy one-shot AOB path (no session) — always streamed with backpressure.
    if (pattern && !do_next && !do_hits && !do_close && !do_reset && value_type == HDL_VALUE_BYTES &&
        !have_session && !have_cmp) {
        AppendPod(req, static_cast<uint32_t>(OpSearchMemory));
        AppendPod(req, start);
        AppendPod(req, size);
        AppendPod(req, max_hits);
        AppendString(req, pattern);
        append_job_trailer(req, HDL_IPC_REQ_STREAM);
        int32_t st = 0;
        uint32_t total = 0;
        std::vector<uint64_t> hits;
        if (!CollectStreamedHits(ctx.client, req, &st, &total, &hits)) {
            return FailIpc(ctx);
        }
        if (ctx.json) {
            EmitHitsJson(ctx, st, 0, false, total, hits);
            return st == HDL_OK ? 0 : 1;
        }
        wprintf(L"status=%ls hits=%u\n", StatusName(st), total);
        PrintHitList(hits, 0);
        PrintStatusHint(ctx.cmd, st);
        return st == HDL_OK ? 0 : 1;
    }

    if (do_hits || do_close || do_reset || do_next) {
        if (!have_session) {
            return FailArg(ctx, L"--session required");
        }
    }

    if (do_hits) {
        return PrintScanHits(ctx, session, max_hits);
    }
    if (do_close || do_reset) {
        AppendPod(req, static_cast<uint32_t>(do_close ? OpSearchClose : OpSearchReset));
        AppendPod(req, session);
        if (!ctx.client.Request(req, resp)) {
            return FailIpc(ctx);
        }
        Reader r(resp);
        int32_t st = 0;
        r.TakePod(st);
        if (ctx.json) {
            JsonWriter w;
            w.BeginObject();
            w.Key("session");
            w.HexStr(session);
            w.EndObject();
            EmitEnvelope(ctx, st, ctx.cmd.c_str(), w.Take());
            return st == HDL_OK ? 0 : 1;
        }
        wprintf(L"status=%ls session=%llu\n", StatusName(st),
                static_cast<unsigned long long>(session));
        PrintStatusHint(ctx.cmd, st);
        return st == HDL_OK ? 0 : 1;
    }

    if (do_next) {
        std::vector<uint8_t> encoded;
        if (have_value) {
            // Type is unknown on the ctx.client for next; encode as raw for bytes pattern
            // or require --type when value is supplied.
            if (value_type < 0) {
                return FailArg(ctx, L"--type required with --value on --next");
            }
            if (!EncodeTypedValue(value_type, value_text.c_str(), encoded)) {
                return FailArg(ctx, L"Bad --value");
            }
        }
        AppendPod(req, static_cast<uint32_t>(OpSearchNext));
        AppendPod(req, session);
        AppendPod(req, cmp);
        AppendPod(req, static_cast<uint32_t>(encoded.size()));
        if (!encoded.empty()) {
            AppendBytes(req, encoded.data(), encoded.size());
        }
        append_job_trailer(req);
        if (!ctx.client.Request(req, resp)) {
            return FailIpc(ctx);
        }
        Reader r(resp);
        int32_t st = 0;
        uint32_t count = 0;
        if (!r.TakePod(st) || !r.TakePod(count)) {
            if (ctx.json) {
                EmitError(ctx, HDL_E_FAILED, ctx.cmd.c_str(), L"bad response");
            }
            return 1;
        }
        if (ctx.json) {
            if (st == HDL_OK) {
                return PrintScanHits(ctx, session, max_hits);
            }
            JsonWriter w;
            w.BeginObject();
            w.Key("session");
            w.HexStr(session);
            w.Key("hits");
            w.Num(count);
            w.EndObject();
            EmitEnvelope(ctx, st, ctx.cmd.c_str(), w.Take());
            return 1;
        }
        wprintf(L"status=%ls hits=%u session=%llu\n", StatusName(st), count,
                static_cast<unsigned long long>(session));
        if (st == HDL_OK) {
            return PrintScanHits(ctx, session, max_hits);
        }
        PrintStatusHint(ctx.cmd, st);
        return 1;
    }

    // First typed / session scan.
    if (value_type < 0) {
        return FailArg(ctx, L"--type or --pattern required");
    }
    if (cmp != HDL_CMP_UNKNOWN && !have_value && value_type != HDL_VALUE_BYTES) {
        return FailArg(ctx, L"--value required");
    }
    if (value_type == HDL_VALUE_BYTES && !have_value && !pattern) {
        return FailArg(ctx, L"--value/--pattern required for bytes");
    }

    std::vector<uint8_t> encoded;
    if (value_type == HDL_VALUE_BYTES) {
        const wchar_t* src = have_value ? value_text.c_str() : nullptr;
        std::wstring tmp;
        if (pattern && !have_value) {
            // pattern already narrow; re-widen for EncodeTypedValue path via storage
            wchar_t wbuf[1024];
            MultiByteToWideChar(CP_UTF8, 0, pattern, -1, wbuf, 1024);
            tmp = wbuf;
            src = tmp.c_str();
            if (!EncodeTypedValue(HDL_VALUE_BYTES, src, encoded)) {
                return FailArg(ctx, L"Bad pattern");
            }
        } else if (!EncodeTypedValue(HDL_VALUE_BYTES, value_text.c_str(), encoded)) {
            return FailArg(ctx, L"Bad --value");
        }
    } else if (cmp != HDL_CMP_UNKNOWN) {
        if (!EncodeTypedValue(value_type, value_text.c_str(), encoded)) {
            return FailArg(ctx, L"Bad --value");
        }
    }

    if (!have_session) {
        if (!IpcCreateSession(ctx, &session)) {
            return ctx.json ? 1 : 1;
        }
        have_session = true;
    }

    AppendPod(req, static_cast<uint32_t>(OpSearchFirst));
    AppendPod(req, session);
    AppendPod(req, start);
    AppendPod(req, size);
    AppendPod(req, value_type);
    AppendPod(req, cmp);
    AppendPod(req, unaligned ? 1u : 0u);
    AppendPod(req, max_hits);
    AppendPod(req, static_cast<uint32_t>(encoded.size()));
    if (!encoded.empty()) {
        AppendBytes(req, encoded.data(), encoded.size());
    }
    uint32_t search_flags = 0;
    std::wstring module;
    for (int i = 3; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--image") == 0) {
            search_flags |= HDL_SEARCH_IMAGE;
        } else if (wcscmp(ctx.argv[i], L"--executable") == 0) {
            search_flags |= HDL_SEARCH_EXECUTABLE;
        } else if (wcscmp(ctx.argv[i], L"--module") == 0 && i + 1 < ctx.argc) {
            module = ctx.argv[++i];
            search_flags |= HDL_SEARCH_MODULE;
        }
    }
    AppendPod(req, search_flags);
    AppendWString(req, module.c_str());
    append_job_trailer(req, HDL_IPC_REQ_STREAM);
    int32_t st = 0;
    uint32_t total = 0;
    std::vector<uint64_t> hits;
    if (!CollectStreamedHits(ctx.client, req, &st, &total, &hits)) {
        return FailIpc(ctx);
    }
    if (ctx.json) {
        EmitHitsJson(ctx, st, session, true, total, hits);
        return st == HDL_OK ? 0 : 1;
    }
    wprintf(L"status=%ls hits=%u session=%llu\n", StatusName(st), total,
            static_cast<unsigned long long>(session));
    PrintHitList(hits, 0);
    PrintStatusHint(ctx.cmd, st);
    return st == HDL_OK ? 0 : 1;
}

