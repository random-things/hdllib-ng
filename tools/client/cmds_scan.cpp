#include "cmd.hpp"
#include "cmd_fail.hpp"
#include "json_out.hpp"
#include "usage.hpp"
#include "util.hpp"

#include "hdllib/hdllib.h"
#include "protocol.hpp"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#pragma comment(lib, "Bcrypt.lib")

namespace {

class CandidateFileWriter {
  public:
    ~CandidateFileWriter() {
        if (handle_ != INVALID_HANDLE_VALUE) {
            CloseHandle(handle_);
        }
    }

    bool Open(const std::wstring& path) {
        path_ = path;
        handle_ = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
        if (handle_ == INVALID_HANDLE_VALUE) {
            return false;
        }
        static constexpr char kMagic[] = "HDLCAND1";
        const uint32_t version = 1;
        const uint32_t record_size = sizeof(uint64_t);
        const uint64_t count = 0;
        return WriteAll(kMagic, sizeof(kMagic) - 1) && WriteAll(&version, sizeof(version)) &&
               WriteAll(&record_size, sizeof(record_size)) && WriteAll(&count, sizeof(count));
    }

    bool Append(const uint64_t* hits, uint32_t count) {
        if (!hits || count == 0) {
            return true;
        }
        if (!WriteAll(hits, static_cast<size_t>(count) * sizeof(uint64_t))) {
            return false;
        }
        count_ += count;
        return true;
    }

    bool Finish() {
        if (handle_ == INVALID_HANDLE_VALUE) {
            return true;
        }
        LARGE_INTEGER count_offset{};
        count_offset.QuadPart = 16;
        if (!SetFilePointerEx(handle_, count_offset, nullptr, FILE_BEGIN) ||
            !WriteAll(&count_, sizeof(count_)) || !FlushFileBuffers(handle_)) {
            return false;
        }
        CloseHandle(handle_);
        handle_ = INVALID_HANDLE_VALUE;
        return true;
    }

    uint64_t Count() const { return count_; }
    const std::wstring& Path() const { return path_; }

  private:
    bool WriteAll(const void* data, size_t size) {
        const auto* cursor = static_cast<const uint8_t*>(data);
        while (size != 0) {
            const DWORD chunk = static_cast<DWORD>((std::min)(size, size_t{0xffffffffu}));
            DWORD wrote = 0;
            if (!WriteFile(handle_, cursor, chunk, &wrote, nullptr) || wrote == 0) {
                return false;
            }
            cursor += wrote;
            size -= wrote;
        }
        return true;
    }

    HANDLE handle_ = INVALID_HANDLE_VALUE;
    uint64_t count_ = 0;
    std::wstring path_;
};

bool MakeDefaultCandidatePath(std::wstring* out) {
    if (!out) {
        return false;
    }
    wchar_t temp[MAX_PATH]{};
    const DWORD length = GetTempPathW(MAX_PATH, temp);
    if (length == 0 || length >= MAX_PATH) {
        return false;
    }
    std::array<uint32_t, 4> token{};
    if (BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(token.data()), sizeof(token),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
        return false;
    }
    wchar_t path[MAX_PATH]{};
    if (swprintf_s(path, L"%shdllib-candidates-%08x%08x%08x%08x.bin", temp, token[0], token[1],
                   token[2], token[3]) < 0) {
        return false;
    }
    *out = path;
    return true;
}

} // namespace

static std::string BuildHitsJson(int32_t /*st*/, uint64_t session, bool have_session,
                                 uint64_t total, const std::vector<uint64_t>& hits,
                                 const std::wstring& candidate_file, const wchar_t* /*cmd*/) {
    JsonWriter w;
    w.BeginObject();
    if (have_session) {
        w.Key("session");
        w.HexStr(session);
    }
    w.Key("total");
    w.Num(total);
    if (!candidate_file.empty()) {
        w.Key("candidate_file");
        w.Str(candidate_file);
    }
    w.Key("hits");
    w.BeginArray();
    for (uint64_t h : hits) {
        w.HexStr(h);
    }
    w.EndArray();
    w.EndObject();
    return w.Take();
}

bool ParseValueType(const wchar_t* s, int32_t* out) {
    if (!s || !out)
        return false;
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
    if (!s || !out)
        return false;
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
        const int n = WideCharToMultiByte(CP_UTF8, 0, text, -1, buf, sizeof(buf), nullptr, nullptr);
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
        if (end == text)
            return false;
        memcpy(out.data(), &v, 4);
        return true;
    }
    if (type == HDL_VALUE_F64) {
        const double v = wcstod(text, &end);
        if (end == text)
            return false;
        memcpy(out.data(), &v, 8);
        return true;
    }
    if (type == HDL_VALUE_I8 || type == HDL_VALUE_I16 || type == HDL_VALUE_I32 ||
        type == HDL_VALUE_I64) {
        const int64_t v = _wcstoi64(text, &end, 0);
        if (end == text)
            return false;
        memcpy(out.data(), &v, width);
        return true;
    }
    const uint64_t v = _wcstoui64(text, &end, 0);
    if (end == text)
        return false;
    memcpy(out.data(), &v, width);
    return true;
}

static bool IpcCreateSession(CmdCtx& ctx, uint64_t* out_id) {
    using namespace hdl::proto;
    PreparedRequest req;
    std::vector<uint8_t> resp;
    SetMethod(req, hdl::rpc::Method::SearchCreate);
    if (!ctx.client.Request(req, resp)) {
        return false;
    }
    Reader r(resp);
    int32_t st = 0;
    if (!r.TakePod(st) || !r.TakePod(*out_id) || st != HDL_OK) {
        return false;
    }
    return true;
}

/* Growable collector for search frames: total, count, u64[count] (no offset). */
bool CollectStreamedHits(PipeClient& client, const hdl::rpc::PreparedRequest& req, int32_t* out_st,
                         uint64_t* out_total, std::vector<uint64_t>* out_hits,
                         CandidateFileWriter* writer, bool* out_bad_resp) {
    using namespace hdl::proto;
    if (!out_st || !out_total || !out_hits) {
        return false;
    }
    out_hits->clear();
    *out_st = HDL_E_FAILED;
    *out_total = 0;
    if (out_bad_resp) {
        *out_bad_resp = false;
    }
    bool bad_resp = false;
    bool ok =
        client.RequestStream(req, [&](int32_t st, uint32_t flags, const uint8_t* p, size_t n) {
            Reader r(p, n);
            uint64_t total = 0;
            uint32_t count = 0;
            if (!r.TakePod(total) || !r.TakePod(count)) {
                bad_resp = true;
                return false;
            }
            std::vector<uint64_t> frame_hits;
            frame_hits.reserve(count);
            for (uint32_t i = 0; i < count; ++i) {
                uint64_t hit = 0;
                if (!r.TakePod(hit)) {
                    bad_resp = true;
                    return false;
                }
                frame_hits.push_back(hit);
                if (!writer || out_hits->size() < 64) {
                    out_hits->push_back(hit);
                }
            }
            if (writer && !writer->Append(frame_hits.data(), count)) {
                bad_resp = true;
                return false;
            }
            if ((flags & HDL_IPC_MORE) == 0) {
                *out_st = st;
                *out_total = total ? total : (writer ? writer->Count() : out_hits->size());
            }
            return true;
        });
    if (out_bad_resp) {
        *out_bad_resp = bad_resp;
    }
    return ok;
}

static bool CollectScanResults(PipeClient& client, const hdl::rpc::PreparedRequest& req,
                               uint32_t max_hits, const std::wstring& requested_file,
                               int32_t* out_st, uint64_t* out_total,
                               std::vector<uint64_t>* out_hits, std::wstring* out_file,
                               bool* out_bad_resp, bool* out_bad_file) {
    if (!out_file || !out_bad_file) {
        return false;
    }
    *out_bad_file = false;
    out_file->clear();
    CandidateFileWriter writer;
    CandidateFileWriter* writer_ptr = nullptr;
    if (!requested_file.empty() || max_hits == 0) {
        *out_file = requested_file;
        if (out_file->empty() && !MakeDefaultCandidatePath(out_file)) {
            *out_bad_file = true;
            return false;
        }
        if (!writer.Open(*out_file)) {
            *out_bad_file = true;
            return false;
        }
        writer_ptr = &writer;
    }
    if (!CollectStreamedHits(client, req, out_st, out_total, out_hits, writer_ptr, out_bad_resp)) {
        return false;
    }
    if (writer_ptr && !writer.Finish()) {
        *out_bad_file = true;
        return false;
    }
    return true;
}

static CommandResult PrintScanHits(CmdCtx& ctx, uint64_t session, uint32_t max_hits,
                                   const std::wstring& requested_file) {
    using namespace hdl::proto;
    PreparedRequest req;
    SetMethod(req, hdl::rpc::Method::SearchGetHits);
    AppendPod(req, session);
    AppendPod(req, max_hits);
    AppendPod(req, static_cast<uint64_t>(0));
    AppendPod(req, static_cast<uint32_t>(0));
    AppendPod(req, static_cast<uint32_t>(HDL_IPC_REQ_STREAM));

    int32_t st = 0;
    uint64_t total = 0;
    std::vector<uint64_t> hits;
    std::wstring candidate_file;
    bool bad_resp = false;
    bool bad_file = false;
    if (!CollectScanResults(ctx.client, req, max_hits, requested_file, &st, &total, &hits,
                            &candidate_file, &bad_resp, &bad_file)) {
        if (bad_file) {
            return CmdFail(ctx.cmd.c_str(), HDL_E_ACCESS, L"Unable to write candidate file");
        }
        return bad_resp ? FailBadResp(ctx) : FailIpc(ctx);
    }
    std::string data_json =
        BuildHitsJson(st, session, true, total, hits, candidate_file, ctx.cmd.c_str());
    return CmdStatus(ctx.cmd.c_str(), st, std::move(data_json));
}

CommandResult CmdScan(CmdCtx& ctx) {
    using namespace hdl::proto;
    PreparedRequest req;
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
    uint32_t timeout_ms = 0;
    uint32_t max_hits = 0; /* 0 = unlimited */
    std::wstring candidate_file_request;

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
        } else if (wcscmp(ctx.argv[i], L"--timeout") == 0 && i + 1 < ctx.argc) {
            timeout_ms = static_cast<uint32_t>(_wtoi(ctx.argv[++i]));
        } else if (wcscmp(ctx.argv[i], L"--candidates") == 0 && i + 1 < ctx.argc) {
            candidate_file_request = ctx.argv[++i];
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

    auto append_request_trailer = [&](PreparedRequest& out, uint32_t flags = 0) {
        out.timeout_ms = timeout_ms;
        AppendPod(out, static_cast<uint64_t>(0));
        AppendPod(out, timeout_ms);
        AppendPod(out, flags);
    };

    // One-shot AOB path (no session) — always streamed with backpressure.
    if (pattern && !do_next && !do_hits && !do_close && !do_reset &&
        value_type == HDL_VALUE_BYTES && !have_session && !have_cmp) {
        SetMethod(req, hdl::rpc::Method::SearchMemory);
        AppendPod(req, start);
        AppendPod(req, size);
        AppendPod(req, max_hits);
        AppendString(req, pattern);
        append_request_trailer(req, HDL_IPC_REQ_STREAM);
        int32_t st = 0;
        uint64_t total = 0;
        std::vector<uint64_t> hits;
        std::wstring candidate_file;
        bool bad_resp = false;
        bool bad_file = false;
        if (!CollectScanResults(ctx.client, req, max_hits, candidate_file_request, &st, &total,
                                &hits, &candidate_file, &bad_resp, &bad_file)) {
            if (bad_file) {
                return CmdFail(ctx.cmd.c_str(), HDL_E_ACCESS, L"Unable to write candidate file");
            }
            return bad_resp ? FailBadResp(ctx) : FailIpc(ctx);
        }
        std::string data_json =
            BuildHitsJson(st, 0, false, total, hits, candidate_file, ctx.cmd.c_str());
        return CmdStatus(ctx.cmd.c_str(), st, std::move(data_json));
    }

    if (do_hits || do_close || do_reset || do_next) {
        if (!have_session) {
            return FailArg(ctx, L"--session required");
        }
    }

    if (do_hits) {
        return PrintScanHits(ctx, session, max_hits, candidate_file_request);
    }
    if (do_close || do_reset) {
        SetMethod(req, do_close ? hdl::rpc::Method::SearchClose : hdl::rpc::Method::SearchReset);
        AppendPod(req, session);
        if (!ctx.client.Request(req, resp)) {
            return FailIpc(ctx);
        }
        Reader r(resp);
        int32_t st = 0;
        r.TakePod(st);
        JsonWriter w;
        w.BeginObject();
        w.Key("session");
        w.HexStr(session);
        w.EndObject();
        return CmdStatus(ctx.cmd.c_str(), st, w.Take());
    }

    if (do_next) {
        std::vector<uint8_t> encoded;
        if (have_value) {
            if (value_type < 0) {
                return FailArg(ctx, L"--type required with --value on --next");
            }
            if (!EncodeTypedValue(value_type, value_text.c_str(), encoded)) {
                return FailArg(ctx, L"Bad --value");
            }
        }
        SetMethod(req, hdl::rpc::Method::SearchNext);
        AppendPod(req, session);
        AppendPod(req, cmp);
        AppendPod(req, static_cast<uint32_t>(encoded.size()));
        if (!encoded.empty()) {
            AppendBytes(req, encoded.data(), encoded.size());
        }
        append_request_trailer(req);
        if (!ctx.client.Request(req, resp)) {
            return FailIpc(ctx);
        }
        Reader r(resp);
        int32_t st = 0;
        uint32_t count = 0;
        if (!r.TakePod(st) || !r.TakePod(count)) {
            return CmdFail(ctx.cmd.c_str(), HDL_E_FAILED, L"Bad response");
        }
        if (st == HDL_OK) {
            return PrintScanHits(ctx, session, max_hits, candidate_file_request);
        }
        JsonWriter w;
        w.BeginObject();
        w.Key("session");
        w.HexStr(session);
        w.Key("hits");
        w.Num(count);
        w.EndObject();
        return CmdStatus(ctx.cmd.c_str(), st, w.Take());
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
            return FailIpc(ctx);
        }
        have_session = true;
    }

    SetMethod(req, hdl::rpc::Method::SearchFirst);
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
    append_request_trailer(req, HDL_IPC_REQ_STREAM);
    int32_t st = 0;
    uint64_t total = 0;
    std::vector<uint64_t> hits;
    std::wstring candidate_file;
    bool bad_resp = false;
    bool bad_file = false;
    if (!CollectScanResults(ctx.client, req, max_hits, candidate_file_request, &st, &total, &hits,
                            &candidate_file, &bad_resp, &bad_file)) {
        if (bad_file) {
            return CmdFail(ctx.cmd.c_str(), HDL_E_ACCESS, L"Unable to write candidate file");
        }
        return bad_resp ? FailBadResp(ctx) : FailIpc(ctx);
    }
    std::string data_json =
        BuildHitsJson(st, session, true, total, hits, candidate_file, ctx.cmd.c_str());
    return CmdStatus(ctx.cmd.c_str(), st, std::move(data_json));
}
