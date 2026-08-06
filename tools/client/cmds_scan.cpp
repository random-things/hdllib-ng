#include "cmd.hpp"
#include "cmd_fail.hpp"
#include "json_out.hpp"
#include "rpc_helpers.hpp"
#include "usage.hpp"
#include "util.hpp"

#include "hdl/rpc/v1/services.rpc.hpp"
#include "hdllib/hdllib.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <string>
#include <vector>

#pragma comment(lib, "Bcrypt.lib")

namespace {

class CandidateFileWriter {
  public:
    ~CandidateFileWriter() {
        if (handle_ != INVALID_HANDLE_VALUE)
            CloseHandle(handle_);
    }
    bool Open(const std::wstring& path) {
        path_ = path;
        handle_ = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, nullptr);
        if (handle_ == INVALID_HANDLE_VALUE)
            return false;
        static constexpr char magic[] = "HDLCAND1";
        const uint32_t version = 1, record_size = sizeof(uint64_t);
        const uint64_t count = 0;
        return WriteAll(magic, sizeof(magic) - 1) && WriteAll(&version, sizeof(version)) &&
               WriteAll(&record_size, sizeof(record_size)) && WriteAll(&count, sizeof(count));
    }
    bool Append(const uint64_t* values, uint32_t count) {
        if (!count)
            return true;
        if (!values || !WriteAll(values, static_cast<size_t>(count) * sizeof(*values)))
            return false;
        count_ += count;
        return true;
    }
    bool Finish() {
        if (handle_ == INVALID_HANDLE_VALUE)
            return true;
        LARGE_INTEGER offset{};
        offset.QuadPart = 16;
        if (!SetFilePointerEx(handle_, offset, nullptr, FILE_BEGIN) ||
            !WriteAll(&count_, sizeof(count_)) || !FlushFileBuffers(handle_))
            return false;
        CloseHandle(handle_);
        handle_ = INVALID_HANDLE_VALUE;
        return true;
    }
    uint64_t Count() const { return count_; }

  private:
    bool WriteAll(const void* data, size_t size) {
        const auto* cursor = static_cast<const uint8_t*>(data);
        while (size) {
            const DWORD chunk = static_cast<DWORD>((std::min)(size, size_t{0xffffffffu}));
            DWORD wrote = 0;
            if (!WriteFile(handle_, cursor, chunk, &wrote, nullptr) || !wrote)
                return false;
            cursor += wrote;
            size -= wrote;
        }
        return true;
    }
    HANDLE handle_ = INVALID_HANDLE_VALUE;
    uint64_t count_ = 0;
    std::wstring path_;
};

bool MakeDefaultCandidatePath(std::wstring* output) {
    wchar_t temp[MAX_PATH]{};
    const DWORD length = GetTempPathW(MAX_PATH, temp);
    if (!output || !length || length >= MAX_PATH)
        return false;
    std::array<uint32_t, 4> token{};
    if (BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(token.data()), sizeof(token),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
        return false;
    wchar_t path[MAX_PATH]{};
    if (swprintf_s(path, L"%shdllib-candidates-%08x%08x%08x%08x.bin", temp, token[0], token[1],
                   token[2], token[3]) < 0)
        return false;
    *output = path;
    return true;
}

std::string BuildHitsJson(uint64_t session, bool have_session, uint64_t total,
                          const std::vector<uint64_t>& hits, const std::wstring& candidate_file) {
    JsonWriter writer;
    writer.BeginObject();
    if (have_session) {
        writer.Key("session");
        writer.HexStr(session);
    }
    writer.Key("total");
    writer.Num(total);
    if (!candidate_file.empty()) {
        writer.Key("candidate_file");
        writer.Str(candidate_file);
    }
    writer.Key("hits");
    writer.BeginArray();
    for (uint64_t hit : hits)
        writer.HexStr(hit);
    writer.EndArray();
    writer.EndObject();
    return writer.Take();
}

bool ParseValueType(const wchar_t* text, int32_t* output) {
    if (!text || !output)
        return false;
    struct Entry {
        const wchar_t* name;
        int32_t value;
    };
    static constexpr Entry entries[] = {
        {L"bytes", HDL_VALUE_BYTES},    {L"aob", HDL_VALUE_BYTES},  {L"i8", HDL_VALUE_I8},
        {L"u8", HDL_VALUE_U8},          {L"i16", HDL_VALUE_I16},    {L"u16", HDL_VALUE_U16},
        {L"i32", HDL_VALUE_I32},        {L"u32", HDL_VALUE_U32},    {L"i64", HDL_VALUE_I64},
        {L"u64", HDL_VALUE_U64},        {L"f32", HDL_VALUE_F32},    {L"float", HDL_VALUE_F32},
        {L"f64", HDL_VALUE_F64},        {L"double", HDL_VALUE_F64}, {L"string", HDL_VALUE_STRING},
        {L"wstring", HDL_VALUE_WSTRING}};
    for (const auto& entry : entries)
        if (_wcsicmp(text, entry.name) == 0) {
            *output = entry.value;
            return true;
        }
    return false;
}

bool ParseComparison(const wchar_t* text, hdl::rpc::v1::SearchComparison* output) {
    if (!text || !output)
        return false;
    struct Entry {
        const wchar_t* name;
        hdl::rpc::v1::SearchComparison value;
    };
    static constexpr Entry entries[] = {
        {L"exact", hdl::rpc::v1::SEARCH_COMPARISON_EXACT},
        {L"unknown", hdl::rpc::v1::SEARCH_COMPARISON_UNKNOWN},
        {L"changed", hdl::rpc::v1::SEARCH_COMPARISON_CHANGED},
        {L"unchanged", hdl::rpc::v1::SEARCH_COMPARISON_UNCHANGED},
        {L"increased", hdl::rpc::v1::SEARCH_COMPARISON_INCREASED},
        {L"decreased", hdl::rpc::v1::SEARCH_COMPARISON_DECREASED},
        {L"increased_by", hdl::rpc::v1::SEARCH_COMPARISON_INCREASED_BY},
        {L"decreased_by", hdl::rpc::v1::SEARCH_COMPARISON_DECREASED_BY},
        {L"greater", hdl::rpc::v1::SEARCH_COMPARISON_GREATER},
        {L"less", hdl::rpc::v1::SEARCH_COMPARISON_LESS}};
    for (const auto& entry : entries)
        if (_wcsicmp(text, entry.name) == 0) {
            *output = entry.value;
            return true;
        }
    return false;
}

bool SetSearchValue(int32_t type, std::wstring_view text, hdl::rpc::v1::SearchValue* output) {
    if (!output)
        return false;
    wchar_t* end = nullptr;
    const std::wstring owned(text);
    switch (type) {
    case HDL_VALUE_BYTES: {
        std::string value;
        if (!WideToUtf8(text, &value))
            return false;
        output->set_aob_pattern(std::move(value));
        return true;
    }
    case HDL_VALUE_STRING: {
        std::string value;
        if (!WideToUtf8(text, &value) || value.empty())
            return false;
        output->set_narrow_bytes(std::move(value));
        return true;
    }
    case HDL_VALUE_WSTRING: {
        std::string value;
        if (!WideToUtf8(text, &value) || value.empty())
            return false;
        output->set_wide_text(std::move(value));
        return true;
    }
    case HDL_VALUE_I8:
        output->set_signed_8(static_cast<int32_t>(_wcstoi64(owned.c_str(), &end, 0)));
        break;
    case HDL_VALUE_U8:
        output->set_unsigned_8(static_cast<uint32_t>(_wcstoui64(owned.c_str(), &end, 0)));
        break;
    case HDL_VALUE_I16:
        output->set_signed_16(static_cast<int32_t>(_wcstoi64(owned.c_str(), &end, 0)));
        break;
    case HDL_VALUE_U16:
        output->set_unsigned_16(static_cast<uint32_t>(_wcstoui64(owned.c_str(), &end, 0)));
        break;
    case HDL_VALUE_I32:
        output->set_signed_32(static_cast<int32_t>(_wcstoi64(owned.c_str(), &end, 0)));
        break;
    case HDL_VALUE_U32:
        output->set_unsigned_32(static_cast<uint32_t>(_wcstoui64(owned.c_str(), &end, 0)));
        break;
    case HDL_VALUE_I64:
        output->set_signed_64(_wcstoi64(owned.c_str(), &end, 0));
        break;
    case HDL_VALUE_U64:
        output->set_unsigned_64(_wcstoui64(owned.c_str(), &end, 0));
        break;
    case HDL_VALUE_F32:
        output->set_float_32(static_cast<float>(wcstod(owned.c_str(), &end)));
        break;
    case HDL_VALUE_F64:
        output->set_float_64(wcstod(owned.c_str(), &end));
        break;
    default:
        return false;
    }
    return end != owned.c_str() && *end == L'\0';
}

template <typename Response, typename Invoke>
bool CollectHits(uint32_t max_hits, const std::wstring& requested_file, Invoke&& invoke,
                 hdl::rpc::Status* status, uint64_t* total, std::vector<uint64_t>* hits,
                 std::wstring* candidate_file, bool* bad_file) {
    *bad_file = false;
    *total = 0;
    hits->clear();
    candidate_file->clear();
    CandidateFileWriter writer;
    CandidateFileWriter* file = nullptr;
    if (!requested_file.empty() || max_hits == 0) {
        *candidate_file = requested_file;
        if ((candidate_file->empty() && !MakeDefaultCandidatePath(candidate_file)) ||
            !writer.Open(*candidate_file)) {
            *bad_file = true;
            return false;
        }
        file = &writer;
    }
    bool write_failed = false;
    *status = invoke([&](const Response& batch) {
        std::vector<uint64_t> frame(batch.addresses().begin(), batch.addresses().end());
        if (file && !writer.Append(frame.data(), static_cast<uint32_t>(frame.size()))) {
            write_failed = true;
            return false;
        }
        for (uint64_t address : frame)
            if (!file || hits->size() < 64)
                hits->push_back(address);
        if (batch.has_total())
            *total = batch.total();
        return true;
    });
    if (write_failed || (file && !writer.Finish())) {
        *bad_file = true;
        return false;
    }
    if (!*total)
        *total = file ? writer.Count() : hits->size();
    return status->code() != hdl::rpc::v1::RPC_CODE_UNAVAILABLE;
}

hdl::rpc::CallOptions Options(uint32_t timeout_ms) {
    hdl::rpc::CallOptions value;
    value.timeout_ms = timeout_ms;
    return value;
}

CommandResult PrintScanHits(CmdCtx& ctx, uint64_t session, uint32_t max_hits,
                            const std::wstring& requested_file, uint32_t timeout_ms) {
    hdl::rpc::v1::SearchGetHitsRequest request;
    request.set_session_id(session);
    request.set_max_hits(max_hits);
    hdl::rpc::Status status;
    uint64_t total = 0;
    std::vector<uint64_t> hits;
    std::wstring file;
    bool bad_file = false;
    const bool ok = CollectHits<hdl::rpc::v1::SearchGetHitsResponse>(
        max_hits, requested_file,
        [&](auto callback) {
            return hdl::rpc::SearchClient(&ctx.client)
                .SearchGetHits(request, std::move(callback), Options(timeout_ms));
        },
        &status, &total, &hits, &file, &bad_file);
    if (!ok)
        return bad_file ? CmdFail(ctx.cmd.c_str(), HDL_E_ACCESS, L"Unable to write candidate file")
                        : FailIpc(ctx);
    return CmdStatus(ctx.cmd.c_str(), status.hdl_status(),
                     BuildHitsJson(session, true, total, hits, file));
}

} // namespace

CommandResult CmdScan(CmdCtx& ctx) {
    std::wstring pattern, value_text, module, candidate_file_request;
    bool have_pattern = false, have_value = false, have_comparison = false, have_session = false;
    bool do_next = false, do_hits = false, do_close = false, do_reset = false, unaligned = false;
    int32_t value_type = -1;
    auto comparison = hdl::rpc::v1::SEARCH_COMPARISON_EXACT;
    uint64_t start = 0, size = 0, session = 0;
    uint32_t timeout_ms = 0, max_hits = 0, search_flags = 0;
    for (int i = 3; i < ctx.argc; ++i) {
        if (wcscmp(ctx.argv[i], L"--pattern") == 0 && i + 1 < ctx.argc) {
            pattern = ctx.argv[++i];
            have_pattern = true;
            value_type = HDL_VALUE_BYTES;
        } else if (wcscmp(ctx.argv[i], L"--type") == 0 && i + 1 < ctx.argc) {
            if (!ParseValueType(ctx.argv[++i], &value_type))
                return FailArg(ctx, L"Unknown --type");
        } else if (wcscmp(ctx.argv[i], L"--value") == 0 && i + 1 < ctx.argc) {
            value_text = ctx.argv[++i];
            have_value = true;
        } else if (wcscmp(ctx.argv[i], L"--cmp") == 0 && i + 1 < ctx.argc) {
            if (!ParseComparison(ctx.argv[++i], &comparison))
                return FailArg(ctx, L"Unknown --cmp");
            have_comparison = true;
        } else if (wcscmp(ctx.argv[i], L"--start") == 0 && i + 1 < ctx.argc)
            ParseHexU64(ctx.argv[++i], &start);
        else if (wcscmp(ctx.argv[i], L"--size") == 0 && i + 1 < ctx.argc)
            ParseHexU64(ctx.argv[++i], &size);
        else if (wcscmp(ctx.argv[i], L"--max") == 0 && i + 1 < ctx.argc)
            max_hits = _wtoi(ctx.argv[++i]);
        else if (wcscmp(ctx.argv[i], L"--session") == 0 && i + 1 < ctx.argc) {
            session = _wcstoui64(ctx.argv[++i], nullptr, 0);
            have_session = true;
        } else if (wcscmp(ctx.argv[i], L"--timeout") == 0 && i + 1 < ctx.argc)
            timeout_ms = _wtoi(ctx.argv[++i]);
        else if (wcscmp(ctx.argv[i], L"--candidates") == 0 && i + 1 < ctx.argc)
            candidate_file_request = ctx.argv[++i];
        else if (wcscmp(ctx.argv[i], L"--module") == 0 && i + 1 < ctx.argc) {
            module = ctx.argv[++i];
            search_flags |= HDL_SEARCH_MODULE;
        } else if (wcscmp(ctx.argv[i], L"--image") == 0)
            search_flags |= HDL_SEARCH_IMAGE;
        else if (wcscmp(ctx.argv[i], L"--executable") == 0)
            search_flags |= HDL_SEARCH_EXECUTABLE;
        else if (wcscmp(ctx.argv[i], L"--next") == 0)
            do_next = true;
        else if (wcscmp(ctx.argv[i], L"--hits") == 0)
            do_hits = true;
        else if (wcscmp(ctx.argv[i], L"--close") == 0)
            do_close = true;
        else if (wcscmp(ctx.argv[i], L"--reset") == 0)
            do_reset = true;
        else if (wcscmp(ctx.argv[i], L"--unaligned") == 0)
            unaligned = true;
    }
    hdl::rpc::SearchClient client(&ctx.client);
    if (have_pattern && !do_next && !do_hits && !do_close && !do_reset && !have_session &&
        !have_comparison) {
        hdl::rpc::v1::SearchMemoryRequest request;
        request.set_aob_pattern(WideToUtf8(pattern));
        request.set_max_hits(max_hits);
        request.mutable_scope()->set_start(start);
        request.mutable_scope()->set_size(size);
        request.mutable_scope()->set_flags(search_flags);
        request.mutable_scope()->set_module(WideToUtf8(module));
        hdl::rpc::Status status;
        uint64_t total = 0;
        std::vector<uint64_t> hits;
        std::wstring file;
        bool bad_file = false;
        const bool ok = CollectHits<hdl::rpc::v1::SearchMemoryResponse>(
            max_hits, candidate_file_request,
            [&](auto callback) {
                return client.SearchMemory(request, std::move(callback), Options(timeout_ms));
            },
            &status, &total, &hits, &file, &bad_file);
        if (!ok)
            return bad_file
                       ? CmdFail(ctx.cmd.c_str(), HDL_E_ACCESS, L"Unable to write candidate file")
                       : FailIpc(ctx);
        return CmdStatus(ctx.cmd.c_str(), status.hdl_status(),
                         BuildHitsJson(0, false, total, hits, file));
    }
    if ((do_hits || do_close || do_reset || do_next) && !have_session)
        return FailArg(ctx, L"--session required");
    if (do_hits)
        return PrintScanHits(ctx, session, max_hits, candidate_file_request, timeout_ms);
    if (do_close || do_reset) {
        hdl::rpc::Result<hdl::rpc::v1::Empty> result;
        if (do_close) {
            hdl::rpc::v1::SearchCloseRequest request;
            request.set_session_id(session);
            result = client.SearchClose(request, Options(timeout_ms));
        } else {
            hdl::rpc::v1::SearchResetRequest request;
            request.set_session_id(session);
            result = client.SearchReset(request, Options(timeout_ms));
        }
        JsonWriter writer;
        writer.BeginObject();
        writer.Key("session");
        writer.HexStr(session);
        writer.EndObject();
        return CmdStatus(ctx.cmd.c_str(), result.status.hdl_status(), writer.Take());
    }
    if (do_next) {
        hdl::rpc::v1::SearchNextRequest request;
        request.set_session_id(session);
        request.set_comparison(comparison);
        if (have_value &&
            (value_type < 0 || !SetSearchValue(value_type, value_text, request.mutable_value())))
            return FailArg(ctx, value_type < 0 ? L"--type required with --value on --next"
                                               : L"Bad --value");
        const auto result = client.SearchNext(request, Options(timeout_ms));
        if (result.status.ok())
            return PrintScanHits(ctx, session, max_hits, candidate_file_request, timeout_ms);
        JsonWriter writer;
        writer.BeginObject();
        writer.Key("session");
        writer.HexStr(session);
        writer.Key("hits");
        writer.Num(result.has_response ? result.response.remaining_count() : 0);
        writer.EndObject();
        return CmdStatus(ctx.cmd.c_str(), result.status.hdl_status(), writer.Take());
    }
    if (value_type < 0)
        return FailArg(ctx, L"--type or --pattern required");
    if (comparison != hdl::rpc::v1::SEARCH_COMPARISON_UNKNOWN && !have_value &&
        value_type != HDL_VALUE_BYTES)
        return FailArg(ctx, L"--value required");
    if (value_type == HDL_VALUE_BYTES && !have_value && !have_pattern)
        return FailArg(ctx, L"--value/--pattern required for bytes");
    if (!have_session) {
        const auto created = client.SearchCreate(hdl::rpc::v1::Empty{}, Options(timeout_ms));
        if (!created.status.ok() || !created.has_response)
            return FailIpc(ctx);
        session = created.response.session_id();
        have_session = true;
    }
    hdl::rpc::v1::SearchFirstRequest request;
    request.set_session_id(session);
    request.set_comparison(comparison);
    request.set_alignment(unaligned ? hdl::rpc::v1::SEARCH_ALIGNMENT_BYTE
                                    : hdl::rpc::v1::SEARCH_ALIGNMENT_NATURAL);
    request.set_max_results(max_hits);
    request.mutable_scope()->set_start(start);
    request.mutable_scope()->set_size(size);
    request.mutable_scope()->set_flags(search_flags);
    request.mutable_scope()->set_module(WideToUtf8(module));
    const std::wstring_view chosen =
        have_value ? std::wstring_view(value_text) : std::wstring_view(pattern);
    if (!SetSearchValue(value_type, chosen, request.mutable_value()))
        return FailArg(ctx, L"Bad --value");
    hdl::rpc::Status status;
    uint64_t total = 0;
    std::vector<uint64_t> hits;
    std::wstring file;
    bool bad_file = false;
    const bool ok = CollectHits<hdl::rpc::v1::SearchFirstResponse>(
        max_hits, candidate_file_request,
        [&](auto callback) {
            return client.SearchFirst(request, std::move(callback), Options(timeout_ms));
        },
        &status, &total, &hits, &file, &bad_file);
    if (!ok)
        return bad_file ? CmdFail(ctx.cmd.c_str(), HDL_E_ACCESS, L"Unable to write candidate file")
                        : FailIpc(ctx);
    return CmdStatus(ctx.cmd.c_str(), status.hdl_status(),
                     BuildHitsJson(session, true, total, hits, file));
}
