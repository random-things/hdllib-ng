#include "json_out.hpp"
#include "util.hpp"

#include <cstdio>
#include <cstring>
#include <string>

void JsonWriter::CommaIfNeeded() {
    if (need_comma_.empty()) {
        return;
    }
    if (!expecting_value_ && need_comma_.back()) {
        buf_.push_back(',');
    }
    expecting_value_ = false;
    need_comma_.back() = true;
}

void JsonWriter::AppendEscaped(const char* s, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        switch (c) {
        case '"':
            buf_ += "\\\"";
            break;
        case '\\':
            buf_ += "\\\\";
            break;
        case '\b':
            buf_ += "\\b";
            break;
        case '\f':
            buf_ += "\\f";
            break;
        case '\n':
            buf_ += "\\n";
            break;
        case '\r':
            buf_ += "\\r";
            break;
        case '\t':
            buf_ += "\\t";
            break;
        default:
            if (c < 0x20) {
                char tmp[8];
                snprintf(tmp, sizeof(tmp), "\\u%04x", c);
                buf_ += tmp;
            } else {
                buf_.push_back(static_cast<char>(c));
            }
            break;
        }
    }
}

void JsonWriter::BeginObject() {
    CommaIfNeeded();
    buf_.push_back('{');
    need_comma_.push_back(false);
    expecting_value_ = true;
}

void JsonWriter::EndObject() {
    if (!need_comma_.empty()) {
        need_comma_.pop_back();
    }
    buf_.push_back('}');
    expecting_value_ = false;
    if (!need_comma_.empty()) {
        need_comma_.back() = true;
    }
}

void JsonWriter::BeginArray() {
    CommaIfNeeded();
    buf_.push_back('[');
    need_comma_.push_back(false);
    expecting_value_ = true;
}

void JsonWriter::EndArray() {
    if (!need_comma_.empty()) {
        need_comma_.pop_back();
    }
    buf_.push_back(']');
    expecting_value_ = false;
    if (!need_comma_.empty()) {
        need_comma_.back() = true;
    }
}

void JsonWriter::Key(const char* k) {
    CommaIfNeeded();
    buf_.push_back('"');
    AppendEscaped(k, strlen(k));
    buf_ += "\":";
    expecting_value_ = true;
    if (!need_comma_.empty()) {
        need_comma_.back() = false;
    }
}

void JsonWriter::Str(const char* s) {
    CommaIfNeeded();
    buf_.push_back('"');
    if (s) {
        AppendEscaped(s, strlen(s));
    }
    buf_.push_back('"');
}

void JsonWriter::Str(const wchar_t* s) {
    Str(WideToUtf8(s ? s : L""));
}

void JsonWriter::Str(const std::string& s) {
    CommaIfNeeded();
    buf_.push_back('"');
    AppendEscaped(s.data(), s.size());
    buf_.push_back('"');
}

void JsonWriter::Str(const std::wstring& s) {
    Str(WideToUtf8(s));
}

void JsonWriter::Num(int64_t v) {
    CommaIfNeeded();
    char tmp[32];
    snprintf(tmp, sizeof(tmp), "%lld", static_cast<long long>(v));
    buf_ += tmp;
}

void JsonWriter::Num(uint64_t v) {
    CommaIfNeeded();
    char tmp[32];
    snprintf(tmp, sizeof(tmp), "%llu", static_cast<unsigned long long>(v));
    buf_ += tmp;
}

void JsonWriter::Num(uint32_t v) {
    Num(static_cast<uint64_t>(v));
}

void JsonWriter::Num(int32_t v) {
    Num(static_cast<int64_t>(v));
}

void JsonWriter::Bool(bool v) {
    CommaIfNeeded();
    buf_ += v ? "true" : "false";
}

void JsonWriter::Null() {
    CommaIfNeeded();
    buf_ += "null";
}

void JsonWriter::HexStr(uint64_t v) {
    char tmp[24];
    snprintf(tmp, sizeof(tmp), "0x%llx", static_cast<unsigned long long>(v));
    Str(tmp);
}

void JsonWriter::Raw(const std::string& json_fragment) {
    CommaIfNeeded();
    buf_ += json_fragment;
}

std::string JsonWriter::Take() {
    std::string out = std::move(buf_);
    buf_.clear();
    need_comma_.clear();
    expecting_value_ = true;
    return out;
}

static void WriteUtf8Line(const std::string& utf8) {
    const HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (h && h != INVALID_HANDLE_VALUE && GetFileType(h) == FILE_TYPE_CHAR) {
        const std::wstring w = Utf8ToWide(utf8);
        DWORD wrote = 0;
        WriteConsoleW(h, w.c_str(), static_cast<DWORD>(w.size()), &wrote, nullptr);
        WriteConsoleW(h, L"\n", 1, &wrote, nullptr);
    } else {
        fwrite(utf8.data(), 1, utf8.size(), stdout);
        fputc('\n', stdout);
    }
    fflush(stdout);
}

void EmitEnvelope(const CmdCtx& ctx, int32_t status, const wchar_t* cmd,
                  const std::string& data_json) {
    (void)ctx;
    JsonWriter w;
    w.BeginObject();
    w.Key("ok");
    w.Bool(status == HDL_OK);
    w.Key("status");
    w.Num(status);
    w.Key("cmd");
    w.Str(cmd ? cmd : L"");
    w.Key("data");
    if (data_json.empty()) {
        w.BeginObject();
        w.EndObject();
    } else {
        w.Raw(data_json);
    }
    w.Key("error");
    if (status == HDL_OK) {
        w.Null();
    } else {
        w.BeginObject();
        w.Key("code");
        w.Num(status);
        w.Key("name");
        w.Str(StatusName(status));
        const wchar_t* hint = StatusHint(cmd ? cmd : L"", status);
        w.Key("hint");
        if (hint) {
            w.Str(hint);
        } else {
            w.Str("");
        }
        w.EndObject();
    }
    w.EndObject();
    WriteUtf8Line(w.Take());
}

void EmitError(const CmdCtx& ctx, int32_t status, const wchar_t* cmd,
               const wchar_t* extra_hint_or_null) {
    JsonWriter data;
    data.BeginObject();
    data.EndObject();
    if (!ctx.json) {
        wprintf(L"status=%ls\n", StatusName(status));
        if (extra_hint_or_null && extra_hint_or_null[0]) {
            wprintf(L"  hint: %ls\n", extra_hint_or_null);
        } else {
            PrintStatusHint(cmd ? cmd : L"", status);
        }
        return;
    }
    JsonWriter w;
    w.BeginObject();
    w.Key("ok");
    w.Bool(false);
    w.Key("status");
    w.Num(status);
    w.Key("cmd");
    w.Str(cmd ? cmd : L"");
    w.Key("data");
    w.Raw(data.Take());
    w.Key("error");
    w.BeginObject();
    w.Key("code");
    w.Num(status);
    w.Key("name");
    w.Str(StatusName(status));
    w.Key("hint");
    if (extra_hint_or_null && extra_hint_or_null[0]) {
        w.Str(extra_hint_or_null);
    } else {
        const wchar_t* hint = StatusHint(cmd ? cmd : L"", status);
        w.Str(hint ? hint : L"");
    }
    w.EndObject();
    w.EndObject();
    WriteUtf8Line(w.Take());
}

void PrintStatusHint(const std::wstring& cmd, int32_t status) {
    if (status == HDL_OK) {
        return;
    }
    const wchar_t* hint = StatusHint(cmd, status);
    if (hint && hint[0]) {
        wprintf(L"  hint: %ls\n", hint);
    }
}
