#include "json_out.hpp"
#include "usage.hpp"
#include "util.hpp"

#include <cstdio>
#include <string>
#include <utility>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

void JsonWriter::Str(const wchar_t* s) {
    hdl::json::Writer::Str(WideToUtf8(s ? s : L""));
}

void JsonWriter::Str(const std::wstring& s) {
    hdl::json::Writer::Str(WideToUtf8(s));
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

/* Derive human text from structured data_json (handlers no longer pre-format text). */
static void AppendUtf8AsWide(std::wstring* out, const std::string& utf8) {
    if (!out) {
        return;
    }
    *out += Utf8ToWide(utf8);
}

/* CLI historically prints JSON booleans as 1/0 (e.g. enabled=1). */
static std::string HumanScalar(const std::string& v) {
    if (v == "true") {
        return "1";
    }
    if (v == "false") {
        return "0";
    }
    return v;
}

static void AppendFieldKv(std::wstring* out, const std::string& key, const std::string& val) {
    AppendUtf8AsWide(out, key);
    out->push_back(L'=');
    AppendUtf8AsWide(out, HumanScalar(val));
}

static std::wstring FormatHumanFromData(int32_t status, const std::string& data_json) {
    wchar_t hdr[64];
    swprintf_s(hdr, L"status=%ls", StatusName(status));
    std::wstring out = hdr;

    const std::string& raw = data_json.empty() ? std::string("{}") : data_json;
    std::vector<std::pair<std::string, std::string>> fields;
    if (!hdl::json::ParseObjectFields(raw, &fields) || fields.empty()) {
        out.push_back(L'\n');
        return out;
    }

    std::vector<std::pair<std::string, std::string>> scalars;
    std::vector<std::pair<std::string, std::string>> arrays;
    std::vector<std::pair<std::string, std::string>> objects;
    for (auto& f : fields) {
        if (!f.second.empty() && f.second[0] == '[') {
            arrays.push_back(std::move(f));
        } else if (!f.second.empty() && f.second[0] == '{') {
            objects.push_back(std::move(f));
        } else {
            scalars.push_back(std::move(f));
        }
    }

    for (const auto& s : scalars) {
        out.push_back(L' ');
        AppendFieldKv(&out, s.first, s.second);
    }
    out.push_back(L'\n');

    for (const auto& a : arrays) {
        std::vector<std::string> elems;
        if (!hdl::json::ParseArrayElements(a.second, &elems)) {
            continue;
        }
        for (const auto& e : elems) {
            out += L"  ";
            if (!e.empty() && e[0] == '{') {
                std::vector<std::pair<std::string, std::string>> nested;
                if (hdl::json::ParseObjectFields(e, &nested)) {
                    bool first = true;
                    for (const auto& nf : nested) {
                        if (!first) {
                            out.push_back(L' ');
                        }
                        first = false;
                        AppendFieldKv(&out, nf.first, nf.second);
                    }
                } else {
                    AppendUtf8AsWide(&out, e);
                }
            } else {
                AppendUtf8AsWide(&out, HumanScalar(e));
            }
            out.push_back(L'\n');
        }
    }
    for (const auto& o : objects) {
        out += L"  ";
        AppendFieldKv(&out, o.first, o.second);
        out.push_back(L'\n');
    }
    return out;
}

int Render(const CmdCtx& ctx, const CommandResult& result) {
    if (ctx.json) {
        if (!result.ok() && result.data_json.empty()) {
            EmitError(ctx, result.status, result.cmd.c_str(),
                      result.hint.empty() ? nullptr : result.hint.c_str());
        } else {
            EmitEnvelope(ctx, result.status, result.cmd.c_str(), result.data_json);
        }
        return result.exit_code();
    }
    if (result.print_usage) {
        PrintUsage();
        return 1;
    }
    if (!result.ok() && result.data_json.empty()) {
        if (!result.hint.empty()) {
            wprintf(L"%ls\n", result.hint.c_str());
        } else {
            wprintf(L"status=%ls\n", StatusName(result.status));
            PrintStatusHint(result.cmd, result.status);
        }
        return result.exit_code();
    }
    const std::wstring text = FormatHumanFromData(result.status, result.data_json);
    fputws(text.c_str(), stdout);
    if (!result.ok()) {
        if (!result.hint.empty()) {
            wprintf(L"  hint: %ls\n", result.hint.c_str());
        } else {
            PrintStatusHint(result.cmd, result.status);
        }
    }
    return result.exit_code();
}
