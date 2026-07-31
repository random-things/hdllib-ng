#pragma once

#include "cmd.hpp"

#include <cstdint>
#include <string>
#include <vector>

/* Lightweight JSON builder for --json CLI envelopes. Addresses/ids as "0x..." strings. */
class JsonWriter {
public:
    void BeginObject();
    void EndObject();
    void BeginArray();
    void EndArray();
    void Key(const char* k);
    void Str(const char* s);
    void Str(const wchar_t* s);
    void Str(const std::string& s);
    void Str(const std::wstring& s);
    void Num(int64_t v);
    void Num(uint64_t v);
    void Num(uint32_t v);
    void Num(int32_t v);
    void Bool(bool v);
    void Null();
    void HexStr(uint64_t v);
    void Raw(const std::string& json_fragment);
    std::string Take();

private:
    std::string buf_;
    std::vector<bool> need_comma_; /* per nesting level */
    bool expecting_value_ = true;

    void CommaIfNeeded();
    void AppendEscaped(const char* s, size_t n);
};

void EmitEnvelope(const CmdCtx& ctx, int32_t status, const wchar_t* cmd,
                  const std::string& data_json);
void EmitError(const CmdCtx& ctx, int32_t status, const wchar_t* cmd,
               const wchar_t* extra_hint_or_null);

/* Text-mode: print "  hint: ..." after a failing status line when a hint exists. */
void PrintStatusHint(const std::wstring& cmd, int32_t status);
