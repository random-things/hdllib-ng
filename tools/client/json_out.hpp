#pragma once

#include "cmd.hpp"
#include "command_result.hpp"
#include "json/json.hpp"

#include <cstdint>
#include <string>

/* CLI JsonWriter: shared hdl::json::Writer plus wide-string helpers. */
class JsonWriter : public hdl::json::Writer {
  public:
    using hdl::json::Writer::Str;
    void Str(const wchar_t* s);
    void Str(const std::wstring& s);
};

void EmitEnvelope(const CmdCtx& ctx, int32_t status, const wchar_t* cmd,
                  const std::string& data_json);
void EmitError(const CmdCtx& ctx, int32_t status, const wchar_t* cmd,
               const wchar_t* extra_hint_or_null);

/* Text-mode: print "  hint: ..." after a failing status line when a hint exists. */
void PrintStatusHint(const std::wstring& cmd, int32_t status);

/* Edge renderer: JSON envelope or human text from a typed CommandResult. */
int Render(const CmdCtx& ctx, const CommandResult& result);
