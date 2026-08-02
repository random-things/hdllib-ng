#pragma once

#include "hdllib/hdllib.h"

#include <cstdint>
#include <string>

/* Typed CLI result: handlers never print; Render() chooses text vs JSON.
 * Handlers supply structured data_json only — human text is derived in Render(). */
struct CommandResult {
    int32_t status = HDL_OK;
    std::wstring cmd;
    std::string data_json; /* envelope "data" fragment; empty => {} */
    std::wstring hint;     /* optional extra error hint */
    bool print_usage = false;
    bool ok() const { return status == HDL_OK; }
    int exit_code() const { return status == HDL_OK ? 0 : 1; }
};

inline CommandResult CmdOk(const wchar_t* cmd, std::string data_json) {
    CommandResult r;
    r.status = HDL_OK;
    r.cmd = cmd ? cmd : L"";
    r.data_json = std::move(data_json);
    return r;
}

inline CommandResult CmdStatus(const wchar_t* cmd, int32_t status, std::string data_json) {
    CommandResult r;
    r.status = status;
    r.cmd = cmd ? cmd : L"";
    r.data_json = std::move(data_json);
    return r;
}

inline CommandResult CmdFail(const wchar_t* cmd, int32_t status, const wchar_t* hint) {
    CommandResult r;
    r.status = status;
    r.cmd = cmd ? cmd : L"";
    r.hint = hint ? hint : L"";
    return r;
}

inline CommandResult CmdFailUsage(const wchar_t* cmd) {
    CommandResult r;
    r.status = HDL_E_INVALID_ARG;
    r.cmd = cmd ? cmd : L"";
    r.hint = L"missing or invalid arguments";
    r.print_usage = true;
    return r;
}
