#pragma once

#include "cmd.hpp"

#include <cstdint>
#include <string>

namespace hdlcli {

/* Sidecar next to --store (PATH.session) or %TEMP%\hdl_session_<pid>.txt when no store. */
std::wstring SessionSidecarPath(uint32_t pid, const wchar_t* store_path_or_null);

bool ReadPersistedSession(uint32_t pid, const wchar_t* store_path_or_null, uint64_t* out_id);
bool WritePersistedSession(uint32_t pid, const wchar_t* store_path_or_null, uint64_t id);
bool ClearPersistedSession(uint32_t pid, const wchar_t* store_path_or_null);

/*
 * Resolve discover session ID:
 *   1) explicit --session on argv (ctx.argv)
 *   2) HDL_SESSION env
 *   3) sidecar file for pid / --store
 * Returns 0 if none found.
 */
uint64_t ResolveSessionId(const CmdCtx& ctx);

/* Persist id to sidecar (and leave server session open). Returns false on write failure. */
bool PersistSessionId(const CmdCtx& ctx, uint64_t id);

} // namespace hdlcli
