#pragma once

#include "pipe_client.hpp"

#include <cstdint>
#include <string>
#include <vector>

const wchar_t* StatusName(int32_t st);
/* One-line English hint for cmd+status, or nullptr if none. */
const wchar_t* StatusHint(const std::wstring& cmd, int32_t status);
bool ParseHexBytes(const wchar_t* text, std::vector<uint8_t>& out);
bool ParseHexU64(const wchar_t* s, uint64_t* out);
int FailConnect(uint32_t pid);

/* UTF-8 <-> UTF-16 without fixed-buffer truncation. */
std::string WideToUtf8(const std::wstring& w);
std::wstring Utf8ToWide(const std::string& s);

/*
 * Read one line from stdin as UTF-16.
 * Console: ReadConsoleW. Pipe/file: UTF-8 bytes until LF (keeps scripted REPL tests working).
 * Returns false on EOF with no content.
 */
bool ReadLineWide(std::wstring* out);

/* Wait until the user presses Enter (console or pipe). Returns false on EOF/cancel. */
bool WaitEnterWide();
