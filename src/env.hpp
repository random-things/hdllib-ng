#pragma once

namespace hdl {

// True for 1 / true / yes / on (case-insensitive). Missing => false.
bool EnvFlag(const wchar_t* name);

// Parse HDL_* int env; returns default_value when unset or invalid.
int EnvInt(const wchar_t* name, int default_value);

// Log off unless HDL_LOG_LEVEL is set (0..3); honor an optional HDL_LOG_FILE path.
void ApplyQuietLogDefaults();

} // namespace hdl
