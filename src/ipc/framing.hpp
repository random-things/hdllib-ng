#pragma once

#include <cstdint>
#include <string>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

namespace hdl {
namespace ipc {

std::wstring PipeName();
SECURITY_ATTRIBUTES* BuildPipeSa(std::vector<uint8_t>& sd_storage);

bool ReadExact(HANDLE pipe, void* buf, DWORD size);
bool WriteExact(HANDLE pipe, const void* buf, DWORD size);

bool ReadFrame(HANDLE pipe, std::vector<uint8_t>& out, bool* frame_too_large = nullptr);
bool WriteFrameBytes(HANDLE pipe, const void* data, uint32_t size);

} // namespace ipc
} // namespace hdl
