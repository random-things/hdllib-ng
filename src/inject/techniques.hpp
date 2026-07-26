#pragma once

#include "hdllib/hdllib.h"

#include <cstdint>

namespace hdl {
namespace inject {

HdlStatus Local(const wchar_t* dll_path, uint64_t* out_base);

HdlStatus UnloadLocal(const wchar_t* dll_path, int reload, uint64_t* out_base);
HdlStatus UnloadRemote(uint32_t pid, const wchar_t* dll_path, int reload, uint64_t* out_base);

HdlStatus CreateRemoteThreadMethod(uint32_t pid, const wchar_t* dll_path, uint64_t* out_base);
HdlStatus NtCreateThreadExMethod(uint32_t pid, const wchar_t* dll_path, uint64_t* out_base);
HdlStatus RtlCreateUserThreadMethod(uint32_t pid, const wchar_t* dll_path, uint64_t* out_base);
HdlStatus QueueUserApcMethod(uint32_t pid, const wchar_t* dll_path, uint64_t* out_base);
HdlStatus SetWindowsHookExMethod(uint32_t pid, const wchar_t* dll_path, const char* hook_export,
                                 uint64_t* out_base);
HdlStatus ThreadHijackMethod(uint32_t pid, const wchar_t* dll_path, uint64_t* out_base);
HdlStatus ManualMapMethod(uint32_t pid, const wchar_t* dll_path, uint64_t* out_base);
HdlStatus EarlyBirdApcMethod(const wchar_t* exe_path, const wchar_t* dll_path, uint32_t* out_pid,
                             uint64_t* out_base);

HdlStatus AtomBombingMethod(uint32_t pid, const wchar_t* dll_path, uint64_t* out_base);
HdlStatus ModuleStompMethod(uint32_t pid, const wchar_t* dll_path, uint64_t* out_base);
HdlStatus SectionMapMethod(uint32_t pid, const wchar_t* dll_path, uint64_t* out_base);
HdlStatus WindowSubclassMethod(uint32_t pid, const wchar_t* dll_path, uint64_t* out_base);
HdlStatus InstrumentationCallbackMethod(uint32_t pid, const wchar_t* dll_path, uint64_t* out_base);
HdlStatus KernelCallbackTableMethod(uint32_t pid, const wchar_t* dll_path, uint64_t* out_base);
HdlStatus VehMethod(uint32_t pid, const wchar_t* dll_path, uint64_t* out_base);

HdlStatus SetWinEventHookMethod(uint32_t pid, const wchar_t* dll_path, const char* hook_export,
                                uint64_t* out_base);
HdlStatus RtlRemoteCallMethod(uint32_t pid, const wchar_t* dll_path, uint64_t* out_base);
HdlStatus SpecialUserApcMethod(uint32_t pid, const wchar_t* dll_path, uint64_t* out_base);
HdlStatus ThreadPoolMethod(uint32_t pid, const wchar_t* dll_path, uint64_t* out_base);
HdlStatus EtwCallbackMethod(uint32_t pid, const wchar_t* dll_path, uint64_t* out_base);

}  // namespace inject
}  // namespace hdl
