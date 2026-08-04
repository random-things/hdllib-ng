#pragma once

#include "support.hpp"

#include "hdllib/hdllib.h"

#include <cstdint>

void RunLocalApiTests(hdltest::Counters& c, const wchar_t* dll_path, bool include_ui_thread_test,
                      bool include_process_region_scan_test);
void RunLocateTargetTests(hdltest::Counters& c, const wchar_t* target_path,
                          const wchar_t* dll_path);
void RunDiscoverTargetTests(hdltest::Counters& c, const wchar_t* target_path,
                            const wchar_t* dll_path);
void RunLifecycleStressTests(hdltest::Counters& c, const wchar_t* target_exe,
                             const wchar_t* dll_path);
void RunCleanUnloadTests(hdltest::Counters& c, const wchar_t* target_exe, const wchar_t* dll_path);
void RunInjectMatrix(hdltest::Counters& c, const wchar_t* target_exe, const wchar_t* dll_path);

void EvaluateInject(hdltest::Counters& c, const char* case_name, hdltest::Expect expect,
                    HdlStatus st, bool verified);
HdlStatus InjectSealed(uint32_t pid, const wchar_t* dll_path, int method, const wchar_t* exe,
                       const char* hook_export, uint32_t* out_pid, uint64_t* out_base);

std::wstring PreparePayloadDll(const std::wstring& built_dll);
