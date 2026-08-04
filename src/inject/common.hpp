#pragma once

#include "hdllib/hdllib.h"
#include "log.hpp"

#define WIN32_LEAN_AND_MEAN
#include <TlHelp32.h>
#include <Windows.h>

#include <string>
#include <vector>

namespace hdl {
namespace inject {

#ifndef NTSTATUS
using NTSTATUS = LONG;
#endif

#ifndef NTAPI
#define NTAPI __stdcall
#endif

struct RemoteAlloc {
    HANDLE process = nullptr;
    void* ptr = nullptr;
    SIZE_T size = 0;

    ~RemoteAlloc() { Free(); }

    void Free();
    bool Alloc(HANDLE proc, SIZE_T bytes, DWORD protect = PAGE_READWRITE);
    bool Write(const void* data, SIZE_T bytes) const;
    void* Detach();
};

std::wstring NormalizePath(const wchar_t* path);
bool PathsEqual(const wchar_t* a, const wchar_t* b);
bool PathEndsWithFile(const wchar_t* full, const wchar_t* file);

uint64_t FindModuleBaseByPath(DWORD pid, const wchar_t* dll_path);
HANDLE OpenTargetProcess(DWORD pid, DWORD extra = 0);
FARPROC GetLoadedModuleProc(const wchar_t* module_name, const char* proc_name);
FARPROC GetKernel32Proc(const char* name);
std::vector<DWORD> EnumProcessThreads(DWORD pid);

HdlStatus WriteRemotePath(HANDLE process, const wchar_t* dll_path, RemoteAlloc& remote);
HdlStatus WaitThreadAndBase(HANDLE thread, DWORD pid, const wchar_t* dll_path, uint64_t* out_base);

// Poll until the DLL appears in the module list (or timeout).
HdlStatus PollForModule(DWORD pid, const wchar_t* dll_path, uint64_t* out_base, int attempts = 50,
                        DWORD sleep_ms = 100);

// Poll until the DLL disappears from the module list (or timeout).
HdlStatus PollForModuleGone(DWORD pid, const wchar_t* dll_path, int attempts = 50,
                            DWORD sleep_ms = 100);

bool ReadRemote(HANDLE process, const void* addr, void* buf, size_t n);
bool WriteRemote(HANDLE process, void* addr, const void* buf, size_t n);

HWND FindWindowForPid(DWORD pid);

// Match top-level windows by optional title substring and/or class (case-insensitive).
// If pid != 0, only windows owned by that process are considered.
// On success with a unique match: *out_hwnd and *out_pid set, returns HDL_OK.
// Multiple matches: *out_count set when non-null, returns HDL_E_BUSY.
// No matches: HDL_E_NOT_FOUND.
HdlStatus FindWindowByTitleClass(DWORD pid, const wchar_t* title_substr_or_null,
                                 const wchar_t* class_name_or_null, HWND* out_hwnd,
                                 uint32_t* out_pid, uint32_t* out_count);

using NtQueueApcThread_t = NTSTATUS(NTAPI*)(HANDLE ThreadHandle, PVOID ApcRoutine, PVOID Arg1,
                                            PVOID Arg2, PVOID Arg3);

NtQueueApcThread_t GetNtQueueApcThread();

// Queue GlobalGetAtomNameW APC to write a global atom's contents to remote dest (cch includes room
// for NUL).
HdlStatus AtomWriteW(HANDLE thread, ATOM atom, void* remote_dest, ULONG cch);

// Write arbitrary bytes using NtQueueApcThread(memset, dst, byte, 1) — no WriteProcessMemory.
HdlStatus ApcMemsetWrite(HANDLE thread, void* remote_dest, const void* data, size_t size);

// Open a thread suitable for APC queueing; prefers suspended-capable workers.
HANDLE OpenApcThread(DWORD pid,
                     DWORD desired_access = THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION);

// x64: LoadLibraryW(path); ret
#pragma pack(push, 1)
struct X64LoadLibraryStub {
    uint8_t sub_rsp[4] = {0x48, 0x83, 0xEC, 0x28};
    uint8_t mov_rcx[2] = {0x48, 0xB9};
    uint64_t path = 0;
    uint8_t mov_rax[2] = {0x48, 0xB8};
    uint64_t loadlib = 0;
    uint8_t call_rax[2] = {0xFF, 0xD0};
    uint8_t add_rsp[4] = {0x48, 0x83, 0xC4, 0x28};
    uint8_t ret[1] = {0xC3};
};
#pragma pack(pop)

// Allocate remote path + RWX LoadLibrary stub. Detach both on success (caller owns).
HdlStatus AllocLoadLibraryStub(HANDLE process, const wchar_t* dll_path, RemoteAlloc& path_mem,
                               RemoteAlloc& stub_mem);

// Mark a remote executable address as a valid CFG call target (best-effort).
void RegisterCfgCallTarget(HANDLE process, void* stub);

} // namespace inject
} // namespace hdl
