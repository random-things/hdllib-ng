#include "inject/common.hpp"
#include "inject/techniques.hpp"
#include "win/raii.hpp"

#include <cstring>

namespace hdl {
namespace inject {
namespace {

// Sacrificial modules commonly present / safely loadable for stomping.
const wchar_t* kStompCandidates[] = {
    L"cryptbase.dll",
    L"dpapi.dll",
    L"profapi.dll",
};

uint64_t ModuleEntryPoint(HANDLE process, HMODULE mod) {
    uint8_t headers[0x1000]{};
    if (!ReadRemote(process, mod, headers, sizeof(headers))) {
        return 0;
    }
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(headers);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return 0;
    }
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(headers + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return 0;
    }
    return reinterpret_cast<uint64_t>(mod) + nt->OptionalHeader.AddressOfEntryPoint;
}

HMODULE FindOrLoadSacrifice(HANDLE process, DWORD pid) {
    for (const wchar_t* name : kStompCandidates) {
        win::unique_handle snap(
            CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid));
        if (snap) {
            MODULEENTRY32W me{};
            me.dwSize = sizeof(me);
            if (Module32FirstW(snap.get(), &me)) {
                do {
                    if (_wcsicmp(me.szModule, name) == 0) {
                        return me.hModule;
                    }
                } while (Module32NextW(snap.get(), &me));
            }
        }
    }

    // Load cryptbase into the target. Do not use GetExitCodeThread for the HMODULE —
    // on x64 module bases do not fit in a DWORD.
    RemoteAlloc name_mem;
    const char* narrow = "cryptbase.dll";
    const size_t n = strlen(narrow) + 1;
    if (!name_mem.Alloc(process, n) || !name_mem.Write(narrow, n)) {
        return nullptr;
    }
    auto load_a = reinterpret_cast<LPTHREAD_START_ROUTINE>(GetKernel32Proc("LoadLibraryA"));
    win::unique_handle t(
        ::CreateRemoteThread(process, nullptr, 0, load_a, name_mem.ptr, 0, nullptr));
    if (!t) {
        return nullptr;
    }
    WaitForSingleObject(t.get(), INFINITE);
    t.reset();

    win::unique_handle snap(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid));
    if (!snap) {
        return nullptr;
    }
    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    HMODULE found = nullptr;
    if (Module32FirstW(snap.get(), &me)) {
        do {
            if (_wcsicmp(me.szModule, L"cryptbase.dll") == 0) {
                found = me.hModule;
                break;
            }
        } while (Module32NextW(snap.get(), &me));
    }
    return found;
}

} // namespace

HdlStatus ModuleStompMethod(uint32_t pid, const wchar_t* dll_path, uint64_t* out_base) {
    win::unique_handle process(OpenTargetProcess(pid));
    if (!process) {
        return HDL_E_ACCESS;
    }

    HMODULE sacrifice = FindOrLoadSacrifice(process.get(), pid);
    if (!sacrifice) {
        HDL_LOG_ERROR("ModuleStomp: failed to locate/load sacrificial DLL");
        return HDL_E_FAILED;
    }

    const uint64_t entry = ModuleEntryPoint(process.get(), sacrifice);
    if (!entry) {
        return HDL_E_FAILED;
    }

    RemoteAlloc path_mem;
    RemoteAlloc stub_mem;
    // Build stub in scratch, then copy onto the sacrificial entry point.
    HdlStatus st = AllocLoadLibraryStub(process.get(), dll_path, path_mem, stub_mem);
    if (st != HDL_OK) {
        return st;
    }

    X64LoadLibraryStub stub{};
    if (!ReadRemote(process.get(), stub_mem.ptr, &stub, sizeof(stub))) {
        return HDL_E_FAILED;
    }

    DWORD old_prot = 0;
    if (!VirtualProtectEx(process.get(), reinterpret_cast<void*>(entry), sizeof(stub),
                          PAGE_EXECUTE_READWRITE, &old_prot)) {
        return HDL_E_ACCESS;
    }
    if (!WriteRemote(process.get(), reinterpret_cast<void*>(entry), &stub, sizeof(stub))) {
        return HDL_E_FAILED;
    }

    win::unique_handle thread(::CreateRemoteThread(process.get(), nullptr, 0,
                                                   reinterpret_cast<LPTHREAD_START_ROUTINE>(entry),
                                                   nullptr, 0, nullptr));
    if (!thread) {
        HDL_LOG_ERROR("ModuleStomp CreateRemoteThread failed: %lu", GetLastError());
        return HDL_E_FAILED;
    }
    WaitForSingleObject(thread.get(), INFINITE);
    thread.reset();

    VirtualProtectEx(process.get(), reinterpret_cast<void*>(entry), sizeof(stub), old_prot,
                     &old_prot);

    st = PollForModule(pid, dll_path, out_base);
    path_mem.Detach();
    stub_mem.Detach();

    if (st == HDL_OK) {
        HDL_LOG_INFO("ModuleStomp inject into pid %u ok (stomped %p)", pid, sacrifice);
    }
    return st;
}

} // namespace inject
} // namespace hdl
