#include "call.hpp"

#include "call_dispatch.hpp"
#include "call_registry.hpp"

#include <cstring>
#include <memory>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

extern "C" uint64_t HdlInvokeX64(void* fn, const uint64_t* gpr, const uint64_t* xmm,
                                 const uint64_t* stack_args, uint32_t stack_count);

namespace hdl {
namespace {

constexpr uint32_t kMaxArgs = 16;
constexpr size_t kMaxBufArg = 1u * 1024u * 1024u;

struct PreparedArg {
    uint64_t value = 0;
    bool is_float = false;
    std::vector<uint8_t> owned;
};

struct CallWork {
    std::shared_ptr<CallRecord> record;
    void* fn = nullptr;
    uint64_t gpr[4]{};
    uint64_t xmm[4]{};
    std::vector<uint64_t> stack;
    uint64_t result = 0;
    DWORD last_error = 0;
    HdlStatus status = HDL_OK;
    std::vector<PreparedArg> prepared;
};

HMODULE ResolveModule(const wchar_t* module_or_null) {
    if (!module_or_null || !module_or_null[0]) {
        return GetModuleHandleW(nullptr);
    }
    HMODULE module = GetModuleHandleW(module_or_null);
    return module ? module : LoadLibraryW(module_or_null);
}

bool PrepareArgs(const HdlCallArg* args, uint32_t arg_count, std::vector<PreparedArg>* out) {
    out->clear();
    out->resize(arg_count);
    for (uint32_t index = 0; index < arg_count; ++index) {
        const HdlCallArg& argument = args[index];
        PreparedArg& prepared = (*out)[index];
        switch (argument.kind) {
        case HDL_CALL_ARG_U64:
        case HDL_CALL_ARG_I64:
            prepared.value = argument.u64;
            break;
        case HDL_CALL_ARG_F32:
            prepared.value = argument.u64 & 0xffffffffull;
            prepared.is_float = true;
            break;
        case HDL_CALL_ARG_F64:
            prepared.value = argument.u64;
            prepared.is_float = true;
            break;
        case HDL_CALL_ARG_PTR:
            prepared.value = reinterpret_cast<uint64_t>(argument.ptr);
            break;
        case HDL_CALL_ARG_BUF:
            if (!argument.ptr || !argument.size || argument.size > kMaxBufArg) {
                return false;
            }
            prepared.owned.assign(static_cast<const uint8_t*>(argument.ptr),
                                  static_cast<const uint8_t*>(argument.ptr) + argument.size);
            prepared.value = reinterpret_cast<uint64_t>(prepared.owned.data());
            break;
        case HDL_CALL_ARG_CSTR: {
            if (!argument.ptr) {
                return false;
            }
            const char* value = static_cast<const char*>(argument.ptr);
            const size_t size = strlen(value) + 1;
            if (size > kMaxBufArg) {
                return false;
            }
            prepared.owned.assign(reinterpret_cast<const uint8_t*>(value),
                                  reinterpret_cast<const uint8_t*>(value) + size);
            prepared.value = reinterpret_cast<uint64_t>(prepared.owned.data());
            break;
        }
        case HDL_CALL_ARG_WSTR: {
            if (!argument.ptr) {
                return false;
            }
            const wchar_t* value = static_cast<const wchar_t*>(argument.ptr);
            const size_t size = (wcslen(value) + 1) * sizeof(wchar_t);
            if (size > kMaxBufArg) {
                return false;
            }
            prepared.owned.resize(size);
            memcpy(prepared.owned.data(), value, size);
            prepared.value = reinterpret_cast<uint64_t>(prepared.owned.data());
            break;
        }
        default:
            return false;
        }
    }
    return true;
}

HdlStatus CopyOutBuffers(const std::vector<PreparedArg>& prepared, const HdlCallArg* arguments,
                         uint32_t argument_count) {
    __try {
        for (uint32_t index = 0; index < argument_count; ++index) {
            if (arguments[index].kind != HDL_CALL_ARG_BUF) {
                continue;
            }
            if (!arguments[index].ptr || arguments[index].size > prepared[index].owned.size()) {
                return HDL_E_ACCESS;
            }
            memcpy(const_cast<void*>(arguments[index].ptr), prepared[index].owned.data(),
                   arguments[index].size);
        }
        return HDL_OK;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return HDL_E_ACCESS;
    }
}

void BuildAbi(const std::vector<PreparedArg>& prepared, uint64_t gpr[4], uint64_t xmm[4],
              std::vector<uint64_t>* stack) {
    memset(gpr, 0, sizeof(uint64_t) * 4);
    memset(xmm, 0, sizeof(uint64_t) * 4);
    stack->clear();
    for (uint32_t index = 0; index < static_cast<uint32_t>(prepared.size()); ++index) {
        const uint64_t value = prepared[index].value;
        if (index < 4) {
            gpr[index] = value;
            if (prepared[index].is_float) {
                xmm[index] = value;
            }
        } else {
            stack->push_back(value);
        }
    }
}

HdlStatus InvokeSeh(void* fn, const uint64_t gpr[4], const uint64_t xmm[4],
                    const uint64_t* stack_arguments, uint32_t stack_count, uint64_t* result,
                    DWORD* last_error) {
    SetLastError(0);
    __try {
        *result = HdlInvokeX64(fn, gpr, xmm, stack_arguments, stack_count);
        *last_error = GetLastError();
        return HDL_OK;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        *last_error = GetExceptionCode();
        return HDL_E_FAILED;
    }
}

void RunInvoke(CallWork* work) {
    work->status = InvokeSeh(
        work->fn, work->gpr, work->xmm, work->stack.empty() ? nullptr : work->stack.data(),
        static_cast<uint32_t>(work->stack.size()), &work->result, &work->last_error);
    CompleteCallExecution(work->record, work->status, work->result, work->last_error);
}

DWORD WINAPI CallWorker(LPVOID parameter) {
    auto holder = std::unique_ptr<std::shared_ptr<CallWork>>(
        static_cast<std::shared_ptr<CallWork>*>(parameter));
    std::shared_ptr<CallWork> work = *holder;
    if (BeginCallExecution(work->record, GetCurrentThreadId())) {
        RunInvoke(work.get());
    }
    SignalCallCompletion(work->record);
    return 0;
}

ManagedCallResult ResultFromRecord(HdlStatus status, const std::shared_ptr<CallRecord>& record,
                                   uint64_t blocking_call_id, uint32_t orphan_count) {
    ManagedCallResult result;
    result.status = status;
    result.blocking_call_id = blocking_call_id;
    result.unacknowledged_orphan_count = orphan_count;
    if (!record) {
        return result;
    }
    const HdlCallInfo info = SnapshotCall(record);
    result.call_id = info.call_id;
    result.phase = info.phase;
    result.orphaned = (info.flags & HDL_CALL_INFO_ORPHANED) != 0;
    result.result.return_value = info.return_value;
    result.result.last_error = info.last_error;
    result.result.reserved = 0;
    result.unacknowledged_orphan_count = UnacknowledgedCallOrphanCount();
    return result;
}

ManagedCallResult FinishCompletedCall(const std::shared_ptr<CallWork>& work,
                                      const HdlCallArg* original_arguments,
                                      uint32_t original_argument_count, uint32_t orphan_count) {
    const HdlCallInfo info = SnapshotCall(work->record);
    HdlStatus status = static_cast<HdlStatus>(info.completion_status);
    if (status == HDL_OK) {
        const HdlStatus copy_status =
            CopyOutBuffers(work->prepared, original_arguments, original_argument_count);
        if (copy_status != HDL_OK) {
            status = copy_status;
        }
    }
    FinishSynchronousCall(work->record);
    return ResultFromRecord(status, work->record, 0, orphan_count);
}

} // namespace

HdlStatus ResolveExport(const wchar_t* module_or_null, const char* export_name,
                        uint64_t* out_addr) {
    if (!export_name || !export_name[0] || !out_addr) {
        return HDL_E_INVALID_ARG;
    }
    HMODULE module = ResolveModule(module_or_null);
    if (!module) {
        return HDL_E_NOT_FOUND;
    }
    FARPROC procedure = GetProcAddress(module, export_name);
    if (!procedure) {
        return HDL_E_NOT_FOUND;
    }
    *out_addr = reinterpret_cast<uint64_t>(procedure);
    return HDL_OK;
}

ManagedCallResult CallTracked(const HdlCallDesc* desc, volatile int* cancel) {
    if (!desc || !desc->address || desc->arg_count > kMaxArgs || (desc->arg_count && !desc->args) ||
        desc->thread_mode > HDL_CALL_THREAD_MAIN) {
        ManagedCallResult result;
        result.status = HDL_E_INVALID_ARG;
        return result;
    }
    if (cancel && *cancel) {
        ManagedCallResult result;
        result.status = HDL_E_CANCELLED;
        return result;
    }

    HWND hwnd = nullptr;
    uint32_t target_thread_id = 0;
    if (desc->thread_mode == HDL_CALL_THREAD_MAIN) {
        hwnd = FindPrimaryWindow();
        if (!hwnd) {
            ManagedCallResult result;
            result.status = HDL_E_NOT_FOUND;
            return result;
        }
        target_thread_id = GetWindowThreadProcessId(hwnd, nullptr);
        if (!target_thread_id) {
            ManagedCallResult result;
            result.status = HDL_E_NOT_FOUND;
            return result;
        }
    }

    const CallReservation reservation = ReserveCall(desc->address, desc->thread_mode);
    if (reservation.status != HDL_OK) {
        return ResultFromRecord(reservation.status, nullptr, reservation.blocking_call_id,
                                reservation.unacknowledged_orphan_count);
    }

    auto work = std::make_shared<CallWork>();
    work->record = reservation.record;
    if (!PrepareArgs(desc->args, desc->arg_count, &work->prepared)) {
        RollbackCall(work->record);
        ManagedCallResult result;
        result.status = HDL_E_INVALID_ARG;
        result.unacknowledged_orphan_count = reservation.unacknowledged_orphan_count;
        return result;
    }
    work->fn = reinterpret_cast<void*>(desc->address);
    BuildAbi(work->prepared, work->gpr, work->xmm, &work->stack);

    if (desc->thread_mode == HDL_CALL_THREAD_MAIN) {
        if (target_thread_id == GetCurrentThreadId()) {
            if (BeginCallExecution(work->record, target_thread_id)) {
                RunInvoke(work.get());
            }
            MarkCallExecutionExited(work->record);
            SignalCallCompletion(work->record);
            return FinishCompletedCall(work, desc->args, desc->arg_count,
                                       reservation.unacknowledged_orphan_count);
        }

        const HdlStatus posted = PostWindowCall(
            hwnd, CallRecordId(work->record),
            [work, target_thread_id] {
                if (BeginCallExecution(work->record, target_thread_id)) {
                    RunInvoke(work.get());
                }
            },
            [record = work->record] { CancelQueuedCall(record); },
            [record = work->record] {
                MarkCallExecutionExited(record);
                SignalCallCompletion(record);
            });
        if (posted != HDL_OK) {
            RollbackCall(work->record);
            return ResultFromRecord(posted, nullptr, 0, reservation.unacknowledged_orphan_count);
        }

        const HdlStatus wait_status = WaitForCallDispatch(work->record, desc->timeout_ms, cancel);
        if (wait_status == HDL_OK) {
            return FinishCompletedCall(work, desc->args, desc->arg_count,
                                       reservation.unacknowledged_orphan_count);
        }
        if (MarkCallWaitAbandoned(work->record, wait_status)) {
            return ResultFromRecord(wait_status, work->record, 0,
                                    reservation.unacknowledged_orphan_count);
        }
        return FinishCompletedCall(work, desc->args, desc->arg_count,
                                   reservation.unacknowledged_orphan_count);
    }

    auto* holder = new std::shared_ptr<CallWork>(work);
    DWORD thread_id = 0;
    HANDLE thread = CreateThread(nullptr, 0, CallWorker, holder, 0, &thread_id);
    if (!thread) {
        delete holder;
        RollbackCall(work->record);
        return ResultFromRecord(HDL_E_FAILED, nullptr, 0, reservation.unacknowledged_orphan_count);
    }
    SetCallThread(work->record, thread, thread_id);

    const HdlStatus wait_status = WaitForCallWorker(work->record, desc->timeout_ms, cancel);
    if (wait_status == HDL_OK) {
        return FinishCompletedCall(work, desc->args, desc->arg_count,
                                   reservation.unacknowledged_orphan_count);
    }
    if (MarkCallWaitAbandoned(work->record, wait_status)) {
        return ResultFromRecord(wait_status, work->record, 0,
                                reservation.unacknowledged_orphan_count);
    }
    return FinishCompletedCall(work, desc->args, desc->arg_count,
                               reservation.unacknowledged_orphan_count);
}

HdlStatus Call(const HdlCallDesc* desc, HdlCallResult* out, volatile int* cancel) {
    if (!out) {
        return HDL_E_INVALID_ARG;
    }
    const ManagedCallResult result = CallTracked(desc, cancel);
    *out = result.result;
    return result.status;
}

ManagedCallResult CallExportTracked(const wchar_t* module_or_null, const char* export_name,
                                    const HdlCallArg* args, uint32_t arg_count, uint32_t timeout_ms,
                                    volatile int* cancel) {
    uint64_t address = 0;
    const HdlStatus status = ResolveExport(module_or_null, export_name, &address);
    if (status != HDL_OK) {
        ManagedCallResult result;
        result.status = status;
        return result;
    }
    HdlCallDesc desc{};
    desc.address = address;
    desc.args = args;
    desc.arg_count = arg_count;
    desc.thread_mode = HDL_CALL_THREAD_WORKER;
    desc.timeout_ms = timeout_ms;
    return CallTracked(&desc, cancel);
}

HdlStatus CallExport(const wchar_t* module_or_null, const char* export_name, const HdlCallArg* args,
                     uint32_t arg_count, HdlCallResult* out, uint32_t timeout_ms,
                     volatile int* cancel) {
    if (!out) {
        return HDL_E_INVALID_ARG;
    }
    const ManagedCallResult result =
        CallExportTracked(module_or_null, export_name, args, arg_count, timeout_ms, cancel);
    *out = result.result;
    return result.status;
}

HdlStatus ReadU64Seh(uint64_t address, uint64_t* out) {
    if (!address || !out) {
        return HDL_E_INVALID_ARG;
    }
    __try {
        *out = *reinterpret_cast<uint64_t*>(address);
        return HDL_OK;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return HDL_E_ACCESS;
    }
}

ManagedCallResult CallVtableTracked(uint64_t object, uint32_t index, const HdlCallArg* args,
                                    uint32_t arg_count, int prepend_this, uint32_t thread_mode,
                                    uint32_t timeout_ms, volatile int* cancel) {
    if (!object) {
        ManagedCallResult result;
        result.status = HDL_E_INVALID_ARG;
        return result;
    }
    uint64_t vtable = 0;
    HdlStatus status = ReadU64Seh(object, &vtable);
    if (status != HDL_OK || !vtable) {
        ManagedCallResult result;
        result.status = status == HDL_OK ? HDL_E_NOT_FOUND : status;
        return result;
    }
    uint64_t function = 0;
    status = ReadU64Seh(vtable + static_cast<uint64_t>(index) * 8ull, &function);
    if (status != HDL_OK || !function) {
        ManagedCallResult result;
        result.status = status == HDL_OK ? HDL_E_NOT_FOUND : status;
        return result;
    }

    std::vector<HdlCallArg> local;
    const HdlCallArg* use_args = args;
    uint32_t use_count = arg_count;
    if (prepend_this) {
        HdlCallArg this_argument{};
        this_argument.kind = HDL_CALL_ARG_PTR;
        this_argument.ptr = reinterpret_cast<const void*>(object);
        local.push_back(this_argument);
        if (arg_count && args) {
            local.insert(local.end(), args, args + arg_count);
        }
        use_args = local.data();
        use_count = static_cast<uint32_t>(local.size());
    }

    HdlCallDesc desc{};
    desc.address = function;
    desc.args = use_count ? use_args : nullptr;
    desc.arg_count = use_count;
    desc.thread_mode = thread_mode;
    desc.timeout_ms = timeout_ms;
    return CallTracked(&desc, cancel);
}

HdlStatus CallVtable(uint64_t object, uint32_t index, const HdlCallArg* args, uint32_t arg_count,
                     int prepend_this, uint32_t thread_mode, HdlCallResult* out,
                     uint32_t timeout_ms, volatile int* cancel) {
    if (!out) {
        return HDL_E_INVALID_ARG;
    }
    const ManagedCallResult result = CallVtableTracked(object, index, args, arg_count, prepend_this,
                                                       thread_mode, timeout_ms, cancel);
    *out = result.result;
    return result.status;
}

} // namespace hdl
