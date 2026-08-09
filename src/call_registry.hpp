#pragma once

#include "hdllib/hdllib.h"

#include <cstdint>
#include <memory>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

namespace hdl {

struct CallRecord;

struct CallReservation {
    HdlStatus status = HDL_E_FAILED;
    std::shared_ptr<CallRecord> record;
    uint64_t blocking_call_id = 0;
    uint32_t unacknowledged_orphan_count = 0;
};

void CallRegistryInit();
CallReservation ReserveCall(uint64_t target_address, uint32_t thread_mode);
void SetCallThread(const std::shared_ptr<CallRecord>& record, HANDLE thread, uint32_t thread_id);

/* Claims QUEUED -> RUNNING. An orphaned queued call is instead cancelled. */
bool BeginCallExecution(const std::shared_ptr<CallRecord>& record, uint32_t thread_id);
void CompleteCallExecution(const std::shared_ptr<CallRecord>& record, HdlStatus status,
                           uint64_t return_value, uint32_t last_error);
void SignalCallCompletion(const std::shared_ptr<CallRecord>& record);

HdlStatus WaitForCallWorker(const std::shared_ptr<CallRecord>& record, uint32_t timeout_ms,
                            volatile int* cancel);
HdlStatus WaitForCallDispatch(const std::shared_ptr<CallRecord>& record, uint32_t timeout_ms,
                              volatile int* cancel);
/* Returns true when the execution was marked orphaned; false if it already completed. */
bool MarkCallWaitAbandoned(const std::shared_ptr<CallRecord>& record, HdlStatus wait_status);
void FinishSynchronousCall(const std::shared_ptr<CallRecord>& record);
void MarkCallExecutionExited(const std::shared_ptr<CallRecord>& record);
void CancelQueuedCall(const std::shared_ptr<CallRecord>& record);
void RollbackCall(const std::shared_ptr<CallRecord>& record);

HdlCallInfo SnapshotCall(const std::shared_ptr<CallRecord>& record);
uint64_t CallRecordId(const std::shared_ptr<CallRecord>& record);

HdlStatus EnumCallOrphans(std::vector<HdlCallInfo>* out);
HdlStatus GetCallStatus(uint64_t call_id, HdlCallInfo* out);
HdlStatus AcknowledgeCallOrphan(uint64_t call_id, HdlCallInfo* out);
uint32_t UnacknowledgedCallOrphanCount();

/* Cancels queued work and refuses shutdown while arbitrary target code is running. */
HdlStatus CallRegistryTryBeginShutdown();
void CallRegistryAbortShutdown();
void CallRegistryShutdown();

} // namespace hdl
