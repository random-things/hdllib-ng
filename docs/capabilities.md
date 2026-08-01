# hdllib capabilities

Capability reference organized around the IPC opcodes in [`src/protocol.hpp`](../src/protocol.hpp). The named-pipe protocol is the sole remote control surface for an injected `hdllib.dll`. Shared types/enums live in [`include/hdllib/hdllib.h`](../include/hdllib/hdllib.h).

**What it is:** an injectable x64 Windows helper DLL. Once loaded in a target process it provides memory R/W and search, locate/discovery tooling (including reverse xrefs, function resolution, import hooks, access-shaped watch hits, frame-aware ranking, accumulating heat, and session export/import), placement (caves / nearby alloc / protect), pluggable disassembly, stubs and a reversible patch ledger, PE/graph/vtable helpers, hardware and page watchpoints, in-process calls and hooks, health/events, passive process fingerprinting, allocation, and further DLL injection—controllable from outside via a multi-client named pipe (the sole remote control channel). The companion `hdlclient` adds an interest store and orchestration recipes on top of those ops.

**Client workflows** (CLI groups, `discover-*` pipelines, recipes / store): [client.md](client.md).

**Platform:** x64 only (no Wow64 helper). Opcodes: **1…91**, **`OpUnloadDll` = 92**, **`OpFingerprint` = 93**, **`OpShutdown` = 94**, **`OpTrackLoadedDll` = 95** (`enum Op` in [`src/protocol.hpp`](../src/protocol.hpp)).

---

## Architecture at a glance

```
┌─────────────────┐     named pipe      ┌──────────────────────────┐
│ hdlclient.exe / │ ◄──────────────────► │ hdllib.dll (in target)   │
│ custom client   │  length-prefixed     │  IPC server → Op handlers│
└─────────────────┘  frames              │  C API / MinHook / search│
         │                               └──────────────────────────┘
         │ inject (hdlclient inject / HdlInjectDllEx)
         ▼
  target process
```

| Layer | Role |
|-------|------|
| `hdllib.dll` | Loaded in-target; runs IPC server, memory/search/call/hook/place/code/discover logic |
| `hdlclient.exe` | CLI: local multi-technique inject + pipe protocol + REPL/TUI interest store & recipes |
| `hdllib.h` | Shared types/status/enums; DLL exports only `HdlHookProc` / `HdlWinEventProc` |
| `protocol.hpp` | Opcode enum + POD/string encode helpers used by server and client |

Pipe name: `HdlFormatPipeName(pid)` → `\\.\pipe\RPCControl_<hash>` ([`pipe_name.h`](../include/hdllib/pipe_name.h)). Override with env `HDL_PIPE` (exact path, or a `swprintf` format with `%lu` for the pid). ACL: SYSTEM, Administrators, and the process user — not Everyone. Multiple concurrent clients are supported.

---

## Framing and encoding

### Frame layout

Every request and response is a length-prefixed byte frame:

| Field | Type | Notes |
|-------|------|--------|
| `size` | `uint32_t` | Payload byte count |
| `payload` | `size` bytes | Request: starts with `uint32_t opcode`. Reply: starts with `int32_t status` (`HdlStatus`) |

Implementation: `PipeReadFrame` / `PipeWriteFrame` in `src/ipc/` (facade in `ipc_server.cpp`); client mirror in `tools/client/pipe_client.cpp`.

### Encoding helpers (`hdl::proto`)

| Helper | Wire form |
|--------|-----------|
| `AppendPod` / `TakePod` | Native little-endian POD (`memcpy`) |
| `AppendString` / `TakeString` | `uint32_t byte_len` + NUL-terminated narrow bytes (len includes NUL; empty ⇒ `0`) |
| `AppendWString` / `TakeWString` | `uint32_t byte_len` + UTF-16LE including trailing `L'\0'` (len includes NUL; empty ⇒ `0`) |
| `AppendBytes` | Raw bytes |

### Optional request trailer

Many long-running or bulk ops accept an optional trailing triple (missing fields default to 0):

| Field | Type | Purpose |
|-------|------|---------|
| `job_id` | `uint64_t` | Bind to an existing cooperative job (`OpJobCreate`) |
| `timeout_ms` | `uint32_t` | Deadline; if no `job_id`, a transient job may be created |
| `flags` | `uint32_t` | `HDL_IPC_REQ_STREAM` (1) requests chunked replies |

### Streaming replies

When `HDL_IPC_REQ_STREAM` is set on a supporting request, the server writes **multiple frames**. Each chunk (regions/modules/threads/…):

| Field | Type |
|-------|------|
| `status` | `int32_t` |
| `flags` | `uint32_t` — `HDL_IPC_MORE` (1) if more chunks follow |
| `total` | `uint32_t` |
| `offset` | `uint32_t` |
| `count` | `uint32_t` |
| items | `count` records (type depends on op) |

**Search** streams omit `offset`: `status`, `flags`, `total`, `count`, `u64[count]`.

Clients loop until a frame without `HDL_IPC_MORE` (see `PipeClient::RequestStream`).

### Status codes (`HdlStatus`)

| Code | Name | Meaning |
|------|------|---------|
| 0 | `HDL_OK` | Success |
| 1 | `HDL_E_INVALID_ARG` | Bad payload / unsupported opcode |
| 2 | `HDL_E_ACCESS` | Access denied |
| 3 | `HDL_E_NOT_FOUND` | Missing session, module, window, etc. |
| 4 | `HDL_E_NO_MEM` | Allocation failure |
| 5 | `HDL_E_BUSY` | Ambiguous target, action already open, etc. |
| 6 | `HDL_E_FAILED` | Generic failure |
| 7 | `HDL_E_BUFFER_SMALL` | Caller buffer too small (C API: `*inout_count` = needed) |
| 8 | `HDL_E_CANCELLED` | Cancelled via job / cancel flag |
| 9 | `HDL_E_NOT_INIT` | Library not initialized |
| 10 | `HDL_E_TIMEOUT` | Deadline exceeded (callee may still be running on calls) |

---

## Capability map (opcodes → features)

Opcodes are `enum Op : uint32_t` in `protocol.hpp` (1…91, plus `OpUnloadDll` = 92, `OpFingerprint` = 93, `OpShutdown` = 94, `OpTrackLoadedDll` = 95). Groups below match product capabilities.

### 1. Lifecycle, connectivity, logging

| Op | Value | Capability | C API |
|----|------:|------------|-------|
| `OpPing` | 1 | Liveness + echo host PID | — (IPC only; `HdlIsInitialized` / `HdlIsIpcRunning` for local) |
| `OpSetLogLevel` | 8 | Set log verbosity | `HdlSetLogLevel` |

**Also (env / bootstrap):** `HDL_LOG_LEVEL`, `HDL_NO_IPC=1`, `HDL_HEALTH_VEH`. Lifecycle prepare is on the pipe as `OpShutdown`. Log file and health VEH are pipe ops (`OpSetLogFile`, `OpSetHealthVeh` / `OpGetHealthVeh`).

Default after inject: log level **off**; health VEH **off** until enabled or first `PollEvents`; IPC starts unless `HDL_NO_IPC`.

**`OpPing` reply:** `status`, `uint32_t pid`.

**`OpSetLogLevel` request:** `int32_t level` (`HDL_LOG_OFF`…`HDL_LOG_DEBUG`).

---

### 2. DLL injection

| Op | Value | Capability | C API |
|----|------:|------------|-------|
| `OpInjectDll` | 2 | Inject another DLL into a process (or self / early-bird) | `HdlInjectDll`, `HdlInjectDllEx` |
| `OpUnloadDll` | 92 | Unload a module-list DLL; optional reload at same path | `HdlUnloadDll` / `HdlUnloadDllEx` |
| `OpShutdown` | 94 | Restore hooks/patches/watches; optional unload tracked DLLs; stop IPC (DLL stays mapped) | `HdlShutdown` / `HdlShutdownEx` |
| `OpTrackLoadedDll` | 95 | Register a module-list DLL for later `UNLOAD_MODULES` shutdown | `HdlTrackLoadedDll` |

**`OpInjectDll` request:** `uint32_t pid`, `uint32_t method`, `wstring dll_path`, `wstring exe_path`, `string hook_export`.  
**Reply:** `status`, `uint64_t base`, `uint32_t out_pid`.

**`OpUnloadDll` request:** `uint32_t pid`, `int32_t reload`, `wstring dll_path`.  
**Reply:** `status`, `uint64_t base` (new base when `reload != 0`, else 0).  
Remote unload of a module that exports `HdlShutdown` first sends `OpShutdown(shutdown_flags)` so instrumentation is restored outside the loader lock.

**`OpShutdown` request:** `uint32_t flags` (`HDL_SHUTDOWN_UNLOAD_MODULES = 1` FreeLibrary-tracks registered payloads, never the helper itself). Reply `status`; then the server signals IPC stop without joining the accept thread from the worker. Eject with local `hdlclient unload <pid> <hdllib.dll> [--modules]`.

**`OpTrackLoadedDll` request:** `uint64_t base`, `wstring dll_path`.

**Techniques** (`HDL_INJECT_*`, see [inject/](inject/README.md)):

| Method | Constant | Notes |
|--------|----------|--------|
| CreateRemoteThread | 0 | Default / classic `LoadLibraryW` |
| NtCreateThreadEx | 1 | ntdll remote thread |
| RtlCreateUserThread | 2 | ntdll remote thread |
| QueueUserAPC | 3 | Needs alertable thread |
| SetWindowsHookEx | 4 | Needs window; DLL exports hook (`HdlHookProc` default) |
| Thread hijack | 5 | Suspend + `SetThreadContext` |
| Manual map | 6 | PE map without module-list entry |
| Early Bird APC | 7 | Create suspended process from `exe_path`, queue APC |
| AtomBombing | 8 | Global atom + APC (path ≤ 255) |
| Module stomp | 9 | Stomp sacrificial DLL |
| Section map | 10 | `NtCreateSection` + map + `LoadLibraryW` |
| Window subclass | 11 | `GWLP_WNDPROC` stub |
| Instrumentation callback | 12 | `NtSetInformationProcess` |
| Kernel callback table | 13 | PEB `KernelCallbackTable` |
| VEH | 14 | Vectored handler + `DebugBreak` |
| SetWinEventHook | 15 | In-context (`HdlWinEventProc`) |
| RtlRemoteCall | 16 | Undocumented ntdll |
| Special user APC | 17 | `NtQueueApcThreadEx2` |
| Thread pool | 18 | `TpAllocWork` / `TpPostWork` |
| ETW callback | 19 | `EtwEventRegister` enable-callback |
| Auto | −1 | `HdlRecommendInject` ranking (C API / `hdlclient inject`; not a separate opcode) |

**Controller-local (not target-pipe):** target resolve and inject recommend live in `hdl_inject` / `hdlclient inject`. Injector `--stealth` stages a bland temp copy and prefers stealthier techniques on auto.

---

### 3. Memory read / write / enumerate

| Op | Value | Capability | C API |
|----|------:|------------|-------|
| `OpReadMemory` | 3 | SEH-safe read (max 16 MiB per request) | `HdlReadMemory` |
| `OpWriteMemory` | 4 | SEH-safe write (max 16 MiB) | `HdlWriteMemory` |
| `OpEnumRegions` | 5 | Virtual memory regions | `HdlEnumRegions` |
| `OpEnumModules` | 6 | Loaded modules | `HdlEnumModules` |

**Read request:** `uint64_t address`, `uint32_t size` → reply `status`, `uint32_t got`, bytes.  
**Write request:** `address`, `size`, raw bytes → `status`, `uint32_t wrote`.  
**Enum regions/modules:** optional trailer; non-stream reply `status`, `count`, array of `HdlRegionInfo` / `HdlModuleInfo`. Stream chunks as above (regions chunk 64, modules 16).

`HdlRegionInfo`: base, size, protect, state, type.  
`HdlModuleInfo`: base, size, path\[260\].

---

### 4. Memory search (AOB + Cheat Engine–style incremental)

| Op | Value | Capability | C API |
|----|------:|------------|-------|
| `OpSearchMemory` | 7 | One-shot AOB scan | `HdlSearchMemory` |
| `OpSearchCreate` | 9 | Open incremental session | `HdlSearchCreate` |
| `OpSearchClose` | 10 | Destroy session | `HdlSearchClose` |
| `OpSearchFirst` | 11 | First scan (typed / AOB) | `HdlSearchFirst` |
| `OpSearchNext` | 12 | Refine candidates | `HdlSearchNext` |
| `OpSearchGetHits` | 13 | Dump hit addresses | `HdlSearchGetHits` / `HdlSearchGetCount` |
| `OpSearchReset` | 14 | Clear session state | `HdlSearchReset` |

**AOB syntax:** `"48 8B ?? ?? 90"` (spaces optional; `??` / `?` = wildcard). `start==0 && size==0` ⇒ all committed readable regions.

**Value types (`HDL_VALUE_*`):** bytes (AOB), i8/u8, i16/u16, i32/u32, i64/u64, f32/f64, string, wstring.

**Comparisons (`HDL_CMP_*`):** first scan: `EXACT` or `UNKNOWN`. Next: `CHANGED`, `UNCHANGED`, `INCREASED`/`DECREASED` (+ `_BY`), `GREATER`/`LESS`, `EXACT`. Snapshots of prior values enable change detection.

**Scope flags (`HDL_SEARCH_*`):** `IMAGE`, `EXECUTABLE`, `MODULE` (+ module name).

**IPC sessions:** server maps `uint64_t session_id` → `HdlSearchSession*` (create returns id). Cancel/timeout via optional job trailer.

**`OpSearchMemory` / `OpSearchFirst` / `OpSearchGetHits` always stream.** Hits are produced into a bounded in-DLL buffer (4096 addresses); when full the scan blocks on `WriteFile` until the client drains the pipe. Search frames: `status`, `flags(MORE)`, `total` (0 until final), `count`, `u64[count]` (no `offset` — append in order). Final frame has `MORE=0` and the true `total`. `max_hits` / `max_results` 0 = unlimited; nonzero = optional early stop. AOB is always byte-unaligned; typed `alignment` 0 = natural, 1 = unaligned.  
**`OpSearchNext`:** `session`, `cmp`, `value_len` + bytes \[+ trailer\] → `status`, `count` (then use GetHits to stream survivors).

---

### 5. Cooperative jobs

| Op | Value | Capability | C API |
|----|------:|------------|-------|
| `OpJobCreate` | 15 | Create cancel/timeout token | `HdlJobCreate` |
| `OpJobCancel` | 16 | Cancel job | `HdlJobCancel` |
| `OpJobClose` | 17 | Release job | `HdlJobClose` |

Jobs bind to long ops (search, call, pattern resolve, …) so one client can cancel another’s work or enforce a deadline. Completion can surface as `HDL_EVENT_JOB_DONE` via `OpPollEvents`.

**Create:** `uint32_t timeout_ms` → `status`, `uint64_t job_id`.

---

### 6. Process / thread health and events

| Op | Value | Capability | C API |
|----|------:|------------|-------|
| `OpGetHealth` | 18 | Snapshot: CPU, WS, hang, last exception | `HdlGetHealth` |
| `OpEnumThreads` | 19 | Thread list | `HdlEnumThreads` |
| `OpPollEvents` | 20 | Drain exception / health / job / hook wake-ups | `HdlPollEvents` |

**Health flags:** `GUI_HUNG`, `HIGH_CPU`, `RECENT_EXCEPTION`. Optional VEH (`HdlSetHealthVeh` / `HDL_HEALTH_VEH`) feeds exception events.

**Events (`HDL_EVENT_*`):** `EXCEPTION`, `HEALTH`, `JOB_DONE`, `HOOK` (wake only; full payload via `OpPollHookHits`), `WATCH` (wake only; full payload via `OpPollWatchHits` when armed).

**`OpPollEvents`:** `max_events`, `timeout_ms` (0 = non-blocking) → `status`, `count`, `HdlEvent[]` (max clamped to 64).

---

### 6b. Process fingerprint

| Op | Value | Capability | C API |
|----|------:|------------|-------|
| `OpFingerprint` | 93 | Passive tags: language/runtime/UI/graphics/engine/… from modules + main IAT + PE subsystem | `HdlEnumFingerprintTags`, `HdlClassifyFingerprint` |

**Request:** `uint32_t scan_flags` (`HDL_FP_SCAN_MODULES` / `IMPORTS` / `PE`; `0` or omit → `HDL_FP_SCAN_DEFAULT`) + optional stream trailer.

**Response:** `status`, `count`, `HdlFingerprintTag[]` (or streamed like modules). Each tag: `category`, `confidence` 0–100, `flags` (`FROM_MODULE` / `FROM_IMPORT` / `FROM_PE` / `PRIMARY`), `id`, `evidence`.

`HdlClassifyFingerprint` classifies caller-provided module basenames + import pairs (tests / offline dumps; no process walk). Active probes (`HDL_FP_ACTIVE`) are reserved.

CLI: `hdlclient <pid> fingerprint`; REPL: `recipe suggest` prints next-step watch/call hints from primaries.

---

### 7. Address resolution helpers

| Op | Value | Capability | C API |
|----|------:|------------|-------|
| `OpResolveExport` | 21 | `GetProcAddress`-style resolve | `HdlResolveExport` |
| `OpResolveRip` | 26 | RIP-relative decode | `HdlResolveRipRelative` |
| `OpFollowPointers` | 27 | Multilevel pointer chain | `HdlFollowPointers` |
| `OpModuleBase` | 28 | Module base (null/empty = main EXE) | `HdlModuleBase` |

Typical LEA/CALL/JMP: `disp_offset=3`, `instr_len=7` (or 1/5 for near call/jmp). Pointer follow: start at `base`, repeatedly read pointer and add `offsets[i]` (IPC allows up to 64 offsets).

---

### 8. In-process calls (export / absolute / vtable)

| Op | Value | Capability | C API |
|----|------:|------------|-------|
| `OpCallExport` | 22 | Resolve export + call (worker thread) | `HdlCallExport` |
| `OpCall` | 23 | Absolute address call | `HdlCall` |
| `OpCallVtable` | 29 | `(*obj)[index]` then call | `HdlCallVtable` |

Microsoft x64 ABI, up to **16** arguments. Arg kinds (`HDL_CALL_ARG_*`): `U64`, `I64`, `PTR`, `BUF` (copy-in/out), `CSTR`, `WSTR`, `F32`, `F64` (IEEE bits in `u64`).

Thread modes: `WORKER` (default helper thread) or `MAIN` (sync on primary UI HWND; fails if none / console-only).

**IPC arg encoding (each):** `int32_t kind`, `uint32_t size`, `uint64_t u64` \[+ for BUF/CSTR/WSTR: `uint32_t blob_len` + bytes\]. PTR uses `u64` as the pointer value.

**Call reply:** `status`, `HdlCallResult` (`return_value`, `last_error`), then for Call/CallExport: `buf_n` and per-BUF `(index, size, bytes)` copy-outs. On timeout/cancel the callee may still be running.

**`OpCallVtable` extras:** `obj`, `index`, `arg_count`, `prepend_this`, `thread_mode`, `timeout_ms`, `job_id`, then args. When `prepend_this != 0`, a synthetic `this` is prepended if missing.

---

### 9. Durable scratch allocation

| Op | Value | Capability | C API |
|----|------:|------------|-------|
| `OpAlloc` | 24 | Tracked `VirtualAlloc` | `HdlAlloc` |
| `OpFree` | 25 | Free prior alloc | `HdlFree` |

**Alloc:** `uint64_t size`, `uint32_t protect` (`PAGE_*`) → `status`, `addr`. Useful for remote call buffers that must outlive a single call’s temp copies.

---

### 10. Hooks (MinHook + capture/trace)

| Op | Value | Capability | C API |
|----|------:|------------|-------|
| `OpHookTrace` | 30 | Install capture-only hook (≤8 int-view args + return + caller) | `HdlHookTrace` |
| `OpEnableHook` | 31 | Enable/disable | `HdlEnableHook` |
| `OpUnhook` | 32 | Remove hook | `HdlUnhook` |
| `OpPollHookHits` | 33 | Drain hit queue | `HdlPollHookHits` |
| `OpHookImport` | 83 | Resolve PE import (DLL+name) → `HookTrace` on `bound_va` | `HdlHookImport` |

**Custom detours over the pipe:** `OpHook` (`target_va`, `detour_va` → handle + trampoline). Default exports for inject: `HdlHookProc`, `HdlWinEventProc`.

Trace hooks call the original, enqueue `HdlHookHit` (incl. `frame_count` + `frames[8]`), and wake `PollEvents` with `HDL_EVENT_HOOK`. Handle is the target address as `uint64_t`. Trampolines live while `hdllib.dll` remains loaded.

**Import hook:** `HdlHookImport(module_or_null, dll_name, import_name, arg_count, out)` walks `EnumImports`, matches case-insensitive DLL basename + import name, then `HookTrace` on the current IAT `bound_va` (no IAT rewrite in v1). Client: `hook-import KERNEL32.dll!GetCurrentProcessId` or `--dll` / `--import`.

---

### 11. Locate (signatures, xrefs, pointer scan, struct probe)

| Op | Value | Capability | C API |
|----|------:|------------|-------|
| `OpResolvePattern` | 34 | AOB → optional RIP + multilevel follow → abs/RVA | `HdlResolvePattern` |
| `OpFindStringXrefs` | 35 | String → absolute / RIP-relative xrefs | `HdlFindStringXrefs` |
| `OpPointerScan` | 36 | CE-style static pointer paths to a target | `HdlPointerScan` |
| `OpProbeStruct` | 37 | Heuristic field kinds over a byte range (≤4096) | `HdlProbeStruct` |

**Pattern resolve:** pick Nth AOB hit, add `pattern_offset`, optionally decode RIP (`rip_disp_offset` / `rip_instr_len`), then follow offsets. Scope via `HDL_SEARCH_*`. Result: `match_addr`, `resolved_addr`, `module_base`, `rva`.

**Xref flags:** `HDL_XREF_ABSOLUTE`, `HDL_XREF_RIP_REL`.

**Pointer path:** `static_base` + up to 8 offsets; typically scan with `HDL_SEARCH_IMAGE`.

**Struct field kinds:** unknown, ptr, vtable (ptr into executable image), ascii, float, int32, int64.

---

### 12. Discover (automated find / stabilize / expand)

Session-based pipeline: seed candidates → constraint / action evidence → stabilize with AOB synthesis or pointer-path consensus → cluster related objects → optional JSON export/import and field promotion from watches.

| Op | Value | Capability | C API |
|----|------:|------------|-------|
| `OpDiscoverCreate` | 38 | Open discover session | `HdlDiscoverCreate` |
| `OpDiscoverClose` | 39 | Close session | `HdlDiscoverClose` |
| `OpDiscoverAddCandidate` | 40 | Manually seed address/function/object/field | `HdlDiscoverAddCandidate` |
| `OpDiscoverConstraintScan` | 41 | Find object bases matching field predicates | `HdlDiscoverConstraintScan` |
| `OpDiscoverSynthesizePattern` | 42 | Build module-unique AOB for a candidate | `HdlDiscoverSynthesizePattern` |
| `OpDiscoverPathConsensus` | 43 | Pointer-scan + keep paths that still resolve | `HdlDiscoverPathConsensus` |
| `OpDiscoverPathValidate` | 44 | Filter path list against expected target | `HdlDiscoverPathValidate` |
| `OpDiscoverWatch` | 45 | HookTrace a function for action ranking | `HdlDiscoverWatch` |
| `OpDiscoverUnwatchAll` | 46 | Remove watches | `HdlDiscoverUnwatchAll` |
| `OpDiscoverActionBegin` | 47 | Open named action window | `HdlDiscoverActionBegin` |
| `OpDiscoverActionEnd` | 48 | Close action; associate hits / diffs | `HdlDiscoverActionEnd` |
| `OpDiscoverWatchRegion` | 49 | Register region for change-heat | `HdlDiscoverWatchRegion` |
| `OpDiscoverGetHeat` | 50 | Per-offset change heat after actions | `HdlDiscoverGetHeat` |
| `OpDiscoverRankFunctions` | 51 | Rank functions seen during an action | `HdlDiscoverRankFunctions` |
| `OpDiscoverClusterType` | 52 | Find other objects with same vtable@0 | `HdlDiscoverClusterType` |
| `OpDiscoverGetCandidates` | 53 | Dump candidate list | `HdlDiscoverGetCandidates` |
| `OpDiscoverWatchImport` | 84 | HookImport + register on session watches | `HdlDiscoverWatchImport` |
| `OpDiscoverResetHeat` | 86 | Clear accumulated heat for a watched base | `HdlDiscoverResetHeat` |
| `OpDiscoverExport` | 87 | Serialize session → UTF-8 JSON (≤4 MiB) | `HdlDiscoverExport` |
| `OpDiscoverImport` | 88 | Best-effort restore candidates from JSON | `HdlDiscoverImport` |
| `OpDiscoverDiffObjects` | 89 | Bytewise multi-instance field diffs | `HdlDiscoverDiffObjects` |
| `OpDiscoverApplyWatchHits` | 90 | Promote watch hits in a range → `FIELD` cands | `HdlDiscoverApplyWatchHits` |
| `OpDiscoverGetEvidence` | 91 | UTF-8 provenance string for a candidate id | `HdlDiscoverGetCandidateEvidence` |

**Candidate kinds:** `ADDRESS`, `FUNCTION`, `OBJECT`, `FIELD` (with confidence 0–100, address, module/RVA, tag).

**Field predicates (`HDL_PRED_*`):** eq i32/f32/u64, range/le i32, readable ptr, vtable ptr — relative to object base; object size capped at 4096, alignment 8.

**Ranking:** default is **frame-aware** — walk `HdlHookHit.frames[]`, `ResolveFunction` each frame, skip System32/SysWOW64/`hdllib`, weight by `max(1, 8−depth)`, bucket by function start. Pass `HDL_RANK_CALLER_ONLY` (1) to rank immediate `caller` return sites instead. IPC request includes a `flags` pod after the action name.

**Heat:** 1-byte diffs merged into aligned 1/2/4/8 runs; `HdlHeatField.reserved` holds run **size**; `changes` **accumulates** across actions (not cleared on `ActionBegin` — only on region re-register or `ResetHeat`).

**Typical workflow:**

1. `Create` → add seeds and/or `ConstraintScan` / typed C-API `HdlDiscoverScanValue`
2. `Watch` / `WatchImport` + `WatchRegion` → `ActionBegin` / user action / `ActionEnd`
3. `GetHeat` + `RankFunctions` (+ optional `GetEvidence`) to promote fields/functions
4. `SynthesizePattern` and/or `PathConsensus` (+ `PathValidate` across mutations)
5. `ClusterType` / `DiffObjects` / `ApplyWatchHits` to expand layout → `GetCandidates`
6. Optional `Export` / later `Import` for durable session snapshots

Concrete `hdlclient` command sequences for these pipelines (and recipes that wrap them): [client.md § Discover](client.md#3-discover-sessions-discover-).

**Discover typed scan:** `OpDiscoverScanValue` (opcode 99); `hdlclient discover-scan` uses it.

---

### 13. Place (caves, nearby alloc, protect)

| Op | Value | Capability | C API |
|----|------:|------------|-------|
| `OpFindCaves` | 54 | Search for fill-byte padding near a VA | `HdlFindCaves` |
| `OpAllocNear` | 55 | `VirtualAlloc` within ±`max_distance` of a hint | `HdlAllocNear` |
| `OpProtectMemory` | 56 | `VirtualProtect` wrapper | `HdlProtectMemory` |
| `OpFlushICache` | 57 | Flush instruction cache for a range | `HdlFlushICache` |

**Cave query:** `min_size`, `fill_byte` (often `0xCC` / `0x00`), `near_addr`, `max_distance`, `search_flags` / module, `max_results`. Reply: cave `addr` + `size` list. Client recipes score caves (nearer first, then larger size).

**AllocNear:** `near`, `max_distance`, `size`, `protect` → tracked address (free with `OpFree`).

---

### 14. Disassembly backends

| Op | Value | Capability | C API |
|----|------:|------------|-------|
| `OpDisasmEnumBackends` | 58 | List registered engines | `HdlDisasmEnumBackends` |
| `OpDisasmGetBackend` | 59 | Active backend id | `HdlDisasmGetBackend` |
| `OpDisasmSetBackend` | 60 | Select Zydis / Capstone / custom | `HdlDisasmSetBackend` |

Built-in: **Zydis** (default) and **Capstone**. Remote surface is Enum/Get/Set only (no custom-engine registration over the pipe).

---

### 15. Code (instr length, disasm, stubs, patch ledger)

| Op | Value | Capability | C API |
|----|------:|------------|-------|
| `OpInstrLen` | 61 | Length of one insn at VA | `HdlInstrLen` |
| `OpDisasm` | 62 | Decode up to N insns | `HdlDisasm` |
| `OpBuildStub` | 63 | Emit trampoline / jmp template | `HdlBuildStub` |
| `OpPatchCreate` | 64 | Record bytes + original for undo | `HdlPatchCreate` |
| `OpPatchEnable` | 65 | Apply / restore patch | `HdlPatchEnable` |
| `OpPatchRemove` | 66 | Drop ledger entry | `HdlPatchRemove` |
| `OpPatchEnum` | 67 | List patches | `HdlPatchEnum` |

**Stub kinds (`HDL_STUB_*`):** `ABS_JMP`, `REL_JMP32`, `MOV_RAX_JMP`, `RAW` (caller hex). Optional `steal_from` / `steal_min_bytes` copies prologue bytes; `alloc_rx` allocates an RX stub VA.

**Patch ledger:** create with target VA + bytes + optional name → handle; enable writes bytes (with protect + I-cache flush); disable restores original; enum lists handles.

---

### 16. PE metadata

| Op | Value | Capability | C API |
|----|------:|------------|-------|
| `OpEnumSections` | 68 | Section table for a module | `HdlEnumSections` |
| `OpEnumExports` | 69 | Export names / RVAs | `HdlEnumExports` |
| `OpEnumImports` | 70 | Import DLL+name / IAT | `HdlEnumImports` |

`module_base_or_0 == 0` ⇒ main EXE image.

---

### 17. Bounded function / xref graph

| Op | Value | Capability | C API |
|----|------:|------------|-------|
| `OpEnumFunctions` | 71 | Heuristic function starts in a range / module | `HdlEnumFunctions` |
| `OpXrefsFrom` | 72 | Outgoing call/jmp(/data) edges from a seed | `HdlXrefsFrom` |
| `OpResolveFunction` | 79 | Align any interior VA → containing function (`start`/`end`/confidence/flags) | `HdlResolveFunction` |
| `OpXrefsTo` | 80 | Incoming call/jmp(/data) sites targeting an address | `HdlXrefsTo` |
| `OpInvalidateFnIndex` | 85 | Drop process-local function index cache | `HdlInvalidateFunctionIndex` |

`ResolveFunction` prefers compiler-authored x64 unwind ranges (confidence **100**) and accepts any interior byte address, including a post-watchpoint RIP. Its fallback and `EnumFunctions` use the active disassembler: export **90** (`HDL_FN_EXPORT`), call target **75** (`HDL_FN_CALLED`), and narrowly matched prologue **45** (`HDL_FN_PROLOGUE`); conditional/local jump targets are not function starts. Heuristic ends prefer ret / `int3` padding / next start, and the fallback index is cached per `(module_base, SizeOfImage)`.

**XrefsTo kinds:** `HDL_XREF_CALL|JMP|DATA`; with `HDL_XREF_FUNC` (8) also match branches into `[fn.start, fn.end)`. Client: `resolve-function`, `xrefs-to` (`--exact` drops `FUNC`), `invalidate-fn-index`.

---

### 18. Observe (vtable / RTTI)

| Op | Value | Capability | C API |
|----|------:|------------|-------|
| `OpWalkVtable` | 73 | Walk slots until non-code | `HdlWalkVtable` |
| `OpQueryRttiName` | 74 | Best-effort MSVC type name | `HdlQueryRttiName` |

`is_object != 0` treats the address as an object (read vptr at +0); else as a vtable pointer. RTTI may return `HDL_E_NOT_FOUND` when COL / type_info is absent.

---

### 19. Watchpoints (hardware + page)

| Op | Value | Capability | C API |
|----|------:|------------|-------|
| `OpWatchHw` | 75 | DR0–3 breakpoint (tracked free-slot allocation) | `HdlWatchHw` |
| `OpWatchPage` | 76 | `PAGE_GUARD` or `PAGE_NOACCESS` | `HdlWatchPage` |
| `OpUnwatch` | 77 | Remove watch (clears stored DR index) | `HdlUnwatch` |
| `OpEnumWatches` | 78 | List active watches | `HdlEnumWatches` |
| `OpWatchRefresh` | 81 | Re-apply all HW watches to current threads | `HdlWatchRefresh` |
| `OpPollWatchHits` | 82 | Drain `HdlWatchHit` queue (cap 256) | `HdlPollWatchHits` |

**HW:** size `1|2|4|8`, access `exec|write|rw`, optional `tid` (0 = best-effort all threads). At most **4** concurrent HW watches.  
**Page:** size region + mode `guard|noaccess`.  
**Hits:** VEH only enqueues for registered watches. `HDL_EVENT_WATCH` is **wake-only** (like `HDL_EVENT_HOOK`); full payload is `HdlWatchHit` (`watch_handle`, `rip`, `accessed`, `size`, `tid`, …) via `PollWatchHits`. Client: `watch hw|page|list|unwatch|hits|refresh`.

---

## Opcode quick index

| # | Op | Capability group |
|--:|----|------------------|
| 1 | Ping | Connectivity |
| 2 | InjectDll | Injection |
| 3–4 | Read/WriteMemory | Memory |
| 5–6 | EnumRegions/Modules | Memory |
| 7 | SearchMemory | Search |
| 8 | SetLogLevel | Logging |
| 9–14 | Search* session | Search |
| 15–17 | Job* | Jobs |
| 18–20 | Health / Threads / Events | Health |
| 21 | ResolveExport | Resolve |
| 22–23 | CallExport / Call | Call |
| 24–25 | Alloc / Free | Alloc |
| 26–28 | ResolveRip / FollowPointers / ModuleBase | Resolve |
| 29 | CallVtable | Call |
| 30–33 | HookTrace / Enable / Unhook / PollHits | Hooks |
| 34–37 | ResolvePattern / Xrefs / PointerScan / Probe | Locate |
| 38–53 | Discover* | Discover |
| 54–57 | FindCaves / AllocNear / Protect / FlushICache | Place |
| 58–60 | DisasmEnum/Get/SetBackend | Disasm |
| 61–67 | InstrLen / Disasm / BuildStub / Patch* | Code |
| 68–70 | EnumSections / Exports / Imports | PE |
| 71–72 | EnumFunctions / XrefsFrom | Graph |
| 73–74 | WalkVtable / QueryRttiName | Observe |
| 75–78 | WatchHw / WatchPage / Unwatch / EnumWatches | Watch |
| 79–80 | ResolveFunction / XrefsTo | Graph |
| 81–82 | WatchRefresh / PollWatchHits | Watch |
| 83 | HookImport | Hooks |
| 84 | DiscoverWatchImport | Discover |
| 85 | InvalidateFnIndex | Graph |
| 86–91 | DiscoverResetHeat / Export / Import / DiffObjects / ApplyWatchHits / GetEvidence | Discover |
| 92 | UnloadDll | Injection |
| 93 | Fingerprint | Process fingerprint |
| 94 | Shutdown | Lifecycle |
| 95 | TrackLoadedDll | Lifecycle |

### Opcodes 79–91 (graph / watch / discover extensions)

| Opcode | ID | Role |
|--------|-----|------|
| `OpResolveFunction` | 79 | Map address to function bounds |
| `OpXrefsTo` | 80 | Incoming call/jmp/data refs to target |
| `OpWatchRefresh` | 81 | Re-arm DR/page watches after thread churn |
| `OpPollWatchHits` | 82 | Drain watch hit queue |
| `OpHookImport` | 83 | HookTrace on a PE import by DLL+name |
| `OpDiscoverWatchImport` | 84 | Discover session: trace import for action ranking |
| `OpInvalidateFnIndex` | 85 | Drop cached function index |
| `OpDiscoverResetHeat` | 86 | Clear change-heat for a watched region |
| `OpDiscoverExport` | 87 | Serialize discover session to JSON |
| `OpDiscoverImport` | 88 | Load discover session JSON |
| `OpDiscoverDiffObjects` | 89 | Diff candidate object snapshots |
| `OpDiscoverApplyWatchHits` | 90 | Promote watch hits into field candidates |
| `OpDiscoverGetEvidence` | 91 | Fetch UTF-8 evidence string for candidate |

---

## Place / code / PE / graph / watch (54–91)

In-process placement and analysis surface:

- **Caves / AllocNear / Protect / FlushICache** — executable padding search, nearby scratch, protect + I-cache flush
- **Disasm backends** — pluggable Zydis + Capstone (runtime select via Enum/Get/Set); no remote custom-engine registration
- **InstrLen / Disasm / BuildStub / Patch ledger** — decode, trampoline emit, reversible patches
- **PE sections / exports / imports** — mapped-image metadata
- **EnumFunctions / XrefsFrom / ResolveFunction / XrefsTo / InvalidateFunctionIndex** — unwind-aligned x64 resolution plus bounded fallback index (export/call/prologue confidence, ret-based ends, process-local cache) and outbound/inbound edges (`HDL_XREF_CALL|JMP|DATA|FUNC`)
- **WalkVtable / QueryRttiName** — MSVC RTTI best-effort
- **WatchHw / WatchPage / Unwatch / EnumWatches / WatchRefresh / PollWatchHits** — DR breakpoints (tracked slots) and page guards; `HDL_EVENT_WATCH` is wake-only; full `HdlWatchHit` payload via `PollWatchHits`
- **HookImport** — one-shot IAT sink tracing (opcode 83)
- **Discover WatchImport / ResetHeat / Export / Import / DiffObjects / ApplyWatchHits / GetEvidence** — import watches, layout heat, session JSON, field promotion (opcodes 84, 86–91)

Hook hits include `frame_count` + `frames[8]` (stack capture) for frame-aware discover ranking.

Controller-local (not target-pipe opcodes):

- **Inject method ranking** — `hdlclient inject --recommend` / `--method auto` (`hdl_inject`)
- **Target resolution** — pid + window title substring / class (`hdl_inject`)

Pipe parity ops **96…100:** `OpSetLogFile`, `OpSetHealthVeh` / `OpGetHealthVeh`, `OpDiscoverScanValue`, `OpHook`.

In-process lifecycle prepare is on the pipe: `OpShutdown` / `hdlclient <pid> shutdown [--modules]`.

**Client-side orchestration (no new DLL opcode):**

- **Interest store + recipes** — JSON locators and `recipe place` / `stitch` / `expand` / discover recipes (see [Interest store and recipes](#interest-store-and-recipes-client-only))

Full inject technique notes: [docs/inject/](inject/README.md). Future ideas: [docs/future/](future/README.md).

---

## CLI ↔ capability mapping (`hdlclient`)

| Command area | Ops used |
|--------------|----------|
| `ping`, `log`, `log-file`, `health-veh` | Ping, SetLogLevel, SetLogFile, Set/GetHealthVeh |
| `hook` | OpHook (target_va + detour_va) |
| `shutdown` | Shutdown (optional `--modules`) |
| `inject` (pipe + `hdlclient inject`) | InjectDll / local inject |
| `read`, `write` | ReadMemory, WriteMemory |
| `regions`, `modules`, `threads` | Enum* (+ stream) |
| `scan` / `--next` / `--hits` | SearchMemory or Search* session |
| `health`, `fingerprint`, `events`, `job` | GetHealth, Fingerprint, PollEvents, Job* |
| `call` / `vcall` / `resolve` | Call, CallExport, CallVtable, ResolveExport |
| `alloc` / `free` / `alloc-near` | Alloc, Free, AllocNear |
| `caves` / `protect` / `flush-icache` / `alloc-near` | Place ops 54–57 |
| `disasm-backend` / `disasm` / `instrlen` / `stub` | Disasm 58–60 + InstrLen / Disasm / BuildStub |
| `patch` (`list`/`create`/`enable`/`disable`/`remove`) | Patch ledger 64–67 |
| `sections` / `exports` / `imports` | PE 68–70 |
| `functions` / `xrefs-from` / `resolve-function` / `xrefs-to` / `invalidate-fn-index` | Graph 71–72, 79–80, 85 |
| `vtable` / `rtti` | Observe 73–74 |
| `watch` (`hw`/`page`/`list`/`unwatch`/`hits`/`refresh`) | Watch 75–78, 81–82 |
| `rip`, `ptrchain`, `modbase` | ResolveRip, FollowPointers, ModuleBase |
| `hooktrace`, `hook-import`, `hook-enable`/`enablehook`, `unhook`, `hookhits` | HookTrace, HookImport, EnableHook, Unhook, PollHookHits |
| `resolve-pattern`, `xrefs`, `ptrscan`, `probe` | Locate ops |
| `discover-*` (incl. `discover-pathvalidate`, `discover-scan`, `discover-watch-import`, `discover-reset-heat`, `discover-export`/`import`, `discover-diff`, `discover-apply-watch`, `discover-evidence`) | Discover ops 38–53 + 84, 86–91 (+ scan compose) |
| `hdlclient <pid>` / `repl` / `--tui` | Interactive controller (all pipe cmds + store/recipes) |
| `store` / `recipe` / `stabilize` (REPL/TUI) | Interest JSON + discover recipes |

Call arg prefixes: `u64:`, `i64:`, `f32:`, `f64:`, `cstr:`, `wstr:`, `buf:HEX`, `ptr:HEX`. Scan scope: `--image`, `--executable`, `--module NAME`.

### Interest store and recipes (client-only)

`hdlclient` persists addresses as **interests** in a JSON file (`--store PATH`). Schema **version 3** (Save always writes ≥3; older files still load; unknown locator types are skipped with a warning).

**Locator types:** `pattern`, `path`, `export`, `import`, `cave`, `stub`, `patch` — revalidate via ResolvePattern / FollowPointers / ResolveExport / EnumImports / FindCaves / BuildStub / address-only for patches.

**Recipes** (REPL / TUI): `place`, `stitch`, `expand`, `action`, `constrain`, plus `stabilize <cand_id>`.

Full workflows, predicate syntax, end-to-end examples, and TUI keys: **[client.md § Interest store and recipes](client.md#4-interest-store-and-recipes)**.

Stub CLI kinds match DLL templates (no text assembler): `abs_jmp` / `rel_jmp32` / `mov_rax_jmp` / `raw`.

---

## Practical limits (IPC)

| Resource | Limit |
|----------|------:|
| Read/write per request | 16 MiB |
| Search hits (AOB / GetHits cap) | 100 000 |
| Call arguments | 16 |
| HookTrace captured args | 8 |
| FollowPointers offsets | 64 |
| Pattern follow offsets | 16 |
| Pointer path depth (struct) | 8 offsets |
| PollEvents / PollHookHits / PollWatchHits max | 64 |
| Discover constraint preds | 32 |
| Probe / heat field size | struct ≤ 4096 bytes |
| Discover export JSON | 4 MiB |
| Hardware watch slots (DR0–3) | 4 |
| Stream chunk sizes | regions 64, modules 16, threads 32, hits 256 |

---

## Related sources

| File | Contents |
|------|----------|
| [`src/protocol.hpp`](../src/protocol.hpp) | Opcode enum, stream flags, encode/decode |
| [`src/ipc_server.hpp`](../src/ipc_server.hpp) / [`src/ipc_server.cpp`](../src/ipc_server.cpp) | Public IPC start/stop + frame helpers |
| [`src/ipc/`](../src/ipc/) | Server loop, framing, dispatch, handlers by domain |
| [`include/hdllib/hdllib.h`](../include/hdllib/hdllib.h) | C API, structs, enums |
| [`include/hdllib/pipe_name.h`](../include/hdllib/pipe_name.h) | Pipe naming |
| [`tools/client/main.cpp`](../tools/client/main.cpp) | CLI entry + command dispatch table |
| [`tools/client/cmds_*.cpp`](../tools/client/) | Pipe command handlers by domain |
| [`tools/client/repl.cpp`](../tools/client/repl.cpp) / [`tui.cpp`](../tools/client/tui.cpp) | Interactive REPL / PDCurses TUI |
| [`tools/client/store.cpp`](../tools/client/store.cpp) / [`recipes.cpp`](../tools/client/recipes.cpp) | Interest JSON + discovery recipes |
| [`tools/client/local_inject.cpp`](../tools/client/local_inject.cpp) | Local inject / recommend / early-bird |
| [`README.md`](../README.md) | Build, inject quickstart, API summary |
| [`docs/client.md`](client.md) | CLI / discover / recipe workflows |
