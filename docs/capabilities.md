# hdllib capabilities

Capability reference organized around the named protobuf RPC services in [`services.proto`](../proto/hdl/rpc/v1/services.proto). The named-pipe protocol is the sole remote control surface for an injected `hdllib.dll`. Shared domain types/enums live in [`include/hdllib/hdllib.h`](../include/hdllib/hdllib.h); the complete transport contract is in [rpc.md](rpc.md).

**What it is:** an injectable x64 Windows helper DLL. Once loaded in a target process it provides memory R/W and search, locate/discovery tooling (including reverse xrefs, function resolution, import hooks, access-shaped watch hits, frame-aware ranking, accumulating heat, and session export/import), placement (caves / nearby alloc / protect), pluggable disassembly, stubs and a reversible patch ledger, PE/graph/vtable helpers, hardware and page watchpoints, in-process calls and hooks, health/events, passive process fingerprinting, allocation, and further DLL injection—controllable from outside via a multi-client named pipe (the sole remote control channel). The companion `hdlclient` adds an interest store and orchestration recipes on top of those RPC methods.

**Client workflows** (CLI groups, `discover-*` pipelines, recipes / store): [client.md](client.md).

**Platform:** x64 only (no Wow64 helper). This is the first release protocol: there are no legacy numeric operation identifiers or compatibility modes.

---

## Architecture at a glance

```
┌─────────────────┐     named pipe      ┌──────────────────────────┐
│ hdlclient.exe / │ ◄──────────────────► │ hdllib.dll (in target)   │
│ custom client   │  protobuf envelopes  │  named RPC handlers      │
└─────────────────┘  + bounded frames    │  C API / MinHook / search│
         │                               └──────────────────────────┘
         │ inject (hdlclient inject / HdlInjectDllEx)
         ▼
  target process
```

| Layer | Role |
|-------|------|
| `hdllib.dll` | Loaded in-target; runs IPC server, memory/search/call/hook/place/code/discover logic |
| `hdlclient.exe` | CLI: local multi-technique inject + pipe protocol + interest store & recipes |
| `hdllib.h` | Shared types/status/enums; DLL exports only `HdlHookProc` / `HdlWinEventProc` |
| `proto/hdl/rpc/v1` | Protobuf envelopes and named service/method declarations |
| `protocol.hpp` | Compact domain payload codecs; never method identity |

Pipe name: `HdlFormatPipeName(pid)` → `\\.\pipe\RPCControl_<hash>` ([`pipe_name.h`](../include/hdllib/pipe_name.h)). Override with env `HDL_PIPE` (exact `\\.\pipe\...` path, or the same with one literal pid placeholder such as `%lu` / `%08X`, expanded by replacement — never used as a `swprintf` format). Non-pipe paths and unknown `%` sequences are rejected; the path passed to `CreateFileW` is always rebuilt as `\\.\pipe\` + sanitized name. ACL: SYSTEM, Administrators, and the process user — not Everyone. Multiple concurrent clients are supported.

---

## Framing and encoding

### Handshake

The client writes `HDLRPC1\n` followed by a framed protobuf `ClientHello`. The
server returns `ServerHello` with protocol `1.0`, a random 128-bit server
instance ID that is stable for the loaded server lifetime, generated method
inventory, streaming metadata, and transport limits. An incompatible major fails
negotiation with a clear error.

### Frame layout

Every post-preface message is a length-prefixed protobuf `Envelope`:

| Field | Type | Notes |
|-------|------|--------|
| `size` | `uint32_t` | Payload byte count |
| `payload` | `size` bytes | Serialized `Envelope` containing a hello, named request, response, or `GoAway` |

Implementation: `PipeReadFrame` / `PipeWriteFrame` in `src/ipc/` (facade in `ipc_server.cpp`); client mirror in `tools/client/pipe_client.cpp`.

### Encoding helpers (`hdl::proto`)

| Helper | Wire form |
|--------|-----------|
| `AppendPod` / `TakePod` | Native little-endian POD (`memcpy`) |
| `AppendString` / `TakeString` | `uint32_t byte_len` + NUL-terminated narrow bytes (len includes NUL; empty ⇒ `0`) |
| `AppendWString` / `TakeWString` | `uint32_t byte_len` + UTF-16LE including trailing `L'\0'` (len includes NUL; empty ⇒ `0`) |
| `AppendBytes` | Raw bytes |
| `AppendHdl*` / `TakeHdl*` (`wire.hpp`) | Field-wise LE codecs for public `Hdl*` reply structs (no struct padding on the wire) |

### Compact payload adapter fields

The envelope owns the caller deadline and delivery mode. The current domain
adapter retains a trailing tuple because the in-process handlers share the same
compact field codec:

| Field | Type | Purpose |
|-------|------|---------|
| reserved | `uint64_t` | Must be zero; remote jobs do not exist |
| `timeout_ms` | `uint32_t` | Handler-adapter mirror of `Request.timeout_ms`; zero means no deadline |
| `flags` | `uint32_t` | Handler-adapter streaming flag |

### Streaming replies

When `Request.stream_response` and the compact adapter's `HDL_IPC_REQ_STREAM`
mirror are set for a schema-streaming method, the server writes **multiple
`Response` envelopes**. Each compact chunk (regions/modules/threads/…):

| Field | Type |
|-------|------|
| `status` | `int32_t` |
| `flags` | `uint32_t` — `HDL_IPC_MORE` (1) if more chunks follow |
| `total` | `uint32_t` |
| `offset` | `uint32_t` |
| `count` | `uint32_t` |
| items | `count` records (type depends on the method) |

**Search** streams omit `offset` and use a 64-bit total: `status`, `flags`,
`uint64_t total`, `uint32_t count`, `u64[count]`.

Clients loop until a frame without `HDL_IPC_MORE` (see `PipeClient::RequestStream`).

### Status codes (`HdlStatus`)

| Code | Name | Meaning |
|------|------|---------|
| 0 | `HDL_OK` | Success |
| 1 | `HDL_E_INVALID_ARG` | Bad payload or method argument |
| 2 | `HDL_E_ACCESS` | Access denied |
| 3 | `HDL_E_NOT_FOUND` | Missing session, module, window, etc. |
| 4 | `HDL_E_NO_MEM` | Allocation failure |
| 5 | `HDL_E_BUSY` | Ambiguous target, action already open, etc. |
| 6 | `HDL_E_FAILED` | Generic failure |
| 7 | `HDL_E_BUFFER_SMALL` | Caller buffer too small (C API: `*inout_count` = needed) |
| 8 | `HDL_E_CANCELLED` | Cancelled by a local job/token or abandoned streaming request |
| 9 | `HDL_E_NOT_INIT` | Library not initialized |
| 10 | `HDL_E_TIMEOUT` | Deadline exceeded (callee may still be running on calls) |

---

## Capability map (RPC methods → features)

Method identity comes from `services.proto`. Tables below use the generated
method short name; the fully qualified form is `hdl.rpc.v1.Service/Method`.

### 1. Lifecycle, connectivity, logging

| RPC method | Capability | C API |
|------------|------------|-------|
| `Ping` | Liveness + echo host PID | — (IPC only; `HdlIsInitialized` / `HdlIsIpcRunning` for local) |
| `SetLogLevel` | Set log verbosity | `HdlSetLogLevel` |

**Also (env / bootstrap):** `HDL_LOG_LEVEL`, `HDL_NO_IPC=1`, `HDL_HEALTH_VEH`. Lifecycle prepare is on the pipe as `Shutdown`. Log file and health VEH are named RPC methods (`SetLogFile`, `SetHealthVeh` / `GetHealthVeh`).

Default after inject: log level **off**; health VEH **off** until enabled or first `PollEvents`; IPC starts unless `HDL_NO_IPC`.

**`Ping` reply:** `status`, `uint32_t pid`.

**`SetLogLevel` request:** `int32_t level` (`HDL_LOG_OFF`…`HDL_LOG_DEBUG`).

---

### 2. DLL injection

| RPC method | Capability | C API |
|------------|------------|-------|
| `InjectDll` | Inject another DLL into a process (or self / early-bird) | `HdlInjectDll`, `HdlInjectDllEx` |
| `UnloadDll` | Unload a module-list DLL; optional reload at same path | `HdlUnloadDll` / `HdlUnloadDllEx` |
| `Shutdown` | Restore hooks/patches/watches; optional unload tracked DLLs; stop IPC (DLL stays mapped) | `HdlShutdown` / `HdlShutdownEx` |
| `TrackLoadedDll` | Register a module-list DLL for later `UNLOAD_MODULES` shutdown | `HdlTrackLoadedDll` |

**`InjectDll` request:** `uint32_t pid`, `uint32_t method`, `wstring dll_path`, `wstring exe_path`, `string hook_export`.
**Reply:** `status`, `uint64_t base`, `uint32_t out_pid`.

**`UnloadDll` request:** `uint32_t pid`, `int32_t reload`, `wstring dll_path`.
**Reply:** `status`, `uint64_t base` (new base when `reload != 0`, else 0).  
Remote unload of a module that exports `HdlShutdown` first sends `Shutdown(shutdown_flags)` so instrumentation is restored outside the loader lock.

**`Shutdown` request:** `uint32_t flags` (`HDL_SHUTDOWN_UNLOAD_MODULES = 1` FreeLibrary-tracks registered payloads, never the helper itself). Reply `status`; then the server signals IPC stop without joining the accept thread from the worker. Eject with local `hdlclient unload <pid> <hdllib.dll> [--modules]`.

**`TrackLoadedDll` request:** `uint64_t base`, `wstring dll_path`.

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
| Auto | −1 | `HdlRecommendInject` ranking (C API / `hdlclient inject`; not a separate RPC method) |

**Controller-local (not target-pipe):** target resolve and inject recommend live in `hdl_inject` / `hdlclient inject`. Injector `--stealth` stages a bland temp copy and prefers stealthier techniques on auto.

---

### 3. Memory read / write / enumerate

| RPC method | Capability | C API |
|------------|------------|-------|
| `ReadMemory` | SEH-safe read (max 16 MiB per request) | `HdlReadMemory` |
| `WriteMemory` | SEH-safe write (max 16 MiB) | `HdlWriteMemory` |
| `EnumRegions` | Virtual memory regions | `HdlEnumRegions` |
| `EnumModules` | Loaded modules | `HdlEnumModules` |

**Read request:** `uint64_t address`, `uint32_t size` → reply `status`, `uint32_t got`, bytes.  
**Write request:** `address`, `size`, raw bytes → `status`, `uint32_t wrote`.  
**Enum regions/modules:** non-stream reply `status`, `count`, array of `HdlRegionInfo` / `HdlModuleInfo`. Stream chunks as above (regions chunk 64, modules 16).

`HdlRegionInfo`: base, size, protect, state, type.  
`HdlModuleInfo`: base, size, path\[260\].

---

### 4. Memory search (AOB + Cheat Engine–style incremental)

| RPC method | Capability | C API |
|------------|------------|-------|
| `SearchMemory` | One-shot AOB scan | `HdlSearchMemory` |
| `SearchCreate` | Open incremental session | `HdlSearchCreate` |
| `SearchClose` | Destroy session | `HdlSearchClose` |
| `SearchFirst` | First scan (typed / AOB) | `HdlSearchFirst` |
| `SearchNext` | Refine candidates | `HdlSearchNext` |
| `SearchGetHits` | Dump hit addresses | `HdlSearchGetHits` / `HdlSearchGetCount` |
| `SearchReset` | Clear session state | `HdlSearchReset` |

**AOB syntax:** `"48 8B ?? ?? 90"` (spaces optional; `??` / `?` = wildcard). `start==0 && size==0` ⇒ all committed readable regions.

**Value types (`HDL_VALUE_*`):** bytes (AOB), i8/u8, i16/u16, i32/u32, i64/u64, f32/f64, string, wstring.

**Comparisons (`HDL_CMP_*`):** first scan: `EXACT` or `UNKNOWN`. Next: `CHANGED`, `UNCHANGED`, `INCREASED`/`DECREASED` (+ `_BY`), `GREATER`/`LESS`, `EXACT`. Snapshots of prior values enable change detection.

**Scope flags (`HDL_SEARCH_*`):** `IMAGE`, `EXECUTABLE`, `MODULE` (+ module name).

**IPC sessions:** server maps `uint64_t session_id` → `HdlSearchSession*` (create returns id). The request envelope supplies an optional cooperative deadline; zero means unlimited.

**`SearchMemory` / `SearchFirst` / `SearchGetHits` support response streaming.** Hits are produced into a bounded in-DLL buffer (4096 addresses); when full the scan blocks on pipe backpressure until the client drains it. Compact chunks carry `status`, `flags(MORE)`, `total:u64` (0 until final), `count`, and `u64[count]` (append in order). The final chunk clears `MORE` and carries the true total. `max_hits` / `max_results` 0 = unlimited; nonzero = optional early stop. `hdlclient` writes unlimited results to a controller-owned candidate file and retains only a 64-address preview in memory. AOB is always byte-unaligned; typed `alignment` 0 = natural, 1 = unaligned.
**`SearchNext`:** `session`, `cmp`, `value_len` + bytes plus compact adapter fields → `status`, `count` (then use GetHits to stream survivors).

---

### 5. Cooperative deadlines

`Request.timeout_ms` applies a cooperative deadline to the named RPC. Zero means
no deadline, including for all search methods. The local C API retains
`HdlJobCreate` / `HdlJobCancel` / `HdlJobClose` for in-process composition, but
jobs are not remotely addressable and are not RPC methods.

---

### 6. Process / thread health and events

| RPC method | Capability | C API |
|------------|------------|-------|
| `GetHealth` | Snapshot: CPU, WS, hang, last exception | `HdlGetHealth` |
| `EnumThreads` | Thread list | `HdlEnumThreads` |
| `PollEvents` | Drain exception / health / job / hook wake-ups | `HdlPollEvents` |

**Health flags:** `GUI_HUNG`, `HIGH_CPU`, `RECENT_EXCEPTION`. Optional VEH (`HdlSetHealthVeh` / `HDL_HEALTH_VEH`) feeds exception events.

**Events (`HDL_EVENT_*`):** `EXCEPTION`, `HEALTH`, `JOB_DONE`, `HOOK` (wake only; full payload via `PollHookHits`), `WATCH` (wake only; full payload via `PollWatchHits` when armed).

**`PollEvents`:** `max_events`, `timeout_ms` (0 = non-blocking) → `status`, `count`, `HdlEvent[]` (max clamped to 64).

---

### 6b. Process fingerprint

| RPC method | Capability | C API |
|------------|------------|-------|
| `Fingerprint` | Passive tags: language/runtime/UI/graphics/engine/… from modules + main IAT + PE subsystem | `HdlEnumFingerprintTags`, `HdlClassifyFingerprint` |

**Request:** `uint32_t scan_flags` (`HDL_FP_SCAN_MODULES` / `IMPORTS` / `PE`; `0` or omit → `HDL_FP_SCAN_DEFAULT`). Streaming delivery is selected by the request envelope.

**Response:** `status`, `count`, `HdlFingerprintTag[]` (or streamed like modules). Each tag: `category`, `confidence` 0–100, `flags` (`FROM_MODULE` / `FROM_IMPORT` / `FROM_PE` / `PRIMARY`), `id`, `evidence`.

`HdlClassifyFingerprint` classifies caller-provided module basenames + import pairs (tests / offline dumps; no process walk). Active probes (`HDL_FP_ACTIVE`) are reserved.

CLI: `hdlclient <pid> fingerprint`; `hdlclient --store PATH <pid> recipe suggest` prints next-step watch/call hints from primaries.

---

### 7. Address resolution helpers

| RPC method | Capability | C API |
|------------|------------|-------|
| `ResolveExport` | `GetProcAddress`-style resolve | `HdlResolveExport` |
| `ResolveRip` | RIP-relative decode | `HdlResolveRipRelative` |
| `FollowPointers` | Multilevel pointer chain | `HdlFollowPointers` |
| `ModuleBase` | Module base (null/empty = main EXE) | `HdlModuleBase` |

Typical LEA/CALL/JMP: `disp_offset=3`, `instr_len=7` (or 1/5 for near call/jmp). Pointer follow: start at `base`, repeatedly read pointer and add `offsets[i]` (IPC allows up to 64 offsets).

---

### 8. In-process calls (export / absolute / vtable)

| RPC method | Capability | C API |
|------------|------------|-------|
| `CallExport` | Resolve export + call (worker thread) | `HdlCallExport` |
| `Call` | Absolute address call | `HdlCall` |
| `CallVtable` | `(*obj)[index]` then call | `HdlCallVtable` |

Microsoft x64 ABI, up to **16** arguments. Arg kinds (`HDL_CALL_ARG_*`): `U64`, `I64`, `PTR`, `BUF` (copy-in/out), `CSTR`, `WSTR`, `F32`, `F64` (IEEE bits in `u64`).

Thread modes: `WORKER` (default helper thread) or `MAIN` (sync on primary UI HWND; fails if none / console-only).

**IPC arg encoding (each):** `int32_t kind`, `uint32_t size`, `uint64_t u64` \[+ for BUF/CSTR/WSTR: `uint32_t blob_len` + bytes\]. PTR uses `u64` as the pointer value.

**Call reply:** `status`, `HdlCallResult` (`return_value`, `last_error`), then for Call/CallExport: `buf_n` and per-BUF `(index, size, bytes)` copy-outs. On timeout/cancel the callee may still be running.

**`CallVtable` extras:** `obj`, `index`, `arg_count`, `prepend_this`, `thread_mode`, `timeout_ms`, a reserved zero field, then args. When `prepend_this != 0`, a synthetic `this` is prepended if missing. The envelope deadline is authoritative for remote calls.

---

### 9. Durable scratch allocation

| RPC method | Capability | C API |
|------------|------------|-------|
| `Alloc` | Tracked `VirtualAlloc` | `HdlAlloc` |
| `Free` | Free prior alloc | `HdlFree` |

**Alloc:** `uint64_t size`, `uint32_t protect` (`PAGE_*`) → `status`, `addr`. Useful for remote call buffers that must outlive a single call’s temp copies.

---

### 10. Hooks (MinHook + capture/trace)

| RPC method | Capability | C API |
|------------|------------|-------|
| `HookTrace` | Install capture-only hook (≤8 int-view args + return + caller) | `HdlHookTrace` |
| `EnableHook` | Enable/disable | `HdlEnableHook` |
| `Unhook` | Remove hook | `HdlUnhook` |
| `PollHookHits` | Drain hit queue | `HdlPollHookHits` |
| `HookImport` | Resolve PE import (DLL+name) → `HookTrace` on `bound_va` | `HdlHookImport` |

**Custom detours over the pipe:** `Hook` (`target_va`, `detour_va` → handle + trampoline). Default exports for inject: `HdlHookProc`, `HdlWinEventProc`.

Trace hooks call the original, enqueue `HdlHookHit` (incl. `frame_count` + `frames[8]`), and wake `PollEvents` with `HDL_EVENT_HOOK`. Handle is the target address as `uint64_t`. Trampolines live while `hdllib.dll` remains loaded.

**Import hook:** `HdlHookImport(module_or_null, dll_name, import_name, arg_count, out)` walks `EnumImports`, matches case-insensitive DLL basename + import name, then `HookTrace` on the current IAT `bound_va` (no IAT rewrite in v1). Client: `hook-import KERNEL32.dll!GetCurrentProcessId` or `--dll` / `--import`.

---

### 11. Locate (signatures, xrefs, pointer scan, struct probe)

| RPC method | Capability | C API |
|------------|------------|-------|
| `ResolvePattern` | AOB → optional RIP + multilevel follow → abs/RVA | `HdlResolvePattern` |
| `FindStringXrefs` | String → absolute / RIP-relative xrefs | `HdlFindStringXrefs` |
| `PointerScan` | CE-style static pointer paths to a target | `HdlPointerScan` |
| `ProbeStruct` | Heuristic field kinds over a byte range (≤4096) | `HdlProbeStruct` |

**Pattern resolve:** pick Nth AOB hit, add `pattern_offset`, optionally decode RIP (`rip_disp_offset` / `rip_instr_len`), then follow offsets. Scope via `HDL_SEARCH_*`. Result: `match_addr`, `resolved_addr`, `module_base`, `rva`.

**Xref flags:** `HDL_XREF_ABSOLUTE`, `HDL_XREF_RIP_REL`.

**Pointer path:** `static_base` + up to 8 offsets; typically scan with `HDL_SEARCH_IMAGE`.

**Struct field kinds:** unknown, ptr, vtable (ptr into executable image), ascii, float, int32, int64.

---

### 12. Discover (automated find / stabilize / expand)

Session-based pipeline: seed candidates → constraint / action evidence → stabilize with AOB synthesis or pointer-path consensus → cluster related objects → optional JSON export/import and field promotion from watches.

| RPC method | Capability | C API |
|------------|------------|-------|
| `DiscoverCreate` | Open discover session | `HdlDiscoverCreate` |
| `DiscoverClose` | Close session | `HdlDiscoverClose` |
| `DiscoverAddCandidate` | Manually seed address/function/object/field | `HdlDiscoverAddCandidate` |
| `DiscoverConstraintScan` | Find object bases matching field predicates | `HdlDiscoverConstraintScan` |
| `DiscoverSynthesizePattern` | Build module-unique AOB for a candidate | `HdlDiscoverSynthesizePattern` |
| `DiscoverPathConsensus` | Pointer-scan + keep paths that still resolve | `HdlDiscoverPathConsensus` |
| `DiscoverPathValidate` | Filter path list against expected target | `HdlDiscoverPathValidate` |
| `DiscoverWatch` | HookTrace a function for action ranking | `HdlDiscoverWatch` |
| `DiscoverUnwatchAll` | Remove watches | `HdlDiscoverUnwatchAll` |
| `DiscoverActionBegin` | Open named action window | `HdlDiscoverActionBegin` |
| `DiscoverActionEnd` | Close action; associate hits / diffs | `HdlDiscoverActionEnd` |
| `DiscoverWatchRegion` | Register region for change-heat | `HdlDiscoverWatchRegion` |
| `DiscoverGetHeat` | Per-offset change heat after actions | `HdlDiscoverGetHeat` |
| `DiscoverRankFunctions` | Rank functions seen during an action | `HdlDiscoverRankFunctions` |
| `DiscoverClusterType` | Find other objects with same vtable@0 | `HdlDiscoverClusterType` |
| `DiscoverGetCandidates` | Dump candidate list | `HdlDiscoverGetCandidates` |
| `DiscoverWatchImport` | HookImport + register on session watches | `HdlDiscoverWatchImport` |
| `DiscoverResetHeat` | Clear accumulated heat for a watched base | `HdlDiscoverResetHeat` |
| `DiscoverExport` | Serialize session → UTF-8 JSON (≤4 MiB) | `HdlDiscoverExport` |
| `DiscoverImport` | Best-effort restore candidates from JSON | `HdlDiscoverImport` |
| `DiscoverDiffObjects` | Bytewise multi-instance field diffs | `HdlDiscoverDiffObjects` |
| `DiscoverApplyWatchHits` | Promote watch hits in a range → `FIELD` cands | `HdlDiscoverApplyWatchHits` |
| `DiscoverGetEvidence` | UTF-8 provenance string for a candidate id | `HdlDiscoverGetCandidateEvidence` |

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

**Discover typed scan:** the named `Discover/DiscoverScanValue` method backs `hdlclient discover-scan`.

---

### 13. Place (caves, nearby alloc, protect)

| RPC method | Capability | C API |
|------------|------------|-------|
| `FindCaves` | Search for fill-byte padding near a VA | `HdlFindCaves` |
| `AllocNear` | `VirtualAlloc` within ±`max_distance` of a hint | `HdlAllocNear` |
| `ProtectMemory` | `VirtualProtect` wrapper | `HdlProtectMemory` |
| `FlushICache` | Flush instruction cache for a range | `HdlFlushICache` |

**Cave query:** `min_size`, `fill_byte` (often `0xCC` / `0x00`), `near_addr`, `max_distance`, `search_flags` / module, `max_results`. Reply: cave `addr` + `size` list. Client recipes score caves (nearer first, then larger size).

**AllocNear:** `near`, `max_distance`, `size`, `protect` → tracked address (free with `Free`).

---

### 14. Disassembly backends

| RPC method | Capability | C API |
|------------|------------|-------|
| `DisasmEnumBackends` | List registered engines | `HdlDisasmEnumBackends` |
| `DisasmGetBackend` | Active backend id | `HdlDisasmGetBackend` |
| `DisasmSetBackend` | Select Zydis / Capstone / custom | `HdlDisasmSetBackend` |

Built-in: **Zydis** (default) and **Capstone**. Remote surface is Enum/Get/Set only (no custom-engine registration over the pipe).

---

### 15. Code (instr length, disasm, stubs, patch ledger)

| RPC method | Capability | C API |
|------------|------------|-------|
| `InstrLen` | Length of one insn at VA | `HdlInstrLen` |
| `Disasm` | Decode up to N insns | `HdlDisasm` |
| `BuildStub` | Emit trampoline / jmp template | `HdlBuildStub` |
| `PatchCreate` | Record bytes + original for undo | `HdlPatchCreate` |
| `PatchEnable` | Apply / restore patch | `HdlPatchEnable` |
| `PatchRemove` | Drop ledger entry | `HdlPatchRemove` |
| `PatchEnum` | List patches | `HdlPatchEnum` |

**Stub kinds (`HDL_STUB_*`):** `ABS_JMP`, `REL_JMP32`, `MOV_RAX_JMP`, `RAW` (caller hex). Optional `steal_from` / `steal_min_bytes` copies prologue bytes; `alloc_rx` allocates an RX stub VA.

**Patch ledger:** create with target VA + bytes + optional name → handle; enable writes bytes (with protect + I-cache flush); disable restores original; enum lists handles.

---

### 16. PE metadata

| RPC method | Capability | C API |
|------------|------------|-------|
| `EnumSections` | Section table for a module | `HdlEnumSections` |
| `EnumExports` | Export names / RVAs | `HdlEnumExports` |
| `EnumImports` | Import DLL+name / IAT | `HdlEnumImports` |

`module_base_or_0 == 0` ⇒ main EXE image.

---

### 17. Bounded function / xref graph

| RPC method | Capability | C API |
|------------|------------|-------|
| `EnumFunctions` | Heuristic function starts in a range / module | `HdlEnumFunctions` |
| `XrefsFrom` | Outgoing call/jmp(/data) edges from a seed | `HdlXrefsFrom` |
| `ResolveFunction` | Align any interior VA → containing function (`start`/`end`/confidence/flags) | `HdlResolveFunction` |
| `XrefsTo` | Incoming call/jmp(/data) sites targeting an address | `HdlXrefsTo` |
| `InvalidateFnIndex` | Drop process-local function index cache | `HdlInvalidateFunctionIndex` |

`ResolveFunction` prefers compiler-authored x64 unwind ranges (confidence **100**) and accepts any interior byte address, including a post-watchpoint RIP. Its fallback and `EnumFunctions` use the active disassembler: export **90** (`HDL_FN_EXPORT`), call target **75** (`HDL_FN_CALLED`), and narrowly matched prologue **45** (`HDL_FN_PROLOGUE`); conditional/local jump targets are not function starts. Heuristic ends prefer ret / `int3` padding / next start, and the fallback index is cached per `(module_base, SizeOfImage)`.

**XrefsTo kinds:** `HDL_XREF_CALL|JMP|DATA`; with `HDL_XREF_FUNC` (8) also match branches into `[fn.start, fn.end)`. Client: `resolve-function`, `xrefs-to` (`--exact` drops `FUNC`), `invalidate-fn-index`.

---

### 18. Observe (vtable / RTTI)

| RPC method | Capability | C API |
|------------|------------|-------|
| `WalkVtable` | Walk slots until non-code | `HdlWalkVtable` |
| `QueryRttiName` | Best-effort MSVC type name | `HdlQueryRttiName` |

`is_object != 0` treats the address as an object (read vptr at +0); else as a vtable pointer. RTTI may return `HDL_E_NOT_FOUND` when COL / type_info is absent.

---

### 19. Watchpoints (hardware + page)

| RPC method | Capability | C API |
|------------|------------|-------|
| `WatchHw` | DR0–3 breakpoint (tracked free-slot allocation) | `HdlWatchHw` |
| `WatchPage` | `PAGE_GUARD` or `PAGE_NOACCESS` | `HdlWatchPage` |
| `Unwatch` | Remove watch (clears stored DR index) | `HdlUnwatch` |
| `EnumWatches` | List active watches | `HdlEnumWatches` |
| `WatchRefresh` | Re-apply all HW watches to current threads | `HdlWatchRefresh` |
| `PollWatchHits` | Drain `HdlWatchHit` queue (cap 256) | `HdlPollWatchHits` |

**HW:** size `1|2|4|8`, access `exec|write|rw`, optional `tid` (0 = best-effort all threads). At most **4** concurrent HW watches.  
**Page:** size region + mode `guard|noaccess`.  
**Hits:** VEH only enqueues for registered watches. `HDL_EVENT_WATCH` is **wake-only** (like `HDL_EVENT_HOOK`); full payload is `HdlWatchHit` (`watch_handle`, `rip`, `accessed`, `size`, `tid`, …) via `PollWatchHits`. Client: `watch hw|page|list|unwatch|hits|refresh`.

---

## RPC service index

The schema groups methods by domain. Method names, rather than assigned numbers, are the public protocol identity.

| Service | Capability group |
|---------|------------------|
| `Control` | Connectivity, logging, health, lifecycle, events |
| `Process` | Process fingerprint, modules, regions, threads |
| `Memory` | Read, write, allocate, protect, and placement |
| `Search` | Stateless and stateful memory search |
| `Call` | Exports, calls, and vtable calls |
| `Hook` | Function/import hooks and hit polling |
| `Locate` | Patterns, pointer paths, xrefs, and probes |
| `Discover` | Discovery sessions, ranking, evidence, and import/export |
| `Code` | Disassembly, stubs, patches, PE metadata, and function graph |
| `Watch` | Hardware/page watches and hit polling |
| `Injection` | DLL injection, unload, and tracking |

---

## Place / code / PE / graph / watch

In-process placement and analysis surface:

- **Caves / AllocNear / Protect / FlushICache** — executable padding search, nearby scratch, protect + I-cache flush
- **Disasm backends** — pluggable Zydis + Capstone (runtime select via Enum/Get/Set); no remote custom-engine registration
- **InstrLen / Disasm / BuildStub / Patch ledger** — decode, trampoline emit, reversible patches
- **PE sections / exports / imports** — mapped-image metadata
- **EnumFunctions / XrefsFrom / ResolveFunction / XrefsTo / InvalidateFunctionIndex** — unwind-aligned x64 resolution plus bounded fallback index (export/call/prologue confidence, ret-based ends, process-local cache) and outbound/inbound edges (`HDL_XREF_CALL|JMP|DATA|FUNC`)
- **WalkVtable / QueryRttiName** — MSVC RTTI best-effort
- **WatchHw / WatchPage / Unwatch / EnumWatches / WatchRefresh / PollWatchHits** — DR breakpoints (tracked slots) and page guards; `HDL_EVENT_WATCH` is wake-only; full `HdlWatchHit` payload via `PollWatchHits`
- **HookImport** — one-shot IAT sink tracing
- **Discover WatchImport / ResetHeat / Export / Import / DiffObjects / ApplyWatchHits / GetEvidence** — import watches, layout heat, session JSON, field promotion

Hook hits include `frame_count` + `frames[8]` (stack capture) for frame-aware discover ranking.

Controller-local (not target-pipe RPC methods):

- **Inject method ranking** — `hdlclient inject --recommend` / `--method auto` (`hdl_inject`)
- **Target resolution** — pid + window title substring / class (`hdl_inject`)

In-process lifecycle prepare is on the pipe: `Shutdown` / `hdlclient <pid> shutdown [--modules]`.

**Client-side orchestration (no new DLL RPC method):**

- **Interest store + recipes** — JSON locators and `recipe place` / `stitch` / `expand` / discover recipes (see [Interest store and recipes](#interest-store-and-recipes-client-only))

Full inject technique notes: [docs/inject/](inject/README.md). Future ideas: [docs/future/](future/README.md).

---

## CLI ↔ capability mapping (`hdlclient`)

| Command area | RPC methods used |
|--------------|------------------|
| `ping`, `log`, `log-file`, `health-veh` | Ping, SetLogLevel, SetLogFile, Set/GetHealthVeh |
| `hook` | Hook (target_va + detour_va) |
| `shutdown` | Shutdown (optional `--modules`) |
| `inject` (pipe + `hdlclient inject`) | InjectDll / local inject |
| `read`, `write` | ReadMemory, WriteMemory |
| `regions`, `modules`, `threads` | Enum* (+ stream) |
| `scan` / `--next` / `--hits` | SearchMemory or Search* session |
| `health`, `fingerprint`, `events` | GetHealth, Fingerprint, PollEvents |
| `call` / `vcall` / `resolve` | Call, CallExport, CallVtable, ResolveExport |
| `alloc` / `free` / `alloc-near` | Alloc, Free, AllocNear |
| `caves` / `protect` / `flush-icache` / `alloc-near` | FindCaves, Protect, FlushICache, AllocNear |
| `disasm-backend` / `disasm` / `instrlen` / `stub` | Enum/Get/SetDisasmBackend, InstrLen, Disasm, BuildStub |
| `patch` (`list`/`create`/`enable`/`disable`/`remove`) | Patch ledger methods |
| `sections` / `exports` / `imports` | EnumSections, EnumExports, EnumImports |
| `functions` / `xrefs-from` / `resolve-function` / `xrefs-to` / `invalidate-fn-index` | Function graph methods |
| `vtable` / `rtti` | WalkVtable, QueryRttiName |
| `watch` (`hw`/`page`/`list`/`unwatch`/`hits`/`refresh`) | Watch methods |
| `rip`, `ptrchain`, `modbase` | ResolveRip, FollowPointers, ModuleBase |
| `hooktrace`, `hook-import`, `hook-enable`/`enablehook`, `unhook`, `hookhits` | HookTrace, HookImport, EnableHook, Unhook, PollHookHits |
| `resolve-pattern`, `xrefs`, `ptrscan`, `probe` | Locate methods |
| `discover-*` (incl. `discover-pathvalidate`, `discover-scan`, `discover-watch-import`, `discover-reset-heat`, `discover-export`/`import`, `discover-diff`, `discover-apply-watch`, `discover-evidence`) | Discover methods (+ scan composition) |
| `hdlclient <pid> <verb>` / `session` / `store` / `recipe` / `stabilize` | One-shot controller (all pipe cmds + store/recipes) |
| `store` / `recipe` / `stabilize` | Interest JSON + discover recipes (`--store` required for mutators) |

Call arg prefixes: `u64:`, `i64:`, `f32:`, `f64:`, `cstr:`, `wstr:`, `buf:HEX`, `ptr:HEX`. Scan scope: `--image`, `--executable`, `--module NAME`.

### Interest store and recipes (client-only)

`hdlclient` persists addresses as **interests** in a JSON file (`--store PATH`). Schema **version 3** (Save always writes ≥3; older files still load; unknown locator types are skipped with a warning).

**Locator types:** `pattern`, `path`, `export`, `import`, `cave`, `stub`, `patch` — revalidate via ResolvePattern / FollowPointers / ResolveExport / EnumImports / FindCaves / BuildStub / address-only for patches.

**Recipes:** `place`, `stitch`, `expand`, `action` (`--wait-ms`/`--signal FILE`), `constrain`, plus `stabilize <cand_id>`.

Full workflows, predicate syntax, and end-to-end examples: **[client.md § Interest store and recipes](client.md#4-interest-store-and-recipes)**.

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
| [`src/protocol.hpp`](../src/protocol.hpp) | RPC method enum, stream flags, encode/decode |
| [`src/ipc_server.hpp`](../src/ipc_server.hpp) / [`src/ipc_server.cpp`](../src/ipc_server.cpp) | Public IPC start/stop + frame helpers |
| [`src/ipc/`](../src/ipc/) | Server loop, framing, dispatch, handlers by domain |
| [`include/hdllib/hdllib.h`](../include/hdllib/hdllib.h) | C API, structs, enums |
| [`include/hdllib/pipe_name.h`](../include/hdllib/pipe_name.h) | Pipe naming |
| [`tools/client/main.cpp`](../tools/client/main.cpp) | CLI entry + command dispatch table |
| [`tools/client/cmds_*.cpp`](../tools/client/) | Pipe command handlers by domain |
| [`tools/client/cmds_controller.cpp`](../tools/client/cmds_controller.cpp) | session/store/recipe/stabilize |
| [`tools/client/store.cpp`](../tools/client/store.cpp) / [`recipes.cpp`](../tools/client/recipes.cpp) | Interest JSON + discovery recipes |
| [`tools/client/local_inject.cpp`](../tools/client/local_inject.cpp) | Local inject / recommend / early-bird |
| [`README.md`](../README.md) | Build, inject quickstart, API summary |
| [`docs/client.md`](client.md) | CLI / discover / recipe workflows |
