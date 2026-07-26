# hdllib

Injectable x64 helper DLL for Windows. Load it into a target process to get memory search, module/region/PE enumeration, code caves and nearby alloc, pluggable disassembly (Zydis/Capstone), stubs and a reversible patch ledger, function/xref heuristics, vtable/RTTI helpers, hardware and page watchpoints, DLL injection, MinHook-based function hooks (including capture/trace hooks with stack frames), process/thread health, in-process calls (absolute address / export / vtable, floats, UI-thread dispatch), address helpers, durable scratch alloc, and a multi-client named-pipe control channel—plus the same surface as a stable exported C API. `hdlclient` adds an interest store and place/stitch/discover recipes on top.

Capability reference (opcodes **1…91** plus **`OpUnloadDll` = 92** from `protocol.hpp`, wire formats, place/code/observe, store/recipes): [docs/capabilities.md](docs/capabilities.md). CLI / discover / recipe workflows: [docs/client.md](docs/client.md).

## Build

Requirements: Visual Studio 2019+ Build Tools (MSVC x64), CMake, Ninja (or the VS generator). MinHook v1.3.3 is vendored under `third_party/minhook`. With `HDL_CLIENT_TUI=ON` (default), CMake FetchContent pulls PDCurses 3.9 for `hdlclient --tui`. Zydis and Capstone are fetched for the disasm backends.

```bat
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
set CMAKE="C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"

%CMAKE% --preset x64-windows-vs
%CMAKE% --build --preset x64-windows-vs --config Release
```

Artifacts land under `build/x64-windows-vs/Release/`:

- `hdllib.dll` — inject this
- `hdlclient.exe` — inject + IPC CLI / REPL / optional TUI

Ninja preset (`x64-windows`) works the same if `ninja` is on `PATH` after `vcvars64`.

## Inject and talk

```bat
hdlclient inject <pid> C:\full\path\to\hdllib.dll
hdlclient inject <pid> C:\full\path\to\hdllib.dll --method nt_create_thread_ex
hdlclient inject <pid> C:\full\path\to\hdllib.dll --method auto
hdlclient inject <pid> C:\full\path\to\hdllib.dll --stealth
hdlclient inject --recommend <pid> C:\full\path\to\hdllib.dll
hdlclient inject --title Notepad --class Notepad C:\full\path\to\hdllib.dll
hdlclient inject --early-bird C:\Windows\System32\notepad.exe C:\full\path\to\hdllib.dll
hdlclient <pid> ping
hdlclient <pid> modules
hdlclient <pid> scan --pattern "48 8B ?? 90" --max 32
hdlclient <pid> scan --type i32 --value 100 --max 64
hdlclient <pid> scan --next --session 1 --cmp decreased
hdlclient <pid> scan --next --session 1 --type i32 --cmp exact --value 90
hdlclient <pid> read 0x7FF6ABCD0000 64
hdlclient <pid> write 0x7FF6ABCD0000 90 90 90 90
hdlclient <pid> caves --near 0x7FF6ABCD1000 --min 16 --image
hdlclient <pid> alloc-near 0x7FF6ABCD1000 64
hdlclient <pid> disasm-backend list
hdlclient <pid> disasm 0x7FF6ABCD1000 --max 8
hdlclient <pid> stub --kind mov_rax_jmp --target 0x7FF6ABCD1000 --alloc
hdlclient <pid> patch create 0x7FF6ABCD2000 90 90 90 90 90 --name nop5
hdlclient <pid> patch enable 1
hdlclient <pid> watch hw 0x7FF6ABCD3000 --size 8 --access write
hdlclient <pid> watch page 0x7FF6ABCD3000 4096 --mode guard
hdlclient <pid> sections
hdlclient <pid>                       REM interactive REPL (default)
hdlclient <pid> repl --store interests.json
hdlclient <pid> --tui --store interests.json
```

Typed scan `--type` values: `bytes`, `i8`/`u8`, `i16`/`u16`, `i32`/`u32`, `i64`/`u64`, `f32`/`float`, `f64`/`double`, `string`, `wstring`. Comparison modes (`--cmp`): `exact`, `unknown`, `changed`, `unchanged`, `increased`, `decreased`, `increased_by`, `decreased_by`, `greater`, `less`. First scan creates a session id (printed); `--next` / `--hits` / `--close` reuse it.

Stub kinds: `abs_jmp`, `rel_jmp32`, `mov_rax_jmp`, `raw` (DLL templates — no text assembler).

### Interactive controller (REPL / TUI)

`hdlclient <pid>` (or `repl`) opens a line REPL over the pipe. All one-shot pipe verbs work; extras include `store`, `recipe`, `stabilize`, and `session`. `--tui` is a PDCurses full-screen UI (log + interests panes; recipe prefills on `a`/`c`/`p`/`t`/`x`). Build with `HDL_CLIENT_TUI=ON` (default).

Workflows for CLI groups, `discover-*` pipelines, and recipes: **[docs/client.md](docs/client.md)**.

### Injection methods

Implementations live under `src/inject/` (one file per technique). Full notes: [docs/inject/](docs/inject/README.md).

| Method | Flag | Notes |
|--------|------|--------|
| Auto-select | `auto` | Probe + confidence ranking ([selection.md](docs/inject/selection.md)) |
| `CreateRemoteThread` | `create_remote_thread` (default) | Classic `LoadLibraryW` |
| `NtCreateThreadEx` | `nt_create_thread_ex` | ntdll remote thread |
| `RtlCreateUserThread` | `rtl_create_user_thread` | ntdll remote thread |
| `QueueUserAPC` | `queue_user_apc` | Needs an alertable thread |
| `SetWindowsHookEx` | `set_windows_hook_ex` | Needs a window; DLL exports hook (`HdlHookProc` by default) |
| Thread hijack | `thread_hijack` | Suspend + `SetThreadContext` stub |
| Manual map | `manual_map` | PE map without `LoadLibrary` module list entry |
| Early Bird APC | `early_bird_apc` / `--early-bird` | Suspended process + APC |
| AtomBombing | `atom_bombing` | Global atom + APC stub (path ≤ 255) |
| Module stomp | `module_stomp` | Stomp sacrificial DLL entry |
| Section map | `section_map` | `NtCreateSection` + map + `LoadLibraryW` |
| Window subclass | `window_subclass` | `GWLP_WNDPROC` stub |
| Instrumentation callback | `instrumentation_callback` | `NtSetInformationProcess` callback |
| Kernel callback table | `kernel_callback_table` | PEB `KernelCallbackTable` hijack |
| VEH | `veh` | Vectored exception handler + `DebugBreak` |
| SetWinEventHook | `set_win_event_hook` | In-context win-event hook (`HdlWinEventProc`) |
| RtlRemoteCall | `rtl_remote_call` | Undocumented ntdll remote call |
| Special user APC | `special_user_apc` | `NtQueueApcThreadEx2` special APC |
| Thread pool | `thread_pool` | `TpAllocWork` / `TpPostWork` |
| ETW callback | `etw_callback` | `EtwEventRegister` enable-callback |

Pipe: `HdlFormatPipeName(pid)` → `\\.\pipe\RPCControl_<hash>` (see `include/hdllib/pipe_name.h`). Override with env `HDL_PIPE` (exact path, or a `swprintf` format with `%lu` for the pid).

Quiet / anti-fingerprint defaults after inject:

- Log level **off** (set `HDL_LOG_LEVEL=0..3` or `HdlSetLogLevel`)
- Health **VEH off** until `HdlSetHealthVeh(1)`, `HDL_HEALTH_VEH=1`, or first `HdlPollEvents`
- Optional skip IPC: `HDL_NO_IPC=1` (then call `HdlStartIpc` yourself)
- `--stealth` on inject: stage a bland `%TEMP%\drvstore_*.dll` copy and prefer `manual_map` / `module_stomp` on auto

Logs go to `OutputDebugString` when enabled (view with DebugView). Optional file sink via `HdlSetLogFile`.

## Exported C API

Link against `hdllib.lib` / include `hdllib/hdllib.h`:

| Export | Purpose |
|--------|---------|
| `HdlInit` / `HdlShutdown` | Lifecycle (auto-started after inject) |
| `HdlInjectDll` | Default `CreateRemoteThread` inject (`pid==0` = in-process) |
| `HdlInjectDllEx` | Same with method / early-bird exe / hook export (`HDL_INJECT_AUTO` picks) |
| `HdlUnloadDll` | `FreeLibrary` unload; optional reload at the same path |
| `HdlResolveTarget` | Resolve PID/HWND from pid and/or window title/class |
| `HdlRecommendInject` | Rank methods with confidence (no inject) |
| `HdlHookProc` | Default `SetWindowsHookEx` callback |
| `HdlReadMemory` / `HdlWriteMemory` | SEH-safe copies |
| `HdlEnumRegions` / `HdlEnumModules` | Fill-buffer enumeration |
| `HdlSearchMemory` | IDA-style AOB (`"48 8B ?? ?? 90"`) |
| `HdlSearchCreate` / `HdlSearchClose` / `HdlSearchReset` | Incremental search session |
| `HdlSearchFirst` / `HdlSearchNext` | Typed first scan + refine (exact / changed / increased / …) |
| `HdlSearchGetCount` / `HdlSearchGetHits` | Read session candidate addresses |
| `HdlGetHealth` / `HdlEnumThreads` | Process/thread health (GUI hang, CPU, VEH last exception) |
| `HdlPollEvents` | Drain exception/health/hook/watch wake-ups (optional wait) |
| `HdlJobCreate` / `HdlJobCancel` / `HdlJobClose` | Cross-client cancel + deadline tokens |
| `HdlAlloc` / `HdlFree` / `HdlAllocNear` | Tracked scratch (+ nearby VA) |
| `HdlFindCaves` / `HdlProtectMemory` / `HdlFlushICache` | Code caves, protect, I-cache flush |
| `HdlDisasmEnumBackends` / `Get` / `Set` / `Register` / `Unregister` | Pluggable Zydis/Capstone (+ custom C-API backends) |
| `HdlInstrLen` / `HdlDisasm` / `HdlBuildStub` | Decode + trampoline templates |
| `HdlPatchCreate` / `Enable` / `Remove` / `Enum` | Reversible patch ledger |
| `HdlEnumSections` / `Exports` / `Imports` | PE metadata |
| `HdlResolveRipRelative` / `HdlFollowPointers` / `HdlModuleBase` | Signature → address helpers |
| `HdlResolvePattern` | AOB + optional RIP/follows → abs/RVA |
| `HdlFindStringXrefs` | String → absolute / RIP-relative xrefs |
| `HdlPointerScan` | CE-style static pointer paths to a target |
| `HdlProbeStruct` | Heuristic field classification over a range |
| `HdlEnumFunctions` / `HdlResolveFunction` / `HdlInvalidateFunctionIndex` | Function index (confidence/flags/ends + cache) |
| `HdlXrefsFrom` / `HdlXrefsTo` | Outbound / inbound call·jmp·data edges |
| `HdlWalkVtable` / `HdlQueryRttiName` | Vtable walk + best-effort MSVC RTTI |
| `HdlDiscover*` | Discover sessions: constraints, sig synth, path consensus, action windows, accumulating heat, frame-aware rank, type cluster, import watch, object diff, watch→fields, evidence, JSON export/import |
| `HdlResolveExport` / `HdlCall` / `HdlCallExport` / `HdlCallVtable` | In-process calls (≤16 args, F32/F64, BUF inout, worker or UI thread) |
| `HdlHook` / `HdlEnableHook` / `HdlUnhook` | MinHook wrappers |
| `HdlHookTrace` / `HdlHookImport` / `HdlPollHookHits` | Capture-only hooks, IAT-sink hook, hit queue |
| `HdlWatchHw` / `HdlWatchPage` / `HdlUnwatch` / `HdlEnumWatches` / `HdlWatchRefresh` / `HdlPollWatchHits` | HW/page watches + refresh + hit queue (`HDL_EVENT_WATCH` = wake) |
| `HdlStartIpc` / `HdlStopIpc` | Named-pipe server control |
| `HdlSetHealthVeh` | Opt-in exception VEH for health events |
| `HdlSetLogLevel` / `HdlSetLogFile` | Logging |

Hook trampolines live as long as `hdllib.dll` remains loaded. `HdlCall` with `HDL_CALL_THREAD_MAIN` posts to the process primary HWND (console windows skipped); returns `HDL_E_NOT_FOUND` if none.

## IPC protocol

Length-prefixed frames: `uint32_t size` + payload. Payload starts with `uint32_t opcode`; reply starts with `int32_t status`. Opcodes **1…91** (+ **92** unload) mirror the C API (ping, inject, unload, read/write, enum, search, jobs, health, events, resolve/call, alloc, rip/ptrchain, hooks, locate, discover, place/code/PE/graph/watch). See `src/protocol.hpp` and `src/ipc/` (handlers by domain).

**Full capability reference** (all opcodes, wire layouts, search/locate/discover/call/hook/place/code surfaces): [docs/capabilities.md](docs/capabilities.md).

The pipe accepts **multiple concurrent clients** and uses an ACL for SYSTEM, Administrators, and the process user (not Everyone). Long ops accept an optional trailer: `job_id`, `timeout_ms`, `flags` (`HDL_IPC_REQ_STREAM` yields chunked replies with `HDL_IPC_MORE`).

`OpInjectDll` payload: `pid`, `method`, `dll_path`, `exe_path`, `hook_export`. Reply: `status`, `base`, `out_pid`.

`OpUnloadDll` payload: `pid`, `reload`, `dll_path`. Reply: `status`, `base` (set when reloading).

`hdlclient` extras: `call --addr`, `vcall`, `alloc`/`free`/`alloc-near`, `caves`, `protect`, `flush-icache`, `disasm-backend`/`disasm`/`instrlen`, `stub`, `patch`, `sections`/`exports`/`imports`, `functions`, `resolve-function`, `xrefs-from`/`xrefs-to`, `invalidate-fn-index`, `vtable`/`rtti`, `watch` (`hw`/`page`/`list`/`unwatch`/`hits`/`refresh`), `rip`, `ptrchain`, `modbase`, `hooktrace`, `hook-import`, `hook-enable`, `hookhits`, `unhook`, `write`, `resolve-pattern`, `xrefs`, `ptrscan`, `probe`, `discover-*` (incl. pathvalidate/scan/watch-import/reset-heat/export/import/diff/apply-watch/evidence), `unload`/`reload`, REPL/`--tui`, interest store v3 + recipes (`place`/`stitch`/`expand`/`action`/`constrain`). Call arg prefixes: `u64:` `i64:` `f32:` `f64:` `cstr:` `wstr:` `buf:HEX` `ptr:HEX`. Scan scope: `--image` `--executable` `--module NAME`.

Discover / recipe workflows (command sequences, predicates, store locators): [docs/client.md](docs/client.md). See also `HdlDiscover*` in `hdllib.h`. C-API-only leftovers (no pipe): `HdlSetLogFile`, `HdlSetHealthVeh`, custom `HdlHook`, custom `HdlDisasmRegisterBackend`.

## Notes

- x64 only; no Wow64 helper in v1.
- Remote inject methods generally need sufficient process access (often elevation for protected targets).
- `SetWindowsHookEx` requires a UI thread/window on the target and a suitable hook export on the DLL.
- Prefer `hdlclient <pid> modules` to resolve bases after inject when unsure.
- `HdlCall` / `HdlCallExport` timeouts abandon waiting; the callee thread may still be running.
- `HDL_CALL_THREAD_MAIN` requires a non-console top-level HWND in the target process.
- Functional / injection / place-code API tests: [tests/README.md](tests/README.md) (`hdl_tests.exe --api-only`, `hdl_client_tests.exe`, `hdl_store_tests.exe`).
- Higher-level locate/discover + place/code playground: [toys/arena/README.md](toys/arena/README.md) (`hdl_toy_arena.exe`, `HDL_BUILD_TOYS`). Automated verify: `hdl_toy_tests.exe`.
