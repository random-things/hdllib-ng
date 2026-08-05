# Injection techniques

Live DLL injection methods implemented under `src/inject/`. The public entry points are `HdlInjectDll` / `HdlInjectDllEx` / `HdlUnloadDll` / `HdlUnloadDllEx` (see `include/hdllib/hdllib.h`); `src/inject.cpp` dispatches to technique implementations and unload.

When unloading `hdllib` itself, [`unload.cpp`](../../src/inject/unload.cpp) first sends the named `Control/Shutdown` RPC over the target pipe (if the module exports `HdlShutdown`) so hooks/patches/watches are restored **outside** the loader lock, waits for the pipe to disappear, then `CreateRemoteThread(FreeLibrary)`.

## Layout

```
src/inject.hpp              C++ facade used by the DLL / hdlclient inject
src/inject.cpp              Method switch / validation / AUTO / unload
src/inject/
  common.hpp|.cpp           Shared remote alloc, path, module/thread/window helpers
  select.hpp|.cpp           Requirement catalog, target profile, confidence scoring
  techniques.hpp            Per-technique declarations
  unload.cpp                FreeLibrary unload + Control/Shutdown prepare + optional reload
  create_remote_thread.cpp
  nt_create_thread_ex.cpp
  rtl_create_user_thread.cpp
  queue_user_apc.cpp
  set_windows_hook_ex.cpp
  thread_hijack.cpp
  manual_map.cpp
  early_bird_apc.cpp
  atom_bombing.cpp
  module_stomp.cpp
  section_map.cpp
  window_subclass.cpp
  instrumentation_callback.cpp
  kernel_callback_table.cpp
  veh.cpp
  set_win_event_hook.cpp
  rtl_remote_call.cpp
  special_user_apc.cpp
  thread_pool.cpp
  etw_callback.cpp
```

## Techniques

| Method enum | CLI name | Doc |
|-------------|----------|-----|
| `HDL_INJECT_CREATE_REMOTE_THREAD` | `create_remote_thread` | [create_remote_thread.md](create_remote_thread.md) |
| `HDL_INJECT_NT_CREATE_THREAD_EX` | `nt_create_thread_ex` | [nt_create_thread_ex.md](nt_create_thread_ex.md) |
| `HDL_INJECT_RTL_CREATE_USER_THREAD` | `rtl_create_user_thread` | [rtl_create_user_thread.md](rtl_create_user_thread.md) |
| `HDL_INJECT_QUEUE_USER_APC` | `queue_user_apc` | [queue_user_apc.md](queue_user_apc.md) |
| `HDL_INJECT_SET_WINDOWS_HOOK_EX` | `set_windows_hook_ex` | [set_windows_hook_ex.md](set_windows_hook_ex.md) |
| `HDL_INJECT_THREAD_HIJACK` | `thread_hijack` | [thread_hijack.md](thread_hijack.md) |
| `HDL_INJECT_MANUAL_MAP` | `manual_map` | [manual_map.md](manual_map.md) |
| `HDL_INJECT_EARLY_BIRD_APC` | `early_bird_apc` | [early_bird_apc.md](early_bird_apc.md) |
| `HDL_INJECT_ATOM_BOMBING` | `atom_bombing` | [atom_bombing.md](atom_bombing.md) |
| `HDL_INJECT_MODULE_STOMP` | `module_stomp` | [module_stomp.md](module_stomp.md) |
| `HDL_INJECT_SECTION_MAP` | `section_map` | [section_map.md](section_map.md) |
| `HDL_INJECT_WINDOW_SUBCLASS` | `window_subclass` | [window_subclass.md](window_subclass.md) |
| `HDL_INJECT_INSTRUMENTATION_CALLBACK` | `instrumentation_callback` | [instrumentation_callback.md](instrumentation_callback.md) |
| `HDL_INJECT_KERNEL_CALLBACK_TABLE` | `kernel_callback_table` | [kernel_callback_table.md](kernel_callback_table.md) |
| `HDL_INJECT_VEH` | `veh` | [veh.md](veh.md) |
| `HDL_INJECT_SET_WIN_EVENT_HOOK` | `set_win_event_hook` | [set_win_event_hook.md](set_win_event_hook.md) |
| `HDL_INJECT_RTL_REMOTE_CALL` | `rtl_remote_call` | [rtl_remote_call.md](rtl_remote_call.md) |
| `HDL_INJECT_SPECIAL_USER_APC` | `special_user_apc` | [special_user_apc.md](special_user_apc.md) |
| `HDL_INJECT_THREAD_POOL` | `thread_pool` | [thread_pool.md](thread_pool.md) |
| `HDL_INJECT_ETW_CALLBACK` | `etw_callback` | [etw_callback.md](etw_callback.md) |

In-process load (`pid == 0` or self) always uses `LoadLibraryW` and ignores the method (except early bird, which creates a new process).

## CLI

```bat
hdlclient inject <pid> <dll> [--method <name>] [--hook-export <name>]
hdlclient inject --title <substr> [--class <name>] <dll> [--method auto|…]
hdlclient inject --recommend <pid> [dll]
hdlclient inject --recommend --title <substr> [--class <name>] [dll]
hdlclient inject --early-bird <exe> <dll>
```

Method auto-selection (requirements catalog + confidence scoring): [selection.md](selection.md).

## Deferred ideas

Notes on techniques investigated but not shipped yet: [../future/](../future/README.md).

## Shared helpers

`common.cpp` owns primitives used by most techniques:

- `RemoteAlloc` — RAII `VirtualAllocEx` / `WriteProcessMemory`
- `WriteRemotePath` — write a wide DLL path into the target
- `OpenTargetProcess` / `EnumProcessThreads`
- `FindModuleBaseByPath` / `PollForModule` — resolve or wait for the loaded module
- `FindWindowForPid` / `FindWindowByTitleClass` — HWND probes for GUI methods / target resolve
- `WaitThreadAndBase` — join a remote loader thread and recover the base
