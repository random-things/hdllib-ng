# hdllib Python client

Pure-Python bindings for [hdllib-ng](../README.md): **ctypes** for out-of-process inject/resolve, and a **named-pipe** client for in-target memory/search/call/hook ops.

> **Important:** After inject, control the *target* over the pipe. Loading `hdllib.dll` into Python and calling `HdlReadMemory` would read the Python process, not the game.

## Install

Build the native DLL first (CMake stages it into `hdllib/_native/` for the package):

```bat
cmake --preset x64-windows
cmake --build --preset x64-windows
cd python
pip install -e ".[dev]"
```

After install, `hdl` / Scripts resolve `hdllib.dll` from the package (`hdllib/_native/hdllib.dll`) — no `HDL_DLL` required.

Override order if needed:

1. Environment variable `HDL_DLL` (full path)
2. Packaged `hdllib/_native/hdllib.dll` (staged by CMake / `pip install`)
3. In-tree CMake build dirs (`build/x64-windows/…`)

Re-stage without a full reinstall: `python _stage_dll.py`

## Quick start

```bat
python examples\inject_flow.py --exe hdl_test_target.exe
python examples\inject_flow.py --exe game.exe --method auto
```

```python
from hdllib import HdlClient, find_processes, INJECT_CREATE_REMOTE_THREAD

pid = find_processes("hdl_test_target.exe")[0].pid
with HdlClient(pid) as hdl:
    hdl.inject(method=INJECT_CREATE_REMOTE_THREAD)
    print("ping", hdl.ping())
    for m in hdl.modules()[:10]:
        print(hex(m.base), m.path)
    hits = hdl.search("48 8B ?? 90", max_hits=32)
```

## Shell and Python REPL

`hdl` / `python -m hdllib` mirrors `hdlclient`: a **command shell** (default) and a **Python REPL** with `hdl` bound to an `HdlClient`.

```bat
REM Command shell (hdlclient-like verbs)
hdl --exe hdl_test_target.exe
hdl 1234
hdl 1234 ping
hdl 1234 modules
hdl --exe game.exe --inject

REM Python REPL with programmatic client
hdl --exe game.exe --python
REM >>> hdl.ping()
REM >>> hdl.modules()

REM Local inject then shell
hdl inject 1234 --shell
```

Inside the shell:

| Input | Effect |
|---|---|
| `ping` / `modules` / `read` / `scan` / … | hdlclient-equivalent commands (`help` for list) |
| `py` / `python` | Drop into Python with `hdl` = connected `HdlClient` |
| `quit` / `exit` | Leave |

```text
hdl:70672> ping
status=HDL_OK remote_pid=70672
hdl:70672> py
>>> hdl.module_base()
>>> hdl.read(hdl.module_base(), 2)
```

## Tests

Offline framing (no DLL):

```bat
pytest tests\test_pipe_framing.py -q
```

Inject against `hdl_test_target.exe` (build with `HDL_BUILD_TESTS=ON`):

```bat
pytest tests\test_inject_target.py -q
```

## Game adapters

Core IPC/inject stays on `HdlClient`. Per-game helpers live under `hdllib.games` as an abstract `GameTarget` ABC and registry. Concrete adapters ship as separate packages and register via `register_game` or the `hdllib.games` entry-point group.

The Python REPL also binds a `DebugSession` toolbox:

| Name | Facade | Role |
|---|---|---|
| `dbg` | `DebugSession` | Bundle + `locals_dict()` / `discover()` / `search()` |
| `hdl` | `HdlClient` | Raw pipe/session ops |
| `mem` | `Memory` | Typed R/W (`u32`, `ptr`, …) |
| `scan` | `Scanner` | AOB, typed scans, pointer scan/follow, string xrefs |
| `hooks` | `Hooks` | Trace / import hooks |
| `watches` | `Watches` | HW + page watches + list/refresh |
| `structs` | `Structs` | Probe, vtable, RTTI |
| `graph` | `Graph` | Functions, resolve, xrefs |
| `place` | `Place` | Alloc / caves / protect / flush |
| `code` | `Code` | Disasm, stubs, patch ledger |
| `pe` | `Pe` | Sections / exports / imports |
| `health` | `Health` | Health snapshot, threads, events, jobs |

```python
with open_debug_session(pid) as dbg:
    hits = dbg.scan.u64(0x1234)
    for insn in dbg.code.disasm(dbg.hdl.module_base(), 8):
        print(hex(insn.addr), insn.mnemonic, insn.op_str)
    with dbg.discover() as disc:
        disc.add(hits[0], tag="hp")
        print(disc.candidates())
```

## Cheat Engine strategies

`hdllib.strategies` maps the [CE x64 tutorial](https://wiki.cheatengine.org/index.php?title=Tutorials:Cheat_Engine_Tutorial_Guide_x64) onto toolbox classes. The REPL also binds `vs`, `ce`, `access`, `patcher`, `ptrs`, `aob`.

| CE concept | Helper | Example |
|---|---|---|
| Exact / unknown / float scan (steps 2–4) | `ValueScan` | `vs.first_exact(100); vs.next_decreased()` |
| Address list + freeze | `CheatTable` / `ce` | `e = ce.add(addr); ce.freeze(e, 5000)` |
| Find what accesses (step 5) | `AccessFinder` | `access.watch_until(addr, take_damage)` |
| Replace → NOP / restore | `CodePatcher` | `patcher.nop_insn(rip, name="dmg")` |
| Pointers / multilevel (steps 6/8) | `PointerHelper` | `ptrs.scan_paths(addr); ptrs.validate(...)` |
| AOB / code injection (step 7) | `AobInjector` | `aob.install("89 83 ?? ?? 00 00")` |
| Structure / shared code (step 9) | `StructHelper` | `structs_helper.diff([a,b,c])` |

```python
from hdllib import ValueScan, CheatTable, AccessFinder, open_debug_session
from hdllib.protocol import HDL_VALUE_I32

with open_debug_session(pid) as dbg:
    vs = ValueScan(dbg, HDL_VALUE_I32)
    vs.first_exact(100)
    # … change value in-game …
    vs.next_exact(95)
    hp = vs.hits()[0]

    ce = CheatTable(dbg)
    entry = ce.add(hp, description="health")
    ce.freeze(entry, 5000)

    writers = AccessFinder(dbg).watch_until(hp, lambda: None)
    for w in writers:
        print(hex(w.rip), w.insn.mnemonic if w.insn else "?")
```

| Module | Role |
|---|---|
| `hdllib.games.base.GameTarget` | Abstract base: find/launch/`open`/attach/verify |

```python
from hdllib.games import GameTarget, register_game, get_game
# concrete adapters (e.g. hdllib-wesnoth) register via entry points
```

CLI:

```bat
hdl --game NAME --inject --python
REM adapters are separate packages; after install, NAME appears in list_games()
REM >>> hdl.ping(); mem.u32(addr); scan.aob("48 8B ??"); game.verify_attached(hdl)
```
