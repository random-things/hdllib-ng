# hdlclient workflows

How to drive an injected `hdllib.dll` with `hdlclient`: one-shot CLI, `discover-*` sessions, and interest-store recipes. For outcome-oriented guidance, start with [Goal-oriented workflows](workflows.md); for a complete worked lab with captured output, use the [Toy arena walkthrough](toy-arena-walkthrough.md). Protocol reference: [rpc.md](rpc.md); capability and typed contract reference: [capabilities.md](capabilities.md). Inject techniques: [inject/](inject/README.md). Live command list: `hdlclient` with no args, or `tools/client/usage.cpp`.

## Modes

| Mode | Invocation | Best for |
|------|------------|----------|
| Local inject | `hdlclient inject …` | Load the DLL (no pipe yet) |
| One-shot pipe | `hdlclient <pid> <verb> …` | All named RPC commands; each process exits |
| Controller | `hdlclient --store PATH <pid> session\|store\|recipe\|stabilize …` | Interests + recipes across processes |

Pipe name: `HdlFormatPipeName(pid)` → `\\.\pipe\RPCControl_<hash>`. Override with env `HDL_PIPE`.

Discover session IDs resolve from `--session`, else `HDL_SESSION`, else `<store>.session` / `%TEMP%\hdl_session_<pid>.txt`. Short aliases (`dcreate`, `dwatch`, `drank`, `henable`, `rpat`, …) are registered in `main.cpp`.

### Structured output (`--json`)

Global flag before or after the pid (not on local `inject`/`unload`):

```bat
hdlclient --json <pid> ping
hdlclient <pid> --json modules
hdlclient --store interests.json --json <pid> session new
```

Stdout is one line of UTF-8 JSON:

```json
{ "ok": true, "status": 0, "cmd": "ping", "data": { "remote_pid": 1234 }, "error": null }
```

On failure, `ok` is false and `error` is `{ "code", "name", "hint" }` with an actionable one-line hint. Stream verbs (`modules --stream`, scan hits, …) still emit **one aggregated** envelope (not NDJSON). Controller verbs (`session`/`store`/`recipe`/`stabilize`) always return a single envelope under `--json` (no preceding human lines). Text mode remains the default; failing text lines may also print `hint: …`.

**Controller `data` shapes (representative):**

| Verb | Typical `data` fields |
|------|------------------------|
| `session` | `session`, `pid`, `store` |
| `store list` | `store`, `interests[]` (`name`, `kind`, `locators`) |
| `store add` / `revalidate` | `store`, mutation summary / `ok` count |
| `recipe *` | `session`, `interest` / `cave_addr` / `stub_va`, `lines[]` |
| `stabilize` | `session`, `cand_id`, `interest`, `pattern`, `resolved` |

---

## 1. Get in: inject → talk

```bat
hdlclient inject <pid> C:\full\path\to\hdllib.dll
hdlclient inject <pid> C:\path\hdllib.dll --method auto
hdlclient inject --recommend <pid> C:\path\hdllib.dll
hdlclient inject --title Notepad --class Notepad C:\path\hdllib.dll
hdlclient inject --early-bird C:\Windows\System32\notepad.exe C:\path\hdllib.dll

hdlclient <pid> ping
hdlclient <pid> modules
hdlclient <pid> fingerprint
hdlclient <pid> health
```

Typical first checks after inject: `ping`, then `modules` / `fingerprint` for bases and stack hints, then either a one-shot scan or `hdlclient --store interests.json <pid> session new` for a controller session. `recipe suggest` turns fingerprint primaries into concrete watch/call next steps.

Quiet defaults after inject (log off, health VEH off). Raise logging with `hdlclient <pid> log 2` when debugging.

### Clean unload (leave the target intact)

Always prepare before ejecting `hdllib.dll`. Blind `FreeLibrary` under the loader
lock is what used to crash targets after hooks/patches.

```bat
rem Prepare only: restore hooks/patches/watches, optional tracked payload DLLs, stop pipe
hdlclient <pid> shutdown
hdlclient <pid> shutdown --modules

rem Preferred eject: Control/Shutdown (when the helper exports HdlShutdown) then FreeLibrary
hdlclient unload <pid> C:\full\path\to\hdllib.dll
hdlclient unload <pid> C:\full\path\to\hdllib.dll --modules
```

`--modules` / `HDL_SHUTDOWN_UNLOAD_MODULES` FreeLibrary's module-list DLLs that were
tracked via inject/track (never the helper itself). Manual-map / module-stomp
images are not unloadable this way. Pipe `unload` cannot eject the helper in-process
(`HDL_E_BUSY`); use the local `hdlclient unload` command.

---

## 2. Everyday CLI workflows

### Memory and search

```bat
rem One-shot AOB
hdlclient <pid> scan --pattern "48 8B ?? ??" --max 32 --image

rem Cheat Engine–style typed scan
hdlclient <pid> scan --type i32 --value 100 --max 64
hdlclient <pid> scan --type i32 --value 100 --unaligned --max 0
hdlclient <pid> scan --next --session 1 --cmp decreased
hdlclient <pid> scan --next --session 1 --cmp exact --value 90
hdlclient <pid> scan --hits --session 1 --max 64
hdlclient <pid> scan --close --session 1

hdlclient <pid> read 0x7FF6ABCD0000 64
hdlclient <pid> write 0x7FF6ABCD0000 90 90 90 90
```

`--type`: `bytes`, `i8`/`u8`, `i16`/`u16`, `i32`/`u32`, `i64`/`u64`, `f32`, `f64`, `string`, `wstring`.  
`--cmp`: `exact`, `unknown`, `changed`, `unchanged`, `increased`, `decreased`, `increased_by`, `decreased_by`, `greater`, `less`.  
Scope: `--image`, `--executable`, `--module NAME`. First typed scan prints a session id for `--next` / `--hits` / `--close`. Typed scans use natural alignment by default; `--unaligned` uses a byte stride. Search replies are always streamed; `--max 0` (default) is unlimited. Unlimited results are written to a controller-owned binary candidate file and only a 64-hit preview is printed; use `--candidates FILE` to choose the path. The DLL pauses the scan when its 4096-hit buffer is full until the client reads.

### Locate (signatures → addresses)

```bat
hdlclient <pid> resolve-pattern "48 8B ?? ??" --module game.exe --hit 0 --rip-disp 3 --rip-len 7
hdlclient <pid> xrefs "PlayerHealth" --wide --rip --module game.exe
hdlclient <pid> ptrscan 0xHEAP_TARGET --depth 3 --max-offset 0x1000 --module game.exe
hdlclient <pid> ptrchain 0xSTATIC_BASE +0x10 +0x20 +0
hdlclient <pid> rip 0x7FF6ABCD1000 --disp 3 --len 7
hdlclient <pid> probe 0xOBJECT 256
```

**Workflow:** AOB or string xref → optional RIP decode / pointer follows → absolute address. Prefer `--module` when the hit should stay inside one image.

### Call / hook / watch

```bat
hdlclient <pid> resolve --module kernel32.dll GetCurrentProcessId
hdlclient <pid> call --module kernel32.dll GetCurrentProcessId
hdlclient <pid> call --addr 0xFN [--main] [--timeout MS] u64:1 f32:1.5 cstr:hi
hdlclient <pid> vcall 0xOBJ 3 [--main] [--no-this] u64:1

hdlclient <pid> hooktrace 0xFN --args 4
hdlclient <pid> hook-import KERNEL32.dll!GetCurrentProcessId --args 0
hdlclient <pid> hookhits --max 16
hdlclient <pid> unhook 0xHANDLE

hdlclient <pid> watch hw 0xADDR --size 8 --access write
hdlclient <pid> watch page 0xADDR 4096 --mode guard
hdlclient <pid> watch hits --max 16
hdlclient <pid> events --timeout 1000
```

Call args: `u64:N` `i64:N` `f32:N` `f64:N` `cstr:TEXT` `wstr:TEXT` `buf:HEXBYTES` `ptr:HEX`. `--main` posts to the process UI thread (needs a non-console HWND).

### Place / code / PE / graph

```bat
hdlclient <pid> caves --near 0xFN --min 16 --image --executable
hdlclient <pid> alloc-near 0xFN 64
hdlclient <pid> stub --kind mov_rax_jmp --target 0xDEST --alloc
hdlclient <pid> patch create 0xFN 90 90 90 90 90 --name nop5
hdlclient <pid> patch enable 1

hdlclient <pid> disasm 0xFN --max 8
hdlclient <pid> functions --module game.exe --max 200
hdlclient <pid> resolve-function 0xADDR
hdlclient <pid> xrefs-to 0xADDR --module game.exe
hdlclient <pid> vtable 0xOBJ --vtable
hdlclient <pid> rtti 0xOBJ
```

`resolve-function` accepts any interior byte address. For x64 image code it
prefers compiler-authored unwind boundaries, then falls back to the bounded
call-target/prologue index.

Stub kinds: `abs_jmp`, `rel_jmp32`, `mov_rax_jmp`, `raw` (templates only — no text assembler).

---

## 3. Discover sessions (`discover-*`)

Discover is a **server-side session** that accumulates candidates, action evidence, heat, and patterns. Pass `--session ID`, or rely on `HDL_SESSION` / the store sidecar written by `session new` / `discover-create`.

### Command map

| Command | Role |
|---------|------|
| `discover-create` / `discover-close --session ID` | Open / destroy session |
| `discover-add --session ID --kind address\|function\|object --addr HEX [--tag T]` | Manual seed |
| `discover-scan --session ID --type T --value V …` | Typed scan → `ADDRESS` candidates (client composes Search + Add) |
| `discover-constraint --session ID --size N --pred SPEC…` | Object bases matching field predicates |
| `discover-watch` / `discover-watch-import` / `discover-unwatch` | HookTrace (or import) for ranking |
| `discover-action-begin` / `discover-action-end` | Named window around a user-triggered action |
| `discover-watch-region` / `discover-heat` / `discover-reset-heat` | Change-heat on `[addr, addr+size)` |
| `discover-rank --session ID --name NAME` | Rank functions seen during that action |
| `discover-synth --session ID --cand ID` | Module-unique AOB for a candidate |
| `discover-pathscan HEX` / `discover-pathvalidate HEX --base … --offs …` | Pointer-path consensus / filter |
| `discover-cluster --session ID --seed HEX --size N` | Same vtable@0 siblings |
| `discover-diff` / `discover-apply-watch` | Multi-object field diffs / promote watch hits → fields |
| `discover-cands` / `discover-evidence` | Dump candidates / provenance string |
| `discover-export` / `discover-import` | Session JSON snapshot (≤4 MiB) |

**Constraint `--pred` specs:**

| Spec | Meaning |
|------|---------|
| `eq_i32:OFF:VAL` | `*(i32*)(base+OFF) == VAL` |
| `range_i32:OFF:MIN:MAX` | inclusive range |
| `le_i32:OFF:REL` | field ≤ field at `OFF+REL` |
| `eq_u64:OFF:HEX` | exact u64 |
| `eq_f32:OFF:FLOAT` | bit-exact float |
| `ptr:OFF` | readable pointer |
| `vtable:OFF` | pointer into executable image |

Object size capped at 4096; scan alignment 8.

### Pipeline A — find a function via an action

Goal: watch a known entry (or import), trigger gameplay, rank callers, stabilize an AOB into the interest store.

**One-shot:**

```bat
hdlclient <pid> discover-create
rem note session id, e.g. 1

hdlclient <pid> discover-watch --session 1 --addr 0xKNOWN_FN --args 4
rem or: discover-watch-import --session 1 --dll USER32.dll --import DispatchMessageW --args 4

hdlclient <pid> discover-action-begin --session 1 --name fire
rem … perform the action in the target …
hdlclient <pid> discover-action-end --session 1

hdlclient <pid> discover-rank --session 1 --name fire
hdlclient <pid> discover-cands --session 1
hdlclient <pid> discover-evidence --session 1 --id <cand_id>
hdlclient <pid> discover-synth --session 1 --cand <cand_id> --module game.exe
```

**Recipe shortcut:**

```bat
hdlclient --store interests.json <pid> session new
hdlclient --store interests.json <pid> recipe action fire 0xKNOWN_FN --wait-ms 5000
```

That watches, opens the action, waits `--wait-ms` (or `--signal FILE` until the file exists), ends, ranks, and runs `stabilize` on the top hit (synth + store write).

### Pipeline B — find object instances via constraints

```bat
hdlclient <pid> discover-create
hdlclient <pid> discover-constraint --session 1 --size 0x80 ^
  --pred vtable:0 --pred eq_i32:0x10:100 --pred ptr:0x18 --tag player
hdlclient <pid> discover-cands --session 1
hdlclient <pid> discover-cluster --session 1 --seed 0xFIRST_OBJ --size 0x80
```

Or seed from a known value, then constrain:

```bat
hdlclient <pid> discover-scan --session 1 --type i32 --value 100 --tag hp
hdlclient <pid> discover-add --session 1 --kind object --addr 0xGUESSED_BASE --tag player
```

**Recipe:** `hdlclient --store interests.json <pid> recipe constrain 128 vtable:0 eq_i32:16:100 --module game.exe` — constraint scan within one module, list objects, cluster the first. Omit `--module` to retain the full image scope.

### Pipeline C — layout / fields via heat and watches

```bat
hdlclient <pid> discover-watch-region --session 1 --addr 0xOBJ --size 256
hdlclient <pid> discover-action-begin --session 1 --name damage
rem … mutate the object in-target …
hdlclient <pid> discover-action-end --session 1
hdlclient <pid> discover-heat --session 1 --addr 0xOBJ
hdlclient <pid> discover-apply-watch --session 1 --addr 0xOBJ --size 256

rem Compare several live instances:
hdlclient <pid> discover-diff --session 1 --addr 0xA --addr 0xB --addr 0xC --size 256
hdlclient <pid> discover-reset-heat --session 1 --addr 0xOBJ
```

**Recipe:** `hdlclient <pid> recipe expand 0xOBJ 256` registers the watch-region and prints the next manual steps (`action-begin` → trigger → `action-end` → `discover-heat`). Session ID is persisted to the sidecar.

Heat **accumulates** across actions until you reset or re-register the region.

### Pipeline D — stabilize with patterns or pointer paths

```bat
rem AOB unique in module
hdlclient <pid> discover-synth --session 1 --cand 3 --before 0 --after 24 --module game.exe

rem CE-style paths (image statics → target); validate after realloc/mutation
hdlclient <pid> discover-pathscan 0xTARGET --depth 3 --max-offset 0x1000 --module game.exe
hdlclient <pid> discover-pathvalidate 0xTARGET --base 0xSTATIC --depth 2 --offs 0x10,0x20
```

Attach a path locator in the same process that found it: `discover-pathscan 0xTARGET --store PATH --store-add NAME` (also `ptrscan`). `stabilize <cand_id> --session ID --store PATH` runs synth and writes a **pattern** locator interest.

### Persist / resume a discover session

```bat
hdlclient <pid> discover-export --session 1 --out session.json
hdlclient <pid> discover-import --session 2 --in session.json
```

Export is UTF-8 JSON (candidates, evidence, heat, action names). Import is best-effort `AddCandidate` restore — not a full live watch state.

---

## 4. Interest store and recipes

Client-only. JSON file via `--store PATH`, schema **v3**. Locators survive ASLR when revalidated against the live process. Mutating verbs require `--store` and perform load–mutate–save.

### Store verbs

| Verb | Purpose |
|------|---------|
| `store list` | Load `--store` and list interests + locator counts |
| `store revalidate` | Resolve every locator now; save on success |
| `store revalidate --apply` | Same, then recreate patch ledger entries and enable when `enabled_intent` is set |
| `store add <name> export N [--kind K]` | Export locator (stateless) |
| `store add <name> --pattern AOB …` | Explicit pattern / cave / stub / patch flags |
| `discover-pathscan` / `ptrscan … --store-add NAME` | Attach path locator in the producing process |

**Locator types and revalidate:**

| Type | Revalidate does |
|------|-----------------|
| `pattern` | `ResolvePattern` |
| `path` | `ModBase` + `FollowPointers` |
| `export` | `ResolveExport` |
| `import` | Match `EnumImports` bound VA |
| `cave` | `FindCaves` + nearer/larger score |
| `stub` | `BuildStub` (alloc RX) |
| `patch` | Resolve target address only; with `--apply`, `PatchCreate` (+ `PatchEnable` if `enabled_intent`) |

Optional interest fields: `kind` (`function` / `object` / `field` / `patch` / …), `evidence`, `struct_fields[]`.

### Recipes

Recipes are top-level one-shot verbs. Place/stitch/restitch require `--store`; action requires `--wait-ms` or `--signal FILE`.

| Recipe | What it does |
|--------|----------------|
| `recipe suggest` | Fingerprint process; print primary tags + suggested watch/call/module commands |
| `recipe action <name> <watch_hex> --wait-ms N\|--signal FILE` | Watch → action window → wait → end → rank → **stabilize** top candidate |
| `recipe constrain <size> <pred>… [--module NAME]` | Constraint scan, optionally scoped to one module → list objects → cluster first object |
| `recipe place <interest> <near_hex>` | Best cave near VA (or `AllocNear` fallback) → cave locator on interest |
| `recipe stitch <interest> --target HEX [--kind …] [--steal-min N]` | BuildStub + patch jmp at target → stub + patch locators |
| `recipe restitch` | Alias for `store revalidate --apply` (restore stubs/patches after unload) |
| `recipe expand <base> <size>` | `discover-watch-region` + printed next steps for heat |
| `stabilize <cand_id>` | Synth AOB → pattern interest (needs `--session` + `--store`) |

**End-to-end: discover a function, then place a cave and stitch a stub**

```bat
hdlclient --store interests.json <pid> session new
hdlclient --store interests.json <pid> recipe action fire 0xKNOWN_ENTRY --wait-ms 3000
hdlclient --store interests.json <pid> store list
hdlclient --store interests.json <pid> store revalidate
hdlclient --store interests.json <pid> recipe place my_hook 0xRESOLVED_FN
hdlclient --store interests.json <pid> recipe stitch my_hook --target 0xRESOLVED_FN --kind mov_rax_jmp --steal-min 5
rem After unload/reinject:
hdlclient --store interests.json <pid> store revalidate --apply
```

**End-to-end: objects → fields → pattern**

```bat
hdlclient --store interests.json <pid> session new
hdlclient --store interests.json <pid> recipe constrain 128 vtable:0 eq_i32:16:100 --module game.exe
hdlclient <pid> recipe expand 0xOBJ 256
hdlclient <pid> discover-action-begin --name bump
rem trigger writes …
hdlclient <pid> discover-action-end
hdlclient <pid> discover-heat --addr 0xOBJ
hdlclient <pid> discover-cands
hdlclient --store interests.json <pid> stabilize <field_or_fn_cand>
```

---

## 5. Choosing a path

| Goal | Prefer |
|------|--------|
| Quick AOB / CE scan | One-shot `scan` / `resolve-pattern` |
| Scripted R/W, call, hook | One-shot pipe verbs |
| Find code tied to a UI/game action | `discover-watch` + action + rank, or `recipe action --wait-ms` |
| Find typed objects in heap/image | `discover-constraint` / `recipe constrain` |
| Map which fields change | `recipe expand` + heat / `discover-diff` / `discover-apply-watch` |
| Durable relocatable addresses | Interest store + `stabilize` / `--store-add` |
| Cave + trampoline near a target | `recipe place` then `recipe stitch` |
| Practice without a real game | [toys/arena](../toys/arena/README.md) (`hdl_toy_arena.exe`) |

---

## Related sources

| Path | Contents |
|------|----------|
| [`tools/client/usage.cpp`](../tools/client/usage.cpp) | Full CLI synopsis |
| [`tools/client/main.cpp`](../tools/client/main.cpp) | Command registry + aliases |
| [`tools/client/cmds_controller.cpp`](../tools/client/cmds_controller.cpp) | session/store/recipe/stabilize |
| [`tools/client/session_persist.cpp`](../tools/client/session_persist.cpp) | Session sidecar / env resolution |
| [`tools/client/store.cpp`](../tools/client/store.cpp) / [`recipes.cpp`](../tools/client/recipes.cpp) | Interest JSON + recipes |
| [`docs/rpc.md`](rpc.md) / [`docs/capabilities.md`](capabilities.md) | Named RPC transport and typed method contracts |
