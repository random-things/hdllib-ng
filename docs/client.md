# hdlclient workflows

How to drive an injected `hdllib.dll` with `hdlclient`: one-shot CLI, interactive REPL/TUI, `discover-*` sessions, and interest-store recipes. Full opcode / wire reference: [capabilities.md](capabilities.md). Inject techniques: [inject/](inject/README.md). Live command list: `hdlclient` with no args, or `tools/client/usage.cpp`.

## Modes

| Mode | Invocation | Best for |
|------|------------|----------|
| Local inject | `hdlclient inject …` | Load the DLL (no pipe yet) |
| One-shot pipe | `hdlclient <pid> <verb> …` | Scripted ops; each process exits |
| REPL | `hdlclient <pid>` or `… repl [--store PATH]` | Iterative work + store/recipes |
| TUI | `hdlclient <pid> --tui [--store PATH]` | Same controller, full-screen panes |

Pipe name: `HdlFormatPipeName(pid)` → `\\.\pipe\RPCControl_<hash>`. Override with env `HDL_PIPE`.

In REPL/TUI, every pipe verb works. Discover verbs also have short aliases (`dcreate`, `dwatch`, `drank`, … — see `help` / `repl.cpp`).

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

Typical first checks after inject: `ping`, then `modules` / `fingerprint` for bases and stack hints, then either a one-shot scan or `hdlclient <pid> --store interests.json` for a controller session. In REPL, `recipe suggest` turns fingerprint primaries into concrete watch/call next steps.

Quiet defaults after inject (log off, health VEH off). Raise logging with `hdlclient <pid> log 2` when debugging.

---

## 2. Everyday CLI workflows

### Memory and search

```bat
rem One-shot AOB
hdlclient <pid> scan --pattern "48 8B ?? ??" --max 32 --image

rem Cheat Engine–style typed scan
hdlclient <pid> scan --type i32 --value 100 --max 64
hdlclient <pid> scan --next --session 1 --cmp decreased
hdlclient <pid> scan --next --session 1 --cmp exact --value 90
hdlclient <pid> scan --hits --session 1 --max 64
hdlclient <pid> scan --close --session 1

hdlclient <pid> read 0x7FF6ABCD0000 64
hdlclient <pid> write 0x7FF6ABCD0000 90 90 90 90
```

`--type`: `bytes`, `i8`/`u8`, `i16`/`u16`, `i32`/`u32`, `i64`/`u64`, `f32`, `f64`, `string`, `wstring`.  
`--cmp`: `exact`, `unknown`, `changed`, `unchanged`, `increased`, `decreased`, `increased_by`, `decreased_by`, `greater`, `less`.  
Scope: `--image`, `--executable`, `--module NAME`. First typed scan prints a session id for `--next` / `--hits` / `--close`.

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

Stub kinds: `abs_jmp`, `rel_jmp32`, `mov_rax_jmp`, `raw` (templates only — no text assembler).

---

## 3. Discover sessions (`discover-*`)

Discover is a **server-side session** that accumulates candidates, action evidence, heat, and patterns. One-shot CLI always passes `--session ID`. REPL/TUI keep a current session (`session new|show|close`; recipes auto-create one).

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

**REPL shortcut (recipe):**

```text
session new
recipe action fire 0xKNOWN_FN
```

That watches, opens the action, waits for Enter, ends, ranks, and runs `stabilize` on the top hit (synth + store write).

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

**REPL:** `recipe constrain 128 vtable:0 eq_i32:16:100` — constraint scan, list objects, cluster the first.

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

**REPL:** `recipe expand 0xOBJ 256` registers the watch-region and prints the next manual steps (`action-begin` → trigger → `action-end` → `discover-heat`).

Heat **accumulates** across actions until you reset or re-register the region.

### Pipeline D — stabilize with patterns or pointer paths

```bat
rem AOB unique in module
hdlclient <pid> discover-synth --session 1 --cand 3 --before 0 --after 24 --module game.exe

rem CE-style paths (image statics → target); validate after realloc/mutation
hdlclient <pid> discover-pathscan 0xTARGET --depth 3 --max-offset 0x1000 --module game.exe
hdlclient <pid> discover-pathvalidate 0xTARGET --base 0xSTATIC --depth 2 --offs 0x10,0x20
```

In REPL, a successful pathscan/pathvalidate is remembered for `store add <name> path`. `stabilize <cand_id>` runs synth and writes a **pattern** locator interest.

### Persist / resume a discover session

```bat
hdlclient <pid> discover-export --session 1 --out session.json
hdlclient <pid> discover-import --session 2 --in session.json
```

Export is UTF-8 JSON (candidates, evidence, heat, action names). Import is best-effort `AddCandidate` restore — not a full live watch state.

---

## 4. Interest store and recipes

Client-only. JSON file (`--store PATH`, default `hdl_interests.json`), schema **v3**. Locators survive ASLR when revalidated against the live process.

### Store verbs (REPL / TUI)

| Verb | Purpose |
|------|---------|
| `store load [PATH]` / `store save [PATH]` | Load / save JSON |
| `store list` | Interests + locator counts |
| `store revalidate` | Resolve every locator now; update `last_addr` |
| `store add <name> [--kind K] synth\|path\|export N\|cave\|stub\|patch` | Attach last synth / path / cave / stub / patch |

**Locator types and revalidate:**

| Type | Tag (TUI) | Revalidate does |
|------|-----------|-----------------|
| `pattern` | P | `ResolvePattern` |
| `path` | A | `ModBase` + `FollowPointers` |
| `export` | E | `ResolveExport` |
| `import` | I | Match `EnumImports` bound VA |
| `cave` | C | `FindCaves` + nearer/larger score |
| `stub` | S | `BuildStub` (alloc RX) |
| `patch` | X | Resolve target address only (does **not** re-apply) |

Optional interest fields: `kind` (`function` / `object` / `field` / `patch` / …), `evidence`, `struct_fields[]`.

### Recipes

Recipes orchestrate pipe ops and write the store. Use them from REPL/TUI (not as top-level one-shot argv).

| Recipe | What it does |
|--------|----------------|
| `recipe suggest` | Fingerprint process; print primary tags + suggested watch/call/module commands |
| `recipe action <name> <watch_hex>` | Watch → action window → wait → end → rank → **stabilize** top candidate |
| `recipe constrain <size> <pred>…` | Constraint scan → list objects → cluster first object |
| `recipe place <interest> <near_hex>` | Best cave near VA (or `AllocNear` fallback) → cave locator on interest |
| `recipe stitch <interest> --target HEX [--kind …] [--steal-min N]` | BuildStub + patch jmp at target → stub + patch locators |
| `recipe expand <base> <size>` | `discover-watch-region` + printed next steps for heat |
| `stabilize <cand_id>` | Synth AOB for candidate → `AddOrReplace` pattern interest |

**End-to-end: discover a function, then place a cave and stitch a stub**

```text
session new
store load interests.json

recipe action fire 0xKNOWN_ENTRY
store list
store revalidate

recipe place my_hook 0xRESOLVED_FN
recipe stitch my_hook --target 0xRESOLVED_FN --kind mov_rax_jmp --steal-min 5

store save
```

**End-to-end: objects → fields → pattern**

```text
session new
recipe constrain 128 vtable:0 eq_i32:16:100
recipe expand 0xOBJ 256
discover-action-begin --session <id> --name bump
rem trigger writes …
discover-action-end --session <id>
discover-heat --session <id> --addr 0xOBJ
discover-cands --session <id>
stabilize <field_or_fn_cand>
store save
```

### TUI keys

| Key | Prefill / action |
|-----|------------------|
| `q` | Quit |
| `s` / `L` | Save / load store |
| `r` | Revalidate |
| `a` / `c` / `p` / `t` / `x` | Prefill `recipe action` / `constrain` / `place` / `stitch` / `expand` |
| `z` | Prefill `stabilize` |
| `n` | Prefill `session` |
| Enter | Run the wide-string command line |

Interests pane shows locator tags `P`/`A`/`E`/`I`/`C`/`S`/`X`.

---

## 5. Choosing a path

| Goal | Prefer |
|------|--------|
| Quick AOB / CE scan | One-shot `scan` / `resolve-pattern` |
| Scripted R/W, call, hook | One-shot pipe verbs |
| Find code tied to a UI/game action | `discover-watch` + action + rank, or `recipe action` |
| Find typed objects in heap/image | `discover-constraint` / `recipe constrain` |
| Map which fields change | `recipe expand` + heat / `discover-diff` / `discover-apply-watch` |
| Durable relocatable addresses | Interest store + `stabilize` / `store add … path` |
| Cave + trampoline near a target | `recipe place` then `recipe stitch` |
| Practice without a real game | [toys/arena](../toys/arena/README.md) (`hdl_toy_arena.exe`) |

---

## Related sources

| Path | Contents |
|------|----------|
| [`tools/client/usage.cpp`](../tools/client/usage.cpp) | Full CLI synopsis |
| [`tools/client/cmds_*.cpp`](../tools/client/) | One-shot command handlers |
| [`tools/client/cmds_discover.cpp`](../tools/client/cmds_discover.cpp) | All `discover-*` verbs |
| [`tools/client/recipes.cpp`](../tools/client/recipes.cpp) | Recipe implementations |
| [`tools/client/store.cpp`](../tools/client/store.cpp) | Interest JSON v3 |
| [`tools/client/repl.cpp`](../tools/client/repl.cpp) / [`tui.cpp`](../tools/client/tui.cpp) | Controller |
| [`docs/capabilities.md`](capabilities.md) | Opcodes, wire formats, limits |
