# Usability improvements

Client friction ordered by leverage for day-to-day operators and scripted use.
Prefer changes that unlock automation and shorten the inject→investigate loop.

Related: [client](client.md), [workflows](workflows.md),
[toy-arena-walkthrough](toy-arena-walkthrough.md). Product/ABI gaps live in
[missing-features.md](missing-features.md) (item 8 overlaps `--json` / bindings).

## Status summary

| # | Item | Status |
|---|---|---|
| 1 | Structured output (`--json`) for CLI verbs | **Partial** (envelope done; goldens/streams thin) |
| 2 | Expose recipes as one-shot CLI | **Done** |
| 3 | Inject → connect as one flow | **Open** |
| 4 | Implicit discover session in one-shot mode | **Done** |
| 5 | Actionable error strings | **Partial** (central hints landed) |
| 6 | Per-command help instead of one giant synopsis | **Open** |
| 7 | Cleanup recipes | **Open** |
| 8 | Annotated `read` / scan hit views | **Open** |
| 9 | Auto-resolve on hook / watch hits | **Open** |
| 10 | Make `recipe suggest` executable | **Open** |
| 11 | Bridge interest store ↔ discover export | **Open** |
| 12 | CE scan parity polish | **Open** |

---

## 1. Structured output (`--json`) for CLI verbs — **partial**

**Why it matters:** One-shot `hdlclient <pid> …` is the scripting surface.
Structured output unlocks CI, agents, and thin wrappers without a full SDK.

**Current state:** Global `--json` (before or after pid) is implemented. Handlers
under [`tools/client/cmds_*.cpp`](../tools/client/) emit the envelope from
[`EmitEnvelope`](../tools/client/json_out.cpp):
`{ "ok", "status", "cmd", "data", "error": { "code", "name", "hint" } | null }`.
Default remains human text. See [client.md](client.md).

**Remaining gaps:**

1. Expand golden fixtures beyond ping/modules/error (`scan`, `discover-cands`,
   `hookhits`, `watch hits`, `fingerprint`, `health`) under `tests/golden/`.
2. Stream-heavy commands emit one final JSON envelope today (not NDJSON chunks).
3. Optional thicker PipeClient bindings remain under
   [missing-features.md](missing-features.md) §8.

**Acceptance (core done):** `hdlclient --json <pid> ping` is valid JSON with the
remote pid; handlers return `CommandResult` with structured `data_json` only and
`Render()` selects JSON vs human text. Golden fixtures under `tests/golden/` are
consumed by `hdl_client_tests` for the envelopes that exist.

---

## 2. Expose recipes as one-shot CLI — **done**

Implemented: `hdlclient <pid> recipe …` / `store` / `session` / `stabilize` with
`--store` transactions, `--wait-ms`/`--signal FILE` for `recipe action`, and JSON
envelopes via `CommandResult`.

---

## 3. Inject → connect as one flow — **open**

**Why it matters:** The common path is `inject`, note the pid, then
`hdlclient <pid> ping`. Failures after inject are easy to mis-attribute
when the second process never starts.

**Current state:** Local inject in [`local_inject.cpp`](../tools/client/local_inject.cpp)
exits after load; pipe commands are a separate invocation. No `--then` flag.

**What needs to be done:**

1. Add flags on inject: `--then ping` or `--then <verb…>`.
2. After successful inject, wait for the pipe (retry with backoff) using
   `HdlFormatPipeName` / `HDL_PIPE`, then run the follow-on command.
3. Print the pid and pipe wait timing; on timeout, say “DLL loaded but IPC not
   up” (distinguish inject success vs `HDL_NO_IPC` / bootstrap failure).
4. Honor `--stealth` / early-bird `out_pid` so follow-on uses the real pid.
5. Keep default inject behavior unchanged (no surprise follow-on).

**Acceptance:** `hdlclient inject <pid> hdllib.dll --then ping` is the happy-path
demo in the README.

---

## 4. Implicit discover session in one-shot mode — **done**

Implemented: resolve `--session` → `HDL_SESSION` → `<store>.session` /
`%TEMP%\hdl_session_<pid>.txt`. Written by `session new` / `discover-create`;
cleared by `session close` / `discover-close`.

---

## 5. Actionable error strings — **partial**

**Why it matters:** Operators see numeric `HdlStatus` or short failures
(`HDL_E_NOT_FOUND`) without the domain hint (“no non-console HWND for
`--main`”, “Wow64 target rejected”, “APC needs alertable thread”).

**Current state:** [`StatusHint`](../tools/client/util.cpp) maps status (+ optional
cmd) to one-line hints and is wired through
[`EmitEnvelope`](../tools/client/json_out.cpp) / `Render()` for both JSON
`error.hint` and human text. Coverage includes `call`/`vcall` HWND and timeout
orphans, discover/scan missing sessions, `hook-import`, inject Wow64/access, plus
generic per-status fallbacks. Some inject-method-specific strings (e.g. APC
alertable thread) and deeper domain tags are still thin compared to the original
wish list.

**What remains:**

1. Extend hints for remaining high-frequency inject-method failures (APC,
   hijack, early-bird) with stable context tags where useful.
2. Prefer explicit `CmdFail(..., hint)` overrides only when `StatusHint` cannot
   be specific enough; keep machine `status` / `error.code` stable.
3. Spot-check that `call --main` under `--json` still names the HWND constraint
   (already true for `HDL_E_NOT_FOUND`).

**Acceptance (mostly met):** A failed `call --main` under `--json` includes a hint
that names the HWND/`--main` constraint without requiring a docs dive. Treat as
done once inject-method hints are filled in; until then keep as partial.

---

## 6. Per-command help instead of one giant synopsis — **open**

**Why it matters:** [`usage.cpp`](../tools/client/usage.cpp) dumps the full CLI.
Discover predicates, scan comparisons, and watch modes are easy to miss.
`PrintUsage()` is also the fallback on many parse errors — noisy and unfocused.

**Current state:** Global `PrintUsage()`; `inject` / `unload` / `reload` have
dedicated `--help`. Most pipe verbs lack `verb --help`.

**What needs to be done:**

1. Split usage into per-group or per-verb strings (scan, discover, watch, patch,
   recipe, store).
2. `hdlclient <pid> <verb> --help` / `-h` prints only that verb (examples +
   flags + predicate tables where relevant).
3. Top-level `hdlclient` with no args keeps a short index that points at groups.
4. Keep usage strings next to command registration to reduce drift (or generate
   from a small table).

**Acceptance:** `hdlclient 1234 scan --help` explains `--type` / `--cmp` /
`--next` without scrolling past every discover command.

---

## 7. Cleanup recipes — **open**

**Why it matters:** [workflows.md](workflows.md) tells operators to remove hooks,
watches, and patches when an experiment ends. Tooling does not automate that,
so leftovers accumulate across sequenced one-shot runs and affect later
ranks/heats.

**Current state:** Individual `unhook`, `watch unwatch`, `patch disable` /
`remove`, `discover-unwatch`, `discover-close`, `scan --close`. No aggregate.
`shutdown` / `Control/Shutdown` restores instrumentation and stops the pipe but
is heavier than a selective quieting pass.

**What needs to be done:**

1. Add `recipe cleanup` / `hdlclient <pid> cleanup` with flags:
   `--hooks`, `--watches`, `--patches`, `--discover`, `--search`, `--all`.
2. Enumerate via existing list/poll APIs where available; disable patches before
   remove; close sessions last.
3. Optional `--dry-run` listing what would be cleared.
4. Document as the last step in workflow “Verify and clean up.”

**Acceptance:** One command returns the target to a known quiet instrumentation
state without killing the process or unloading the DLL.

**Note:** `hdlclient <pid> shutdown` / `Control/Shutdown` already restores hooks, patches,
watches, and health and stops the pipe (optional `--modules` unloads tracked
payload DLLs) without `FreeLibrary` of `hdllib`. A selective `cleanup` verb that
leaves the helper running remains useful for long sessions.

---

## 8. Annotated `read` / scan hit views — **open**

**Why it matters:** After a typed scan or `read`, CE-style questions (“what
module? what neighbors? ascii?”) require extra manual commands (`modbase`,
`probe`, `disasm`).

**Current state:** `read` dumps raw hex; scan hits print addresses (and little
context). `probe` / `disasm` exist but are separate verbs. No `--annotate` /
`--ascii` flags.

**What needs to be done:**

1. `read` options: `--ascii`, `--cols`, `--annotate` (module+RVA per line when
   the range falls in an image).
2. `scan --hits --annotate`: address, module!RVA, region protect, optional
   16-byte peek.
3. Optional `--probe` on a single hit to run `ProbeStruct` summary inline.
4. Keep raw mode for scripts; pair with `--json` structured fields.
5. Respect size limits so annotation does not trigger huge reads by default.

**Acceptance:** A survivor address from a health scan shows module+RVA and a
hex+ASCII window without extra typing.

---

## 9. Auto-resolve on hook / watch hits — **open**

**Why it matters:** `hookhits` and `watch hits` print raw RIP / caller /
addresses. Frame-aware discover ranking already resolves functions internally;
the interactive drain path does not show that quality of detail.

**Current state:** Hit structs include RIP, args, frames
([`hdllib.h`](../include/hdllib/hdllib.h)); client printers are minimal in
[`cmds_hooks.cpp`](../tools/client/cmds_hooks.cpp) /
place watch commands. No `--resolve` flag.

**What needs to be done:**

1. On hit dump, optionally call `ResolveFunction` / `ModuleBase` for RIP and each
   frame (cap cost; cache per session).
2. Flags: `--resolve` / `--no-resolve`; default off for scripts unless `--json`
   includes both raw and resolved fields.
3. Align formatting with `discover-rank` / evidence so operators can promote a
   hit to a watch or stabilize path quickly.
4. Rate-limit resolution when draining large queues.

**Acceptance:** `hookhits --resolve` shows `module!RVA` (or nearby function) for
RIP without a second `resolve-function` invocation.

---

## 10. Make `recipe suggest` executable — **open**

**Why it matters:** `recipe suggest` turns fingerprint primaries into
copy-and-paste ideas but does not run them. Triage still requires retyping.

**Current state:** Suggestion printer in [`recipes.cpp`](../tools/client/recipes.cpp);
fingerprint via `Process/Fingerprint`. Still print-only (“does not auto-run”).

**What needs to be done:**

1. Number suggestions; add `recipe suggest --run N` or `recipe apply-suggest N`.
2. Map suggestion classes to safe default actions (e.g. `discover-watch-import`
   for a message-pump import, module-scoped scan hints — **not** blind `call`).
3. Require confirmation or `--yes` before intrusive steps (hooks/watches).
4. Persist last suggestion list beside the session sidecar / store so `--run`
   works in a later process after `suggest`.
5. Integrate with active fingerprint later (missing-features item 11) without
   blocking this UX.

**Acceptance:** `recipe suggest` followed by `recipe suggest --run 1` installs the
first recommended watch/import without retyping addresses.

---

## 11. Bridge interest store ↔ discover export — **open**

**Why it matters:** Two persistence models confuse operators: client interest
JSON (revalidatable locators) vs discover session JSON (investigation snapshot).
Promotion between them is manual (`stabilize`, `--store-add`, separate export).

**Current state:** Store v3 in [`store.cpp`](../tools/client/store.cpp);
discover export/import in the DLL. Workflows describe them as complementary.
`stabilize` and `--store-add` on pathscan/ptrscan cover parts of the handoff.
No `store import-discover` / `export-discover`.

**What needs to be done:**

1. `store import-discover PATH` — pull candidates into interests (pattern synth
   optional per candidate).
2. `store export-discover PATH` — build a discover-importable blob from selected
   interests (leads only).
3. One “save investigation” recipe: store save + discover-export with a shared
   basename.
4. Docs: decision table (durable across ASLR → store; pause mid-session →
   discover export).

**Acceptance:** An operator can finish a discover session and land stable
locators in the interest store without hand-copying candidate ids.

---

## 12. CE scan parity polish — **open**

**Why it matters:** Typed incremental scan is already strong (exact / changed /
increased / …) but expert-shaped. Missing conveniences from Cheat Engine–style
tools slow value hunting.

**Current state:** Search in [`src/memory_search.cpp`](../src/memory_search.cpp)
(and related); CLI in [`cmds_scan.cpp`](../tools/client/cmds_scan.cpp). Compare
ops remain exact / unknown / changed / increased / … / greater / less
([`memory.h`](../include/hdllib/memory.h)); float compares are bit-oriented.
No `HDL_CMP_BETWEEN`, no fuzzy float epsilon, no first-class `--eps`.

**What needs to be done:**

1. Add `HDL_CMP_BETWEEN` (or first+next value range) and fuzzy float epsilon
   compares; wire CLI `--cmp between --min/--max`, `--eps`.
2. Short aliases for common refine patterns (`scan --next --cmp decreased`, …).
3. Warn when hit counts are huge and `--stream` was not set; suggest scoping
   `--module` / `--image`.
4. Optional hit table with progressive refine summary (“was 12000, now 40”).
5. Align docs/examples with the toy-arena health-scan walkthrough.

**Acceptance:** Finding a float that “is about 100” and then “dropped” does not
require bit-exact `f32` retyping.

---

## Dropped (console-only)

These items targeted the removed REPL/TUI surfaces and are no longer planned:

- REPL command history + tab completion
- Richer TUI than recipe prefills / PDCurses browser panes

---

## Suggested implementation order

If only a few items ship next:

1. Finish actionable inject-method hints (§5) — nearly done
2. Broader JSON schema/golden fixtures (`scan`, `discover-cands`, …) (§1)
3. inject `--then` (§3) — loop time
4. `cleanup` (§7) — parity with documented workflows
5. annotated hits / auto-resolve (§8–§9) — investigation speed
6. CE scan polish (`between` / fuzzy float) (§12)
7. executable `recipe suggest --run` (§10)
8. per-command `--help` (§6)
9. store ↔ discover bridge (§11)
