# Usability improvements

Client/REPL/TUI friction ordered by leverage for day-to-day operators and
scripted use. Prefer changes that unlock automation and shorten the
inject→investigate loop before large TUI rewrites.

Related: [client](client.md), [workflows](workflows.md),
[toy-arena-walkthrough](toy-arena-walkthrough.md). Product/ABI gaps live in
[missing-features.md](missing-features.md) (item 8 overlaps `--json` / bindings).

---

## 1. Structured output (`--json`) for CLI verbs

**Why it matters:** One-shot `hdlclient <pid> …` is the scripting surface, but
output is human text only. Automation must scrape hex addresses and counts.
This is the highest-leverage usability fix because it unlocks CI, agents, and
thin wrappers without waiting for a full SDK.

**Current state:** Command handlers under [`tools/client/cmds_*.cpp`](../tools/client/)
print with `wprintf`; no `--json` / NDJSON path. REPL/TUI stay human-first.

**What needs to be done:**

1. Add a process-wide `--json` (before the verb) or per-command flag; default
   remains text.
2. Standardize an envelope: `{ "ok": bool, "status": N, "cmd": "...", "data": …,
   "error": { "code": N, "hint": "..." } }`.
3. Prioritize verbs used in workflows: `ping`, `modules`, `scan` / `--hits`,
   `discover-create` / `discover-cands` / `discover-rank`, `hookhits`,
   `watch hits`, `fingerprint`, `health`.
4. Ensure stream ops emit one JSON value per chunk or a final aggregated array
   (document the choice).
5. Golden tests comparing JSON shape for a few verbs against the toy arena.

**Acceptance:** `hdlclient --json <pid> ping` is valid JSON with the host pid;
scripts never need to parse prose.

---

## 2. Expose recipes as one-shot CLI

**Why it matters:** `recipe action|constrain|place|stitch|expand|suggest` only
exist in REPL/TUI ([`tools/client/recipes.cpp`](../tools/client/recipes.cpp),
[`repl.cpp`](../tools/client/repl.cpp)). Scripted operators reimplement the same
pipelines with many `discover-*` process launches.

**Current state:** Recipes need a live `ControllerState` (pipe + optional store +
current discover session). One-shot argv dispatch in [`main.cpp`](../tools/client/main.cpp)
has no `recipe` verb.

**What needs to be done:**

1. Add `hdlclient <pid> recipe <name> …` that constructs the same
   `ControllerState`, connects the pipe, optionally `--store PATH`, and runs the
   existing recipe functions.
2. For `recipe action`, support non-interactive mode: `--wait-ms` / `--signal`
   instead of “press Enter” (critical for scripts).
3. Print the discover session id and stabilized interest names in text and JSON.
4. Share argument parsing with REPL tokens to avoid drift.
5. Document one-shot recipes in [client.md](client.md) beside REPL examples.

**Acceptance:** A batch file can run `recipe constrain …` and `recipe action …`
without entering the REPL.

---

## 3. Inject → connect as one flow

**Why it matters:** The common path is `inject`, note the pid, then
`hdlclient <pid> ping|repl`. Failures after inject are easy to mis-attribute
when the second process never starts.

**Current state:** Local inject in [`local_inject.cpp`](../tools/client/local_inject.cpp)
exits after load; pipe commands are a separate invocation.

**What needs to be done:**

1. Add flags on inject: `--then ping`, `--then repl`, `--then --tui`, or
   `--then <verb…>`.
2. After successful inject, wait for the pipe (retry with backoff) using
   `HdlFormatPipeName` / `HDL_PIPE`, then run the follow-on command.
3. Print the pid and pipe wait timing; on timeout, say “DLL loaded but IPC not
   up” (distinguish inject success vs `HDL_NO_IPC` / bootstrap failure).
4. Honor `--stealth` / early-bird `out_pid` so follow-on uses the real pid.
5. Keep default inject behavior unchanged (no surprise REPL).

**Acceptance:** `hdlclient inject <pid> hdllib.dll --then ping` is the happy-path
demo in the README.

---

## 4. Implicit discover session in one-shot mode

**Why it matters:** Every one-shot `discover-*` requires `--session ID` across
separate processes. REPL keeps a current session; one-shot users juggle ids by
hand and mistype them.

**Current state:** REPL `session new|show|close` in [`repl.cpp`](../tools/client/repl.cpp);
one-shot discover commands require `--session` in
[`cmds_discover.cpp`](../tools/client/cmds_discover.cpp).

**What needs to be done:**

1. Client-side default: if `--session` is omitted, read `HDL_SESSION` or a small
   file (e.g. next to `--store`, or `%TEMP%\hdl_session_<pid>.txt`).
2. `discover-create` writes that default; `discover-close` clears it.
3. Print which session was used when defaulting (avoid silent wrong-session
   bugs).
4. Do not invent a server-side “default session” — keep authority in the client
   so multiple controllers stay explicit (see missing-features session isolation).
5. Document env/file precedence in client.md.

**Acceptance:** After `discover-create`, a bare `discover-cands` uses the new
session without `--session`.

---

## 5. Actionable error strings

**Why it matters:** Operators see numeric `HdlStatus` or short failures
(`HDL_E_NOT_FOUND`) without the domain hint (“no non-console HWND for
`--main`”, “Wow64 target rejected”, “APC needs alertable thread”).

**Current state:** Status enum in [`hdllib.h`](../include/hdllib/hdllib.h);
client often prints the integer. Inject recommendation already has richer
reason strings; pipe verbs mostly do not.

**What needs to be done:**

1. Central `HdlStatusHint(status, context_op)` (or client-side table keyed by
   cmd + status) returning a one-line wchar hint.
2. Thread context through failing calls: e.g. call-main, inject method, missing
   session, buffer-small with needed size.
3. Include `hint` in `--json` errors (item 1).
4. For inject, surface `HdlRecommendInject` soft/hard fail strings next to the
   chosen method when `--method auto` fails.
5. Avoid localization complexity; English strings are enough.

**Acceptance:** A failed `call --main` prints why MAIN dispatch was impossible,
not only `HDL_E_NOT_FOUND`.

---

## 6. Per-command help instead of one giant synopsis

**Why it matters:** [`usage.cpp`](../tools/client/usage.cpp) dumps the full CLI.
Discover predicates, scan comparisons, and watch modes are easy to miss.
`PrintUsage()` is also the fallback on many parse errors — noisy and unfocused.

**Current state:** Global `PrintUsage()`; inject has a dedicated `--help`.
Most verbs lack `verb --help`.

**What needs to be done:**

1. Split usage into per-group or per-verb strings (scan, discover, watch, patch,
   recipe, store).
2. `hdlclient <pid> <verb> --help` / `-h` prints only that verb (examples +
   flags + predicate tables where relevant).
3. Top-level `hdlclient` with no args keeps a short index that points at groups.
4. REPL `help scan` / `help discover` mirrors the same text.
5. Keep usage strings next to command registration to reduce drift (or generate
   from a small table).

**Acceptance:** `hdlclient 1234 scan --help` explains `--type` / `--cmp` /
`--next` without scrolling past discover opcodes.

---

## 7. Cleanup recipes

**Why it matters:** [workflows.md](workflows.md) tells operators to remove hooks,
watches, and patches when an experiment ends. Tooling does not automate that,
so leftovers accumulate in long REPL sessions and affect later ranks/heats.

**Current state:** Individual `unhook`, `watch unwatch`, `patch disable` /
`remove`, `discover-unwatch`, `discover-close`, `scan --close`. No aggregate.

**What needs to be done:**

1. Add `recipe cleanup` / `hdlclient <pid> cleanup` with flags:
   `--hooks`, `--watches`, `--patches`, `--discover`, `--search`, `--all`.
2. Enumerate via existing list/poll APIs where available; disable patches before
   remove; close sessions last.
3. Optional `--dry-run` listing what would be cleared.
4. TUI key binding (e.g. `C`) prefilling cleanup.
5. Document as the last step in workflow “Verify and clean up.”

**Acceptance:** One command returns the target to a known quiet instrumentation
state without killing the process or unloading the DLL.

**Note:** `hdlclient <pid> shutdown` / `OpShutdown` already restores hooks, patches,
watches, and health and stops the pipe (optional `--modules` unloads tracked
payload DLLs) without `FreeLibrary` of `hdllib`. A selective `cleanup` verb that
leaves the helper running remains useful for long sessions.

---

## 8. Annotated `read` / scan hit views

**Why it matters:** After a typed scan or `read`, CE-style questions (“what
module? what neighbors? ascii?”) require extra manual commands (`modbase`,
`probe`, `disasm`).

**Current state:** `read` dumps raw hex; scan hits print addresses (and little
context). `probe` / `disasm` exist but are separate verbs.

**What needs to be done:**

1. `read` options: `--ascii`, `--cols`, `--annotate` (module+RVA per line when
   the range falls in an image).
2. `scan --hits --annotate` (or default in REPL): address, module!RVA, region
   protect, optional 16-byte peek.
3. Optional `--probe` on a single hit to run `ProbeStruct` summary inline.
4. Keep raw mode for scripts; pair with `--json` structured fields.
5. Respect size limits so annotation does not trigger huge reads by default.

**Acceptance:** A survivor address from a health scan shows module+RVA and a
hex+ASCII window without extra typing.

---

## 9. Auto-resolve on hook / watch hits

**Why it matters:** `hookhits` and `watch hits` print raw RIP / caller /
addresses. Frame-aware discover ranking already resolves functions internally;
the interactive drain path does not show that quality of detail.

**Current state:** Hit structs include RIP, args, frames
([`hdllib.h`](../include/hdllib/hdllib.h)); client printers are minimal in
[`cmds_hooks.cpp`](../tools/client/cmds_hooks.cpp) /
place watch commands.

**What needs to be done:**

1. On hit dump, optionally call `ResolveFunction` / `ModuleBase` for RIP and each
   frame (cap cost; cache per session).
2. Flags: `--resolve` / `--no-resolve`; default on in REPL, off in raw scripts
   unless `--json` includes both raw and resolved fields.
3. Align formatting with `discover-rank` / evidence so operators can promote a
   hit to a watch or stabilize path quickly.
4. Rate-limit resolution when draining large queues.

**Acceptance:** `hookhits --resolve` shows `module+RVA` / function bounds next to
each frame, not only hex pointers.

---

## 10. Make `recipe suggest` executable

**Why it matters:** `recipe suggest` turns fingerprint primaries into
copy-and-paste ideas but does not run them. Triage still requires retyping.

**Current state:** Suggestion printer in [`recipes.cpp`](../tools/client/recipes.cpp);
fingerprint via `OpFingerprint`.

**What needs to be done:**

1. Number suggestions; add `recipe suggest --run N` or `recipe apply-suggest N`.
2. Map suggestion classes to safe default actions (e.g. `discover-watch-import`
   for a message-pump import, module-scoped scan hints — **not** blind `call`).
3. Require confirmation or `--yes` before intrusive steps (hooks/watches).
4. Persist last suggestion list on `ControllerState` so run works after suggest.
5. Integrate with active fingerprint later (missing-features item 11) without
   blocking this UX.

**Acceptance:** `recipe suggest` followed by `recipe suggest --run 1` installs the
first recommended watch/import without retyping addresses.

---

## 11. Bridge interest store ↔ discover export

**Why it matters:** Two persistence models confuse operators: client interest
JSON (revalidatable locators) vs discover session JSON (investigation snapshot).
Promotion between them is manual (`stabilize`, `store add`, separate export).

**Current state:** Store v3 in [`store.cpp`](../tools/client/store.cpp);
discover export/import in the DLL. Workflows describe them as complementary.

**What needs to be done:**

1. `store import-discover PATH` — pull candidates into interests (pattern synth
   optional per candidate).
2. `store export-discover PATH` — build a discover-importable blob from selected
   interests (leads only).
3. One “save investigation” recipe: store save + discover-export with a shared
   basename.
4. Clarify UI labels in TUI panes: “locators” vs “session candidates.”
5. Docs: decision table (durable across ASLR → store; pause mid-session →
   discover export).

**Acceptance:** An operator can finish a discover session and land stable
locators in the interest store without hand-copying candidate ids.

---

## 12. REPL command history + tab completion

**Why it matters:** The interactive controller exposes a large verb set and
aliases (`dcreate`, `dwatch`, …) on a bare line reader. Mistypes are common;
re-running prior scan/discover lines means retyping.

**Current state:** Input via [`util.hpp`](../tools/client/util.hpp)
(`ReadConsoleW` / pipe lines). No history file, no tab completion.

**What needs to be done:**

1. Keep a session history list; Up/Down navigation when stdin is a console.
2. Optional persist to `%LOCALAPPDATA%\hdllib\repl_history` (cap length).
3. Tab completion for: top-level verbs, discover aliases, `--flags` for the
   current verb, interest names from the store, recent hex tokens.
4. Stay dependency-light (console APIs); avoid pulling a full readline port if
   a small custom completer suffices.
5. Ensure scripted stdin (tests) stays line-oriented without requiring TTY
   features.

**Acceptance:** In an interactive REPL, Up recalls the last command and Tab
completes `discover-` verbs.

---

## 13. CE scan parity polish

**Why it matters:** Typed incremental scan is already strong (exact / changed /
increased / …) but expert-shaped. Missing conveniences from Cheat Engine–style
tools slow value hunting.

**Current state:** Search in [`src/memory.cpp`](../src/memory.cpp); CLI in
[`cmds_scan.cpp`](../tools/client/cmds_scan.cpp). Float compares are bit-oriented;
no first-class “between” / fuzzy float. `--max 0` and `--stream` are powerful but
under-explained.

**What needs to be done:**

1. Add `HDL_CMP_BETWEEN` (or first+next value range) and fuzzy float epsilon
   compares; wire CLI `--cmp between --min/--max`, `--eps`.
2. REPL helpers: `scan narrow decreased` style short aliases.
3. Warn when hit counts are huge and `--stream` was not set; suggest scoping
   `--module` / `--image`.
4. Optional hit table with progressive refine summary (“was 12000, now 40”).
5. Align docs/examples with the toy-arena health-scan walkthrough.

**Acceptance:** Finding a float that “is about 100” and then “dropped” does not
require bit-exact `f32` retyping.

---

## 14. Richer TUI than recipe prefills

**Why it matters:** `--tui` is a full-screen shell, but keys mostly paste recipe
templates into a command line ([`tui.cpp`](../tools/client/tui.cpp)). The product
depth (interests, candidates, ranks, heat) deserves browse/apply interactions.

**Current state:** Log pane + interests pane; keys `a/c/p/t/x/z` prefill recipes;
Enter runs the wide-string command line.

**What needs to be done:**

1. Candidate browser bound to the current discover session (id, kind, conf,
   tag, addr) with keys to stabilize / watch / evidence.
2. Interest list actions: revalidate one, stitch, copy address, delete locator.
3. Hit inbox pane for hook/watch wakes (poll in background with timeout).
4. Keep the command line for power users; do not remove prefills.
5. Gate complexity: ship browse+stabilize before a general GUI redesign.
6. Tests remain mostly non-TUI; manual checklist in client.md for key bindings.

**Acceptance:** From the TUI, an operator can select a ranked candidate and
stabilize it without typing `stabilize <id>` by hand.

---

## Suggested implementation order

If only a few items ship next:

1. `--json` + error hints (automation + clarity)
2. inject `--then` + implicit discover session (loop time)
3. one-shot `recipe` + `cleanup` (parity with documented workflows)
4. annotated hits / auto-resolve (investigation speed)
5. REPL history and TUI browser (interactive polish)
