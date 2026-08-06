# Crucial missing features

Gaps that block or weaken the product workflow ladder
(connect → locate → persist → observe → act), ordered by priority.
Priority favors: ABI stability first, then operator safety, then durable
instrumentation, then investigation continuity, then platform reach.

Related: [capabilities](capabilities.md), [architecture](architecture.md),
[workflows](workflows.md), [client](client.md). Usability-only items live in
[missing-usability.md](missing-usability.md).

---

## 1. Named RPC negotiation and capability discovery — **done**

Implemented: the `HDLRPC1\n` preface, protobuf `ClientHello` / `ServerHello`,
major-version rejection, generated named-method inventory, and advertised
transport limits. `hdl_client_tests` covers mismatched-major rejection;
`hdl_rpc_schema_tests` checks schema/generated-dispatch parity. See
[rpc.md](rpc.md) and [capabilities.md](capabilities.md).

Follow-ups: warn/disable individual client verbs when the advertised method is
missing; expand fuzzing of envelope parsing and complex typed request messages.

---

## 2. Safe in-process call lifecycle

**Why it matters:** The “observe, then invoke deliberately” workflow depends on
`HdlCall` / `HdlCallExport` / `HdlCallVtable`. Today a timeout returns
`HDL_E_TIMEOUT` while the callee thread may still be running. That can leave
the target mid-mutation, re-enter unsafe code on a later call, or make the
operator think the call never happened.

**Current state:** Worker-thread and `HDL_CALL_THREAD_MAIN` paths in
[`src/call.cpp`](../src/call.cpp) / [`src/call_dispatch.cpp`](../src/call_dispatch.cpp).
Docs already warn that timeouts abandon waiting. Jobs cancel cooperatively
elsewhere; calls are not joined after abandon.

**What needs to be done:**

1. Track outstanding calls (handle / job id / thread id / start time) in a
   process-local registry similar to hooks/watches.
2. On timeout: mark the call **orphaned**, surface that in the reply (status +
   flags or a dedicated `HdlCallResult` field), and refuse overlapping calls to
   the same target until the orphan completes or is explicitly acknowledged.
3. Prefer join-with-deadline where possible; if abort is impossible without
   suspending the target thread, document that and expose `call status` /
   a named `Call/EnumOrphans` RPC.
4. For `HDL_CALL_THREAD_MAIN`, define behavior when the UI thread never pumps
   (hung GUI): distinguish “no HWND” (`HDL_E_NOT_FOUND`) from “posted but not
   run” (timeout + orphan).
5. Client: print orphan warnings on subsequent `call` / `events`; add tests that
   intentionally hang a callee and assert orphan tracking.

**Acceptance:** After a timed-out call, the operator can see that work may still
be running and cannot silently stack another call into the same hazard without
acknowledgment.

---

## 3. Remote surface parity for operator-critical controls — DONE

Landed as named RPC methods: `SetLogFile`, `SetHealthVeh` /
`GetHealthVeh`, `DiscoverScanValue`, and `Hook` (target/detour VA). Client
verbs: `log-file`, `health-veh`, `discover-scan`, `hook`. Custom disasm backend
registration is intentionally not remote (built-in Enum/Get/Set only). The
exported C control ABI was removed; only inject callbacks remain.

---

## 4. Patch / stub durability across unload and reinject

**Why it matters:** Workflow 7 (“install reversible instrumentation”) and the
`recipe place` / `recipe stitch` path persist *intent* in the interest store,
but patch revalidation resolves the target address only and does **not**
re-apply bytes. After unload/reload or process restart, stitches are gone until
manual `patch enable`.

**Current state:** Patch ledger in [`src/code.cpp`](../src/code.cpp); locator
type `patch` in [`tools/client/store.cpp`](../tools/client/store.cpp);
architecture notes that patch revalidate is address-only.

**What needs to be done:**

1. Extend the interest-store `patch` (and optionally `stub`) locator schema to
   hold enough to recreate: target locator (pattern/export/…), patch bytes or
   stub kind + target, enabled flag, name.
2. Add `store revalidate --apply` (or `recipe restitch`) that: resolves targets,
   rebuilds stubs if needed (`BuildStub` / `AllocNear`), recreates ledger
   entries, and optionally enables them.
3. Decide unload semantics: `HdlUnloadDll` / process exit already drop in-target
   ledger state — durability is therefore a **client** concern, not silent
   DLL persistence across FreeLibrary.
4. Document the safety default: revalidate updates addresses; apply is explicit
   so ASLR churn cannot surprise-write code.
5. Toy/client tests: stitch → save store → reinject → revalidate --apply →
   verify bytes and disable/restore.

**Acceptance:** An operator can save a stitch, restart the target, reinject, and
restore instrumentation with one explicit command.

---

## 5. Connection-scoped session isolation

**Why it matters:** Search and discover session IDs are process-global. Multiple
concurrent pipe clients (or overlapping scripts) can mutate each other’s
sessions. Architecture already warns that search mutation relies on caller
coordination.

**Current state:** ID allocation in [`src/ipc/common.cpp`](../src/ipc/common.cpp)
(`g_next_session_id`); maps are global. Discover has per-session locks; search
does not fully isolate concurrent Next/First.

**What needs to be done:**

1. Bind each accepted pipe connection to a client context that owns the session
   IDs it created (or a private ID namespace).
2. On disconnect: optionally auto-close sessions created by that connection
   (with a flag to keep “shared” sessions for intentional handoff).
3. Reject or require an explicit share token when client B uses client A’s
   session id.
4. Document multi-client rules in architecture/capabilities; add a test with two
   `PipeClient`s creating discover sessions and verifying isolation.
5. Keep a migration path: a capabilities bit for “scoped sessions” so old
   clients that relied on global IDs can be detected.

**Acceptance:** Two concurrent controllers cannot silently corrupt each other’s
typed-scan or discover state; disconnect cleans up by default.

---

## 6. Durable import redirection (IAT rewrite)

**Why it matters:** `HdlHookImport` / `Hook/HookImport` resolve a PE import and
install `HookTrace` on the current IAT `bound_va`. Docs say “no IAT rewrite in
v1.” Tracing observes calls; it does not redirect them, and a rebound IAT slot
leaves the hook on a stale target.

**Current state:** [`src/hooks.cpp`](../src/hooks.cpp) `HookImport`,
[`src/ipc/handlers_hooks.cpp`](../src/ipc/handlers_hooks.cpp), PE import enum in
[`src/pe_meta.cpp`](../src/pe_meta.cpp).

**What needs to be done:**

1. Add an optional mode (flag on `HdlHookImport` / its RPC request): **trace-at-bound**
   (current) vs **rewrite-IAT** (write thunk / detour pointer into the IAT slot
   with protect flip + restore on unhook).
2. Record original `bound_va` and slot address for undo; integrate with existing
   unhook / shutdown paths.
3. Handle delay-load and bound imports carefully; fail clearly when the slot is
   not writable or not found.
4. Client: `hook-import … --iat` (or `--redirect`) plus document when to prefer
   MinHook-at-target vs IAT rewrite (shared exports vs per-module binding).
5. Tests: hook an import, verify callee diversion (or trace with rewritten
   slot), unhook restores original bytes/pointer.

**Acceptance:** Operators can choose observation vs redirection; unhook restores
the IAT; rebinds are detectable (refresh/rehook helper or watch on the slot).

---

## 7. Discover session restore completeness

**Why it matters:** `discover-export` / `discover-import` are marketed as pause/
resume for investigations, but import is best-effort `AddCandidate` restore.
Live watches, action windows, hook registrations, and region heat ownership are
not restored. Operators think they resumed; they only restored leads.

**Current state:** Export/import in [`src/discover.cpp`](../src/discover.cpp);
client verbs in [`tools/client/cmds_discover.cpp`](../tools/client/cmds_discover.cpp).
Workflows already note hooks/watches are process resources.

**What needs to be done:**

1. Split export into **leads** (candidates, evidence strings, heat snapshots,
   action names) vs **live plan** (watch addresses/imports, watch-regions,
   preferred rank flags).
2. On import: restore leads always; optionally `--restore-watches` to reinstall
   HookTrace / HookImport / WatchRegion from the plan (fail soft per entry).
3. Never pretend action windows are hot across import — require a new
   `action-begin` after restore.
4. Version the JSON schema; reject or migrate older blobs.
5. Document the guarantee in client.md: “import restores evidence; live
   instrumentation is opt-in.”

**Acceptance:** After export → new session → import `--restore-watches`, ranked
action workflows can continue without manually re-entering every watch.

---

## 8. Machine-readable automation surface

**Why it matters:** Agents, CI, and long scripted investigations need stable
structured output and preferably a binding thicker than hand-rolled pipe frames.

**Current state:** CLI `--json` is implemented (envelope via
[`EmitEnvelope`](../tools/client/json_out.cpp); see [client.md](client.md) and
[missing-usability.md](missing-usability.md) §1). Public surfaces remain
`hdllib.h` and the named protobuf RPC protocol; there is no thicker SDK/binding yet.

**What needs to be done:**

1. ~~Define a JSON envelope for CLI results~~ (done: `ok`/`status`/`cmd`/`data`/`error`).
2. ~~Implement `--json` on high-traffic verbs~~ (done across `cmds_*.cpp`).
3. Optionally publish a minimal C++/Python helper that wraps `PipeClient`
   framing (even if Python is ctypes over a small shim DLL).
4. Tie to protocol capabilities (item 1) so automation can feature-detect.
5. Keep human text as default; never break existing CLI formatting.
6. Expand golden schema fixtures beyond ping/modules/error
   (see [missing-usability.md](missing-usability.md) §1).

**Acceptance (CLI half done):** A script can inject, scan, and drain hook hits
without regexing console output; status codes remain aligned with `HdlStatus`.
Handlers return structured `data_json`; `Render()` owns JSON vs text. Remaining
acceptance is the optional PipeClient helper / bindings.

---

## 9. Richer code emission

**Why it matters:** Place/stitch depends on `HdlBuildStub` templates. Without a
text assembler or richer emitters, operators paste raw hex for anything beyond
absolute/relative jumps. `REL_JMP32` without `alloc_rx` still emits a zero
displacement placeholder until a VA is known.

**Current state:** Stub kinds in [`src/code.cpp`](../src/code.cpp); RIP-rel fixup
exists when allocating RX near the steal site; CLI documents “no text
assembler.”

**What needs to be done:**

1. Short term: refuse or clearly error `REL_JMP32` without a known stub VA;
   require `--alloc` or an explicit `--stub-va`.
2. Medium term: expand templates (call/pop stubs, push-ret, short vs long jump
   selection, steal-length auto based on `InstrLen`).
3. Longer term: optional text assembler backend (Keystone or a tiny in-tree
   subset) behind `HdlBuildStub` / a new `Code/Assemble` RPC, still producing bytes for
   the patch ledger.
4. Ensure stolen prologues with multiple RIP-rel insns remain correct after
   relocate (extend existing fixup loop; add tests with RIP-relative LEA/MOV).
5. Client `stub` / `recipe stitch` should print final bytes + VA and warn on
   truncated steals.

**Acceptance:** Common trampoline shapes work without hand-hex; invalid
rel32-without-VA fails loudly; RIP-rel stolen prefixes survive allocation.

---

## 10. Symbol / PDB / dbghelp resolution

**Why it matters:** When PDBs or exported RVAs-with-names exist, forcing AOB /
pointer-path discovery is wasted work. Interest locators have `export` / `import`
but no `symbol` kind backed by dbghelp/DIA.

**Current state:** No dbghelp/DIA usage in-tree. Resolve paths are PE exports,
imports, patterns, and paths ([`src/resolve.cpp`](../src/resolve.cpp),
[`src/locate.cpp`](../src/locate.cpp), store locator types).

**What needs to be done:**

1. Optional build flag (e.g. `HDL_SYMBOLS=ON`) linking `dbghelp` (and/or DIA) so
   default builds stay lean.
2. New APIs: resolve module+symbol → VA/RVA; enumerate symbols matching a glob;
   optional offline PDB path override.
3. New interest locator type `symbol` with revalidate via dbghelp.
4. Add named RPC methods only if symbol resolution runs **in-target** (usual), or document
   controller-side resolution using a local copy of the module/PDB (often
   better for stealth and dependency weight).
5. Graceful degrade when PDBs are absent; never require symbols for existing
   workflows.

**Acceptance:** With a PDB present, `store add foo symbol game.exe!Player::Update`
revalidates across ASLR; without PDB, the feature is simply unavailable.

---

## 11. Active fingerprint probes (`HDL_FP_ACTIVE`)

**Why it matters:** Passive fingerprinting (modules + main IAT + PE subsystem)
feeds `recipe suggest`. Reserved `HDL_FP_ACTIVE = 8` was left for probes that
confirm runtimes (e.g. safe export probes, window-class checks) without full
RE. Without it, suggestions stay generic.

**Current state:** [`src/fingerprint.cpp`](../src/fingerprint.cpp),
[`src/fingerprint_rules.hpp`](../src/fingerprint_rules.hpp), flag comment in
[`hdllib.h`](../include/hdllib/hdllib.h).

**What needs to be done:**

1. Define a small allowlist of active probes (no arbitrary code exec): e.g.
   `GetClassName` on primary HWND, presence of well-known exports, optional
   cheap `IsDebuggerPresent`-style environment bits — each with explicit risk
   tags.
2. Gate behind `HDL_FP_ACTIVE` in `scan_flags`; default remains passive-only
   (quiet inject defaults).
3. Raise confidence / `PRIMARY` when probes confirm a passive tag.
4. Extend `recipe suggest` to prefer probe-confirmed anchors (Present, message
   pump, scripting hosts).
5. Document probe inventory and why each is considered safe enough for an
   injected helper.

**Acceptance:** `fingerprint --active` (or flag) can confirm a subset of tags;
suggestions cite probe evidence, not only module names.

---

## 12. Wow64 / 32-bit target support

**Why it matters:** Inject selection rejects Wow64 targets. If hdllib is meant
as a general Windows helper, a large fraction of processes are unreachable. If
it remains x64 labware, this stays explicitly out of scope.

**Current state:** x64-only docs; Wow64 hard-fail in
[`src/inject/select.cpp`](../src/inject/select.cpp); tests in
[`tests/test_select.cpp`](../tests/test_select.cpp).

**What needs to be done (only if product scope expands):**

1. Ship a separate WOW64 helper DLL (or 32-bit build) with matching IPC — do not
   pretend one x64 DLL can run inside a 32-bit process.
2. Controller: detect Wow64, pick the correct payload, and use Wow64-aware
   inject paths where needed.
3. Dual protocol testing; pointer width and stub emitters become arch-specific.
4. Expect a large matrix cost (inject methods, disasm, hooks, call ABI).

**Acceptance:** Either (a) documented permanent x64-only scope with crisp errors,
or (b) `hdlclient inject` works on a 32-bit notepad with a 32-bit `hdllib`
and ping succeeds. Do not half-implement.

---

## Deferred / non-goals (see also)

Injection research that is intentionally not scheduled:
[future/](future/README.md) (e.g. I/O ring completions). Prefer finishing the
items above before adding more inject techniques.
