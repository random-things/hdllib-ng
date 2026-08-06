## Overall assessment

The project has a strong conceptual architecture: controller-side injection is separated from target-side services, domain logic is mostly isolated from C API and IPC adapters, documentation is unusually comprehensive, and the test suite exercises real end-to-end workflows.

The largest weakness is resource lifetime under concurrency and DLL unload. I would treat graceful shutdown as the release-blocking issue; maintainability and tooling are the next tier.

The reviewed first-party code is approximately 35,200 lines across 137 C/C++/ASM files.

## Highest-priority findings

| Priority | Status | Finding / fix |
|---|---|---|
| Critical | **Fixed** | `DllMain` DETACH calls `CoreShutdownDetach()` which is a loader-lock no-op. Teardown is `Control/Shutdown` → `CoreShutdownPrepare` / `CoreShutdownFinish` (finish deferred until IPC workers join via `CoreOnIpcServerExited`). FreeLibrary without prior shutdown prepare is unsupported. Lifecycle stress: `hdl_tests --lifecycle-only`. |
| Critical | **Fixed** | IPC `ServeClient` workers are joinable (`server.cpp`); accept thread joins them before session/job map teardown. Soft 2s wait removed as primary safety. `CoreShutdownPrepare` tears down instrumentation only; session/job close runs after worker join (`ThreadMain` + `CloseDomainSessionsAndJobs` on the finish path). |
| High | **Fixed** | Search/discover sessions use `shared_ptr` holders with per-session mutexes (`common.cpp`). Sessions remain process-global by id so multi-process CLI staging works; UAF on concurrent close is prevented by shared ownership (no disconnect auto-close). Regression: `lifecycle/search_close_vs_inflight`, `lifecycle/discover_close_vs_inflight`, `lifecycle/close_all_vs_inflight`, `lifecycle/ipc_close_vs_inflight` in `hdl_tests --lifecycle-only`. |
| High | **Fixed** | `CoreInit` already uses `kUninit → kBootstrapping → kReady`. `ipc::Start` now returns `HDL_E_FAILED` unless the listen pipe becomes ready. |
| High | **Fixed** | The `HDLRPC1\n` preface and protobuf `ClientHello` / `ServerHello` negotiate protocol 1.0 and advertise the schema-generated method inventory and transport limits. Every method now uses declared protobuf request/response types directly, with a descriptor-derived contract golden. |
| High | **Fixed** | Bounds-checked `PeImageView` (`src/inject/pe_image_view.*`) used by manual map: rejects one-past-end `AddressOfEntryPoint`; shared `WalkBaseRelocDirectory` / local `ApplyRelocations` (`pe_relocs.*`) fail closed on truncated/malformed base-reloc blocks — covered by `hdl_pe_tests` fixtures that reach `ApplyRelocations`. |

Residual: the `hdl_tests` host may still `TerminateProcess` after in-process `CoreShutdown` because MinHook/CRT teardown can `STATUS_STACK_BUFFER_OVERRUN` after heavy hook API tests. Injected unload remains named shutdown RPC + no-op detach.

## Practical refactors

1. Separate CLI execution from presentation. **Done**

   Commands return `CommandResult` with structured `data_json` only; `Render()` in
   `json_out.cpp` formats human text from that payload (or the JSON envelope) at
   the `main` edge. Handlers no longer branch on `ctx.json` or pre-render
   prose.

2. Replace the three ad hoc JSON implementations. **Done**

   Shared first-party module in [`src/json/`](../src/json/); `JsonWriter` / store /
   discover / CLI text rendering consume it. Helpers are minimal extractors (not a
   full-document JSON validator); see the contract comment in `json.hpp`. Redirected
   UTF-8 via `fwrite` remains.

3. Split the largest translation units by responsibility. **Done**

   - `cmds_place.cpp` → `cmds_place_mem.cpp`, `cmds_disasm.cpp`, `cmds_pe_meta.cpp`, `cmds_typeinfo.cpp`, `cmds_watch.cpp`, `cmds_patch.cpp` (shared helpers in `cmds_place_internal.hpp`).
   - `test_main.cpp` → `test_local_api.cpp`, `test_locate.cpp`, `test_discover_target.cpp`, `test_lifecycle.cpp`, `test_inject_matrix.cpp` (shared fixtures in `test_fixtures.cpp`/`test_runners.hpp`).
   - `memory.cpp` → `memory_rw.cpp`, `memory_aob.cpp`, `memory_search.cpp` (shared state in `memory_internal.hpp`).
   - `discover.cpp` → `discover_type.cpp`, `discover_session.cpp`, `discover_scan.cpp`, `discover_path.cpp`, `discover_watch.cpp`, `discover_serde.cpp` (shared state in `discover_internal.hpp`).

   Public facades `discover.hpp`, `memory.hpp`, `cmd.hpp` are preserved.

4. Introduce Win32 RAII primitives. **Done**

   `src/win/raii.hpp` provides `unique_handle`, `unique_hmodule`, and `scope_exit`. Applied across injection techniques (`create_remote_thread`, `queue_user_apc`, `rtl_create_user_thread`, `nt_create_thread_ex`, `thread_hijack`, `rtl_remote_call`, `early_bird_apc`, `section_map`, `manual_map`) and IPC server ownership.

5. Make RPC methods declarative. **Done**

   `proto/hdl/rpc/v1/services.proto` defines the named service surface. The
   `hdl_rpc_codegen` protoc plugin derives method metadata and handler dispatch;
   `hdl_rpc_schema_tests` verifies generated inventory and dispatch parity. There
   is no parallel numeric registry.

6. Split the public header without breaking consumers. **Done**

   `hdllib/hdllib.h` is now an umbrella that includes subsystem headers (`types.h`, `memory.h`, `locate.h`, `discover.h`, `health.h`, `place.h`, `call.h`, `hooks.h`, `code.h`, `pe.h`, `graph.h`, `vtable.h`, `watch.h`). ABI `static_assert`s and an exported-symbol golden-file snapshot test are in `hdl_abi_tests`.

7. Correct documentation drift. **Done**

   `missing-usability.md` and `missing-features.md` now describe the implemented `--json`
   envelope and remaining gaps (broader goldens, optional bindings).

## Testing and tooling recommendations

The unified testing/tooling work below is now implemented. All supported checks
flow through `tools/ci/run-checks.ps1`; see [ci.md](ci.md). Completed work
includes hosted/headless and interactive GUI partitions, API headless mode,
backend and sanitizer presets, clang-format/actionlint/clang-tidy/MSVC analysis,
CodeQL SARIF generation, parser fuzzers, LLVM coverage gating, immutable
dependency pins, MinHook v1.3.4 provenance, and an offline rebuild.

The historical recommendations are retained below as the implementation record.

- Add Windows CI with separate quick and extended jobs:

  - PR: build, selection/store unit tests, API-only, client IPC tests.
  - Nightly/manual: full injection matrix and toy workflows.
  - Build variants: both disassemblers, each backend alone, Release and ASan.

- Split CTest registration into labeled tests such as `unit`, `api`, `ipc`, `lifecycle`, `inject`, and `toy`. The binary already supports modes, but CTest currently exposes only five coarse executables.

- Add an ASan preset, initially for parser, session, and lifecycle tests. MSVC supports `/fsanitize=address` for x64 EXEs and DLLs and integrates it with CMake. [Microsoft ASan documentation](https://learn.microsoft.com/en-us/cpp/sanitizers/asan?view=msvc-170)

- Add:

  - Root `.clang-format` and `.editorconfig`.
  - `clang-format --dry-run --Werror` in CI.
  - `clang-tidy` with an initially narrow `bugprone`, `performance`, and ownership baseline.
  - MSVC `/analyze`.
  - `/WX` for first-party targets, excluding fetched/vendor warnings.
  - CodeQL for C/C++ security analysis. [GitHub CodeQL documentation](https://docs.github.com/en/code-security/concepts/code-scanning/codeql/codeql-code-scanning)

- Add fuzz targets for:

  - RPC envelope parsing and generated typed method dispatch.
  - AOB parsing and typed scan descriptors.
  - Manual-map PE parsing.
  - Discover/store JSON import.
  - CLI argument parsing.

  LLVM’s libFuzzer is coverage-guided and designed for small parser-style entry points like these. [LLVM libFuzzer documentation](https://llvm.org/docs/LibFuzzer.html)

- Add coverage reporting with `llvm-cov` or a Windows coverage runner. Start by enforcing coverage on deterministic unit/parser code rather than platform-sensitive injection techniques.

- Improve dependency reproducibility: pin FetchContent dependencies to immutable commit hashes, cache them in CI, and support offline builds. A vcpkg manifest is a reasonable longer-term option.

- The CMake/toolchain contract is now explicit: VS 2026 with CMake 4.4+ and
  Ninja 1.13+ is primary, while VS 2022 is exercised as a compatibility tier.

## Recommended implementation order

1. Fix loader-lock teardown and join IPC workers.
2. Add lifecycle/unload stress tests under ASan.
3. Scope and safely own IPC sessions.
4. Version and harden the wire protocol.
5. Harden and fuzz PE/JSON/protocol parsers.
6. Refactor CLI commands into typed results plus renderers.
7. Split large modules and consolidate build/test configuration.

Validation performed: current Release source built successfully; selection tests passed 16/16, API-only passed 130/130, client/store/E2E passed 140/140, and the standalone store test passed. The full injection matrix and toy suite were not run. No project source files were changed.
