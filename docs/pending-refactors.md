## Overall assessment

The project has a strong conceptual architecture: controller-side injection is separated from target-side services, domain logic is mostly isolated from C API and IPC adapters, documentation is unusually comprehensive, and the test suite exercises real end-to-end workflows.

The largest weakness is resource lifetime under concurrency and DLL unload. I would treat graceful shutdown as the release-blocking issue; maintainability and tooling are the next tier.

The reviewed first-party code is approximately 35,200 lines across 137 C/C++/ASM files.

## Highest-priority findings

| Priority | Status | Finding / fix |
|---|---|---|
| Critical | **Fixed** | `DllMain` DETACH calls `CoreShutdownDetach()` which is a loader-lock no-op. Teardown is `OpShutdown` → `CoreShutdownPrepare` / `CoreShutdownFinish` (finish deferred until IPC workers join via `CoreOnIpcServerExited`). FreeLibrary without prior `OpShutdown` is unsupported. Lifecycle stress: `hdl_tests --lifecycle-only`. |
| Critical | **Fixed** | IPC `ServeClient` workers are joinable (`server.cpp`); accept thread joins them before session/job map teardown. Soft 2s wait removed as primary safety. `CoreShutdownPrepare` tears down instrumentation only; session/job close runs after worker join (`ThreadMain` + `CloseDomainSessionsAndJobs` on the finish path). |
| High | **Fixed** | Search/discover sessions use `shared_ptr` holders with per-session mutexes (`common.cpp`). Sessions remain process-global by id so multi-process CLI staging works; UAF on concurrent close is prevented by shared ownership (no disconnect auto-close). Regression: `lifecycle/search_close_vs_inflight`, `lifecycle/discover_close_vs_inflight`, `lifecycle/close_all_vs_inflight`, `lifecycle/ipc_close_vs_inflight` in `hdl_tests --lifecycle-only`. |
| High | **Fixed** | `CoreInit` already uses `kUninit → kBootstrapping → kReady`. `ipc::Start` now returns `HDL_E_FAILED` unless the listen pipe becomes ready. |
| High | **Fixed** | `OpHello` / `OpCapabilities` (`HDL_IPC_PROTO_MAJOR=1`); `PipeClient` negotiates on connect. Field-wise LE codecs in `src/ipc/wire.hpp` for wire `Hdl*` structs (including request-side `HdlFieldPred` / `HdlPointerPath`); `hdl_pe_tests` round-trips codecs. |
| High | **Fixed** | Bounds-checked `PeImageView` (`src/inject/pe_image_view.*`) used by manual map: rejects one-past-end `AddressOfEntryPoint`; shared `WalkBaseRelocDirectory` / local `ApplyRelocations` (`pe_relocs.*`) fail closed on truncated/malformed base-reloc blocks — covered by `hdl_pe_tests` fixtures that reach `ApplyRelocations`. |

Residual: the `hdl_tests` host may still `TerminateProcess` after in-process `CoreShutdown` because MinHook/CRT teardown can `STATUS_STACK_BUFFER_OVERRUN` after heavy hook API tests. Injected unload remains OpShutdown + no-op detach.

## Practical refactors

1. Separate CLI execution from presentation.

   The latest JSON work added 128 `ctx.json` branches across command handlers. Commands should return a typed `CommandResult`; independent human and JSON renderers should format it. This would shrink files such as [`cmds_place.cpp`](/C:/Users/Me/Documents/GitHub/hdllib/tools/client/cmds_place.cpp:61), centralize error handling, and make JSON schema tests straightforward.

2. Replace the three ad hoc JSON implementations.

   JSON parsing/writing is duplicated in [`store.cpp`](/C:/Users/Me/Documents/GitHub/hdllib/tools/client/store.cpp:43), [`discover.cpp`](/C:/Users/Me/Documents/GitHub/hdllib/src/discover.cpp:406), and `JsonWriter`. Use a vetted parser or one shared, strictly tested module. Also write UTF-8 bytes directly: the current JSON path converts UTF-8 back to wide text and calls `fputws` ([json_out.cpp](/C:/Users/Me/Documents/GitHub/hdllib/tools/client/json_out.cpp:179)), making redirected output encoding locale-dependent.

3. Split the largest translation units by responsibility.

   - `discover.cpp` (1,554 lines): session state, scanning, path/pattern analysis, action evidence, persistence.
   - `memory.cpp` (1,281 lines): safe access, region/module enumeration, scan engine, search-session state.
   - `cmds_place.cpp` (1,488 lines): placement, disassembly, PE metadata, graph, watches, patches, stubs.
   - `test_main.cpp` (2,155 lines): lifecycle, memory, code, hooks, discovery, IPC, injection.

   Preserve the current public facades while moving implementation into focused files.

4. Introduce Win32 RAII primitives.

   There are many manually balanced `HANDLE`, remote allocation, mapping, protection, and thread cleanup paths. Add `unique_handle`, `unique_hmodule`, `remote_allocation`, and scope-exit helpers. Apply them first to injection techniques and IPC server ownership.

5. Make operations declarative.

   A single operation manifest could define opcode, handler, capability group, and name. Generate or derive the opcode table, dispatch table, capability response, and documentation checks from it. This prevents drift across `protocol.hpp`, `handlers.hpp`, `dispatch.cpp`, client commands, and capability documentation.

6. Split the public header without breaking consumers.

   Keep `hdllib/hdllib.h` as the umbrella header, but move declarations into versioned subsystem headers such as `types.h`, `memory.h`, `discover.h`, and `hooks.h`. Add ABI `static_assert`s and an exported-symbol snapshot test.

7. Correct documentation drift.

   Both [`missing-usability.md`](/C:/Users/Me/Documents/GitHub/hdllib/docs/missing-usability.md:21) and [`missing-features.md`](/C:/Users/Me/Documents/GitHub/hdllib/docs/missing-features.md:249) still claim that `--json` does not exist, although it was implemented in the same current commit.

## Testing and tooling recommendations

- Add Windows CI with separate quick and extended jobs:

  - PR: build, selection/store unit tests, API-only, client IPC tests.
  - Nightly/manual: full injection matrix and toy workflows.
  - Build variants: both disassemblers, each backend alone, TUI on/off, Release and ASan.

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

  - IPC `Reader` and request dispatch.
  - AOB parsing and typed scan descriptors.
  - Manual-map PE parsing.
  - Discover/store JSON import.
  - CLI argument parsing.

  LLVM’s libFuzzer is coverage-guided and designed for small parser-style entry points like these. [LLVM libFuzzer documentation](https://llvm.org/docs/LibFuzzer.html)

- Add coverage reporting with `llvm-cov` or a Windows coverage runner. Start by enforcing coverage on deterministic unit/parser code rather than platform-sensitive injection techniques.

- Improve dependency reproducibility: pin FetchContent dependencies to immutable commit hashes, cache them in CI, and support offline builds. A vcpkg manifest is a reasonable longer-term option.

- Fix the CMake version contract. [`CMakeLists.txt`](/C:/Users/Me/Documents/GitHub/hdllib/CMakeLists.txt:1) claims CMake 3.16, while [`CMakePresets.json`](/C:/Users/Me/Documents/GitHub/hdllib/CMakePresets.json:2) uses schema version 3, which requires CMake 3.21. The installed VS 2019 CMake 3.20 rejected the documented preset command. [CMake preset version reference](https://cmake.org/cmake/help/v3.29/manual/cmake-presets.7.html)

## Recommended implementation order

1. Fix loader-lock teardown and join IPC workers.
2. Add lifecycle/unload stress tests under ASan.
3. Scope and safely own IPC sessions.
4. Version and harden the wire protocol.
5. Harden and fuzz PE/JSON/protocol parsers.
6. Refactor CLI commands into typed results plus renderers.
7. Split large modules and consolidate build/test configuration.

Validation performed: current Release source built successfully; selection tests passed 16/16, API-only passed 130/130, client/store/E2E passed 140/140, and the standalone store test passed. The full injection matrix and toy suite were not run. No project source files were changed.