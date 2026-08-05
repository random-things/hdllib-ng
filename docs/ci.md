# Windows CI and local checks

[`tools/ci/run-checks.ps1`](../tools/ci/run-checks.ps1) is the single supported
entry point for build, test, formatting, analysis, fuzzing, coverage, and
reproducibility checks. Workflows select runners, restore caches, and publish
artifacts; they do not duplicate check commands.

## Reproduce checks locally

```powershell
# Fast developer gate (the default)
./tools/ci/run-checks.ps1

# Required pull-request parity; downloads the pinned CodeQL bundle if absent
./tools/ci/run-checks.ps1 -Profile PR -Bootstrap

# Diagnose one check
./tools/ci/run-checks.ps1 -Check DependencyPins

# Interactive desktop suite
./tools/ci/run-checks.ps1 -Profile GUI
```

Use `-ListChecks` to list check names and `-DryRun` to inspect profile expansion.
In CI, caches default below `$RUNNER_TEMP`; locally they default below
`build/tooling/cache`. Logs, reports, fuzz corpora, minimized failures, and the
machine-readable summary default below `build/tooling/artifacts`. Override those
locations with `-FetchContentDir` and `-ArtifactsDir`; no drive-level cache path
is assumed.

The profiles are:

| Profile | Purpose |
|---|---|
| `Fast` | Workflow lint, formatting, dependency pins, Release headless tests |
| `PR` | `Fast` plus fuzzer smoke tests, coverage, and CodeQL |
| `Nightly` | Backend variants, sanitizers, static analysis, VS 2022 compatibility, offline build, extended fuzzing |
| `GUI` | GUI smoke, GUI stress, and ASan lifecycle coverage |
| `All` | Every registered check once |

`-Bootstrap` may download pinned tooling such as CodeQL. It never installs or
changes Visual Studio components. Install VS 2026 Build Tools with the Desktop
development with C++ workload, CMake tools, and (for fuzzing/coverage)
LLVM/clang-cl and Ninja. The wrapper imports the newest installed x64 Visual
Studio environment via `vswhere`, then selects the newest complete CMake, Ninja,
and LLVM installations it can find. VS 2022 is retained only as the compatibility
floor. The primary tier requires CMake 4.4+ and Ninja 1.13.2+.

Formatting fixes and git-hook installation intentionally remain direct,
developer-only mutation commands:

```powershell
./tools/ci/fix-format.ps1 -WorkingTree
./tools/ci/install-git-hooks.ps1
```

## Hosted and interactive jobs

GitHub's `windows-2025-vs2026` image is the primary hosted target. It executes
headless builds, parser/client IPC tests, backend variants, static analysis,
CodeQL, fuzzing, coverage, and the fully disconnected rebuild with VS 2026.
The image currently supplies CMake 4.4, Ninja 1.13.2, and standalone LLVM
20.1.8. The wrapper chooses a newer complete LLVM toolset when the VS component
or a local installation provides one; this Windows 11 development runner uses
LLVM 22. The manifest records the hosted floor, and the wrapper refuses an
older VS 2026 toolchain. A nightly `windows-2022` job preserves explicit VS 2022
compatibility. The repository's existing self-hosted runner, labeled
`self-hosted`, `Windows`, and `X64`, executes tests that create windows, install
hooks, inject DLLs, or exercise UI-thread calls. No additional or paid runner is
required. That runner must have VS 2026 Build Tools installed so GUI validation
uses the same current compiler generation as hosted CI.

CTest labels are the execution boundary:

- `headless` covers deterministic unit, selection, store, PE, JSON, operations
  manifest, ABI, headless API, invocation, and no-window client IPC tests.
- `gui` covers UI-thread API, locate/injection, lifecycle, and toy tests.
- `full` is the combined GUI suite.

GUI tests use a single worker and the `hdl_gui_desktop` resource lock.

### The self-hosted runner must own an interactive desktop

A GitHub Actions runner installed as a Windows service runs in session 0.
Windows isolates session 0 from the logged-on desktop, so a service can be
automatic but cannot run these GUI tests. The desktop probe fails early in that
configuration by design.

Use the already registered runner application from the intended user's logged-on
session. For automatic startup without paying for hosting, disable the runner
service and create a Task Scheduler task triggered at that user's logon which
starts `C:\actions-runner\run.cmd` with that directory as its working directory.
Configure it to run only when the user is logged on. Keep the desktop unlocked;
disconnecting RDP can remove or lock the interactive desktop.

Only trusted `main` code is sent to the persistent interactive machine. Pull
requests run on GitHub-hosted runners. Restrict the runner group to this
repository and do not grant the runner account unrelated secrets or admin rights.

## Coverage and fuzzing

`FuzzSmoke` runs each clang-cl/libFuzzer harness for 5,000 iterations;
`FuzzExtended` runs each for 300 seconds. Harnesses parse IPC framing/wire data,
search patterns/descriptors, PE data, JSON/store/discover data, and one-shot CLI
invocations. They never dispatch operational IPC handlers.

`Coverage` runs deterministic headless tests with clang source coverage, emits
LLVM JSON and HTML reports, and gates only the first-party sources listed in
`tools/ci/coverage-sources.txt`. A decrease greater than 0.1 percentage points
fails. After reviewing an intentional change, update the baseline locally with:

```powershell
./tools/ci/run-checks.ps1 -Check Coverage -UpdateCoverageBaseline
```

Baseline updates are rejected in CI.

## Dependency and CodeQL reproducibility

Zydis and Capstone are pinned to audited commit hashes. MinHook v1.3.4 is
vendored with its upstream commit recorded in CMake. `DependencyPins` rejects
mutable FetchContent references and checks that the CodeQL bundle, CLI, and
SARIF upload action match `.github/codeql/toolchain.json`.

`OfflineBuild` first populates the selected FetchContent cache, then configures a
fresh build tree with `FETCHCONTENT_FULLY_DISCONNECTED=ON`, builds it, and runs
headless tests. `CodeQL` always uses the same local database/analyze path in CI
and on a developer machine; GitHub only uploads the resulting SARIF. Its default
C/C++ `none` build mode scans checked-in runtime, client, test, and toy source
without compiling large pinned dependencies. The build-only Protobuf generator
is excluded because buildless extraction cannot resolve its `libprotoc` headers.
For a configuration-specific traced database, use the manual fallback from a
configured VS developer shell:

```powershell
./tools/ci/run-codeql.ps1 -BuildMode manual
```
