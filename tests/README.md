# Test suite

| Binary | Role |
|--------|------|
| `hdl_test_target.exe` | Configurable victim (`--window`, `--alertable`, `--integrity low\|medium`, inheritable `--ready-handle` / `--exit-handle`). Also hosts locate/discover ground-truth exports. |
| `hdl_tests.exe` | In-process domain coverage (links `hdl_domain_obj`, not DLL control exports) + locate/discover inject checks + full injection × target-profile matrix |
| `hdl_client_tests.exe` | End-to-end `hdlclient` vs `hdl_test_target` (CLI + store/recipes; inject via `hdlclient inject`) |
| `hdl_store_tests.exe` | Interest-store JSON round-trip |

New platform coverage (place/code/PE/graph/watch 54–91, interest store v3, recipes) is exercised in `hdl_tests`, `hdl_client_tests`, `hdl_store_tests`, and `hdl_toy_tests`.

## Profiles (possibility space)

Each live inject method is run against:

| Profile | Window | Alertable thread | Integrity |
|---------|--------|------------------|-----------|
| `med_console_busy` | no | no | Medium |
| `med_console_alertable` | no | yes | Medium |
| `med_gui_busy` | yes | no | Medium |
| `med_gui_alertable` | yes | yes | Medium |
| `low_console_alertable` | no | yes | Low |
| `low_gui_alertable` | yes | yes | Low |

Expected outcomes follow method requirements (APC/atom need alertable; hook/subclass/KCT need a window). Early bird is tested separately by spawning the target EXE suspended.

Success for inject means `hdl::InjectDllEx == HDL_OK`, nonzero base, module list entry (except manual map), and IPC `ping` on `HdlFormatPipeName(pid)` (default `\\.\pipe\RPCControl_<hash>`).

Soft-pass (`[SOFT]`) covers flaky verify, privilege/version-sensitive methods, and known-hard paths (console hijack / RtlRemoteCall, ETW). Negative capability checks (no window / non-alertable APC) remain hard.

## Run

Build with `HDL_BUILD_TESTS=ON` (default), then from the output directory:

```bat
hdl_tests.exe
hdl_tests.exe --api-only
hdl_tests.exe --api-headless-only
hdl_tests.exe --api-asan-only
hdl_tests.exe --inject-only
hdl_tests.exe --locate-only
hdl_client_tests.exe
hdl_store_tests.exe
ctest -C Release -R hdl_ --output-on-failure
```

`--locate-only` runs locate + discover inject fixtures (skips the inject matrix).
`hdl_client_tests` requires `hdlclient.exe`, `hdllib.dll`, and `hdl_test_target.exe` beside the test binary (POST_BUILD copies them).

`--api-headless-only` runs the local API suite without its UI-thread call case.
`--api-asan-only` retains UI-thread/API coverage but skips the whole-process-region
code-cave scan, whose intentional reads of ASan redzones are incompatible with
the sanitizer runtime.
CTest exposes `headless`, `gui`, and `full` labels. Deterministic unit/parser,
headless API, and no-window client IPC coverage is headless. UI-thread calls,
injection, locate, lifecycle, and toy coverage require an interactive Windows
desktop. Reproduce supported check partitions through the wrapper:

```bat
powershell -NoProfile -File tools/ci/run-checks.ps1 -Check ReleaseHeadless
powershell -NoProfile -File tools/ci/run-checks.ps1 -Profile GUI
```

The GUI presets deliberately use one worker and a shared CTest resource lock.
Runner setup and the pull-request security boundary are documented in
[`docs/ci.md`](../docs/ci.md).
