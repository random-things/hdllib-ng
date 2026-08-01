# Windows continuous integration

`hdllib` uses two Windows CI tiers because its end-to-end tests create real
windows, install hooks, inject DLLs, and communicate with child processes.
GitHub-hosted Windows machines are used for builds and tests that do not need a
desktop. A self-hosted runner on an existing Windows PC supplies an unlocked
interactive desktop for trusted `main` builds and scheduled GUI and injection
suites. It does not need to be a rented server.

## Workflow layout

| Workflow/job | Runner | Trigger | Coverage |
|---|---|---|---|
| `Windows CI / hosted-build` | `windows-2022` | pull request, `main`, manual | Release build, changed-file formatting, `headless` CTest label |
| `Windows CI / gui-tests` | Self-hosted Windows x64 | Push or manual dispatch of `main` | Partitioned GUI, API, injection, IPC, and toy tests |
| `Windows Nightly / backend-matrix` | `windows-2022` | Nightly, manual | Zydis-only, Capstone-only, and no-TUI configurations |
| `Windows Nightly / address-sanitizer` | `windows-2022` | Nightly, manual | MSVC ASan build and headless tests |
| `Windows Nightly / *-analysis` | `windows-2022` | Nightly, manual | MSVC `/analyze` and clang-tidy; initially advisory |
| `Windows Nightly / windows-canary` | `windows-2025` | Nightly, manual | Non-blocking newest-image compatibility signal |
| `Windows Nightly / gui-stress` | Self-hosted Windows x64 | Nightly or manual dispatch of `main` | GUI partitions repeated three times, then the combined full suite |
| `CodeQL` | `windows-2022` | Pull request, `main`, weekly | C/C++ security analysis excluding vendored sources |

The primary image is pinned to `windows-2022` so changes to
`windows-latest` cannot silently change the compiler. The `windows-2025`
canary is intentionally non-blocking until it has a stable history.

## Test partitions

CTest labels are the boundary between hosted and desktop execution:

- `headless`: deterministic selection and interest-store tests. These may run
  on GitHub-hosted Windows.
- `gui`: tests that load or inject the DLL, create a target window, use hooks,
  or drive live IPC. These run only on the interactive runner.
- `full`: the combined `hdl_tests` suite. It runs nightly to avoid duplicating
  every partition on each trusted push.

GUI tests also acquire the `hdl_gui_desktop` CTest resource lock. Keep the GUI
CTest presets at one worker; parallel desktop/injection tests can interfere
with each other's processes and window state.

Useful local commands:

```powershell
cmake --preset ci-windows
cmake --build --preset ci-windows --parallel
ctest --preset ci-headless

cmake --preset ci-gui
cmake --build --preset ci-gui --parallel
ctest --preset ci-gui-smoke
ctest --preset ci-gui-full
```

For a local ASan run, execute
`tools/ci/add-msvc-asan-runtime-to-path.ps1` in the same PowerShell session
before CTest. Visual Studio does not place its ASan runtime DLL on an ordinary
shell's `PATH`; the nightly workflow performs this step explicitly.

## Local CodeQL (same gate as GitHub)

Before pushing, you can run the same C/C++ `security-extended` analysis as
[`.github/workflows/codeql.yml`](../.github/workflows/codeql.yml) without waiting
on Actions:

```powershell
# First time: download GitHub's exact win64 CodeQL bundle into tools/.cache/codeql
powershell -NoProfile -File tools/ci/run-codeql.ps1 -InstallBundle

# Later runs: recreate the DB and traced build, then analyze
powershell -NoProfile -File tools/ci/run-codeql.ps1

# Advanced: re-run queries against the existing DB only (source must be unchanged)
powershell -NoProfile -File tools/ci/run-codeql.ps1 -AnalyzeOnly
```

What it does:

1. Validates the exact CodeQL Action/CLI/bundle versions pinned in
   [`.github/codeql/toolchain.json`](../.github/codeql/toolchain.json), refusing
   a different local CLI instead of silently using a newer query pack.
2. Deletes the previous database and `build/ci-codeql`, then traces a clean
   `cmake --preset ci-codeql` + `cmake --build --preset ci-codeql` (VS 2022).
3. Applies [`.github/codeql/codeql-config.yml`](../.github/codeql/codeql-config.yml)
   (`paths-ignore`: `build/**`, `third_party/**`).
4. Analyzes with [`.github/codeql/hdllib-security-extended.qls`](../.github/codeql/hdllib-security-extended.qls)
   (security-extended + alert suppression; excludes intentional
   `cpp/uncontrolled-process-operation` for this injection toolkit).
5. Writes `codeql-results.sarif` / `codeql-results.csv` and fails if any
   actionable alerts remain (only in-source `// codeql[...]` / `// lgtm[...]`
   suppressions are ignored — same as GitHub Code Scanning; override with
   `-AllowFindings`). Always passes `--rerun` so incremental cache cannot
   false-green after a database recreate.

If the pinned CodeQL version is already on `PATH`, omit `-InstallBundle`. Pass
`-CodeQlHome` to point at that exact unpacked bundle. `-AnalyzeOnly` is only for
re-querying a database when its extracted source is known to be unchanged; a
normal run always rebuilds so it cannot report against stale code.

## Interactive runner setup

For occasional open-source CI, the self-hosted runner can be this development
PC and can remain offline between runs. A dedicated Windows 11 VM or physical
machine is safer for frequent or multi-contributor use. Do not attach a runner
that holds production credentials to workflows which may execute untrusted code.

1. Install current Visual Studio 2022 Build Tools with the Desktop development
   with C++ workload, CMake 3.20 or newer, Git, and PowerShell 5.1 or newer.
2. Create a dedicated local runner account. Give it only the permissions the
   tests need and write access to the runner's work directory.
3. In the repository's **Settings > Actions > Runners** page, add a self-hosted
   Windows x64 runner. The workflows use its default `self-hosted`, `Windows`,
   and `X64` labels.
4. When runner setup asks whether to run as a Windows service, answer **No**.
   A service runs in session 0 and cannot provide the required desktop.
5. Sign in as the runner account and start `run.cmd` from that session. For
   automatic startup, create a Task Scheduler entry triggered **At log on**,
   select **Run only when user is logged on**, and launch `run.cmd` with its
   runner directory as the working directory.
6. Keep the session signed in and unlocked. Prefer a hypervisor console over an
   RDP session: disconnecting or locking RDP can remove access to the active
   desktop even while the runner process remains online.
7. Run `tools/ci/assert-interactive-desktop.ps1` in the runner session. It must
   report a nonzero session, a visible window station, an Explorer shell, a
   display, and successful window creation.
8. Keep the runner application current. `actions/checkout@v6` requires runner
   version 2.329.0 or later. The runner normally updates itself, but an offline
   runner can fall behind.

### Convert an existing service runner

Running `run.cmd` does not require registering a second runner. To preserve the
existing GitHub registration while moving an installed runner out of session 0,
open PowerShell as Administrator and run:

```powershell
$runnerRoot = 'C:\actions-runner'
$runnerService = Get-CimInstance Win32_Service |
    Where-Object {
        $_.Name -like 'actions.runner.*' -and
        $_.PathName -like "*$runnerRoot\bin\RunnerService.exe*"
    }

if ($null -eq $runnerService) {
    throw "No GitHub Actions service found under $runnerRoot."
}

Stop-Service -Name $runnerService.Name
Set-Service -Name $runnerService.Name -StartupType Disabled

$runnerUser = "$env:USERDOMAIN\$env:USERNAME"
$action = New-ScheduledTaskAction `
    -Execute "$env:SystemRoot\System32\cmd.exe" `
    -Argument "/d /s /c `"`"$runnerRoot\run.cmd`"`"" `
    -WorkingDirectory $runnerRoot
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $runnerUser
$principal = New-ScheduledTaskPrincipal `
    -UserId $runnerUser `
    -LogonType Interactive `
    -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -MultipleInstances IgnoreNew

Register-ScheduledTask `
    -TaskName 'GitHub Actions Runner (interactive)' `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal `
    -Settings $settings `
    -Force
Start-ScheduledTask -TaskName 'GitHub Actions Runner (interactive)'
```

Verify that `Runner.Listener.exe` moved to the signed-in user's nonzero session:

```powershell
Get-CimInstance Win32_Process -Filter "Name='Runner.Listener.exe'" |
    Select-Object ProcessId, SessionId
tools/ci/assert-interactive-desktop.ps1
```

The scheduled task starts automatically only after that user signs in. Keep the
session signed in and unlocked for GUI runs; Windows services cannot be moved
onto the interactive desktop by changing the workflow.

The GUI smoke job runs after the hosted build on every trusted push to `main`.
The GUI stress job runs nightly. Both can also be dispatched manually against
`main`; pull-request code is never sent to this runner. If the PC is offline,
the job remains queued until the runner comes online or the workflow is
cancelled. If you do not want GitHub orchestration for a particular run, use
the `ci-gui-smoke` and `ci-gui-full` presets locally instead.

The workflows place FetchContent checkouts under
`$env:RUNNER_TEMP\hdllib-fetchcontent`. On the example installation at
`C:\actions-runner`, this resolves beneath `C:\actions-runner\_work\_temp`.
It is separate from the repository checkout because it contains only downloaded
and built third-party dependencies. The `add-vs-cmake-to-path.ps1` helper finds
Visual Studio's bundled CMake through `vswhere`; the runner account does not
need a machine-wide CMake `PATH` entry.

## Security boundary

Do not add `pull_request` or `pull_request_target` execution to a persistent
self-hosted runner. Pull-request code can modify the build, tests, or workflow
and retain control of the machine after a job. The checked-in workflows allow
the GUI runner only when `github.ref` is exactly `refs/heads/main`.

Recommended repository settings:

- Protect `main` and require `hosted-build` plus CodeQL before merge.
- Put GUI runners in a runner group restricted to this repository.
- Do not expose production secrets, signing keys, personal browser sessions,
  or sensitive network access to the runner account.
- Snapshot or rebuild the VM regularly and after any suspected compromise.
- If GUI tests must become a pre-merge gate, provision a fresh ephemeral VM for
  each merge-queue job and destroy it afterward. Do not broaden the persistent
  runner's trigger.

## Quality-tool adoption

Changed C/C++ lines are checked against `.clang-format` in primary CI
(`tools/ci/check-format.ps1`). Format locally before commit:

```powershell
# One-time: point git at the repo hooks (formats staged C/C++ on commit)
powershell -NoProfile -File tools/ci/install-git-hooks.ps1

# Or format on demand
powershell -NoProfile -File tools/ci/fix-format.ps1 -Staged
powershell -NoProfile -File tools/ci/fix-format.ps1 -WorkingTree
```

actionlint validates workflow files with the custom runner labels in
`.github/actionlint.yaml`. CodeQL is blocking; run
`tools/ci/run-codeql.ps1` before push. clang-tidy and MSVC native analysis are
nightly and advisory while the existing warning baseline is reduced; remove
`continue-on-error` from those jobs once their output is clean. Dependabot
proposes updates to pinned GitHub Actions versions each week.
