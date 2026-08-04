[CmdletBinding(DefaultParameterSetName = 'Profile')]
param(
    [Parameter(ParameterSetName = 'Profile')]
    [ValidateSet('Fast', 'PR', 'Nightly', 'GUI', 'All')]
    [string]$Profile = 'Fast',

    [Parameter(Mandatory, ParameterSetName = 'Check')]
    [ValidateSet('Format', 'Workflows', 'DependencyPins', 'ReleaseHeadless', 'GuiSmoke',
        'GuiStress', 'BackendZydis', 'BackendCapstone', 'AsanHeadless',
        'AsanGuiLifecycle', 'ClangTidy', 'MsvcAnalyze', 'CodeQL', 'WindowsCanary',
        'OfflineBuild', 'FuzzSmoke', 'FuzzExtended', 'Coverage')]
    [string]$Check,

    [string]$BaseRevision,
    [string]$FetchContentDir,
    [string]$ArtifactsDir,
    [switch]$Bootstrap,
    [switch]$FailFast,
    [switch]$ListChecks,
    [switch]$DryRun,
    [switch]$UpdateCoverageBaseline
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$originalLocation = Get-Location
$allChecks = @(
    'Format', 'Workflows', 'DependencyPins', 'ReleaseHeadless', 'GuiSmoke', 'GuiStress',
    'BackendZydis', 'BackendCapstone', 'AsanHeadless', 'AsanGuiLifecycle', 'ClangTidy',
    'MsvcAnalyze', 'CodeQL', 'WindowsCanary', 'OfflineBuild', 'FuzzSmoke',
    'FuzzExtended', 'Coverage'
)
$profiles = [ordered]@{
    Fast = @('Workflows', 'Format', 'DependencyPins', 'ReleaseHeadless')
    PR = @('Workflows', 'Format', 'DependencyPins', 'ReleaseHeadless', 'FuzzSmoke', 'Coverage', 'CodeQL')
    Nightly = @('BackendZydis', 'BackendCapstone', 'AsanHeadless', 'ClangTidy',
        'MsvcAnalyze', 'WindowsCanary', 'OfflineBuild', 'FuzzExtended')
    GUI = @('GuiSmoke', 'GuiStress', 'AsanGuiLifecycle')
}
$profiles.All = @($profiles.PR + $profiles.Nightly + $profiles.GUI | Select-Object -Unique)

function Resolve-OutputPath {
    param([string]$Value, [string]$Default)
    $chosen = if ([string]::IsNullOrWhiteSpace($Value)) { $Default } else { $Value }
    if ([IO.Path]::IsPathRooted($chosen)) {
        return [IO.Path]::GetFullPath($chosen)
    }
    return [IO.Path]::GetFullPath((Join-Path $repoRoot $chosen))
}

function Get-ProcessEnvironmentSnapshot {
    $snapshot = @{}
    Get-ChildItem Env: | ForEach-Object { $snapshot[$_.Name] = $_.Value }
    return $snapshot
}

function Restore-ProcessEnvironment {
    param([Parameter(Mandatory)][hashtable]$Snapshot)
    foreach ($entry in @(Get-ChildItem Env:)) {
        if (-not $Snapshot.ContainsKey($entry.Name)) {
            [Environment]::SetEnvironmentVariable($entry.Name, $null, 'Process')
        }
    }
    foreach ($entry in $Snapshot.GetEnumerator()) {
        [Environment]::SetEnvironmentVariable($entry.Key, $entry.Value, 'Process')
    }
    $script:vsEnvironmentImported = $false
    $script:vsInstallationPath = $null
    $script:vsVersion = $null
}

function Invoke-Native {
    param([Parameter(Mandatory)][string]$File, [string[]]$Arguments = @())
    Write-Host "> $File $($Arguments -join ' ')"
    & $File @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code ${LASTEXITCODE}: $File"
    }
}

function Add-ToolDirectory {
    param([Parameter(Mandatory)][string]$Path)
    $normalized = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $entries = @($env:PATH -split ';' | Where-Object { $_ })
    $entries = @($entries | Where-Object {
            -not [IO.Path]::GetFullPath($_).TrimEnd('\').Equals(
                $normalized, [StringComparison]::OrdinalIgnoreCase)
        })
    $env:PATH = (@($normalized) + $entries) -join ';'
}

function Select-NewestExecutable {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string[]]$Candidates,
        [string[]]$VersionArguments = @('--version')
    )
    $found = @()
    $seen = @{}
    foreach ($candidate in $Candidates) {
        if ([string]::IsNullOrWhiteSpace($candidate) -or
            -not (Test-Path -LiteralPath $candidate -PathType Leaf)) { continue }
        $resolved = [IO.Path]::GetFullPath($candidate)
        if ($seen.ContainsKey($resolved)) { continue }
        $seen[$resolved] = $true
        try {
            $versionText = (& $resolved @VersionArguments 2>&1 | Out-String)
            $match = [regex]::Match($versionText, '(?<!\d)(?<version>\d+\.\d+(?:\.\d+){0,2})')
            if ($match.Success) {
                $found += [pscustomobject]@{
                    Path = $resolved
                    Version = [version]$match.Groups['version'].Value
                }
            }
        } catch {
            Write-Verbose "Unable to query $Name candidate '$resolved': $($_.Exception.Message)"
        }
    }
    $selected = $found | Sort-Object Version -Descending | Select-Object -First 1
    if (-not $selected) { throw "$Name was not found in any supported tool location." }
    Add-ToolDirectory (Split-Path -Parent $selected.Path)
    Write-Host "Using $Name $($selected.Version): $($selected.Path)"
    return $selected
}

function Get-CommandCandidates {
    param([Parameter(Mandatory)][string]$Name)
    return @(Get-Command $Name -All -CommandType Application -ErrorAction SilentlyContinue |
        ForEach-Object Source)
}

function Import-VisualStudioEnvironment {
    if ($script:vsEnvironmentImported) { return }
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) {
        throw "vswhere.exe was not found at '$vswhere'. Install VS 2026 or VS 2022 Build Tools with C++."
    }
    $instance = @(& $vswhere -latest -products '*' `
            -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -format json |
            ConvertFrom-Json) | Select-Object -First 1
    if (-not $instance) {
        throw 'No Visual Studio installation with the x64 C++ toolchain was found.'
    }
    $install = [string]$instance.installationPath
    $vsVersion = [version]$instance.installationVersion
    $vsDevCmd = Join-Path $install 'Common7\Tools\VsDevCmd.bat'
    $vsEnvironmentCommand = "`"$vsDevCmd`" -no_logo -arch=x64 -host_arch=x64 && set"
    $environmentLines = & $env:ComSpec /d /s /c $vsEnvironmentCommand
    if ($LASTEXITCODE -ne 0) { throw 'VsDevCmd.bat failed.' }
    foreach ($line in $environmentLines) {
        $separator = $line.IndexOf('=')
        if ($separator -gt 0) {
            [Environment]::SetEnvironmentVariable(
                $line.Substring(0, $separator), $line.Substring($separator + 1), 'Process')
        }
    }
    if ($env:HDL_EXPECTED_VS_MAJOR -and
        $vsVersion.Major -ne [int]$env:HDL_EXPECTED_VS_MAJOR) {
        throw "Expected Visual Studio major $env:HDL_EXPECTED_VS_MAJOR but selected $vsVersion at '$install'."
    }

    $cmakeCandidates = @(
        (Join-Path $install 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'),
        (Join-Path $env:ProgramFiles 'CMake\bin\cmake.exe')
    ) + @(Get-ChildItem -Path (Join-Path $script:cachePath 'cmake-*\bin\cmake.exe') `
        -File -ErrorAction SilentlyContinue | ForEach-Object FullName) +
        @(Get-CommandCandidates 'cmake.exe')
    $cmake = Select-NewestExecutable 'CMake' $cmakeCandidates

    $ninjaCandidates = @(
        (Join-Path $install 'Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe'),
        (Join-Path $env:ProgramFiles 'CMake\bin\ninja.exe')
    ) + @(Get-CommandCandidates 'ninja.exe')
    $ninja = Select-NewestExecutable 'Ninja' $ninjaCandidates

    $manifest = Get-Content (Join-Path $PSScriptRoot 'toolchain.json') -Raw | ConvertFrom-Json
    if ($vsVersion.Major -ge [int]$manifest.windows.primaryVisualStudioMajor) {
        if ($cmake.Version -lt [version]$manifest.windows.primaryCmakeMinimum) {
            throw "VS 2026 builds require CMake $($manifest.windows.primaryCmakeMinimum) or newer."
        }
        if ($ninja.Version -lt [version]$manifest.windows.primaryNinjaMinimum) {
            throw "VS 2026 builds require Ninja $($manifest.windows.primaryNinjaMinimum) or newer."
        }
    }

    $script:vsInstallationPath = $install
    $script:vsVersion = $vsVersion
    Write-Host "Using Visual Studio ${vsVersion}: $install"
    $script:vsEnvironmentImported = $true
}

function Select-LlvmToolchain {
    param([Parameter(Mandatory)][string[]]$RequiredTools)
    Import-VisualStudioEnvironment
    $directories = @(
        (Join-Path $script:vsInstallationPath 'VC\Tools\Llvm\x64\bin'),
        (Join-Path $env:ProgramFiles 'LLVM\bin')
    )
    $directories += @(Get-ChildItem -Path (Join-Path $script:cachePath 'llvm-*\bin') `
        -Directory -ErrorAction SilentlyContinue | ForEach-Object FullName)
    foreach ($name in $RequiredTools) {
        $directories += @(Get-CommandCandidates "$name.exe" | ForEach-Object { Split-Path -Parent $_ })
    }

    $choices = @()
    foreach ($directory in @($directories | Select-Object -Unique)) {
        if ([string]::IsNullOrWhiteSpace($directory) -or
            -not (Test-Path -LiteralPath $directory -PathType Container)) { continue }
        $missing = @($RequiredTools | Where-Object {
                -not (Test-Path -LiteralPath (Join-Path $directory "$_.exe") -PathType Leaf)
            })
        if ($missing.Count -gt 0) { continue }
        $probe = Join-Path $directory "$($RequiredTools[0]).exe"
        $versionText = (& $probe --version 2>&1 | Out-String)
        $match = [regex]::Match($versionText, '(?<!\d)(?<version>\d+\.\d+(?:\.\d+){0,2})')
        if ($match.Success) {
            $choices += [pscustomobject]@{
                Directory = [IO.Path]::GetFullPath($directory)
                Version = [version]$match.Groups['version'].Value
            }
        }
    }
    $selected = $choices | Sort-Object Version -Descending | Select-Object -First 1
    if (-not $selected) {
        throw "No single LLVM toolchain contains: $($RequiredTools -join ', ')."
    }
    $manifest = Get-Content (Join-Path $PSScriptRoot 'toolchain.json') -Raw | ConvertFrom-Json
    if ($selected.Version -lt [version]$manifest.windows.llvmMinimum) {
        throw "LLVM $($manifest.windows.llvmMinimum) or newer is required; selected $($selected.Version)."
    }
    Add-ToolDirectory $selected.Directory
    Write-Host "Using LLVM $($selected.Version): $($selected.Directory)"
    return $selected
}

function Get-CMakePresetArguments {
    param([Parameter(Mandatory)][string]$Preset, [string[]]$Additional = @())
    $expectedGenerator = if ($Preset -eq 'ci-vs2022-compat') {
        'Visual Studio 17 2022'
    } else {
        'Ninja'
    }
    $arguments = @('--preset', $Preset) + $Additional
    $cache = Join-Path $repoRoot "build\$Preset\CMakeCache.txt"
    if (Test-Path -LiteralPath $cache -PathType Leaf) {
        $generatorLine = Get-Content -LiteralPath $cache -ErrorAction SilentlyContinue |
            Where-Object { $_ -like 'CMAKE_GENERATOR:INTERNAL=*' } | Select-Object -First 1
        if ($generatorLine) {
            $currentGenerator = $generatorLine.Substring($generatorLine.IndexOf('=') + 1)
            if ($currentGenerator -ne $expectedGenerator) {
                Write-Host "Resetting $Preset after generator change: $currentGenerator -> $expectedGenerator"
                $arguments = @('--fresh') + $arguments
            }
        }
    }
    return $arguments
}

function Invoke-CMakeCheck {
    param(
        [string]$ConfigurePreset,
        [string]$BuildPreset,
        [string]$TestPreset,
        [string]$FetchNamespace
    )
    Import-VisualStudioEnvironment
    if ([string]::IsNullOrWhiteSpace($FetchNamespace)) {
        $FetchNamespace = $ConfigurePreset
    }
    $checkFetchPath = Join-Path $script:fetchPath $FetchNamespace
    New-Item -ItemType Directory -Force -Path $checkFetchPath | Out-Null
    $configureArguments = Get-CMakePresetArguments $ConfigurePreset `
        @("-DFETCHCONTENT_BASE_DIR=$checkFetchPath")
    Invoke-Native cmake $configureArguments
    Invoke-Native cmake @('--build', '--preset', $BuildPreset, '--parallel')
    if (-not [string]::IsNullOrWhiteSpace($TestPreset)) {
        Invoke-Native ctest @('--preset', $TestPreset)
    }
}

function Assert-InteractiveDesktop {
    & (Join-Path $PSScriptRoot 'assert-interactive-desktop.ps1')
}

function Invoke-FuzzerCheck {
    param([bool]$Extended)
    Import-VisualStudioEnvironment
    Select-LlvmToolchain @('clang-cl', 'lld-link', 'llvm-mt') | Out-Null
    $fuzzFetchPath = Join-Path $script:fetchPath 'ci-fuzz'
    New-Item -ItemType Directory -Force -Path $fuzzFetchPath | Out-Null
    $configureArguments = Get-CMakePresetArguments 'ci-fuzz' `
        @("-DFETCHCONTENT_BASE_DIR=$fuzzFetchPath")
    Invoke-Native cmake $configureArguments
    $fuzzerTargets = @('hdl_fuzz_ipc', 'hdl_fuzz_search', 'hdl_fuzz_pe',
        'hdl_fuzz_json', 'hdl_fuzz_invocation')
    Invoke-Native cmake (@('--build', '--preset', 'ci-fuzz', '--parallel', '4', '--target') +
        $fuzzerTargets)
    $fuzzRoot = Join-Path $repoRoot 'build\ci-fuzz'
    $fuzzArtifacts = Join-Path $script:artifactPath 'fuzz'
    New-Item -ItemType Directory -Force -Path $fuzzArtifacts | Out-Null
    foreach ($name in $fuzzerTargets) {
        $exe = Get-ChildItem -LiteralPath $fuzzRoot -Filter "$name.exe" -Recurse |
            Select-Object -First 1
        if (-not $exe) { throw "Fuzzer executable '$name.exe' was not built." }
        $corpus = Join-Path $fuzzArtifacts "corpus\$name"
        $failures = Join-Path $fuzzArtifacts "failures\$name"
        New-Item -ItemType Directory -Force -Path $corpus, $failures | Out-Null
        $arguments = @($corpus, "-artifact_prefix=$failures\", '-max_len=65536',
            '-rss_limit_mb=4096')
        $arguments += if ($Extended) { '-max_total_time=300' } else { '-runs=5000' }
        Invoke-Native $exe.FullName $arguments
    }
}

function Get-TrackedStatus {
    $statusLines = @(& git status --porcelain=v1 --untracked-files=no)
    if ($UpdateCoverageBaseline) {
        $statusLines = @($statusLines | Where-Object {
                $_ -notmatch 'tools/ci/coverage-baseline\.json$'
            })
    }
    return ($statusLines -join "`n")
}

function Invoke-RegisteredCheck {
    param([string]$Name)
    switch ($Name) {
        'Format' {
            Select-LlvmToolchain @('clang-format') | Out-Null
            & (Join-Path $PSScriptRoot 'check-format.ps1') -BaseRevision $BaseRevision
        }
        'Workflows' {
            $manifest = Get-Content (Join-Path $PSScriptRoot 'toolchain.json') -Raw | ConvertFrom-Json
            if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
                throw 'Go is required to run the pinned actionlint package.'
            }
            Invoke-Native go @('run', "github.com/rhysd/actionlint/cmd/actionlint@$($manifest.actionlintVersion)",
                '-no-color', '-config-file', '.github/actionlint.yaml')
            if ((Get-Module -ListAvailable -Name Pester) -and -not $env:HDL_WRAPPER_PESTER_ACTIVE) {
                $previousPesterMarker = $env:HDL_WRAPPER_PESTER_ACTIVE
                try {
                    $env:HDL_WRAPPER_PESTER_ACTIVE = '1'
                    $pesterCommand = Get-Command Invoke-Pester
                    $pesterPath = Join-Path $repoRoot 'tests\powershell'
                    if ($pesterCommand.Parameters.ContainsKey('CI')) {
                        & $pesterCommand -Path $pesterPath -CI
                    } else {
                        $pesterResult = & $pesterCommand -Script $pesterPath -PassThru
                        if ($pesterResult.FailedCount -gt 0) {
                            throw "$($pesterResult.FailedCount) Pester test(s) failed."
                        }
                    }
                } finally {
                    $env:HDL_WRAPPER_PESTER_ACTIVE = $previousPesterMarker
                }
            } else {
                Write-Warning 'Pester is not installed; wrapper unit tests were not run.'
            }
        }
        'DependencyPins' { & (Join-Path $PSScriptRoot 'check-dependency-pins.ps1') }
        'ReleaseHeadless' { Invoke-CMakeCheck 'ci-windows' 'ci-windows' 'ci-headless' }
        'GuiSmoke' {
            Assert-InteractiveDesktop
            Invoke-CMakeCheck 'ci-gui' 'ci-gui' 'ci-gui-smoke'
        }
        'GuiStress' {
            Assert-InteractiveDesktop
            Invoke-CMakeCheck 'ci-gui' 'ci-gui' $null
            Invoke-Native ctest @('--preset', 'ci-gui-smoke', '--repeat', 'until-fail:3')
            Invoke-Native ctest @('--preset', 'ci-gui-full')
        }
        'BackendZydis' { Invoke-CMakeCheck 'ci-zydis' 'ci-zydis' 'ci-zydis-headless' }
        'BackendCapstone' { Invoke-CMakeCheck 'ci-capstone' 'ci-capstone' 'ci-capstone-headless' }
        'AsanHeadless' {
            Invoke-CMakeCheck 'ci-asan' 'ci-asan' $null
            & (Join-Path $PSScriptRoot 'add-msvc-asan-runtime-to-path.ps1')
            $env:ASAN_OPTIONS = 'halt_on_error=1'
            Invoke-Native ctest @('--preset', 'ci-asan-headless')
        }
        'AsanGuiLifecycle' {
            Assert-InteractiveDesktop
            Invoke-CMakeCheck 'ci-asan-gui' 'ci-asan-gui' $null
            & (Join-Path $PSScriptRoot 'add-msvc-asan-runtime-to-path.ps1')
            $env:ASAN_OPTIONS = 'halt_on_error=1'
            Invoke-Native ctest @('--preset', 'ci-asan-gui-lifecycle')
        }
        'ClangTidy' {
            Select-LlvmToolchain @('clang-tidy') | Out-Null
            Invoke-CMakeCheck 'ci-clang-tidy' 'ci-clang-tidy' $null
        }
        'MsvcAnalyze' { Invoke-CMakeCheck 'ci-msvc-analyze' 'ci-msvc-analyze' $null }
        'CodeQL' {
            Import-VisualStudioEnvironment
            $codeqlFetchPath = Join-Path $script:fetchPath 'ci-codeql'
            New-Item -ItemType Directory -Force -Path $codeqlFetchPath | Out-Null
            $codeqlArgs = @{
                DatabaseDir = (Join-Path $script:artifactPath 'codeql\database')
                SarifOut = (Join-Path $script:artifactPath 'codeql\codeql-results.sarif')
                CsvOut = (Join-Path $script:artifactPath 'codeql\codeql-results.csv')
                CacheDir = (Join-Path $script:cachePath 'codeql')
                FetchContentDir = $codeqlFetchPath
            }
            if ($Bootstrap) { $codeqlArgs.InstallBundle = $true }
            & (Join-Path $PSScriptRoot 'run-codeql.ps1') @codeqlArgs
        }
        'WindowsCanary' {
            Invoke-CMakeCheck 'ci-vs2022-compat' 'ci-vs2022-compat' `
                'ci-vs2022-compat-headless'
        }
        'OfflineBuild' {
            Import-VisualStudioEnvironment
            $offlineFetchPath = Join-Path $script:fetchPath 'offline'
            New-Item -ItemType Directory -Force -Path $offlineFetchPath | Out-Null
            $warmArguments = Get-CMakePresetArguments 'ci-windows' `
                @("-DFETCHCONTENT_BASE_DIR=$offlineFetchPath")
            Invoke-Native cmake $warmArguments
            $offline = [IO.Path]::GetFullPath((Join-Path $repoRoot 'build\ci-offline'))
            $buildRoot = [IO.Path]::GetFullPath((Join-Path $repoRoot 'build')) + [IO.Path]::DirectorySeparatorChar
            if (-not $offline.StartsWith($buildRoot, [StringComparison]::OrdinalIgnoreCase)) {
                throw "Refusing to remove unexpected offline build path '$offline'."
            }
            if (Test-Path -LiteralPath $offline) { Remove-Item -LiteralPath $offline -Recurse -Force }
            Invoke-CMakeCheck 'ci-offline' 'ci-offline' 'ci-offline-headless' 'offline'
        }
        'FuzzSmoke' { Invoke-FuzzerCheck $false }
        'FuzzExtended' { Invoke-FuzzerCheck $true }
        'Coverage' {
            Import-VisualStudioEnvironment
            Select-LlvmToolchain @('clang-cl', 'lld-link', 'llvm-mt',
                'llvm-profdata', 'llvm-cov') | Out-Null
            $coverageFetchPath = Join-Path $script:fetchPath 'ci-coverage'
            New-Item -ItemType Directory -Force -Path $coverageFetchPath | Out-Null
            & (Join-Path $PSScriptRoot 'run-coverage.ps1') -FetchContentDir $coverageFetchPath `
                -ArtifactsDir (Join-Path $script:artifactPath 'coverage') `
                -UpdateBaseline:$UpdateCoverageBaseline
        }
        default { throw "Unknown check '$Name'." }
    }
}

$failureMessage = $null
try {
    Set-Location -LiteralPath $repoRoot
    if ($ListChecks) {
        $allChecks | ForEach-Object { Write-Output $_ }
        return
    }
    if ($UpdateCoverageBaseline -and $env:CI) {
        throw '-UpdateCoverageBaseline is forbidden in CI.'
    }
    if ($UpdateCoverageBaseline -and $Check -ne 'Coverage') {
        throw '-UpdateCoverageBaseline is valid only with -Check Coverage.'
    }

    $defaultCache = if ($env:CI -and $env:RUNNER_TEMP) {
        Join-Path $env:RUNNER_TEMP 'hdllib-tooling-cache'
    } else {
        Join-Path $repoRoot 'build\tooling\cache'
    }
    $script:cachePath = Resolve-OutputPath $null $defaultCache
    $script:fetchPath = Resolve-OutputPath $FetchContentDir (Join-Path $script:cachePath 'fetchcontent')
    $script:artifactPath = Resolve-OutputPath $ArtifactsDir (Join-Path $repoRoot 'build\tooling\artifacts')
    New-Item -ItemType Directory -Force -Path $script:cachePath, $script:fetchPath,
        $script:artifactPath | Out-Null

    $selected = if ($PSCmdlet.ParameterSetName -eq 'Check') { @($Check) } else { @($profiles[$Profile]) }
    if ($DryRun) {
        Write-Host "Dry run; selected checks: $($selected -join ', ')"
        $selected | ForEach-Object { Write-Output $_ }
        return
    }

    $beforeStatus = Get-TrackedStatus
    $results = @()
    foreach ($name in $selected) {
        $environmentSnapshot = Get-ProcessEnvironmentSnapshot
        $started = Get-Date
        $status = 'Passed'
        $message = ''
        $logDir = Join-Path $script:artifactPath 'logs'
        New-Item -ItemType Directory -Force -Path $logDir | Out-Null
        $logPath = Join-Path $logDir "$name.log"
        $transcriptStarted = $false
        try {
            Start-Transcript -LiteralPath $logPath -Force | Out-Null
            $transcriptStarted = $true
            Write-Host "`n=== $name ==="
            Invoke-RegisteredCheck $name
        } catch {
            $status = 'Failed'
            $message = $_.Exception.Message
            Write-Error -ErrorAction Continue $message
        } finally {
            if ($transcriptStarted) { Stop-Transcript | Out-Null }
            Restore-ProcessEnvironment $environmentSnapshot
        }
        $results += [pscustomobject]@{
            Check = $name
            Status = $status
            Duration = ((Get-Date) - $started).ToString('hh\:mm\:ss')
            Message = $message
        }
        if ($status -eq 'Failed' -and $FailFast) { break }
    }

    $afterStatus = Get-TrackedStatus
    if ($beforeStatus -ne $afterStatus) {
        $results += [pscustomobject]@{
            Check = 'TrackedFiles'
            Status = 'Failed'
            Duration = '00:00:00'
            Message = 'A check unexpectedly modified tracked files.'
        }
    }

    $table = $results | Format-Table -AutoSize | Out-String
    Write-Host "`n$table"
    if ($env:GITHUB_STEP_SUMMARY) {
        "## hdllib checks`n`n| Check | Status | Duration | Message |`n|---|---|---:|---|" |
            Out-File -LiteralPath $env:GITHUB_STEP_SUMMARY -Append -Encoding utf8
        foreach ($result in $results) {
            "| $($result.Check) | $($result.Status) | $($result.Duration) | $($result.Message -replace '\|', '\|') |" |
                Out-File -LiteralPath $env:GITHUB_STEP_SUMMARY -Append -Encoding utf8
        }
    }
    $summaryJson = Join-Path $script:artifactPath 'summary.json'
    $results | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $summaryJson -Encoding utf8
    if (@($results | Where-Object Status -eq 'Failed').Count -gt 0) {
        $failureMessage = 'One or more checks failed. See the summary and per-check logs.'
    }
} finally {
    Set-Location -LiteralPath $originalLocation
}

if ($failureMessage) { throw $failureMessage }
