$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$wrapper = Join-Path $repoRoot 'tools\ci\run-checks.ps1'
$pwsh = (Get-Process -Id $PID).Path
$env:HDL_WRAPPER_PESTER_ACTIVE = '1'

function Invoke-Wrapper([string[]]$Arguments) {
    $output = & $pwsh -NoProfile -File $wrapper @Arguments 2>&1 | Out-String
    [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $output }
}

Describe 'run-checks wrapper interface' {
    It 'lists every registered check' {
        $result = Invoke-Wrapper @('-ListChecks')
        $result.ExitCode | Should Be 0
        @($result.Output -split "`r?`n" | Where-Object { $_ }).Count | Should Be 18
    }

    It 'expands Fast exactly' {
        $result = Invoke-Wrapper @('-Profile', 'Fast', '-DryRun')
        $result.ExitCode | Should Be 0
        $result.Output | Should Match 'Workflows, Format, DependencyPins, ReleaseHeadless'
    }

    It 'expands All without duplicate checks' {
        $result = Invoke-Wrapper @('-Profile', 'All', '-DryRun')
        $result.ExitCode | Should Be 0
        $checks = @($result.Output -split "`r?`n" |
            Where-Object { $_ -match '^(Format|Workflows|DependencyPins|Release|Gui|Backend|Asan|Clang|Msvc|CodeQL|Windows|Offline|Fuzz|Coverage)' })
        ($checks | Select-Object -Unique).Count | Should Be $checks.Count
        $checks.Count | Should Be 18
    }

    It 'rejects profile and check together' {
        $result = Invoke-Wrapper @('-Profile', 'Fast', '-Check', 'Format')
        $result.ExitCode | Should Not Be 0
    }

    It 'rejects coverage baseline mutation outside Coverage' {
        $result = Invoke-Wrapper @('-Check', 'Format', '-UpdateCoverageBaseline')
        $result.ExitCode | Should Not Be 0
    }
}

Describe 'run-checks failure handling' {
    It 'reports prerequisite failures and writes a summary' {
        $oldProgramFiles = ${env:ProgramFiles(x86)}
        try {
            ${env:ProgramFiles(x86)} = $TestDrive
            $artifacts = Join-Path $TestDrive 'prerequisite-summary'
            $result = Invoke-Wrapper @('-Check', 'ReleaseHeadless', '-ArtifactsDir', $artifacts)
            $result.ExitCode | Should Not Be 0
            $summary = Get-Content (Join-Path $artifacts 'summary.json') -Raw | ConvertFrom-Json
            $summary.Status | Should Be 'Failed'
            $summary.Message | Should Match 'vswhere'
        } finally {
            ${env:ProgramFiles(x86)} = $oldProgramFiles
        }
    }

    It 'detects a changed tracked-status snapshot' {
        $fakeBin = Join-Path $TestDrive 'fake-bin'
        New-Item -ItemType Directory -Force -Path $fakeBin | Out-Null
        $counter = Join-Path $TestDrive 'git-count.txt'
        @"
@echo off
set /a count=0
if exist "$counter" set /p count=<"$counter"
set /a count=count+1
>"$counter" echo %count%
if %count% GEQ 2 echo  M synthetic-file
exit /b 0
"@ | Set-Content (Join-Path $fakeBin 'git.cmd') -Encoding ascii
        "@echo off`r`nexit /b 0" | Set-Content (Join-Path $fakeBin 'go.cmd') -Encoding ascii

        $oldPath = $env:PATH
        try {
            $env:PATH = $fakeBin
            $artifacts = Join-Path $TestDrive 'mutation-summary'
            $result = Invoke-Wrapper @('-Check', 'Workflows', '-ArtifactsDir', $artifacts)
            $result.ExitCode | Should Not Be 0
            $summary = @(Get-Content (Join-Path $artifacts 'summary.json') -Raw | ConvertFrom-Json)
            @($summary | Where-Object Check -eq 'TrackedFiles').Count | Should Be 1
        } finally {
            $env:PATH = $oldPath
        }
    }
}
