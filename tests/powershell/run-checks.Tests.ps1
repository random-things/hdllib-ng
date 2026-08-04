Describe 'run-checks wrapper interface' {
    BeforeAll {
        $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
        $wrapper = Join-Path $repoRoot 'tools\ci\run-checks.ps1'
        $pwsh = (Get-Process -Id $PID).Path
        $env:HDL_WRAPPER_PESTER_ACTIVE = '1'

        function Invoke-Wrapper([string[]]$Arguments) {
            $output = & $pwsh -NoProfile -File $wrapper @Arguments 2>&1 | Out-String
            [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $output }
        }

        function Assert-Condition([bool]$Condition, [string]$Message) {
            if (-not $Condition) {
                throw $Message
            }
        }
    }

    It 'lists every registered check' {
        $result = Invoke-Wrapper @('-ListChecks')
        Assert-Condition ($result.ExitCode -eq 0) 'ListChecks should succeed.'
        $count = @($result.Output -split "`r?`n" | Where-Object { $_ }).Count
        Assert-Condition ($count -eq 18) "Expected 18 checks, found $count."
    }

    It 'expands Fast exactly' {
        $result = Invoke-Wrapper @('-Profile', 'Fast', '-DryRun')
        Assert-Condition ($result.ExitCode -eq 0) 'Fast dry run should succeed.'
        Assert-Condition ($result.Output -match 'Workflows, Format, DependencyPins, ReleaseHeadless') `
            'Fast profile did not expand to the expected checks.'
    }

    It 'expands All without duplicate checks' {
        $result = Invoke-Wrapper @('-Profile', 'All', '-DryRun')
        Assert-Condition ($result.ExitCode -eq 0) 'All dry run should succeed.'
        $checks = @($result.Output -split "`r?`n" |
            Where-Object { $_ -match '^(Format|Workflows|DependencyPins|Release|Gui|Backend|Asan|Clang|Msvc|CodeQL|Windows|Offline|Fuzz|Coverage)' })
        $uniqueCount = ($checks | Select-Object -Unique).Count
        Assert-Condition ($uniqueCount -eq $checks.Count) 'All profile contains duplicate checks.'
        Assert-Condition ($checks.Count -eq 18) "Expected 18 checks, found $($checks.Count)."
    }

    It 'rejects profile and check together' {
        $result = Invoke-Wrapper @('-Profile', 'Fast', '-Check', 'Format')
        Assert-Condition ($result.ExitCode -ne 0) 'Profile and Check should be mutually exclusive.'
    }

    It 'rejects coverage baseline mutation outside Coverage' {
        $result = Invoke-Wrapper @('-Check', 'Format', '-UpdateCoverageBaseline')
        Assert-Condition ($result.ExitCode -ne 0) `
            'UpdateCoverageBaseline should be rejected outside Coverage.'
    }
}

Describe 'run-checks failure handling' {
    BeforeAll {
        $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
        $wrapper = Join-Path $repoRoot 'tools\ci\run-checks.ps1'
        $pwsh = (Get-Process -Id $PID).Path
        $env:HDL_WRAPPER_PESTER_ACTIVE = '1'

        function Invoke-Wrapper([string[]]$Arguments) {
            $output = & $pwsh -NoProfile -File $wrapper @Arguments 2>&1 | Out-String
            [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $output }
        }

        function Assert-Condition([bool]$Condition, [string]$Message) {
            if (-not $Condition) {
                throw $Message
            }
        }
    }

    It 'reports prerequisite failures and writes a summary' {
        $oldProgramFiles = ${env:ProgramFiles(x86)}
        try {
            ${env:ProgramFiles(x86)} = $TestDrive
            $artifacts = Join-Path $TestDrive 'prerequisite-summary'
            $result = Invoke-Wrapper @('-Check', 'ReleaseHeadless', '-ArtifactsDir', $artifacts)
            Assert-Condition ($result.ExitCode -ne 0) 'Missing vswhere should fail the check.'
            $summary = Get-Content (Join-Path $artifacts 'summary.json') -Raw | ConvertFrom-Json
            Assert-Condition ($summary.Status -eq 'Failed') 'Prerequisite summary should report failure.'
            Assert-Condition ($summary.Message -match 'vswhere') `
                'Prerequisite summary should identify vswhere.'
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
            Assert-Condition ($result.ExitCode -ne 0) 'Tracked-file mutation should fail the check.'
            $summary = @(Get-Content (Join-Path $artifacts 'summary.json') -Raw | ConvertFrom-Json)
            $trackedResults = @($summary | Where-Object Check -eq 'TrackedFiles').Count
            Assert-Condition ($trackedResults -eq 1) `
                "Expected one TrackedFiles result, found $trackedResults."
        } finally {
            $env:PATH = $oldPath
        }
    }
}
