[CmdletBinding()]
param(
    [string]$BaseRevision
)

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot '_clang-format.ps1')

$clangFormatPath = Resolve-ClangFormat
$pathSpecs = @('*.c', '*.cc', '*.cpp', '*.h', '*.hpp')

if ([string]::IsNullOrWhiteSpace($BaseRevision) -or
    $BaseRevision -match '^0+$') {
    if (-not [string]::IsNullOrWhiteSpace($env:GITHUB_BASE_REF)) {
        $BaseRevision = "origin/$($env:GITHUB_BASE_REF)"
    }
}

if ([string]::IsNullOrWhiteSpace($BaseRevision) -or
    $BaseRevision -match '^0+$') {
    & git rev-parse --verify 'HEAD^' *> $null
    if ($LASTEXITCODE -eq 0) {
        $BaseRevision = 'HEAD^'
    }
}

$checkEntireFile = $false
if ([string]::IsNullOrWhiteSpace($BaseRevision) -or
    $BaseRevision -match '^0+$') {
    $files = & git ls-files -- $pathSpecs
    $checkEntireFile = $true
}
else {
    & git rev-parse --verify "$BaseRevision^{commit}" *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "Base revision '$BaseRevision' is not available in this checkout."
    }
    $files = & git diff --name-only --diff-filter=ACMR "$BaseRevision...HEAD" -- $pathSpecs
}

$files = @($files) |
    Where-Object { Test-IsFormattableCppPath -Path $_ } |
    Sort-Object -Unique

if ($files.Count -eq 0) {
    Write-Host 'No changed C/C++ files require formatting checks.'
    exit 0
}

$failed = $false
foreach ($file in $files) {
    $formatArguments = @('--dry-run', '--Werror', '--style=file')
    if (-not $checkEntireFile) {
        $diffLines = & git diff --unified=0 --no-color "$BaseRevision...HEAD" -- $file
        foreach ($line in $diffLines) {
            $match = [regex]::Match(
                $line,
                '^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@')
            if (-not $match.Success) {
                continue
            }

            $start = [int]$match.Groups[1].Value
            $count = if ($match.Groups[2].Success) {
                [int]$match.Groups[2].Value
            }
            else {
                1
            }
            if ($count -gt 0) {
                $end = $start + $count - 1
                $formatArguments += "--lines=$start`:$end"
            }
        }

        if ($formatArguments.Count -eq 3) {
            continue
        }
    }

    & $clangFormatPath @formatArguments -- $file
    if ($LASTEXITCODE -ne 0) {
        $failed = $true
    }
}

if ($failed) {
    throw 'clang-format found files that do not match .clang-format.'
}

Write-Host "clang-format checked $($files.Count) changed file(s)."
