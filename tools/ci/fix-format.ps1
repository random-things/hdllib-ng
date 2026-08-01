[CmdletBinding()]
param(
    # Explicit files (repo-relative or absolute).
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Path,

    # Format index (staged) C/C++ files and re-stage them. Used by the git pre-commit hook.
    [switch]$Staged,

    # Format dirty working-tree C/C++ files (staged + unstaged).
    [switch]$WorkingTree
)

$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot '_clang-format.ps1')

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location -LiteralPath $repoRoot

$clangFormat = Resolve-ClangFormat
$pathSpecs = @('*.c', '*.cc', '*.cpp', '*.h', '*.hpp')

function Get-RepoRelativePath {
    param([string]$FullPath)
    $full = (Resolve-Path -LiteralPath $FullPath).Path
    $root = $repoRoot.TrimEnd('\', '/')
    if ($full.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) {
        return ($full.Substring($root.Length).TrimStart('\', '/') -replace '\\', '/')
    }
    return ($full -replace '\\', '/')
}

$files = @()
if ($Path -and $Path.Count -gt 0) {
    foreach ($p in $Path) {
        if ([string]::IsNullOrWhiteSpace($p)) { continue }
        $full = if ([System.IO.Path]::IsPathRooted($p)) { $p } else { Join-Path $repoRoot $p }
        if (-not (Test-Path -LiteralPath $full)) {
            Write-Warning "Skipping missing path: $p"
            continue
        }
        $files += (Get-RepoRelativePath -FullPath $full)
    }
}
elseif ($Staged) {
    $files = @(& git diff --cached --name-only --diff-filter=ACMR -- $pathSpecs)
}
elseif ($WorkingTree) {
    $files = @(
        & git diff --name-only --diff-filter=ACMR -- $pathSpecs
        & git diff --cached --name-only --diff-filter=ACMR -- $pathSpecs
        & git ls-files --others --exclude-standard -- $pathSpecs
    )
}
else {
    # Default: dirty working tree (staged + unstaged). Pre-commit passes -Staged.
    $files = @(
        & git diff --name-only --diff-filter=ACMR -- $pathSpecs
        & git diff --cached --name-only --diff-filter=ACMR -- $pathSpecs
    )
}

$files = @($files) |
    Where-Object { Test-IsFormattableCppPath -Path $_ } |
    Sort-Object -Unique

if ($files.Count -eq 0) {
    Write-Host 'No C/C++ files to format.'
    exit 0
}

$formatted = 0
foreach ($file in $files) {
    $full = Join-Path $repoRoot ($file -replace '/', '\')
    if (-not (Test-Path -LiteralPath $full)) { continue }
    & $clangFormat -i --style=file -- $full
    if ($LASTEXITCODE -ne 0) {
        throw "clang-format failed on $file (exit $LASTEXITCODE)."
    }
    $formatted++
    if ($Staged) {
        & git add -- $file
        if ($LASTEXITCODE -ne 0) {
            throw "git add failed for $file after formatting."
        }
    }
}

Write-Host "clang-format applied to $formatted file(s)."
