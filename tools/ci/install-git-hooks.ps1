[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location -LiteralPath $repoRoot

$hooksPath = Join-Path $repoRoot '.githooks'
if (-not (Test-Path -LiteralPath $hooksPath)) {
    throw "Missing hooks directory: $hooksPath"
}

& git config core.hooksPath .githooks
if ($LASTEXITCODE -ne 0) {
    throw 'git config core.hooksPath failed.'
}

$configured = (& git config --get core.hooksPath).Trim()
Write-Host "Git hooks path set to '$configured'."
Write-Host 'pre-commit will run tools/ci/fix-format.ps1 -Staged before each commit.'
