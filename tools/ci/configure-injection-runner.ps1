#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [switch]$Remove
)

$ErrorActionPreference = 'Stop'

if ($env:OS -ne 'Windows_NT') {
    throw 'The injection runner is supported only on Windows.'
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$buildRoot = [IO.Path]::GetFullPath((Join-Path $repoRoot 'build')).TrimEnd('\')
$variableName = 'HDL_INJECTION_TEST_EXCLUSION_ROOTS'
$existingRoots = @(
    ([Environment]::GetEnvironmentVariable($variableName, 'Machine') -split ';') |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { [IO.Path]::GetFullPath($_).TrimEnd('\') }
)

if ($Remove) {
    Remove-MpPreference -ExclusionPath $buildRoot
    $remainingRoots = @($existingRoots | Where-Object {
            -not $_.Equals($buildRoot, [StringComparison]::OrdinalIgnoreCase)
        })
    $remaining = if ($remainingRoots.Count -eq 0) { $null } else { $remainingRoots -join ';' }
    [Environment]::SetEnvironmentVariable($variableName, $remaining, 'Machine')
    Write-Host "Removed Microsoft Defender exclusion: $buildRoot"
    return
}

Add-MpPreference -ExclusionPath $buildRoot
$registered = @((Get-MpPreference).ExclusionPath | Where-Object {
        $_ -ieq $buildRoot
    }).Count -gt 0
if (-not $registered) {
    throw "Microsoft Defender did not register the requested exclusion: $buildRoot"
}
$configuredRoots = @($existingRoots + $buildRoot | Select-Object -Unique)
[Environment]::SetEnvironmentVariable($variableName, ($configuredRoots -join ';'), 'Machine')

Write-Host "Added Microsoft Defender exclusion: $buildRoot"
