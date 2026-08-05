[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$BuildRoot
)

$ErrorActionPreference = 'Stop'

if ($env:OS -ne 'Windows_NT') {
    throw 'Injection tests require Windows.'
}

$defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
if ($null -eq $defender -or -not $defender.AntivirusEnabled) {
    Write-Host 'Microsoft Defender Antivirus is not active; no Defender exclusion is required.'
    return
}

$buildPath = [IO.Path]::GetFullPath($BuildRoot).TrimEnd('\')
$configuredRoots = @(
    ([Environment]::GetEnvironmentVariable(
            'HDL_INJECTION_TEST_EXCLUSION_ROOTS', 'Machine') -split ';') |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { [IO.Path]::GetFullPath($_).TrimEnd('\') }
)
$covered = @($configuredRoots | Where-Object {
        $buildPath.Equals($_, [StringComparison]::OrdinalIgnoreCase) -or
        $buildPath.StartsWith("$_\", [StringComparison]::OrdinalIgnoreCase)
    }).Count -gt 0

if (-not $covered) {
    $setup = Join-Path $PSScriptRoot 'configure-injection-runner.ps1'
    throw @"
Microsoft Defender Antivirus is enabled, but the injection-test build tree is not registered as excluded:
  $buildPath

Defender quarantines hdllib.dll when the live injection matrix runs. From an elevated PowerShell in this checkout, run:
  & '$setup'

Use -Remove to undo the exclusion and its machine configuration marker.
"@
}

Write-Host "Injection-test antivirus exclusion registered for: $buildPath"
