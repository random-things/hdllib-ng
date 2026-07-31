[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere)) {
    throw "vswhere.exe was not found at '$vswhere'."
}

$installationPath = & $vswhere `
    -latest `
    -products '*' `
    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
    -property installationPath
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($installationPath)) {
    throw 'No Visual Studio installation with the x64 C++ toolchain was found.'
}

$toolRoot = Join-Path $installationPath 'VC\Tools\MSVC'
$runtime = $null
$toolsets = Get-ChildItem $toolRoot -Directory -ErrorAction SilentlyContinue |
    Sort-Object { [version]$_.Name } -Descending
foreach ($toolset in $toolsets) {
    $candidate = Join-Path $toolset.FullName `
        'bin\Hostx64\x64\clang_rt.asan_dynamic-x86_64.dll'
    if (Test-Path -LiteralPath $candidate) {
        $runtime = Get-Item -LiteralPath $candidate
        break
    }
}
if ($null -eq $runtime) {
    throw 'The x64 MSVC AddressSanitizer runtime is not installed.'
}

$runtimeDirectory = $runtime.Directory.FullName
$env:PATH = "$runtimeDirectory;$env:PATH"

if (-not [string]::IsNullOrWhiteSpace($env:GITHUB_PATH)) {
    Add-Content -LiteralPath $env:GITHUB_PATH -Value $runtimeDirectory -Encoding utf8
}

Write-Host "MSVC AddressSanitizer runtime: $runtimeDirectory"
