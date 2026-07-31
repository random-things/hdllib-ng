[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$vswhere = Join-Path ${env:ProgramFiles(x86)} `
    'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) {
    throw "vswhere.exe was not found at '$vswhere'. Install Visual Studio 2022 Build Tools."
}

$installationPath = & $vswhere `
    -latest `
    -products * `
    -requires Microsoft.VisualStudio.Component.VC.CMake.Project `
    -property installationPath |
    Select-Object -First 1
if ([string]::IsNullOrWhiteSpace($installationPath)) {
    throw 'No Visual Studio installation with the CMake component was found.'
}

$cmakeBin = Join-Path $installationPath `
    'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin'
$cmake = Join-Path $cmakeBin 'cmake.exe'
$ctest = Join-Path $cmakeBin 'ctest.exe'
if (-not (Test-Path -LiteralPath $cmake -PathType Leaf) -or
    -not (Test-Path -LiteralPath $ctest -PathType Leaf)) {
    throw "Visual Studio's CMake tools were not found under '$cmakeBin'."
}

$env:PATH = "$cmakeBin;$env:PATH"
if (-not [string]::IsNullOrWhiteSpace($env:GITHUB_PATH)) {
    $cmakeBin | Out-File -FilePath $env:GITHUB_PATH -Encoding utf8 -Append
}

Write-Host "Using Visual Studio CMake from: $cmakeBin"
& $cmake --version

