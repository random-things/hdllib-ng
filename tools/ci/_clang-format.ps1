# Shared helpers for check-format.ps1 / fix-format.ps1 (dot-source this file).

function Resolve-ClangFormat {
    $cmd = Get-Command clang-format -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source) {
        return (Resolve-Path -LiteralPath $cmd.Source).Path
    }

    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path -LiteralPath $vswhere) {
        $install = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Llvm.Clang `
            -property installationPath 2>$null
        if (-not $install) {
            $install = & $vswhere -latest -products * -property installationPath 2>$null
        }
        foreach ($root in @($install)) {
            if ([string]::IsNullOrWhiteSpace($root)) { continue }
            foreach ($rel in @(
                    'VC\Tools\Llvm\x64\bin\clang-format.exe',
                    'VC\Tools\Llvm\bin\clang-format.exe'
                )) {
                $candidate = Join-Path $root $rel
                if (Test-Path -LiteralPath $candidate) {
                    return (Resolve-Path -LiteralPath $candidate).Path
                }
            }
        }
    }

    foreach ($candidate in @(
            "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\BuildTools\VC\Tools\Llvm\x64\bin\clang-format.exe",
            "${env:ProgramFiles}\Microsoft Visual Studio\2022\BuildTools\VC\Tools\Llvm\x64\bin\clang-format.exe",
            "${env:ProgramFiles}\LLVM\bin\clang-format.exe"
        )) {
        if (Test-Path -LiteralPath $candidate) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }

    throw @'
clang-format not found. Install LLVM clang-format or the VS "C++ Clang tools for Windows"
component, or add clang-format to PATH.
'@
}

function Test-IsFormattableCppPath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $norm = $Path -replace '\\', '/'
    if ($norm -match '(^|/)third_party/') { return $false }
    return $norm -match '\.(c|cc|cpp|h|hpp)$'
}
