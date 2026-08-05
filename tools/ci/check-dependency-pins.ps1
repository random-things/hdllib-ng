[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$cmake = Get-Content -LiteralPath (Join-Path $repoRoot 'CMakeLists.txt') -Raw -Encoding utf8

$fetchBlocks = [regex]::Matches(
    $cmake,
    'FetchContent_Declare\s*\(\s*(?<name>[^\s\)]+)(?<body>.*?)\)',
    [Text.RegularExpressions.RegexOptions]::Singleline)
if ($fetchBlocks.Count -eq 0) {
    throw 'No FetchContent declarations were found.'
}
foreach ($block in $fetchBlocks) {
    $name = $block.Groups['name'].Value
    $body = $block.Groups['body'].Value
    $tag = [regex]::Match($body, 'GIT_TAG\s+(?<tag>[^\s\)]+)')
    $url = [regex]::Match($body, 'URL\s+(?<url>https://[^\s\)]+)')
    $urlHash = [regex]::Match($body, 'URL_HASH\s+SHA256=(?<hash>[0-9a-fA-F]{64})')
    if ($tag.Success) {
        if ($tag.Groups['tag'].Value -notmatch '^[0-9a-fA-F]{40}$') {
            throw "FetchContent dependency '$name' is not pinned to a full commit hash."
        }
        if ($body -match 'GIT_SHALLOW\s+TRUE') {
            throw "FetchContent dependency '$name' uses shallow fetching, which is not reproducible by commit."
        }
    } elseif (-not $url.Success -or -not $urlHash.Success) {
        throw "FetchContent dependency '$name' must use a full commit or a SHA-256-pinned HTTPS archive."
    }
}

$minHookCommit = 'c3fcafdc10146beb5919319d0683e44e3c30d537'
if ($cmake -notmatch [regex]::Escape($minHookCommit)) {
    throw "MinHook v1.3.4 provenance commit '$minHookCommit' is not recorded."
}

$codeqlToolchainPath = Join-Path $repoRoot '.github\codeql\toolchain.json'
$codeqlToolchain = Get-Content -LiteralPath $codeqlToolchainPath -Raw -Encoding utf8 | ConvertFrom-Json
if ([string]$codeqlToolchain.bundleTag -ne "codeql-bundle-v$($codeqlToolchain.cliVersion)") {
    throw 'CodeQL bundle and CLI versions are inconsistent.'
}

$workflow = Get-Content -LiteralPath (Join-Path $repoRoot '.github\workflows\codeql.yml') -Raw
$uploadRefs = [regex]::Matches(
    $workflow,
    'github/codeql-action/upload-sarif@(?<version>v[0-9.]+)')
if ($uploadRefs.Count -ne 1 -or
    $uploadRefs[0].Groups['version'].Value -ne [string]$codeqlToolchain.actionVersion) {
    throw "CodeQL SARIF upload action must match '$($codeqlToolchain.actionVersion)'."
}

$windowsToolchain = Get-Content -LiteralPath (Join-Path $repoRoot 'tools\ci\toolchain.json') `
    -Raw -Encoding utf8 | ConvertFrom-Json
$primaryRunner = [string]$windowsToolchain.windows.primaryRunner
$compatibilityRunner = [string]$windowsToolchain.windows.compatibilityRunner
if ([version]$windowsToolchain.windows.primaryCmakeValidated -lt
    [version]$windowsToolchain.windows.primaryCmakeMinimum) {
    throw 'The validated primary CMake version is below the required minimum.'
}

$ciWorkflow = Get-Content -LiteralPath (Join-Path $repoRoot '.github\workflows\windows-ci.yml') -Raw
$codeqlWorkflow = Get-Content -LiteralPath (Join-Path $repoRoot '.github\workflows\codeql.yml') -Raw
if ($ciWorkflow -notmatch "runs-on:\s+$([regex]::Escape($primaryRunner))" -or
    $codeqlWorkflow -notmatch "runs-on:\s+$([regex]::Escape($primaryRunner))") {
    throw "Required hosted CI jobs must target '$primaryRunner'."
}

$nightlyWorkflow = Get-Content -LiteralPath `
    (Join-Path $repoRoot '.github\workflows\windows-nightly.yml') -Raw
if ($nightlyWorkflow -notmatch
    "check:\s+WindowsCanary,\s+runner:\s+$([regex]::Escape($compatibilityRunner))") {
    throw "WindowsCanary must retain the '$compatibilityRunner' compatibility build."
}
$compatibilityRows = [regex]::Matches(
    $nightlyWorkflow, "runner:\s+$([regex]::Escape($compatibilityRunner))")
if ($compatibilityRows.Count -ne 1) {
    throw 'Only the explicit compatibility check may use windows-2022.'
}
$nightlyRunners = [regex]::Matches($nightlyWorkflow, 'runner:\s+(?<runner>[A-Za-z0-9-]+)')
foreach ($runner in $nightlyRunners) {
    if ($runner.Groups['runner'].Value -notin @($primaryRunner, $compatibilityRunner)) {
        throw "Unexpected nightly hosted runner '$($runner.Groups['runner'].Value)'."
    }
}

$presets = Get-Content -LiteralPath (Join-Path $repoRoot 'CMakePresets.json') -Raw |
    ConvertFrom-Json
$vs2026Preset = $presets.configurePresets | Where-Object name -eq 'x64-windows-vs2026'
if (-not $vs2026Preset -or $vs2026Preset.generator -ne 'Visual Studio 18 2026') {
    throw 'The VS 2026 developer preset is missing or uses the wrong generator.'
}

Write-Host "Validated $($fetchBlocks.Count) FetchContent pin(s), MinHook provenance, CodeQL alignment, and Windows toolchain tiers."
