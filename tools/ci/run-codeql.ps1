[CmdletBinding()]
param(
    # Existing CodeQL CLI home (directory containing codeql.exe), or leave empty to use PATH / cache.
    [string]$CodeQlHome,

    # Download the win64 CodeQL bundle into tools/.cache/codeql if no CLI is found.
    [switch]$InstallBundle,

    # Bundle tag under github/codeql-action releases (e.g. codeql-bundle-v2.20.4). Empty = latest matching codeql-bundle-*.
    [string]$BundleTag,

    # Recreate the database even if DatabaseDir already exists.
    [switch]$RebuildDatabase,

    # Skip database create; analyze an existing DatabaseDir.
    [switch]$AnalyzeOnly,

    # Do not exit non-zero when the SARIF contains alerts (still writes reports).
    [switch]$AllowFindings,

    [string]$DatabaseDir = '.codeql-db',
    [string]$SarifOut = 'codeql-results.sarif',
    [string]$CsvOut = 'codeql-results.csv',

    # Query suite (matches .github/codeql/hdllib-security-extended.qls / workflow).
    [string]$QuerySuite = '.github/codeql/hdllib-security-extended.qls'
)

$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location -LiteralPath $repoRoot

function Resolve-CodeQlExe {
    param([string]$HomeDir)

    if (-not [string]::IsNullOrWhiteSpace($HomeDir)) {
        $candidate = Join-Path $HomeDir 'codeql.exe'
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
        throw "codeql.exe not found under CodeQlHome '$HomeDir'."
    }

    $cmd = Get-Command codeql -ErrorAction SilentlyContinue
    if ($cmd) {
        return $cmd.Source
    }

    $cacheExe = Join-Path $repoRoot 'tools\.cache\codeql\codeql\codeql.exe'
    if (Test-Path -LiteralPath $cacheExe -PathType Leaf) {
        return (Resolve-Path -LiteralPath $cacheExe).Path
    }

    return $null
}

function Install-CodeQlBundle {
    param([string]$Tag)

    $cacheRoot = Join-Path $repoRoot 'tools\.cache\codeql'
    New-Item -ItemType Directory -Force -Path $cacheRoot | Out-Null

    if ([string]::IsNullOrWhiteSpace($Tag)) {
        Write-Host 'Resolving latest codeql-bundle-* release from github/codeql-action...'
        $Tag = $null
        $gh = Get-Command gh -ErrorAction SilentlyContinue
        if ($gh) {
            $releaseJson = & gh api repos/github/codeql-action/releases --jq `
                '[.[] | select(.tag_name | startswith("codeql-bundle-"))][0].tag_name'
            if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($releaseJson)) {
                $Tag = $releaseJson.Trim()
            }
        }
        if ([string]::IsNullOrWhiteSpace($Tag)) {
            $releases = Invoke-RestMethod -Uri 'https://api.github.com/repos/github/codeql-action/releases'
            $match = $releases | Where-Object { $_.tag_name -like 'codeql-bundle-*' } | Select-Object -First 1
            if (-not $match) {
                throw 'Could not resolve a codeql-bundle release. Pass -BundleTag explicitly.'
            }
            $Tag = $match.tag_name
        }
        Write-Host "Using bundle tag: $Tag"
    }

    $asset = 'codeql-bundle-win64.tar.gz'
    $url = "https://github.com/github/codeql-action/releases/download/$Tag/$asset"
    $archive = Join-Path $cacheRoot $asset
    $extractDir = Join-Path $cacheRoot 'codeql'

    Write-Host "Downloading $url"
    Invoke-WebRequest -Uri $url -OutFile $archive

    if (Test-Path -LiteralPath $extractDir) {
        Remove-Item -LiteralPath $extractDir -Recurse -Force
    }

    Write-Host "Extracting to $cacheRoot (this can take several minutes)..."
    tar -xf $archive -C $cacheRoot
    if ($LASTEXITCODE -ne 0) {
        throw 'Failed to extract CodeQL bundle (tar).'
    }

    $exe = Join-Path $extractDir 'codeql.exe'
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) {
        throw "Extraction finished but '$exe' is missing."
    }
    return (Resolve-Path -LiteralPath $exe).Path
}

$codeql = Resolve-CodeQlExe -HomeDir $CodeQlHome
if (-not $codeql) {
    if ($InstallBundle) {
        $codeql = Install-CodeQlBundle -Tag $BundleTag
    } else {
        throw @"
CodeQL CLI not found. Options:
  1) Install the win64 bundle and add it to PATH
  2) Pass -CodeQlHome <dir containing codeql.exe>
  3) Re-run with -InstallBundle (downloads into tools/.cache/codeql)
"@
    }
}

Write-Host "Using CodeQL: $codeql"
& $codeql version
if ($LASTEXITCODE -ne 0) {
    throw 'codeql version failed.'
}

Write-Host "Ensuring query pack for suite: $QuerySuite"
& $codeql pack download codeql/cpp-queries
if ($LASTEXITCODE -ne 0) {
    throw 'codeql pack download codeql/cpp-queries failed.'
}

$dbPath = Join-Path $repoRoot $DatabaseDir
$sarifPath = Join-Path $repoRoot $SarifOut
$csvPath = Join-Path $repoRoot $CsvOut
$configPath = Join-Path $repoRoot '.github\codeql\codeql-config.yml'

if (-not $AnalyzeOnly) {
    & (Join-Path $PSScriptRoot 'add-vs-cmake-to-path.ps1')

    if ((Test-Path -LiteralPath $dbPath) -and $RebuildDatabase) {
        Write-Host "Removing existing database: $dbPath"
        Remove-Item -LiteralPath $dbPath -Recurse -Force
    }

    if (Test-Path -LiteralPath $dbPath) {
        Write-Host "Reusing database at $dbPath (pass -RebuildDatabase to recreate)."
    } else {
        $fetchDir = Join-Path $env:TEMP 'hdllib-fetchcontent'
        $buildScript = Join-Path $env:TEMP ("hdllib-codeql-build-{0}.cmd" -f [guid]::NewGuid().ToString('N'))
        @"
@echo off
setlocal
cd /d "$repoRoot"
cmake --preset ci-codeql "-DFETCHCONTENT_BASE_DIR=$fetchDir"
if errorlevel 1 exit /b 1
cmake --build --preset ci-codeql --parallel
exit /b %ERRORLEVEL%
"@ | Set-Content -LiteralPath $buildScript -Encoding ascii

        Write-Host 'Creating CodeQL database (traced ci-codeql build)...'
        try {
            & $codeql database create $dbPath `
                --language=cpp `
                --source-root=$repoRoot `
                --codescanning-config=$configPath `
                --command=$buildScript
            if ($LASTEXITCODE -ne 0) {
                throw "codeql database create failed with exit code $LASTEXITCODE."
            }
        } finally {
            Remove-Item -LiteralPath $buildScript -Force -ErrorAction SilentlyContinue
        }
    }
} elseif (-not (Test-Path -LiteralPath $dbPath)) {
    throw "AnalyzeOnly set but database '$dbPath' does not exist."
}

Write-Host "Analyzing with $QuerySuite ..."
& $codeql database analyze $dbPath $QuerySuite `
    --format=sarif-latest `
    --output=$sarifPath `
    --sarif-category=/language:c-cpp
if ($LASTEXITCODE -ne 0) {
    throw "codeql database analyze (SARIF) failed with exit code $LASTEXITCODE."
}

& $codeql database analyze $dbPath $QuerySuite `
    --format=csv `
    --output=$csvPath
if ($LASTEXITCODE -ne 0) {
    throw "codeql database analyze (CSV) failed with exit code $LASTEXITCODE."
}

function Test-CodeQlAlertActionable {
    param($Result)

    # In-source // codeql[...] suppressions (requires AlertSuppression.ql in the suite).
    foreach ($sup in @($Result.suppressions)) {
        if ($null -eq $sup) { continue }
        $status = if ($sup.PSObject.Properties['status']) { [string]$sup.status } else { '' }
        if ([string]::IsNullOrEmpty($status) -or $status -eq 'accepted') {
            return $false
        }
    }

    # paths-ignore does not drop compiled third_party objects from a traced C/C++ DB.
    foreach ($loc in @($Result.locations)) {
        $uri = $loc.physicalLocation.artifactLocation.uri
        if (-not $uri) { continue }
        $norm = ([string]$uri) -replace '\\', '/'
        if ($norm -match '(^|/)third_party/') {
            return $false
        }
    }
    return $true
}

$sarif = Get-Content -LiteralPath $sarifPath -Raw -Encoding utf8 | ConvertFrom-Json
$rawCount = 0
$alertCount = 0
foreach ($run in @($sarif.runs)) {
    foreach ($result in @($run.results)) {
        $rawCount++
        if (Test-CodeQlAlertActionable -Result $result) {
            $alertCount++
        }
    }
}

Write-Host "Wrote $sarifPath and $csvPath"
Write-Host "CodeQL alerts: $alertCount actionable ($rawCount raw SARIF results)"

if ($alertCount -gt 0) {
    Write-Host '--- CSV (first 40 lines) ---'
    Get-Content -LiteralPath $csvPath -TotalCount 40 | ForEach-Object { Write-Host $_ }
    if (-not $AllowFindings) {
        throw "CodeQL reported $alertCount actionable alert(s). Fix them or re-run with -AllowFindings."
    }
    Write-Host 'AllowFindings set; not failing the script.'
} else {
    Write-Host 'No actionable CodeQL alerts.'
}
