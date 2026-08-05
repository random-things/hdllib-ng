[CmdletBinding()]
param(
    # Existing CodeQL CLI home (directory containing codeql.exe), or leave empty to use cache / PATH.
    [string]$CodeQlHome,

    # Download the exact win64 bundle pinned for the GitHub Action when needed.
    [switch]$InstallBundle,

    # Compatibility override. If supplied, it must equal .github/codeql/toolchain.json.
    [string]$BundleTag,

    # Retained for command-line compatibility; normal runs now always recreate the database.
    [switch]$RebuildDatabase,

    # Skip database create; analyze an existing DatabaseDir.
    [switch]$AnalyzeOnly,

    # The default scans checked-in C/C++ without compiling dependencies. Use
    # manual only when a traced, configuration-specific build is required.
    [ValidateSet('none', 'manual')]
    [string]$BuildMode = 'none',

    # Do not exit non-zero when the SARIF contains alerts (still writes reports).
    [switch]$AllowFindings,

    [string]$DatabaseDir = '.codeql-db',
    [string]$SarifOut = 'codeql-results.sarif',
    [string]$CsvOut = 'codeql-results.csv',

    # Wrapper-owned caches; defaults preserve direct developer compatibility.
    [string]$CacheDir = 'tools/.cache/codeql',
    [string]$FetchContentDir,

    # Must be the same single suite the GitHub workflow loads via codeql-config.yml.
    [string]$QuerySuite = '.github/codeql/hdllib-security-extended.qls'
)

$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Set-Location -LiteralPath $repoRoot

$toolchainPath = Join-Path $repoRoot '.github\codeql\toolchain.json'
$workflowPath = Join-Path $repoRoot '.github\workflows\codeql.yml'
$toolchain = Get-Content -LiteralPath $toolchainPath -Raw -Encoding utf8 | ConvertFrom-Json
$actionVersion = [string]$toolchain.actionVersion
$pinnedBundleTag = [string]$toolchain.bundleTag
$expectedCodeQlVersion = [string]$toolchain.cliVersion

if ([string]::IsNullOrWhiteSpace($actionVersion) -or
    [string]::IsNullOrWhiteSpace($pinnedBundleTag) -or
    [string]::IsNullOrWhiteSpace($expectedCodeQlVersion)) {
    throw "Invalid CodeQL toolchain manifest '$toolchainPath'."
}
if ($pinnedBundleTag -ne "codeql-bundle-v$expectedCodeQlVersion") {
    throw "CodeQL bundle '$pinnedBundleTag' does not match CLI version '$expectedCodeQlVersion'."
}
if (-not [string]::IsNullOrWhiteSpace($BundleTag) -and $BundleTag -ne $pinnedBundleTag) {
    throw "BundleTag '$BundleTag' differs from GitHub's pinned bundle '$pinnedBundleTag'."
}
$BundleTag = $pinnedBundleTag

$workflow = Get-Content -LiteralPath $workflowPath -Raw -Encoding utf8
$actionRefs = [regex]::Matches(
    $workflow,
    'github/codeql-action/upload-sarif@(?<version>v[0-9.]+)'
)
if ($actionRefs.Count -ne 1 -or
    @($actionRefs | Where-Object { $_.Groups['version'].Value -ne $actionVersion }).Count -ne 0) {
    throw "CodeQL workflow action references do not match toolchain action '$actionVersion'."
}

function Resolve-CodeQlExe {
    param([string]$HomeDir)

    if (-not [string]::IsNullOrWhiteSpace($HomeDir)) {
        $candidate = Join-Path $HomeDir 'codeql.exe'
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
        throw "codeql.exe not found under CodeQlHome '$HomeDir'."
    }

    $cacheExe = Join-Path $script:cacheRoot 'codeql\codeql.exe'
    if (Test-Path -LiteralPath $cacheExe -PathType Leaf) {
        return (Resolve-Path -LiteralPath $cacheExe).Path
    }

    $legacyCacheExe = Join-Path $repoRoot 'tools\.cache\codeql\codeql\codeql.exe'
    if (Test-Path -LiteralPath $legacyCacheExe -PathType Leaf) {
        return (Resolve-Path -LiteralPath $legacyCacheExe).Path
    }

    $cmd = Get-Command codeql -ErrorAction SilentlyContinue
    if ($cmd) {
        return $cmd.Source
    }

    return $null
}

function Install-CodeQlBundle {
    param([string]$Tag)

    $cacheRoot = $script:cacheRoot
    New-Item -ItemType Directory -Force -Path $cacheRoot | Out-Null

    if ([string]::IsNullOrWhiteSpace($Tag)) {
        throw 'A pinned CodeQL bundle tag is required.'
    }

    $asset = 'codeql-bundle-win64.tar.gz'
    $url = "https://github.com/github/codeql-action/releases/download/$Tag/$asset"
    $archive = Join-Path $cacheRoot $asset
    $extractDir = Join-Path $cacheRoot 'codeql'

    Write-Host "Downloading $url"
    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    if ($curl) {
        & $curl.Source --fail --location --retry 3 --continue-at - --silent --show-error `
            --output $archive $url
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to download '$url' with curl.exe."
        }
    } else {
        Invoke-WebRequest -Uri $url -OutFile $archive
    }

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

function Get-CodeQlVersion {
    param([string]$Executable)

    $versionJson = (& $Executable version --format=json | Out-String)
    if ($LASTEXITCODE -ne 0) {
        throw 'codeql version failed.'
    }
    return [string](($versionJson | ConvertFrom-Json).version)
}

$script:cacheRoot = if ([IO.Path]::IsPathRooted($CacheDir)) {
    [IO.Path]::GetFullPath($CacheDir)
} else {
    [IO.Path]::GetFullPath((Join-Path $repoRoot $CacheDir))
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

$actualCodeQlVersion = Get-CodeQlVersion -Executable $codeql
if ($actualCodeQlVersion -ne $expectedCodeQlVersion -and $InstallBundle -and
    [string]::IsNullOrWhiteSpace($CodeQlHome)) {
    Write-Host "Found CodeQL $actualCodeQlVersion; installing GitHub's pinned $BundleTag."
    $codeql = Install-CodeQlBundle -Tag $BundleTag
    $actualCodeQlVersion = Get-CodeQlVersion -Executable $codeql
}
if ($actualCodeQlVersion -ne $expectedCodeQlVersion) {
    throw @"
CodeQL CLI $actualCodeQlVersion does not match github/codeql-action $actionVersion
(CLI $expectedCodeQlVersion). Re-run with -InstallBundle or pass -CodeQlHome for
the $BundleTag bundle.
"@
}
Write-Host "Using CodeQL: $codeql"
Write-Host "Matched github/codeql-action ${actionVersion}: CLI $actualCodeQlVersion ($BundleTag)"

function Resolve-ResultPath([string]$Path) {
    if ([IO.Path]::IsPathRooted($Path)) { return [IO.Path]::GetFullPath($Path) }
    return [IO.Path]::GetFullPath((Join-Path $repoRoot $Path))
}

$dbPath = Resolve-ResultPath $DatabaseDir
$sarifPath = Resolve-ResultPath $SarifOut
$csvPath = Resolve-ResultPath $CsvOut
$configPath = Join-Path $repoRoot '.github\codeql\codeql-config.yml'
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dbPath),
    (Split-Path -Parent $sarifPath), (Split-Path -Parent $csvPath) | Out-Null

if (-not $AnalyzeOnly) {
    if (Test-Path -LiteralPath $dbPath) {
        Write-Host "Removing stale database: $dbPath"
        Remove-Item -LiteralPath $dbPath -Recurse -Force
    }

    if ($BuildMode -eq 'none') {
        Write-Host 'Creating fresh CodeQL database (C/C++ build mode: none)...'
        & $codeql database create $dbPath `
            --language=cpp `
            --build-mode=none `
            --source-root=$repoRoot `
            --codescanning-config=$configPath
        if ($LASTEXITCODE -ne 0) {
            throw "codeql database create failed with exit code $LASTEXITCODE."
        }
    } else {
        if (-not (Get-Command cmake -ErrorAction SilentlyContinue)) {
            throw 'CMake is not available for manual CodeQL extraction.'
        }

        # A manual extraction must trace a clean build. Otherwise an up-to-date
        # tree can produce an empty or partial database.
        $buildDir = Join-Path $repoRoot 'build\ci-codeql'
        if (Test-Path -LiteralPath $buildDir) {
            Write-Host "Removing stale CodeQL build: $buildDir"
            Remove-Item -LiteralPath $buildDir -Recurse -Force
        }

        $tempRoot = Join-Path $env:TEMP ("hdllib-codeql-{0}" -f [guid]::NewGuid().ToString('N'))
        $fetchDir = if ([string]::IsNullOrWhiteSpace($FetchContentDir)) {
            Join-Path $tempRoot 'fetchcontent'
        } else {
            Resolve-ResultPath $FetchContentDir
        }
        $buildScript = Join-Path $tempRoot 'build.cmd'
        New-Item -ItemType Directory -Force -Path $tempRoot | Out-Null
        try {
            @"
@echo off
setlocal
cd /d "$repoRoot"
cmake --preset ci-codeql "-DFETCHCONTENT_BASE_DIR=$fetchDir"
if errorlevel 1 exit /b 1
cmake --build --preset ci-codeql --parallel
exit /b %ERRORLEVEL%
"@ | Set-Content -LiteralPath $buildScript -Encoding ascii

            Write-Host 'Creating fresh CodeQL database (clean traced ci-codeql build)...'
            & $codeql database create $dbPath `
                --language=cpp `
                --source-root=$repoRoot `
                --codescanning-config=$configPath `
                --command="cmd /c `"$buildScript`""
            if ($LASTEXITCODE -ne 0) {
                throw "codeql database create failed with exit code $LASTEXITCODE."
            }
        } finally {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
} elseif (-not (Test-Path -LiteralPath $dbPath)) {
    throw "AnalyzeOnly set but database '$dbPath' does not exist."
}

Write-Host "Analyzing with $QuerySuite ..."
# Always --rerun: incremental "No need to rerun" after a DB recreate has produced
# false greens (stale empty results while GitHub Actions still fails).
& $codeql database analyze $dbPath $QuerySuite `
    --rerun `
    --format=sarif-latest `
    --output=$sarifPath `
    --sarif-category=/language:c-cpp
if ($LASTEXITCODE -ne 0) {
    throw "codeql database analyze (SARIF) failed with exit code $LASTEXITCODE."
}

# The database is fresh and the exact suite just completed above. Reuse those
# query results when serializing CSV instead of evaluating every query twice.
& $codeql database analyze $dbPath $QuerySuite `
    --format=csv `
    --output=$csvPath
if ($LASTEXITCODE -ne 0) {
    throw "codeql database analyze (CSV) failed with exit code $LASTEXITCODE."
}

function Test-CodeQlAlertActionable {
    param($Result)

    # Match GitHub code scanning: only ignore alerts GitHub itself would drop.
    # In-source suppressions must still be present in SARIF with suppressions[];
    # do NOT silently drop unsuppressed alerts (that caused local false greens).
    $hasAcceptedSuppression = $false
    foreach ($sup in @($Result.suppressions)) {
        if ($null -eq $sup) { continue }
        $status = if ($sup.PSObject.Properties['status']) { [string]$sup.status } else { '' }
        $kind = if ($sup.PSObject.Properties['kind']) { [string]$sup.kind } else { '' }
        if ($kind -eq 'inSource' -and ([string]::IsNullOrEmpty($status) -or $status -eq 'accepted')) {
            $hasAcceptedSuppression = $true
            break
        }
    }
    if ($hasAcceptedSuppression) {
        return $false
    }

    return $true
}

$sarif = Get-Content -LiteralPath $sarifPath -Raw -Encoding utf8 | ConvertFrom-Json
$vendorResultCount = 0
foreach ($run in @($sarif.runs)) {
    $keptResults = @()
    foreach ($result in @($run.results)) {
        $isVendorResult = $false
        foreach ($location in @($result.locations)) {
            $uri = [string]$location.physicalLocation.artifactLocation.uri
            if (($uri -replace '\\', '/') -match '(^|/)third_party/') {
                $isVendorResult = $true
                break
            }
        }
        if ($isVendorResult) {
            $vendorResultCount++
        } else {
            $keptResults += $result
        }
    }
    $run.results = $keptResults
}
if ($vendorResultCount -gt 0) {
    # CodeQL's compiled-language extractor includes built vendor code even when
    # codeql-config.yml uses paths-ignore. Filter it from the exact SARIF that
    # is gated locally and uploaded by GitHub, preserving pristine vendor source.
    $sarif | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $sarifPath -Encoding utf8
    Write-Host "Excluded $vendorResultCount third_party SARIF result(s)."
}
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
