[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$validationProject = Join-Path `
    $repositoryRoot `
    'validation/tools/SarifRegress.Validation/SarifRegress.Validation.csproj'
$captureToolsRoot = Join-Path $repositoryRoot 'validation/tools/capture'
$expectedRoot = Join-Path $repositoryRoot 'validation/expected'
$artifactRoot = Join-Path $repositoryRoot 'artifacts/holdout-validation'
$localOnlyNuGetConfig = Join-Path `
    $repositoryRoot `
    'validation/tools/NuGet.LocalOnly.config'
$multitoolPackageId = 'Sarif.Multitool'
$multitoolVersion = '5.5.0'
$multitoolRuntimeVersion = '8.0.29'
$multitoolPackageUrl = `
    'https://api.nuget.org/v3-flatcontainer/sarif.multitool/5.5.0/sarif.multitool.5.5.0.nupkg'
$multitoolPackageSha256 = `
    '2d2c73cc1fa4b79e5a41bded05d94dd645fa61d003492054260d7e106e838149'
$multitoolPackageSizeBytes = 33705414L
$workingRoot = Join-Path `
    ([System.IO.Path]::GetTempPath()) `
    "sarif-regress-holdout-$([Guid]::NewGuid().ToString('N'))"

function Invoke-DotNet {
    param(
        [Parameter(Mandatory = $true)]
        [string[]] $Arguments
    )

    & dotnet @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet $($Arguments -join ' ') failed with exit code $LASTEXITCODE."
    }
}

function Invoke-Python {
    param(
        [Parameter(Mandatory = $true)]
        [string[]] $Arguments
    )

    & python @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "python $($Arguments -join ' ') failed with exit code $LASTEXITCODE."
    }
}

function Write-HoldoutSnapshot {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Destination
    )

    $holdoutRoot = Join-Path $repositoryRoot 'validation/holdout'
    $lines = @(
        Get-ChildItem -LiteralPath $holdoutRoot -File -Recurse |
            ForEach-Object {
                $relativePath = [System.IO.Path]::GetRelativePath(
                    $repositoryRoot,
                    $_.FullName).Replace('\', '/')
                [pscustomobject]@{
                    Path = $relativePath
                    Hash = (
                        Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256
                    ).Hash.ToLowerInvariant()
                }
            } |
            Sort-Object -Property Path -CaseSensitive |
            ForEach-Object { "$($_.Hash)  $($_.Path)" }
    )
    $content = if ($lines.Count -eq 0) {
        ''
    }
    else {
        ($lines -join "`n") + "`n"
    }
    [System.IO.File]::WriteAllText(
        $Destination,
        $content,
        [System.Text.UTF8Encoding]::new($false))
}

function Assert-FilesEqual {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Left,

        [Parameter(Mandatory = $true)]
        [string] $Right,

        [Parameter(Mandatory = $true)]
        [string] $FailureMessage
    )

    $leftBytes = [System.IO.File]::ReadAllBytes($Left)
    $rightBytes = [System.IO.File]::ReadAllBytes($Right)
    if ($leftBytes.Length -ne $rightBytes.Length) {
        throw $FailureMessage
    }
    for ($index = 0; $index -lt $leftBytes.Length; $index++) {
        if ($leftBytes[$index] -ne $rightBytes[$index]) {
            throw $FailureMessage
        }
    }
}

New-Item -ItemType Directory -Path $workingRoot | Out-Null
Push-Location -LiteralPath $repositoryRoot
try {
    $installedRuntimes = & dotnet --list-runtimes
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet --list-runtimes failed with exit code $LASTEXITCODE."
    }
    $requiredRuntimePrefix = `
        "Microsoft.NETCore.App $multitoolRuntimeVersion "
    if (-not ($installedRuntimes | Where-Object {
                $_.StartsWith($requiredRuntimePrefix, [StringComparison]::Ordinal)
            })) {
        throw `
            "Microsoft.NETCore.App $multitoolRuntimeVersion is required by $multitoolPackageId $multitoolVersion."
    }

    $beforeSnapshot = Join-Path $workingRoot 'holdout-before.sha256'
    $afterSnapshot = Join-Path $workingRoot 'holdout-after.sha256'
    Write-HoldoutSnapshot -Destination $beforeSnapshot

    Invoke-Python -Arguments @(
        '-B',
        (Join-Path $captureToolsRoot 'verify_capture_provenance.py'),
        '--repository-root',
        $repositoryRoot
    )
    Invoke-Python -Arguments @(
        '-B',
        (Join-Path $captureToolsRoot 'verify_source_transformations.py'),
        '--repository-root',
        $repositoryRoot
    )
    Invoke-Python -Arguments @(
        '-B',
        (Join-Path $captureToolsRoot 'verify_projected_holdout.py'),
        '--repository-root',
        $repositoryRoot,
        '--output-root',
        (Join-Path $workingRoot 'projection-reproduction')
    )
    Invoke-Python -Arguments @(
        '-B',
        (Join-Path $captureToolsRoot 'test_capture_tools.py')
    )

    $packagePath = Join-Path `
        $workingRoot `
        "sarif.multitool.$multitoolVersion.nupkg"
    Invoke-WebRequest `
        -Uri $multitoolPackageUrl `
        -OutFile $packagePath `
        -MaximumRedirection 5

    $actualPackageSize = (Get-Item -LiteralPath $packagePath).Length
    if ($actualPackageSize -ne $multitoolPackageSizeBytes) {
        throw `
            "$multitoolPackageId package size mismatch: expected $multitoolPackageSizeBytes, got $actualPackageSize."
    }
    $actualPackageSha256 = (
        Get-FileHash -LiteralPath $packagePath -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    if ($actualPackageSha256 -ne $multitoolPackageSha256) {
        throw `
            "$multitoolPackageId package checksum mismatch: expected $multitoolPackageSha256, got $actualPackageSha256."
    }

    Invoke-DotNet -Arguments @('nuget', 'verify', '--all', $packagePath)

    $localFeed = Join-Path $workingRoot 'feed'
    $toolDirectory = Join-Path $workingRoot 'tool'
    New-Item -ItemType Directory -Path $localFeed | Out-Null
    New-Item -ItemType Directory -Path $toolDirectory | Out-Null
    Copy-Item -LiteralPath $packagePath -Destination $localFeed
    Invoke-DotNet -Arguments @(
        'tool',
        'install',
        '--tool-path',
        $toolDirectory,
        '--configfile',
        $localOnlyNuGetConfig,
        '--add-source',
        $localFeed,
        '--no-cache',
        $multitoolPackageId,
        '--version',
        $multitoolVersion
    )

    $multitoolPath = Join-Path $toolDirectory 'sarif.exe'
    if (-not (Test-Path -LiteralPath $multitoolPath -PathType Leaf)) {
        throw `
            "The verified Multitool installation did not produce '$multitoolPath'."
    }

    Invoke-DotNet -Arguments @('restore', $validationProject, '--locked-mode')
    Invoke-DotNet -Arguments @(
        'build',
        $validationProject,
        '--configuration',
        'Release',
        '--no-restore',
        '--warnaserror'
    )

    $generatedRoot = Join-Path $workingRoot 'generated'
    Invoke-DotNet -Arguments @(
        'run',
        '--project',
        $validationProject,
        '--configuration',
        'Release',
        '--no-build',
        '--no-restore',
        '--',
        'evaluate',
        '--repository-root',
        $repositoryRoot,
        '--output-root',
        $generatedRoot,
        '--expected-root',
        $expectedRoot,
        '--multitool-path',
        $multitoolPath,
        '--multitool-version',
        $multitoolVersion,
        '--compare-expected',
        'true',
        '--cross-platform-byte-identity',
        'true'
    )

    Write-HoldoutSnapshot -Destination $afterSnapshot
    Assert-FilesEqual `
        -Left $beforeSnapshot `
        -Right $afterSnapshot `
        -FailureMessage `
            'Holdout validation modified one or more committed fixture files.'

    $normalizedReports = @(
        'sarif-regress-holdout.json',
        'sarif-multitool-baseline.json',
        'comparison-summary.json',
        'checksums.sha256'
    )
    foreach ($reportName in $normalizedReports) {
        $generatedReport = Join-Path $generatedRoot $reportName
        if (-not (Test-Path -LiteralPath $generatedReport -PathType Leaf)) {
            throw "Validation did not produce '$reportName'."
        }
    }
    $rawRoot = Join-Path $generatedRoot 'raw'
    if (-not (Test-Path -LiteralPath $rawRoot -PathType Container)) {
        throw `
            'Validation did not preserve raw Multitool output under output-root/raw.'
    }

    if (Test-Path -LiteralPath $artifactRoot -PathType Container) {
        Get-ChildItem -LiteralPath $artifactRoot -Force |
            Remove-Item -Recurse -Force
    }
    else {
        New-Item -ItemType Directory -Path $artifactRoot | Out-Null
    }
    foreach ($reportName in $normalizedReports) {
        Copy-Item `
            -LiteralPath (Join-Path $generatedRoot $reportName) `
            -Destination (Join-Path $artifactRoot $reportName)
    }
    Copy-Item `
        -LiteralPath $rawRoot `
        -Destination (Join-Path $artifactRoot 'raw') `
        -Recurse

    Write-Host `
        'Holdout validation reproduced all committed normalized reports byte-for-byte.'
    Write-Host "Evidence: $artifactRoot"
}
finally {
    Pop-Location
    if (Test-Path -LiteralPath $workingRoot -PathType Container) {
        Remove-Item -LiteralPath $workingRoot -Recurse -Force
    }
}
