[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($args.Count -ne 0) {
    throw 'Usage: validate-holdout.ps1'
}

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$validationProject = Join-Path `
    $repositoryRoot `
    'validation/tools/SarifRegress.Validation/SarifRegress.Validation.csproj'
$captureToolsRoot = Join-Path $repositoryRoot 'validation/tools/capture'
$expectedRoot = Join-Path $repositoryRoot 'validation/expected'
$crossPlatformAttestation = Join-Path `
    $repositoryRoot `
    'validation/holdout/cross-platform-attestation.json'
$artifactParent = Join-Path $repositoryRoot 'artifacts'
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
$beforeSnapshot = $null
$isolatedEnvironmentNames = @(
    'NUGET_PACKAGES',
    'DOTNET_CLI_HOME',
    'NUGET_HTTP_CACHE_PATH'
)
$previousEnvironment = @{}
foreach ($name in $isolatedEnvironmentNames) {
    $previousEnvironment[$name] = [Environment]::GetEnvironmentVariable(
        $name,
        [EnvironmentVariableTarget]::Process)
}

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

function Assert-RealDirectoryOrMissing {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (-not $item.PSIsContainer) {
        throw "Artifact path '$Path' exists but is not a directory."
    }
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing to use reparseable artifact path '$Path'."
    }
}

New-Item -ItemType Directory -Path $workingRoot | Out-Null
Assert-RealDirectoryOrMissing -Path $artifactParent
if (-not (Test-Path -LiteralPath $artifactParent)) {
    New-Item -ItemType Directory -Path $artifactParent | Out-Null
}
Assert-RealDirectoryOrMissing -Path $artifactParent
Assert-RealDirectoryOrMissing -Path $artifactRoot
if (Test-Path -LiteralPath $artifactRoot) {
    Get-ChildItem -LiteralPath $artifactRoot -Force |
        Remove-Item -Recurse -Force
}
else {
    New-Item -ItemType Directory -Path $artifactRoot | Out-Null
}
Assert-RealDirectoryOrMissing -Path $artifactRoot
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
    $isolatedNuGetPackages = Join-Path $workingRoot 'nuget-packages'
    $isolatedDotNetHome = Join-Path $workingRoot 'dotnet-home'
    $isolatedHttpCache = Join-Path $workingRoot 'nuget-http-cache'
    New-Item -ItemType Directory -Path $localFeed | Out-Null
    New-Item -ItemType Directory -Path $toolDirectory | Out-Null
    New-Item -ItemType Directory -Path $isolatedNuGetPackages | Out-Null
    New-Item -ItemType Directory -Path $isolatedDotNetHome | Out-Null
    New-Item -ItemType Directory -Path $isolatedHttpCache | Out-Null
    Copy-Item -LiteralPath $packagePath -Destination $localFeed
    $env:NUGET_PACKAGES = $isolatedNuGetPackages
    $env:DOTNET_CLI_HOME = $isolatedDotNetHome
    $env:NUGET_HTTP_CACHE_PATH = $isolatedHttpCache
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

    $installedPackageFiles = @(
        Get-ChildItem `
            -LiteralPath (Join-Path $toolDirectory '.store') `
            -Filter 'sarif.multitool.*.nupkg' `
            -File `
            -Recurse
    )
    if ($installedPackageFiles.Count -ne 1) {
        throw "Expected exactly one retained installed $multitoolPackageId package."
    }
    $installedPackageHash = (
        Get-FileHash `
            -LiteralPath $installedPackageFiles[0].FullName `
            -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    if ($installedPackageFiles[0].Length -ne $multitoolPackageSizeBytes -or
        $installedPackageHash -ne $multitoolPackageSha256) {
        throw `
            "The installed $multitoolPackageId package bytes differ from the verified download."
    }

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
    New-Item -ItemType Directory -Path $generatedRoot | Out-Null
    $evaluationArguments = @(
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
        '--multitool-path',
        $multitoolPath,
        '--multitool-version',
        $multitoolVersion
    )
    $evaluationArguments += @(
        '--expected-root',
        $expectedRoot,
        '--compare-expected',
        'true',
        '--cross-platform-attestation',
        $crossPlatformAttestation
    )
    & dotnet @evaluationArguments
    $evaluationExitCode = $LASTEXITCODE

    Write-HoldoutSnapshot -Destination $afterSnapshot
    Assert-FilesEqual `
        -Left $beforeSnapshot `
        -Right $afterSnapshot `
        -FailureMessage `
            'Holdout validation modified one or more committed fixture files.'

    $normalizedReports = @(
        'sarif-regress-holdout.json',
        'sarif-multitool-baseline.json',
        'v2-to-v3-delta.json',
        'comparison-summary.json',
        'checksums.sha256'
    )
    $missingEvidence = $false
    foreach ($reportName in $normalizedReports) {
        $generatedReport = Join-Path $generatedRoot $reportName
        if (-not (Test-Path -LiteralPath $generatedReport -PathType Leaf)) {
            [Console]::Error.WriteLine(
                "Validation did not produce '$reportName'.")
            $missingEvidence = $true
        }
        else {
            Copy-Item `
                -LiteralPath $generatedReport `
                -Destination (Join-Path $artifactRoot $reportName)
        }
    }
    $rawRoot = Join-Path $generatedRoot 'raw'
    if (-not (Test-Path -LiteralPath $rawRoot -PathType Container)) {
        [Console]::Error.WriteLine(
            'Validation did not preserve raw Multitool output under output-root/raw.'
        )
        $missingEvidence = $true
    }
    else {
        Copy-Item `
            -LiteralPath $rawRoot `
            -Destination (Join-Path $artifactRoot 'raw') `
            -Recurse
    }

    if ($missingEvidence) {
        throw 'Holdout evaluation did not produce the complete evidence set.'
    }
    if ($evaluationExitCode -ne 0) {
        throw `
            "Holdout evaluation failed with exit code $evaluationExitCode; available evidence was preserved at $artifactRoot."
    }

    Write-Host `
        'Holdout validation reproduced all committed normalized reports byte-for-byte.'
    Write-Host "Evidence: $artifactRoot"
}
finally {
    try {
        if ($null -ne $beforeSnapshot -and
            (Test-Path -LiteralPath $beforeSnapshot -PathType Leaf)) {
            $finalSnapshot = Join-Path $workingRoot 'holdout-final.sha256'
            Write-HoldoutSnapshot -Destination $finalSnapshot
            Assert-FilesEqual `
                -Left $beforeSnapshot `
                -Right $finalSnapshot `
                -FailureMessage `
                    'Holdout validation modified one or more committed fixture files.'
        }
    }
    finally {
        Pop-Location
        foreach ($name in $isolatedEnvironmentNames) {
            [Environment]::SetEnvironmentVariable(
                $name,
                $previousEnvironment[$name],
                [EnvironmentVariableTarget]::Process)
        }
        if (Test-Path -LiteralPath $workingRoot -PathType Container) {
            Remove-Item -LiteralPath $workingRoot -Recurse -Force
        }
    }
}
