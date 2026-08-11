[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$cliProject = Join-Path $repositoryRoot 'src/SarifRegress.Cli/SarifRegress.Cli.csproj'
$artifactDirectory = Join-Path $repositoryRoot 'artifacts'
$packageDirectory = Join-Path $artifactDirectory 'packages'
$publishDirectory = Join-Path $artifactDirectory 'publish'
$releaseDirectory = Join-Path $artifactDirectory 'release'
$noticeDirectory = Join-Path $repositoryRoot 'notices'
$noticeChecksumManifest = Join-Path $noticeDirectory 'checksums.sha256'
$projectLicense = Join-Path $repositoryRoot 'LICENSE'
$thirdPartyNotices = Join-Path $repositoryRoot 'THIRD_PARTY_NOTICES.md'
$auditedRuntimeFrameworkVersion = '10.0.10'
$pathComparison = [System.StringComparison]::OrdinalIgnoreCase

$upstreamNoticeNames = @(
    'DOTNET_RUNTIME_LICENSE.txt',
    'DOTNET_RUNTIME_THIRD_PARTY_NOTICES.txt',
    'SYSTEM_COMMANDLINE_LICENSE.md'
)
$releaseNoticeSources = [ordered]@{
    'DOTNET_RUNTIME_LICENSE.txt' = Join-Path `
        $noticeDirectory `
        'DOTNET_RUNTIME_LICENSE.txt'
    'DOTNET_RUNTIME_THIRD_PARTY_NOTICES.txt' = Join-Path `
        $noticeDirectory `
        'DOTNET_RUNTIME_THIRD_PARTY_NOTICES.txt'
    'LICENSE' = $projectLicense
    'SYSTEM_COMMANDLINE_LICENSE.md' = Join-Path `
        $noticeDirectory `
        'SYSTEM_COMMANDLINE_LICENSE.md'
    'THIRD_PARTY_NOTICES.md' = $thirdPartyNotices
}

function Get-NormalizedFullPath {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    return $fullPath.TrimEnd([char[]] @(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar))
}

function Assert-PhysicalDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path,

        [Parameter(Mandatory = $true)]
        [string] $ExpectedPath
    )

    $item = Get-Item -LiteralPath $Path -Force
    if (-not $item.PSIsContainer) {
        throw "Packaging path '$Path' exists but is not a directory."
    }
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing to use reparseable packaging path '$Path'."
    }

    $actualFullPath = Get-NormalizedFullPath (
        (Resolve-Path -LiteralPath $Path).ProviderPath)
    $expectedFullPath = Get-NormalizedFullPath $ExpectedPath
    if (-not $actualFullPath.Equals($expectedFullPath, $pathComparison)) {
        throw "Packaging path '$Path' resolves outside its expected repository location."
    }
}

# Time: O(n), Space: O(d), where n is the number of descendants and d is directory depth.
function Assert-NoNestedReparsePoints {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Directory
    )

    $pendingDirectories = [System.Collections.Generic.Stack[string]]::new()
    $pendingDirectories.Push($Directory)
    while ($pendingDirectories.Count -gt 0) {
        $currentDirectory = $pendingDirectories.Pop()
        foreach (
            $entryPath in
            [System.IO.Directory]::EnumerateFileSystemEntries($currentDirectory)
        ) {
            $attributes = [System.IO.File]::GetAttributes($entryPath)
            if (
                ($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
            ) {
                throw "Refusing to recursively clean reparseable path '$entryPath'."
            }
            if (($attributes -band [System.IO.FileAttributes]::Directory) -ne 0) {
                $pendingDirectories.Push($entryPath)
            }
        }
    }
}

function Reset-ManagedPackagingDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path,

        [Parameter(Mandatory = $true)]
        [string] $ExpectedLeafName
    )

    $expectedPath = Join-Path $artifactDirectory $ExpectedLeafName
    $normalizedPath = Get-NormalizedFullPath $Path
    $normalizedExpectedPath = Get-NormalizedFullPath $expectedPath
    if (-not $normalizedPath.Equals($normalizedExpectedPath, $pathComparison)) {
        throw "Refusing to clean unexpected packaging path '$Path'."
    }

    if (Test-Path -LiteralPath $Path) {
        Assert-PhysicalDirectory -Path $Path -ExpectedPath $expectedPath
        Assert-NoNestedReparsePoints -Directory $Path
        Remove-Item -LiteralPath $Path -Recurse -Force
    }

    New-Item -ItemType Directory -Path $Path | Out-Null
    Assert-PhysicalDirectory -Path $Path -ExpectedPath $expectedPath
}

function Reset-ManagedPackagingDirectories {
    $expectedArtifactDirectory = Join-Path $repositoryRoot 'artifacts'
    $normalizedArtifactDirectory = Get-NormalizedFullPath $artifactDirectory
    $normalizedExpectedArtifactDirectory = Get-NormalizedFullPath `
        $expectedArtifactDirectory
    if (
        -not $normalizedArtifactDirectory.Equals(
            $normalizedExpectedArtifactDirectory,
            $pathComparison)
    ) {
        throw 'The packaging artifact directory is outside the repository.'
    }

    if (Test-Path -LiteralPath $artifactDirectory) {
        Assert-PhysicalDirectory `
            -Path $artifactDirectory `
            -ExpectedPath $expectedArtifactDirectory
    }
    else {
        New-Item -ItemType Directory -Path $artifactDirectory | Out-Null
        Assert-PhysicalDirectory `
            -Path $artifactDirectory `
            -ExpectedPath $expectedArtifactDirectory
    }

    Reset-ManagedPackagingDirectory `
        -Path $packageDirectory `
        -ExpectedLeafName 'packages'
    Reset-ManagedPackagingDirectory `
        -Path $publishDirectory `
        -ExpectedLeafName 'publish'
    Reset-ManagedPackagingDirectory `
        -Path $releaseDirectory `
        -ExpectedLeafName 'release'
}

function Assert-UpstreamNoticeChecksums {
    $manifestEntries = [ordered]@{}
    foreach ($line in [System.IO.File]::ReadAllLines($noticeChecksumManifest)) {
        $match = [regex]::Match(
            $line,
            '^(?<hash>[0-9a-f]{64})  (?<name>[A-Za-z0-9._-]+)$')
        if (-not $match.Success) {
            throw "Invalid upstream notice checksum entry: $line"
        }

        $name = $match.Groups['name'].Value
        if ($manifestEntries.Contains($name)) {
            throw "Duplicate upstream notice checksum entry: $name"
        }

        $manifestEntries.Add($name, $match.Groups['hash'].Value)
    }

    if ($manifestEntries.Count -ne $upstreamNoticeNames.Count) {
        throw 'The upstream notice checksum manifest has an unexpected file count.'
    }

    foreach ($name in $upstreamNoticeNames) {
        if (-not $manifestEntries.Contains($name)) {
            throw "The upstream notice checksum manifest omits $name."
        }

        $path = Join-Path $noticeDirectory $name
        $actualHash = (
            Get-FileHash -LiteralPath $path -Algorithm SHA256
        ).Hash.ToLowerInvariant()
        if ($actualHash -cne $manifestEntries[$name]) {
            throw "The retained upstream notice bytes differ for $name."
        }
    }
}

function Assert-AuditedRuntimeFrameworkVersion {
    $runtimeFrameworkVersion = @(
        & dotnet msbuild `
            $cliProject `
            -nologo `
            -getProperty:RuntimeFrameworkVersion `
            -property:SelfContained=true `
            -verbosity:quiet
    )
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not evaluate RuntimeFrameworkVersion for the CLI project.'
    }

    if (
        $runtimeFrameworkVersion.Count -ne 1 -or
        $runtimeFrameworkVersion[0] -cne $auditedRuntimeFrameworkVersion
    ) {
        throw (
            'RuntimeFrameworkVersion does not match the audited notice version ' +
            "$auditedRuntimeFrameworkVersion.")
    }
}

# Time: O(n), Space: O(1), where n is the number of bytes in the stream.
function Get-StreamSha256 {
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.Stream] $Stream
    )

    $hasher = [System.Security.Cryptography.SHA256]::Create()
    try {
        return [System.BitConverter]::ToString(
            $hasher.ComputeHash($Stream)
        ).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $hasher.Dispose()
    }
}

function Assert-FileBytesEqual {
    param(
        [Parameter(Mandatory = $true)]
        [string] $ExpectedPath,

        [Parameter(Mandatory = $true)]
        [string] $ActualPath
    )

    $expectedFile = Get-Item -LiteralPath $ExpectedPath
    $actualFile = Get-Item -LiteralPath $ActualPath
    $expectedHash = (
        Get-FileHash -LiteralPath $expectedFile.FullName -Algorithm SHA256
    ).Hash
    $actualHash = (
        Get-FileHash -LiteralPath $actualFile.FullName -Algorithm SHA256
    ).Hash
    if ($expectedFile.Length -ne $actualFile.Length -or $expectedHash -cne $actualHash) {
        throw "Packaged file differs from its audited source: $ActualPath"
    }
}

function Assert-PackageNoticeBytes {
    param(
        [Parameter(Mandatory = $true)]
        [string] $PackagePath
    )

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $expectedEntries = [ordered]@{
        'LICENSE' = $projectLicense
        'THIRD_PARTY_NOTICES.md' = $thirdPartyNotices
        'notices/SYSTEM_COMMANDLINE_LICENSE.md' = Join-Path `
            $noticeDirectory `
            'SYSTEM_COMMANDLINE_LICENSE.md'
    }

    $archive = [System.IO.Compression.ZipFile]::OpenRead($PackagePath)
    try {
        foreach ($entryName in $expectedEntries.Keys) {
            $matchingEntries = @(
                $archive.Entries |
                    Where-Object { $_.FullName -ceq $entryName }
            )
            if ($matchingEntries.Count -ne 1) {
                throw "Expected one package entry named $entryName."
            }

            $actualStream = $matchingEntries[0].Open()
            try {
                $actualHash = Get-StreamSha256 $actualStream
            }
            finally {
                $actualStream.Dispose()
            }

            $expectedPath = $expectedEntries[$entryName]
            $expectedFile = Get-Item -LiteralPath $expectedPath
            $expectedHash = (
                Get-FileHash -LiteralPath $expectedFile.FullName -Algorithm SHA256
            ).Hash.ToLowerInvariant()
            if (
                $matchingEntries[0].Length -ne $expectedFile.Length -or
                $actualHash -cne $expectedHash
            ) {
                throw "Package entry differs from its audited source: $entryName"
            }
        }
    }
    finally {
        $archive.Dispose()
    }
}

function Copy-AndVerifyReleaseNotices {
    foreach ($noticeName in $releaseNoticeSources.Keys) {
        $destination = Join-Path $releaseDirectory $noticeName
        Copy-Item -LiteralPath $releaseNoticeSources[$noticeName] -Destination $destination
        Assert-FileBytesEqual $releaseNoticeSources[$noticeName] $destination
    }
}

function Write-ReleaseChecksumManifest {
    [string[]] $releaseNames = @(
        Get-ChildItem -LiteralPath $releaseDirectory -File |
            Where-Object { $_.Name -cne 'checksums.sha256' } |
            ForEach-Object { $_.Name }
    )
    if ($releaseNames.Count -eq 0) {
        throw 'No release files were available to checksum.'
    }

    [System.Array]::Sort($releaseNames, [System.StringComparer]::Ordinal)
    $manifestLines = foreach ($name in $releaseNames) {
        $hash = Get-FileHash `
            -LiteralPath (Join-Path $releaseDirectory $name) `
            -Algorithm SHA256
        '{0}  {1}' -f $hash.Hash.ToLowerInvariant(), $name
    }

    $manifest = ($manifestLines -join "`n") + "`n"
    $utf8WithoutBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText(
        (Join-Path $releaseDirectory 'checksums.sha256'),
        $manifest,
        $utf8WithoutBom)
}

Assert-UpstreamNoticeChecksums
Assert-AuditedRuntimeFrameworkVersion
Reset-ManagedPackagingDirectories
& (Join-Path $PSScriptRoot 'build.ps1')

# The .NET tool is portable; the project RID graph exists for the standalone binaries.
Invoke-DotNet -Arguments @(
    'pack',
    $cliProject,
    '--configuration',
    'Release',
    '--no-build',
    '--no-restore',
    '--output',
    $packageDirectory,
    '-p:RuntimeIdentifiers='
)

foreach ($runtimeIdentifier in @('linux-x64', 'win-x64')) {
    $runtimeOutput = Join-Path $publishDirectory $runtimeIdentifier
    Invoke-DotNet -Arguments @(
        'publish',
        $cliProject,
        '--configuration',
        'Release',
        '--runtime',
        $runtimeIdentifier,
        '--self-contained',
        'true',
        '--no-restore',
        '--output',
        $runtimeOutput,
        '-p:PublishSingleFile=true',
        '-p:IncludeNativeLibrariesForSelfExtract=true',
        '-p:PublishTrimmed=false',
        '-p:PublishReadyToRun=false',
        '-p:DebugSymbols=false',
        '-p:DebugType=None'
    )
}

$packageFiles = @(
    Get-ChildItem -LiteralPath $packageDirectory -Filter '*.nupkg' -File
)
if ($packageFiles.Count -ne 1) {
    throw "Expected exactly one .NET tool package, found $($packageFiles.Count)."
}

$linuxBinary = Join-Path $publishDirectory 'linux-x64/sarif-regress'
$windowsBinary = Join-Path $publishDirectory 'win-x64/sarif-regress.exe'
if (
    -not (Test-Path -LiteralPath $linuxBinary -PathType Leaf) -or
    -not (Test-Path -LiteralPath $windowsBinary -PathType Leaf)
) {
    throw 'Expected single-file Linux and Windows binaries were not produced.'
}

Copy-Item -LiteralPath $packageFiles[0].FullName -Destination $releaseDirectory
Copy-Item `
    -LiteralPath $linuxBinary `
    -Destination (Join-Path $releaseDirectory 'sarif-regress-linux-x64')
Copy-Item `
    -LiteralPath $windowsBinary `
    -Destination (Join-Path $releaseDirectory 'sarif-regress-win-x64.exe')
Copy-AndVerifyReleaseNotices
Assert-PackageNoticeBytes $packageFiles[0].FullName
Write-ReleaseChecksumManifest
