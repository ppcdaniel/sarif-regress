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

& (Join-Path $PSScriptRoot 'build.ps1')

foreach ($path in @($packageDirectory, $publishDirectory, $releaseDirectory)) {
    if (Test-Path -LiteralPath $path) {
        Remove-Item -LiteralPath $path -Recurse -Force
    }

    New-Item -ItemType Directory -Path $path | Out-Null
}

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

$manifestNames = @(
    $packageFiles[0].Name,
    'sarif-regress-linux-x64',
    'sarif-regress-win-x64.exe'
)
$manifestLines = foreach ($name in $manifestNames) {
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
