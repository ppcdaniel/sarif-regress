[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $StandaloneExecutable,

    [Parameter(Mandatory = $true)]
    [string] $InstalledToolExecutable,

    [Parameter(Mandatory = $true)]
    [string] $OutputRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$baselineFixture = Join-Path `
    $repositoryRoot `
    'corpus/cases/github-supported-subset/baseline.sarif'
$candidateFixture = Join-Path `
    $repositoryRoot `
    'corpus/cases/github-supported-subset/candidate.sarif'
$offlineMarker = `
    '  <meta http-equiv="Content-Security-Policy" content="default-src ''none''; style-src ''unsafe-inline''; img-src data:; base-uri ''none''; form-action ''none''">'
$expectedRootProperties = @(
    'determinism',
    'diagnostics',
    'findings',
    'inputs',
    'metrics',
    'outputSchemaVersion',
    'summary',
    'tool'
)
$expectedSummary = [ordered]@{
    'baselineCount' = 1
    'candidateCount' = 1
    'new' = 0
    'unchanged' = 1
    'moved' = 0
    'modified' = 0
    'resolved' = 0
    'ambiguous' = 0
}

function Assert-ExactPropertyNames {
    param(
        [Parameter(Mandatory = $true)]
        [object] $Value,

        [Parameter(Mandatory = $true)]
        [string[]] $ExpectedNames,

        [Parameter(Mandatory = $true)]
        [string] $ContractName
    )

    [string[]] $actualNames = @($Value.PSObject.Properties.Name)
    [System.Array]::Sort($actualNames, [System.StringComparer]::Ordinal)
    [string[]] $sortedExpectedNames = @($ExpectedNames)
    [System.Array]::Sort(
        $sortedExpectedNames,
        [System.StringComparer]::Ordinal)
    if (
        $actualNames.Count -ne $sortedExpectedNames.Count -or
        (Compare-Object $actualNames $sortedExpectedNames -CaseSensitive)
    ) {
        throw "Comparison smoke $ContractName properties differ from the contract."
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
        Get-FileHash -LiteralPath $ExpectedPath -Algorithm SHA256
    ).Hash
    $actualHash = (
        Get-FileHash -LiteralPath $ActualPath -Algorithm SHA256
    ).Hash
    if (
        $expectedFile.Length -ne $actualFile.Length -or
        $expectedHash -cne $actualHash
    ) {
        throw 'Standalone and installed-tool smoke reports differ.'
    }
}

function Assert-ReportContract {
    param(
        [Parameter(Mandatory = $true)]
        [string] $ReportDirectory
    )

    $jsonPath = Join-Path $ReportDirectory 'report.json'
    $htmlPath = Join-Path $ReportDirectory 'report.html'
    $report = Get-Content -LiteralPath $jsonPath -Raw | ConvertFrom-Json
    Assert-ExactPropertyNames `
        -Value $report `
        -ExpectedNames $expectedRootProperties `
        -ContractName 'root'
    Assert-ExactPropertyNames `
        -Value $report.summary `
        -ExpectedNames @($expectedSummary.Keys) `
        -ContractName 'summary'

    if (
        $report.outputSchemaVersion -cne '1' -or
        $report.tool.name -cne 'sarif-regress' -or
        $report.inputs.baseline -cne 'baseline.sarif' -or
        $report.inputs.candidate -cne 'candidate.sarif'
    ) {
        throw 'Comparison smoke JSON identity fields differ from the contract.'
    }
    foreach ($name in $expectedSummary.Keys) {
        if ($report.summary.$name -ne $expectedSummary[$name]) {
            throw "Comparison smoke summary field '$name' differs from the contract."
        }
    }
    if (
        @($report.findings).Count -ne 1 -or
        $report.findings[0].classification -cne 'unchanged' -or
        @($report.diagnostics).Count -ne 0
    ) {
        throw 'Comparison smoke finding or diagnostic content differs from the contract.'
    }

    $html = [System.IO.File]::ReadAllText($htmlPath)
    if (-not $html.StartsWith("<!doctype html>`n", [StringComparison]::Ordinal)) {
        throw 'Comparison smoke HTML has an unexpected document contract.'
    }
    if ($html.IndexOf($offlineMarker, [StringComparison]::Ordinal) -lt 0) {
        throw 'Comparison smoke HTML omits the offline Content Security Policy.'
    }
}

function Invoke-SmokeComparison {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Executable,

        [Parameter(Mandatory = $true)]
        [string] $ReportDirectory
    )

    New-Item -ItemType Directory -Path $ReportDirectory | Out-Null
    & $Executable compare `
        --baseline $baselineFixture `
        --candidate $candidateFixture `
        --json-out (Join-Path $ReportDirectory 'report.json') `
        --html-out (Join-Path $ReportDirectory 'report.html')
    if ($LASTEXITCODE -ne 0) {
        throw "Comparison smoke executable failed: $Executable"
    }
    Assert-ReportContract -ReportDirectory $ReportDirectory
}

if (Test-Path -LiteralPath $OutputRoot) {
    throw "Comparison smoke output root already exists: $OutputRoot"
}

$resolvedStandaloneExecutable = (
    Resolve-Path -LiteralPath $StandaloneExecutable
).ProviderPath
$resolvedInstalledToolExecutable = (
    Resolve-Path -LiteralPath $InstalledToolExecutable
).ProviderPath
New-Item -ItemType Directory -Path $OutputRoot | Out-Null
$standaloneOutput = Join-Path $OutputRoot 'standalone'
$installedToolOutput = Join-Path $OutputRoot 'installed-tool'
Invoke-SmokeComparison `
    -Executable $resolvedStandaloneExecutable `
    -ReportDirectory $standaloneOutput
Invoke-SmokeComparison `
    -Executable $resolvedInstalledToolExecutable `
    -ReportDirectory $installedToolOutput
Assert-FileBytesEqual `
    -ExpectedPath (Join-Path $standaloneOutput 'report.json') `
    -ActualPath (Join-Path $installedToolOutput 'report.json')
Assert-FileBytesEqual `
    -ExpectedPath (Join-Path $standaloneOutput 'report.html') `
    -ActualPath (Join-Path $installedToolOutput 'report.html')
