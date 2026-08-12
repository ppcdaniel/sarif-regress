# Windows owner verification

This checklist is for the repository owner to execute from a clean Windows checkout. It records
personal, local evidence in addition to the hosted Windows jobs. The agent that prepared this
checklist **did not perform these commands on a local Windows machine**.

Use 64-bit Windows, PowerShell 7 (`pwsh`), Git, Python 3, and the SDK pinned by `global.json`
(`10.0.302`). Holdout validation also requires the exact `Microsoft.NETCore.App 8.0.29` runtime for
the pinned Multitool baseline. Run PowerShell without administrator privileges. Do not publish the
generated package or create a release or tag.

## 1. Create and identify a clean checkout

Before starting, replace `<FINAL_HEAD_SHA>` with the full head SHA shown by the draft pull request.
The comparison against that value prevents an accidental test of a different commit.

```powershell
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
Set-StrictMode -Version Latest

$ExpectedHead = '<FINAL_HEAD_SHA>'
$Checkout = Join-Path $PWD 'sarif-regress-owner-check'

git clone https://github.com/ppcdaniel/sarif-regress.git $Checkout
Set-Location $Checkout
git fetch --no-tags origin $ExpectedHead
git switch --detach $ExpectedHead

$ActualHead = (git rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $ActualHead -ne $ExpectedHead) {
    throw "Expected $ExpectedHead but checked out $ActualHead."
}

if ((git status --short).Count -ne 0) {
    throw 'The clean checkout already contains changes.'
}
```

Start a transcript and capture the machine identity before verification:

```powershell
New-Item -ItemType Directory -Path artifacts/owner-verification -Force | Out-Null
Start-Transcript -Path artifacts/owner-verification/windows-owner-verification.txt

Get-ComputerInfo |
    Select-Object WindowsProductName, WindowsVersion, OsBuildNumber, OsArchitecture
$PSVersionTable.PSVersion
dotnet --version
dotnet --info
dotnet --list-runtimes
git --version
python --version
git rev-parse HEAD
```

Record whether `dotnet --version` is exactly `10.0.302`. A later SDK may be installed alongside
it, but `global.json` must select the pinned SDK for this checkout. Confirm that
`dotnet --list-runtimes` contains `Microsoft.NETCore.App 8.0.29`; the holdout wrapper fails closed
without that exact runtime.

## 2. Run the repository verification and package build

These are the two required clean-clone commands. Keep their complete output in the transcript.

```powershell
.\scripts\verify.ps1
.\scripts\package.ps1
```

Both commands must return exit code `0`. `verify.ps1` restores locked dependencies, checks .NET
formatting, builds Release with warnings as errors, and runs the full test suite. `package.ps1`
repeats the build, creates the .NET tool package, publishes self-contained Linux x64 and Windows
x64 executables, and writes `artifacts/release/checksums.sha256`.

Confirm the checkout is still clean; generated files must remain ignored:

```powershell
if ((git status --short).Count -ne 0) {
    git status --short
    throw 'Verification changed tracked or untracked repository state unexpectedly.'
}
```

## 3. Verify release-bundle checksums

Verify every line rather than checking only the Windows executable:

```powershell
$ReleaseRoot = (Resolve-Path artifacts/release).Path
$ChecksumPath = Join-Path $ReleaseRoot 'checksums.sha256'
$ManifestLines = @(Get-Content -LiteralPath $ChecksumPath)

if ($ManifestLines.Count -ne 3) {
    throw "Expected three checksum entries, found $($ManifestLines.Count)."
}

foreach ($Line in $ManifestLines) {
    $ChecksumMatch = [regex]::Match($Line, '^([0-9a-f]{64})  ([^/\\]+)$')
    if (-not $ChecksumMatch.Success) {
        throw "Malformed checksum line: $Line"
    }

    $ExpectedHash = $ChecksumMatch.Groups[1].Value
    $ArtifactName = $ChecksumMatch.Groups[2].Value
    $ArtifactPath = Join-Path $ReleaseRoot $ArtifactName
    $ActualHash = (
        Get-FileHash -LiteralPath $ArtifactPath -Algorithm SHA256
    ).Hash.ToLowerInvariant()

    if ($ActualHash -ne $ExpectedHash) {
        throw "Checksum mismatch for $ArtifactName."
    }

    [pscustomobject]@{
        Artifact = $ArtifactName
        Sha256 = $ActualHash
        Bytes = (Get-Item -LiteralPath $ArtifactPath).Length
    }
}
```

## 4. Install the locally generated .NET tool

Install only from the local bundle. This is an installation smoke test, not publication to a
feed.

```powershell
$PackageFiles = @(
    Get-ChildItem -LiteralPath $ReleaseRoot -Filter 'SarifRegress.Tool.*.nupkg' -File
)
if ($PackageFiles.Count -ne 1) {
    throw "Expected one local tool package, found $($PackageFiles.Count)."
}

$PackageMatch = [regex]::Match(
    $PackageFiles[0].Name,
    '^SarifRegress\.Tool\.(.+)\.nupkg$'
)
if (-not $PackageMatch.Success) {
    throw 'Could not read the tool version from the package name.'
}

$ToolVersion = $PackageMatch.Groups[1].Value
$ToolRoot = Join-Path $PWD 'artifacts/owner-verification/tool'
$LocalFeed = Join-Path $PWD 'release'
$ToolStateRoot = Join-Path $PWD 'artifacts/owner-verification/dotnet-state'
$env:NUGET_PACKAGES = Join-Path $ToolStateRoot 'packages'
$env:DOTNET_CLI_HOME = Join-Path $ToolStateRoot 'cli-home'
$env:NUGET_HTTP_CACHE_PATH = Join-Path $ToolStateRoot 'http-cache'
New-Item -ItemType Directory -Path $ToolRoot -Force | Out-Null
New-Item -ItemType Directory -Path $LocalFeed -Force | Out-Null
New-Item -ItemType Directory -Path $env:NUGET_PACKAGES -Force | Out-Null
New-Item -ItemType Directory -Path $env:DOTNET_CLI_HOME -Force | Out-Null
New-Item -ItemType Directory -Path $env:NUGET_HTTP_CACHE_PATH -Force | Out-Null
Copy-Item -LiteralPath $PackageFiles[0].FullName -Destination $LocalFeed

dotnet tool install `
    --tool-path $ToolRoot `
    --configfile NuGet.ReleaseSmoke.config `
    --no-cache `
    SarifRegress.Tool `
    --version $ToolVersion
if ($LASTEXITCODE -ne 0) {
    throw 'The local .NET tool installation failed.'
}

$InstalledPackages = @(
    Get-ChildItem `
        -LiteralPath (Join-Path $ToolRoot '.store') `
        -Filter 'sarifregress.tool.*.nupkg' `
        -File `
        -Recurse
)
if ($InstalledPackages.Count -ne 1) {
    throw "Expected one retained installed package, found $($InstalledPackages.Count)."
}

$BuiltPackageHash = (
    Get-FileHash -LiteralPath $PackageFiles[0].FullName -Algorithm SHA256
).Hash
$InstalledPackageHash = (
    Get-FileHash -LiteralPath $InstalledPackages[0].FullName -Algorithm SHA256
).Hash
if (
    $PackageFiles[0].Length -ne $InstalledPackages[0].Length -or
    $BuiltPackageHash -ne $InstalledPackageHash
) {
    throw 'The installed package bytes differ from the locally generated package.'
}

$SarifRegress = Join-Path $ToolRoot 'sarif-regress.exe'
& $SarifRegress --help
if ($LASTEXITCODE -ne 0) {
    throw 'The installed .NET tool did not start.'
}
```

Optionally prove that the packaged self-contained Windows executable starts without relying on the
tool shim:

```powershell
& (Join-Path $ReleaseRoot 'sarif-regress-win-x64.exe') --help
if ($LASTEXITCODE -ne 0) {
    throw 'The self-contained Windows executable did not start.'
}
```

## 5. Run the ESLint demonstration

```powershell
$DemoRoot = Join-Path $PWD 'artifacts/owner-verification/eslint'
New-Item -ItemType Directory -Path $DemoRoot -Force | Out-Null

& $SarifRegress compare `
    --baseline corpus/cases/eslint-real-mutation/baseline.sarif `
    --candidate corpus/cases/eslint-real-mutation/candidate.sarif `
    --json-out (Join-Path $DemoRoot 'report.json') `
    --html-out (Join-Path $DemoRoot 'report.html')
$DemoExit = $LASTEXITCODE
if ($DemoExit -notin @(0, 3)) {
    throw "The ESLint comparison returned invalid exit code $DemoExit."
}
if (
    -not (Test-Path -LiteralPath (Join-Path $DemoRoot 'report.json') -PathType Leaf) -or
    -not (Test-Path -LiteralPath (Join-Path $DemoRoot 'report.html') -PathType Leaf)
) {
    throw 'The ESLint comparison did not write both requested reports.'
}
$DemoExit
```

Exit `3` means the comparison completed and wrote its reports, but a classification named by the
default policy (`new`, `modified`, or `ambiguous`) was present. It is evidence to inspect, not an
execution failure. Exit `0` means the comparison and policy both passed; any other exit is a
failure.

Inspect the stable JSON and its rendered HTML:

```powershell
$DemoReport = Get-Content -Raw -LiteralPath (Join-Path $DemoRoot 'report.json') |
    ConvertFrom-Json
$DemoReport.tool
$DemoReport.summary | Format-List
$DemoReport.metrics | Format-List
$DemoReport.findings |
    Group-Object classification |
    Select-Object Name, Count |
    Format-Table

Start-Process (Join-Path $DemoRoot 'report.html')
```

Check that the JSON is readable, the summary totals agree with the finding classifications, and
the offline HTML shows the same decisions. The HTML is a projection of the JSON; it must not show
a different match result.

## 6. Run the Semgrep and Gitleaks fixture comparisons

Run the authentic projected inputs with their committed configurations:

```powershell
$HoldoutRoot = Join-Path $PWD 'artifacts/owner-verification/holdout-fixtures'
New-Item -ItemType Directory -Path $HoldoutRoot -Force | Out-Null

foreach ($Producer in @('semgrep', 'gitleaks')) {
    $CaseRoot = "validation/holdout/cases/$Producer"
    $CaseOut = Join-Path $HoldoutRoot $Producer
    New-Item -ItemType Directory -Path $CaseOut -Force | Out-Null

    & $SarifRegress compare `
        --baseline "$CaseRoot/baseline.sarif" `
        --candidate "$CaseRoot/candidate.sarif" `
        --config "$CaseRoot/config.json" `
        --json-out (Join-Path $CaseOut 'report.json') `
        --html-out (Join-Path $CaseOut 'report.html')
    $ComparisonExit = $LASTEXITCODE
    if ($ComparisonExit -notin @(0, 3)) {
        throw "$Producer comparison returned invalid exit code $ComparisonExit."
    }
    if (
        -not (Test-Path -LiteralPath (Join-Path $CaseOut 'report.json') -PathType Leaf) -or
        -not (Test-Path -LiteralPath (Join-Path $CaseOut 'report.html') -PathType Leaf)
    ) {
        throw "$Producer comparison did not write both requested reports."
    }

    $Report = Get-Content -Raw -LiteralPath (Join-Path $CaseOut 'report.json') |
        ConvertFrom-Json
    [pscustomobject]@{
        Producer = $Producer
        PolicyExit = $ComparisonExit
        Baseline = $Report.summary.baselineCount
        Candidate = $Report.summary.candidateCount
        New = $Report.summary.new
        Unchanged = $Report.summary.unchanged
        Moved = $Report.summary.moved
        Modified = $Report.summary.modified
        Resolved = $Report.summary.resolved
        Ambiguous = $Report.summary.ambiguous
    } | Format-List

    Start-Process (Join-Path $CaseOut 'report.html')
}
```

The ground-truth evaluator, rather than the raw comparison summary alone, establishes the expected
identity result. If network access is available, run the pinned holdout wrapper:

```powershell
$Runtime829 = @(
    dotnet --list-runtimes |
        Where-Object { $_ -match '^Microsoft\.NETCore\.App 8\.0\.29 \[' }
)
if ($LASTEXITCODE -ne 0 -or $Runtime829.Count -ne 1) {
    throw 'validate-holdout.ps1 requires Microsoft.NETCore.App 8.0.29.'
}

.\scripts\validate-holdout.ps1
```

It must reproduce the tracked outputs under `validation/expected` byte-for-byte. Inspect the
project-owned report:

```powershell
$Holdout = Get-Content -Raw -LiteralPath `
    artifacts/holdout-validation/sarif-regress-holdout.json |
    ConvertFrom-Json

$Holdout.evaluation
$Holdout.aggregate | Format-List
$Holdout.producers |
    ForEach-Object {
        [pscustomobject]@{
            Producer = $_.producerId
            TP = $_.metrics.truePositives
            FP = $_.metrics.falsePositives
            FN = $_.metrics.falseNegatives
            ClassificationMismatches = $_.metrics.classificationMismatches
            Precision = $_.metrics.precision
            Recall = $_.metrics.recall
            F1 = $_.metrics.f1
        }
    } | Format-Table
```

The exposed-holdout regression expectations for matcher v3.2 are Semgrep
`25 TP / 0 FP / 0 FN`, Gitleaks
`25 TP / 0 FP / 0 FN`, zero classification mismatches, zero ingestion failures, and zero labelled
ambiguity silently matched. The aggregate remains `50 TP / 0 FP / 25 FN` because PMD contributes
`0 TP / 0 FP / 25 FN`.

## 7. Inspect safe PMD and sparse-SARIF behavior

First run the historical PMD SARIF-only comparison. Do not provide a repository root: the old PMD
source snapshots contain ground-truth markers and are intentionally excluded as matcher evidence.

```powershell
$PmdRoot = Join-Path $PWD 'artifacts/owner-verification/pmd'
New-Item -ItemType Directory -Path $PmdRoot -Force | Out-Null

& $SarifRegress compare `
    --baseline validation/holdout/cases/pmd/baseline.sarif `
    --candidate validation/holdout/cases/pmd/candidate.sarif `
    --config validation/holdout/cases/pmd/config.json `
    --json-out (Join-Path $PmdRoot 'report.json') `
    --html-out (Join-Path $PmdRoot 'report.html')
$PmdExit = $LASTEXITCODE
if ($PmdExit -notin @(0, 3)) {
    throw "The PMD comparison returned invalid exit code $PmdExit."
}
if (
    -not (Test-Path -LiteralPath (Join-Path $PmdRoot 'report.json') -PathType Leaf) -or
    -not (Test-Path -LiteralPath (Join-Path $PmdRoot 'report.html') -PathType Leaf)
) {
    throw 'The PMD comparison did not write both requested reports.'
}
$PmdExit

$PmdReport = Get-Content -Raw -LiteralPath (Join-Path $PmdRoot 'report.json') |
    ConvertFrom-Json
$PmdReport.summary | Format-List
$PmdReport.findings |
    Group-Object classification |
    Select-Object Name, Count |
    Format-Table
Start-Process (Join-Path $PmdRoot 'report.html')
```

The current safe SARIF-only result on the legacy PMD holdout accepts no identity pair; the scored
result is
`0 TP / 0 FP / 25 FN`. That is a documented limitation, not a passing recall result.

Then reproduce the clean sparse-SARIF research harness. The first command emits label-neutral
observations; only the second command opens the labels and scores them.

```powershell
python -B validation/research/sparse-sarif/tools/test_scan_contamination.py
if ($LASTEXITCODE -ne 0) {
    throw 'The contamination-scanner tests failed.'
}

python -B `
    validation/research/sparse-sarif/tools/scan_contamination.py `
    --research-root validation/research/sparse-sarif
if ($LASTEXITCODE -ne 0) {
    throw 'The clean sparse-SARIF corpus failed contamination admission.'
}

$SparseProject = `
    'validation/tools/SarifRegress.Validation/SarifRegress.Validation.csproj'
$SparseObservationRoot = Join-Path $PWD 'artifacts/owner-verification/sparse-observations'
$SparseEvidenceRoot = Join-Path $PWD 'artifacts/owner-verification/sparse-evidence'
New-Item -ItemType Directory -Path $SparseObservationRoot -Force | Out-Null
New-Item -ItemType Directory -Path $SparseEvidenceRoot -Force | Out-Null

dotnet run `
    --project $SparseProject `
    --configuration Release `
    --no-build `
    --no-restore `
    -- `
    sparse-run `
    --repository-root $PWD.Path `
    --output-root $SparseObservationRoot
if ($LASTEXITCODE -ne 0) {
    throw 'The label-neutral sparse experiment failed.'
}

$Observations = Join-Path `
    $SparseObservationRoot `
    'sparse-experiment-observations.json'
dotnet run `
    --project $SparseProject `
    --configuration Release `
    --no-build `
    --no-restore `
    -- `
    sparse-evaluate `
    --repository-root $PWD.Path `
    --output-root $SparseEvidenceRoot `
    --observations $Observations
if ($LASTEXITCODE -ne 0) {
    throw 'The sparse experiment evaluator failed.'
}

Get-Content -Raw -LiteralPath $Observations | ConvertFrom-Json |
    Select-Object kind, schemaVersion
Get-Content -Raw -LiteralPath `
    (Join-Path $SparseEvidenceRoot 'sparse-experiment-gate-evidence.json') |
    ConvertFrom-Json |
    ConvertTo-Json -Depth 12

function Assert-ByteIdentical {
    param(
        [Parameter(Mandatory)] [string] $Actual,
        [Parameter(Mandatory)] [string] $Expected
    )
    $ActualBytes = [System.IO.File]::ReadAllBytes((Resolve-Path $Actual).Path)
    $ExpectedBytes = [System.IO.File]::ReadAllBytes((Resolve-Path $Expected).Path)
    if (
        $ActualBytes.Length -ne $ExpectedBytes.Length -or
        [Convert]::ToBase64String($ActualBytes) -cne
            [Convert]::ToBase64String($ExpectedBytes)
    ) {
        throw "$Actual differs byte-for-byte from $Expected."
    }
}

$SparseExpectedRoot = Join-Path $PWD 'validation/research/sparse-sarif/expected'
$GeneratedGates = Join-Path $SparseEvidenceRoot 'sparse-experiment-gate-evidence.json'
Assert-ByteIdentical `
    -Actual $Observations `
    -Expected (Join-Path $SparseExpectedRoot 'sparse-experiment-observations.json')
Assert-ByteIdentical `
    -Actual $GeneratedGates `
    -Expected (Join-Path $SparseExpectedRoot 'sparse-experiment-gate-evidence.json')

foreach ($Line in Get-Content -LiteralPath (Join-Path $SparseExpectedRoot 'checksums.sha256')) {
    $ChecksumMatch = [regex]::Match($Line, '^([0-9a-f]{64})  (.+)$')
    if (-not $ChecksumMatch.Success) {
        throw "Malformed sparse checksum line: $Line"
    }
    $RelativeName = $ChecksumMatch.Groups[2].Value.Replace(
        '/',
        [System.IO.Path]::DirectorySeparatorChar)
    $EvidencePath = Join-Path $SparseExpectedRoot $RelativeName
    $ActualHash = (
        Get-FileHash -LiteralPath $EvidencePath -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    if ($ActualHash -ne $ChecksumMatch.Groups[1].Value) {
        throw "Sparse evidence checksum mismatch for $RelativeName."
    }
}

$Limitation = Get-Content -Raw -LiteralPath `
    (Join-Path $SparseExpectedRoot 'sparse-experiment-limitation.json') |
    ConvertFrom-Json
if (
    $Limitation.kind -ne 'sparse-experiment-limitation/v1' -or
    $Limitation.decision -ne 'document-limitation' -or
    $Limitation.matcherV4Implemented -ne $false -or
    $Limitation.sourceHeadSha -ne '4cc6faf0167d7da385c1d204cba97d1f34ccb479' -or
    $Limitation.matcherAlgorithmVersion -ne 'sarifregress/matcher/v3.2' -or
    $Limitation.blockedCompositeValidationIssue -ne 27
) {
    throw 'The sparse limitation record does not match the reviewed safe stop.'
}
$Limitation |
    Select-Object kind, decision, matcherV4Implemented, sourceHeadSha,
        matcherAlgorithmVersion, blockedCompositeValidationIssue |
    Format-List
```

This section reproduces the historical ADR 0003 result: `9 TP / 0 FP / 10 FN`, precision `1.0`,
recall `0.473684`, F1 `0.642857`, with all three labelled ambiguity units refused. The current
preview candidate separately verifies the all-or-nothing side-root/manifest product profile from
ADR 0004; matcher v4 remains uncreated.

## 8. Finish and retain the record

Record a short disposition for every item: pass, fail, or not run, with the exit code and a link
or path to the retained output. Do not silently omit a failed command. At minimum record:

| Item | Required record |
|---|---|
| Windows | product name, version, build number, architecture |
| .NET | selected SDK version and complete `dotnet --info` |
| Source | branch and exact full commit SHA |
| Verification | `verify.ps1` exit and test summary |
| Packaging | `package.ps1` exit and the three SHA-256 values |
| Tool smoke | package version and installed-tool `--help` exit |
| Fixtures | ESLint, Semgrep, Gitleaks, and PMD exit codes and JSON summaries |
| Sparse research | observation/evaluator exits and per-variant metrics |
| Presentation | confirmation that JSON and HTML were opened and compared |
| Deviations | any skipped step, environmental failure, or result mismatch |

```powershell
git status --short
git rev-parse HEAD
Stop-Transcript
```

Attach the transcript, the generated JSON reports, checksum verification output, and screenshots
or notes from HTML inspection to the owner-verification record. Do not describe this checklist as
passed until the owner has actually run every required step on the recorded Windows machine.
