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
$solutionFile = 'SarifRegress.slnx'

& (Join-Path $PSScriptRoot 'build.ps1')

Push-Location -LiteralPath $repositoryRoot
try {
    Invoke-DotNet -Arguments @(
        'test',
        $solutionFile,
        '--configuration',
        'Release',
        '--no-build',
        '--no-restore'
    )
}
finally {
    Pop-Location
}
