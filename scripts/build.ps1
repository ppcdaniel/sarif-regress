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

Push-Location -LiteralPath $repositoryRoot
try {
    Invoke-DotNet -Arguments @('restore', $solutionFile, '--locked-mode')
    Invoke-DotNet -Arguments @(
        'build',
        $solutionFile,
        '--configuration',
        'Release',
        '--no-restore',
        '--warnaserror'
    )
}
finally {
    Pop-Location
}
