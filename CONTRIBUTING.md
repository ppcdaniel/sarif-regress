# Contributing to SarifRegress

SarifRegress accepts narrowly scoped changes that preserve deterministic behaviour and the project boundaries in [docs/architecture.md](docs/architecture.md).

## Setup requirements

Install:

- Git;
- the stable .NET SDK version pinned in `global.json`;
- PowerShell 5.1 or later on Windows, or Bash on Linux.

The exact SDK pin is intentional. Confirm the active version from the repository root:

```text
dotnet --version
```

## Branch and pull-request workflow

1. Start from an up-to-date `main` branch.
2. Create a focused branch named for the active issue, such as `issue-42-short-description`.
3. Implement only the issue's acceptance criteria.
4. Add deterministic tests for every observable behaviour introduced or changed.
5. Run the platform verification command below.
6. Run `git diff --check` and review the complete diff for generated or unrelated files.
7. Open a pull request that links the issue and records the commands run and their outcomes.

Do not broaden a contribution beyond the active issue without first agreeing that scope in a tracked issue. Do not commit build outputs, test results, local package caches, IDE state, generated user files, or secrets.

## Local verification

The single required Windows command is:

```powershell
.\scripts\verify.ps1
```

The single required Linux command is:

```bash
./scripts/verify.sh
```

Verification checks formatting, performs a warning-free deterministic Release build, and runs the complete test suite. Contributions that affect observable output must include tests for repeated-run byte equality and, where relevant, Windows/Linux equality.
