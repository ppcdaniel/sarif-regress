# Packaging and release

SarifRegress has three distribution forms:

1. a framework-dependent .NET tool package, `SarifRegress.Tool`;
2. a self-contained single-file `linux-x64` executable;
3. a self-contained single-file `win-x64` executable.

Native AOT, trimming, and ReadyToRun are intentionally disabled. The normal .NET tool keeps
contributor installation simple; the self-contained executables provide a runtime-independent
option after the dependency graph has been tested.

## Local package command

From any current directory, invoke the script by its checkout path.

Windows:

```powershell
.\scripts\package.ps1
```

Linux:

```bash
./scripts/package.sh
```

Each script:

1. restores locked dependencies, including the committed `linux-x64` and `win-x64` runtime
   graphs, and performs a Release build with the tracked lock files;
2. packs the framework-dependent .NET tool;
3. publishes `linux-x64` and `win-x64` from that locked graph with `--no-restore`;
4. copies the distributable files to `artifacts/release/`;
5. writes a lowercase SHA-256 manifest with LF line endings and no BOM.

The CLI project declares both runtime identifiers together so one committed lock graph covers the
framework-dependent tool and both self-contained publications. Package commands do not evaluate a
new dependency graph or modify tracked lock files.

Self-contained `RuntimeFrameworkVersion` is pinned to `10.0.10`, the runtime included with the
repository's pinned SDK `10.0.302`. The framework-dependent tool retains normal .NET 10 runtime
roll-forward behavior. Changing the self-contained version requires re-auditing the runtime and
host packs and replacing the retained upstream notice files and their hashes in
`notices/checksums.sha256`.

Before packaging, each script verifies the retained upstream notice bytes. It then compares every
notice copied to the release bundle with its repository source and compares the licence and notice
entries embedded in the NuGet package byte-for-byte. A missing or changed file fails packaging.
Before recursive cleanup, the scripts also require `artifacts` and the managed `packages`,
`publish`, and `release` children to be their expected physical non-link directories. A linked
root, linked target, or linked descendant fails closed; CI protects an external canary with a Linux
symlink and a Windows junction.

The release directory contains exactly the distribution surface:

```text
artifacts/release/
  DOTNET_RUNTIME_LICENSE.txt
  DOTNET_RUNTIME_THIRD_PARTY_NOTICES.txt
  LICENSE
  SarifRegress.Tool.<version>.nupkg
  SYSTEM_COMMANDLINE_LICENSE.md
  THIRD_PARTY_NOTICES.md
  sarif-regress-linux-x64
  sarif-regress-win-x64.exe
  checksums.sha256
```

The NuGet package contains the project `LICENSE`, `THIRD_PARTY_NOTICES.md`, and the verbatim
`System.CommandLine` licence. The two .NET notice files accompany the self-contained executables in
the release bundle. `THIRD_PARTY_NOTICES.md` records the exact package versions, source commit,
package hashes, and why build/validation/test dependencies are outside the product distribution.

Intermediate publish directories remain under `artifacts/publish/` and are ignored by Git.
During the release workflow, the labelled-corpus report plus enforced full and deterministic
1,000-finding unique and pathological benchmark reports and a `source-commit.txt` containing the
exact checked-out commit are added to this directory. The workflow then regenerates
`checksums.sha256` over the complete release set.

Packaging does not replace verification. Run `scripts/verify.ps1` or `scripts/verify.sh` first when
preparing a release.

## Verify downloaded files

Linux:

```bash
sha256sum --check checksums.sha256
chmod +x sarif-regress-linux-x64
```

PowerShell can compare a manifest entry with:

```powershell
(Get-FileHash .\sarif-regress-win-x64.exe -Algorithm SHA256).Hash.ToLowerInvariant()
```

Compare that value with the corresponding lowercase value in `checksums.sha256` before execution.

## Integrity and authenticity

The release manifest detects changed or corrupted assets when the manifest itself was obtained
through a trusted channel. SarifRegress does not currently code-sign the executables, sign the
NuGet package or checksum manifest, or publish a provenance attestation. Checksums therefore
provide integrity evidence, not an independent proof of publisher identity. Treat the repository's
HTTPS release page and protected maintainer account as the trust root, and do not execute an asset
whose digest differs.

## Version preparation

Before tagging:

1. choose a Semantic Version;
2. align `VersionPrefix` and optional `VersionSuffix` in `Directory.Build.props`,
   `ProductInformation.Version`, the release-note filename, the package version, and the intended
   tag;
3. update lock files only if dependency, framework, runtime, or project-graph inputs changed;
4. for every matching change that can alter classifications, increment the matcher algorithm
   version and retain before/after corpus reports;
5. prepare release-note text recording the behavioral change, before/after precision and recall,
   and changed classification or ambiguity sets;
6. run verification on Windows and Linux;
7. run a package script and verify the manifest;
8. confirm the package version and intended tag are identical;
9. confirm a repository ruleset restricts creation of release tags to authorised maintainers and
   prevents their update or deletion after creation.

The tag form is `v<version>`, for example `v0.1.0` or preview `v0.1.0-rc.1`. A tag whose version does not match the generated
`SarifRegress.Tool.<version>.nupkg` is rejected by the workflow.

Automatic GitHub release notes are a change index, not the required behavioral record. The
maintainer reviewing a matching change must retain its before/after corpus comparison and prepare
the semantic classification impact before creating the tag. After the workflow creates the draft,
the maintainer must add that prepared text, link or attach the comparison, and review the exact
assets before publishing it. The workflow enforces the current corpus gates but cannot decide
whether a changed ground truth or release explanation is correct.

## GitHub Actions behavior

`.github/workflows/release.yml` supports:

- a manual dispatch, which verifies Windows and Linux, runs raw-byte cross-platform corpus and
  deterministic-benchmark gates for that exact commit, creates the release bundle, and retains it
  as a GitHub Actions artifact for review;
- a `v*.*.*` tag push, which performs the same exact-tag-SHA gates and then creates a draft GitHub
  release with the package, both binaries, corpus/benchmark evidence, and checksum manifest.

Repository permission is read-only for verification and packaging. Only the tag-only
release-draft job receives `contents: write`, using GitHub's short-lived workflow token. The
workflow refuses to overwrite an existing release.

The release bundle is built once on Linux and uploaded as one immutable workflow artifact. Separate
Windows and Linux smoke jobs download that exact bundle, verify its complete checksum manifest,
compare every notice with the checked-out audited source, inspect the NuGet notice entries, execute
the matching self-contained binary, and install and execute the tool package. Both forms compare
the checked `github-supported-subset` fixture into runner-temporary JSON and HTML outputs. The smoke
contract asserts the exact schema version, root shape, summary, classification, empty diagnostics,
HTML doctype, and offline Content Security Policy, then requires byte-identical outputs. Each job
isolates NuGet to the downloaded bundle, disables caches, and verifies that the retained installed
`.nupkg` has the same bytes as the downloaded package (`cmp` on Linux, length plus SHA-256 on
Windows). A same-version package from another source therefore cannot satisfy the smoke test. Draft
creation cannot start until both native smoke jobs and the reusable Windows/Linux determinism
workflow pass.

The tag workflow deliberately leaves the GitHub release as a draft. Before publishing it, a
maintainer must replace or extend the generated change index with the prepared behavioral release
notes and link or attach the retained before/after corpus comparison. This manual review is the
release gate for semantic matching changes that automation cannot assess.

Immediately before draft creation, the workflow resolves and peels the remote tag and requires it
to equal `source-commit.txt` from the checksummed bundle. The repository release-tag ruleset is
still required because it closes the remaining race by preventing a tag from moving during or
after that check.

The workflow does not publish to NuGet.org and requires no NuGet API key. A maintainer may promote
the verified `.nupkg` to a configured feed through a separately reviewed process.

## Installing the tool package

After publication to a configured NuGet source:

```bash
dotnet tool install --global SarifRegress.Tool --version <version>
```

For a local release bundle:

```bash
dotnet tool install \
  --tool-path ./artifacts/tool \
  --add-source ./artifacts/release \
  SarifRegress.Tool \
  --version <version>
```

The .NET tool needs a compatible .NET 10 runtime. The RID executables are self-contained.
