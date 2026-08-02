# Third-party inventory and notice status

Status: **incomplete and release-blocking**

This file records only facts supported by committed manifests, lock files, and provenance. It is
not yet a complete binary-redistribution notice. In particular, the repository does not contain
the exact upstream licence/notice texts for every component embedded in the self-contained
executables. Do not treat the presence of this file as satisfying issue #18 or as permission to
publish a release.

## SarifRegress

SarifRegress is distributed under the MIT License. The authoritative text is the repository
`LICENSE` file. The `.nupkg` includes that file; the current top-level standalone release bundle
does not, which must be corrected before distribution.

## Components in product distribution

| Component | Verified version/source | Distribution role | Verified notice status |
|---|---|---|---|
| `System.CommandLine` | NuGet `2.0.10`; central version and locked content hash are committed | Direct dependency of `SarifRegress.Tool`; included in tool/self-contained publication as applicable | Upstream licence/notice text is not committed or verified in this repository; unresolved |
| .NET runtime components | Self-contained `linux-x64` and `win-x64` output produced under pinned SDK `10.0.302`; the exact embedded runtime dependency graph is not committed | Embedded in standalone executables | Exact redistributed component inventory and corresponding notice text are not committed; unresolved |

Before any release, derive the exact distribution inventory from the final locked restore/publish,
obtain the applicable primary licence and notice files, review them without paraphrasing their
terms, include the required material beside both standalone executables and in the package where
applicable, add the project `LICENSE`, checksum every notice, and assert exact contents in Linux and
Windows package smoke tests.

## Validation and test dependencies not shipped as product artifacts

The following are used to build or validate the repository and are not intended to be copied into
the product release bundle.

| Scope | Direct pins | Locked transitive examples | Disposition |
|---|---|---|---|
| Schema validation | `JsonSchema.Net 9.4.0` | `JsonPointer.Net 7.0.2`, `Json.More.Net 3.0.1` | The named packages' maintenance terms require an owner-specific applicability/exemption/acceptance decision; issue #17 is open |
| Supporting validation transitive | — | `Humanizer.Core 3.0.10` | Locked but not redistributed in the product bundle; its exact licence/notice disposition remains part of the incomplete inventory, separate from issue #17's named maintenance-terms question |
| Tests | `Microsoft.NET.Test.Sdk 18.8.1`, `xunit.v3 3.2.2`, `xunit.runner.visualstudio 3.1.5` | Versions and package content hashes are frozen by test lock files | Not redistributed in the product bundle; upstream licence texts are not reproduced here |

This inventory does not conclude that a maintenance fee is owed. The necessary owner facts are not
present in the repository. It records the unresolved decision and prevents silence from being
mistaken for acceptance.

## Capture and comparison tools not redistributed

The repository commits small controlled source fixtures, authentic/projection-audited SARIF, and
provenance—not the producer executables or release archives.

| Tool | Exact provenance | Licence recorded by committed evidence | Distribution status |
|---|---|---|---|
| Semgrep Community Edition | `1.172.0`, source `651f37efa397bf066e1cf627414eeabe40b07e27`, wheel SHA-256 `d8b94af4266a575287ad2cd844573743ab4fe58f6bfb6d9229327807937eade3` | `LGPL-2.1-only` | Capture-only; binary/archive not committed or released |
| Gitleaks | `8.30.1`, source `83d9cd684c87d95d656c1458ef04895a7f1cbd8e`, archive SHA-256 `551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb` | MIT | Capture-only; binary/archive not committed or released |
| PMD | `7.26.0`, source `8fd38edf285a33e1164f66205ebe243441db9557`, archive SHA-256 `9f55cb7ff0e9f9a66dd2f005eaa370e84c8a4cd971b134aa14a930c4a283ebc9` | `LicenseRef-PMD-BSD-Style`; the archive includes Apache-2.0-licensed components | Capture-only; binary/archive not committed or released |
| Microsoft SARIF Multitool | NuGet `5.5.0`, source `e68c02f86ac02bb9acb3b9da6c3de2291d5b0e2a`, package SHA-256 `2d2c73cc1fa4b79e5a41bded05d94dd645fa61d003492054260d7e106e838149` | MIT | External validation baseline only; package not redistributed |

No additional attribution obligation for committed producer output is invented here. Preserve the
existing producer/version/source/licence provenance and obtain a legal or owner disposition if the
distribution surface changes.

## CI actions

External GitHub Actions are execution-time dependencies, not release assets. Every use is pinned to
an immutable commit:

- `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1` (`v7.0.1`)
- `actions/setup-dotnet@a98b56852c35b8e3190ac28c8c2271da59106c68` (`v6.0.0`)
- `actions/setup-python@e797f83bcb11b83ae66e0230d6156d7c80228e7c` (`v6.0.0`)
- `actions/setup-java@dded0888837ed1f317902acf8a20df0ad188d165` (`v5.0.0`)
- `actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` (`v7.0.1`)
- `actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c` (`v8.0.1`)

Version comments are audit labels; the commit SHA is the executed identity.

The tag-only draft-release job also calls the GitHub-hosted runner's preinstalled `gh` executable.
No exact `gh` version, binary hash, or licence record is committed. It is not a release asset, but
its provenance remains an unresolved release-workflow reproducibility item.
