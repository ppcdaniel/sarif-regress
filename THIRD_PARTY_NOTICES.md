# Third-party notices

This document identifies the third-party software redistributed by SarifRegress release artifacts
and the exact upstream material retained with those artifacts. It records source and package facts;
it does not add to, summarize, or interpret the upstream licence terms.

SarifRegress itself is distributed under the MIT License in `LICENSE`.

## Product distribution

SarifRegress has three distribution forms. The framework-dependent `SarifRegress.Tool` NuGet
package contains the application assemblies and `System.CommandLine`. The `linux-x64` and
`win-x64` single-file executables contain those assemblies plus the corresponding .NET runtime and
application host components.

| Component | Distribution forms | Verified package/source identity | Verbatim material |
|---|---|---|---|
| `System.CommandLine` | NuGet tool and both self-contained executables | NuGet `2.0.10`; package SHA-256 `8a58c35e21a3b40fb0f642c72edc914a6ebb56f4674ca89049f3d44cdb760541`; package repository commit `f7d90799ce4ef09a0bb257852a57248d2a8fb8dd` | `SYSTEM_COMMANDLINE_LICENSE.md` in the release bundle; `notices/SYSTEM_COMMANDLINE_LICENSE.md` in the NuGet package and source tree |
| `Microsoft.NETCore.App.Runtime.linux-x64` | Linux self-contained executable only | NuGet `10.0.10`; package SHA-256 `1225154d0588617fdb9fe3fa1c37b40216ecdd2372154e661e115a6836b85b84`; package repository commit `f7d90799ce4ef09a0bb257852a57248d2a8fb8dd` | `DOTNET_RUNTIME_LICENSE.txt` and `DOTNET_RUNTIME_THIRD_PARTY_NOTICES.txt` in the release bundle and under `notices/` in the source tree |
| `Microsoft.NETCore.App.Host.linux-x64` | Linux self-contained executable only | NuGet `10.0.10`; package SHA-256 `0efbaceec8bb257804c13074f4405a6676722e551fedcc1528f73ae051199a5c`; package repository commit `f7d90799ce4ef09a0bb257852a57248d2a8fb8dd` | Same two .NET files; the package copies are byte-identical to the Linux runtime-package copies |
| `Microsoft.NETCore.App.Runtime.win-x64` | Windows self-contained executable only | NuGet `10.0.10`; package SHA-256 `56899c9057d6981ab9f237d6489e469af043668ab34cfb4199b55f92702b06bb`; package repository commit `f7d90799ce4ef09a0bb257852a57248d2a8fb8dd` | Same two .NET files; the upstream Windows copies contain the same text with CRLF line endings |
| `Microsoft.NETCore.App.Host.win-x64` | Windows self-contained executable only | NuGet `10.0.10`; package SHA-256 `39713e65938f3bc8ccee343dd377e01049844c3484731ab9b29085e650ba19bd`; package repository commit `f7d90799ce4ef09a0bb257852a57248d2a8fb8dd` | Same two .NET files; the package copies are byte-identical to the Windows runtime-package copies |

The checked-in .NET notice files are the exact LF bytes supplied by the Linux `10.0.10` runtime
and host packs. Direct comparison verified that the Windows packs supply identical text using CRLF
line endings. `notices/checksums.sha256` binds every retained upstream file.

The pinned .NET SDK `10.0.302` includes .NET runtime `10.0.10`. Self-contained packaging also
pins `RuntimeFrameworkVersion` to `10.0.10`, so a runtime servicing change cannot silently reuse
these notice files. The framework-dependent NuGet tool retains normal .NET 10 runtime roll-forward
behavior and does not redistribute runtime components.

## Authoritative upstream records

- `System.CommandLine 2.0.10` NuGet package:
  <https://api.nuget.org/v3-flatcontainer/system.commandline/2.0.10/system.commandline.2.0.10.nupkg>
- `System.CommandLine` licence at the package's repository commit:
  <https://github.com/dotnet/dotnet/blob/f7d90799ce4ef09a0bb257852a57248d2a8fb8dd/src/command-line-api/LICENSE.md>
- .NET `10.0.10` download and SDK/runtime relationship:
  <https://dotnet.microsoft.com/en-us/download/dotnet/10.0>
- .NET `10.0.10` packs inspected for the self-contained outputs:
  [Linux runtime](https://api.nuget.org/v3-flatcontainer/microsoft.netcore.app.runtime.linux-x64/10.0.10/microsoft.netcore.app.runtime.linux-x64.10.0.10.nupkg),
  [Linux host](https://api.nuget.org/v3-flatcontainer/microsoft.netcore.app.host.linux-x64/10.0.10/microsoft.netcore.app.host.linux-x64.10.0.10.nupkg),
  [Windows runtime](https://api.nuget.org/v3-flatcontainer/microsoft.netcore.app.runtime.win-x64/10.0.10/microsoft.netcore.app.runtime.win-x64.10.0.10.nupkg), and
  [Windows host](https://api.nuget.org/v3-flatcontainer/microsoft.netcore.app.host.win-x64/10.0.10/microsoft.netcore.app.host.win-x64.10.0.10.nupkg).
- Microsoft's .NET licence-information record:
  <https://github.com/dotnet/core/blob/main/license-information.md>

The NuGet package specifications name the same repository commit for `System.CommandLine` and all
four .NET packs. Each pack provides its own licence metadata; the exact supplied texts are retained
without paraphrase.

## Build, validation, and test dependencies are not product dependencies

The following dependencies are used only while building, validating, or testing this repository.
They are not copied into the NuGet tool or either self-contained executable, so their licence texts
are not presented as product redistribution notices here.

| Scope | Direct dependencies | Locked transitive dependencies |
|---|---|---|
| Validation application | No validation-only NuGet package dependencies; it uses repository project references and the repository-owned bounded schema evaluator | None |
| Test projects | `Microsoft.NET.Test.Sdk 18.8.1`, `xunit.v3 3.2.2`, `xunit.runner.visualstudio 3.1.5` | The exact test-only graph is retained in each test project's `packages.lock.json` |

Producer tools used to capture committed fixtures, Microsoft SARIF Multitool used as an external
validation baseline, and commit-pinned GitHub Actions are also not release-asset contents. Their
provenance remains documented with the corresponding validation evidence and workflows, rather
than being represented as software redistributed by SarifRegress.
