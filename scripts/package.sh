#!/usr/bin/env bash
set -euo pipefail

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd -- "${script_directory}/.." && pwd)"
cli_project="${repository_root}/src/SarifRegress.Cli/SarifRegress.Cli.csproj"
artifact_directory="${repository_root}/artifacts"
package_directory="${artifact_directory}/packages"
publish_directory="${artifact_directory}/publish"
release_directory="${artifact_directory}/release"

"${script_directory}/build.sh"

rm -rf -- "${package_directory}" "${publish_directory}" "${release_directory}"
mkdir -p -- "${package_directory}" "${publish_directory}" "${release_directory}"

# The .NET tool is portable; the project RID graph exists for the standalone binaries.
dotnet pack \
    "${cli_project}" \
    --configuration Release \
    --no-build \
    --no-restore \
    --output "${package_directory}" \
    -p:RuntimeIdentifiers=

for runtime_identifier in linux-x64 win-x64; do
    runtime_output="${publish_directory}/${runtime_identifier}"
    dotnet publish \
        "${cli_project}" \
        --configuration Release \
        --runtime "${runtime_identifier}" \
        --self-contained true \
        --no-restore \
        --output "${runtime_output}" \
        -p:PublishSingleFile=true \
        -p:IncludeNativeLibrariesForSelfExtract=true \
        -p:PublishTrimmed=false \
        -p:PublishReadyToRun=false \
        -p:DebugSymbols=false \
        -p:DebugType=None
done

shopt -s nullglob
package_files=("${package_directory}"/*.nupkg)
if (( ${#package_files[@]} != 1 )); then
    echo "Expected exactly one .NET tool package, found ${#package_files[@]}." >&2
    exit 1
fi

linux_binary="${publish_directory}/linux-x64/sarif-regress"
windows_binary="${publish_directory}/win-x64/sarif-regress.exe"
if [[ ! -f "${linux_binary}" || ! -f "${windows_binary}" ]]; then
    echo "Expected single-file Linux and Windows binaries were not produced." >&2
    exit 1
fi

cp -- "${package_files[0]}" "${release_directory}/"
cp -- "${linux_binary}" "${release_directory}/sarif-regress-linux-x64"
cp -- "${windows_binary}" "${release_directory}/sarif-regress-win-x64.exe"
chmod 755 "${release_directory}/sarif-regress-linux-x64"

(
    cd "${release_directory}"
    LC_ALL=C sha256sum \
        ./*.nupkg \
        ./sarif-regress-linux-x64 \
        ./sarif-regress-win-x64.exe |
        sed 's#  \\./#  #' > checksums.sha256
)
