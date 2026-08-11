#!/usr/bin/env bash
set -euo pipefail

script_directory="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repository_root="$(cd -P -- "${script_directory}/.." && pwd -P)"
cli_project="${repository_root}/src/SarifRegress.Cli/SarifRegress.Cli.csproj"
artifact_directory="${repository_root}/artifacts"
package_directory="${artifact_directory}/packages"
publish_directory="${artifact_directory}/publish"
release_directory="${artifact_directory}/release"
notice_directory="${repository_root}/notices"
notice_checksum_manifest="${notice_directory}/checksums.sha256"
project_license="${repository_root}/LICENSE"
third_party_notices="${repository_root}/THIRD_PARTY_NOTICES.md"
readonly audited_runtime_framework_version="10.0.10"

readonly -a release_notice_names=(
    "DOTNET_RUNTIME_LICENSE.txt"
    "DOTNET_RUNTIME_THIRD_PARTY_NOTICES.txt"
    "LICENSE"
    "SYSTEM_COMMANDLINE_LICENSE.md"
    "THIRD_PARTY_NOTICES.md"
)

assert_physical_directory() {
    local path="$1"
    local expected_path="$2"
    local resolved_path

    if [[ -L "${path}" ]]; then
        echo "Refusing to use linked packaging path '${path}'." >&2
        exit 1
    fi
    if [[ ! -d "${path}" ]]; then
        echo "Packaging path '${path}' exists but is not a directory." >&2
        exit 1
    fi

    resolved_path="$(realpath -e -- "${path}")"
    if [[ "${resolved_path}" != "${expected_path}" ]]; then
        echo \
            "Packaging path '${path}' resolves outside its expected repository location." \
            >&2
        exit 1
    fi
}

reset_managed_packaging_directory() {
    local path="$1"
    local expected_leaf_name="$2"
    local expected_path="${artifact_directory}/${expected_leaf_name}"
    local linked_descendant

    if [[ "${path}" != "${expected_path}" ]]; then
        echo "Refusing to clean unexpected packaging path '${path}'." >&2
        exit 1
    fi

    if [[ -e "${path}" || -L "${path}" ]]; then
        assert_physical_directory "${path}" "${expected_path}"
        if ! linked_descendant="$(
            find -P "${path}" -mindepth 1 -type l -print -quit
        )"; then
            echo "Could not inspect packaging path '${path}' before cleanup." >&2
            exit 1
        fi
        if [[ -n "${linked_descendant}" ]]; then
            echo \
                "Refusing to recursively clean linked path '${linked_descendant}'." \
                >&2
            exit 1
        fi
        rm -rf -- "${path}"
    fi

    mkdir -- "${path}"
    assert_physical_directory "${path}" "${expected_path}"
}

reset_managed_packaging_directories() {
    local expected_artifact_directory="${repository_root}/artifacts"

    if [[ "${artifact_directory}" != "${expected_artifact_directory}" ]]; then
        echo "The packaging artifact directory is outside the repository." >&2
        exit 1
    fi

    if [[ -e "${artifact_directory}" || -L "${artifact_directory}" ]]; then
        assert_physical_directory \
            "${artifact_directory}" \
            "${expected_artifact_directory}"
    else
        mkdir -- "${artifact_directory}"
        assert_physical_directory \
            "${artifact_directory}" \
            "${expected_artifact_directory}"
    fi

    reset_managed_packaging_directory "${package_directory}" "packages"
    reset_managed_packaging_directory "${publish_directory}" "publish"
    reset_managed_packaging_directory "${release_directory}" "release"
}

verify_upstream_notice_bytes() {
    (
        cd -- "${notice_directory}"
        LC_ALL=C sha256sum --check --strict "${notice_checksum_manifest}"
    )
}

verify_audited_runtime_version() {
    local runtime_framework_version

    runtime_framework_version="$(
        dotnet msbuild \
            "${cli_project}" \
            -nologo \
            -getProperty:RuntimeFrameworkVersion \
            -property:SelfContained=true \
            -verbosity:quiet
    )"
    if [[ "${runtime_framework_version}" != "${audited_runtime_framework_version}" ]]; then
        echo \
            "RuntimeFrameworkVersion ${runtime_framework_version} does not match audited notices for ${audited_runtime_framework_version}." \
            >&2
        exit 1
    fi
}

copy_release_notices() {
    cp -- "${project_license}" "${release_directory}/LICENSE"
    cp -- "${third_party_notices}" "${release_directory}/THIRD_PARTY_NOTICES.md"
    cp -- \
        "${notice_directory}/DOTNET_RUNTIME_LICENSE.txt" \
        "${release_directory}/DOTNET_RUNTIME_LICENSE.txt"
    cp -- \
        "${notice_directory}/DOTNET_RUNTIME_THIRD_PARTY_NOTICES.txt" \
        "${release_directory}/DOTNET_RUNTIME_THIRD_PARTY_NOTICES.txt"
    cp -- \
        "${notice_directory}/SYSTEM_COMMANDLINE_LICENSE.md" \
        "${release_directory}/SYSTEM_COMMANDLINE_LICENSE.md"
}

assert_file_bytes_equal() {
    local expected_path="$1"
    local actual_path="$2"

    if ! cmp --silent -- "${expected_path}" "${actual_path}"; then
        echo "Packaged file differs from its audited source: ${actual_path}" >&2
        exit 1
    fi
}

assert_archive_entry_equals_file() {
    local archive_path="$1"
    local entry_name="$2"
    local expected_path="$3"

    if ! unzip -p "${archive_path}" "${entry_name}" |
        cmp --silent -- "${expected_path}" -; then
        echo "Package entry is missing or differs from its audited source: ${entry_name}" >&2
        exit 1
    fi
}

verify_packaged_notice_bytes() {
    local package_path="$1"
    local notice_name

    assert_archive_entry_equals_file "${package_path}" "LICENSE" "${project_license}"
    assert_archive_entry_equals_file \
        "${package_path}" \
        "THIRD_PARTY_NOTICES.md" \
        "${third_party_notices}"
    assert_archive_entry_equals_file \
        "${package_path}" \
        "notices/SYSTEM_COMMANDLINE_LICENSE.md" \
        "${notice_directory}/SYSTEM_COMMANDLINE_LICENSE.md"

    for notice_name in "${release_notice_names[@]}"; do
        case "${notice_name}" in
            LICENSE)
                assert_file_bytes_equal \
                    "${project_license}" \
                    "${release_directory}/${notice_name}"
                ;;
            THIRD_PARTY_NOTICES.md)
                assert_file_bytes_equal \
                    "${third_party_notices}" \
                    "${release_directory}/${notice_name}"
                ;;
            *)
                assert_file_bytes_equal \
                    "${notice_directory}/${notice_name}" \
                    "${release_directory}/${notice_name}"
                ;;
        esac
    done
}

write_release_checksum_manifest() {
    local -a release_files

    mapfile -d '' release_files < <(
        find "${release_directory}" \
            -maxdepth 1 \
            -type f \
            ! -name 'checksums.sha256' \
            -printf '%f\0' |
            LC_ALL=C sort -z
    )

    if (( ${#release_files[@]} == 0 )); then
        echo "No release files were available to checksum." >&2
        exit 1
    fi

    (
        cd -- "${release_directory}"
        LC_ALL=C sha256sum "${release_files[@]}" > checksums.sha256
    )
}

verify_upstream_notice_bytes
verify_audited_runtime_version
reset_managed_packaging_directories
"${script_directory}/build.sh"

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
copy_release_notices
verify_packaged_notice_bytes "${package_files[0]}"

write_release_checksum_manifest
