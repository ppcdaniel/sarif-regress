#!/usr/bin/env bash
set -euo pipefail

readonly script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly repository_root="$(cd -- "${script_directory}/.." && pwd)"
readonly validation_project="${repository_root}/validation/tools/SarifRegress.Validation/SarifRegress.Validation.csproj"
readonly capture_tools_root="${repository_root}/validation/tools/capture"
readonly expected_root="${repository_root}/validation/expected"
readonly artifact_root="${repository_root}/artifacts/holdout-validation"
readonly local_only_nuget_config="${repository_root}/validation/tools/NuGet.LocalOnly.config"
readonly multitool_package_id="Sarif.Multitool"
readonly multitool_version="5.5.0"
readonly multitool_runtime_version="8.0.29"
readonly multitool_package_url="https://api.nuget.org/v3-flatcontainer/sarif.multitool/5.5.0/sarif.multitool.5.5.0.nupkg"
readonly multitool_package_sha256="2d2c73cc1fa4b79e5a41bded05d94dd645fa61d003492054260d7e106e838149"
readonly multitool_package_size_bytes="33705414"

working_root="$(mktemp -d "${TMPDIR:-/tmp}/sarif-regress-holdout.XXXXXXXX")"
readonly working_root

cleanup() {
  if [[ -d "${working_root}" ]]; then
    rm -rf -- "${working_root}"
  fi
}
trap cleanup EXIT

snapshot_holdout() {
  local destination="$1"
  (
    cd -- "${repository_root}"
    find validation/holdout -type f -print0 \
      | LC_ALL=C sort -z \
      | xargs -0 sha256sum
  ) > "${destination}"
}

require_command() {
  local command_name="$1"
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    echo "Required command '${command_name}' was not found on PATH." >&2
    exit 1
  fi
}

for command_name in cmp curl cut diff dotnet find grep python3 sha256sum sort stat xargs; do
  require_command "${command_name}"
done

if ! dotnet --list-runtimes \
  | grep -Fq "Microsoft.NETCore.App ${multitool_runtime_version} "; then
  echo \
    "Microsoft.NETCore.App ${multitool_runtime_version} is required by ${multitool_package_id} ${multitool_version}." \
    >&2
  exit 1
fi

readonly before_snapshot="${working_root}/holdout-before.sha256"
readonly after_snapshot="${working_root}/holdout-after.sha256"
snapshot_holdout "${before_snapshot}"

python3 -B "${capture_tools_root}/verify_capture_provenance.py" \
  --repository-root "${repository_root}"
python3 -B "${capture_tools_root}/verify_source_transformations.py" \
  --repository-root "${repository_root}"
python3 -B "${capture_tools_root}/verify_projected_holdout.py" \
  --repository-root "${repository_root}" \
  --output-root "${working_root}/projection-reproduction"
python3 -B "${capture_tools_root}/test_capture_tools.py"

readonly package_path="${working_root}/sarif.multitool.${multitool_version}.nupkg"
curl \
  --proto '=https' \
  --tlsv1.2 \
  --fail \
  --location \
  --silent \
  --show-error \
  --output "${package_path}" \
  "${multitool_package_url}"

actual_package_size="$(stat -c '%s' "${package_path}")"
readonly actual_package_size
if [[ "${actual_package_size}" != "${multitool_package_size_bytes}" ]]; then
  echo \
    "${multitool_package_id} package size mismatch: expected ${multitool_package_size_bytes}, got ${actual_package_size}." \
    >&2
  exit 1
fi

actual_package_sha256="$(sha256sum "${package_path}" | cut -d ' ' -f 1)"
readonly actual_package_sha256
if [[ "${actual_package_sha256}" != "${multitool_package_sha256}" ]]; then
  echo \
    "${multitool_package_id} package checksum mismatch: expected ${multitool_package_sha256}, got ${actual_package_sha256}." \
    >&2
  exit 1
fi

dotnet nuget verify --all "${package_path}"

readonly local_feed="${working_root}/feed"
readonly tool_directory="${working_root}/tool"
mkdir -p "${local_feed}" "${tool_directory}"
cp -- "${package_path}" "${local_feed}/"
dotnet tool install \
  --tool-path "${tool_directory}" \
  --configfile "${local_only_nuget_config}" \
  --add-source "${local_feed}" \
  --no-cache \
  "${multitool_package_id}" \
  --version "${multitool_version}"

readonly multitool_path="${tool_directory}/sarif"
if [[ ! -x "${multitool_path}" ]]; then
  echo "The verified Multitool installation did not produce '${multitool_path}'." >&2
  exit 1
fi

dotnet restore "${validation_project}" --locked-mode
dotnet build \
  "${validation_project}" \
  --configuration Release \
  --no-restore \
  --warnaserror

readonly generated_root="${working_root}/generated"
dotnet run \
  --project "${validation_project}" \
  --configuration Release \
  --no-build \
  --no-restore \
  -- \
  evaluate \
  --repository-root "${repository_root}" \
  --output-root "${generated_root}" \
  --expected-root "${expected_root}" \
  --multitool-path "${multitool_path}" \
  --multitool-version "${multitool_version}" \
  --compare-expected true \
  --cross-platform-byte-identity true

snapshot_holdout "${after_snapshot}"
if ! cmp --silent -- "${before_snapshot}" "${after_snapshot}"; then
  echo "Holdout validation modified one or more committed fixture files." >&2
  diff --unified -- "${before_snapshot}" "${after_snapshot}" >&2 || true
  exit 1
fi

readonly normalized_reports=(
  'sarif-regress-holdout.json'
  'sarif-multitool-baseline.json'
  'comparison-summary.json'
  'checksums.sha256'
)
for report_name in "${normalized_reports[@]}"; do
  if [[ ! -f "${generated_root}/${report_name}" ]]; then
    echo "Validation did not produce '${report_name}'." >&2
    exit 1
  fi
done
if [[ ! -d "${generated_root}/raw" ]]; then
  echo "Validation did not preserve raw Multitool output under output-root/raw." >&2
  exit 1
fi

mkdir -p "${artifact_root}"
find "${artifact_root}" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
for report_name in "${normalized_reports[@]}"; do
  cp -- "${generated_root}/${report_name}" "${artifact_root}/${report_name}"
done
cp -R -- "${generated_root}/raw" "${artifact_root}/raw"

echo "Holdout validation reproduced all committed normalized reports byte-for-byte."
echo "Evidence: ${artifact_root}"
