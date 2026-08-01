#!/usr/bin/env bash
set -euo pipefail

evaluation_mode='strict'
if (($# > 1)); then
  echo \
    "Usage: $0 [--generate-cross-platform-attestation-candidate|--regenerate-attested-expected]" \
    >&2
  exit 1
fi
if (($# == 1)); then
  case "$1" in
    --generate-cross-platform-attestation-candidate)
      evaluation_mode='bootstrap'
      ;;
    --regenerate-attested-expected)
      evaluation_mode='regenerate'
      ;;
    *)
      echo "Unknown option '$1'." >&2
      exit 1
      ;;
  esac
fi
readonly evaluation_mode

readonly script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly repository_root="$(cd -- "${script_directory}/.." && pwd)"
readonly validation_project="${repository_root}/validation/tools/SarifRegress.Validation/SarifRegress.Validation.csproj"
readonly capture_tools_root="${repository_root}/validation/tools/capture"
readonly expected_root="${repository_root}/validation/expected"
readonly cross_platform_attestation="${repository_root}/validation/holdout/cross-platform-attestation.json"
readonly artifact_parent="${repository_root}/artifacts"
readonly artifact_root="${repository_root}/artifacts/holdout-validation"
readonly local_only_nuget_config="${repository_root}/validation/tools/NuGet.LocalOnly.config"
readonly multitool_package_id="Sarif.Multitool"
readonly multitool_version="5.5.0"
readonly multitool_runtime_version="8.0.29"
readonly multitool_package_url="https://api.nuget.org/v3-flatcontainer/sarif.multitool/5.5.0/sarif.multitool.5.5.0.nupkg"
readonly multitool_package_sha256="2d2c73cc1fa4b79e5a41bded05d94dd645fa61d003492054260d7e106e838149"
readonly multitool_package_size_bytes="33705414"

cd -- "${repository_root}"

assert_real_directory_or_missing() {
  local path="$1"
  if [[ -L "${path}" ]]; then
    echo "Refusing to use reparseable artifact path '${path}'." >&2
    exit 1
  fi
  if [[ -e "${path}" && ! -d "${path}" ]]; then
    echo "Artifact path '${path}' exists but is not a directory." >&2
    exit 1
  fi
}

assert_real_directory_or_missing "${artifact_parent}"
mkdir -p -- "${artifact_parent}"
assert_real_directory_or_missing "${artifact_parent}"
assert_real_directory_or_missing "${artifact_root}"
mkdir -- "${artifact_root}" 2>/dev/null || [[ -d "${artifact_root}" ]]
assert_real_directory_or_missing "${artifact_root}"
find "${artifact_root}" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +

temporary_parent="${TMPDIR:-/tmp}"
if [[ ! -d "${temporary_parent}" || -L "${temporary_parent}" ]]; then
  temporary_parent="${artifact_parent}"
fi
readonly temporary_parent
working_root="$(mktemp -d "${temporary_parent%/}/sarif-regress-holdout.XXXXXXXX")"
readonly working_root

cleanup() {
  local exit_code=$?
  trap - EXIT
  if [[ -n "${before_snapshot:-}" && -f "${before_snapshot}" ]]; then
    local final_snapshot="${working_root}/holdout-final.sha256"
    if ! snapshot_holdout "${final_snapshot}" \
        || ! cmp --silent -- "${before_snapshot}" "${final_snapshot}"; then
      echo "Holdout validation modified one or more committed fixture files." >&2
      if [[ -f "${final_snapshot}" ]]; then
        diff --unified -- "${before_snapshot}" "${final_snapshot}" >&2 || true
      fi
      exit_code=1
    fi
  fi
  if [[ -d "${working_root}" ]]; then
    rm -rf -- "${working_root}"
  fi
  exit "${exit_code}"
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
readonly isolated_nuget_packages="${working_root}/nuget-packages"
readonly isolated_dotnet_home="${working_root}/dotnet-home"
readonly isolated_http_cache="${working_root}/nuget-http-cache"
mkdir -p \
  "${local_feed}" \
  "${tool_directory}" \
  "${isolated_nuget_packages}" \
  "${isolated_dotnet_home}" \
  "${isolated_http_cache}"
cp -- "${package_path}" "${local_feed}/"
NUGET_PACKAGES="${isolated_nuget_packages}" \
DOTNET_CLI_HOME="${isolated_dotnet_home}" \
NUGET_HTTP_CACHE_PATH="${isolated_http_cache}" \
  dotnet tool install \
  --tool-path "${tool_directory}" \
  --configfile "${local_only_nuget_config}" \
  --add-source "${local_feed}" \
  --no-cache \
  "${multitool_package_id}" \
  --version "${multitool_version}"

mapfile -d '' installed_package_files < <(
  find "${tool_directory}/.store" \
    -type f \
    -iname 'sarif.multitool.*.nupkg' \
    -print0
)
if ((${#installed_package_files[@]} != 1)); then
  echo "Expected exactly one retained installed ${multitool_package_id} package." >&2
  exit 1
fi
if ! cmp --silent -- "${package_path}" "${installed_package_files[0]}"; then
  echo "The installed ${multitool_package_id} package bytes differ from the verified download." >&2
  exit 1
fi

readonly multitool_path="${tool_directory}/sarif"
if [[ ! -x "${multitool_path}" ]]; then
  echo "The verified Multitool installation did not produce '${multitool_path}'." >&2
  exit 1
fi

NUGET_PACKAGES="${isolated_nuget_packages}" \
DOTNET_CLI_HOME="${isolated_dotnet_home}" \
NUGET_HTTP_CACHE_PATH="${isolated_http_cache}" \
  dotnet restore "${validation_project}" --locked-mode
dotnet build \
  "${validation_project}" \
  --configuration Release \
  --no-restore \
  --warnaserror

readonly generated_root="${working_root}/generated"
mkdir -- "${generated_root}"
evaluation_arguments=(
  evaluate
  --repository-root "${repository_root}"
  --output-root "${generated_root}"
  --multitool-path "${multitool_path}"
  --multitool-version "${multitool_version}"
)
case "${evaluation_mode}" in
  bootstrap)
    evaluation_arguments+=(--compare-expected false)
    ;;
  regenerate)
    evaluation_arguments+=(
      --compare-expected false
      --cross-platform-attestation "${cross_platform_attestation}"
    )
    ;;
  strict)
    evaluation_arguments+=(
      --expected-root "${expected_root}"
      --compare-expected true
      --cross-platform-attestation "${cross_platform_attestation}"
    )
    ;;
esac
set +e
dotnet run \
  --project "${validation_project}" \
  --configuration Release \
  --no-build \
  --no-restore \
  -- \
  "${evaluation_arguments[@]}"
evaluation_exit_code=$?
readonly evaluation_exit_code
set -e

snapshot_holdout "${after_snapshot}"
if ! cmp --silent -- "${before_snapshot}" "${after_snapshot}"; then
  echo "Holdout validation modified one or more committed fixture files." >&2
  diff --unified -- "${before_snapshot}" "${after_snapshot}" >&2 || true
  exit 1
fi

readonly normalized_reports=(
  'sarif-regress-holdout.json'
  'sarif-multitool-baseline.json'
  'v3-to-v3.1-delta.json'
  'comparison-summary.json'
  'checksums.sha256'
)
missing_evidence=0
for report_name in "${normalized_reports[@]}"; do
  if [[ ! -f "${generated_root}/${report_name}" ]]; then
    echo "Validation did not produce '${report_name}'." >&2
    missing_evidence=1
  else
    cp -- "${generated_root}/${report_name}" "${artifact_root}/${report_name}"
  fi
done
if [[ ! -d "${generated_root}/raw" ]]; then
  echo "Validation did not preserve raw Multitool output under output-root/raw." >&2
  missing_evidence=1
else
  cp -R -- "${generated_root}/raw" "${artifact_root}/raw"
fi

if ((missing_evidence != 0)); then
  exit 1
fi
if [[ "${evaluation_mode}" == 'bootstrap' ]]; then
  if ((evaluation_exit_code != 2)); then
    echo \
      "Unattested candidate generation expected validation exit code 2, got ${evaluation_exit_code}." \
      >&2
    exit 1
  fi
  python3 -B - "${generated_root}/comparison-summary.json" <<'PY'
import json
import pathlib
import sys

summary = json.loads(pathlib.Path(sys.argv[1]).read_bytes())
conditions = summary.get("releaseConditions", {})
reasons = summary.get("recommendationReasons", [])
if conditions.get("evaluationCompleted") is not True:
    raise SystemExit("Unattested evaluation did not complete successfully.")
if conditions.get("noStructuralFailures") is not True:
    raise SystemExit("Unattested evaluation contains a structural failure.")
if conditions.get("everyChangedDecisionExplained") is not True:
    raise SystemExit("Unattested evaluation lacks a changed-decision trace.")
if conditions.get("crossPlatformByteIdentity") is not False:
    raise SystemExit("Unattested evaluation unexpectedly asserts byte identity.")
if summary.get("releaseRecommendation") != "blocked":
    raise SystemExit("Unattested evaluation must retain a blocked recommendation.")
if "cross-platform-determinism-failed" not in reasons:
    raise SystemExit("Unattested evaluation omitted the determinism blocker.")
PY
elif ((evaluation_exit_code != 0)); then
  echo \
    "Holdout evaluation failed with exit code ${evaluation_exit_code}; available evidence was preserved at ${artifact_root}." \
    >&2
  exit "${evaluation_exit_code}"
fi

if [[ "${evaluation_mode}" == 'bootstrap' ]]; then
  echo "Generated unattested normalized reports for a hosted attestation candidate."
elif [[ "${evaluation_mode}" == 'regenerate' ]]; then
  python3 -B - "${generated_root}/comparison-summary.json" <<'PY'
import json
import pathlib
import sys

summary = json.loads(pathlib.Path(sys.argv[1]).read_bytes())
conditions = summary.get("releaseConditions", {})
if conditions.get("evaluationCompleted") is not True:
    raise SystemExit("Attested expected-output regeneration did not complete.")
if conditions.get("noStructuralFailures") is not True:
    raise SystemExit("Attested expected-output regeneration has a structural failure.")
if conditions.get("everyChangedDecisionExplained") is not True:
    raise SystemExit("Attested expected-output regeneration lacks decision traces.")
if conditions.get("crossPlatformByteIdentity") is not True:
    raise SystemExit("Attested expected-output regeneration lacks validated byte identity.")
PY
  echo "Regenerated attested normalized reports without comparing stale expected bytes."
else
  echo "Holdout validation reproduced all committed normalized reports byte-for-byte."
fi
echo "Evidence: ${artifact_root}"
