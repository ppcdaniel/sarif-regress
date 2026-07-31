#!/usr/bin/env bash

set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

readonly CAPTURE_SCRIPT_DIRECTORY="$(
  cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1
  pwd -P
)"
readonly REPOSITORY_ROOT="$(
  cd -- "${CAPTURE_SCRIPT_DIRECTORY}/../../.." >/dev/null 2>&1
  pwd -P
)"
readonly HOLDOUT_CASES_ROOT="${REPOSITORY_ROOT}/validation/holdout/cases"
readonly PROJECTION_SCRIPT="${CAPTURE_SCRIPT_DIRECTORY}/project_holdout.py"
readonly ZIP_EXTRACTOR="${CAPTURE_SCRIPT_DIRECTORY}/extract_zip.py"
readonly TRANSFORMATION_VERIFIER="${CAPTURE_SCRIPT_DIRECTORY}/verify_source_transformations.py"
readonly SEMGREP_REQUIREMENTS_LOCK="${CAPTURE_SCRIPT_DIRECTORY}/semgrep-requirements.linux-x86_64-py312.lock"

readonly SEMGREP_VERSION="1.172.0"
readonly SEMGREP_WHEEL_NAME="semgrep-1.172.0-cp310.cp311.cp312.cp313.cp314.py310.py311.py312.py313.py314-none-manylinux_2_34_x86_64.whl"
readonly SEMGREP_WHEEL_URL="https://files.pythonhosted.org/packages/84/a5/21624510b65271a673961a894af7511b5123d662e84c74c765560ea28b27/${SEMGREP_WHEEL_NAME}"
readonly SEMGREP_WHEEL_SHA256="d8b94af4266a575287ad2cd844573743ab4fe58f6bfb6d9229327807937eade3"
readonly SEMGREP_WHEEL_BYTES="69575334"

readonly GITLEAKS_VERSION="8.30.1"
readonly GITLEAKS_ARCHIVE_NAME="gitleaks_8.30.1_linux_x64.tar.gz"
readonly GITLEAKS_ARCHIVE_URL="https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/${GITLEAKS_ARCHIVE_NAME}"
readonly GITLEAKS_ARCHIVE_SHA256="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"
readonly GITLEAKS_ARCHIVE_BYTES="8230402"
readonly GITLEAKS_CHECKSUMS_NAME="gitleaks_8.30.1_checksums.txt"
readonly GITLEAKS_CHECKSUMS_URL="https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/${GITLEAKS_CHECKSUMS_NAME}"
readonly GITLEAKS_CHECKSUMS_SHA256="061476c21adaf5441516f96f185c1a4706a83cd6329b9b38762271b3d4a52fae"
readonly GITLEAKS_CHECKSUMS_BYTES="999"

readonly PMD_VERSION="7.26.0"
readonly PMD_ARCHIVE_NAME="pmd-dist-7.26.0-bin.zip"
readonly PMD_ARCHIVE_URL="https://github.com/pmd/pmd/releases/download/pmd_releases/7.26.0/${PMD_ARCHIVE_NAME}"
readonly PMD_ARCHIVE_SHA256="9f55cb7ff0e9f9a66dd2f005eaa370e84c8a4cd971b134aa14a930c4a283ebc9"
readonly PMD_ARCHIVE_BYTES="73646044"
readonly PMD_ARCHIVE_PREFIX="pmd-bin-7.26.0"

readonly MAX_CAPTURE_BYTES=$((16 * 1024 * 1024))
TEMPORARY_ROOT=""

usage() {
  cat <<'EOF'
Usage: capture-holdout.sh --output-root PATH [--producer all|semgrep|gitleaks|pmd]

Captures authentic SARIF into a new staging directory and projects deterministic
case files there. The script never edits committed holdout fixtures.
EOF
}

fail() {
  echo "holdout capture failed: $*" >&2
  exit 1
}

cleanup() {
  ((BASH_SUBSHELL == 0)) || return 0
  if [[ -n "${TEMPORARY_ROOT:-}" && -d "${TEMPORARY_ROOT}" ]]; then
    rm -rf -- "${TEMPORARY_ROOT}"
  fi
}

require_command() {
  local command_name="$1"
  command -v -- "${command_name}" >/dev/null 2>&1 ||
    fail "required command '${command_name}' is unavailable."
}

download_verified() {
  local source_url="$1"
  local expected_sha256="$2"
  local expected_bytes="$3"
  local destination="$4"

  curl \
    --fail \
    --location \
    --proto '=https' \
    --retry 3 \
    --retry-all-errors \
    --show-error \
    --silent \
    --tlsv1.2 \
    --output "${destination}" \
    "${source_url}"
  local actual_bytes
  actual_bytes="$(stat --format='%s' -- "${destination}")"
  [[ "${actual_bytes}" == "${expected_bytes}" ]] ||
    fail "size mismatch for ${source_url}: expected ${expected_bytes}, got ${actual_bytes}."
  local actual_sha256
  actual_sha256="$(sha256sum -- "${destination}" | cut -d ' ' -f 1)"
  [[ "${actual_sha256}" == "${expected_sha256}" ]] ||
    fail "SHA-256 mismatch for ${source_url}: expected ${expected_sha256}, got ${actual_sha256}."
}

assert_regular_bounded_capture() {
  local capture_path="$1"
  [[ -f "${capture_path}" && ! -L "${capture_path}" ]] ||
    fail "producer did not create a regular capture at ${capture_path}."
  local capture_bytes
  capture_bytes="$(stat --format='%s' -- "${capture_path}")"
  ((capture_bytes > 0 && capture_bytes <= MAX_CAPTURE_BYTES)) ||
    fail "${capture_path} has disallowed size ${capture_bytes} bytes."
}

prepare_semgrep() {
  local tools_root="$1"
  local wheelhouse="${tools_root}/semgrep-wheelhouse"
  local environment_root="${tools_root}/semgrep-environment"
  mkdir -p -- "${wheelhouse}"

  python3 -B - <<'PY'
import platform
import sys

if sys.version_info[:2] != (3, 12):
    raise SystemExit(
        f"Semgrep capture requires Python 3.12; found {sys.version.split()[0]}."
    )
if platform.system() != "Linux" or platform.machine() not in {"x86_64", "AMD64"}:
    raise SystemExit(
        "Semgrep capture lock is valid only for Linux x86-64."
    )
PY

  download_verified \
    "${SEMGREP_WHEEL_URL}" \
    "${SEMGREP_WHEEL_SHA256}" \
    "${SEMGREP_WHEEL_BYTES}" \
    "${wheelhouse}/${SEMGREP_WHEEL_NAME}"

  python3 -m venv "${environment_root}"
  "${environment_root}/bin/python" -m pip download \
    --disable-pip-version-check \
    --dest "${wheelhouse}" \
    --only-binary=:all: \
    --quiet \
    --require-hashes \
    --requirement "${SEMGREP_REQUIREMENTS_LOCK}"
  "${environment_root}/bin/python" -m pip install \
    --disable-pip-version-check \
    --no-index \
    --find-links "${wheelhouse}" \
    --only-binary=:all: \
    --quiet \
    --require-hashes \
    --requirement "${SEMGREP_REQUIREMENTS_LOCK}"

  # pip preserves the verified wheel bytes but this capture environment can
  # discard executable mode from native files embedded in a wheel. Restore the
  # mode only for Semgrep's two documented native launcher names, after
  # rejecting links and non-regular files.
  local native_name
  local native_path
  local native_count=0
  for native_name in osemgrep semgrep-core; do
    native_path="${environment_root}/lib/python3.12/site-packages/semgrep/bin/${native_name}"
    if [[ -e "${native_path}" ]]; then
      [[ -f "${native_path}" && ! -L "${native_path}" ]] ||
        fail "the verified Semgrep wheel installed an unsafe ${native_name} path."
      chmod 0755 -- "${native_path}"
      native_count=$((native_count + 1))
    fi
  done
  ((native_count > 0)) ||
    fail "the verified Semgrep wheel lacks its expected native executable."

  local observed_version
  local semgrep_vendor_library_path
  semgrep_vendor_library_path="${environment_root}/lib/python3.12/site-packages/semgrep/bin/libs"
  local semgrep_tree_sitter_path="${semgrep_vendor_library_path}/libtree-sitter.so.0.22"
  [[ -f "${semgrep_tree_sitter_path}" && ! -L "${semgrep_tree_sitter_path}" ]] ||
    fail "the verified Semgrep wheel lacks its expected tree-sitter library."
  local semgrep_runtime_library_path="${environment_root}/holdout-runtime-libs"
  mkdir -- "${semgrep_runtime_library_path}"
  cp -- "${semgrep_tree_sitter_path}" "${semgrep_runtime_library_path}/"
  chmod 0644 -- "${semgrep_runtime_library_path}/libtree-sitter.so.0.22"
  observed_version="$(
    SEMGREP_SEND_METRICS=off \
      LD_LIBRARY_PATH="${semgrep_runtime_library_path}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}" \
      "${environment_root}/bin/semgrep" --version
  )"
  [[ "${observed_version}" == "${SEMGREP_VERSION}" ]] ||
    fail "expected Semgrep ${SEMGREP_VERSION}, found ${observed_version}."
  printf '%s\n' "${environment_root}/bin/semgrep"
}

prepare_gitleaks() {
  local tools_root="$1"
  local archive_path="${tools_root}/${GITLEAKS_ARCHIVE_NAME}"
  local checksums_path="${tools_root}/${GITLEAKS_CHECKSUMS_NAME}"
  local extraction_root="${tools_root}/gitleaks"

  download_verified \
    "${GITLEAKS_CHECKSUMS_URL}" \
    "${GITLEAKS_CHECKSUMS_SHA256}" \
    "${GITLEAKS_CHECKSUMS_BYTES}" \
    "${checksums_path}"
  grep -Fqx \
    "${GITLEAKS_ARCHIVE_SHA256}  ${GITLEAKS_ARCHIVE_NAME}" \
    "${checksums_path}" ||
    fail "official Gitleaks checksum manifest does not pin the selected archive."

  download_verified \
    "${GITLEAKS_ARCHIVE_URL}" \
    "${GITLEAKS_ARCHIVE_SHA256}" \
    "${GITLEAKS_ARCHIVE_BYTES}" \
    "${archive_path}"
  mkdir -- "${extraction_root}"
  tar -tzf "${archive_path}" | grep -Fqx "gitleaks" ||
    fail "Gitleaks archive does not contain the expected executable."
  tar \
    --extract \
    --gzip \
    --file "${archive_path}" \
    --directory "${extraction_root}" \
    --no-same-owner \
    --no-same-permissions \
    -- gitleaks
  [[ -f "${extraction_root}/gitleaks" && ! -L "${extraction_root}/gitleaks" ]] ||
    fail "the extracted Gitleaks executable is not a regular non-link file."
  chmod 0755 -- "${extraction_root}/gitleaks"

  local observed_version
  observed_version="$("${extraction_root}/gitleaks" version)"
  [[ "${observed_version}" == "${GITLEAKS_VERSION}" ]] ||
    fail "expected Gitleaks ${GITLEAKS_VERSION}, found ${observed_version}."
  printf '%s\n' "${extraction_root}/gitleaks"
}

prepare_pmd() {
  local tools_root="$1"
  local archive_path="${tools_root}/${PMD_ARCHIVE_NAME}"
  local extraction_root="${tools_root}/pmd"

  download_verified \
    "${PMD_ARCHIVE_URL}" \
    "${PMD_ARCHIVE_SHA256}" \
    "${PMD_ARCHIVE_BYTES}" \
    "${archive_path}"
  python3 -B "${ZIP_EXTRACTOR}" \
    --archive "${archive_path}" \
    --destination "${extraction_root}" \
    --required-prefix "${PMD_ARCHIVE_PREFIX}"
  local pmd_executable="${extraction_root}/${PMD_ARCHIVE_PREFIX}/bin/pmd"
  chmod 0755 -- "${pmd_executable}"

  local java_executable
  java_executable="$(readlink -f -- "$(command -v -- java)")"
  local java_home
  java_home="$(cd -- "$(dirname -- "${java_executable}")/.." && pwd -P)"
  local java_library_path="${java_home}/lib:${java_home}/lib/server"
  local observed_version
  observed_version="$(
    JAVA_HOME="${java_home}" \
      LD_LIBRARY_PATH="${java_library_path}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}" \
      "${pmd_executable}" --version
  )"
  grep -Fq "PMD ${PMD_VERSION}" <<<"${observed_version}" ||
    fail "expected PMD ${PMD_VERSION}, found ${observed_version}."
  printf '%s\n' "${pmd_executable}"
}

capture_semgrep_side() {
  local semgrep_executable="$1"
  local side="$2"
  local destination="$3"
  local case_root="${HOLDOUT_CASES_ROOT}/semgrep"
  local source_root="${case_root}/producer-input/${side}"
  local semgrep_environment
  semgrep_environment="$(cd -- "$(dirname -- "${semgrep_executable}")/.." && pwd -P)"
  local semgrep_library_path="${semgrep_environment}/holdout-runtime-libs"

  (
    cd -- "${source_root}"
    SEMGREP_SEND_METRICS=off \
      LD_LIBRARY_PATH="${semgrep_library_path}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}" \
      "${semgrep_executable}" scan \
      --config "${case_root}/producer-input/semgrep-rules.yml" \
      --disable-version-check \
      --metrics=off \
      --no-git-ignore \
      --no-rewrite-rule-ids \
      --oss-only \
      --quiet \
      --sarif \
      --strict \
      --output "${destination}" \
      .
  )
  assert_regular_bounded_capture "${destination}"
}

capture_gitleaks_side() {
  local gitleaks_executable="$1"
  local side="$2"
  local destination="$3"
  local case_root="${HOLDOUT_CASES_ROOT}/gitleaks"
  local source_root="${case_root}/producer-input/${side}"

  (
    cd -- "${source_root}"
    "${gitleaks_executable}" dir . \
      --config "${case_root}/producer-input/gitleaks.toml" \
      --exit-code 0 \
      --log-level error \
      --no-banner \
      --no-color \
      --redact=100 \
      --report-format sarif \
      --report-path "${destination}"
  )
  assert_regular_bounded_capture "${destination}"
}

capture_pmd_side() {
  local pmd_executable="$1"
  local side="$2"
  local destination="$3"
  local case_root="${HOLDOUT_CASES_ROOT}/pmd"
  local source_root="${case_root}/producer-input/${side}"
  local java_executable
  java_executable="$(readlink -f -- "$(command -v -- java)")"
  local java_home
  java_home="$(cd -- "$(dirname -- "${java_executable}")/.." && pwd -P)"
  local java_library_path="${java_home}/lib:${java_home}/lib/server"

  (
    cd -- "${source_root}"
    JAVA_HOME="${java_home}" \
      LD_LIBRARY_PATH="${java_library_path}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}" \
      "${pmd_executable}" check \
      --dir . \
      --format sarif \
      --no-cache \
      --no-fail-on-violation \
      --no-progress \
      --relativize-paths-with "${source_root}" \
      --report-file "${destination}" \
      --rulesets "${case_root}/producer-input/pmd-ruleset.xml" \
      --threads 0 \
      --use-version java-17
  )
  assert_regular_bounded_capture "${destination}"
}

capture_and_project() {
  local producer="$1"
  local executable="$2"
  local output_root="$3"
  local output_case_root="${output_root}/${producer}"
  local capture_root="${output_case_root}/producer-input/captures"
  mkdir -p -- "${capture_root}"

  local side
  for side in baseline candidate; do
    "capture_${producer}_side" \
      "${executable}" \
      "${side}" \
      "${capture_root}/${side}.raw.sarif"
  done
  python3 -B "${PROJECTION_SCRIPT}" \
    --case-root "${HOLDOUT_CASES_ROOT}/${producer}" \
    --capture-root "${capture_root}" \
    --output-root "${output_case_root}"
}

main() {
  local output_root=""
  local selected_producer="all"
  while (($# > 0)); do
    case "$1" in
      --output-root)
        (($# >= 2)) || fail "--output-root requires a value."
        output_root="$2"
        shift 2
        ;;
      --producer)
        (($# >= 2)) || fail "--producer requires a value."
        selected_producer="$2"
        shift 2
        ;;
      --help|-h)
        usage
        return 0
        ;;
      *)
        fail "unknown argument: $1"
        ;;
    esac
  done

  [[ -n "${output_root}" ]] || fail "--output-root is required."
  case "${selected_producer}" in
    all|semgrep|gitleaks|pmd) ;;
    *) fail "unsupported producer: ${selected_producer}" ;;
  esac

  require_command curl
  require_command cut
  require_command grep
  require_command python3
  require_command sha256sum
  require_command stat
  require_command tar
  require_command java

  local output_parent
  output_parent="$(dirname -- "${output_root}")"
  mkdir -p -- "${output_parent}"
  output_parent="$(cd -- "${output_parent}" && pwd -P)"
  output_root="${output_parent}/$(basename -- "${output_root}")"
  [[ ! -e "${output_root}" ]] ||
    fail "output root already exists: ${output_root}"
  mkdir -- "${output_root}"

  local temporary_parent
  temporary_parent="$(cd -- "${REPOSITORY_ROOT}/.." && pwd -P)"
  [[ -w "${temporary_parent}" ]] ||
    fail "repository parent is not writable for isolated capture temporary files."
  TEMPORARY_ROOT="$(
    mktemp -d "${temporary_parent}/sarif-regress-holdout-capture.XXXXXX"
  )"
  trap cleanup EXIT
  mkdir -- "${TEMPORARY_ROOT}/tmp"
  export TMPDIR="${TEMPORARY_ROOT}/tmp"
  local tools_root="${TEMPORARY_ROOT}/tools"
  mkdir -- "${tools_root}"

  python3 -B "${TRANSFORMATION_VERIFIER}" \
    --repository-root "${REPOSITORY_ROOT}"

  if [[ "${selected_producer}" == "all" || "${selected_producer}" == "semgrep" ]]; then
    local semgrep_executable
    semgrep_executable="$(prepare_semgrep "${tools_root}")"
    capture_and_project semgrep "${semgrep_executable}" "${output_root}"
  fi
  if [[ "${selected_producer}" == "all" || "${selected_producer}" == "gitleaks" ]]; then
    local gitleaks_executable
    gitleaks_executable="$(prepare_gitleaks "${tools_root}")"
    capture_and_project gitleaks "${gitleaks_executable}" "${output_root}"
  fi
  if [[ "${selected_producer}" == "all" || "${selected_producer}" == "pmd" ]]; then
    local pmd_executable
    pmd_executable="$(prepare_pmd "${tools_root}")"
    capture_and_project pmd "${pmd_executable}" "${output_root}"
  fi

  trap - EXIT
  cleanup
  TEMPORARY_ROOT=""
  echo "Holdout captures and projections written to ${output_root}."
}

main "$@"
