#!/usr/bin/env bash

set -euo pipefail
export LC_ALL=C
export PYTHONDONTWRITEBYTECODE=1
export PYTHONNOUSERSITE=1
export TZ=UTC
unset PYTHONPATH || true
umask 077

readonly SCRIPT_DIRECTORY="$({
  cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1
  pwd -P
})"
readonly RESEARCH_ROOT="$({
  cd -- "${SCRIPT_DIRECTORY}/.." >/dev/null 2>&1
  pwd -P
})"
readonly REPOSITORY_ROOT="$({
  cd -- "${RESEARCH_ROOT}/../../.." >/dev/null 2>&1
  pwd -P
})"
readonly CASES_ROOT="${RESEARCH_ROOT}/cases"
readonly PROJECTOR="${SCRIPT_DIRECTORY}/project_pmd_sarif.py"
readonly VERIFIER="${SCRIPT_DIRECTORY}/verify_pmd_capture.py"
readonly ZIP_EXTRACTOR="${REPOSITORY_ROOT}/validation/tools/capture/extract_zip.py"

readonly PMD_VERSION="7.26.0"
readonly PMD_ARCHIVE_NAME="pmd-dist-7.26.0-bin.zip"
readonly PMD_ARCHIVE_URL="https://github.com/pmd/pmd/releases/download/pmd_releases/7.26.0/${PMD_ARCHIVE_NAME}"
readonly PMD_ARCHIVE_BYTES="73646044"
readonly PMD_ARCHIVE_SHA256="9f55cb7ff0e9f9a66dd2f005eaa370e84c8a4cd971b134aa14a930c4a283ebc9"
readonly PMD_ARCHIVE_PREFIX="pmd-bin-7.26.0"
readonly PMD_HELP_SHA256="babf2b1e17bddd7611cc4882b9686c207e2b73fee3e3053276b3455e6c890b91"
readonly PYTHON_VERSION="3.12.13"
readonly JAVA_DISTRIBUTION="Eclipse Temurin"
readonly JAVA_VENDOR="Eclipse Adoptium"
readonly JAVA_VERSION="17.0.19+10"
readonly RUNNER_LABEL="ubuntu-24.04"
readonly RUNNER_IMAGE_OS="ubuntu24"
readonly RUNNER_IMAGE_VERSION_PATTERN='^[0-9]{8}\.[0-9]+\.[0-9]+$'
readonly PROJECTION_ALGORITHM_VERSION="pmd-file-uri-prefix-projection/v1"
readonly FILE_SIZE_LIMIT_BLOCK_BYTES=1024
readonly DOWNLOAD_FILE_SIZE_BLOCKS=$((
  (PMD_ARCHIVE_BYTES + FILE_SIZE_LIMIT_BLOCK_BYTES - 1) /
    FILE_SIZE_LIMIT_BLOCK_BYTES
))
readonly MAX_CAPTURE_BYTES=$((16 * 1024 * 1024))
readonly -a CAPTURE_COMMAND_TEMPLATE=(
  pmd
  check
  --dir
  .
  --format
  sarif
  --no-cache
  --no-fail-on-violation
  --no-progress
  --relativize-paths-with
  '<side-source-root>'
  --report-file
  '<raw-capture>'
  --rulesets
  '<family-ruleset>'
  --threads
  0
  --use-version
  java-17
)
readonly -a DOWNLOAD_COMMAND_TEMPLATE=(
  curl
  --disable
  --fail
  --location
  --max-filesize
  '<archive-bytes>'
  --proto
  '=https'
  --retry
  3
  --retry-all-errors
  --show-error
  --silent
  --tlsv1.2
  --output
  '<archive-destination>'
  '<archive-url>'
)

TEMPORARY_ROOT=""
TEMPORARY_PARENT=""
CAPTURE_JAVA_HOME=""
CAPTURE_JAVA_LIBRARY_PATH=""
CAPTURE_CONTRACT_SHA256=""

usage() {
  cat <<'EOF'
Usage: capture_pmd.sh --output-root PATH [--source-sha SHA]

Capture authentic PMD 7.26.0 SARIF for every sparse-SARIF research family,
preserve untouched raw bytes, project only ambient file-URI prefixes, and
verify the resulting artifact. The output root must not already exist.
EOF
}

fail() {
  echo "sparse PMD capture failed: $*" >&2
  exit 1
}

require_command() {
  command -v -- "$1" >/dev/null 2>&1 ||
    fail "required command '$1' is unavailable."
}

verify_shell_capture_contract() {
  local -a arguments=(
    python3 -B "${VERIFIER}" verify-contract
    --pmd-version "${PMD_VERSION}"
    --archive-name "${PMD_ARCHIVE_NAME}"
    --archive-url "${PMD_ARCHIVE_URL}"
    --archive-bytes "${PMD_ARCHIVE_BYTES}"
    --archive-sha256 "${PMD_ARCHIVE_SHA256}"
    --archive-prefix "${PMD_ARCHIVE_PREFIX}"
    --help-sha256 "${PMD_HELP_SHA256}"
    --python-version "${PYTHON_VERSION}"
    --java-distribution "${JAVA_DISTRIBUTION}"
    --java-vendor "${JAVA_VENDOR}"
    --java-version "${JAVA_VERSION}"
    --runner-label "${RUNNER_LABEL}"
    --runner-image-os "${RUNNER_IMAGE_OS}"
    --projection-algorithm-version "${PROJECTION_ALGORITHM_VERSION}"
    --download-file-size-blocks "${DOWNLOAD_FILE_SIZE_BLOCKS}"
  )
  local argument
  for argument in "${CAPTURE_COMMAND_TEMPLATE[@]}"; do
    arguments+=("--capture-argument=${argument}")
  done
  for argument in "${DOWNLOAD_COMMAND_TEMPLATE[@]}"; do
    arguments+=("--download-argument=${argument}")
  done
  if ! CAPTURE_CONTRACT_SHA256="$("${arguments[@]}")"; then
    fail "shell constants or command templates differ from the canonical contract."
  fi
  [[ "${CAPTURE_CONTRACT_SHA256}" =~ ^[0-9a-f]{64}$ ]] ||
    fail "canonical capture contract did not produce a SHA-256."
}

cleanup() {
  ((BASH_SUBSHELL == 0)) || return 0
  [[ -n "${TEMPORARY_ROOT:-}" && -n "${TEMPORARY_PARENT:-}" ]] || return 0
  case "${TEMPORARY_ROOT}" in
    "${TEMPORARY_PARENT}"/sarif-regress-sparse-pmd.*)
      [[ -d "${TEMPORARY_ROOT}" && ! -L "${TEMPORARY_ROOT}" ]] &&
        rm -rf -- "${TEMPORARY_ROOT}"
      ;;
    *)
      echo "refusing to remove unexpected temporary root: ${TEMPORARY_ROOT}" >&2
      ;;
  esac
}

verify_host_environment() {
  python3 -B - "${PYTHON_VERSION}" <<'PY'
import platform
import sys

expected = sys.argv[1]
if platform.python_version() != expected:
    raise SystemExit(
        f"capture requires Python {expected}; found {platform.python_version()}"
    )
if platform.system() != "Linux" or platform.machine() not in {"x86_64", "AMD64"}:
    raise SystemExit("capture requires Linux x86-64")
PY

  [[ -r /etc/os-release ]] || fail "cannot identify the capture operating system."
  # shellcheck disable=SC1091
  source /etc/os-release
  [[ "${ID:-}" == "ubuntu" && "${VERSION_ID:-}" == "24.04" ]] ||
    fail "capture requires Ubuntu 24.04."
  [[ "${ImageOS:-}" == "${RUNNER_IMAGE_OS}" &&
    "${ImageVersion:-}" =~ ${RUNNER_IMAGE_VERSION_PATTERN} ]] ||
    fail "hosted runner image evidence is missing or invalid."

  local java_properties
  java_properties="$(java -XshowSettings:properties -version 2>&1)"
  local observed_vendor
  observed_vendor="$(sed -n 's/^[[:space:]]*java.vendor = //p' <<<"${java_properties}")"
  [[ "${observed_vendor}" == "${JAVA_VENDOR}" ]] ||
    fail "capture requires ${JAVA_VENDOR}; found ${observed_vendor}."
  local observed_version
  observed_version="$(sed -n 's/^[[:space:]]*java.runtime.version = //p' <<<"${java_properties}")"
  [[ "${observed_version}" == "${JAVA_VERSION}" ]] ||
    fail "capture requires Java ${JAVA_VERSION}; found ${observed_version}."
  local java_executable
  java_executable="$(readlink -f -- "$(command -v -- java)")"
  [[ -x "${java_executable}" ]] || fail "cannot resolve the verified Java executable."
  CAPTURE_JAVA_HOME="$(cd -- "$(dirname -- "${java_executable}")/.." && pwd -P)"
  CAPTURE_JAVA_LIBRARY_PATH="${CAPTURE_JAVA_HOME}/lib:${CAPTURE_JAVA_HOME}/lib/server"
}

download_verified_archive() {
  local destination="$1"
  [[ ! -e "${destination}" ]] || fail "archive destination already exists."
  local -ar download_arguments=(
    curl
    --disable
    --fail
    --location
    --max-filesize
    "${PMD_ARCHIVE_BYTES}"
    --proto
    '=https'
    --retry
    3
    --retry-all-errors
    --show-error
    --silent
    --tlsv1.2
    --output
    "${destination}"
    "${PMD_ARCHIVE_URL}"
  )
  local -a verifier_arguments=(
    python3 -B "${VERIFIER}" verify-download-command
    --destination "${destination}"
    --file-size-limit-blocks "${DOWNLOAD_FILE_SIZE_BLOCKS}"
  )
  local argument
  for argument in "${download_arguments[@]}"; do
    verifier_arguments+=("--argument=${argument}")
  done
  "${verifier_arguments[@]}"
  (
    # curl enforces the exact response ceiling. The child also inherits an
    # unraisable file-size limit rounded up to Bash's 1024-byte block unit.
    ulimit -S -f "${DOWNLOAD_FILE_SIZE_BLOCKS}"
    ulimit -H -f "${DOWNLOAD_FILE_SIZE_BLOCKS}"
    "${download_arguments[@]}"
  )
  local observed_bytes
  observed_bytes="$(stat --format='%s' -- "${destination}")"
  [[ "${observed_bytes}" == "${PMD_ARCHIVE_BYTES}" ]] ||
    fail "PMD archive size mismatch: ${observed_bytes}."
  local observed_sha256
  observed_sha256="$(sha256sum -- "${destination}" | cut -d ' ' -f 1)"
  [[ "${observed_sha256}" == "${PMD_ARCHIVE_SHA256}" ]] ||
    fail "PMD archive SHA-256 mismatch."
}

prepare_pmd() {
  local tools_root="$1"
  local archive_path="${tools_root}/${PMD_ARCHIVE_NAME}"
  local extraction_root="${tools_root}/pmd"
  download_verified_archive "${archive_path}"
  python3 -I -B "${ZIP_EXTRACTOR}" \
    --archive "${archive_path}" \
    --destination "${extraction_root}" \
    --required-prefix "${PMD_ARCHIVE_PREFIX}"

  local executable="${extraction_root}/${PMD_ARCHIVE_PREFIX}/bin/pmd"
  [[ -f "${executable}" && ! -L "${executable}" ]] ||
    fail "safe PMD extraction did not produce its regular launcher."
  chmod 0755 -- "${executable}"
  local observed_version
  observed_version="$(
    JAVA_HOME="${CAPTURE_JAVA_HOME}" \
      LD_LIBRARY_PATH="${CAPTURE_JAVA_LIBRARY_PATH}" \
      "${executable}" --version
  )"
  grep -Fq "PMD ${PMD_VERSION}" <<<"${observed_version}" ||
    fail "expected PMD ${PMD_VERSION}; found ${observed_version}."
  local help_path="${tools_root}/pmd-check-help.txt"
  JAVA_HOME="${CAPTURE_JAVA_HOME}" \
    LD_LIBRARY_PATH="${CAPTURE_JAVA_LIBRARY_PATH}" \
    "${executable}" check --help >"${help_path}"
  local observed_help_sha256
  observed_help_sha256="$(sha256sum -- "${help_path}" | cut -d ' ' -f 1)"
  [[ "${observed_help_sha256}" == "${PMD_HELP_SHA256}" ]] ||
    fail "PMD check help differs from reviewed provenance."
  printf '%s\n' "${executable}"
}

assert_controlled_source_root() {
  local source_root="$1"
  [[ -d "${source_root}" && ! -L "${source_root}" ]] ||
    fail "source root is missing or unsafe: ${source_root}"
  if find "${source_root}" -type l -print -quit | grep -q .; then
    fail "source root contains a symbolic link: ${source_root}"
  fi
  if find "${source_root}" \! -type f \! -type d -print -quit | grep -q .; then
    fail "source root contains a non-regular entry: ${source_root}"
  fi
  find "${source_root}" -type f -name '*.java' -print -quit | grep -q . ||
    fail "source root contains no Java input: ${source_root}"
}

assert_controlled_cases_root() {
  [[ -d "${CASES_ROOT}" && ! -L "${CASES_ROOT}" ]] ||
    fail "research cases root is missing or unsafe."
  if find "${CASES_ROOT}" -type l -print -quit | grep -q .; then
    fail "research cases contain a symbolic link."
  fi
  if find "${CASES_ROOT}" \! -type f \! -type d -print -quit | grep -q .; then
    fail "research cases contain a non-regular entry."
  fi
}

assert_capture() {
  local path="$1"
  [[ -f "${path}" && ! -L "${path}" ]] ||
    fail "PMD did not create a regular raw capture: ${path}"
  local bytes
  bytes="$(stat --format='%s' -- "${path}")"
  ((bytes > 0 && bytes <= MAX_CAPTURE_BYTES)) ||
    fail "raw capture has disallowed size ${bytes}: ${path}"
}

capture_side() {
  local executable="$1"
  local family_id="$2"
  local side="$3"
  local output_case_root="$4"
  local case_root="${CASES_ROOT}/${family_id}"
  local source_root="${case_root}/${side}/source"
  local ruleset="${case_root}/pmd-ruleset.xml"
  local raw_capture="${output_case_root}/${side}.raw.sarif"
  local projection="${output_case_root}/${side}.sarif"
  local audit="${output_case_root}/${side}.projection-audit.json"

  assert_controlled_source_root "${source_root}"
  [[ -f "${ruleset}" && ! -L "${ruleset}" ]] ||
    fail "family ruleset is missing or unsafe: ${ruleset}"
  local -ar pmd_arguments=(
    "${executable}"
    check
    --dir
    .
    --format
    sarif
    --no-cache
    --no-fail-on-violation
    --no-progress
    --relativize-paths-with
    "${source_root}"
    --report-file
    "${raw_capture}"
    --rulesets
    "${ruleset}"
    --threads
    0
    --use-version
    java-17
  )
  local -a verifier_arguments=(
    python3 -B "${VERIFIER}" verify-command
    --executable "${executable}"
    --source-root "${source_root}"
    --raw-capture "${raw_capture}"
    --ruleset "${ruleset}"
  )
  local argument
  for argument in "${pmd_arguments[@]}"; do
    verifier_arguments+=("--argument=${argument}")
  done
  "${verifier_arguments[@]}"
  (
    cd -- "${source_root}"
    JAVA_HOME="${CAPTURE_JAVA_HOME}" \
      LD_LIBRARY_PATH="${CAPTURE_JAVA_LIBRARY_PATH}" \
      "${pmd_arguments[@]}"
  )
  assert_capture "${raw_capture}"
  python3 -I -B "${PROJECTOR}" \
    --input "${raw_capture}" \
    --output "${projection}" \
    --audit "${audit}" \
    --source-root "${source_root}" \
    --logical-source-root "cases/${family_id}/${side}/source" \
    --family-id "${family_id}" \
    --side "${side}" \
    --capture-contract-sha256 "${CAPTURE_CONTRACT_SHA256}"
}

write_checksums() {
  local output_root="$1"
  local checksum_path="${output_root}/checksums.sha256"
  [[ ! -e "${checksum_path}" ]] || fail "checksum destination already exists."
  (
    cd -- "${output_root}"
    local relative
    while IFS= read -r -d '' relative; do
      relative="${relative#./}"
      printf '%s  %s\n' \
        "$(sha256sum -- "${relative}" | cut -d ' ' -f 1)" \
        "${relative}"
    done < <(
      find . -type f \! -name checksums.sha256 -printf '%p\0' |
        LC_ALL=C sort -z
    )
  ) >"${checksum_path}"
}

main() {
  local output_root=""
  local source_sha=""
  while (($# > 0)); do
    case "$1" in
      --output-root)
        (($# >= 2)) || fail "--output-root requires a value."
        output_root="$2"
        shift 2
        ;;
      --source-sha)
        (($# >= 2)) || fail "--source-sha requires a value."
        source_sha="$2"
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

  require_command curl
  require_command cut
  require_command find
  require_command git
  require_command grep
  require_command java
  require_command mktemp
  require_command python3
  require_command readlink
  require_command sed
  require_command sha256sum
  require_command sort
  require_command stat
  verify_host_environment
  verify_shell_capture_contract
  assert_controlled_cases_root

  local actual_source_sha
  actual_source_sha="$(git -C "${REPOSITORY_ROOT}" rev-parse HEAD)"
  source_sha="${source_sha:-${actual_source_sha}}"
  [[ "${source_sha}" =~ ^[0-9a-f]{40}$ ]] || fail "source SHA is not full lowercase SHA-1."
  [[ "${actual_source_sha}" == "${source_sha}" ]] ||
    fail "checked-out SHA ${actual_source_sha} differs from requested ${source_sha}."

  local output_parent
  output_parent="$(dirname -- "${output_root}")"
  mkdir -p -- "${output_parent}"
  output_parent="$(cd -- "${output_parent}" && pwd -P)"
  output_root="${output_parent}/$(basename -- "${output_root}")"
  [[ ! -e "${output_root}" ]] || fail "output root already exists: ${output_root}"
  case "${output_root}/" in
    "${RESEARCH_ROOT}/"*) fail "capture output must be outside research inputs." ;;
  esac
  mkdir -- "${output_root}"

  TEMPORARY_PARENT="$(cd -- "${REPOSITORY_ROOT}/.." && pwd -P)"
  TEMPORARY_ROOT="$(mktemp -d "${TEMPORARY_PARENT}/sarif-regress-sparse-pmd.XXXXXX")"
  trap cleanup EXIT
  local tools_root="${TEMPORARY_ROOT}/tools"
  mkdir -- "${tools_root}"
  local executable
  executable="$(prepare_pmd "${tools_root}")"

  python3 -B "${VERIFIER}" write-environment \
    --output "${output_root}/capture-environment.json" \
    --source-sha "${source_sha}" \
    --image-os "${ImageOS}" \
    --image-version "${ImageVersion}" \
    --capture-contract-sha256 "${CAPTURE_CONTRACT_SHA256}"

  mapfile -d '' -t families < <(
    find "${CASES_ROOT}" -mindepth 1 -maxdepth 1 -type d -printf '%f\0' |
      LC_ALL=C sort -z
  )
  ((${#families[@]} >= 2)) || fail "at least two research families are required."
  local family_id
  local side
  for family_id in "${families[@]}"; do
    [[ "${family_id}" =~ ^[a-z][a-z0-9]*(-[a-z0-9]+)*$ ]] ||
      fail "unsafe family ID: ${family_id}"
    local output_case_root="${output_root}/cases/${family_id}"
    mkdir -p -- "${output_case_root}"
    for side in baseline candidate; do
      capture_side "${executable}" "${family_id}" "${side}" "${output_case_root}"
    done
  done

  write_checksums "${output_root}"
  python3 -B "${VERIFIER}" verify \
    --research-root "${RESEARCH_ROOT}" \
    --capture-root "${output_root}" \
    --source-sha "${source_sha}" \
    --expected-image-os "${ImageOS}" \
    --expected-image-version "${ImageVersion}"

  trap - EXIT
  cleanup
  TEMPORARY_ROOT=""
  echo "Verified sparse PMD capture evidence written to ${output_root}."
}

main "$@"
