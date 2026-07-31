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
readonly GITLEAKS_NORMALIZER="${CAPTURE_SCRIPT_DIRECTORY}/normalize_gitleaks_sarif.py"
readonly PROVENANCE_VERIFIER="${CAPTURE_SCRIPT_DIRECTORY}/verify_capture_provenance.py"
readonly SEMGREP_RUNNER="${CAPTURE_SCRIPT_DIRECTORY}/run_semgrep.py"
readonly SEMGREP_CORE_LOADER="${CAPTURE_SCRIPT_DIRECTORY}/semgrep-core-loader.sh"
readonly TAR_EXTRACTOR="${CAPTURE_SCRIPT_DIRECTORY}/extract_tar.py"
readonly ZIP_EXTRACTOR="${CAPTURE_SCRIPT_DIRECTORY}/extract_zip.py"
readonly TRANSFORMATION_VERIFIER="${CAPTURE_SCRIPT_DIRECTORY}/verify_source_transformations.py"
readonly SEMGREP_REQUIREMENTS_LOCK="${CAPTURE_SCRIPT_DIRECTORY}/semgrep-requirements.linux-x86_64-py312.lock"

readonly SEMGREP_VERSION="1.172.0"
readonly SEMGREP_WHEEL_NAME="semgrep-1.172.0-cp310.cp311.cp312.cp313.cp314.py310.py311.py312.py313.py314-none-manylinux_2_34_x86_64.whl"
readonly SEMGREP_WHEEL_URL="https://files.pythonhosted.org/packages/84/a5/21624510b65271a673961a894af7511b5123d662e84c74c765560ea28b27/${SEMGREP_WHEEL_NAME}"
readonly SEMGREP_WHEEL_SHA256="d8b94af4266a575287ad2cd844573743ab4fe58f6bfb6d9229327807937eade3"
readonly SEMGREP_WHEEL_BYTES="69575334"
readonly SEMGREP_NATIVE_CORE_SHA256="8a7c27e6286381fdb6235eb91bd0fed40b919496a242c72f1e55d2b5caa10cb2"
readonly SEMGREP_NATIVE_CORE_BYTES="253156344"
readonly SEMGREP_CORE_LOADER_SHA256="64930ae1e1bb0be1ca7b742c20c900f21a05352699d2852da141154077c68613"
readonly SEMGREP_HELP_SHA256="b63d6e12f56f512a1c5cd1f9d9d931056c103c06dfec971b1ff26e12c2c16582"
readonly CAPTURE_PYTHON_VERSION="3.12.13"
readonly CAPTURE_JAVA_VENDOR="Eclipse Adoptium"
readonly CAPTURE_JAVA_VERSION="17.0.19+10"
readonly CAPTURE_GLIBC_VERSION="glibc 2.39"
readonly CAPTURE_DYNAMIC_LOADER="/lib64/ld-linux-x86-64.so.2"
readonly CAPTURE_DYNAMIC_LOADER_BYTES="236616"
readonly CAPTURE_DYNAMIC_LOADER_SHA256="1cd555ac46b7887edeaf3c42aac5408c8135e52f6b37870da2cf82d5fe14e829"
readonly CAPTURE_LIBC="/lib/x86_64-linux-gnu/libc.so.6"
readonly CAPTURE_LIBC_BYTES="2125328"
readonly CAPTURE_LIBC_SHA256="d8db8739a1633c972cec6a4fe0566bdcec6fd088f98723492ab0361f66238f75"

readonly GITLEAKS_VERSION="8.30.1"
readonly GITLEAKS_ARCHIVE_NAME="gitleaks_8.30.1_linux_x64.tar.gz"
readonly GITLEAKS_ARCHIVE_URL="https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/${GITLEAKS_ARCHIVE_NAME}"
readonly GITLEAKS_ARCHIVE_SHA256="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"
readonly GITLEAKS_ARCHIVE_BYTES="8230402"
readonly GITLEAKS_CHECKSUMS_NAME="gitleaks_8.30.1_checksums.txt"
readonly GITLEAKS_CHECKSUMS_URL="https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/${GITLEAKS_CHECKSUMS_NAME}"
readonly GITLEAKS_CHECKSUMS_SHA256="061476c21adaf5441516f96f185c1a4706a83cd6329b9b38762271b3d4a52fae"
readonly GITLEAKS_CHECKSUMS_BYTES="999"
readonly GITLEAKS_HELP_SHA256="ff55bf949d8ac8354e133f09c8be4ccac32cf82ec3a01446e2f31cbe20857a86"
readonly GITLEAKS_VERSION_OUTPUT_SHA256="c9fd9ccb6682c54b5fcb0363757b6c6873564e7c067f70b3b5581b611528b9f4"

readonly PMD_VERSION="7.26.0"
readonly PMD_ARCHIVE_NAME="pmd-dist-7.26.0-bin.zip"
readonly PMD_ARCHIVE_URL="https://github.com/pmd/pmd/releases/download/pmd_releases/7.26.0/${PMD_ARCHIVE_NAME}"
readonly PMD_ARCHIVE_SHA256="9f55cb7ff0e9f9a66dd2f005eaa370e84c8a4cd971b134aa14a930c4a283ebc9"
readonly PMD_ARCHIVE_BYTES="73646044"
readonly PMD_ARCHIVE_PREFIX="pmd-bin-7.26.0"
readonly PMD_HELP_SHA256="babf2b1e17bddd7611cc4882b9686c207e2b73fee3e3053276b3455e6c890b91"

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

verify_capture_environment() {
  python3 -B - "${CAPTURE_PYTHON_VERSION}" <<'PY'
import platform
import sys

expected = sys.argv[1]
actual = sys.version.split()[0]
if actual != expected:
    raise SystemExit(
        f"Holdout capture requires Python {expected}; found {actual}."
    )
if platform.system() != "Linux" or platform.machine() not in {"x86_64", "AMD64"}:
    raise SystemExit("Holdout capture is pinned to Linux x86-64.")
PY

  local observed_glibc_version
  observed_glibc_version="$(getconf GNU_LIBC_VERSION)"
  [[ "${observed_glibc_version}" == "${CAPTURE_GLIBC_VERSION}" ]] ||
    fail "capture requires ${CAPTURE_GLIBC_VERSION}; found ${observed_glibc_version}."
  local resolved_dynamic_loader
  resolved_dynamic_loader="$(readlink -f -- "${CAPTURE_DYNAMIC_LOADER}")"
  [[ -f "${resolved_dynamic_loader}" && ! -L "${resolved_dynamic_loader}" && -x "${resolved_dynamic_loader}" ]] ||
    fail "capture dynamic loader does not resolve to a regular executable."
  local observed_dynamic_loader_bytes
  observed_dynamic_loader_bytes="$(stat --format='%s' -- "${resolved_dynamic_loader}")"
  [[ "${observed_dynamic_loader_bytes}" == "${CAPTURE_DYNAMIC_LOADER_BYTES}" ]] ||
    fail "capture dynamic-loader size differs from the reviewed runtime."
  local observed_dynamic_loader_sha256
  observed_dynamic_loader_sha256="$(
    sha256sum -- "${resolved_dynamic_loader}" | cut -d ' ' -f 1
  )"
  [[ "${observed_dynamic_loader_sha256}" == "${CAPTURE_DYNAMIC_LOADER_SHA256}" ]] ||
    fail "capture dynamic-loader SHA-256 differs from the reviewed runtime."
  local resolved_libc
  resolved_libc="$(readlink -f -- "${CAPTURE_LIBC}")"
  [[ -f "${resolved_libc}" && ! -L "${resolved_libc}" && -x "${resolved_libc}" ]] ||
    fail "capture libc does not resolve to a regular executable."
  local observed_libc_bytes
  observed_libc_bytes="$(stat --format='%s' -- "${resolved_libc}")"
  [[ "${observed_libc_bytes}" == "${CAPTURE_LIBC_BYTES}" ]] ||
    fail "capture libc size differs from the reviewed runtime."
  local observed_libc_sha256
  observed_libc_sha256="$(
    sha256sum -- "${resolved_libc}" | cut -d ' ' -f 1
  )"
  [[ "${observed_libc_sha256}" == "${CAPTURE_LIBC_SHA256}" ]] ||
    fail "capture libc SHA-256 differs from the reviewed runtime."

  local java_executable
  java_executable="$(readlink -f -- "$(command -v -- java)")"
  local java_home
  java_home="$(cd -- "$(dirname -- "${java_executable}")/.." && pwd -P)"
  local java_library_path="${java_home}/lib:${java_home}/lib/server"
  local java_properties
  java_properties="$(
    LC_ALL=C \
      JAVA_HOME="${java_home}" \
      LD_LIBRARY_PATH="${java_library_path}" \
      "${java_executable}" -XshowSettings:properties -version 2>&1
  )"
  local observed_java_vendor
  observed_java_vendor="$(
    sed -n 's/^[[:space:]]*java.vendor = //p' <<<"${java_properties}"
  )"
  [[ "${observed_java_vendor}" == "${CAPTURE_JAVA_VENDOR}" ]] ||
    fail "capture requires ${CAPTURE_JAVA_VENDOR} Java."
  local observed_java_version
  observed_java_version="$(
    sed -n 's/^[[:space:]]*java.runtime.version = //p' <<<"${java_properties}"
  )"
  [[ "${observed_java_version}" == "${CAPTURE_JAVA_VERSION}" ]] ||
    fail "capture requires Java runtime ${CAPTURE_JAVA_VERSION}."
}

prepare_semgrep() {
  local tools_root="$1"
  local wheelhouse="${tools_root}/semgrep-wheelhouse"
  local environment_root="${tools_root}/semgrep-environment"
  mkdir -p -- "${wheelhouse}"

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

  # Pysemgrep invokes the packaged core several times. Apply the wheel's
  # complete library closure only to those native processes. Exporting it
  # process-wide is unsafe: osemgrep re-enters Python, whose loader would then
  # pick up the wheel's older libm.
  local semgrep_native_directory
  semgrep_native_directory="${environment_root}/lib/python3.12/site-packages/semgrep/bin"
  local semgrep_core="${semgrep_native_directory}/semgrep-core"
  local semgrep_native_core="${semgrep_native_directory}/semgrep-core.native"
  local observed_native_core_bytes
  observed_native_core_bytes="$(stat --format='%s' -- "${semgrep_core}")"
  [[ "${observed_native_core_bytes}" == "${SEMGREP_NATIVE_CORE_BYTES}" ]] ||
    fail "the installed Semgrep native core has an unexpected size."
  local observed_native_core_sha256
  observed_native_core_sha256="$(sha256sum -- "${semgrep_core}" | cut -d ' ' -f 1)"
  [[ "${observed_native_core_sha256}" == "${SEMGREP_NATIVE_CORE_SHA256}" ]] ||
    fail "the installed Semgrep native core differs from the pinned wheel."
  [[ -f "${SEMGREP_CORE_LOADER}" && ! -L "${SEMGREP_CORE_LOADER}" ]] ||
    fail "the repository Semgrep core loader is unsafe."
  local observed_loader_sha256
  observed_loader_sha256="$(sha256sum -- "${SEMGREP_CORE_LOADER}" | cut -d ' ' -f 1)"
  [[ "${observed_loader_sha256}" == "${SEMGREP_CORE_LOADER_SHA256}" ]] ||
    fail "the repository Semgrep core loader differs from reviewed provenance."
  [[ ! -e "${semgrep_native_core}" ]] ||
    fail "the Semgrep native-core destination unexpectedly exists."
  mv -- "${semgrep_core}" "${semgrep_native_core}"
  cp -- "${SEMGREP_CORE_LOADER}" "${semgrep_core}"
  chmod 0755 -- "${semgrep_core}" "${semgrep_native_core}"

  local semgrep_vendor_library_path
  semgrep_vendor_library_path="${environment_root}/lib/python3.12/site-packages/semgrep/bin/libs"
  local library_count=0
  local library_path
  while IFS= read -r -d '' library_path; do
    [[ -f "${library_path}" && ! -L "${library_path}" ]] ||
      fail "the verified Semgrep wheel contains an unsafe runtime library entry."
    local library_bytes
    library_bytes="$(stat --format='%s' -- "${library_path}")"
    ((library_bytes > 0 && library_bytes <= 64 * 1024 * 1024)) ||
      fail "the verified Semgrep wheel contains an oversized runtime library."
    library_count=$((library_count + 1))
  done < <(
    find "${semgrep_vendor_library_path}" \
      -mindepth 1 \
      -maxdepth 1 \
      -print0
  )
  ((library_count > 0 && library_count <= 64)) ||
    fail "the verified Semgrep runtime library set has an invalid member count."

  local observed_version
  observed_version="$(
    "${environment_root}/bin/python" -I -B "${SEMGREP_RUNNER}" \
      --semgrep-script "${environment_root}/bin/semgrep" \
      --library-directory "${semgrep_vendor_library_path}" \
      -- --legacy --version
  )"
  [[ "${observed_version}" == "${SEMGREP_VERSION}" ]] ||
    fail "expected Semgrep ${SEMGREP_VERSION}, found ${observed_version}."

  local help_output="${tools_root}/semgrep-scan-help.txt"
  "${environment_root}/bin/python" -I -B "${SEMGREP_RUNNER}" \
    --semgrep-script "${environment_root}/bin/semgrep" \
    --library-directory "${semgrep_vendor_library_path}" \
    -- --legacy scan --help > "${help_output}"
  local observed_help_sha256
  observed_help_sha256="$(sha256sum "${help_output}" | cut -d ' ' -f 1)"
  [[ "${observed_help_sha256}" == "${SEMGREP_HELP_SHA256}" ]] ||
    fail "Semgrep scan help differs from the reviewed command evidence."
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
  python3 -B "${TAR_EXTRACTOR}" \
    --archive "${archive_path}" \
    --destination "${extraction_root}" \
    --member gitleaks
  [[ -f "${extraction_root}/gitleaks" && ! -L "${extraction_root}/gitleaks" ]] ||
    fail "the extracted Gitleaks executable is not a regular non-link file."
  chmod 0755 -- "${extraction_root}/gitleaks"

  local observed_version
  observed_version="$("${extraction_root}/gitleaks" version)"
  [[ "${observed_version}" == "${GITLEAKS_VERSION}" ]] ||
    fail "expected Gitleaks ${GITLEAKS_VERSION}, found ${observed_version}."
  local observed_version_sha256
  observed_version_sha256="$(
    printf '%s\n' "${observed_version}" | sha256sum | cut -d ' ' -f 1
  )"
  [[ "${observed_version_sha256}" == "${GITLEAKS_VERSION_OUTPUT_SHA256}" ]] ||
    fail "Gitleaks version output differs from the reviewed evidence."
  local help_output="${tools_root}/gitleaks-dir-help.txt"
  "${extraction_root}/gitleaks" dir --help > "${help_output}"
  local observed_help_sha256
  observed_help_sha256="$(sha256sum "${help_output}" | cut -d ' ' -f 1)"
  [[ "${observed_help_sha256}" == "${GITLEAKS_HELP_SHA256}" ]] ||
    fail "Gitleaks dir help differs from the reviewed command evidence."
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
      LD_LIBRARY_PATH="${java_library_path}" \
      "${pmd_executable}" --version
  )"
  grep -Fq "PMD ${PMD_VERSION}" <<<"${observed_version}" ||
    fail "expected PMD ${PMD_VERSION}, found ${observed_version}."
  local help_output="${tools_root}/pmd-check-help.txt"
  JAVA_HOME="${java_home}" \
    LD_LIBRARY_PATH="${java_library_path}" \
    "${pmd_executable}" check --help > "${help_output}"
  local observed_help_sha256
  observed_help_sha256="$(sha256sum "${help_output}" | cut -d ' ' -f 1)"
  [[ "${observed_help_sha256}" == "${PMD_HELP_SHA256}" ]] ||
    fail "PMD check help differs from the reviewed command evidence."
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
  local semgrep_library_path="${semgrep_environment}/lib/python3.12/site-packages/semgrep/bin/libs"

  (
    cd -- "${source_root}"
    "${semgrep_environment}/bin/python" -I -B "${SEMGREP_RUNNER}" \
      --semgrep-script "${semgrep_executable}" \
      --library-directory "${semgrep_library_path}" \
      -- --legacy scan \
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
      LD_LIBRARY_PATH="${java_library_path}" \
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
    if [[ "${producer}" == "gitleaks" ]]; then
      "capture_${producer}_side" \
        "${executable}" \
        "${side}" \
        "${capture_root}/${side}.producer.sarif"
      python3 -B "${GITLEAKS_NORMALIZER}" \
        --input "${capture_root}/${side}.producer.sarif" \
        --output "${capture_root}/${side}.raw.sarif"
    else
      "capture_${producer}_side" \
        "${executable}" \
        "${side}" \
        "${capture_root}/${side}.raw.sarif"
    fi
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
  require_command cp
  require_command cut
  require_command find
  require_command getconf
  require_command grep
  require_command python3
  require_command mv
  require_command sha256sum
  require_command stat
  require_command java
  require_command readlink
  require_command sed

  verify_capture_environment

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
  python3 -B "${PROVENANCE_VERIFIER}" \
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
