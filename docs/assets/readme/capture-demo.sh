#!/usr/bin/env bash
set -euo pipefail

if (( $# != 2 )); then
    echo "Usage: $0 <sarif-regress-executable> <output-directory>" >&2
    exit 1
fi

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd -- "${script_directory}/../../.." && pwd)"
demo_fixture_directory="${repository_root}/corpus/cases/eslint-real-mutation"

if [[ ! -e "$1" ]]; then
    echo "The SarifRegress executable does not exist: $1" >&2
    exit 1
fi
executable_path="$(realpath -e -- "$1")"
if [[ ! -x "${executable_path}" ]]; then
    echo "The SarifRegress file is not executable: ${executable_path}" >&2
    exit 1
fi

requested_output_directory="$2"
if [[ -e "${requested_output_directory}" || -L "${requested_output_directory}" ]]; then
    echo "The output directory must not already exist: ${requested_output_directory}" >&2
    exit 1
fi
output_parent="$(dirname -- "${requested_output_directory}")"
output_name="$(basename -- "${requested_output_directory}")"
if [[ -z "${output_name}" \
    || "${output_name}" == "." \
    || "${output_name}" == ".." \
    || "${output_name}" == "/" ]]; then
    echo "The output directory name is invalid: ${requested_output_directory}" >&2
    exit 1
fi
mkdir -p -- "${output_parent}"
output_parent="$(cd -- "${output_parent}" && pwd -P)"
output_directory="${output_parent}/${output_name}"
if [[ -e "${output_directory}" || -L "${output_directory}" ]]; then
    echo "The output directory must not already exist: ${output_directory}" >&2
    exit 1
fi
staging_directory="$(
    mktemp -d "${output_parent}/.${output_name}.capture.XXXXXXXX"
)"

cleanup_staging_directory() {
    if [[ -d "${staging_directory}" ]]; then
        rm -rf -- "${staging_directory}"
    fi
}
trap cleanup_staging_directory EXIT

run_directory="${staging_directory}/run"
browser_profile_directory="${staging_directory}/browser-profile"
terminal_gif="${staging_directory}/eslint-line-shift-terminal.gif"
report_screenshot="${staging_directory}/eslint-line-shift-report.png"
evidence_screenshot="${staging_directory}/eslint-line-shift-evidence.png"

for required_command in jq python3; do
    if ! command -v "${required_command}" >/dev/null 2>&1; then
        echo "Required command is unavailable: ${required_command}" >&2
        exit 1
    fi
done

browser_path="${SARIF_REGRESS_DEMO_BROWSER:-}"
if [[ -z "${browser_path}" ]]; then
    for browser_candidate in google-chrome chromium chromium-browser; do
        if command -v "${browser_candidate}" >/dev/null 2>&1; then
            browser_path="$(command -v "${browser_candidate}")"
            break
        fi
    done
fi
if [[ -z "${browser_path}" || ! -x "${browser_path}" ]]; then
    echo "Chrome or Chromium is required to capture the HTML report." >&2
    exit 1
fi
browser_path="$(realpath -e -- "${browser_path}")"
"${browser_path}" --version > "${staging_directory}/browser-version.txt"

mkdir -p -- "${run_directory}"
cp -- "${demo_fixture_directory}/baseline.sarif" "${run_directory}/baseline.sarif"
cp -- "${demo_fixture_directory}/candidate.sarif" "${run_directory}/candidate.sarif"
cp -- "${script_directory}/demo-summary.jq" "${run_directory}/demo-summary.jq"

(
    cd -- "${run_directory}"
    "${executable_path}" compare \
        --baseline baseline.sarif \
        --candidate candidate.sarif \
        --json-out report.json \
        --html-out report.html \
        2> diagnostics.txt
)

expected_summary='{
  "baselineCount": 2,
  "candidateCount": 2,
  "new": 0,
  "unchanged": 0,
  "moved": 2,
  "modified": 0,
  "resolved": 0,
  "ambiguous": 0
}'
expected_findings='[
  {
    "classification": "moved",
    "rule": "eslint/eqeqeq",
    "baselineLine": 2,
    "candidateLine": 3,
    "confidence": "high",
    "precedenceTier": "exact-canonical"
  },
  {
    "classification": "moved",
    "rule": "eslint/no-eval",
    "baselineLine": 3,
    "candidateLine": 4,
    "confidence": "high",
    "precedenceTier": "exact-canonical"
  }
]'
jq --exit-status \
    --argjson expected_summary "${expected_summary}" \
    --argjson expected_findings "${expected_findings}" \
    '
      .summary == $expected_summary
      and (
        [
          .findings[]
          | {
              classification,
              rule: .candidate.canonicalRule,
              baselineLine: .baseline.region.startLine,
              candidateLine: .candidate.region.startLine,
              confidence: .decision.displayConfidence,
              precedenceTier: .decision.precedenceTier
            }
        ] == $expected_findings
      )
    ' \
    "${run_directory}/report.json" >/dev/null
jq --raw-output \
    --from-file "${run_directory}/demo-summary.jq" \
    "${run_directory}/report.json" \
    > "${run_directory}/summary.txt"

python3 "${script_directory}/render_terminal_demo.py" \
    --summary-file "${run_directory}/summary.txt" \
    --output "${terminal_gif}"

report_uri="$(
    python3 - "${run_directory}/report.html" <<'PY'
from pathlib import Path
import sys

print(Path(sys.argv[1]).resolve().as_uri())
PY
)"
browser_sandbox_arguments=()
if (( EUID == 0 )); then
    browser_sandbox_arguments+=(--no-sandbox)
fi

capture_browser_screenshot() {
    local page_uri="$1"
    local destination_path="$2"
    local profile_path="${browser_profile_directory}/$(basename -- "${destination_path}")"

    "${browser_path}" \
        --headless=new \
        --disable-background-networking \
        --disable-component-update \
        --disable-default-apps \
        --disable-dev-shm-usage \
        --disable-extensions \
        --disable-gpu \
        --disable-sync \
        --hide-scrollbars \
        "${browser_sandbox_arguments[@]}" \
        --force-color-profile=srgb \
        --force-device-scale-factor=1 \
        --lang=en-US \
        --metrics-recording-only \
        --no-first-run \
        --run-all-compositor-stages-before-draw \
        --user-data-dir="${profile_path}" \
        --virtual-time-budget=1000 \
        --window-size=1440,1000 \
        --screenshot="${destination_path}" \
        "${page_uri}" >/dev/null 2>&1
}

capture_browser_screenshot "${report_uri}" "${report_screenshot}"
capture_browser_screenshot \
    "${report_uri}#finding-0" \
    "${evidence_screenshot}"
rm -rf -- "${browser_profile_directory}"

for generated_asset in \
    "${terminal_gif}" \
    "${report_screenshot}" \
    "${evidence_screenshot}"
do
    if [[ ! -s "${generated_asset}" ]]; then
        echo "Expected demo asset was not generated: ${generated_asset}" >&2
        exit 1
    fi
done

python3 - \
    "${report_screenshot}" \
    "${evidence_screenshot}" <<'PY'
from pathlib import Path
import sys

from PIL import Image

for raw_path in sys.argv[1:]:
    image_path = Path(raw_path)
    with Image.open(image_path) as image:
        if image.size != (1440, 1000):
            raise ValueError(
                f"Unexpected screenshot size for {image_path}: {image.size}"
            )
        extrema = image.convert("RGB").getextrema()
        if all(channel == (255, 255) for channel in extrema):
            raise ValueError(f"Screenshot is blank: {image_path}")
PY

(
    cd -- "${staging_directory}"
    sha256sum \
        run/report.json \
        run/report.html \
        browser-version.txt \
        eslint-line-shift-terminal.gif \
        eslint-line-shift-report.png \
        eslint-line-shift-evidence.png \
        > checksums.sha256
)

mv --no-target-directory --no-clobber -- \
    "${staging_directory}" \
    "${output_directory}"
if [[ -d "${staging_directory}" ]]; then
    echo "The output directory was created concurrently: ${output_directory}" >&2
    exit 1
fi
trap - EXIT
