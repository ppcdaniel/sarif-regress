#!/usr/bin/env bash
set -euo pipefail

if (( $# != 2 )); then
    echo "Usage: $0 <sarif-regress-executable> <output-directory>" >&2
    exit 1
fi

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd -- "${script_directory}/../../.." && pwd)"
demo_fixture_directory="${repository_root}/corpus/cases/eslint-real-mutation"
executable_path="$(realpath -- "$1")"
output_directory="$(mkdir -p -- "$2" && cd -- "$2" && pwd)"
run_directory="${output_directory}/run"
terminal_gif="${output_directory}/eslint-line-shift-terminal.gif"
report_screenshot="${output_directory}/eslint-line-shift-report.png"

if [[ ! -x "${executable_path}" ]]; then
    echo "The SarifRegress executable is missing or not executable: ${executable_path}" >&2
    exit 1
fi

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

rm -rf -- "${run_directory}"
mkdir -p -- "${run_directory}/bin"
cp -- "${demo_fixture_directory}/baseline.sarif" "${run_directory}/baseline.sarif"
cp -- "${demo_fixture_directory}/candidate.sarif" "${run_directory}/candidate.sarif"
cp -- "${script_directory}/demo-summary.jq" "${run_directory}/demo-summary.jq"
ln -s -- "${executable_path}" "${run_directory}/bin/sarif-regress"

(
    cd -- "${run_directory}"
    PATH="${run_directory}/bin:${PATH}" sarif-regress compare \
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
jq --exit-status \
    --argjson expected "${expected_summary}" \
    '.summary == $expected' \
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
"${browser_path}" \
    --headless=new \
    --disable-dev-shm-usage \
    --disable-gpu \
    --hide-scrollbars \
    --no-sandbox \
    --force-color-profile=srgb \
    --force-device-scale-factor=1 \
    --lang=en-US \
    --run-all-compositor-stages-before-draw \
    --virtual-time-budget=1000 \
    --window-size=1440,1000 \
    --screenshot="${report_screenshot}" \
    "${report_uri}" >/dev/null 2>&1

for generated_asset in "${terminal_gif}" "${report_screenshot}"; do
    if [[ ! -s "${generated_asset}" ]]; then
        echo "Expected demo asset was not generated: ${generated_asset}" >&2
        exit 1
    fi
done

sha256sum \
    "${run_directory}/report.json" \
    "${run_directory}/report.html" \
    "${terminal_gif}" \
    "${report_screenshot}" \
    > "${output_directory}/checksums.sha256"
