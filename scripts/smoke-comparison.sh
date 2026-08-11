#!/usr/bin/env bash
set -euo pipefail

if (($# != 3)); then
    echo \
        "Usage: $0 <standalone-executable> <installed-tool-executable> <output-root>" \
        >&2
    exit 1
fi

readonly script_directory="$(cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly repository_root="$(cd -P -- "${script_directory}/.." && pwd -P)"
readonly standalone_executable="$(realpath -e -- "$1")"
readonly installed_tool_executable="$(realpath -e -- "$2")"
readonly output_root="$3"
readonly baseline_fixture="${repository_root}/corpus/cases/github-supported-subset/baseline.sarif"
readonly candidate_fixture="${repository_root}/corpus/cases/github-supported-subset/candidate.sarif"
readonly offline_marker="  <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'\">"

if [[ -e "${output_root}" || -L "${output_root}" ]]; then
    echo "Comparison smoke output root already exists: ${output_root}" >&2
    exit 1
fi

mkdir -- "${output_root}"

assert_report_contract() {
    local report_directory="$1"
    local json_path="${report_directory}/report.json"
    local html_path="${report_directory}/report.html"

    jq -e '
        (keys == [
            "determinism",
            "diagnostics",
            "findings",
            "inputs",
            "metrics",
            "outputSchemaVersion",
            "summary",
            "tool"
        ]) and
        .outputSchemaVersion == "1" and
        .tool.name == "sarif-regress" and
        .inputs == {
            "baseline": "baseline.sarif",
            "candidate": "candidate.sarif"
        } and
        .summary == {
            "baselineCount": 1,
            "candidateCount": 1,
            "new": 0,
            "unchanged": 1,
            "moved": 0,
            "modified": 0,
            "resolved": 0,
            "ambiguous": 0
        } and
        (.findings | length) == 1 and
        .findings[0].classification == "unchanged" and
        .diagnostics == []
    ' "${json_path}" >/dev/null

    if [[ "$(head -n 1 -- "${html_path}")" != '<!doctype html>' ]]; then
        echo "Comparison smoke HTML has an unexpected document contract." >&2
        exit 1
    fi
    if ! grep --fixed-strings --line-regexp -- \
        "${offline_marker}" \
        "${html_path}" >/dev/null; then
        echo "Comparison smoke HTML omits the offline Content Security Policy." >&2
        exit 1
    fi
}

run_comparison() {
    local executable="$1"
    local report_directory="$2"

    mkdir -- "${report_directory}"
    "${executable}" compare \
        --baseline "${baseline_fixture}" \
        --candidate "${candidate_fixture}" \
        --json-out "${report_directory}/report.json" \
        --html-out "${report_directory}/report.html"
    assert_report_contract "${report_directory}"
}

run_comparison "${standalone_executable}" "${output_root}/standalone"
run_comparison "${installed_tool_executable}" "${output_root}/installed-tool"

cmp --silent -- \
    "${output_root}/standalone/report.json" \
    "${output_root}/installed-tool/report.json"
cmp --silent -- \
    "${output_root}/standalone/report.html" \
    "${output_root}/installed-tool/report.html"
