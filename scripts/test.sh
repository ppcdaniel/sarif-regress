#!/usr/bin/env bash
set -euo pipefail

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd -- "${script_directory}/.." && pwd)"
solution_file="SarifRegress.slnx"

"${script_directory}/build.sh"

cd "${repository_root}"

dotnet test "${solution_file}" --configuration Release --no-build --no-restore
