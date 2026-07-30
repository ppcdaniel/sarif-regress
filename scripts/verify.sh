#!/usr/bin/env bash
set -euo pipefail

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd -- "${script_directory}/.." && pwd)"
solution_file="SarifRegress.slnx"

cd "${repository_root}"

dotnet restore "${solution_file}" --locked-mode
dotnet format "${solution_file}" --no-restore --verify-no-changes
dotnet build "${solution_file}" --configuration Release --no-restore --warnaserror
dotnet test "${solution_file}" --configuration Release --no-build --no-restore
