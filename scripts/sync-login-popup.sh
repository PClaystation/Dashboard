#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
dashboard_root="$(cd "${script_dir}/.." && pwd)"
source_dir="${dashboard_root}/login popup"
target_dir="$(cd "${dashboard_root}/.." && pwd)/Login"

if [[ ! -d "${source_dir}" ]]; then
  printf 'Source folder not found: %s\n' "${source_dir}" >&2
  exit 1
fi

if [[ ! -d "${target_dir}" ]]; then
  printf 'Target repo not found: %s\n' "${target_dir}" >&2
  exit 1
fi

copied=()

while IFS= read -r -d '' file; do
  name="$(basename "${file}")"
  cp "${file}" "${target_dir}/${name}"
  copied+=("${name}")
done < <(find "${source_dir}" -maxdepth 1 -type f -print0)

IFS=$'\n' copied=($(printf '%s\n' "${copied[@]}" | sort))
unset IFS

printf 'Synced %d file(s) from %s to %s.\n' "${#copied[@]}" "${source_dir}" "${target_dir}"
for name in "${copied[@]}"; do
  printf -- '- %s\n' "${name}"
done
