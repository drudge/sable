#!/usr/bin/env bash
# A published release must have reviewed, user-facing notes, including candidates.
set -euo pipefail
release_version="${1:?Pass the release version}"
changelog_path="${2:-CHANGELOG.md}"
notes="$(awk -v heading="## [${release_version#v}]" '
  $0 == heading || index($0, heading " ") == 1 { found = 1; next }
  found && /^## / { exit }
  found { print }
  END { if (!found) exit 1 }
' "${changelog_path}")" || {
  echo "Add a curated CHANGELOG.md section for ${release_version} before publishing." >&2
  exit 1
}
if ! [[ "$notes" =~ [^[:space:]] ]]; then
  echo "Release notes for ${release_version} are empty." >&2
  exit 1
fi
printf '%s\n' "$notes"
