#!/usr/bin/env bash
# Runs every Go fuzz target in the repository (each func Fuzz... in a
# _test.go file) for FUZZTIME (10s by default), one after another, and
# fails when any finds a crash or a hang. Go writes the input that failed
# under the package's testdata/fuzz/<target>/; commit it with the fix, and
# it is checked by every go test from then on.
set -uo pipefail
cd "$(dirname "$0")/../.."
fuzztime="${FUZZTIME:-10s}"
failed=()
while IFS=: read -r file name; do
  pkg="./$(dirname "$file")"
  echo "::group::$name ($pkg)"
  if ! go test -run='^$' -fuzz="^${name}\$" -fuzztime="$fuzztime" "$pkg"; then
    failed+=("$name ($pkg)")
  fi
  echo "::endgroup::"
done < <(grep -rEo --include='*_test.go' '^func Fuzz[A-Za-z0-9_]+' internal cmd | sed -E 's/:func /:/' | sort -u)
if [ ${#failed[@]} -gt 0 ]; then
  printf 'failed: %s\n' "${failed[@]}"
  exit 1
fi
