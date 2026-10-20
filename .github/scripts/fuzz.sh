#!/usr/bin/env bash
# Copyright 2026 The Signalith authors
# SPDX-License-Identifier: Apache-2.0
# Runs every Go fuzz target in the repository (each func Fuzz... in a
# _test.go file) for FUZZTIME (10s by default), one after another, and
# fails when any finds a crash or a hang. Go writes the input that failed
# under the package's testdata/fuzz/<target>/; commit it with the fix, and
# it is checked by every go test from then on.
set -uo pipefail
cd "$(dirname "$0")/../.."
fuzztime="${FUZZTIME:-10s}"
out="$(mktemp)"
trap 'rm -f "$out"' EXIT
failed=()
while IFS=: read -r file name; do
  pkg="./$(dirname "$file")"
  echo "::group::$name ($pkg)"
  if ! go test -run='^$' -fuzz="^${name}\$" -fuzztime="$fuzztime" "$pkg" 2>&1 | tee "$out"; then
    # Go's fuzzer can fail with "context deadline exceeded" as fuzztime
    # runs out, without any input having failed; a real failure always
    # says where it wrote the input.
    if grep -q 'context deadline exceeded' "$out" && ! grep -q 'Failing input written to' "$out"; then
      echo "::warning::$name stopped with Go's end-of-fuzztime timeout; no input failed"
    else
      failed+=("$name ($pkg)")
    fi
  fi
  echo "::endgroup::"
done < <(grep -rEo --include='*_test.go' '^func Fuzz[A-Za-z0-9_]+' internal cmd | sed -E 's/:func /:/' | sort -u)
if [ ${#failed[@]} -gt 0 ]; then
  printf 'failed: %s\n' "${failed[@]}"
  exit 1
fi
