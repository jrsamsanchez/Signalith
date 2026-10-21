#!/usr/bin/env bash
# Copyright 2026 The Signalith authors
# SPDX-License-Identifier: Apache-2.0
# Runs every Go fuzz target in the repository (each func Fuzz... in a
# _test.go file) for FUZZTIME (10s by default), one after another, and
# fails when any finds a crash or a hang. FUZZ_SHARD=i/n runs only every
# n-th target from the i-th (1 to n), so n jobs share the targets. Go writes the input that failed
# under the package's testdata/fuzz/<target>/; commit it with the fix, and
# it is checked by every go test from then on.
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1
fuzztime="${FUZZTIME:-10s}"
shard="${FUZZ_SHARD:-1/1}"
shard_i=${shard%/*} shard_n=${shard#*/}
case "$shard_i/$shard_n" in
  *[!0-9/]* | /* | */) echo "FUZZ_SHARD must be i/n, such as 2/4" >&2; exit 2 ;;
esac
if [ "$shard_n" -lt 1 ] || [ "$shard_i" -lt 1 ] || [ "$shard_i" -gt "$shard_n" ]; then
  echo "FUZZ_SHARD must be i/n with 1 <= i <= n" >&2; exit 2
fi
out="$(mktemp)"
trap 'rm -f "$out"' EXIT
failed=()
ran=0 k=0
while IFS=: read -r file name; do
  k=$((k + 1))
  [ $(( (k - 1) % shard_n + 1 )) -eq "$shard_i" ] || continue
  ran=$((ran + 1))
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
echo "ran $ran of $k fuzz targets (shard $shard)"
if [ "$ran" -eq 0 ]; then
  echo "no fuzz target ran" >&2
  exit 1
fi
if [ ${#failed[@]} -gt 0 ]; then
  printf 'failed: %s\n' "${failed[@]}"
  exit 1
fi
