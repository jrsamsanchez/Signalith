#!/usr/bin/env bash
# Usage: ci-changes.sh BASE_SHA
# Prints, as name=true or name=false, which of CI's slower jobs that aren't
# required checks a pull request needs, from the files it changes since
# BASE_SHA. With no BASE_SHA (a push to main), every job runs.
set -euo pipefail

base=${1:-}
files=()
# If the diff can't be made, every job runs.
if [ -n "$base" ] && changed=$(git diff --name-only "$base...HEAD"); then
  mapfile -t files <<< "$changed"
else
  base=""
fi

# out NAME PATTERN...: whether any changed file matches one of the patterns.
out() {
  local name=$1 f p
  shift
  if [ -z "$base" ]; then
    echo "$name=true"
    return
  fi
  for f in "${files[@]}"; do
    for p in "$@"; do
      # shellcheck disable=SC2053 # the pattern is a glob on purpose
      if [[ $f == $p ]]; then
        echo "$name=true"
        return
      fi
    done
  done
  echo "$name=false"
}

ci='.github/workflows/ci.yml'
out fuzz 'internal/*.go' 'cmd/*.go' '*/testdata/fuzz/*' go.mod go.sum .github/scripts/fuzz.sh .github/scripts/ci-changes.sh "$ci"
out packages 'deploy/*' 'cmd/signalith/*' go.mod go.sum '.github/scripts/test-*' .github/scripts/package-versions.sh \
  .github/workflows/packages.yml .github/scripts/ci-changes.sh "$ci"
out lab 'deploy/lab/*' .github/scripts/ci-changes.sh "$ci"
out sensor 'deploy/sensor*' 'deploy/docker/*' 'internal/agents/*' '*sensor*' .github/scripts/ci-changes.sh "$ci"
