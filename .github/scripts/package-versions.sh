#!/bin/sh
# Picks the versions the package jobs build, for $GITHUB_OUTPUT:
#   version   what this run builds: $1 when given (a release), else one
#             patch above the latest release, marked -ci (0.1.1-ci.42)
#   previous  the version to upgrade from in the tests: the latest release
#             when there is one (its packages are downloaded), else 0.0.0
#             built from this code
#   previous_release  the latest release's tag, or empty
set -eu
latest=$(gh release view --repo "$GITHUB_REPOSITORY" --json tagName --jq .tagName 2>/dev/null || true)
base=${latest#v}
[ -n "$base" ] || base=0.0.0
version=${1:-}
version=${version#v}
if [ -z "$version" ]; then
  major=$(echo "$base" | cut -d. -f1); minor=$(echo "$base" | cut -d. -f2); patch=$(echo "$base" | cut -d. -f3 | sed 's/[^0-9].*//')
  version="$major.$minor.$((patch + 1))-ci.${GITHUB_RUN_NUMBER:-0}"
fi
case "$version" in
  [0-9]*.[0-9]*.[0-9]*) ;;
  *) echo "version $version is not like 1.2.3 or 1.2.3-rc.1" >&2; exit 1 ;;
esac
if [ -n "$latest" ] && [ "v$version" = "$latest" ]; then
  # Re-running a release: upgrade from the one before it is not known here,
  # so the test upgrades from a build of this code at 0.0.0.
  latest=""
fi
echo "version=$version"
previous=0.0.0
[ -z "$latest" ] || previous=${latest#v}
echo "previous=$previous"
echo "previous_release=$latest"
