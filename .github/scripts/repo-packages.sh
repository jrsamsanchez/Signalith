#!/bin/sh
# Copyright 2026 The Signalith authors
# SPDX-License-Identifier: Apache-2.0
# Downloads the .deb and .rpm packages of the newest Signalith releases (up
# to five, newest first, drafts and pre-releases left out) into OUTDIR, for
# the apt and dnf repositories, which deploy/repos/build.sh then signs. So
# that it signs only what the Release workflow built, each package must
# carry that release's build provenance: an attestation made by
# release.yml at the release's own tag. One that does not stops the run.
# Needs the GitHub CLI and GH_TOKEN (with attestations: read).
#   repo-packages.sh OUTDIR
set -eu
out=${1:?usage: repo-packages.sh OUTDIR}
mkdir -p "$out"
tags=$(gh api "repos/$GITHUB_REPOSITORY/releases?per_page=50" \
  --jq '[.[] | select(.draft | not) | select(.prerelease | not) | select(.tag_name | test("^v[0-9]"))] | .[:5] | .[].tag_name')
for tag in $tags; do
  case "$tag" in
    *[!A-Za-z0-9.-]*) echo "unexpected release tag: $tag" >&2; exit 1 ;;
  esac
  dir=$(mktemp -d)
  gh release download "$tag" --repo "$GITHUB_REPOSITORY" --dir "$dir" --pattern '*.deb' --pattern '*.rpm'
  for f in "$dir"/*; do
    [ -f "$f" ] || continue
    gh attestation verify "$f" --repo "$GITHUB_REPOSITORY" \
      --cert-identity "https://github.com/$GITHUB_REPOSITORY/.github/workflows/release.yml@refs/tags/$tag" \
      --cert-oidc-issuer https://token.actions.githubusercontent.com >/dev/null ||
      { echo "$(basename "$f") from $tag has no build provenance from its release; not signing it." >&2; exit 1; }
    mv "$f" "$out/"
  done
  rm -rf "$dir"
done
ls "$out"
