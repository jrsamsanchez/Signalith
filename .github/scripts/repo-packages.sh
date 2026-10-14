#!/bin/sh
# Downloads the .deb and .rpm packages of the newest Signalith releases (up
# to five, newest first, drafts and pre-releases left out) into OUTDIR, for
# the apt and dnf repositories. Needs the GitHub CLI and GH_TOKEN.
#   repo-packages.sh OUTDIR
set -eu
out=${1:?usage: repo-packages.sh OUTDIR}
mkdir -p "$out"
gh api "repos/$GITHUB_REPOSITORY/releases?per_page=50" \
  --jq '[.[] | select(.draft | not) | select(.prerelease | not) | select(.tag_name | test("^v[0-9]"))] | .[:5] | .[].tag_name' |
while read -r tag; do
  gh release download "$tag" --repo "$GITHUB_REPOSITORY" --dir "$out" --pattern '*.deb' --pattern '*.rpm'
done
ls "$out"
