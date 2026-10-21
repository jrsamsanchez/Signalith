#!/bin/sh
# Copyright 2026 The Signalith authors
# SPDX-License-Identifier: Apache-2.0
# Usage: docker-release.sh VERSION IMAGE DIGEST OUT
# Makes OUT/signalith-VERSION-docker.tar.gz: the Docker quick start
# (deploy/docker) with Signalith's image locked to the release's digest,
# IMAGE:VERSION@DIGEST, so what runs is exactly what the release built and
# signed, whatever happens to its tag later. SIGNALITH_VERSION no longer
# changes it. Run from the repository's top folder.
set -eu
version=$1 image=$2 digest=$3 out=$4
if ! printf '%s\n' "$digest" | grep -Eqx 'sha256:[0-9a-f]{64}'; then
  echo "docker-release.sh: digest $digest is not sha256:<64 hex>" >&2; exit 1
fi
name="signalith-$version-docker"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/$name/deploy/docker"
cp -R deploy/docker/opensearch deploy/docker/signalith.yaml "$tmp/$name/deploy/docker/"
cp LICENSE NOTICE "$tmp/$name/"
pinned="$image:$version@$digest"
for f in docker-compose.yml docker-compose.server.yml; do
  # The image, and pull only when missing: a digest never changes.
  {
    echo "# From the Signalith $version release (signalith-$version-docker.tar.gz):"
    echo "# Signalith's image is locked to $digest, the one the"
    echo "# release built and signed, and SIGNALITH_VERSION does not change it. To"
    echo "# update, unpack the next release's file and run step 1 from its folder:"
    echo "# it is the same Compose project, so the data is kept."
    echo "#"
    sed -e "s|ghcr.io/jrsamsanchez/signalith:\${SIGNALITH_VERSION:-[^}]*}|$pinned|" \
      -e "\\|image: $pinned|{n;s/pull_policy: always/pull_policy: missing/;}" \
      "deploy/docker/$f"
  } > "$tmp/$name/deploy/docker/$f"
  if grep -q 'SIGNALITH_VERSION:-' "$tmp/$name/deploy/docker/$f" || ! grep -qF "image: $pinned" "$tmp/$name/deploy/docker/$f"; then
    echo "docker-release.sh: $f still has an image that isn't locked to $digest" >&2; exit 1
  fi
done
tar -C "$tmp" -czf "$out/$name.tar.gz" "$name"
echo "made $out/$name.tar.gz with $pinned"
