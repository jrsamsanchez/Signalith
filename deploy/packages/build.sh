#!/bin/sh
# Builds Signalith's Linux packages: .deb and .rpm for amd64 and arm64.
#
#   deploy/packages/build.sh VERSION OUTDIR [BINDIR]
#
# BINDIR holds signalith-linux-amd64 and signalith-linux-arm64 (built here
# when it is left out). Needs nFPM on the PATH. To sign the packages, set
# SIGNALITH_GPG_KEY_FILE to an ASCII-armoured private key (and
# NFPM_PASSPHRASE when it has one).
set -eu
version=${1:?usage: build.sh VERSION OUTDIR [BINDIR]}
out=${2:?usage: build.sh VERSION OUTDIR [BINDIR]}
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
mkdir -p "$out"
out=$(cd "$out" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

bindir=${3:-}
if [ -z "$bindir" ]; then
  bindir=$work/bin
  for arch in amd64 arm64; do
    (cd "$root" && GOOS=linux GOARCH=$arch CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.version=$version" -o "$bindir/signalith-linux-$arch" ./cmd/signalith)
  done
fi
bindir=$(cd "$bindir" && pwd)

# The packaged unit is deploy/systemd/signalith.service with the program
# where packages put it.
stage=$work/stage
mkdir -p "$stage"
sed 's#/usr/local/bin/signalith#/usr/bin/signalith#g' "$root/deploy/systemd/signalith.service" > "$stage/signalith.service"
cp "$here"/nfpm.yaml "$here"/*.sh "$root/LICENSE" "$root/NOTICE" "$root/README.md" "$stage/"

export SIGNALITH_VERSION=$version
export NFPM_SIGNING_KEY_FILE=${SIGNALITH_GPG_KEY_FILE:-} NFPM_SIGNING_KEY_ID=${SIGNALITH_GPG_KEY_ID:-}
for arch in amd64 arm64; do
  export NFPM_ARCH=$arch
  cp "$bindir/signalith-linux-$arch" "$stage/signalith"
  for format in deb rpm; do
    (cd "$stage" && nfpm package --config nfpm.yaml --packager "$format" --target "$out/")
  done
done
ls -l "$out"
