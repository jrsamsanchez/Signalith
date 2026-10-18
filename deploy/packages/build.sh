#!/bin/sh
# Builds Signalith's Linux packages: .deb and .rpm for amd64 and arm64.
#
#   deploy/packages/build.sh VERSION OUTDIR [BINDIR]
#
# BINDIR holds signalith-linux-amd64 and signalith-linux-arm64 (built here
# when it is left out). The Signalith Agent's programs, which the server
# hands to the computers it is installed on (docs/signalith-agent.md), are
# built here for every platform the packages carry, and signed when
# SIGNALITH_AGENT_KEY holds the release key. Needs nFPM on the PATH. To sign the packages, set
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
mkdir -p "$stage/agents"
for p in linux-amd64 linux-arm64 windows-amd64 darwin-amd64 darwin-arm64; do
  ext=''
  [ "${p%-*}" = windows ] && ext=.exe
  (cd "$root" && GOOS=${p%-*} GOARCH=${p#*-} CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X main.version=$version" -o "$stage/agents/signalith-agent-$p$ext" ./cmd/signalith-agent)
done
# With the release key (the Release workflow passes it), sign the agent
# programs so agents update themselves to them (docs/releasing.md).
if [ -n "${SIGNALITH_AGENT_KEY:-}" ]; then
  (cd "$root" && go run ./cmd/signalith agent-programs sign -version "$version" -dir "$stage/agents")
fi

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
