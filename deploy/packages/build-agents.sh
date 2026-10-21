#!/bin/sh
# Copyright 2026 The Signalith authors
# SPDX-License-Identifier: Apache-2.0
# Builds the Signalith Agent's programs, which a server hands to the
# computers it is installed on (docs/signalith-agent.md), for every
# platform the agent runs on, and signs them when SIGNALITH_AGENT_KEY holds
# the release key (docs/releasing.md). The .deb, .rpm, .msi and Windows
# zip all carry the same ones.
#
#   deploy/packages/build-agents.sh VERSION OUTDIR
set -eu
version=${1:?usage: build-agents.sh VERSION OUTDIR}
out=${2:?usage: build-agents.sh VERSION OUTDIR}
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
mkdir -p "$out"
out=$(cd "$out" && pwd)
for p in linux-amd64 linux-arm64 windows-amd64 darwin-amd64 darwin-arm64; do
  ext=''
  [ "${p%-*}" = windows ] && ext=.exe
  (cd "$root" && GOOS=${p%-*} GOARCH=${p#*-} CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X main.version=$version" -o "$out/signalith-agent-$p$ext" ./cmd/signalith-agent)
done
if [ -n "${SIGNALITH_AGENT_KEY:-}" ]; then
  (cd "$root" && go run ./cmd/signalith agent-programs sign -version "$version" -dir "$out")
fi
