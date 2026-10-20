FROM golang:1.27.2@sha256:820153096fda4de6ac1b7194d12e416b7dd8f4e9a33d17e0345b111b945162d8 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/signalith ./cmd/signalith
# The Signalith Agent's programs, which Signalith hands to the computers it
# is installed on (docs/signalith-agent.md).
RUN for p in linux-amd64 linux-arm64 windows-amd64 darwin-amd64 darwin-arm64; do \
      ext=''; [ "${p%-*}" = windows ] && ext=.exe; \
      GOOS=${p%-*} GOARCH=${p#*-} CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
        -o /out/agents/signalith-agent-$p$ext ./cmd/signalith-agent || exit 1; \
    done
# Signed with the release key when the build is given it as the secret
# agent_key (the Release workflow does), so agents update themselves to
# them. The key stays out of the image and its layers.
RUN --mount=type=secret,id=agent_key \
    if [ -s /run/secrets/agent_key ]; then \
      SIGNALITH_AGENT_KEY="$(cat /run/secrets/agent_key)" /out/signalith agent-programs sign -version "${VERSION}" -dir /out/agents; \
    fi
RUN mkdir -p /out/data/detections /out/data/lookups/geoip /out/data/dashboards /out/data/archive && chmod 700 /out/data/archive

# Debian slim rather than distroless, for Nmap: the Vulnerabilities page
# scans networks with it (docs/vulnerabilities.md). Only Nmap, the CA
# certificates (for CVE lookups over HTTPS) and time zones are added, and
# Signalith runs as the same unprivileged user as before (65532).
FROM debian:13-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f
RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap ca-certificates tzdata \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -g 65532 nonroot \
 && useradd -u 65532 -g 65532 -d /home/nonroot -m -s /usr/sbin/nologin nonroot
USER 65532:65532
COPY --from=build /out/signalith /usr/local/bin/signalith
COPY --from=build /out/agents /usr/share/signalith/agents
# Writable folders for custom detections, lookups, dashboards and archived
# days, owned by the nonroot user.
COPY --from=build --chown=65532:65532 /out/data /var/lib/signalith
# SIGNALITH_STATE_DIR holds what Signalith makes for itself: its master key
# (keys/), its HTTPS certificate (tls/), and this server's identity
# (node.id) and its lock (cluster/).
ENV SIGNALITH_STATE_DIR=/var/lib/signalith \
    SIGNALITH_DETECTIONS_DIR=/var/lib/signalith/detections \
    SIGNALITH_LOOKUPS_DIR=/var/lib/signalith/lookups \
    SIGNALITH_DASHBOARDS_DIR=/var/lib/signalith/dashboards \
    SIGNALITH_ARCHIVE_DIR=/var/lib/signalith/archive
# Web UI and API (HTTPS), agents (HTTPS), syslog, and syslog over TLS (see
# deploy/docker/signalith.yaml).
EXPOSE 9000 7779 5514/udp 5514/tcp 6514/tcp
ENTRYPOINT ["/usr/local/bin/signalith"]
CMD ["serve", "-c", "/etc/signalith/signalith.yaml"]
