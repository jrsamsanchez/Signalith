FROM golang:1.26.9@sha256:d7722066f0b60ceccb6c0643cbed1f5f9e15506ac237146c95333504d7805d89 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/signalith ./cmd/signalith
RUN mkdir -p /out/data/detections /out/data/lookups /out/data/dashboards /out/data/archive && chmod 700 /out/data/archive

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
# Web UI and API (HTTPS), syslog, and syslog over TLS (see
# deploy/docker/signalith.yaml).
EXPOSE 8080 5514/udp 5514/tcp 6514/tcp
ENTRYPOINT ["/usr/local/bin/signalith"]
CMD ["serve", "-c", "/etc/signalith/signalith.yaml"]
