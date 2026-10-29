#!/bin/bash
# Copyright 2026 The Signalith authors
# SPDX-License-Identifier: Apache-2.0
# Sets up the public test lab on its one server. Terraform puts this script
# on the server, and testlab-setup.service runs it once after the first
# boot, writing to /var/log/testlab-setup.log.
#
# Each step leaves a mark in /root/testlab/done when it finishes, so
# running "sudo testlab-setup" again carries on from the step that failed.
#
# What it sets up (README.md):
#   1. the data volume, for OpenSearch's data and its snapshots;
#   2. Signalith from its signed apt repository, as any Linux install;
#   3. OpenSearch from its apt repository on 127.0.0.1, with certificates
#      of its own CA and no passwords;
#   4. Signalith pointed at it, on 127.0.0.1 behind Caddy;
#   5. Caddy: HTTPS for the public name, the only way in;
#   6. this server's own logs (sign-ins, journal, audit) sent to Signalith;
#   7. sample data and a small live feed of recorded attack events;
#   8. nightly snapshots and backups, outbound limits, automatic updates.
set -euo pipefail
umask 077
export HOME=/root
export DEBIAN_FRONTEND=noninteractive

LAB=/root/testlab
DONE=$LAB/done
mkdir -p "$DONE"

DOMAIN=$(jq -r .domain "$LAB/settings.json")
EMAIL=$(jq -r '.admin_email // ""' "$LAB/settings.json")
OPENSEARCH_VERSION=3.9.0
DATA=/srv/data
CA=/var/lib/signalith/tls/ca.pem

say() { printf '%s  %s\n' "$(date -u +%H:%M:%S)" "$*"; }
fail() {
  say "FAILED: $*"
  say "Fix the cause, then run: sudo testlab-setup"
  exit 1
}
trap 'say "FAILED at line $LINENO. Run sudo testlab-setup again to carry on."' ERR

step() {
  local name=$1
  shift
  if [ -e "$DONE/$name" ]; then
    say "  done before: $name"
    return
  fi
  say "Starting: $name"
  "$@"
  touch "$DONE/$name"
  say "Done: $name"
}

retry() {
  local tries=$1
  shift
  local i
  for ((i = 1; i <= tries; i++)); do
    if "$@"; then return 0; fi
    sleep 10
  done
  return 1
}

# sg runs signalith as the account its service runs as, with the
# service's folders.
sg() {
  sudo -u signalith env SIGNALITH_STATE_DIR=/var/lib/signalith \
    SIGNALITH_DETECTIONS_DIR=/var/lib/signalith/detections \
    SIGNALITH_LOOKUPS_DIR=/var/lib/signalith/lookups \
    SIGNALITH_DASHBOARDS_DIR=/var/lib/signalith/dashboards \
    SIGNALITH_ARCHIVE_DIR=/var/lib/signalith/archive \
    signalith "$@"
}

# ---- 1. the data volume ----

volume() {
  local vol
  vol=$(ls /dev/disk/by-id/scsi-0HC_Volume_* 2>/dev/null | head -n 1 || true)
  [ -n "$vol" ] || fail "no Hetzner volume attached"
  mkdir -p "$DATA"
  grep -q " $DATA " /etc/fstab || echo "$vol $DATA ext4 discard,nofail,defaults 0 0" >>/etc/fstab
  mountpoint -q "$DATA" || mount "$DATA"
}

# ---- 2. Signalith ----

signalith_package() {
  install -d -m 0755 /etc/apt/keyrings
  curl -fsSL -o /etc/apt/keyrings/signalith.asc https://signalith.io/apt/signalith.asc
  chmod 644 /etc/apt/keyrings/signalith.asc
  echo "deb [signed-by=/etc/apt/keyrings/signalith.asc] https://signalith.io/apt stable main" >/etc/apt/sources.list.d/signalith.list
  apt-get update -q
  apt-get install -y -q signalith
  say "  $(signalith version 2>/dev/null | head -n 1)"
}

# ---- 3. OpenSearch ----

opensearch() {
  rm -rf "$LAB/pki"
  signalith opensearch-certs -out "$LAB/pki" -node localhost -san localhost -san 127.0.0.1 >/dev/null
  local series="${OPENSEARCH_VERSION%%.*}.x"
  curl -fsSL https://artifacts.opensearch.org/publickeys/opensearch-release.pgp | gpg --dearmor --batch --yes -o /usr/share/keyrings/opensearch-keyring
  echo "deb [signed-by=/usr/share/keyrings/opensearch-keyring] https://artifacts.opensearch.org/releases/bundle/opensearch/$series/apt stable main" >"/etc/apt/sources.list.d/opensearch-$series.list"
  apt-get update -q
  if ! dpkg -s opensearch >/dev/null 2>&1; then
    # No demo security settings: this lab's own are put in place below. The
    # package still asks for a demo admin password, which is never used.
    DISABLE_INSTALL_DEMO_CONFIG=true OPENSEARCH_INITIAL_ADMIN_PASSWORD="Lab-$(openssl rand -hex 16)" \
      apt-get install -y -q "opensearch=$OPENSEARCH_VERSION"
  fi
  # Upgraded on purpose with Signalith, never by unattended-upgrades.
  apt-mark hold opensearch >/dev/null
  systemctl stop opensearch 2>/dev/null || true
  install -d -o opensearch -g opensearch "$DATA/opensearch" "$DATA/snapshots"
  # The package's demo certificates stop the security plugin from starting.
  rm -f /etc/opensearch/*.pem
  rm -rf /etc/opensearch/certs
  cp -r "$LAB/pki/opensearch/certs" /etc/opensearch/certs
  chown -R opensearch:opensearch /etc/opensearch/certs
  chmod 700 /etc/opensearch/certs
  chmod 600 /etc/opensearch/certs/*
  install -d -o opensearch -g opensearch /etc/opensearch/opensearch-security
  install -m 600 -o opensearch -g opensearch "$LAB"/pki/opensearch/opensearch-security/*.yml /etc/opensearch/opensearch-security/
  cat >/etc/opensearch/opensearch.yml <<YML
cluster.name: signalith-testlab
node.name: localhost
path.data: $DATA/opensearch
path.logs: /var/log/opensearch
path.repo: ["$DATA/snapshots"]
network.host: 127.0.0.1
discovery.type: single-node

YML
  cat "$LAB/pki/opensearch/add-to-opensearch.yml" >>/etc/opensearch/opensearch.yml
  # A third of the memory for the heap: Signalith and Caddy share the rest.
  local heap
  heap=$(awk '/MemTotal/ { print int($2 / 1024 / 3) }' /proc/meminfo)
  mkdir -p /etc/opensearch/jvm.options.d
  printf -- '-Xms%sm\n-Xmx%sm\n' "$heap" "$heap" >/etc/opensearch/jvm.options.d/testlab-heap.options
  sysctl -q -w vm.max_map_count=262144
  echo vm.max_map_count=262144 >/etc/sysctl.d/90-opensearch.conf
  systemctl enable -q opensearch
  systemctl restart opensearch
  retry 60 os_admin /_cluster/health >/dev/null || fail "OpenSearch did not start. See: journalctl -u opensearch -n 50"
  # The admin certificate stays with root, for snapshots.
  install -d -m 700 "$LAB/os-admin"
  cp "$LAB/pki/opensearch/certs/root-ca.pem" "$LAB/pki/opensearch/certs/admin.pem" "$LAB/pki/opensearch/certs/admin-key.pem" "$LAB/os-admin/"
  rm -f /etc/opensearch/certs/admin.pem /etc/opensearch/certs/admin-key.pem
  os_admin -X PUT /_snapshot/testlab -H 'Content-Type: application/json' \
    -d "{\"type\": \"fs\", \"settings\": {\"location\": \"$DATA/snapshots\"}}" >/dev/null
}

os_admin() {
  local path=$1
  shift
  local c=$LAB/os-admin
  [ -e "$c/admin.pem" ] || c=$LAB/pki/opensearch/certs
  curl -fsS --cacert "$c/root-ca.pem" --cert "$c/admin.pem" --key "$c/admin-key.pem" "$@" "https://localhost:9200$path"
}

# ---- 4. Signalith's settings ----

readyz() { curl -fsS --cacert "$CA" -o /dev/null https://localhost:9000/readyz; }

signalith_config() {
  systemctl stop signalith
  install -m 400 -o signalith -g signalith "$LAB"/pki/signalith/opensearch-*.pem /etc/signalith/
  python3 - /etc/signalith/signalith.yaml "https://$DOMAIN" "$DOMAIN" <<'EOF'
import sys, yaml
path, public, domain = sys.argv[1:]
with open(path) as f:
    c = yaml.safe_load(f)
s = c.setdefault("server", {})
# Only Caddy, on this server, reaches Signalith.
s["listen"] = "127.0.0.1:9000"
s["agent_listen"] = "127.0.0.1:7779"
s["public_url"] = public
s["trusted_proxies"] = ["127.0.0.1", "::1"]
s["client_header"] = "x-forwarded-for"
tls = s.setdefault("tls", {})
tls["names"] = sorted(set(tls.get("names") or []) | {domain, "localhost"})
tls["ca_scope"] = "strict"
o = c.setdefault("opensearch", {})
o["url"] = "https://localhost:9200"
o["ca_file"] = "/etc/signalith/opensearch-ca.pem"
o["cert_file"] = "/etc/signalith/opensearch-client.pem"
o["key_file"] = "/etc/signalith/opensearch-client-key.pem"
o.pop("username", None)
o.pop("password", None)
with open(path, "w") as f:
    f.write("# Written by the test lab setup (deploy/testlab/testlab-setup.sh).\n")
    yaml.safe_dump(c, f, sort_keys=False, default_flow_style=False)
EOF
  # The first start made a certificate before the lab's names were set.
  rm -rf /var/lib/signalith/tls
  systemctl start signalith
  retry 60 readyz || fail "Signalith did not get ready. See: journalctl -u signalith -n 50"
  sg validate >/dev/null || fail "signalith validate found a problem (run it to see)."
}

# ---- 5. Caddy ----

caddy() {
  curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/gpg.key | gpg --dearmor --batch --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  echo "deb [signed-by=/usr/share/keyrings/caddy-stable-archive-keyring.gpg] https://dl.cloudsmith.io/public/caddy/stable/deb/debian any-version main" >/etc/apt/sources.list.d/caddy-stable.list
  apt-get update -q
  apt-get install -y -q caddy
  install -m 644 "$CA" /etc/caddy/signalith-ca.pem
  install -d -o caddy -g caddy /var/log/caddy
  local global=""
  [ -z "$EMAIL" ] || global="{
	email $EMAIL
}
"
  cat >/etc/caddy/Caddyfile <<EOF
$global
$DOMAIN {
	log {
		output file /var/log/caddy/access.log {
			roll_size 50MiB
			roll_keep 10
		}
		format json
	}
	encode zstd gzip

	# Agents, senders and joining servers use tokens rather than a
	# sign-in: the test lab takes no data from outside.
	@closed path /api/ingest* /api/otlp/* /services/collector* /api/osquery/* /api/sensor/* /api/agent/* /api/cluster/join* /api/syslog/* /api/scim/* /metrics*
	respond @closed 404

	reverse_proxy https://127.0.0.1:9000 {
		# The client's own address, never one it sent.
		header_up X-Forwarded-For {remote_host}
		transport http {
			tls_trusted_ca_certs /etc/caddy/signalith-ca.pem
			tls_server_name localhost
		}
	}
}
EOF
  caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null
  systemctl enable -q caddy
  systemctl reload-or-restart caddy
}

# ---- 6. this server's own logs ----

# The built-in admin must replace the first password Signalith made before
# anything else, so the lab gives it a new random one, kept for root in
# $LAB/admin-password (and is shown to the admin once, at the end).
admin_password() {
  if [ -s "$LAB/admin-password" ]; then cat "$LAB/admin-password"; else cat /etc/signalith/initial-admin-password; fi
}

# admin_user is the built-in admin's name in the config:
# signalithadmin on a new install, admin on one made before 0.3.1.
admin_user() {
  local u
  u=$(awk '$1 == "admin_user:" { gsub(/["\047]/, "", $2); print $2; exit }' /etc/signalith/signalith.yaml 2>/dev/null)
  echo "${u:-signalithadmin}"
}

# login signs in as the built-in admin, keeping the session in the jar $1.
# The password goes to curl on its input, not its command line. One whose
# change Signalith took though curl did not hear back is still in
# admin-password.new.
login() {
  local pw
  for pw in "" "$LAB/admin-password.new"; do
    if [ -n "$pw" ]; then [ -s "$pw" ] || return 1; fi
    if jq -n --rawfile p <(if [ -n "$pw" ]; then cat "$pw"; else admin_password; fi) --arg u "$(admin_user)" '{username: $u, password: ($p | rtrimstr("\n"))}' |
      curl -fsS -c "$1" --cacert /var/lib/signalith/tls/ca.pem -H 'Content-Type: application/json' -H 'Origin: https://localhost:9000' \
        --data-binary @- https://localhost:9000/api/login >/dev/null; then
      [ -z "$pw" ] || mv "$pw" "$LAB/admin-password"
      return 0
    fi
  done
  return 1
}

# api calls Signalith's API, signed in as the built-in
# admin (as the Add data page would).
api() {
  local ca=/var/lib/signalith/tls/ca.pem jar=$LAB/cookies
  login "$jar"
  if [ "$(curl -fsS -b "$jar" --cacert "$ca" https://localhost:9000/api/me | jq -r .must_change_password)" = true ]; then
    (umask 077 && openssl rand -base64 24 | tr -d '/+=\n' >"$LAB/admin-password.new")
    jq -n --rawfile c <(admin_password) --rawfile n "$LAB/admin-password.new" \
      '{current_password: ($c | rtrimstr("\n")), new_password: $n}' |
      curl -fsS -b "$jar" --cacert "$ca" -H 'Content-Type: application/json' -H 'Origin: https://localhost:9000' \
        --data-binary @- https://localhost:9000/api/me/password >/dev/null
    mv "$LAB/admin-password.new" "$LAB/admin-password"
    login "$jar"
  fi
  curl -fsS -b "$jar" --cacert "$ca" -H 'Origin: https://localhost:9000' "https://localhost:9000$1"
  rm -f "$jar"
}

# Fluent Bit with the config the Add data page gives for Linux: sign-ins
# and the journal, the audit log and web server logs.
own_logs() {
  local token cfg
  token=$(sg tokens create -purpose linux "Test lab server $(date +%m%d-%H%M%S)")
  cfg=$(api "/api/agents/config?os=linux&server=https://localhost:9000")
  . /etc/os-release
  curl -fsSL https://packages.fluentbit.io/fluentbit.key | gpg --dearmor --batch --yes -o /usr/share/keyrings/fluentbit-keyring.gpg
  echo "deb [signed-by=/usr/share/keyrings/fluentbit-keyring.gpg] https://packages.fluentbit.io/ubuntu/$VERSION_CODENAME $VERSION_CODENAME main" >/etc/apt/sources.list.d/fluent-bit.list
  apt-get update -q >/dev/null
  apt-get install -y -q fluent-bit auditd >/dev/null
  jq -r .config <<<"$cfg" | sed "s/$(jq -r .token_placeholder <<<"$cfg")/$token/g" >"$LAB/fluent-bit.conf"
  install -D -m 600 "$LAB/fluent-bit.conf" "$(jq -r .config_path <<<"$cfg")"
  jq -r .ca <<<"$cfg" >"$LAB/signalith-ca.pem"
  install -D -m 644 "$LAB/signalith-ca.pem" "$(jq -r .ca_path <<<"$cfg")"
  rm -f "$LAB/fluent-bit.conf" "$LAB/signalith-ca.pem"
  # The audit log rules of the detection packs read the programs that run.
  echo '-a always,exit -F arch=b64 -S execve -k exec' >/etc/audit/rules.d/signalith.rules
  augenrules --load >/dev/null 2>&1 || true
  systemctl enable -q fluent-bit
  systemctl restart fluent-bit
}

# ---- 7. data for testers ----

sample_data() {
  sg sample-data load
  # A fresh week every Monday, so the sample never looks stale.
  cat >/etc/systemd/system/testlab-sample.service <<'EOF'
[Unit]
Description=Signalith test lab: load the sample week again

[Service]
Type=oneshot
User=signalith
Environment=SIGNALITH_STATE_DIR=/var/lib/signalith SIGNALITH_LOOKUPS_DIR=/var/lib/signalith/lookups SIGNALITH_DETECTIONS_DIR=/var/lib/signalith/detections SIGNALITH_DASHBOARDS_DIR=/var/lib/signalith/dashboards SIGNALITH_ARCHIVE_DIR=/var/lib/signalith/archive
ExecStart=/usr/bin/signalith sample-data remove
ExecStart=/usr/bin/signalith sample-data load
EOF
  cat >/etc/systemd/system/testlab-sample.timer <<'EOF'
[Unit]
Description=Signalith test lab: a fresh sample week every Monday

[Timer]
OnCalendar=Mon 05:00 UTC
Persistent=true

[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable -q --now testlab-sample.timer
}

# A trickle of the real recorded Windows and Sysmon events of the detection
# packs, sent as recorded, so detections fire through the day. The load
# generator is built from the source of the installed release.
live_feed() {
  local ver gov arch
  ver=$(dpkg-query -W -f '${Version}' signalith | cut -d- -f1)
  rm -rf "$LAB/src"
  git clone -q --depth 1 --branch "v$ver" https://github.com/jrsamsanchez/Signalith.git "$LAB/src"
  gov=$(awk '$1 == "go" { print $2 }' "$LAB/src/go.mod")
  arch=$(dpkg --print-architecture)
  if ! /usr/local/go/bin/go version 2>/dev/null | grep -q "go$gov "; then
    rm -rf /usr/local/go
    curl -fsSL "https://go.dev/dl/go$gov.linux-$arch.tar.gz" | tar -C /usr/local -xz
  fi
  (cd "$LAB/src" && CGO_ENABLED=0 /usr/local/go/bin/go build -trimpath -o /usr/local/bin/signalith-loadgen ./cmd/signalith-loadgen)
  rm -rf /usr/local/go "$LAB/src" /root/go /root/.cache/go-build
  install -d -m 700 /etc/signalith-feed
  sg tokens create -purpose windows "Test lab live feed $(date +%m%d-%H%M%S)" >/etc/signalith-feed/token.txt
  install -m 644 "$CA" /etc/signalith-feed/ca.pem
  # One recorded event every ten seconds, sent as recorded: enough for the
  # detections to keep finding things, few enough to read.
  cat >/etc/signalith-feed/feed.yaml <<'EOF'
name: testlab-feed
description: The test lab's live feed of recorded Windows and Sysmon events.
agent_targets: [https://localhost:7779]
ca_file: /etc/signalith-feed/ca.pem
credentials:
  token_file: /run/credentials/testlab-feed.service/token
phases:
  - {name: feed, for: 87600h, agents: {n: 2, rate: 0.1, replay: {attack_share: 1}}}
EOF
  chmod 644 /etc/signalith-feed/ca.pem /etc/signalith-feed/feed.yaml
  cat >/etc/systemd/system/testlab-feed.service <<'EOF'
[Unit]
Description=Signalith test lab: live feed of recorded Windows events
After=signalith.service

[Service]
DynamicUser=yes
LoadCredential=token:/etc/signalith-feed/token.txt
ExecStart=/usr/local/bin/signalith-loadgen run -q -f /etc/signalith-feed/feed.yaml
Restart=always
RestartSec=60
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable -q --now testlab-feed
}

# ---- 8. backups, outbound limits, updates ----

backups() {
  install -d -m 700 "$DATA/backups"
  cat >/usr/local/sbin/testlab-backup <<EOF
#!/bin/sh
# Nightly: an OpenSearch snapshot (14 kept) and Signalith's own files.
set -eu
c=$LAB/os-admin
os() { curl -fsS --cacert "\$c/root-ca.pem" --cert "\$c/admin.pem" --key "\$c/admin-key.pem" "\$@"; }
os -X PUT "https://localhost:9200/_snapshot/testlab/nightly-\$(date -u +%Y%m%d)?wait_for_completion=true" >/dev/null
for s in \$(os https://localhost:9200/_snapshot/testlab/_all | jq -r '.snapshots[].snapshot' | sort | head -n -14); do
  os -X DELETE "https://localhost:9200/_snapshot/testlab/\$s" >/dev/null
done
SIGNALITH_STATE_DIR=/var/lib/signalith SIGNALITH_LOOKUPS_DIR=/var/lib/signalith/lookups SIGNALITH_DETECTIONS_DIR=/var/lib/signalith/detections \\
  SIGNALITH_DASHBOARDS_DIR=/var/lib/signalith/dashboards SIGNALITH_ARCHIVE_DIR=/var/lib/signalith/archive \\
  signalith backup -c /etc/signalith/signalith.yaml -o "$DATA/backups/signalith-\$(date -u +%Y%m%d).zip" >/dev/null
find "$DATA/backups" -name 'signalith-*' -mtime +14 -delete
EOF
  chmod 700 /usr/local/sbin/testlab-backup
  cat >/etc/systemd/system/testlab-backup.service <<'EOF'
[Unit]
Description=Signalith test lab: nightly snapshot and backup

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/testlab-backup
EOF
  cat >/etc/systemd/system/testlab-backup.timer <<'EOF'
[Unit]
Description=Signalith test lab: nightly snapshot and backup

[Timer]
OnCalendar=*-*-* 03:30 UTC
Persistent=true

[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable -q --now testlab-backup.timer
}

# Nothing on this server needs the cloud's metadata service after the
# first boot, and no service may reach it. OpenSearch talks to this server
# only. Signalith may reach the internet over HTTPS (feeds, content,
# vulnerability data), never a private or link-local address.
outbound() {
  cat >/etc/nftables.conf <<'EOF'
#!/usr/sbin/nft -f
flush ruleset
table inet testlab {
	chain output {
		type filter hook output priority 0; policy accept;
		ip daddr 169.254.169.254 drop
		oif lo accept
		meta skuid "opensearch" drop
		meta skuid "signalith" ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 169.254.0.0/16 } drop
		meta skuid "signalith" ip6 daddr { fc00::/7, fe80::/10 } drop
		meta skuid "signalith" tcp dport 443 accept
		meta skuid "signalith" drop
	}
}
EOF
  nft -c -f /etc/nftables.conf
  systemctl enable -q nftables
  systemctl restart nftables
}

updates() {
  cat >/etc/apt/apt.conf.d/52testlab-upgrades <<'EOF'
// Security updates every night; Signalith from its own repository too, so
// the lab runs each release soon after it is published.
Unattended-Upgrade::Origins-Pattern {
	"origin=${distro_id},archive=${distro_codename}-security";
	"site=signalith.io";
	"site=dl.cloudsmith.io,component=main";
};
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "04:30";
EOF
  echo 'APT::Periodic::Update-Package-Lists "1"; APT::Periodic::Unattended-Upgrade "1";' >/etc/apt/apt.conf.d/20auto-upgrades
}

step volume volume
step signalith signalith_package
step opensearch opensearch
step signalith-config signalith_config
step caddy caddy
step own-logs own_logs
step sample-data sample_data
step live-feed live_feed
step backups backups
step outbound outbound
step updates updates
say "Test lab ready. The built-in admin's password: sudo cat $LAB/admin-password"
