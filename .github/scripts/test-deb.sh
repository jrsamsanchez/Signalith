#!/bin/sh
# Copyright 2026 The Signalith authors
# SPDX-License-Identifier: Apache-2.0
# Installs, upgrades and removes Signalith's .deb on this machine (a CI
# runner with systemd), checking the service and signing in each time.
#   test-deb.sh PREVIOUS.deb NEW.deb NEW_VERSION
set -eu
prev=$(realpath "$1"); new=$(realpath "$2"); want=$3
tmp=$(mktemp -d)

# The web port: 9000, or 8080 for a config written before 0.3, which an
# upgrade keeps.
port=''
up() {
  systemctl is-active --quiet signalith || { sudo journalctl -u signalith --no-pager | tail -50; exit 1; }
  for i in $(seq 1 30); do
    for p in 9000 8080; do
      curl -skf -o /dev/null "https://localhost:$p/livez" && { port=$p; return 0; }
    done
    sleep 2
  done
  echo "Signalith does not answer on https://localhost:9000 (or 8080)"; sudo journalctl -u signalith --no-pager | tail -50; exit 1
}
# The previous release named the built-in admin admin, which the upgrade
# and a new install over the kept config both keep.
signin() {
  curl -skf -o /dev/null -H 'Content-Type: application/json' \
    -d "$(jq -n --arg p "$1" '{username: "admin", password: $p}')" "https://localhost:$port/api/login"
}

echo "== Install $prev"
sudo apt-get install -y "$prev" | tee "$tmp/install.txt"
grep -q "sudo signalith initial-password" "$tmp/install.txt"
up
password=$(sudo signalith initial-password)
signin "$password"
sudo test -f /var/lib/signalith/keys/master.key
test "$(sudo stat -c %U /var/lib/signalith/keys/master.key)" = signalith
test "$(sudo stat -c %U:%a /etc/signalith/initial-admin-password)" = root:600
test "$(sudo stat -c %U:%G:%a /etc/signalith/signalith.yaml)" = root:signalith:640
# The password is not in the installer's output.
if grep -qF "$password" "$tmp/install.txt"; then echo "the password was printed"; exit 1; fi

echo "== Upgrade to $new"
sudo apt-get install -y "$new"
up
signalith version | grep -F "$want"
test "$(sudo signalith initial-password)" = "$password"
signin "$password"

echo "== Remove"
sudo apt-get remove -y signalith
if systemctl is-active --quiet signalith; then echo "the service still runs"; exit 1; fi
test ! -e /usr/bin/signalith
sudo test -f /etc/signalith/signalith.yaml
sudo test -f /var/lib/signalith/keys/master.key

echo "== Install again: the kept config and password are used"
sudo apt-get install -y "$new"
up
signin "$password"

echo "== signalith opensearch install sets up OpenSearch, and Signalith uses it"
# The pinned SHA-512 is the one OpenSearch publishes for the release.
status=$(sudo signalith opensearch status); echo "$status"
rel=$(echo "$status" | sed -n 's/^Release installed: \([^,]*\), SHA-512 .*/\1/p')
pin=$(echo "$status" | sed -n 's/^Release installed: .*, SHA-512 \([0-9a-f]*\)$/\1/p')
published=$(curl -fsSL "$rel.sha512" | awk '{print $1}')
# The arm64 release's pin too, which no runner here installs: read from
# the source this package was built from.
arm=${rel%-linux-x64.tar.gz}-linux-arm64.tar.gz
armpin=$(python3 - "$(dirname "$0")/../../internal/oslocal/oslocal.go" <<'PY'
import re, sys
src = open(sys.argv[1]).read()
m = re.search(r'"linux/arm64":\s*\{.*?SHA512:\s*((?:"[0-9a-f]*"\s*\+?\s*)+)', src, re.S)
print("".join(re.findall(r'"([0-9a-f]*)"', m.group(1))) if m else "")
PY
)
armpublished=$(curl -fsSL "$arm.sha512" | awk '{print $1}')
bad=no
if [ -z "$rel" ] || [ "$published" != "$pin" ]; then
  echo "::error::The pinned SHA-512 for $rel is '$pin'; OpenSearch publishes $published"; bad=yes
fi
if [ "$armpublished" != "$armpin" ]; then
  echo "::error::The pinned SHA-512 for $arm is '$armpin'; OpenSearch publishes $armpublished"; bad=yes
fi
[ "$bad" = no ] || exit 1
sudo signalith opensearch install
systemctl is-active --quiet signalith-opensearch
pid=$(systemctl show -p MainPID --value signalith-opensearch)
test "$(ps -o user= -p "$pid")" = signalith-opensearch
osport=$(sudo jq -r .port /var/lib/signalith-opensearch/installed.json)
listen=$(ss -Hltn "sport = :$osport" | awk '{print $4}' | sed 's/:[0-9]*$//' | sort -u | tr '\n' ' ')
if [ "$listen" != "127.0.0.1 " ]; then echo "OpenSearch listens on $listen, want 127.0.0.1 only"; exit 1; fi
code=$(curl -sk -o /dev/null -w '%{http_code}' -u admin:admin "https://127.0.0.1:$osport/")
if [ "$code" != 401 ]; then echo "OpenSearch answered $code to the demo password, want 401"; exit 1; fi
test "$(sudo stat -c %U:%a /var/lib/signalith-opensearch)" = root:711
test "$(sudo stat -c %U:%a /var/lib/signalith-opensearch/ca)" = root:700
test "$(sudo stat -c %U:%G:%a /etc/signalith/opensearch/opensearch-client-key.pem)" = root:signalith:640
test "$(sudo stat -c %U /var/lib/signalith-opensearch/data)" = signalith-opensearch
# Its settings are root's, which it may read but not change.
test "$(sudo stat -c %U:%G:%a /var/lib/signalith-opensearch/config)" = root:signalith-opensearch:750
test "$(sudo stat -c %U:%G:%a /var/lib/signalith-opensearch/config/opensearch.yml)" = root:signalith-opensearch:640
test "$(sudo stat -c %U:%G:%a /var/lib/signalith-opensearch/config/opensearch.keystore)" = root:signalith-opensearch:640
up
ready=no
for _ in $(seq 1 40); do
  curl -skf -o /dev/null "https://localhost:$port/readyz" && { ready=yes; break; }
  sleep 3
done
if [ "$ready" != yes ]; then
  echo "Signalith is not ready with the OpenSearch on this computer"
  sudo journalctl -u signalith --no-pager | tail -50; sudo journalctl -u signalith-opensearch --no-pager | tail -50; exit 1
fi
signin "$password"
echo "== Run again: it is installed, and still runs"
sudo signalith opensearch install
systemctl is-active --quiet signalith-opensearch
echo "== signalith opensearch remove keeps its data"
sudo signalith opensearch remove
if systemctl is-active --quiet signalith-opensearch; then echo "OpenSearch still runs"; exit 1; fi
test ! -e /etc/systemd/system/signalith-opensearch.service
test ! -e /opt/signalith-opensearch
sudo test -d /var/lib/signalith-opensearch/data
sudo apt-get purge -y signalith
echo "The .deb installs, upgrades and removes cleanly, and sets up OpenSearch."
