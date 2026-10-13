#!/bin/sh
# Installs, upgrades and removes Signalith's .deb on this machine (a CI
# runner with systemd), checking the service and signing in each time.
#   test-deb.sh PREVIOUS.deb NEW.deb NEW_VERSION
set -eu
prev=$(realpath "$1"); new=$(realpath "$2"); want=$3
tmp=$(mktemp -d)

up() {
  systemctl is-active --quiet signalith || { sudo journalctl -u signalith --no-pager | tail -50; exit 1; }
  for i in $(seq 1 30); do
    curl -skf -o /dev/null https://localhost:8080/livez && return 0
    sleep 2
  done
  echo "Signalith does not answer on https://localhost:8080"; sudo journalctl -u signalith --no-pager | tail -50; exit 1
}
signin() {
  curl -skf -o /dev/null -H 'Content-Type: application/json' \
    -d "$(jq -n --arg p "$1" '{username: "admin", password: $p}')" https://localhost:8080/api/login
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
sudo apt-get purge -y signalith
echo "The .deb installs, upgrades and removes cleanly."
