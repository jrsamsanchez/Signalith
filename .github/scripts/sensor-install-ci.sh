#!/bin/sh
# Copyright 2026 The Signalith authors
# SPDX-License-Identifier: Apache-2.0
# Installs a network sensor on this CI machine with the line the Add data
# page makes, sends it traffic, and checks what reaches Signalith; then
# runs the line again and uninstalls. Signalith runs at $SIGNALITH (the
# Docker quick start), trusted with $SIGNALITH_CA, signed in as an admin
# with the cookies in $COOKIES. Needs sudo, curl, jq, tcpdump, tcpreplay.
set -eu
: "${SIGNALITH:?}" "${SIGNALITH_CA:?}" "${COOKIES:?}"
work=${RUNNER_TEMP:-/tmp}/sensor-ci
mkdir -p "$work"
cd "$work"

api() {
  curl -fsS -b "$COOKIES" --cacert "$SIGNALITH_CA" -H "Origin: $SIGNALITH" "$@"
}

step() {
  printf '\n== %s\n' "$*"
}

# found says whether a search for $1 in the last hour matches an event.
found() {
  n=$(api -H 'Content-Type: application/json' -d "$(jq -n --arg q "$1" '{query: $q, earliest: "-1h"}')" \
    "$SIGNALITH/api/search" | jq -r '.matched // 0') || n=0
  [ "$n" -gt 0 ]
}

step "A capture port: cap0, fed from its peer cap1"
sudo ip link add cap0 type veth peer name cap1
sudo ip link set cap0 up
sudo ip link set cap1 up

step "The line, as the Add data page asks for it, with a new sensor token"
api -G "$SIGNALITH/api/sensor/install" --data-urlencode "server=$SIGNALITH" \
  --data-urlencode interface=cap0 --data-urlencode networks=10.99.0.0/16 >install.json
placeholder=$(jq -r .token_placeholder install.json)
token=$(api -H 'Content-Type: application/json' -d '{"name":"CI sensor","purpose":"sensor"}' "$SIGNALITH/api/agent-tokens" | jq -r .secret)
# One rule of our own, so an alert is certain.
printf '%s\n' 'alert http any any -> any any (msg:"Signalith CI request"; http.uri; content:"/signalith-ci"; sid:9900001; rev:1;)' >ci.rules
line=$(jq -r .linux install.json | sed "s|$placeholder|$token|")
line="$line --name ci-sensor --local-rules $work/ci.rules"
printf '%s\n' "$line" | sed "s|$token|<token>|"

# fake_fluent_bit runs a stand-in for a Fluent Bit already shipping logs
# somewhere else, from a unit file in the folder $1.
fake_fluent_bit() {
  sudo mkdir -p "$1"
  printf '[Service]\nExecStart=/bin/sleep infinity\n' | sudo tee "$1/fluent-bit.service" >/dev/null
  sudo systemctl daemon-reload
  sudo systemctl start fluent-bit.service
}
no_fake() {
  sudo systemctl stop fluent-bit.service || true
  sudo rm -f "$1/fluent-bit.service"
  sudo systemctl daemon-reload
}
# refused says the line ($1) stopped with $2, changing nothing.
refused() {
  if sh -c "$1" >vendor.out 2>&1; then cat vendor.out; echo "installed over a running fluent-bit.service"; exit 1; fi
  grep -q "$2" vendor.out || { cat vendor.out; exit 1; }
  if [ -e /etc/signalith-sensor ]; then echo "changed the machine before stopping"; exit 1; fi
  systemctl is-active --quiet fluent-bit.service || { echo "stopped the running fluent-bit.service"; exit 1; }
}

step "A Fluent Bit already running here for something else: the line stops, changing nothing"
fake_fluent_bit /run/systemd/system
refused "$line" "fluent-bit.service already runs here"

step "With --take-over, but its unit is a file of the admin's own in /etc/systemd/system: stops too"
no_fake /run/systemd/system
fake_fluent_bit /etc/systemd/system
refused "$line --take-over" "cannot be masked"
no_fake /etc/systemd/system

step "Install with --take-over: the other Fluent Bit is stopped"
fake_fluent_bit /run/systemd/system
sh -c "$line --take-over"
if systemctl is-active --quiet fluent-bit.service; then echo "the other fluent-bit.service still runs"; exit 1; fi

step "Traffic: HTTP and DNS on lo, captured, then replayed on the capture port"
python3 -m http.server 8099 --bind 127.0.0.1 >/dev/null 2>&1 &
web=$!
sleep 1
sudo timeout 15 tcpdump -i lo -w traffic.pcap 'port 8099 or port 53' >/dev/null 2>&1 &
sleep 2
for i in 1 2 3; do
  curl -s -o /dev/null "http://127.0.0.1:8099/signalith-ci?try=$i" || true
  getent hosts "example$i.com" >/dev/null || true
done
sleep 14
kill "$web" || true
sudo chmod 644 traffic.pcap
# Packets taken on lo carry checksums the kernel never filled in; a real
# capture port sees them filled in, so the copy replayed has them too.
tcprewrite --fixcsum -i traffic.pcap -o replay.pcap
for i in 1 2 3 4 5; do
  sudo tcpreplay -q -i cap1 replay.pcap
  sleep 5
done

step "What reaches Signalith (up to 3 minutes)"
want='sourcetype=zeek:conn|sourcetype=zeek:dns|sourcetype=suricata:alert signature_id=9900001|sourcetype=suricata:stats|sourcetype=sensor:status'
end=$(($(date +%s) + 180))
while :; do
  missing=''
  old=$IFS
  IFS='|'
  for q in $want; do
    found "$q" || missing="$missing [$q]"
  done
  IFS=$old
  [ -n "$missing" ] || break
  if [ "$(date +%s)" -ge "$end" ]; then
    echo "Not found:$missing"
    exit 1
  fi
  sleep 10
done
echo "All found: $want"
api "$SIGNALITH/api/agents" >agents.json
jq '.agents[] | select(.name == "ci-sensor") | .sensor' agents.json
jq -e '.agents[] | select(.name == "ci-sensor") | .sensor.rules_update == "ok"' agents.json

step "Again: nothing to change"
sh -c "$line" | tee rerun.txt
grep -q "Nothing to change" rerun.txt

step "How the units are locked down (for information)"
systemd-analyze security --no-pager signalith-zeek.service signalith-suricata.service signalith-fluent-bit.service || true

step "The Emerging Threats Open licence suricata-update downloaded"
for f in $(sudo find /var/lib/signalith-sensor/suricata/update/cache -name '*.tar.gz' 2>/dev/null); do
  sudo tar -xzOf "$f" --wildcards '*LICENSE*' 2>/dev/null | head -n 40 || true
done

step "Uninstall, with the copy of the script the sensor keeps"
# The output file is the CI user's, not root's.
# shellcheck disable=SC2024
sudo sh /usr/lib/signalith-sensor/install.sh --uninstall >uninstall.txt 2>&1 || { cat uninstall.txt; exit 1; }
cat uninstall.txt
left=''
# The capture port is put back as it was: not promiscuous, answering ARP.
flags=$(cat /sys/class/net/cap0/flags)
[ $((flags & 256)) -eq 0 ] && [ $((flags & 128)) -eq 0 ] || left="$left cap0-flags:$flags"
for u in signalith-zeek signalith-suricata signalith-fluent-bit signalith-sensor-status.timer signalith-suricata-update.timer signalith-sensor-capture; do
  [ ! -e "/etc/systemd/system/$u" ] && [ ! -e "/etc/systemd/system/$u.service" ] || left="$left $u"
done
for f in /etc/signalith-sensor /usr/lib/signalith-sensor /var/lib/signalith-sensor /etc/apt/sources.list.d/signalith-zeek.list \
  /etc/apt/sources.list.d/signalith-fluent-bit.list /etc/apt/sources.list.d/signalith-oisf-suricata.list \
  /etc/apt/keyrings/signalith-zeek.gpg /etc/apt/keyrings/signalith-fluentbit.gpg /etc/apt/keyrings/signalith-oisf.gpg; do
  [ ! -e "$f" ] || left="$left $f"
done
for a in signalith-sensor zeek suricata; do
  ! getent passwd "$a" >/dev/null || left="$left user:$a"
done
for u in suricata.service fluent-bit.service; do
  [ "$(systemctl is-enabled "$u" 2>/dev/null || true)" != masked ] || left="$left masked:$u"
done
# The Fluent Bit it took over is started again (removing the package may
# stop it after that, so this checks what --uninstall said).
! grep -q "Could not start fluent-bit.service" uninstall.txt || left="$left stopped:fluent-bit.service"
no_fake /run/systemd/system
if [ -n "$left" ]; then
  echo "Left after --uninstall:$left"
  exit 1
fi
echo "All removed."
