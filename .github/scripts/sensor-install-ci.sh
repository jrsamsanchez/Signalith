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
  --data-urlencode interface=cap0 --data-urlencode networks=10.99.0.0/16 --data-urlencode ot=true >install.json
placeholder=$(jq -r .token_placeholder install.json)
token=$(api -H 'Content-Type: application/json' -d '{"name":"CI sensor","purpose":"sensor"}' "$SIGNALITH/api/agent-tokens" | jq -r .secret)
# One rule of our own, so an alert is certain.
printf '%s\n' 'alert http any any -> any any (msg:"Signalith CI request"; http.uri; content:"/signalith-ci"; sid:9900001; rev:1;)' >ci.rules
line=$(jq -r .linux install.json | sed "s|$placeholder|$token|")
line="$line --name ci-sensor --local-rules $work/ci.rules"
printf '%s\n' "$line" | sed "s|$token|<token>|"

step "Install"
sh -c "$line"

step "The ICSNPP analyzers Zeek loads (--ot)"
sudo /opt/zeek/bin/zeek -NN | tee plugins.txt >/dev/null
grep -E '^ICSNPP::' plugins.txt
for p in ICSNPP::BACnet ICSNPP::ENIP ICSNPP::OPCUA_Binary ICSNPP::S7COMM GE_SRTP_TCP HART_IP_TCP PROFINET_IO_CM OMRON_FINS_TCP; do
  grep -q "$p" plugins.txt || { echo "Zeek does not load $p"; exit 1; }
done

step "Traffic: HTTP, DNS and Modbus on lo, captured, then replayed on the capture port"
python3 -m http.server 8099 --bind 127.0.0.1 >/dev/null 2>&1 &
web=$!
# A Modbus device on its usual port: it answers reads with two registers
# and echoes writes.
cat >modbus.py <<'EOF'
import socket, struct, sys
if sys.argv[1] == "serve":
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 502))
    s.listen(1)
    s.settimeout(20)
    c, _ = s.accept()
    while True:
        h = c.recv(7)
        if len(h) < 7:
            break
        tid, _, n, unit = struct.unpack(">HHHB", h)
        pdu = c.recv(n - 1)
        if pdu[0] == 3:
            pdu = bytes([3, 4, 0, 1, 0, 2])
        c.sendall(struct.pack(">HHHB", tid, 0, len(pdu) + 1, unit) + pdu)
else:
    c = socket.create_connection(("127.0.0.1", 502))
    for tid, pdu in enumerate([bytes([3, 0, 0, 0, 2]), bytes([6, 0, 1, 0, 42]), bytes([3, 0, 0, 0, 2])], 1):
        c.sendall(struct.pack(">HHHB", tid, 0, len(pdu) + 1, 1) + pdu)
        c.recv(64)
    c.close()
EOF
sudo python3 modbus.py serve &
modbus=$!
sleep 1
sudo timeout 15 tcpdump -i lo -w traffic.pcap 'port 8099 or port 53 or port 502' >/dev/null 2>&1 &
sleep 2
for i in 1 2 3; do
  curl -s -o /dev/null "http://127.0.0.1:8099/signalith-ci?try=$i" || true
  getent hosts "example$i.com" >/dev/null || true
done
python3 modbus.py client
sleep 14
kill "$web" || true
sudo kill "$modbus" 2>/dev/null || true
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
# Industrial: Zeek's own Modbus log, and ICSNPP's, mapped.
want="$want|datamodel=Industrial sourcetype=zeek:modbus ot_function=READ_HOLDING_REGISTERS|datamodel=Industrial sourcetype=zeek:modbus_detailed category=write"
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
sudo sh /usr/lib/signalith-sensor/install.sh --uninstall
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
if [ -n "$left" ]; then
  echo "Left after --uninstall:$left"
  exit 1
fi
echo "All removed."
