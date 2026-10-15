#!/bin/sh
# Written by the Signalith sensor install script (deploy/sensor/install.sh).
# The daily rules update (signalith-suricata-update.timer): suricata-update
# downloads the Emerging Threats Open rules and has Suricata test them
# before it writes them; Suricata then loads them without stopping. A
# failed download or test keeps the rules in use. The result goes to
# /var/lib/signalith-sensor/rules.state, which the status line reports.
#
# With packages, the rules and suricata-update's downloads are kept in
# /var/lib/signalith-sensor/suricata, which only root writes: this runs as
# root, so it never works in a folder the suricata user could change.
set -u
conf=/etc/signalith-sensor/sensor.conf
state=/var/lib/signalith-sensor/rules.state

# get prints the value of KEY='value' in a file the install script wrote.
get() {
  sed -n "s/^$1='\\([^']*\\)'\$/\\1/p" "$2" 2>/dev/null | head -n 1
}
# count prints how many rules a rule file holds (lines that are not
# comments), 0 when it cannot be read.
count() {
  n=$(grep -c '^[a-z]' 2>/dev/null) || true
  case "$n" in '' | *[!0-9]*) n=0 ;; esac
  echo "$n"
}

layout=$(get LAYOUT "$conf")
updated=$(get RULES_UPDATED "$state")
rules=$(get RULES_COUNT "$state")
result=failed
now=$(date -u +%Y-%m-%dT%H:%M:%SZ)

if [ "$layout" = docker ]; then
  dc() {
    docker compose -f /etc/signalith-sensor/docker/docker-compose.yml "$@"
  }
  if dc --profile update run --rm suricata-update; then
    result=ok
    updated=$now
    rules=$(dc --profile update run --rm --entrypoint cat suricata-update /var/lib/suricata/rules/suricata.rules | count)
    dc exec -T suricata suricatasc -c ruleset-reload-nonblocking /var/run/suricata/suricata-command.socket >/dev/null 2>&1 ||
      dc restart suricata >/dev/null 2>&1 || true
  fi
else
  data=/var/lib/signalith-sensor/suricata
  set -- --etopen --data-dir "$data" --suricata-conf /etc/suricata/signalith-sensor-test.yaml \
    --disable-conf /etc/suricata/disable.conf --no-reload --fail
  if [ -s /etc/signalith-sensor/local.rules ]; then
    set -- "$@" --local /etc/signalith-sensor/local.rules
  fi
  if suricata-update "$@"; then
    result=ok
    updated=$now
    rules=$(count <"$data/rules/suricata.rules")
    if systemctl is-active --quiet signalith-suricata.service; then
      suricatasc -c ruleset-reload-nonblocking /run/suricata/suricata-command.socket >/dev/null 2>&1 ||
        systemctl reload signalith-suricata.service || true
    fi
  fi
fi

umask 022
{
  echo "# Written by /usr/lib/signalith-sensor/rules-update.sh: the last rules update."
  echo "RULES_UPDATE='$result'"
  echo "RULES_UPDATED='$updated'"
  echo "RULES_COUNT='$rules'"
  echo "RULES_TRIED='$now'"
} >"$state.new" && mv -f "$state.new" "$state"
[ "$result" = ok ]
