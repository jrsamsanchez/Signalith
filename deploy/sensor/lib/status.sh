#!/bin/sh
# Written by the Signalith sensor install script (deploy/sensor/install.sh).
# The sensor's status line, every 5 minutes (signalith-sensor-status.timer):
# appends one JSON line to /var/log/signalith-sensor/status.json, which the
# agent sends to Signalith (tag sensor.status) for the Endpoints and Health
# pages. Values read from commands and files are cut down to safe
# characters, so the line is always valid JSON.
#
# SIGNALITH_SENSOR_ROOT and SIGNALITH_SENSOR_SYSFS are for tests only: a
# folder standing for / and one standing for /sys.
set -u
R=${SIGNALITH_SENSOR_ROOT:-}
sysfs=${SIGNALITH_SENSOR_SYSFS:-/sys}
conf=$R/etc/signalith-sensor/sensor.conf
out=$R/var/log/signalith-sensor/status.json
counters=$R/var/lib/signalith-sensor/last-counters
umask 027

get() {
  sed -n "s/^$1='\\([^']*\\)'\$/\\1/p" "$2" 2>/dev/null | head -n 1
}
safe() {
  printf '%s' "$1" | tr -cd 'A-Za-z0-9._:+-' | cut -c 1-64
}
num() {
  case "$1" in '' | *[!0-9]*) echo 0 ;; *) echo "$1" ;; esac
}
have() {
  command -v "$1" >/dev/null 2>&1
}
warnings=''
warn() {
  warnings="$warnings${warnings:+,}\"$1\""
}

layout=$(safe "$(get LAYOUT "$conf")")
name=$(safe "$(get NAME "$conf")")
iface=$(safe "$(get INTERFACE "$conf")")
version=$(safe "$(get SENSOR_VERSION "$conf")")
zeek=$(get ZEEK "$conf")
suricata=$(get SURICATA "$conf")

dc() {
  docker compose -f /etc/signalith-sensor/docker/docker-compose.yml "$@"
}

# Versions and whether Zeek and Suricata run.
zv='' sv='' fv='' zr=false sr=false eve=''
if [ "$layout" = docker ]; then
  img() {
    safe "$(sed -n "s/^$1=[^:]*:\\([^@]*\\).*/\\1/p" "$R/etc/signalith-sensor/docker/.env" 2>/dev/null)"
  }
  zv=$(img SIGNALITH_IMAGE_ZEEK)
  sv=$(img SIGNALITH_IMAGE_SURICATA)
  fv=$(img SIGNALITH_IMAGE_FLUENTBIT)
  running=''
  if have docker; then
    running=$(dc ps --status running --services 2>/dev/null) || true
    # Housekeeping the host does for the containers: Zeek's rotated logs
    # go after two days, and Suricata's log is rolled at 512 MB.
    if [ "$zeek" = yes ]; then
      dc exec -T zeek find /logs/zeek/archive -type f -mmin +2880 -delete >/dev/null 2>&1 || true
    fi
    if [ "$suricata" = yes ]; then
      size=$(num "$(dc exec -T suricata stat -c %s /var/log/suricata/eve.json 2>/dev/null | tr -cd 0-9)")
      if [ "$size" -gt 536870912 ]; then
        if dc exec -T suricata mv -f /var/log/suricata/eve.json /var/log/suricata/eve.json.1 >/dev/null 2>&1; then
          dc kill -s HUP suricata >/dev/null 2>&1 || true
        fi
      fi
      eve=$(dc exec -T suricata tail -n 3000 /var/log/suricata/eve.json 2>/dev/null) || true
    fi
  fi
  if printf '%s\n' "$running" | grep -qx zeek; then zr=true; fi
  if printf '%s\n' "$running" | grep -qx suricata; then sr=true; fi
else
  if [ "$zeek" = yes ]; then
    zv=$(safe "$(/opt/zeek/bin/zeek --version 2>/dev/null | sed -n 's/.*version \([^ ]*\).*/\1/p' | head -n 1)")
    if have pgrep && pgrep -x zeek >/dev/null 2>&1; then zr=true; fi
  fi
  if [ "$suricata" = yes ]; then
    sv=$(safe "$(suricata -V 2>/dev/null | sed -n 's/.*version \([^ ]*\).*/\1/p' | head -n 1)")
    if have systemctl && systemctl is-active --quiet signalith-suricata.service; then sr=true; fi
    eve=$(tail -n 3000 "$R/var/log/suricata/signalith/eve.json" 2>/dev/null) || true
  fi
  fv=$(safe "$(/opt/fluent-bit/bin/fluent-bit --version 2>/dev/null | sed -n 's/.*v\([0-9][0-9.]*\).*/\1/p' | head -n 1)")
fi
if [ "$zeek" = yes ] && [ "$zr" = false ]; then warn zeek_stopped; fi
if [ "$suricata" = yes ] && [ "$sr" = false ]; then warn suricata_stopped; fi

# The rules: the last update's result, from rules-update.sh.
rules=''
if [ "$suricata" = yes ]; then
  state=$R/var/lib/signalith-sensor/rules.state
  ru=$(safe "$(get RULES_UPDATED "$state")")
  rc=$(num "$(get RULES_COUNT "$state")")
  rr=$(safe "$(get RULES_UPDATE "$state")")
  [ -n "$rr" ] || rr=never
  rules="\"rules\":{"
  if [ -n "$ru" ]; then
    rules="$rules\"updated\":\"$ru\","
    then=$(date -u -d "$ru" +%s 2>/dev/null) || then=''
    if [ -n "$then" ] && [ $(($(date -u +%s) - then)) -gt 259200 ]; then warn rules_old; fi
  fi
  rules="$rules\"count\":$rc,\"update\":\"$rr\"},"
  if [ "$rr" = failed ]; then warn rules_failed; fi
fi

# The capture port: link, packets, and the share dropped since the last
# line (the kernel's drops on the port plus Suricata's capture drops).
net=$sysfs/class/net/$iface
link=$(safe "$(cat "$net/operstate" 2>/dev/null)")
[ -n "$link" ] || link=missing
rxp=$(num "$(cat "$net/statistics/rx_packets" 2>/dev/null)")
rxd=$(num "$(cat "$net/statistics/rx_dropped" 2>/dev/null)")
kd=$(printf '%s\n' "$eve" | grep '"event_type":"stats"' | tail -n 1 | sed -n 's/.*"kernel_drops":\([0-9]*\).*/\1/p')
lp=0 ld=0 lk=0 before=no
if [ -r "$counters" ]; then
  before=yes
  read -r lp ld lk <"$counters" || true
fi
lp=$(num "$lp") ld=$(num "$ld") lk=$(num "$lk")
# No stats line in the end of eve.json read above (a busy link): Suricata's
# drops are taken as they were at the last line, not as zero, so the next
# stats line is not counted as all new drops.
if [ -z "$kd" ]; then kd=$lk; fi
kd=$(num "$kd")
dp=$((rxp - lp)) dd=$((rxd - ld)) dk=$((kd - lk))
# A counter that went down was reset (a restart): count from zero.
[ "$dp" -ge 0 ] || dp=$rxp
[ "$dd" -ge 0 ] || dd=$rxd
[ "$dk" -ge 0 ] || dk=$kd
printf '%s %s %s\n' "$rxp" "$rxd" "$kd" >"$counters.new" 2>/dev/null && mv -f "$counters.new" "$counters"
drop=$(awk -v d=$((dd + dk)) -v p=$((dp + dd)) 'BEGIN { if (p <= 0) { print "0.0" } else { v = 100 * d / p; if (v > 100) v = 100; printf "%.1f", v } }')
if [ "$link" != up ]; then warn capture_link; fi
if [ "$dp" -eq 0 ] && [ "$before" = yes ]; then warn no_traffic; fi
if awk -v v="$drop" 'BEGIN { exit !(v > 5) }'; then warn drops; fi
if have ip && [ -n "$(ip -o addr show dev "$iface" scope global 2>/dev/null)" ]; then warn capture_ip; fi

# Free disk space where the logs and the agent's buffer are.
dpath=/var
if [ "$layout" = docker ] && [ -d "$R/var/lib/docker" ]; then dpath=/var/lib/docker; fi
# shellcheck disable=SC2046 # two numbers
set -- $(df -Pk "$R$dpath" 2>/dev/null | awk 'NR == 2 { print $2, $4 }')
total=$(num "${1:-}") avail=$(num "${2:-}")
free=$(awk -v a="$avail" -v t="$total" 'BEGIN { if (t <= 0) print "0.0"; else printf "%.1f", 100 * a / t }')
if awk -v v="$free" 'BEGIN { exit !(v < 10) }'; then warn disk_low; fi
encrypted=false
if have lsblk && lsblk -nro TYPE 2>/dev/null | grep -qx crypt; then encrypted=true; fi
synced=false
if have timedatectl && [ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null)" = yes ]; then synced=true; fi
if [ "$synced" = false ]; then warn time_not_synced; fi

tools=''
if [ "$zeek" = yes ]; then tools="\"zeek\":{\"version\":\"$zv\",\"running\":$zr},"; fi
if [ "$suricata" = yes ]; then tools="$tools\"suricata\":{\"version\":\"$sv\",\"running\":$sr},"; fi

line=$(printf '{"kind":"signalith-sensor-status","v":1,"time":"%s","host":"%s","role":"sensor","sensor_version":"%s","layout":"%s",%s"fluentbit":{"version":"%s"},%s"interface":{"name":"%s","link":"%s","rx_packets":%s,"rx_dropped":%s,"drop_percent":%s},"disk":{"path":"%s","free_bytes":%s,"free_percent":%s,"encrypted":%s},"time_synced":%s,"warnings":[%s]}' \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$name" "$version" "$layout" "$tools" "$fv" "$rules" \
  "$iface" "$link" "$rxp" "$rxd" "$drop" "$dpath" $((avail * 1024)) "$free" "$encrypted" "$synced" "$warnings")

# Rolled at 1 MB; the agent follows the rename.
if [ -f "$out" ] && [ "$(wc -c <"$out")" -gt 1048576 ]; then
  mv -f "$out" "$out.1"
fi
printf '%s\n' "$line" >>"$out"
chgrp signalith-sensor "$out" 2>/dev/null || true
chmod 0640 "$out"
