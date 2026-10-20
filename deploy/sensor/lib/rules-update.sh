#!/bin/sh
# Copyright 2026 The Signalith authors
# SPDX-License-Identifier: Apache-2.0
# Written by the Signalith sensor install script (deploy/sensor/install.sh).
# Updates the Suricata rules and applies the rule tuning set on Signalith
# (Settings > Network sensors). suricata-update has Suricata test the
# rules before it writes them; Suricata then loads them without stopping.
# A failed download or test keeps the rules and the tuning in use. A
# tuning is only marked as failed when the rules pass without it; when they
# fail either way (a failed download), it is tried again on the next run.
#
#   rules-update.sh          the daily update (signalith-suricata-update.timer):
#                            fetch the tuning, then download the rules
#   rules-update.sh tuning   every 10 minutes (signalith-sensor-tuning.timer):
#                            fetch the tuning and, only when it changed,
#                            rebuild the rules with it
#   rules-update.sh merge    rebuild the tuning files from the ones in /etc
#                            (the install script, after writing them)
#
# The tuning comes from GET /api/sensor/tuning, with the sensor's own
# token, over HTTPS only. It is written to files, never run: disable.conf
# and threshold.config are the ones in /etc (your hand edits) followed by
# Signalith's, in /var/lib/signalith-sensor/tuning, which only root
# writes; Signalith's own rules go next to your local.rules. Results go to
# rules.state and tuning/tuning.state, which the status line reports.
#
# With packages, the rules and suricata-update's downloads are kept in
# /var/lib/signalith-sensor/suricata, which only root writes: this runs as
# root, so it never works in a folder the suricata user could change.
#
# SIGNALITH_SENSOR_ROOT is for tests only: a folder standing for /, and
# SIGNALITH_RULES_TIMEOUT too: how many seconds one suricata-update may run.
set -u
R=${SIGNALITH_SENSOR_ROOT:-}
lim=$(printf '%s' "${SIGNALITH_RULES_TIMEOUT:-900}" | tr -cd '0-9')
[ -n "$lim" ] || lim=900
mode=${1:-daily}
conf=$R/etc/signalith-sensor/sensor.conf
lib=$R/var/lib/signalith-sensor
state=$lib/rules.state
tdir=$lib/tuning
tstate=$tdir/tuning.state

case "$mode" in
  daily | tuning | merge) ;;
  *)
    echo "usage: rules-update.sh [tuning | merge]" >&2
    exit 2
    ;;
esac

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
# text cuts a message down to safe characters.
text() {
  printf '%s' "$1" | tr -cd 'A-Za-z0-9 ._:,/()=+-' | cut -c 1-200
}

layout=$(get LAYOUT "$conf")
hand=$R/etc/suricata
if [ "$layout" = docker ]; then hand=$R/etc/signalith-sensor/docker/suricata; fi
umask 022
mkdir -p "$tdir"

# merge writes the files Suricata and suricata-update read: yours from
# /etc, then Signalith's.
merge() {
  for f in disable.conf threshold.config; do
    {
      if [ -f "$hand/$f" ]; then cat "$hand/$f"; fi
      echo ""
      echo "# From Signalith (Settings > Network sensors), fetched by rules-update.sh:"
      if [ -f "$tdir/server.$f" ]; then cat "$tdir/server.$f"; fi
    } >"$tdir/$f.new" && mv -f "$tdir/$f.new" "$tdir/$f"
  done
  if [ ! -f "$tdir/server.local.rules" ]; then : >"$tdir/server.local.rules"; fi
}

# One run at a time: the daily update, the tuning timer and the install
# script (merge) may start together.
if command -v flock >/dev/null 2>&1; then
  exec 9>"$lib/rules.lock"
  flock -w 1800 9 || exit 1
fi

if [ "$mode" = merge ]; then
  merge
  exit 0
fi

tmp=$(mktemp -d) || exit 1
trap 'rm -rf "$tmp"' EXIT
chmod 0700 "$tmp"

t_hash=$(get TUNING_HASH "$tstate")
t_result=$(get TUNING_RESULT "$tstate")
t_applied=$(get TUNING_APPLIED "$tstate")
t_error=$(get TUNING_ERROR "$tstate")
t_failed=$(get TUNING_FAILED "$tstate")
[ -n "$t_result" ] || t_result=never
now=$(date -u +%Y-%m-%dT%H:%M:%SZ)

save_tuning() {
  {
    echo "# Written by /usr/lib/signalith-sensor/rules-update.sh: the rule tuning from Signalith."
    echo "TUNING_HASH='$(printf '%s' "$t_hash" | tr -cd '0-9a-f')'"
    echo "TUNING_RESULT='$t_result'"
    echo "TUNING_APPLIED='$t_applied'"
    echo "TUNING_ERROR='$(text "$t_error")'"
    echo "TUNING_FAILED='$(printf '%s' "$t_failed" | tr -cd '0-9a-f')'"
    echo "TUNING_TRIED='$now'"
  } >"$tstate.new" && mv -f "$tstate.new" "$tstate"
}

# The sensor's token: from the unit's environment, or token.env, which
# only root reads (read as text, never run).
token=${SIGNALITH_TOKEN:-}
if [ -z "$token" ]; then
  token=$(sed -n 's/^SIGNALITH_TOKEN=//p' "$R/etc/signalith-sensor/token.env" 2>/dev/null | head -n 1)
fi
token=$(printf '%s' "$token" | tr -cd 'A-Za-z0-9_.-')

# fetch gets the tuning into $tmp/new and its SHA-256 into $new: 0 when it
# is new, 1 when the sensor runs it already, 2 when it could not be
# fetched ($t_error says why), 3 when it is the one that failed its test
# before, unchanged.
new=''
fetch() {
  from=$(get FROM "$conf")
  case "$from" in
    https://*) ;;
    *)
      t_error="no Signalith address in sensor.conf"
      return 2
      ;;
  esac
  if [ -z "$token" ]; then
    t_error="no token in token.env"
    return 2
  fi
  # The token goes to curl in a file only root reads, never on its
  # command line, which every user can see.
  printf 'Authorization: Bearer %s\n' "$token" >"$tmp/hdr"
  etag=$(head -c 80 "$tdir/etag" 2>/dev/null | tr -cd '0-9a-f')
  if [ -n "$etag" ]; then printf 'If-None-Match: "%s"\n' "$etag" >>"$tmp/hdr"; fi
  set -- --proto =https --max-time 60 --max-filesize 1048576
  if grep -q 'BEGIN CERTIFICATE' "$R/etc/signalith-sensor/ca.pem" 2>/dev/null; then
    set -- "$@" --cacert "$R/etc/signalith-sensor/ca.pem"
  fi
  code=$(curl -sS "$@" -H "@$tmp/hdr" -D "$tmp/head" -o "$tmp/body" -w '%{http_code}' "$from/api/sensor/tuning" 2>"$tmp/err") || code=000
  rm -f "$tmp/hdr"
  case "$code" in
    304) return 1 ;;
    200) ;;
    000)
      t_error="Signalith could not be reached: $(tail -n 1 "$tmp/err")"
      return 2
      ;;
    *)
      t_error="Signalith answered $code: $(head -c 200 "$tmp/body")"
      return 2
      ;;
  esac
  sum=$(sha256sum <"$tmp/body" | cut -c 1-64)
  got=$(tr -d '\r' <"$tmp/head" | sed -n 's/^[Ee][Tt][Aa][Gg]:[ ]*"\([0-9a-f]\{64\}\)"$/\1/p' | tail -n 1)
  if [ "$sum" != "$got" ]; then
    t_error="the tuning did not arrive whole (its SHA-256 is not its ETag)"
    return 2
  fi
  mkdir -p "$tmp/new"
  : >"$tmp/new/disable.conf"
  : >"$tmp/new/threshold.config"
  : >"$tmp/new/local.rules"
  # Lines are copied to files by section; nothing is run.
  if ! awk -v d="$tmp/new" '
    NR == 1 { if ($0 != "# signalith-sensor-tuning 1") { bad = 1; exit 1 } next }
    $0 == "[end]" { ended = 1; exit 0 }
    $0 == "[disable]" { out = d "/disable.conf"; next }
    $0 == "[threshold]" { out = d "/threshold.config"; next }
    $0 == "[local]" { out = d "/local.rules"; next }
    /^\[/ || out == "" { bad = 1; exit 1 }
    { print > out }
    END { if (bad || !ended) exit 1 }
  ' "$tmp/body"; then
    t_error="the tuning is not in the form this sensor reads; run the install line again"
    return 2
  fi
  new=$sum
  # A tuning that failed its test is not tried again until it changes.
  if [ "$new" = "$t_failed" ]; then return 3; fi
  return 0
}

# stage keeps the tuning in use in prev/ and puts the new one in place.
stage() {
  mkdir -p "$tdir/prev"
  for f in disable.conf threshold.config local.rules; do
    if [ -f "$tdir/server.$f" ]; then cp -p "$tdir/server.$f" "$tdir/prev/server.$f"; else : >"$tdir/prev/server.$f"; fi
    cp "$tmp/new/$f" "$tdir/server.$f.new" && mv -f "$tdir/server.$f.new" "$tdir/server.$f"
  done
  merge
}

# unstage puts the tuning of prev/ back.
unstage() {
  for f in disable.conf threshold.config local.rules; do
    if [ -f "$tdir/prev/server.$f" ]; then mv -f "$tdir/prev/server.$f" "$tdir/server.$f"; fi
  done
  merge
}

dc() {
  docker compose -f /etc/signalith-sensor/docker/docker-compose.yml "$@"
}

# timed runs a command for at most $lim seconds (then 124), so a rule
# pattern that never ends cannot hold the lock and stop every later update.
timed() {
  if command -v timeout >/dev/null 2>&1; then
    timeout -k 30 "$lim" "$@"
  else
    "$@"
  fi
}

# update runs suricata-update with the tuning in place; with "offline",
# from its last download. Its output goes to $tmp/out.
update() {
  off=${1:-}
  if [ "$layout" = docker ]; then
    t=/etc/suricata/signalith-tuning
    set -- --etopen --suricata-conf /etc/suricata/signalith-sensor.yaml --disable-conf "$t/disable.conf" \
      --local /etc/suricata/local.rules --local "$t/server.local.rules" --no-reload --fail
    if [ -n "$off" ]; then set -- "$@" --offline; fi
    cname=signalith-suricata-update-$$
    timed docker compose -f /etc/signalith-sensor/docker/docker-compose.yml --profile update run --rm --name "$cname" \
      suricata-update "$@" >"$tmp/out" 2>&1
    rc=$?
    # The container outlives a docker command that was stopped.
    if [ "$rc" = 124 ] || [ "$rc" = 137 ]; then docker rm -f "$cname" >/dev/null 2>&1 || true; fi
  else
    set -- --etopen --data-dir "$lib/suricata" --suricata-conf "$R/etc/suricata/signalith-sensor-test.yaml" \
      --disable-conf "$tdir/disable.conf" --no-reload --fail
    if [ -s "$R/etc/signalith-sensor/local.rules" ]; then
      set -- "$@" --local "$R/etc/signalith-sensor/local.rules"
    fi
    if [ -s "$tdir/server.local.rules" ]; then
      set -- "$@" --local "$tdir/server.local.rules"
    fi
    if [ -n "$off" ]; then set -- "$@" --offline; fi
    timed suricata-update "$@" >"$tmp/out" 2>&1
    rc=$?
  fi
  if [ "$rc" = 124 ] || [ "$rc" = 137 ]; then
    echo "Error: suricata-update ran longer than $lim seconds and was stopped" >>"$tmp/out"
  fi
  return "$rc"
}

# cached says whether suricata-update has a download to rebuild from.
cached() {
  if [ "$layout" = docker ]; then
    dc --profile update run --rm --entrypoint sh suricata-update -c 'ls /var/lib/suricata/update/cache 2>/dev/null | grep -q .' >/dev/null 2>&1
  else
    for f in "$lib"/suricata/update/cache/*; do
      if [ -e "$f" ]; then return 0; fi
    done
    return 1
  fi
}

# rules_count prints how many rules Suricata has now.
rules_count() {
  if [ "$layout" = docker ]; then
    dc --profile update run --rm --entrypoint cat suricata-update /var/lib/suricata/rules/suricata.rules | count
  else
    count <"$lib/suricata/rules/suricata.rules"
  fi
}

reload() {
  if [ "$layout" = docker ]; then
    dc exec -T suricata suricatasc -c ruleset-reload-nonblocking /var/run/suricata/suricata-command.socket >/dev/null 2>&1 ||
      dc restart suricata >/dev/null 2>&1 || true
  elif systemctl is-active --quiet signalith-suricata.service; then
    suricatasc -c ruleset-reload-nonblocking /run/suricata/suricata-command.socket >/dev/null 2>&1 ||
      systemctl reload signalith-suricata.service || true
  fi
}

# why prints the last error suricata-update gave (in $tmp/out, or the
# file named).
why() {
  f=${1:-$tmp/out}
  l=$(grep -i 'error' "$f" 2>/dev/null | tail -n 1)
  [ -n "$l" ] || l=$(tail -n 1 "$f" 2>/dev/null)
  printf '%s' "$l" | sed 's/^[0-9/ :.-]*- *//'
}

save_rules() {
  {
    echo "# Written by /usr/lib/signalith-sensor/rules-update.sh: the last rules update."
    echo "RULES_UPDATE='$1'"
    echo "RULES_UPDATED='$2'"
    echo "RULES_COUNT='$3'"
    echo "RULES_TRIED='$4'"
  } >"$state.new" && mv -f "$state.new" "$state"
}

# applied records the tuning now in use.
applied() {
  printf '%s\n' "$new" >"$tdir/etag.new" && mv -f "$tdir/etag.new" "$tdir/etag"
  t_hash=$(printf '%s' "$new" | cut -c 1-12)
  t_result=ok t_applied=$now t_error='' t_failed=''
}

# try_tuning puts the new tuning in place and has suricata-update test
# it with the rules ($1: offline, or empty to download). 0: applied. 1:
# refused: the rules pass without it, so the tuning is at fault; it is
# not tried again until it changes. 2: the rules fail without it too (a
# failed download, say): nothing is known about the tuning, the one
# before stays, and the next run tries it again. Either way but 0, the
# rules were rebuilt without it when that passed.
try_tuning() {
  stage
  if update "$1"; then
    applied
    return 0
  fi
  mv -f "$tmp/out" "$tmp/out.tuning"
  unstage
  if update "$1"; then
    t_result=failed t_error=$(why "$tmp/out.tuning") t_failed=$new
    [ -n "$t_error" ] || t_error="suricata-update refused the rules"
    cp "$tmp/out.tuning" "$tmp/out"
    return 1
  fi
  t_result=unreachable t_error="the rules could not be built to test the tuning: $(why)"
  return 2
}

fetch
fetched=$?
case "$fetched" in
  1)
    # The sensor runs what Signalith has.
    t_result=ok t_error='' t_failed=''
    if [ -z "$t_hash" ]; then t_hash=$(cut -c 1-12 "$tdir/etag" 2>/dev/null); fi
    ;;
  2)
    # The tuning in use stays; the status line says why.
    if [ "$t_result" != failed ]; then t_result=unreachable; fi
    ;;
esac
# Your hand edits in /etc count on every run.
merge

if [ "$mode" = tuning ]; then
  if [ "$fetched" != 0 ]; then
    save_tuning
    exit 0
  fi
  # From the last download when there is one; else it downloads, and a
  # failed download is told from a refused tuning by the run without it.
  off=''
  if cached; then off=offline; fi
  try_tuning "$off"
  tried=$?
  save_tuning
  if [ "$tried" != 2 ]; then
    # The rules were rebuilt, with the tuning or without it.
    updated=$(get RULES_UPDATED "$state")
    [ -n "$off" ] || updated=$now
    save_rules ok "$updated" "$(rules_count)" "$now"
    reload
  fi
  if [ "$tried" = 0 ]; then exit 0; fi
  cat "$tmp/out" >&2
  exit 1
fi

# The daily update: a new tuning is tested first from the last download,
# when there is one, then the rules are downloaded with the tuning that
# passed. With no download kept, the tuning is tested with the download,
# and the rules without it tell a refused tuning from a failed download.
updated=$(get RULES_UPDATED "$state")
rules=$(get RULES_COUNT "$state")
result=failed
if [ "$fetched" = 0 ] && cached; then
  try_tuning offline
  fetched=yes
fi
if [ "$fetched" = 0 ]; then
  try_tuning ''
  case $? in 0 | 1) result=ok ;; esac
elif update; then
  result=ok
fi
if [ "$result" = ok ]; then
  updated=$now
  rules=$(rules_count)
  reload
else
  cat "$tmp/out" >&2
fi
save_tuning
save_rules "$result" "$updated" "$rules" "$now"
[ "$result" = ok ]
