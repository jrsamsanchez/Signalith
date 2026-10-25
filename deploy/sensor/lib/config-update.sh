#!/bin/sh
# Copyright 2026 The Signalith authors
# SPDX-License-Identifier: Apache-2.0
# Written by the Signalith sensor install script (deploy/sensor/install.sh).
# Fetches the sensor agent's Fluent Bit configuration from Signalith every
# hour (signalith-sensor-config.timer), the same one the install line
# fetched, and, only when it changed, writes it and restarts Fluent Bit.
# A new parser tag, Zeek log or buffer limit on the server then reaches
# every sensor without running the line again (DEP-06).
#
# The configuration comes from GET /api/sensor/config, with the sensor's
# own token, over HTTPS only, checked by the certificate authority the
# line pinned. It is never run: before it is written, every section,
# plugin and setting must be on the list below, Fluent Bit may only read
# the sensor's own logs, and it must send to the same server, port and
# certificate authority as the configuration in use. A move to another
# server or a new certificate authority still needs the install line,
# which is checked by the person who runs it. A refused or failed fetch
# keeps the configuration in use; the result goes to config.state.
#
# SIGNALITH_SENSOR_ROOT is for tests only: a folder standing for /.
set -u
R=${SIGNALITH_SENSOR_ROOT:-}
conf=$R/etc/signalith-sensor/sensor.conf
lib=$R/var/lib/signalith-sensor
state=$lib/config.state

# get prints the value of KEY='value' in a file the install script wrote.
get() {
  sed -n "s/^$1='\\([^']*\\)'\$/\\1/p" "$2" 2>/dev/null | head -n 1
}
# text cuts a message down to safe characters.
text() {
  printf '%s' "$1" | tr -cd 'A-Za-z0-9 ._:,/()=+-' | cut -c 1-200
}

layout=$(get LAYOUT "$conf")
if [ "$layout" = docker ]; then
  dest=$R/etc/signalith-sensor/docker/fluent-bit.conf
  mode=0644 owner=root:root
  # The paths as the agent's container sees them.
  logs='/logs/' buffer='/buffer/' ca=/config/ca.pem
else
  dest=$R/etc/signalith-sensor/fluent-bit.conf
  mode=0640 owner=root:signalith-sensor
  logs='/opt/zeek/logs/ /var/log/suricata/signalith/ /var/log/signalith-sensor/'
  buffer='/var/lib/signalith-sensor/agent/' ca=/etc/signalith-sensor/ca.pem
fi

result=failed error='' now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
applied=$(get CONFIG_APPLIED "$state")
save() {
  {
    echo "# Written by /usr/lib/signalith-sensor/config-update.sh: the agent configuration from Signalith."
    echo "CONFIG_RESULT='$result'"
    echo "CONFIG_APPLIED='$applied'"
    echo "CONFIG_ERROR='$(text "$error")'"
    echo "CONFIG_TRIED='$now'"
  } >"$state.new" && mv -f "$state.new" "$state"
  if [ -n "$error" ]; then echo "config-update: $result: $(text "$error")" >&2; fi
}

tmp=$(mktemp -d) || exit 1
trap 'rm -rf "$tmp"' EXIT
chmod 0700 "$tmp"

from=$(get FROM "$conf")
case "$from" in
  https://*) ;;
  *)
    error="no Signalith address in sensor.conf"
    save
    exit 1
    ;;
esac
if [ ! -f "$dest" ]; then
  error="no configuration in use to compare with: run the install line again"
  save
  exit 1
fi
# The sensor's token: from the unit's environment, or token.env, which
# only root reads (read as text, never run).
token=${SIGNALITH_TOKEN:-}
if [ -z "$token" ]; then
  token=$(sed -n 's/^SIGNALITH_TOKEN=//p' "$R/etc/signalith-sensor/token.env" 2>/dev/null | head -n 1)
fi
token=$(printf '%s' "$token" | tr -cd 'A-Za-z0-9_.-')
if [ -z "$token" ]; then
  error="no token in token.env"
  save
  exit 1
fi

# The same question the install line asked, from what it recorded.
z=true s=true p=false
[ "$(get ZEEK "$conf")" != no ] || z=false
[ "$(get SURICATA "$conf")" != no ] || s=false
case "$(get PROTOCOLS "$conf")" in '' | no) ;; *) p=true ;; esac
q="server=$from&layout=${layout:-packages}&zeek=$z&suricata=$s&protocols=$p"

# The token goes to curl in a file only root reads, never on its command
# line, which every user can see.
printf 'Authorization: Bearer %s\n' "$token" >"$tmp/hdr"
set -- --proto =https --max-time 60 --max-filesize 262144
if grep -q 'BEGIN CERTIFICATE' "$R/etc/signalith-sensor/ca.pem" 2>/dev/null; then
  set -- "$@" --cacert "$R/etc/signalith-sensor/ca.pem"
fi
code=$(curl -sS "$@" -H "@$tmp/hdr" -o "$tmp/new" -w '%{http_code}' "$from/api/sensor/config?$q" 2>"$tmp/err") || code=000
rm -f "$tmp/hdr"
case "$code" in
  200) ;;
  000)
    error="Signalith could not be reached: $(tail -n 1 "$tmp/err")"
    save
    exit 1
    ;;
  *)
    error="Signalith answered $code: $(head -c 200 "$tmp/new")"
    save
    exit 1
    ;;
esac
tr -d '\r' <"$tmp/new" >"$tmp/conf"

if cmp -s "$tmp/conf" "$dest"; then
  result=unchanged
  save
  exit 0
fi

# check prints why configuration $1 is refused, or nothing. $2 is the
# configuration in use: the new one must send where it sends.
check() {
  awk -v logs="$logs" -v buffer="$buffer" -v ca="$ca" -v old="$2" '
    function keys(list, set,   n, a, i) { n = split(list, a, " "); for (i = 1; i <= n; i++) set[a[i]] = 1 }
    function bad(why) { if (why_ == "") why_ = "line " NR ": " why; exit }
    function under(p, roots,   n, a, i) {
      if (p ~ /\.\.|[*?]\//) return 0
      n = split(roots, a, " ")
      for (i = 1; i <= n; i++) if (index(p, a[i]) == 1) return 1
      return 0
    }
    BEGIN {
      keys("flush grace log_level storage.path storage.sync storage.checksum storage.max_chunks_up storage.backlog.mem_limit", svc)
      keys("name tag path exclude_path db db.sync db.locking read_from_head skip_long_lines skip_empty_lines buffer_chunk_size buffer_max_size mem_buf_limit refresh_interval rotate_wait ignore_older storage.type storage.pause_on_chunks_overlimit", tail)
      keys("name match record remove_key allowlist_key", recmod)
      keys("name match regex exclude logical_op", grep)
      keys("name match host port uri format header header_tag json_date_key json_date_format compress retry_limit workers storage.total_limit_size net.keepalive net.keepalive_idle_timeout net.connect_timeout tls tls.verify tls.verify_hostname tls.vhost tls.ca_file", out)
      # Where the configuration in use sends.
      while ((getline l < old) > 0) {
        sub(/^[ \t]+/, "", l)
        if (l ~ /^\[/) { sec = toupper(l) ; continue }
        if (sec != "[OUTPUT]") continue
        k = tolower(l); sub(/[ \t].*/, "", k); v = l; sub(/^[^ \t]+[ \t]*/, "", v)
        if (k == "host" || k == "port" || k == "tls.vhost" || k == "tls.ca_file" || k == "tls.verify_hostname") was[k] = v
      }
      close(old)
      sec = ""
    }
    { sub(/\r$/, "") }
    /^[ \t]*(#.*)?$/ { next }
    /^[ \t]*@/ { bad("directives such as @INCLUDE are not allowed") }
    /^\[[A-Z]+\][ \t]*$/ {
      sec = $0; sub(/[ \t]+$/, "", sec); n[sec]++; plugin = ""
      if (sec != "[SERVICE]" && sec != "[INPUT]" && sec != "[FILTER]" && sec != "[OUTPUT]") bad("section " sec " is not allowed")
      if (sec == "[SERVICE]" && n[sec] > 1 || sec == "[OUTPUT]" && n[sec] > 1) bad("more than one " sec)
      next
    }
    {
      line = $0; sub(/^[ \t]+/, "", line)
      k = tolower(line); sub(/[ \t].*/, "", k)
      v = line; sub(/^[^ \t]+[ \t]*/, "", v); sub(/[ \t]+$/, "", v)
      if (sec == "") bad("a setting outside any section")
      if (v ~ /[`]/) bad("the value of " k " is not allowed")
      if (k == "name") {
        if (plugin != "") bad("two names in one section")
        plugin = tolower(v)
        if (sec == "[INPUT]" && plugin != "tail") bad("input " v " is not allowed: only tail")
        if (sec == "[FILTER]" && plugin != "record_modifier" && plugin != "grep") bad("filter " v " is not allowed")
        if (sec == "[OUTPUT]" && plugin != "http") bad("output " v " is not allowed: only http")
        if (sec == "[SERVICE]") bad("name in [SERVICE]")
        next
      }
      if (sec != "[SERVICE]" && plugin == "") bad("a setting before the section names its plugin")
      if (sec == "[SERVICE]" && !(k in svc)) bad("[SERVICE] setting " k " is not allowed")
      if (sec == "[INPUT]" && !(k in tail)) bad("tail setting " k " is not allowed")
      if (sec == "[FILTER]" && plugin == "record_modifier" && !(k in recmod)) bad("record_modifier setting " k " is not allowed")
      if (sec == "[FILTER]" && plugin == "grep" && !(k in grep)) bad("grep setting " k " is not allowed")
      if (sec == "[OUTPUT]" && !(k in out)) bad("http setting " k " is not allowed")
      # Only two variables, each only where Signalith writes it.
      vv = v
      if (sec == "[OUTPUT]" && k == "header") {
        h = tolower(v); sub(/[ \t].*/, "", h); hv = v; sub(/^[^ \t]+[ \t]*/, "", hv)
        if (h == "authorization") { if (hv != "Bearer ${SIGNALITH_TOKEN}") bad("the Authorization header is not the sensor token"); vv = "" }
        else if (h == "x-signalith-agent") { if (hv != "${HOSTNAME}") bad("X-Signalith-Agent is not the host name"); vv = "" }
        else if (h != "x-signalith-config") bad("header " h " is not allowed")
      }
      if (sec == "[FILTER]" && k == "record") { r = v; sub(/\$\{HOSTNAME\}$/, "", r); vv = r }
      if (vv ~ /\$/) bad("the value of " k " is not allowed")
      # Fluent Bit logs HTTP headers, the token among them, at debug and trace.
      if (sec == "[SERVICE]" && k == "log_level" && tolower(v) !~ /^(off|error|warn|warning|info)$/) bad("log_level " v " is not allowed")
      if (sec == "[SERVICE]" && k == "storage.path" && !under(v, buffer)) bad("storage.path " v " is outside the agent folder")
      if (sec == "[INPUT]" && (k == "db") && !under(v, buffer)) bad("db " v " is outside the agent folder")
      if (sec == "[INPUT]" && k == "path") { np = split(v, ps, ","); for (i = 1; i <= np; i++) if (!under(ps[i], logs)) bad("path " ps[i] " is not one of the sensor logs") }
      if (sec == "[OUTPUT]") {
        o[k] = v
        if (k == "uri" && v !~ /^\/api\/[a-z]+$/) bad("uri " v " is not allowed")
        if ((k == "host" || k == "port" || k == "tls.vhost") && v != was[k]) bad(k " " v " is not where the sensor sends now: run the install line to change it")
        if (k == "tls.ca_file" && (v != ca || was[k] != v)) bad("tls.ca_file " v " is not the pinned certificate authority")
      }
      next
    }
    END {
      if (why_ != "") { print why_; exit }
      if (n["[INPUT]"] < 1 || n["[OUTPUT]"] != 1) { print "it must have inputs and one output"; exit }
      if (tolower(o["tls"]) != "on" || tolower(o["tls.verify"]) != "on") { print "the output must use TLS and check the certificate"; exit }
      if (o["host"] == "" || ("tls.ca_file" in was) != ("tls.ca_file" in o) || ("tls.vhost" in was) != ("tls.vhost" in o)) { print "the output does not send where the sensor sends now"; exit }
      if ((("tls.verify_hostname" in o) || tolower(was["tls.verify_hostname"]) == "on") && tolower(o["tls.verify_hostname"]) != "on") { print "the output must check the host name"; exit }
    }
  ' "$1"
}

why=$(check "$tmp/conf" "$dest")
if [ -n "$why" ]; then
  result=refused
  error="kept the configuration in use: $why"
  save
  exit 1
fi

# Written next to the one in use, then moved over it, so Fluent Bit never
# reads half a file.
# Fluent Bit reads it as its group, so a file it could not read is never
# put in place (tests, without that group, skip the owner).
if [ -n "$R" ]; then owner=''; fi
if ! cp "$tmp/conf" "$dest.new" || ! chmod "$mode" "$dest.new" ||
  { [ -n "$owner" ] && ! chown "$owner" "$dest.new"; } || ! mv -f "$dest.new" "$dest"; then
  rm -f "$dest.new"
  error="could not write $dest"
  save
  exit 1
fi
if [ -n "$R" ]; then
  : # Tests: nothing to restart.
elif [ "$layout" = docker ]; then
  docker compose -f /etc/signalith-sensor/docker/docker-compose.yml restart fluent-bit >/dev/null 2>"$tmp/err" ||
    error="written, but Fluent Bit did not restart: $(tail -n 1 "$tmp/err")"
else
  systemctl try-restart signalith-fluent-bit.service 2>"$tmp/err" ||
    error="written, but Fluent Bit did not restart: $(tail -n 1 "$tmp/err")"
fi
result=applied applied=$now
save
