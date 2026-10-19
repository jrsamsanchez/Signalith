#!/bin/sh
# Checks the chart's plain syslog switch (server.syslog.plain), run by
# .github/workflows/helm.yml: syslog over TLS only by default, plain syslog
# over UDP and TCP with server.syslog.plain=true, and also when an upgrade's
# reused values are from before the setting (it is missing, not false).
# Usage: sh deploy/helm/ci/syslog-plain.sh deploy/helm/signalith
set -eu
chart=${1:-deploy/helm/signalith}
fail() { echo "FAIL: $*" >&2; exit 1; }
render() { helm template t "$chart" --kube-version 1.30.0 "$@"; }

out=$(render)
echo "$out" | grep -q 'name: syslog-tls, port: 6514' || fail "default: no TLS on the syslog Service"
echo "$out" | grep -q 'containerPort: 6514' || fail "default: the pods take no syslog over TLS"
if echo "$out" | grep -q 'port: 514,'; then fail "default: the syslog Service takes plain syslog on 514"; fi
if echo "$out" | grep -v '^ *#' | grep -q '5514'; then fail "default: plain syslog on 5514 in the pods, the config or the NetworkPolicy"; fi
echo "$out" | grep -A1 'name: SIGNALITH_SYSLOG_UDP' | grep -q 'value: "off"' || fail "default: SIGNALITH_SYSLOG_UDP is not off"
echo "$out" | grep -A1 'name: SIGNALITH_SYSLOG_TCP' | grep -q 'value: "off"' || fail "default: SIGNALITH_SYSLOG_TCP is not off"
echo "ok: syslog over TLS only by default"

for v in server.syslog.plain=true server.syslog.plain=null; do
  out=$(render --set "$v")
  echo "$out" | grep -q 'name: syslog-udp, port: 514' || fail "$v: no UDP 514 on the syslog Service"
  echo "$out" | grep -q 'name: syslog-tcp, port: 514' || fail "$v: no TCP 514 on the syslog Service"
  echo "$out" | grep -q 'containerPort: 5514, protocol: UDP' || fail "$v: the pods take no plain syslog"
  echo "$out" | grep -q 'port: 5514, protocol: TCP' || fail "$v: no plain syslog in the NetworkPolicy"
  echo "$out" | grep -q 'udp: 0.0.0.0:5514' || fail "$v: the config has no syslog.udp"
  echo "$out" | grep -A1 'name: SIGNALITH_SYSLOG_TCP' | grep -q 'value: "0.0.0.0:5514"' || fail "$v: SIGNALITH_SYSLOG_TCP is not 0.0.0.0:5514"
  echo "ok: $v turns on plain syslog"
done

# Addresses of one's own in server.config.syslog are not overridden.
if render --set server.config.syslog.udp=0.0.0.0:5514 | grep -q 'SIGNALITH_SYSLOG_UDP'; then
  fail "server.config.syslog.udp is overridden by the environment"
fi
echo "ok: server.config.syslog is kept"
