#!/bin/sh
# Checks the chart's plain syslog switch (server.syslog.plain): syslog over
# TLS only on a new install, plain syslog over UDP and TCP with
# server.syslog.plain=true, and off with false. helm template reads nothing
# from a cluster, so an upgrade (which keeps plain syslog as the release's
# syslog Service has it) renders as a new install here. Run by
# TestHelmPlainSyslog (deploy/helm_syslog_test.go) when helm is installed.
# Usage: sh deploy/helm/ci/syslog-plain.sh deploy/helm/signalith
set -eu
chart=${1:-deploy/helm/signalith}
fail() { echo "FAIL: $*" >&2; exit 1; }
render() { helm template t "$chart" --kube-version 1.30.0 "$@"; }

for v in "" server.syslog.plain=false server.syslog.plain=auto; do
  if [ -n "$v" ]; then out=$(render --set "$v" --is-upgrade); else out=$(render); fi
  what=${v:-default}
  echo "$out" | grep -q 'name: syslog-tls, port: 6514' || fail "$what: no TLS on the syslog Service"
  echo "$out" | grep -q 'containerPort: 6514' || fail "$what: the pods take no syslog over TLS"
  if echo "$out" | grep -q 'port: 514,'; then fail "$what: the syslog Service takes plain syslog on 514"; fi
  if echo "$out" | grep -v '^ *#' | grep -q '5514'; then fail "$what: plain syslog on 5514 in the pods, the config or the NetworkPolicy"; fi
  echo "$out" | grep -A1 'name: SIGNALITH_SYSLOG_UDP' | grep -q 'value: "off"' || fail "$what: SIGNALITH_SYSLOG_UDP is not off"
  echo "$out" | grep -A1 'name: SIGNALITH_SYSLOG_TCP' | grep -q 'value: "off"' || fail "$what: SIGNALITH_SYSLOG_TCP is not off"
  echo "ok: $what takes syslog over TLS only"
done

out=$(render --set server.syslog.plain=true)
echo "$out" | grep -q 'name: syslog-udp, port: 514' || fail "plain=true: no UDP 514 on the syslog Service"
echo "$out" | grep -q 'name: syslog-tcp, port: 514' || fail "plain=true: no TCP 514 on the syslog Service"
echo "$out" | grep -q 'containerPort: 5514, protocol: UDP' || fail "plain=true: the pods take no plain syslog"
echo "$out" | grep -q 'port: 5514, protocol: TCP' || fail "plain=true: no plain syslog in the NetworkPolicy"
echo "$out" | grep -q 'udp: 0.0.0.0:5514' || fail "plain=true: the config has no syslog.udp"
echo "$out" | grep -A1 'name: SIGNALITH_SYSLOG_TCP' | grep -q 'value: "0.0.0.0:5514"' || fail "plain=true: SIGNALITH_SYSLOG_TCP is not 0.0.0.0:5514"
echo "ok: server.syslog.plain=true turns on plain syslog"

# Addresses of one's own in server.config.syslog are not overridden.
if render --set server.config.syslog.udp=0.0.0.0:5514 | grep -q 'SIGNALITH_SYSLOG_UDP'; then
  fail "server.config.syslog.udp is overridden by the environment"
fi
echo "ok: server.config.syslog is kept"
