#!/bin/sh
# Copyright 2026 The Signalith authors
# SPDX-License-Identifier: Apache-2.0
# Smoke test of the load balancer lab (docker-compose.cluster.yml), run
# weekly by .github/workflows/cluster-smoke.yml: agents and syslog through
# HAProxy reach both servers and can be searched, each client is seen by
# its own address, and the other server carries on when one stops. Run it after
#   docker compose -f deploy/docker/docker-compose.cluster.yml up -d
# from the folder Signalith is cloned into. Set COMPOSE to add -f files.
set -eu
COMPOSE=${COMPOSE:-docker compose -f deploy/docker/docker-compose.cluster.yml}
LB=https://localhost:8443
# Agents send to their own port, which HAProxy passes on too; the web
# port turns them away.
AGENTS=https://localhost:7779
# This run's own host name in every event, with today's time: events older
# than the store keeps are refused.
HOST=smoke$(date +%s)

fail() { echo "FAIL: $*" >&2; exit 1; }
# until <seconds> <what> <command...>: retry the command every 3 seconds.
until_ok() {
  limit=$1 what=$2; shift 2
  end=$(( $(date +%s) + limit ))
  while ! "$@" >/dev/null 2>&1; do
    [ "$(date +%s)" -lt "$end" ] || fail "$what: not within ${limit}s"
    sleep 3
  done
  echo "ok: $what"
}

until_ok 600 "HAProxy passes /readyz on" sh -c "curl -sfk $LB/readyz | grep -q '\"ready\":true'"
FIRST=$($COMPOSE exec -T signalith-a signalith initial-password | tail -n 1)
TOKEN=$($COMPOSE exec -T signalith-a cat /run/signalith-secrets/ingest-token)
# The first password Signalith made allows only choosing a new one. Until
# the servers share their users each keeps its own, so each try first
# replaces it on whichever server still has it.
PW=$(head -c 18 /dev/urandom | od -An -tx1 | tr -d ' \n')
change="curl -sfk -o /dev/null -u 'signalithadmin:$FIRST' -H 'Content-Type: application/json' -d '{\"current_password\":\"$FIRST\",\"new_password\":\"$PW\"}' $LB/api/me/password || true"
api() { curl -sfk -u "signalithadmin:$PW" "$LB$1"; }
until_ok 120 "both servers are listed" sh -c "$change; curl -sfk -u 'signalithadmin:$PW' $LB/api/cluster | python3 -c 'import json,sys; v=json.load(sys.stdin); sys.exit(0 if sum(s[\"state\"]==\"ready\" for s in v[\"servers\"])==2 else 1)'"
# Both servers have the new password: each answers it.
until_ok 60 "the new password works on both servers" sh -c "$change; for i in 1 2 3 4 5 6; do curl -sfk -o /dev/null -u 'signalithadmin:$PW' $LB/api/health || exit 1; done"

batch() {
  curl -sfk -o /dev/null -H "Authorization: Bearer $TOKEN" -H "X-Signalith-Agent: smoke" \
    "$AGENTS/api/ingest?tag=linux_secure" -d "[{\"log\":\"$(date -u '+%b %e %H:%M:%S') $HOST sshd[1]: Failed password for bob from 10.9.9.$1 port 22 ssh2\"}]"
}
# Syslog over TLS (port 6514), which the lab turns on; plain syslog is off.
# The servers' own CA is not checked: this only tests the way through HAProxy.
syslog() {
  python3 -c '
import socket, ssl, sys
c = ssl.create_default_context()
c.check_hostname = False
c.verify_mode = ssl.CERT_NONE
s = c.wrap_socket(socket.create_connection(("localhost", 6514), 10))
s.sendall(("<13>%s smokefw app: smoke %s\n" % (sys.argv[2], sys.argv[1])).encode())
# Wait briefly before closing: closing at once leaves the TLS 1.3 session
# tickets unread, the close turns into a reset and the server can lose the line.
s.settimeout(0.5)
try:
    s.recv(1)
except (socket.timeout, ssl.SSLError, OSError):
    pass
s.close()' "$1" "$(date -u '+%b %e %H:%M:%S')"
}

# Agent batches and syslog spread over both servers, by HAProxy's leastconn.
i=0
while [ $i -lt 20 ]; do batch $i || fail "agent batch $i"; syslog $i || fail "syslog $i"; i=$((i + 1)); done
check_totals() {
  api '/api/health?scope=cluster' | python3 -c '
import json, sys
h = json.load(sys.stdin)
c = h["cluster"]
rows = c["servers"]
batches = [r["ingest"]["batches"] for r in rows if r["figures"]]
syslog = [r["syslog"]["messages"] for r in rows if r["figures"]]
ok = len(rows) == 2 and all(b > 0 for b in batches) and c["totals"]["ingest"]["batches"] == sum(batches) \
    and c["totals"]["syslog"]["messages"] == sum(syslog) and sum(syslog) >= 20
sys.exit(0 if ok else 1)'
}
until_ok 60 "both servers got agent batches, and Health totals them" check_totals
# found <count>: a search for this run's host finds at least that many of
# its agent events, so they were written to OpenSearch and read back.
found() {
  python3 -c 'import json, sys; print(json.dumps({"query": "host=" + sys.argv[1], "earliest": "-1h", "latest": "now"}))' "$HOST" |
    curl -sfk -u "signalithadmin:$PW" -H "Origin: $LB" -H 'Content-Type: application/json' --data-binary @- "$LB/api/search" |
    python3 -c 'import json, sys; sys.exit(0 if json.load(sys.stdin).get("matched", 0) >= int(sys.argv[1]) else 1)' "$1"
}
until_ok 120 "a search finds the agent events" found 20

# Syslog senders are the device (this host, through Docker's gateway), never
# HAProxy itself (172.30.11.10): the PROXY header named the client.
check_senders() {
  api /api/health | python3 -c '
import json, sys
s = json.load(sys.stdin)["syslog"]["senders"]
sys.exit(0 if s and all(x["address"] != "172.30.11.10" for x in s) else 1)'
}
until_ok 30 "syslog senders are the devices, not HAProxy" check_senders

# Failover: stop one server; HAProxy's /readyz checks take it out.
$COMPOSE stop signalith-b
until_ok 60 "HAProxy answers with one server" sh -c "curl -sfk $LB/readyz | grep -q '\"ready\":true'"
i=0
while [ $i -lt 10 ]; do batch $i || fail "agent batch $i after failover"; i=$((i + 1)); done
echo "ok: agents get through with one server"
until_ok 120 "a search through the remaining server finds every agent event" found 30
$COMPOSE start signalith-b
echo "cluster smoke test passed"
