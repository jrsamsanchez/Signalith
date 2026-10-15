#!/bin/sh
# Smoke test of the load balancer lab (docker-compose.cluster.yml), run
# weekly by .github/workflows/cluster-smoke.yml: agents and syslog through
# HAProxy reach both servers, each client is seen by its own address, and
# the other server carries on when one stops. Run it after
#   docker compose -f deploy/docker/docker-compose.cluster.yml up -d
# from the folder Signalith is cloned into. Set COMPOSE to add -f files.
set -eu
COMPOSE=${COMPOSE:-docker compose -f deploy/docker/docker-compose.cluster.yml}
LB=https://localhost:8443

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
PW=$($COMPOSE exec -T signalith-a signalith initial-password | tail -n 1)
TOKEN=$($COMPOSE exec -T signalith-a cat /run/signalith-secrets/ingest-token)
api() { curl -sfk -u "admin:$PW" "$LB$1"; }
until_ok 120 "both servers are listed" sh -c "curl -sfk -u 'admin:$PW' $LB/api/cluster | python3 -c 'import json,sys; v=json.load(sys.stdin); sys.exit(0 if sum(s[\"state\"]==\"ready\" for s in v[\"servers\"])==2 else 1)'"

batch() {
  curl -sfk -o /dev/null -H "Authorization: Bearer $TOKEN" -H "X-Signalith-Agent: smoke" \
    "$LB/api/ingest?tag=linux_secure" -d "[{\"log\":\"Oct 14 12:00:00 smoke sshd[1]: Failed password for bob from 10.9.9.$1 port 22 ssh2\"}]"
}
syslog() { printf '<13>Oct 14 12:00:00 smokefw app: smoke %s\n' "$1" | nc -q 1 localhost 514; }

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
$COMPOSE start signalith-b
echo "cluster smoke test passed"
