#!/bin/sh
# Copyright 2026 The Signalith authors
# SPDX-License-Identifier: Apache-2.0
# Smoke test of the Helm chart, run by .github/workflows/helm.yml after
# installing it with ci/kind-values.yaml into a namespace that enforces the
# restricted Pod Security Standard: the servers and the scanner form one
# cluster, an agent's events get in, OpenSearch refuses pods outside the
# release, and an upgrade keeps every secret.
set -eu
NS=${NS:-signalith}
REL=${REL:-sig}
CHART=${CHART:-deploy/helm/signalith}
VALUES=${VALUES:-deploy/helm/ci/kind-values.yaml}
FULL=$REL-signalith
PORT=19000
URL=https://localhost:$PORT
AGENT_PORT=17779
AGENT_URL=https://localhost:$AGENT_PORT

fail() { echo "FAIL: $*" >&2; exit 1; }
until_ok() {
  limit=$1 what=$2; shift 2
  end=$(( $(date +%s) + limit ))
  while ! "$@" >/dev/null 2>&1; do
    [ "$(date +%s)" -lt "$end" ] || fail "$what: not within ${limit}s"
    sleep 3
  done
  echo "ok: $what"
}
secret() { kubectl -n "$NS" get secret "$FULL-secrets" -o "jsonpath={.data.$1}" | base64 -d; }

helm test -n "$NS" "$REL" --logs || fail "helm test"
echo "ok: helm test"

kubectl -n "$NS" port-forward "service/$FULL" "$PORT:9000" "$AGENT_PORT:7779" >/tmp/port-forward.log 2>&1 &
PF=$!
# Passwords and the token go to curl in files only this user can read,
# never on a command line.
SECRETS=$(mktemp -d)
chmod 700 "$SECRETS"
trap 'kill $PF 2>/dev/null || true; rm -rf "$SECRETS"' EXIT
until_ok 60 "the web Service answers through port-forward" sh -c "curl -sfk $URL/readyz | grep -q '\"ready\":true'"

PW=$(secret initial-admin-password)
TOKEN=$(secret ingest-token)
if [ -z "$PW" ] || [ -z "$TOKEN" ]; then fail "no password or ingest token in $FULL-secrets"; fi
# sign_in_as writes a curl config that signs in as the built-in admin
# (signalithadmin) with password $1.
sign_in_as() {
  P=$1 python3 -c 'import os, sys
p = os.environ["P"].replace("\\", "\\\\").replace("\"", "\\\"")
sys.stdout.write("user = \"signalithadmin:%s\"\n" % p)' >"$SECRETS/admin"
}
printf 'Authorization: Bearer %s\n' "$TOKEN" >"$SECRETS/agent"

# The first password only lets the admin choose a new one.
NEW_PW=$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')
sign_in_as "$PW"
change_password() {
  CUR=$PW NEW=$NEW_PW python3 -c 'import json, os
print(json.dumps({"current_password": os.environ["CUR"], "new_password": os.environ["NEW"]}))' |
    curl -sfk -o /dev/null -K "$SECRETS/admin" -H 'Content-Type: application/json' --data-binary @- "$URL/api/me/password"
}
until_ok 60 "the admin chose a new password" change_password
sign_in_as "$NEW_PW"

# Both servers and the scanner joined one cluster by themselves, with the
# cluster key from the Secret.
until_ok 300 "two servers and a scanner are ready in one cluster" sh -c "curl -sfk -K '$SECRETS/admin' $URL/api/cluster | python3 -c '
import json, sys
v = json.load(sys.stdin)
ready = [s for s in v[\"servers\"] if s[\"state\"] == \"ready\"]
sys.exit(0 if len(ready) == 3 else 1)'"

# An agent's batch gets in on the agent port, and the web port turns it
# away (503, so an agent set up for the web port keeps its events).
code=$(curl -sk -o /dev/null -w '%{http_code}' -H "@$SECRETS/agent" -H "X-Signalith-Agent: smoke" \
  "$URL/api/ingest?tag=linux_secure" -d '[{"log":"x"}]')
[ "$code" = 503 ] || fail "the web port answered an agent batch with $code, not 503"
echo "ok: the web port turns agents away"
i=0
while [ $i -lt 5 ]; do
  curl -sfk -o /dev/null -H "@$SECRETS/agent" -H "X-Signalith-Agent: smoke" \
    "$AGENT_URL/api/ingest?tag=linux_secure" -d "[{\"log\":\"Oct 14 12:00:00 smoke sshd[1]: Failed password for bob from 10.9.9.$i port 22 ssh2\"}]" \
    || fail "agent batch $i"
  i=$((i + 1))
done
until_ok 60 "Health counts the agent batches" sh -c "curl -sfk -K '$SECRETS/admin' '$URL/api/health?scope=cluster' | python3 -c '
import json, sys
sys.exit(0 if json.load(sys.stdin)[\"cluster\"][\"totals\"][\"ingest\"][\"batches\"] >= 5 else 1)'"

# OpenSearch takes connections from the release's pods only.
probe() {
  # $1: the probe pod's labels, $2 its name; prints open or closed.
  kubectl -n "$NS" run "probe-$2" --rm -i --restart=Never --quiet --image=signalith:local --image-pull-policy=Never \
    --labels="$1" --overrides='{"spec":{"securityContext":{"runAsNonRoot":true,"runAsUser":65532,"seccompProfile":{"type":"RuntimeDefault"}},"containers":[{"name":"p","image":"signalith:local","imagePullPolicy":"Never","command":["bash","-c","timeout 5 bash -c \"exec 3<>/dev/tcp/'"$FULL"'-opensearch/9200\" && echo open || echo closed"],"securityContext":{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]}}}]}}'
}
[ "$(probe app=other outside)" = closed ] || fail "a pod outside the release reached OpenSearch"
echo "ok: a pod outside the release cannot reach OpenSearch"
kubectl -n "$NS" exec "$FULL-0" -c signalith -- bash -c "timeout 5 bash -c 'exec 3<>/dev/tcp/$FULL-opensearch/9200'" \
  || fail "a server pod could not reach OpenSearch"
echo "ok: the servers reach OpenSearch"

# An upgrade runs the setup Job again, which keeps every secret.
before=$(kubectl -n "$NS" get secret "$FULL-secrets" "$FULL-opensearch-certs" "$FULL-opensearch-ca" -o jsonpath='{.items[*].data}')
helm upgrade -n "$NS" "$REL" "$CHART" -f "$VALUES" --wait --timeout 10m
after=$(kubectl -n "$NS" get secret "$FULL-secrets" "$FULL-opensearch-certs" "$FULL-opensearch-ca" -o jsonpath='{.items[*].data}')
[ "$before" = "$after" ] || fail "the upgrade changed the secrets"
echo "ok: an upgrade keeps the secrets"
kubectl -n "$NS" get role,rolebinding,serviceaccount -o name | grep -q setup && fail "the setup Job's rights outlived it"
echo "ok: the setup Job's rights are gone"
echo "Helm chart smoke test passed"
