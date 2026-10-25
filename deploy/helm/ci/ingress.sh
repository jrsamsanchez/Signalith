#!/bin/sh
# Copyright 2026 The Signalith authors
# SPDX-License-Identifier: Apache-2.0
# Checks the chart's Ingress (ingress.*) and agent Service
# (server.agentService.*): both off by default, the Ingress carries the web
# port only and over HTTPS, and the agent Service the agent port only.
# With kubeconform on the PATH, the output is checked against the
# Kubernetes schemas too. Run by TestHelmIngress (deploy/helm_ingress_test.go)
# when helm is installed.
# Usage: sh deploy/helm/ci/ingress.sh deploy/helm/signalith
set -eu
chart=${1:-deploy/helm/signalith}
fail() { echo "FAIL: $*" >&2; exit 1; }
render() { helm template t "$chart" --kube-version 1.30.0 "$@"; }
# doc KIND NAME: the rendered object of that kind and name.
doc() { awk -v k="kind: $1" -v n="  name: $2" '/^---/{if(f&&m)print b; b="";f=0;m=0;next} {b=b $0 "\n"} $0==k{f=1} $0==n{m=1} END{if(f&&m)print b}'; }

out=$(render)
if echo "$out" | grep -q '^kind: Ingress'; then fail "default: an Ingress"; fi
if echo "$out" | grep -q 'name: t-signalith-agents$'; then fail "default: an agent Service"; fi
echo "ok: no Ingress and no agent Service by default"

if render --set ingress.enabled=true >/dev/null 2>&1; then fail "an Ingress without hosts renders"; fi
echo "ok: an Ingress needs a host"

set -- --set ingress.enabled=true --set ingress.className=nginx \
  --set 'ingress.hosts[0].host=siem.example.com' \
  --set 'ingress.tls[0].secretName=siem-tls' --set 'ingress.tls[0].hosts[0]=siem.example.com' \
  --set server.agentService.enabled=true --set 'server.agentService.loadBalancerSourceRanges[0]=10.30.0.0/16'
out=$(render "$@")
ing=$(echo "$out" | doc Ingress t-signalith)
[ -n "$ing" ] || fail "no Ingress"
echo "$ing" | grep -q 'ingressClassName: nginx' || fail "no ingressClassName"
echo "$ing" | grep -q 'host: "siem.example.com"' || fail "no host rule"
echo "$ing" | grep -q 'path: /$' || fail "no / path"
echo "$ing" | grep -q 'pathType: Prefix' || fail "no pathType"
echo "$ing" | grep -A3 'service:' | grep -q 'name: t-signalith$' || fail "not the web Service"
echo "$ing" | grep -A1 'port:' | grep -q 'name: https' || fail "not the web port"
echo "$ing" | grep -q 'nginx.ingress.kubernetes.io/backend-protocol: HTTPS' || fail "no HTTPS to the backend"
echo "$ing" | grep -q 'secretName: siem-tls' || fail "no TLS"
if echo "$ing" | grep -v '^ *#' | grep -q -e agents -e 7779; then fail "the Ingress carries the agent port"; fi
echo "ok: the Ingress carries the web port only, over HTTPS"

agents=$(echo "$out" | doc Service t-signalith-agents)
[ -n "$agents" ] || fail "no agent Service"
echo "$agents" | grep -q 'type: LoadBalancer' || fail "the agent Service is not a LoadBalancer"
echo "$agents" | grep -q 'port: 7779' || fail "the agent Service has no agent port"
echo "$agents" | grep -q '10.30.0.0/16' || fail "the agent Service has no loadBalancerSourceRanges"
if echo "$agents" | grep -v '^ *#' | grep -q -e 9000 -e 'name: https'; then fail "the agent Service carries the web port"; fi
echo "ok: the agent Service carries the agent port only"

# Values of an older chart, without these keys (helm upgrade --reuse-values).
render --set ingress=null --set server.agentService=null >/dev/null || fail "values without ingress or server.agentService"
echo "ok: values of an older chart render"

if command -v kubeconform >/dev/null 2>&1; then
  render "$@" | kubeconform -strict -summary -kubernetes-version 1.30.0 - || fail "kubeconform"
  echo "ok: kubeconform"
fi
