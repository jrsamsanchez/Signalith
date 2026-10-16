#!/bin/bash
# Tests the whole lab end to end: run "sudo lab-e2e" on signalith-1 once
# "Lab ready." shows in /var/log/lab-setup.log. It makes the lab do what
# Signalith should notice (failed logons, sudo, a new account, the EICAR
# test file, traffic on a shell port, unknown DNS names, a threat intel
# match), then checks through the API that it arrived, that the
# detections fire, and that searches, dashboards, cases, risk, scanners,
# sensors and the cluster work.
#
#   sudo lab-e2e          checks that change nothing lasting
#   sudo lab-e2e --all    also drains and restarts servers, stops an
#                         OpenSearch node and runs a vulnerability scan
#   --keep-findings       leaves the findings the test raises open
#
# The report goes to /root/lab/e2e/<time>/report.md (and report.json);
# the exit code is 1 when any check failed.
# A && B || C reads well for pass-or-fail lines (pass never fails), and jq
# programs are in single quotes on purpose.
# shellcheck disable=SC2015,SC2016
set -uo pipefail
umask 077
export HOME=/root

LAB=/root/lab
ALL=false
KEEP=false
for a in "$@"; do
  case $a in
    --all) ALL=true ;;
    --keep-findings) KEEP=true ;;
    -h | --help)
      sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "Unknown option $a (see lab-e2e --help)" >&2
      exit 2
      ;;
  esac
done

conf() { jq -r "$1" "$LAB/lab.json"; }
ip_of() { conf ".machines[] | select(.name == \"$1\") | .ip"; }
have() { [ -n "$(ip_of "$1")" ]; }
DOMAIN=$(conf .domain)
SIEM=$(conf .siem)
CA=/var/lib/signalith/tls/ca.pem
BIN=/usr/local/bin/signalith
STAMP=$(date -u +%Y%m%d-%H%M%S)
OUT=$LAB/e2e/$STAMP
mkdir -p "$OUT"
RESULTS=$OUT/results.tsv
: >"$RESULTS"
TAG="e2e$(date -u +%H%M%S)$RANDOM"

say() { printf '%s  %s\n' "$(date -u +%H:%M:%S)" "$*"; }

SSH=(ssh -i "$LAB/id_lab" -o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=30
  -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$LAB/known_hosts" -o LogLevel=ERROR)
on() {
  local host=$1
  shift
  "${SSH[@]}" "root@$(ip_of "$host")" "$@"
}

sg() {
  sudo -u signalith env SIGNALITH_STATE_DIR=/var/lib/signalith \
    SIGNALITH_DETECTIONS_DIR=/var/lib/signalith/detections \
    SIGNALITH_LOOKUPS_DIR=/var/lib/signalith/lookups \
    SIGNALITH_DASHBOARDS_DIR=/var/lib/signalith/dashboards \
    SIGNALITH_ARCHIVE_DIR=/var/lib/signalith/archive \
    "$BIN" "$@"
}

# ---- results ----

AREA=''
area() {
  AREA=$1
  say "== $1"
}
# result records one check: pass, fail, warn or skip, its name, and what
# was seen.
result() {
  local state=$1 name=$2 detail=${3:-}
  detail=${detail//$'\t'/ }
  detail=${detail//$'\n'/ }
  printf '%s\t%s\t%s\t%s\n' "$AREA" "$state" "$name" "${detail:0:400}" >>"$RESULTS"
  printf '%s  %-4s %s%s\n' "$(date -u +%H:%M:%S)" "$(tr '[:lower:]' '[:upper:]' <<<"$state")" "$name" "${detail:+: ${detail:0:200}}"
}
pass() { result pass "$@"; }
fail() { result fail "$@"; }
warn() { result warn "$@"; }
skip() { result skip "$@"; }

# ---- ports (8080 before the agent port; 9000 and 7779 after) ----

port_ready() { curl -fsSk -o /dev/null --max-time 5 "https://$1:$2/readyz"; }
WEB_PORT=''
for p in 9000 8080; do
  if curl -fsSk -o /dev/null --max-time 5 "https://127.0.0.1:$p/api/tls/ca.pem" &&
    curl -sk --max-time 5 "https://127.0.0.1:$p/" | grep -qi '<html'; then
    WEB_PORT=$p
    break
  fi
done
if [ -z "$WEB_PORT" ]; then
  echo "Signalith's web page answers on neither 9000 nor 8080 on this server. Is it running? (systemctl status signalith)" >&2
  exit 2
fi
AGENT_PORT=$WEB_PORT
if [ "$WEB_PORT" != 7779 ] && port_ready 127.0.0.1 7779; then AGENT_PORT=7779; fi
WEB="https://127.0.0.1:$WEB_PORT"

# ---- the API ----

PW=${E2E_PASSWORD:-}
[ -n "$PW" ] || PW=$(cat /etc/signalith/initial-admin-password 2>/dev/null)
CODE=''
BODY=''
# call METHOD PATH [JSON]: the answer goes in $BODY, the status in $CODE.
call() {
  local method=$1 path=$2 data=${3:-}
  local args=(-sS --max-time 330 --cacert "$CA" -u "admin:$PW" -X "$method" -o "$OUT/.body" -w '%{http_code}')
  [ -z "$data" ] || args+=(-H 'Content-Type: application/json' --data-binary "$data")
  CODE=$(curl "${args[@]}" "$WEB$path" 2>"$OUT/.err") || CODE=000
  BODY=$(cat "$OUT/.body" 2>/dev/null)
  [ "$CODE" != 000 ] || BODY=$(cat "$OUT/.err")
  rm -f "$OUT/.body" "$OUT/.err"
  [[ $CODE == 2* ]]
}
j() { jq -r "$@" <<<"$BODY" 2>/dev/null; }
why() { j '.error // empty' | head -c 300 || true; }

# search QUERY [EARLIEST]: rows in $ROWS, matched events in $MATCHED.
ROWS=0
MATCHED=0
search() {
  ROWS=0
  MATCHED=0
  call POST /api/search "$(jq -nc --arg q "$1" --arg e "${2:--1h}" '{query: $q, earliest: $e, latest: "now"}')" || return 1
  ROWS=$(j '.rows | length')
  MATCHED=$(j '.matched // 0')
}

# expect_events NAME QUERY [EARLIEST] [TRIES]: passes once QUERY finds
# something, searching every 15 seconds.
expect_events() {
  local name=$1 q=$2 e=${3:--30m} tries=${4:-8} i
  for ((i = 1; i <= tries; i++)); do
    if search "$q" "$e"; then
      if [ "$ROWS" -gt 0 ]; then
        pass "$name" "$MATCHED events ($q)"
        return 0
      fi
    else
      fail "$name" "search failed ($CODE): $(why) ($q)"
      return 1
    fi
    [ "$i" = "$tries" ] || sleep 15
  done
  fail "$name" "nothing found by: $q"
  return 1
}

# ---- before anything: can we sign in ----

if ! call GET /api/me; then
  if [ "$CODE" = 401 ]; then
    echo "The admin password was refused. If you changed it, run: sudo E2E_PASSWORD='<password>' lab-e2e" >&2
  else
    echo "Signalith's API did not answer ($CODE): $BODY" >&2
  fi
  exit 2
fi
if [ "$(j .must_change_password)" = true ]; then
  echo "The admin account must choose a new password first: sign in on the web page once, then run: sudo E2E_PASSWORD='<new password>' lab-e2e" >&2
  exit 2
fi

say "Signalith lab end-to-end test $STAMP (web port $WEB_PORT, agent port $AGENT_PORT$([ "$ALL" = true ] && echo ', with --all'))"
START=$(date -u +%s)

# =====================================================================
area "Servers and OpenSearch"

if call GET /api/cluster; then
  printf '%s' "$BODY" >"$OUT/cluster.json"
  servers=$(j '[.servers[] | select(.removed != true)] | length')
  notready=$(j '[.servers[] | select(.removed != true and .state != "ready") | "\(.name) \(.state)"] | join(", ")')
  versions=$(j '[.servers[] | select(.removed != true) | .version] | unique | join(", ")')
  holder=$(j '.lease.holder_name // empty')
  if [ -z "$notready" ]; then pass "Every server is ready" "$servers servers, version $versions"; else fail "Every server is ready" "not ready: $notready"; fi
  for m in signalith-1 signalith-2 scanner; do
    have "$m" || continue
    if j --arg n "$m" -e '.servers[] | select(.name == $n)' >/dev/null; then pass "$m is in the cluster"; else fail "$m is in the cluster" "not listed on the Servers page"; fi
  done
  if [ -n "$holder" ]; then pass "One server runs the jobs" "$holder"; else fail "One server runs the jobs" "no lease holder"; fi
  problems=$(j '[.servers[] | select((.problems // []) | length > 0) | "\(.name): \(.problems | map(if type == "object" then (.text // .message // tostring) else tostring end) | join("; "))"] | join(" | ")')
  if [ -z "$problems" ]; then pass "No server reports a problem"; else warn "No server reports a problem" "$problems"; fi
else
  fail "Cluster status" "($CODE) $(why)"
fi

if call GET /api/cluster/opensearch; then
  st=$(j .status)
  nodes=$(j .nodes)
  if [ "$st" = green ]; then pass "OpenSearch is green" "$nodes nodes"; else fail "OpenSearch is green" "$st, $nodes nodes, $(j '.problem // empty')"; fi
  down=$(j '[.endpoints[]? | select(.down) | .url] | join(", ")')
  if [ -z "$down" ]; then pass "Every OpenSearch address answers"; else fail "Every OpenSearch address answers" "down: $down"; fi
  full=$(j '[.disk[]? | select(.used_percent >= 85) | "\(.node) \(.used_percent)%"] | join(", ")')
  [ -z "$full" ] && pass "OpenSearch disks have room" || warn "OpenSearch disks have room" "$full"
else
  fail "OpenSearch status" "($CODE) $(why)"
fi

for m in signalith-1 signalith-2; do
  have "$m" || continue
  if port_ready "$m.$DOMAIN" "$WEB_PORT"; then pass "$m answers on $WEB_PORT"; else fail "$m answers on $WEB_PORT" "/readyz did not return 200"; fi
done
if [ "$SIEM" != "signalith-1.$DOMAIN" ] && [ -n "$(conf '.lb_ip // empty')" ]; then
  if port_ready "$SIEM" "$AGENT_PORT"; then pass "The load balancer answers on $AGENT_PORT" "$SIEM"; else fail "The load balancer answers on $AGENT_PORT" "https://$SIEM:$AGENT_PORT/readyz did not return 200"; fi
fi

if call GET /api/cluster/upgrade; then
  if [ "$(j .safe)" = true ]; then pass "Upgrade check says it is safe to upgrade" "next: $(j '.next // empty')"; else warn "Upgrade check says it is safe to upgrade" "$(j '[.blockers[]?.text] | join(" ")')"; fi
else
  fail "Upgrade check" "($CODE) $(why)"
fi

if call GET /api/health; then
  st=$(j .opensearch.status)
  failed=$(j '.ingest.failed // 0')
  if [ "$st" = green ]; then pass "Health page: OpenSearch" "$st"; else warn "Health page: OpenSearch" "$st $(j '.opensearch.problem // empty')"; fi
  if [ "$failed" = 0 ]; then pass "No events failed to index" "$(j .ingest.indexed) indexed"; else warn "No events failed to index" "$failed failed of $(j .ingest.received)"; fi
  w=$(j '[.warnings[]? | if type == "object" then (.text // .message // tostring) else tostring end] | join(" | ")')
  [ -z "$w" ] && pass "Health page has no warnings" || warn "Health page has no warnings" "$w"
else
  fail "Health page" "($CODE) $(why)"
fi

if sg security -json >"$OUT/security.json" 2>&1; then pass "signalith security finds nothing at risk"; else warn "signalith security finds nothing at risk" "$(jq -r '[.. | objects | select(.ok == false) | (.title // .name // .id // empty)] | join(", ")' "$OUT/security.json" 2>/dev/null | head -c 300)"; fi

# =====================================================================
area "Agents and data coming in"

if call GET /api/agents; then
  printf '%s' "$BODY" >"$OUT/agents.json"
  for m in linux-1 windows-1; do
    have "$m" || continue
    a=$(j --arg n "$m" --arg ip "$(ip_of "$m")" '[.agents[] | select(.name == $n or ((.addresses // []) | index($ip)))] | first // empty')
    if [ -z "$a" ]; then
      fail "Agent on $m sends" "not on the Agents list"
    elif [ "$(jq -r .silent <<<"$a")" = true ]; then
      fail "Agent on $m sends" "silent since $(jq -r .last_seen <<<"$a")"
    else
      pass "Agent on $m sends" "$(jq -r .events_1h <<<"$a") events in the last hour"
      nc=$(jq -r '(.needs_config // []) | join(", ")' <<<"$a")
      [ -z "$nc" ] && pass "Agent on $m has a current configuration" || warn "Agent on $m has a current configuration" "needs: $nc"
    fi
  done
  win=$(j '[.agents[] | select((.tag // "") | test("win"; "i"))] | length')
  [ "$win" -gt 0 ] && pass "A Windows agent sends" "$win" || skip "A Windows agent sends" "no Windows machine in the lab yet"
else
  fail "Agents list" "($CODE) $(why)"
fi

expect_events "linux-1's logs arrive" "host=linux-1" -15m 2
expect_events "linux-1's logons are read" "datamodel=Authentication dest=linux-1" -24h 1
expect_events "linux-1's audit log arrives" "host=linux-1 sourcetype=*audit*" -1h 1
expect_events "Linux process launches fill the Endpoint data model" "datamodel=Endpoint dest=linux-1" -1h 1

# OpenTelemetry: a record through the agent port, to the load balancer.
token=$(sg tokens create -purpose otel "Lab e2e $STAMP" 2>"$OUT/token.err")
if [ -z "$token" ]; then
  fail "OpenTelemetry token" "$(cat "$OUT/token.err")"
else
  otlp() {
    curl -sS -o "$OUT/.otlp" -w '%{http_code}' --max-time 15 --cacert "$CA" "https://$1:$2/api/otlp/v1/logs" \
      -H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
      -d "$(jq -nc --arg m "$3" '{resourceLogs: [{resource: {attributes: [{key: "service.name", value: {stringValue: "lab-e2e"}}]}, scopeLogs: [{logRecords: [{severityText: "INFO", body: {stringValue: $m}}]}]}]}')"
  }
  # Servers learn of a new token within a few seconds.
  for i in 1 2 3 4 5 6; do
    c=$(otlp "$SIEM" "$AGENT_PORT" "lab e2e otlp $TAG")
    [[ $c == 2* ]] && break
    sleep 5
  done
  if [[ $c == 2* ]]; then
    pass "OpenTelemetry record accepted on the agent port" "$SIEM:$AGENT_PORT ($c)"
    expect_events "OpenTelemetry record is searchable" "\"lab e2e otlp $TAG\"" -15m 8
  else
    fail "OpenTelemetry record accepted on the agent port" "$SIEM:$AGENT_PORT answered $c: $(head -c 200 "$OUT/.otlp")"
  fi
  if [ "$AGENT_PORT" != "$WEB_PORT" ]; then
    c=$(otlp 127.0.0.1 "$WEB_PORT" "lab e2e otlp web port $TAG")
    if [ "$c" = 503 ]; then
      pass "The web port sends agents to the agent port" "503: $(head -c 150 "$OUT/.otlp")"
    elif [[ $c == 2* ]]; then
      warn "The web port sends agents to the agent port" "the web port still takes agents ($c): server.agent_listen is not set on this upgraded server"
    else
      fail "The web port sends agents to the agent port" "answered $c: $(head -c 200 "$OUT/.otlp")"
    fi
    c=$(curl -sk -o "$OUT/.page" -w '%{http_code}' --max-time 5 "https://127.0.0.1:$AGENT_PORT/")
    if grep -qi '<html' "$OUT/.page" 2>/dev/null && [[ $c == 2* ]]; then
      fail "The agent port does not serve the web page" "https://127.0.0.1:$AGENT_PORT/ returned the web page"
    else
      pass "The agent port does not serve the web page" "$c"
    fi
    rm -f "$OUT/.page"
  else
    skip "Agent port separate from the web page" "this Signalith takes agents on its web port ($WEB_PORT)"
  fi
  rm -f "$OUT/.otlp"
  sg tokens revoke -yes "Lab e2e $STAMP" >/dev/null 2>&1 || true
fi

# Syslog, when the receiver is on.
if call GET /api/health && [ "$(j '.syslog.enabled')" = true ]; then
  l=$(j '[.syslog.listeners[]? | select(.protocol == "udp" or .protocol == "tcp")] | first // empty')
  if [ -z "$l" ]; then
    skip "Syslog message arrives" "the receiver listens on TLS only"
  else
    flag=-T
    [ "$(jq -r .protocol <<<"$l")" = udp ] && flag=-d
    on linux-1 "logger -n signalith-1 -P $(jq -r .port <<<"$l") $flag -t lab-e2e 'lab e2e syslog $TAG'" 2>/dev/null
    expect_events "Syslog message arrives" "\"lab e2e syslog $TAG\"" -15m 6
  fi
else
  skip "Syslog message arrives" "the syslog receiver is off (Add data > Syslog)"
fi

# The network sensor.
if have sensor; then
  if call GET /api/sensors; then
    printf '%s' "$BODY" >"$OUT/sensors.json"
    n=$(j '.sensors | length')
    bad=$(j '[.sensors[] | select(.state != "healthy") | "\(.name) \(.state): \((.problems // []) | map(tostring) | join("; "))"] | join(" | ")')
    if [ "$n" = 0 ]; then fail "Network sensor is healthy" "no sensor on the list"; elif [ -z "$bad" ]; then pass "Network sensor is healthy" "$(j '[.sensors[] | "\(.name) \(.events_1h) events/h"] | join(", ")')"; else fail "Network sensor is healthy" "$bad"; fi
  else
    fail "Network sensors list" "($CODE) $(why)"
  fi
  expect_events "Zeek connection logs arrive" "sourcetype=zeek:* datamodel=Network_Traffic" -30m 1
  expect_events "Zeek DNS logs arrive" "datamodel=Network_Resolution" -1h 1
  expect_events "Suricata alerts arrive" "datamodel=Intrusion_Detection vendor_product=*uricata*" -24h 1
fi

# =====================================================================
area "Attacks and detections"

say "  making the lab misbehave"
# Failed logons as 12 accounts that do not exist, from the scanner (or
# signalith-2): brute force and password spray.
from=scanner
have scanner || from=signalith-2
have "$from" || from=''
if [ -n "$from" ]; then
  on "$from" "for i in \$(seq 1 12); do ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o LogLevel=QUIET e2e-nobody\$i@linux-1 true; done; true"
fi
# A new account, three wrong sudo passwords, password hashes read with
# sudo, the EICAR test file, traffic to a shell port, unknown DNS names
# and the lab's own cleartext test alert; then the account goes again.
on linux-1 bash -s <<'EOF' >"$OUT/attacks.log" 2>&1
set -u
id e2e-tester >/dev/null 2>&1 || useradd -m -s /bin/bash e2e-tester
echo "e2e-tester:$(openssl rand -hex 12)Aa1!" | chpasswd
for i in 1 2 3; do su e2e-tester -s /bin/sh -c 'echo wrong-password | sudo -S -k true' </dev/null; done
sudo cat /etc/shadow >/dev/null
if command -v clamdscan >/dev/null; then
  printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' >/root/e2e-eicar.com.txt
  clamdscan --fdpass /root/e2e-eicar.com.txt
  rm -f /root/e2e-eicar.com.txt
fi
curl -s -o /dev/null --max-time 8 http://portquiz.net:4444/
for i in $(seq 1 30); do getent hosts "e2e-$RANDOM-$i.example.com" >/dev/null; done
[ -x /usr/local/sbin/lab-traffic ] && /usr/local/sbin/lab-traffic
sleep 2
userdel -r e2e-tester 2>/dev/null
true
EOF
# A threat intel match: the address linux-1 just sent to on port 4444,
# which the sensor saw (private addresses never count as indicators).
INDICATOR=''
quiz=$(on linux-1 'getent ahostsv4 portquiz.net | head -1' 2>/dev/null | awk '{print $1}')
if have sensor && [ -n "$quiz" ] && call POST /api/intel/indicators "$(jq -nc --arg v "$quiz" '{value: $v, type: "ip", description: "Lab end-to-end test", weight: "80", expires: "1d", tags: ["lab-e2e"]}')"; then
  INDICATOR=$(j .id)
fi
say "  waiting 90 seconds for the events to arrive"
sleep 90

[ -z "$from" ] || expect_events "Failed logons from $from are read" "datamodel=Authentication action=failure dest=linux-1 user=e2e-nobody*" -15m 6
expect_events "sudo use is read" "datamodel=Authentication app=sudo dest=linux-1" -15m 4
expect_events "The new account is read" "datamodel=Change object=e2e-tester" -15m 4
if on linux-1 'command -v clamdscan' >/dev/null 2>&1; then
  expect_events "EICAR found by ClamAV is read" "datamodel=Malware dest=linux-1 file_path=/root/e2e-eicar.com.txt" -15m 6
else
  skip "EICAR found by ClamAV is read" "ClamAV is not installed on linux-1 (apt-get install clamav-daemon)"
fi
if have sensor; then
  expect_events "Traffic to port 4444 is seen by the sensor" "datamodel=Network_Traffic dest_port=4444" -15m 8
fi

FINDINGS=()
# detection ID: runs it now (as Run now does) and checks that it has
# results and a finding; a finding raised earlier still counts, since
# findings are throttled.
detection() {
  local id=$1 name
  name=$(jq -r --arg i "$id" '.detections[] | select(.id == $i) | .title' "$OUT/detections.json" 2>/dev/null)
  [ -n "$name" ] || name=$id
  if ! jq -e --arg i "$id" '.detections[] | select(.id == $i)' "$OUT/detections.json" >/dev/null 2>&1; then
    fail "Detection $id" "not installed"
    return
  fi
  if [ "$(jq -r --arg i "$id" '.detections[] | select(.id == $i) | .enabled' "$OUT/detections.json")" != true ]; then
    warn "Detection $id fires" "turned off"
    return
  fi
  if ! call POST "/api/detections/$id/run"; then
    fail "Detection $id fires" "Run now failed ($CODE): $(why)"
    return
  fi
  local results throttled ids
  results=$(j '.results // 0')
  throttled=$(j '.throttled // 0')
  ids=$(j '[.findings[]?.id] | join(" ")')
  # shellcheck disable=SC2206
  FINDINGS+=($ids)
  if [ "$results" -gt 0 ] && [ -n "$ids" ]; then
    pass "Detection $id fires" "$results results, finding raised"
  elif [ "$results" -gt 0 ]; then
    if call GET "/api/findings?detection=$id&since=24h&limit=1" && [ "$(j '.total // 0')" -gt 0 ]; then
      pass "Detection $id fires" "$results results; already raised in the last 24 hours ($throttled throttled)"
    else
      fail "Detection $id fires" "$results results but no finding ($throttled throttled)"
    fi
  else
    fail "Detection $id fires" "no results over its lookback"
  fi
}

if call GET /api/detections; then
  printf '%s' "$BODY" >"$OUT/detections.json"
  pass "Detections are loaded" "$(j '[.detections[] | select(.enabled)] | length') on of $(j '.detections | length')"
  errs=$(j '[.detections[] | select(.enabled and ((.state.last_error // "") != "")) | "\(.id): \(.state.last_error)"] | join(" | ")')
  [ -z "$errs" ] && pass "No detection has an error on its last run" || fail "No detection has an error on its last run" "$errs"
  behind=$(j '[.detections[] | select(.enabled and (.state.late_runs // 0) > 0) | .id] | length')
  [ "$behind" = 0 ] && pass "No detection runs late" || warn "No detection runs late" "$behind detections had late runs"
  if [ -n "$from" ]; then
    detection auth-brute-force
    detection auth-password-spray
  fi
  detection auth-sudo-failures
  detection auth-shadow-file-access
  detection change-account-created
  detection change-account-deleted
  detection auth-ssh-root-login
  if on linux-1 'command -v clamdscan' >/dev/null 2>&1; then
    detection malware-detected
    detection malware-left-clamav
  fi
  if have sensor; then
    detection network-shell-port
    detection network-dns-nxdomain-burst
  fi
  if [ -n "$INDICATOR" ]; then
    detection threat-activity
  elif have sensor; then
    fail "Detection threat-activity fires" "the test indicator was not added ($CODE): $(why)"
  fi
  # The detection packs' Linux rules read audit logs of programs run.
  pack=$(j '[.detections[] | select(.enabled and ((.query // "") | test("sourcetype=\"?linux:audit|datamodel=Endpoint"; "i")) and ((.tags // []) | tostring | test("linux"; "i")))] | length')
  [ "$pack" -gt 0 ] && pass "Linux rules of the detection packs are on" "$pack" || skip "Linux rules of the detection packs are on" "none turned on (Detections > Packs)"
else
  fail "Detections list" "($CODE) $(why)"
fi
[ -z "$INDICATOR" ] || call DELETE "/api/intel/indicators/$INDICATOR" || warn "Remove the test indicator" "($CODE) $(why)"

if call GET '/api/risk?since=1h'; then
  r=$(j '[.objects[] | select(.risk_object == "linux-1" or .risk_object == "linux-1.'"$DOMAIN"'")] | first | .risk_score // 0')
  [ "${r%.*}" -gt 0 ] && pass "linux-1 has a risk score" "$r" || fail "linux-1 has a risk score" "no risk in the last hour ($(j '.objects | length') objects)"
else
  fail "Risk" "($CODE) $(why)"
fi

# The test's findings go into a case, which is then closed as benign.
if [ "${#FINDINGS[@]}" -gt 0 ]; then
  ids=$(printf '%s\n' "${FINDINGS[@]}" | jq -R . | jq -sc .)
  if call POST /api/cases "$(jq -nc --arg t "Lab end-to-end test $STAMP" --argjson f "$ids" '{title: $t, description: "Findings the lab end-to-end test raised on purpose.", severity: "low", findings: $f}')"; then
    case_id=$(j .case.id)
    n=$(j '.case.findings | length')
    [ "$n" = "${#FINDINGS[@]}" ] && pass "A case holds the test's findings" "$n findings" || fail "A case holds the test's findings" "$n of ${#FINDINGS[@]} added: $(j '.failed | tostring')"
    if [ "$KEEP" = true ]; then
      skip "Close the case and its findings" "--keep-findings"
    elif call PATCH "/api/cases/$case_id" '{"status":"closed","resolution":"Lab end-to-end test: raised on purpose.","close_findings":true,"disposition":"benign_true_positive"}'; then
      pass "Close the case and its findings" "$(j '.findings_closed // 0') findings closed as benign"
    else
      fail "Close the case and its findings" "($CODE) $(why)"
    fi
  else
    fail "A case holds the test's findings" "($CODE) $(why)"
  fi
else
  skip "A case holds the test's findings" "the test raised no new findings (all throttled)"
fi

if call GET '/api/playbooks/runs?limit=5'; then pass "Playbook runs list" "$(j '.total // 0') runs"; else fail "Playbook runs list" "($CODE) $(why)"; fi
if call GET /api/respond/actions; then pass "Response actions list" "$(j '.actions | length') actions"; elif [ "$CODE" = 503 ]; then skip "Response actions list" "response actions are off"; else fail "Response actions list" "($CODE) $(why)"; fi
if call GET /api/notify; then
  pass "Notifications settings" "$(j '.channels | length') channels"
  bad=$(j '[.channels[]? | select((.problem // "") != "") | "\(.label // .id): \(.problem)"] | join(" | ")')
  [ -z "$bad" ] || warn "Notification channels work" "$bad"
else
  fail "Notifications settings" "($CODE) $(why)"
fi

# =====================================================================
area "Search, Ask and dashboards"

while IFS='|' read -r name q; do
  [ -n "$name" ] || continue
  if search "$q" -24h; then
    if [ "$ROWS" -gt 0 ]; then pass "Search: $name" "$ROWS rows"; else fail "Search: $name" "no rows: $q"; fi
  else
    fail "Search: $name" "($CODE) $(why): $q"
  fi
done <<'Q'
events|host=linux-1 | head 5
stats by sourcetype|* | stats count by sourcetype | sort -count
timechart|datamodel=Authentication | timechart span=1h count by action
eval and where|datamodel=Authentication | eval failed=if(action="failure",1,0) | stats sum(failed) as failed, count by dest | where count > 0
rex|datamodel=Authentication app=sshd | rex field=signature "SSH (?<outcome>\w+)" | stats count by outcome
dedup and table|* | dedup sourcetype | table sourcetype, host
stats functions|datamodel=Authentication | stats dc(user) as users, values(app) as apps, latest(_time) as last by dest
data model|datamodel=Authentication action=failure | stats count by src, user | sort -count | head 10
index field|* | stats count by index
Q

if call POST /api/ask '{"question":"failed logins on linux-1 in the last 24 hours","mode":"rules"}'; then
  q=$(j .query)
  if search "$q" -24h; then
    [ "$ROWS" -gt 0 ] && pass "Ask: failed logins on linux-1" "$q" || warn "Ask: failed logins on linux-1" "no rows: $q"
  else
    fail "Ask: failed logins on linux-1" "its query fails ($CODE): $(why): $q"
  fi
else
  fail "Ask" "($CODE) $(why)"
fi

if call GET /api/dashboards; then
  for id in $(j '.dashboards[] | select(.id != "posture") | .id'); do
    if call POST "/api/dashboards/$id/run" '{}'; then
      total=$(j '.panels | length')
      errs=$(j '[.panels[] | select((.error // "") != "") | "panel \(.index + 1): \(.error)"] | join(" | ")')
      empty=$(j '[.panels[] | select((.error // "") == "" and ((.result.rows // []) | length) == 0 and .value == null)] | length')
      if [ -n "$errs" ]; then fail "Dashboard $id" "$errs"; else pass "Dashboard $id" "$total panels, $empty without data"; fi
    else
      fail "Dashboard $id" "($CODE) $(why)"
    fi
  done
else
  fail "Dashboards list" "($CODE) $(why)"
fi
if call GET '/api/posture?range=24h'; then
  errs=$(j '[.errors[]?, (.indicators[]? | select((.error // "") != "") | "\(.label): \(.error)")] | map(tostring) | join(" | ")')
  [ -z "$errs" ] && pass "Security posture dashboard" "$(j '.indicators | length') indicators" || fail "Security posture dashboard" "$errs"
  erroring=$(j '[.health.erroring[]? | tostring] | join(", ")')
  [ -z "$erroring" ] || fail "Posture: no detection erroring" "$erroring"
else
  fail "Security posture dashboard" "($CODE) $(why)"
fi

page=$(curl -sS --max-time 10 --cacert "$CA" "$WEB/")
if grep -qi '<title' <<<"$page"; then
  missing=''
  while read -r a; do
    [ -z "$a" ] || curl -fsS -o /dev/null --max-time 10 --cacert "$CA" "$WEB$a" || missing+=" $a"
  done < <(grep -oE '(src|href)="/[^"]+\.(js|css)[^"]*"' <<<"$page" | sed -E 's/^(src|href)="//; s/"$//' | sort -u)
  [ -z "$missing" ] && pass "The web page and its scripts load" || fail "The web page and its scripts load" "missing:$missing"
else
  fail "The web page loads" "no page at $WEB/"
fi

if call GET /api/compliance; then pass "Compliance page" "$(j '.frameworks | length') frameworks"; else fail "Compliance page" "($CODE) $(why)"; fi
if call GET /api/coverage; then pass "MITRE coverage" "$(j '.summary.enabled // 0') techniques covered"; else fail "MITRE coverage" "($CODE) $(why)"; fi
if call GET '/api/audit?size=5'; then
  [ "$(j .enabled)" = true ] && pass "Audit log" "$(j '.total // 0') events" || warn "Audit log" "off: $(j '.note // empty')"
else
  fail "Audit log" "($CODE) $(why)"
fi
if call GET /api/retention; then
  e=$(j '[.error, .disk_error, .settings_error] | map(select(. != null and . != "")) | join(" | ")')
  [ -z "$e" ] && pass "Retention" "last run $(j '.last_run.finished // .last_run.started // .last_run // "not yet" | tostring' | head -c 60)" || fail "Retention" "$e"
else
  fail "Retention" "($CODE) $(why)"
fi
if sg cluster export -settings -o "$OUT/settings-export.yaml" >/dev/null 2>"$OUT/export.err" && [ -s "$OUT/settings-export.yaml" ]; then
  pass "Shared settings export" "$(wc -c <"$OUT/settings-export.yaml") bytes"
else
  fail "Shared settings export" "$(head -c 300 "$OUT/export.err")"
fi
rm -f "$OUT/settings-export.yaml" "$OUT/export.err"

# =====================================================================
area "Vulnerability scanning"

if have scanner; then
  if call GET '/api/vulns/scanners?fresh=1'; then
    printf '%s' "$BODY" >"$OUT/scanners.json"
    s=$(j '[.servers[] | select(.scanner == true or .name == "scanner")] | first // empty')
    if [ -z "$s" ]; then
      fail "The scanner server is listed" "not on Settings > Scanners"
    else
      [ "$(jq -r .online <<<"$s")" = true ] && pass "The scanner server is online" || fail "The scanner server is online" "$(jq -r .state <<<"$s")"
      [ "$(jq -r .ready <<<"$s")" = true ] && pass "The scanner server can scan" || fail "The scanner server can scan" "$(jq -c .report <<<"$s" | head -c 300)"
      ov=$(jq -r '.report | tostring | test("openvas"; "i")' <<<"$s")
      if [ "$ov" = true ]; then
        if jq -e '.report | tostring | test("still loading|feed"; "i")' <<<"$s" >/dev/null; then warn "OpenVAS is ready" "its feeds are still loading"; else pass "OpenVAS answers"; fi
      fi
      SCANNER_ID=$(jq -r .id <<<"$s")
    fi
  else
    fail "Scanners" "($CODE) $(why)"
  fi
  if call GET /api/vulns; then
    printf '%s' "$BODY" >"$OUT/vulns.json"
    target=$(j --arg s "${SCANNER_ID:-}" '[.targets[] | select(.enabled and .scanner == $s)] | first | .id // empty')
    pass "Vulnerabilities page" "$(j '.totals.hosts') hosts, $(j '.totals.critical') critical, $(j '.totals.kev // 0') known exploited"
    last=$(j --arg t "$target" '[.scans[] | select(.target_id == $t)] | first // empty')
    if [ -z "$target" ]; then
      skip "A scan on the scanner finishes" "no network is set to scan from the scanner (docs/cloud-lab.md, Vulnerability scans)"
    elif [ "$ALL" = true ]; then
      if call POST "/api/vulns/networks/$target/scan"; then
        sid=$(j .scan.id)
        say "  scanning $target from the scanner (up to 30 minutes)"
        for i in $(seq 1 120); do
          sleep 15
          call GET /api/vulns || continue
          st=$(j --arg i "$sid" '.scans[] | select(.id == $i) | .state')
          case $st in done | failed | stopped | interrupted) break ;; esac
        done
        sc=$(j --arg i "$sid" '.scans[] | select(.id == $i)')
        if [ "$st" = "done" ]; then
          pass "A scan on the scanner finishes" "$(jq -c '.counts' <<<"$sc")"
          oe=$(jq -r '.openvas_error // empty' <<<"$sc")
          [ -z "$oe" ] || fail "OpenVAS part of the scan" "$oe"
        else
          fail "A scan on the scanner finishes" "$st: $(jq -r '.error // empty' <<<"$sc")"
        fi
      else
        fail "Start a scan" "($CODE) $(why)"
      fi
    elif [ -n "$last" ]; then
      st=$(jq -r .state <<<"$last")
      [ "$st" = "done" ] && pass "The last scan on the scanner finished" "$(jq -r '.finished_at' <<<"$last")" || fail "The last scan on the scanner finished" "$st: $(jq -r '.error // .openvas_error // empty' <<<"$last")"
    else
      skip "A scan on the scanner finishes" "no scan yet (lab-e2e --all runs one)"
    fi
  else
    fail "Vulnerabilities page" "($CODE) $(why)"
  fi
fi

# =====================================================================
if [ "$ALL" = true ]; then
  area "Servers coming and going"

  wait_request() {
    local id=$1 i st
    for i in $(seq 1 40); do
      call GET "/api/requests/$id" || return 1
      st=$(j .state)
      case $st in done) return 0 ;; failed) return 1 ;; esac
      sleep 5
    done
    return 1
  }
  server_state() { call GET /api/cluster && j --arg n "$1" '.servers[] | select(.name == $n) | .state'; }

  if have signalith-2 && call GET /api/cluster; then
    node=$(j '.servers[] | select(.name == "signalith-2") | .node_id')
    if call POST "/api/cluster/servers/$node/drain" && wait_request "$(j .request_id)"; then
      pass "Drain signalith-2" "$(server_state signalith-2)"
      if port_ready "$SIEM" "$AGENT_PORT" && search "host=linux-1" -10m && [ "$ROWS" -gt 0 ]; then pass "Events still arrive while signalith-2 is drained"; else fail "Events still arrive while signalith-2 is drained" "$CODE"; fi
      if call POST "/api/cluster/servers/$node/resume" && wait_request "$(j .request_id)"; then
        sleep 10
        st=$(server_state signalith-2)
        [ "$st" = ready ] && pass "signalith-2 resumes" || fail "signalith-2 resumes" "$st"
      else
        fail "signalith-2 resumes" "($CODE) $(why) $(j '.error // empty')"
      fi
    else
      fail "Drain signalith-2" "($CODE) $(why) $(j '.error // empty')"
    fi
  fi

  if call GET /api/cluster; then
    holder=$(j '.lease.holder_name')
    if [ -n "$holder" ] && [ "$holder" != null ]; then
      say "  restarting $holder, which runs the jobs"
      if [ "$holder" = signalith-1 ]; then systemctl restart signalith; else on "$holder" 'systemctl restart signalith'; fi
      ok=''
      for i in $(seq 1 24); do
        sleep 5
        call GET /api/cluster || continue
        h=$(j '.lease.holder_name // empty')
        nr=$(j '[.servers[] | select(.removed != true and .state != "ready")] | length')
        if [ -n "$h" ] && [ "$nr" = 0 ]; then
          ok=$h
          break
        fi
      done
      [ -n "$ok" ] && pass "The jobs carry on after $holder restarts" "now on $ok, after $((i * 5)) seconds" || fail "The jobs carry on after $holder restarts" "no ready lease holder after 2 minutes"
    fi
  fi

  if have opensearch-3; then
    say "  stopping OpenSearch on opensearch-3"
    on opensearch-3 'systemctl stop opensearch'
    sleep 20
    if search "* | stats count" -1h && [ "$ROWS" -gt 0 ]; then pass "Searches work with an OpenSearch node down"; else fail "Searches work with an OpenSearch node down" "($CODE) $(why)"; fi
    expect_events "Events are indexed with an OpenSearch node down" "host=linux-1" -2m 6
    on opensearch-3 'systemctl start opensearch'
    st=''
    for i in $(seq 1 40); do
      sleep 15
      call GET /api/cluster/opensearch || continue
      st=$(j .status)
      [ "$st" = green ] && break
    done
    [ "$st" = green ] && pass "OpenSearch is green again" "after $((i * 15)) seconds" || fail "OpenSearch is green again" "$st after 10 minutes"
  fi
fi

# =====================================================================
# The report.

took=$(($(date -u +%s) - START))
jq -R -s 'split("\n") | map(select(. != "") | split("\t") | {area: .[0], state: .[1], check: .[2], detail: .[3]})' "$RESULTS" >"$OUT/report.json"
count() { jq --arg s "$1" '[.[] | select(.state == $s)] | length' "$OUT/report.json"; }
P=$(count pass)
F=$(count fail)
W=$(count warn)
S=$(count skip)
version=$(jq -r '[.servers[]?.version] | unique | join(", ")' "$OUT/cluster.json" 2>/dev/null)
{
  echo "# Lab end-to-end test"
  echo
  echo "$(date -u '+%Y-%m-%d %H:%M UTC'), Signalith ${version:-?}, $((took / 60)) minutes$([ "$ALL" = true ] && echo ', with --all')."
  echo
  echo "**$P passed, $F failed, $W to look at, $S skipped.**"
  if [ "$F" -gt 0 ]; then
    echo
    echo "## Failed"
    echo
    jq -r '.[] | select(.state == "fail") | "- **\(.check)** (\(.area)): \(.detail)"' "$OUT/report.json"
  fi
  if [ "$W" -gt 0 ]; then
    echo
    echo "## To look at"
    echo
    jq -r '.[] | select(.state == "warn") | "- **\(.check)** (\(.area)): \(.detail)"' "$OUT/report.json"
  fi
  if [ "$S" -gt 0 ]; then
    echo
    echo "## Skipped"
    echo
    jq -r '.[] | select(.state == "skip") | "- \(.check): \(.detail)"' "$OUT/report.json"
  fi
  echo
  echo "## Everything"
  jq -r '. as $all | (reduce (map(.area))[] as $a ([]; if index([$a]) then . else . + [$a] end))[] as $a | [$all[] | select(.area == $a)] | "\n### \(.[0].area)\n\n| | Check | Seen |\n| --- | --- | --- |", (.[] | "| \({pass: "✅", fail: "❌", warn: "⚠️", skip: "➖"}[.state]) | \(.check) | \(.detail | gsub("\\|"; "/")) |")' "$OUT/report.json"
} >"$OUT/report.md"
rm -f "$RESULTS"
ln -sfn "$OUT" "$LAB/e2e/latest"

echo
say "$P passed, $F failed, $W to look at, $S skipped. Report: $OUT/report.md"
[ "$F" = 0 ]
