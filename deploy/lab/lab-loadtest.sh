#!/usr/bin/env bash
# lab-loadtest: the cloud lab's terabyte-a-day load test (docs/cloud-lab.md).
# It needs the lab made with size = "loadtest", and runs on signalith-1:
#
#   sudo lab-loadtest          starts the test in the background (about 4.5 hours)
#   sudo lab-loadtest spread   starts the detection spread test instead (about
#                              4.5 hours; needs loadtest_servers = 2 or 3)
#   sudo lab-loadtest status   shows how far it is
#   sudo lab-loadtest stop     stops it, keeping what it measured so far
#
# The load generator runs loadtest/tb-day.yaml against signalith-1 while
# every machine records its CPU, memory, disk and network every 15
# seconds, and OpenSearch's counts, per-node load and how far its newest
# event is behind the clock every 30 seconds. Every minute it also keeps
# each detection's run state (detstate), OpenSearch's search thread pool
# and how the detections are spread over the servers (GET /api/cluster),
# and every 10 minutes OpenSearch's shards and indices; at the end, each
# Signalith server's log lines about detections and rollover. The
# results are in /root/lab/loadtest/<time>/ (latest is the newest):
# report.md, the load generator's report (loadgen.txt, loadgen.json) and
# the samples (*.csv, *.jsonl, logs-*.txt).
#
# spread runs loadtest/spread-10k.yaml (10,000 events a second) through
# every server's agent port, and the phases of the detection spread
# measurement plan, 45 minutes each, written to phases.csv: 1 spread off;
# 2 spread on (detections.spread); 3 signalith-2 restarted with
# systemctl; 4 signalith-3 (or the last server) killed with kill -9, left
# down 10 minutes and started again. The plan's phase 5 (a noisy tenant)
# is done by hand: see docs/cloud-lab.md.
set -uo pipefail

LAB=/root/lab
UNIT=lab-loadtest
LOG=/var/log/lab-loadtest.log

[ "$(id -u)" = 0 ] || { echo "Run it as root: sudo lab-loadtest" >&2; exit 2; }
[ -f "$LAB/lab.json" ] || { echo "This is not the lab's signalith-1 ($LAB/lab.json is missing)." >&2; exit 2; }

conf() { jq -r "$1" "$LAB/lab.json"; }
ip_of() { conf ".machines[] | select(.name == \"$1\") | .ip"; }
names() { conf '.machines[].name'; }
servers() { conf '.machines[] | select(.role == "signalith") | .name'; }
say() { printf '%s  %s\n' "$(date -u +%H:%M:%S)" "$*"; }

SSH=(ssh -i "$LAB/id_lab" -o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=30
  -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$LAB/known_hosts" -o LogLevel=ERROR)
on() {
  local host=$1
  shift
  if [ "$host" = signalith-1 ]; then bash -c "$*"; else "${SSH[@]}" "root@$(ip_of "$host")" "$@"; fi
}

# need_spread refuses the spread test on a lab with one Signalith server.
need_spread() {
  local n
  n=$(servers | wc -l)
  if [ "$n" -lt 2 ]; then
    echo "The spread test needs 2 or 3 Signalith servers; this lab has $n. Make the lab again with" >&2
    echo "  terraform apply -var size=loadtest -var loadtest_servers=3 -var loadtest_opensearch_type=cx33" >&2
    echo "(see docs/cloud-lab.md), then run sudo lab-loadtest spread." >&2
    exit 2
  fi
}

case "${1:-start}" in
  start | spread)
    [ -n "$(ip_of loadgen)" ] || { echo "This lab has no load generator: make it with terraform apply -var size=loadtest (docs/cloud-lab.md)." >&2; exit 2; }
    mode=tb-day
    if [ "${1:-start}" = spread ]; then
      need_spread
      mode=spread
    fi
    if systemctl is-active -q "$UNIT"; then
      echo "The load test is already running: sudo lab-loadtest status" >&2
      exit 1
    fi
    systemd-run -q --unit="$UNIT" --collect -p StandardOutput="append:$LOG" -p StandardError="append:$LOG" -p TimeoutStopSec=300 "$0" run "$mode"
    echo "Started. It takes about 4.5 hours; see how far it is with: sudo lab-loadtest status"
    exit 0
    ;;
  status)
    if systemctl is-active -q "$UNIT"; then echo "Running."; else echo "Not running."; fi
    tail -n 15 "$LOG" 2>/dev/null
    exit 0
    ;;
  stop)
    systemctl stop "$UNIT" && echo "Stopped. What it measured is in $LAB/loadtest/latest/."
    exit 0
    ;;
  run)
    # One run at a time, also when run is started by hand: a second one
    # would restart the samplers and the load generator under the first.
    exec 9>/run/lab-loadtest.lock
    flock -n 9 || { echo "Another load test is running: sudo lab-loadtest status" >&2; exit 1; }
    MODE=${2:-tb-day}
    [ "$MODE" != spread ] || need_spread
    ;;
  *)
    echo "Usage: lab-loadtest [start|spread|status|stop]" >&2
    exit 2
    ;;
esac

OUT=$LAB/loadtest/$(date -u +%Y%m%d-%H%M%S)
mkdir -p "$OUT"
# Each run's samples have a file of their own on every machine.
SAMPLES=/root/lt-sample-$(basename "$OUT").csv
ln -sfn "$OUT" "$LAB/loadtest/latest"
say "Load test ($MODE): results in $OUT"
RUN_START=$(date -u +%s)
DOMAIN=$(conf .domain)

# ---- samples on every machine ----

# sampler prints a script that writes one CSV line every 15 seconds:
# CPU busy %, memory used, data disk used, disk writes and network.
sampler() {
  cat <<'EOF'
set -u
out=$1
data=/
mountpoint -q /var/lib/opensearch && data=/var/lib/opensearch
# The counters pass more than 2^32: awk prints them with %.0f, as print
# would write them in exponent form, which bash cannot count with.
cpu() { awk '/^cpu / { printf "%.0f %.0f\n", $2+$3+$4+$7+$8+$9, $2+$3+$4+$5+$6+$7+$8+$9 }' /proc/stat; }
wr() { awk '$3 !~ /^(loop|ram|sr)/ && $3 !~ /[0-9]p?[0-9]+$/ { s += $10 } END { printf "%.0f\n", s * 512 }' /proc/diskstats; }
# A port's name may or may not have spaces before it: split at the colon.
net() { awk 'NR > 2 { sub(/^ +/, ""); split($0, a, ":"); if (a[1] == "lo") next; split(a[2], f, " "); r += f[1]; t += f[9] }
  END { printf "%.0f %.0f\n", r, t }' /proc/net/dev; }
echo time,cpu_pct,load1,mem_used_mb,mem_total_mb,disk_used_gb,disk_size_gb,disk_write_mb_s,net_rx_mb_s,net_tx_mb_s >"$out"
read -r b0 t0 < <(cpu); w0=$(wr); read -r r0 x0 < <(net)
while sleep 15; do
  read -r b1 t1 < <(cpu); w1=$(wr); read -r r1 x1 < <(net)
  read -r used size < <(df -B1 --output=used,size "$data" | tail -n 1)
  awk -v b=$((b1 - b0)) -v t=$((t1 - t0)) -v w=$((w1 - w0)) -v r=$((r1 - r0)) -v x=$((x1 - x0)) \
    -v l="$(cut -d' ' -f1 /proc/loadavg)" -v u="$used" -v s="$size" -v now="$(date -u +%FT%TZ)" '
    /MemTotal/ { mt = $2 } /MemAvailable/ { ma = $2 }
    END { printf "%s,%.1f,%s,%d,%d,%.1f,%.1f,%.2f,%.2f,%.2f\n", now, t ? 100 * b / t : 0, l, (mt - ma) / 1024, mt / 1024,
      u / 2^30, s / 2^30, w / 15 / 2^20, r / 15 / 2^20, x / 15 / 2^20 }' /proc/meminfo >>"$out"
  b0=$b1 t0=$t1 w0=$w1 r0=$r1 x0=$x1
done
EOF
}

# Ubuntu's automatic updates restart services, and systemd re-executing
# itself during one stopped and restarted a run: hold them for the run.
APT_UNITS="apt-daily.timer apt-daily-upgrade.timer apt-daily.service apt-daily-upgrade.service unattended-upgrades.service"
hold_updates() {
  local m
  for m in $(names); do on "$m" "systemctl stop $APT_UNITS 2>/dev/null; true" </dev/null; done
}
release_updates() {
  local m
  for m in $(names); do on "$m" 'systemctl start apt-daily.timer apt-daily-upgrade.timer unattended-upgrades.service 2>/dev/null; true' </dev/null; done
}

stop_samplers() {
  local m
  for m in $(names); do on "$m" 'systemctl stop lt-sample 2>/dev/null; true' </dev/null; done
}

# ---- the summary ----

report() {
  python3 - "$OUT" "$MODE" <<'EOF'
import csv, glob, json, os, re, statistics, sys
from datetime import datetime, timezone
out, mode = sys.argv[1], sys.argv[2]

def rows(path):
    try:
        with open(path) as f:
            return list(csv.DictReader(f))
    except OSError:
        return []

def num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None

if mode == "spread":
    print("# Detection spread load test\n")
    print(f"Results folder: `{out}`. The load: 10,000 events a second of about 500 bytes for 4 hours "
          "(loadtest/spread-10k.yaml) through every server's agent port, with 5 analysts searching, "
          "while the phases below turn detections.spread on, restart one server and kill another.\n")
else:
    print("# Terabyte-a-day load test\n")
    print(f"Results folder: `{out}`. The load: 25,000 events a second of about 500 bytes for 4 hours "
          "(loadtest/tb-day.yaml), after 10 minutes at 5,000 and 10 at 15,000, with 5 analysts searching.\n")

lines = []
try:
    with open(os.path.join(out, "loadgen.txt")) as f:
        text = f.read()
    lines = [l for l in text.splitlines() if re.match(r"^(PASS|FAIL|RECORD|SKIP)\s", l)]
except OSError:
    pass
print("## The load generator's measurements\n")
if lines:
    print("```\n" + "\n".join(lines) + "\n```\n")
else:
    print("None: see loadgen.txt.\n")

print("## Each machine\n")
print("| Machine | CPU avg % | CPU max % | Memory max (of total) | Data disk used at end (of size) | Disk writes avg MB/s | Network in avg MB/s |")
print("| --- | --- | --- | --- | --- | --- | --- |")
busy = []
machines = {}
for path in sorted(glob.glob(os.path.join(out, "*.csv"))):
    name = os.path.basename(path)[:-4]
    if name.startswith("opensearch") and name not in ("opensearch-1", "opensearch-2", "opensearch-3"):
        continue
    r = rows(path)
    # Only the machines' samples: phases.csv and the like have no CPU.
    if not r or "cpu_pct" not in r[0]:
        continue
    machines[name] = r
    cpu = [num(x["cpu_pct"]) for x in r if num(x["cpu_pct"]) is not None]
    mem = [num(x["mem_used_mb"]) for x in r if num(x["mem_used_mb"]) is not None]
    wr = [num(x["disk_write_mb_s"]) for x in r if num(x["disk_write_mb_s"]) is not None]
    rx = [num(x["net_rx_mb_s"]) for x in r if num(x["net_rx_mb_s"]) is not None]
    last = r[-1]
    if not cpu:
        continue
    print(f"| {name} | {statistics.mean(cpu):.0f} | {max(cpu):.0f} | {max(mem):.0f} MB ({float(last['mem_total_mb']):.0f}) | "
          f"{float(last['disk_used_gb']):.0f} GB ({float(last['disk_size_gb']):.0f}) | {statistics.mean(wr):.1f} | {statistics.mean(rx):.1f} |")
    # The last hour of the load, before the 2 minutes of catching up.
    tail = cpu[-248:-8] if len(cpu) > 16 else cpu
    if tail and statistics.mean(tail) >= 85:
        busy.append(f"{name} ({statistics.mean(tail):.0f}% CPU over the last hour)")
print()

o = rows(os.path.join(out, "opensearch.csv"))
print("## OpenSearch\n")
if o:
    lag = [num(x["lag_s"]) for x in o if num(x["lag_s"]) is not None]
    docs = [(x["time"], num(x["docs"])) for x in o if num(x["docs"]) is not None]
    if len(docs) > 1:
        rates = [(b[1] - a[1]) / 30 for a, b in zip(docs, docs[1:]) if b[1] >= a[1]]
        if rates:
            top = sorted(rates)
            print(f"- Events stored a second (counted every 30 s): median {statistics.median(rates):,.0f}, "
                  f"95th percentile {top[int(len(top) * .95) - 1]:,.0f}, highest {top[-1]:,.0f}.")
        print(f"- Events stored at the end: {docs[-1][1]:,.0f}.")
    if lag:
        s = sorted(lag)
        print(f"- Lag (the clock minus the newest stored event): median {statistics.median(lag):.0f} s, "
              f"95th percentile {s[int(len(s) * .95) - 1]:.0f} s, highest {s[-1]:.0f} s, at the end {lag[-1]:.0f} s.")
        if len(lag) > 240 and lag[-5] > 2 * max(60, lag[len(lag) // 4]):
            busy.append(f"OpenSearch fell behind: the lag grew from {lag[len(lag) // 4]:.0f} s to {lag[-5]:.0f} s")
n = rows(os.path.join(out, "opensearch-nodes.csv"))
if n:
    by = {}
    for x in n:
        by.setdefault(x["node"], []).append(x)
    for node, r in sorted(by.items()):
        cpu = [num(x["cpu_pct"]) for x in r if num(x["cpu_pct"]) is not None]
        heap = [num(x["heap_pct"]) for x in r if num(x["heap_pct"]) is not None]
        rej = num(r[-1]["write_rejected"]) or 0
        print(f"- {node}: CPU average {statistics.mean(cpu):.0f}%, heap highest {max(heap):.0f}%, "
              f"free disk at the end {r[-1]['disk_free_gb']} GB, writes refused {rej:.0f}.")
        if rej > 0:
            busy.append(f"{node} refused {rej:.0f} writes (its write queue was full)")
print()

print("## Where it saturates\n")
if busy:
    for b in busy:
        print(f"- {b}")
else:
    print("- Nothing ran at 85% CPU or more over the last hour, and OpenSearch kept up.")
print()

# ---- detections ----

def ts(v):
    """A time as OpenSearch, Go or this script write it, in seconds."""
    if v is None or v == "":
        return None
    if isinstance(v, (int, float)):
        return float(v)
    m = re.match(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(\.\d+)?(Z|[+-]\d\d:?\d\d)?$", str(v).strip())
    if not m:
        return None
    t = datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
    if m.group(2):
        t += float("0" + m.group(2))
    z = m.group(3)
    if z and z != "Z":
        sign = -1 if z[0] == "+" else 1
        z = z[1:].replace(":", "")
        t += sign * (int(z[:2]) * 3600 + int(z[2:]) * 60)
    return t

def jsonl(name):
    try:
        with open(os.path.join(out, name)) as f:
            for line in f:
                try:
                    yield json.loads(line)
                except ValueError:
                    pass
    except OSError:
        return

def pct(v, p):
    if not v:
        return None
    s = sorted(v)
    return s[max(0, min(len(s) - 1, int(round(len(s) * p)) - 1))]

def fmt(v, unit=""):
    return "-" if v is None else f"{v:,.0f}{unit}"

# The phases: phases.csv in the spread test, the whole run otherwise.
phases = []
for x in rows(os.path.join(out, "phases.csv")):
    a, b = ts(x.get("start")), ts(x.get("end"))
    if a and b:
        phases.append((f"{x['phase']} {x['name']}", a, b))
if not phases:
    phases = [("whole run", 0, float("inf"))]

def phase_of(t):
    if t is None:
        return None
    for p, a, b in phases:
        if a <= t < b:
            return p
    return None

# Server names by node ID, from the samples of GET /api/cluster.
cluster = list(jsonl("cluster.jsonl"))
names = {}
for c in cluster:
    for sv in c.get("servers") or []:
        if sv.get("node_id"):
            names[sv["node_id"]] = sv.get("name") or sv["node_id"]
def server(node):
    return names.get(node, node or "?")

print("## Detections\n")
rules = None
try:
    with open(os.path.join(out, "rules.json")) as f:
        rules = json.load(f)
except (OSError, ValueError):
    pass
if rules:
    sched = ", ".join(f"{k}: {v}" for k, v in sorted(rules.get("by_schedule", {}).items(), key=lambda kv: -kv[1]))
    print(f"- Detections in the default tenant at the start: {rules.get('total', 0):,}, enabled {rules.get('enabled', 0):,} "
          f"(by schedule: {sched or 'none'}).")
    if rules.get("enabled", 0) < 1500:
        print(f"- Fewer than the plan's 1,500 enabled rules ({rules.get('enabled', 0):,}); the test did not turn more on. "
              "Turn on Splunk pack rules on the Detections page before the next run to reach it.")
else:
    print("- The number of enabled detections could not be read from the API (GET /api/detections).")
budgets = {}
for d in jsonl("detassign.jsonl"):
    if d.get("search_budget") is not None:
        budgets.setdefault(d.get("tenant") or "default", set()).add(d["search_budget"])
if budgets:
    print("- search_budget written in the detassign documents: "
          + "; ".join(f"{t}: {', '.join(str(b) for b in sorted(v))}" for t, v in sorted(budgets.items())) + ".")
print()

# Each run once: a detstate document sampled every minute holds the last
# run of its rule, so a run is (tenant, rule, last_run).
runs = {}
late = {}
dupe_slots = {}
seen_slot = {}
for d in jsonl("detstate.jsonl"):
    t = ts(d.get("t"))
    key = (d.get("tenant") or "default", d.get("detection_id") or d.get("id"))
    lr = ts(d.get("last_run"))
    if lr is not None:
        runs[key + (lr,)] = d
    p = phase_of(t)
    if p is not None and d.get("late_runs") is not None:
        lo_hi = late.setdefault((p, key), [d["late_runs"], d["late_runs"], d.get("node")])
        lo_hi[0] = min(lo_hi[0], d["late_runs"])
        lo_hi[1] = max(lo_hi[1], d["late_runs"])
        lo_hi[2] = d.get("node")
    slot = d.get("last_slot")
    if slot and d.get("node"):
        nodes = seen_slot.setdefault(key + (slot,), set())
        nodes.add(d["node"])
        if len(nodes) > 1:
            dupe_slots[key + (slot,)] = nodes

table = {}
for (tenant, rule, lr), d in runs.items():
    p = phase_of(lr)
    if p is None:
        continue
    e = table.setdefault((p, server(d.get("node"))), {"dur": [], "lag": [], "lag1m": [], "timeouts": 0, "busy": 0.0})
    if d.get("last_duration_ms") is not None:
        e["dur"].append(d["last_duration_ms"])
        e["busy"] += d["last_duration_ms"] / 1000
    if d.get("lag_ms") is not None:
        e["lag"].append(d["lag_ms"])
        if d.get("schedule") == "1m":
            e["lag1m"].append(d["lag_ms"])
    if d.get("error_kind") == "timeout":
        e["timeouts"] += 1
late_by = {}
for (p, key), (lo, hi, node) in late.items():
    late_by[(p, server(node))] = late_by.get((p, server(node)), 0) + max(0, hi - lo)

print("### Run time and lag per server\n")
if table:
    print("Each run counted once, from the detstate documents sampled every minute. Busy is the sum of the "
          "run times per hour of the phase (the plan's last_duration_ms x runs/hour).\n")
    print("| Phase | Server | Runs | Run time p50 / p95 ms | Lag p50 / p95 ms | 1m rules lag p95 ms | Late runs | Timeouts | Busy s/h |")
    print("| --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for p, a, b in phases:
        hours = max((b - a) / 3600, 1 / 60) if b != float("inf") else None
        for (pp, sv), e in sorted(table.items()):
            if pp != p:
                continue
            busy_h = f"{e['busy'] / hours:,.0f}" if hours else f"{e['busy']:,.0f} (whole run)"
            print(f"| {p} | {sv} | {len(e['dur']):,} | {fmt(pct(e['dur'], .5))} / {fmt(pct(e['dur'], .95))} | "
                  f"{fmt(pct(e['lag'], .5))} / {fmt(pct(e['lag'], .95))} | {fmt(pct(e['lag1m'], .95))} | "
                  f"{late_by.get((p, sv), 0):,} | {e['timeouts']:,} | {busy_h} |")
    print()
else:
    print("No detstate documents were read (detstate.jsonl): see detections-errors.txt.\n")
if dupe_slots:
    print(f"- **{len(dupe_slots)} rule slots were seen written by two servers** (a possible double run; sampled every minute, "
          "so not every one is seen): " + ", ".join(f"{k[1]} at {k[2]}" for k in list(dupe_slots)[:10]) + ".\n")
elif runs:
    print("- No rule slot was seen written by two servers (sampled every minute).\n")

print("### OpenSearch's search thread pool\n")
pool = {}
for x in jsonl("threadpool.jsonl"):
    p = phase_of(ts(x.get("t")))
    if p is None:
        continue
    for r in x.get("pool") or []:
        e = pool.setdefault((p, r.get("node_name")), {"rej": [], "queue": 0, "active": 0, "size": None})
        e["rej"].append(int(r.get("rejected") or 0))
        e["queue"] = max(e["queue"], int(r.get("queue") or 0))
        e["active"] = max(e["active"], int(r.get("active") or 0))
        e["size"] = r.get("size")
if pool:
    print("| Phase | Node | Pool size | Most active | Longest queue | Rejected during the phase |")
    print("| --- | --- | --- | --- | --- | --- |")
    for p, a, b in phases:
        for (pp, node), e in sorted(pool.items()):
            if pp != p:
                continue
            grew = sum(max(0, y - x) for x, y in zip(e["rej"], e["rej"][1:]))
            print(f"| {p} | {node} | {e['size']} | {e['active']} | {e['queue']} | {grew:,} |")
    print()
else:
    print("Not sampled (threadpool.jsonl): see detections-errors.txt.\n")

print("### Buckets per server (GET /api/cluster)\n")
spread_rows = []
for c in cluster:
    p = phase_of(ts(c.get("t")))
    if p is None:
        continue
    ready = [sv for sv in c.get("servers") or [] if sv.get("state") == "ready" and not sv.get("removed")]
    for v in c.get("detections") or []:
        for node, cnt in (v.get("servers") or {}).items():
            spread_rows.append((p, v.get("tenant"), server(node), cnt.get("run", 0), cnt.get("moving", 0), len(ready), v.get("buckets", 64)))
if spread_rows:
    print("The last sample of each phase; moving is the most seen at once during it.\n")
    print("| Phase | Tenant | Server | Buckets run | Most moving | Even share (64/N, +-25%) |")
    print("| --- | --- | --- | --- | --- | --- |")
    last, moving = {}, {}
    for p, t, sv, run, mv, nready, buckets in spread_rows:
        last[(p, t, sv)] = (run, nready, buckets)
        moving[(p, t, sv)] = max(moving.get((p, t, sv), 0), mv)
    for p, a, b in phases:
        for (pp, t, sv), (run, nready, buckets) in sorted(last.items()):
            if pp != p:
                continue
            share = buckets / max(nready, 1)
            ok = "yes" if abs(run - share) <= share * .25 else "**no**"
            print(f"| {p} | {t} | {sv} | {run} | {moving[(p, t, sv)]} | {share:.1f}: {ok} |")
    print()
else:
    print("No spread buckets were listed: detections ran on one server (spread off), or GET /api/cluster could not be read.\n")

print("### Primary shards per index\n")
idx = None
for x in jsonl("indices.jsonl"):
    idx = x
if idx and idx.get("indices"):
    print(f"From the last sample ({idx.get('t')}).\n")
    print("| Index | Primary shards | Replicas | Documents | Size |")
    print("| --- | --- | --- | --- | --- |")
    for r in sorted(idx["indices"], key=lambda r: r.get("index") or ""):
        print(f"| {r.get('index')} | {r.get('pri')} | {r.get('rep')} | {r.get('docs.count')} | {r.get('store.size')} |")
    print()
else:
    print("Not sampled (indices.jsonl).\n")

print("### Server log lines\n")
pats = ["running fewer", "full rate again", "assigned to servers", "detection ran late", "rollover size"]
logs = sorted(glob.glob(os.path.join(out, "logs-*.txt")))
rollover = []
if logs:
    print("| Server | " + " | ".join(f'"{p}"' for p in pats) + " |")
    print("| --- | " + " | ".join("---" for _ in pats) + " |")
    for path in logs:
        sv = os.path.basename(path)[5:-4]
        counts = dict.fromkeys(pats, 0)
        with open(path, errors="replace") as f:
            for line in f:
                for p in pats:
                    if p in line:
                        counts[p] += 1
                if "rollover size" in line:
                    rollover.append(f"{sv}: {line.strip()[:300]}")
        print(f"| {sv} | " + " | ".join(f"{counts[p]:,}" for p in pats) + " |")
    print()
    if rollover:
        print("Rollover:\n\n```\n" + "\n".join(rollover[:20]) + "\n```\n")
    else:
        print("No index reached the rollover size.\n")
else:
    print("Not collected (logs-*.txt).\n")

if mode == "spread":
    print("### CPU per phase\n")
    if machines and phases[0][0] != "whole run":
        names_m = sorted(machines)
        print("| Phase | " + " | ".join(names_m) + " |")
        print("| --- | " + " | ".join("---" for _ in names_m) + " |")
        for p, a, b in phases:
            cells = []
            for m in names_m:
                v = [num(x["cpu_pct"]) for x in machines[m] if num(x["cpu_pct"]) is not None and a <= (ts(x["time"]) or 0) < b]
                cells.append(f"{statistics.mean(v):.0f}%" if v else "-")
            print(f"| {p} | " + " | ".join(cells) + " |")
        print()
    try:
        with open(os.path.join(out, "events.csv")) as f:
            ev = f.read().strip()
        print("### What the test did\n\n```\n" + ev + "\n```\n")
    except OSError:
        pass
    print("### Not done here\n")
    print("- Phase 5 (noisy tenant) was skipped: it needs a tenant with events of its own to search, which the load generator "
          "does not send, and the plan's two extra tenants of ~300 rules each. Do it by hand: see docs/cloud-lab.md.")
    print("- The plan's opensearch.shards setting and the extra tenants are set by hand before the run; this test leaves them as they are.")
    print()
EOF
}

# ---- the API and OpenSearch ----

os_admin() {
  local c=$LAB/pki/opensearch-1/opensearch/certs
  curl -fsS --max-time 20 --cacert "$c/root-ca.pem" --cert "$c/admin.pem" --key "$c/admin-key.pem" \
    --resolve "opensearch-1:9200:$(ip_of opensearch-1)" "https://opensearch-1:9200$1" "${@:2}"
}

# The admin API of signalith-1, signed in as the built-in admin with the
# password lab-setup chose. The password goes to curl on its input, never
# its command line; the session is kept in a cookie jar only root reads.
API=https://localhost:9000
API_CA=/var/lib/signalith/tls/ca.pem
JAR=$LAB/.lab-loadtest-cookies
api_login() {
  [ -s "$LAB/admin-password" ] || return 1
  (umask 077 && : >"$JAR")
  # signalithadmin on a new install, admin on one made before 0.3.1.
  local user
  user=$(awk '$1 == "admin_user:" { gsub(/["\047]/, "", $2); print $2; exit }' /etc/signalith/signalith.yaml 2>/dev/null)
  jq -n --rawfile p "$LAB/admin-password" --arg u "${user:-signalithadmin}" '{username: $u, password: ($p | rtrimstr("\n"))}' |
    curl -fsS --max-time 20 -c "$JAR" --cacert "$API_CA" -H 'Content-Type: application/json' -H "Origin: $API" \
      --data-binary @- "$API/api/login" >/dev/null
}
# api METHOD PATH [JSON] prints the answer, and fails unless it is 2xx. A
# session that ran out is signed in again once.
api() {
  local method=$1 path=$2 data=${3:-} code try body
  body=$(mktemp)
  for try in 1 2; do
    if [ ! -s "$JAR" ] && ! api_login; then
      rm -f "$body"
      return 1
    fi
    local args=(-sS --max-time 60 -b "$JAR" --cacert "$API_CA" -H "Origin: $API" -X "$method" -o "$body" -w '%{http_code}')
    [ -z "$data" ] || args+=(-H 'Content-Type: application/json' --data-binary @-)
    code=$(printf '%s' "$data" | curl "${args[@]}" "$API$path") || code=000
    [ "$code" = 401 ] && [ "$try" = 1 ] && rm -f "$JAR" && continue
    break
  done
  cat "$body"
  rm -f "$body"
  [[ $code == 2* ]]
}

# ---- detections, every minute ----

# The runtime indices: the default tenant's and each other tenant's.
RUNTIME='signalith_runtime,signalith.t.*_runtime'
det_samples() {
  local i=0 t
  # A session of its own: the phases sign in again while this runs.
  JAR=$JAR-samples
  while :; do
    t=$(date -u +%FT%TZ)
    # Each detection's run state, one JSON line per rule.
    os_admin "/$RUNTIME/_search?ignore_unavailable=true&allow_no_indices=true" -H 'Content-Type: application/json' \
      -d '{"size":10000,"query":{"term":{"kind":"detstate"}},"_source":["detection_id","last_slot","last_run","last_duration_ms","lag_ms","late_runs","node","det_epoch","error_kind","schedule","attempts"]}' |
      jq -c --arg t "$t" '.hits.hits[] | {t: $t, tenant: (._index | if . == "signalith_runtime" then "default" else (sub("^signalith\\.t\\."; "") | sub("_runtime$"; "")) end)} + ._source' \
        >>"$OUT/detstate.jsonl" || echo "$t detstate: could not be read" >>"$OUT/detections-errors.txt"
    os_admin "/$RUNTIME/_search?ignore_unavailable=true&allow_no_indices=true" -H 'Content-Type: application/json' \
      -d '{"size":100,"query":{"term":{"kind":"detassign"}},"_source":["tenant","lease_epoch","search_budget"]}' |
      jq -c --arg t "$t" '.hits.hits[] | {t: $t} + ._source' >>"$OUT/detassign.jsonl" 2>/dev/null || true
    os_admin '/_cat/thread_pool/search?h=node_name,active,queue,rejected,completed,size&format=json' |
      jq -c --arg t "$t" '{t: $t, pool: .}' >>"$OUT/threadpool.jsonl" || echo "$t thread pool: could not be read" >>"$OUT/detections-errors.txt"
    api GET /api/cluster | jq -c --arg t "$t" '{t: $t, lease: .lease.holder_name, detections: (.detections // []),
      servers: [.servers[] | {name, node_id, state, removed, not_eligible}]}' >>"$OUT/cluster.jsonl" ||
      echo "$t GET /api/cluster: could not be read" >>"$OUT/detections-errors.txt"
    if [ $((i % 10)) = 0 ]; then
      os_admin '/_cat/shards?format=json' | jq -c --arg t "$t" '{t: $t, shards: .}' >>"$OUT/shards.jsonl" || true
      os_admin '/_cat/indices/signalith-*?format=json' | jq -c --arg t "$t" '{t: $t, indices: .}' >>"$OUT/indices.jsonl" || true
    fi
    i=$((i + 1))
    sleep 60
  done
}

# rules writes how many detections the default tenant has, how many are
# enabled, and the enabled ones by schedule.
rules() {
  api GET /api/detections | jq '{total: (.detections | length), enabled: ([.detections[] | select(.enabled)] | length),
    by_schedule: ([.detections[] | select(.enabled) | .schedule] | group_by(.) | map({key: .[0], value: length}) | from_entries)}'
}

# logs keeps each Signalith server's log lines about detections and
# rollover since the run started.
logs() {
  local m
  for m in $(servers); do
    on "$m" "journalctl -u signalith --since @$RUN_START --utc -o short-iso --no-pager 2>/dev/null | grep -E 'running fewer|full rate again|assigned to servers|detection ran late|rollover size'" \
      </dev/null >"$OUT/logs-$m.txt" || true
  done
}

# ---- the spread test's phases ----

# spread_value prints detections.spread as the Settings page has it.
spread_value() {
  api GET /api/settings | jq -r '[.sections[]?.fields[]? | select(.key == "detections.spread") | .value][0] // false'
}
# set_spread turns detections.spread on or off for every server. The
# change asks for a recent sign-in, so it signs in again first.
set_spread() {
  rm -f "$JAR"
  if api PUT /api/settings "{\"values\":{\"detections.spread\":$1}}" >/dev/null; then
    event "detections.spread set to $1"
  else
    event "detections.spread could NOT be set to $1"
    return 1
  fi
}
event() {
  [ -s "$OUT/events.csv" ] || echo time,event >"$OUT/events.csv"
  printf '%s,%s\n' "$(date -u +%FT%TZ)" "$*" >>"$OUT/events.csv"
  say "  $*"
}
# phase N NAME starts a phase, ending the one before; phases.csv has
# each one's start and end, for the report.
PHASE='' PHASE_NAME='' PHASE_START='' PHASE_T0=0
# LT_PHASE_MINUTES shortens the phases to try the test out, when run by
# hand: sudo LT_PHASE_MINUTES=2 lab-loadtest run spread.
PHASE_SECS=$((${LT_PHASE_MINUTES:-45} * 60))
phase() {
  local now
  now=$(date -u +%FT%TZ)
  [ -s "$OUT/phases.csv" ] || echo phase,name,start,end >"$OUT/phases.csv"
  [ -z "$PHASE" ] || printf '%s,%s,%s,%s\n' "$PHASE" "$PHASE_NAME" "$PHASE_START" "$now" >>"$OUT/phases.csv"
  PHASE=${1:-} PHASE_NAME=${2:-} PHASE_START=$now PHASE_T0=$(date -u +%s)
  [ -z "$PHASE" ] || say "Phase $PHASE: $PHASE_NAME"
}
# rest waits until the phase has lasted its 45 minutes.
rest() {
  local left=$((PHASE_T0 + PHASE_SECS - $(date -u +%s)))
  [ "$left" -le 0 ] || sleep "$left"
}
server_ready() {
  # shellcheck disable=SC2016 # expanded on that server
  on "$1" 'for i in $(seq 1 60); do curl -fsSk -o /dev/null --max-time 5 https://127.0.0.1:9000/readyz && exit 0; sleep 5; done; exit 1' </dev/null
}
# start_servers starts any Signalith server the test left stopped.
start_servers() {
  local m
  for m in $(servers); do on "$m" 'systemctl is-active -q signalith || systemctl start signalith' </dev/null || true; done
}

spread_test() {
  local m victim t0 bundle=$LAB/servers-ca.pem targets
  # The agents send to every server's agent port, checked with each
  # server's CA, fetched over the lab's own SSH (a CA twice does no harm).
  for m in $(servers); do on "$m" 'cat /var/lib/signalith/tls/ca.pem' </dev/null; done >"$bundle"
  for m in $(servers); do
    curl -fsS -o /dev/null --max-time 10 --cacert "$bundle" "https://$m.$DOMAIN:7779/readyz" ||
      { say "FAILED: $m does not answer on its agent port (https://$m.$DOMAIN:7779/readyz)."; return 1; }
  done
  on loadgen 'umask 077 && cat >/root/loadtest/servers-ca.pem' <"$bundle"
  targets=$(servers | sed "s|.*|https://&.$DOMAIN:7779|" | paste -sd, - | sed 's/,/, /g')
  sed -e "s|^agent_targets:.*|agent_targets: [$targets]|" -e "s|^ca_file:.*|ca_file: /root/loadtest/servers-ca.pem|" \
    "$LAB/src/loadtest/spread-10k.yaml" | on loadgen 'umask 077 && cat >/root/loadtest/spread-run.yaml'
  on loadgen '/root/loadtest/signalith-loadgen check /root/loadtest/spread-run.yaml' </dev/null >/dev/null ||
    { say "FAILED: the load generator refused loadtest/spread-10k.yaml."; return 1; }
  api GET /api/cluster | jq -r '.servers[] | select(.removed != true) | "  \(.name): \(.state)\(if .not_eligible then ", may not run detections: \(.not_eligible)" else "" end)"' |
    while read -r line; do say "$line"; done

  SPREAD_WAS=$(spread_value) || SPREAD_WAS=''
  event "detections.spread was ${SPREAD_WAS:-unknown} at the start"
  if [ "$SPREAD_WAS" = true ]; then
    set_spread false
    sleep 120
  fi

  say "  the load generator runs loadtest/spread-10k.yaml through $targets (about 4.5 hours)"
  on loadgen 'cd /root/loadtest && rm -f report.json && ./signalith-loadgen run -f spread-run.yaml -json report.json' </dev/null >"$OUT/loadgen.txt" 2>&1 &
  LGPID=$!

  phase 0 "warm-up (spread off)"
  sleep 600
  phase 1 "spread off"
  rest
  phase 2 "spread on"
  set_spread true
  rest
  phase 3 "graceful move"
  t0=$(date -u +%s)
  event "systemctl restart signalith on signalith-2"
  on signalith-2 'systemctl restart signalith' </dev/null
  if server_ready signalith-2; then event "signalith-2 ready after $(($(date -u +%s) - t0)) s"; else event "signalith-2 not ready after 5 minutes"; fi
  rest
  phase 4 "crash"
  victim=signalith-3
  [ -n "$(ip_of signalith-3)" ] || victim=$(servers | tail -n 1)
  event "kill -9 signalith on $victim"
  # shellcheck disable=SC2016 # expanded on that server
  on "$victim" 'pid=$(systemctl show -p MainPID --value signalith); [ "${pid:-0}" -gt 0 ] && kill -9 "$pid"; systemctl stop signalith' </dev/null
  sleep 600
  t0=$(date -u +%s)
  event "systemctl start signalith on $victim"
  on "$victim" 'systemctl start signalith' </dev/null
  if server_ready "$victim"; then event "$victim ready after $(($(date -u +%s) - t0)) s"; else event "$victim not ready after 5 minutes"; fi
  rest
  event "phase 5 (noisy tenant) skipped: do it by hand (docs/cloud-lab.md)"
  phase 5 "after: spread on and nothing changed until the load ends"
  wait "$LGPID"
  say "  the load generator finished (exit $?)"
  LGPID=''
  phase
}

finish() {
  trap - EXIT INT TERM
  [ -z "${OSPID:-}" ] || kill "$OSPID" 2>/dev/null
  [ -z "${DETPID:-}" ] || kill "$DETPID" 2>/dev/null
  [ -z "${LGPID:-}" ] || kill "$LGPID" 2>/dev/null
  # Stopped early: the load generator does not stop with its ssh.
  on loadgen 'pkill -INT -f "signalith-loadgen run" 2>/dev/null; true' </dev/null
  if [ "$MODE" = spread ]; then
    [ -z "$PHASE" ] || phase
    start_servers
    if [ -n "${SPREAD_WAS:-}" ] && [ "$(spread_value)" != "$SPREAD_WAS" ]; then set_spread "$SPREAD_WAS" || true; fi
  fi
  stop_samplers
  release_updates
  local m
  for m in $(names); do on "$m" "cat $SAMPLES 2>/dev/null" </dev/null >"$OUT/$m.csv"; done
  on loadgen 'cat /root/loadtest/report.json 2>/dev/null' </dev/null >"$OUT/loadgen.json"
  [ -s "$OUT/loadgen.json" ] || rm -f "$OUT/loadgen.json"
  rules >"$OUT/rules-end.json" 2>/dev/null || rm -f "$OUT/rules-end.json"
  logs
  rm -f "$JAR" "$JAR-samples"
  report >"$OUT/report.md" 2>>"$OUT/report-errors.txt" || say "the summary could not be written: see $OUT/report-errors.txt"
  [ -s "$OUT/report-errors.txt" ] || rm -f "$OUT/report-errors.txt"
  say "Load test done: $OUT/report.md"
}
trap finish EXIT
trap 'exit 130' INT TERM

hold_updates
for m in $(names); do
  sampler | on "$m" "cat >/root/lt-sample.sh && systemctl stop lt-sample 2>/dev/null; rm -f /root/lt-sample*.csv; systemd-run -q --unit=lt-sample --collect bash /root/lt-sample.sh $SAMPLES"
done
say "  sampling on: $(names | tr '\n' ' ')"

# ---- OpenSearch ----

# os_samples writes, every 30 seconds, the events stored and how far the
# newest is behind the clock (lag), and each node's CPU, heap, free disk,
# indexing count and refused writes.
os_samples() {
  local now docs newest lag
  echo time,docs,lag_s >"$OUT/opensearch.csv"
  echo time,node,cpu_pct,heap_pct,disk_free_gb,index_total,write_rejected >"$OUT/opensearch-nodes.csv"
  while sleep 30; do
    now=$(date -u +%s)
    docs=$(os_admin '/_cat/count/signalith-*?h=count' 2>/dev/null | tr -d '[:space:]')
    newest=$(os_admin '/signalith-*/_search?size=0&ignore_unavailable=true' -H 'Content-Type: application/json' \
      -d '{"query":{"range":{"@timestamp":{"gte":"now-6h"}}},"aggs":{"newest":{"max":{"field":"@timestamp"}}}}' 2>/dev/null |
      jq -r '.aggregations.newest.value // empty' 2>/dev/null)
    lag=''
    [ -z "$newest" ] || lag=$(awk -v n="$now" -v v="$newest" 'BEGIN { printf "%.1f", n - v / 1000 }')
    printf '%s,%s,%s\n' "$(date -u +%FT%TZ)" "${docs:-}" "$lag" >>"$OUT/opensearch.csv"
    os_admin '/_nodes/stats/os,jvm,fs,indices,thread_pool' 2>/dev/null | jq -r --arg t "$(date -u +%FT%TZ)" '
      .nodes[] | [$t, .name, .os.cpu.percent, .jvm.mem.heap_used_percent,
        ((.fs.total.available_in_bytes // 0) / 1073741824 | . * 10 | floor / 10),
        .indices.indexing.index_total, (.thread_pool.write.rejected // 0)] | @csv' >>"$OUT/opensearch-nodes.csv" 2>/dev/null
  done
}
os_samples &
OSPID=$!
det_samples 2>>"$OUT/detections-errors.txt" &
DETPID=$!
rules >"$OUT/rules.json" 2>/dev/null || { rm -f "$OUT/rules.json"; say "  the detections could not be counted (GET /api/detections)"; }

# ---- the load ----

if [ "$MODE" = spread ]; then
  spread_test || say "  the spread test stopped early"
else
  say "  the load generator runs loadtest/tb-day.yaml (about 4.5 hours)"
  on loadgen 'cd /root/loadtest && rm -f report.json && ./signalith-loadgen run -f tb-day.yaml -json report.json' </dev/null >"$OUT/loadgen.txt" 2>&1
  say "  the load generator finished (exit $?)"
fi
# A few more samples while OpenSearch catches up.
sleep 120
