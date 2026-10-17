#!/usr/bin/env bash
# lab-loadtest: the cloud lab's terabyte-a-day load test (docs/cloud-lab.md).
# It needs the lab made with size = "loadtest", and runs on signalith-1:
#
#   sudo lab-loadtest          starts the test in the background (about 4.5 hours)
#   sudo lab-loadtest status   shows how far it is
#   sudo lab-loadtest stop     stops it, keeping what it measured so far
#
# The load generator runs loadtest/tb-day.yaml against signalith-1 while
# every machine records its CPU, memory, disk and network every 15
# seconds, and OpenSearch's counts, per-node load and how far its newest
# event is behind the clock every 30 seconds. The results are in
# /root/lab/loadtest/<time>/ (latest is the newest): report.md, the load
# generator's report (loadgen.txt, loadgen.json) and the samples (*.csv).
set -uo pipefail

LAB=/root/lab
UNIT=lab-loadtest
LOG=/var/log/lab-loadtest.log

[ "$(id -u)" = 0 ] || { echo "Run it as root: sudo lab-loadtest" >&2; exit 2; }
[ -f "$LAB/lab.json" ] || { echo "This is not the lab's signalith-1 ($LAB/lab.json is missing)." >&2; exit 2; }

conf() { jq -r "$1" "$LAB/lab.json"; }
ip_of() { conf ".machines[] | select(.name == \"$1\") | .ip"; }
names() { conf '.machines[].name'; }
say() { printf '%s  %s\n' "$(date -u +%H:%M:%S)" "$*"; }

SSH=(ssh -i "$LAB/id_lab" -o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=30
  -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$LAB/known_hosts" -o LogLevel=ERROR)
on() {
  local host=$1
  shift
  if [ "$host" = signalith-1 ]; then bash -c "$*"; else "${SSH[@]}" "root@$(ip_of "$host")" "$@"; fi
}

case "${1:-start}" in
  start)
    [ -n "$(ip_of loadgen)" ] || { echo "This lab has no load generator: make it with terraform apply -var size=loadtest (docs/cloud-lab.md)." >&2; exit 2; }
    if systemctl is-active -q "$UNIT"; then
      echo "The load test is already running: sudo lab-loadtest status" >&2
      exit 1
    fi
    systemd-run -q --unit="$UNIT" --collect -p StandardOutput="append:$LOG" -p StandardError="append:$LOG" -p TimeoutStopSec=300 "$0" run
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
    ;;
  *)
    echo "Usage: lab-loadtest [start|status|stop]" >&2
    exit 2
    ;;
esac

OUT=$LAB/loadtest/$(date -u +%Y%m%d-%H%M%S)
mkdir -p "$OUT"
# Each run's samples have a file of their own on every machine.
SAMPLES=/root/lt-sample-$(basename "$OUT").csv
ln -sfn "$OUT" "$LAB/loadtest/latest"
say "Load test: results in $OUT"

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
  python3 - "$OUT" <<'EOF'
import csv, glob, os, re, statistics, sys
out = sys.argv[1]

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
for path in sorted(glob.glob(os.path.join(out, "*.csv"))):
    name = os.path.basename(path)[:-4]
    if name.startswith("opensearch") and name not in ("opensearch-1", "opensearch-2", "opensearch-3"):
        continue
    r = rows(path)
    if not r:
        continue
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
EOF
}

finish() {
  trap - EXIT INT TERM
  [ -z "${OSPID:-}" ] || kill "$OSPID" 2>/dev/null
  # Stopped early: the load generator does not stop with its ssh.
  on loadgen 'pkill -INT -f "signalith-loadgen run" 2>/dev/null; true' </dev/null
  stop_samplers
  release_updates
  local m
  for m in $(names); do on "$m" "cat $SAMPLES 2>/dev/null" </dev/null >"$OUT/$m.csv"; done
  on loadgen 'cat /root/loadtest/report.json 2>/dev/null' </dev/null >"$OUT/loadgen.json"
  [ -s "$OUT/loadgen.json" ] || rm -f "$OUT/loadgen.json"
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

os_admin() {
  local c=$LAB/pki/opensearch-1/opensearch/certs
  curl -fsS --max-time 20 --cacert "$c/root-ca.pem" --cert "$c/admin.pem" --key "$c/admin-key.pem" \
    --resolve "opensearch-1:9200:$(ip_of opensearch-1)" "https://opensearch-1:9200$1" "${@:2}"
}

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

# ---- the load ----

say "  the load generator runs loadtest/tb-day.yaml (about 4.5 hours)"
on loadgen 'cd /root/loadtest && rm -f report.json && ./signalith-loadgen run -f tb-day.yaml -json report.json' </dev/null >"$OUT/loadgen.txt" 2>&1
say "  the load generator finished (exit $?)"
# A few more samples while OpenSearch catches up.
sleep 120

