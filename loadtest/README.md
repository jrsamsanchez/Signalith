# Load tests

`signalith-loadgen` puts load on Signalith servers and checks how they hold up. It
plays many agents, syslog devices, people using the pages, password guessers and
settings changes at once, against one server, several, or a load balancer; it can
break things on a timeline (kill or stall the server that runs the background jobs, cut
it off from OpenSearch); and it checks each scenario's pass criteria. What it measures
and why is in [docs/performance.md](../docs/performance.md).

Run the load tests against a test setup, not the one you rely on: they make accounts,
a case and many events (all tagged with the run's ID, which the report prints).

## Build it

```
go build -o signalith-loadgen ./cmd/signalith-loadgen
```

It runs on Linux and Windows. Faults that stop processes (`kill9`, `stop`) need Linux.

## Scenarios

| File | What | Where |
| --- | --- | --- |
| `s1-small.yaml` | Agents sending steadily; nothing lost or stored twice | CI, laptop |
| `s1-ingest.yaml` | 500 agents from 5k to 100k events/s, syslog from 1,000 devices | Lab |
| `s2-browsers-small.yaml` | 10 analysts on all servers, same findings, same case | CI, laptop |
| `s2-browsers.yaml` | 100 analysts through the load balancer at about 70% of peak ingest | Lab |
| `s3-idle.yaml` | Idle cost in OpenSearch, then a flood of random session cookies | CI, laptop |
| `s4-small.yaml` | Stall the leader for a minute, then kill the new one | CI, laptop |
| `s4-chaos.yaml` | Kill, stall, cut off from OpenSearch, clock offset, full disk | Lab |
| `s5-config.yaml` | Thousands of users, detections and indicators, then everyday use | Lab |
| `s6-brute.yaml` | Wrong passwords against 20 accounts from 200 addresses | CI, laptop |
| `s7-small.yaml` | Two servers upgraded one at a time under light load | CI, laptop |
| `s7-rolling-upgrade.yaml` | Three servers upgraded from the previous release under load | Lab |
| `s8-windows-member.yaml` | A Windows server joins, takes its share, runs the jobs, archives to SMB | Lab |
| `s9-small.yaml` | One of three OpenSearch nodes stopped for 90 s under light load | CI, laptop |
| `s9-opensearch-node-loss.yaml` | One of three OpenSearch nodes stopped under load | Lab |
| `sizing-small.yaml` | Agents from 1k to 32k events/s; rate stored, answer times, CPU, memory | CI, laptop |
| `tb-day.yaml` | 25k events/s (about 1 TB a day) for 4 hours with analysts searching | Cloud lab's load test ([docs/cloud-lab.md](../docs/cloud-lab.md#load-test)) |
| `spread-10k.yaml` | 10k events/s for 4 hours with analysts searching, while detections are spread over the servers | Cloud lab's spread test ([docs/cloud-lab.md](../docs/cloud-lab.md#detection-spread)) |
| `soak-7d.yaml` | Real recorded Windows events at about 1 TB a day for 7 days with analysts searching | Cloud lab's soak ([docs/cloud-lab.md](../docs/cloud-lab.md#seven-day-soak)) |

A scenario file names the targets (and `agent_targets`, the servers' agent port, when
they take agents on a port of their own), the files with secrets, the phases of load, the
faults and the pass criteria. `${NAME}` in it is replaced by that environment variable.
`signalith-loadgen check loadtest/*.yaml` checks the files without running anything.

### Real events (replay)

By default the agents send made-up lines padded to `event_bytes`. With `replay: {}` under
`agents`, they send real recorded Windows and Sysmon events instead: the 1,677 recordings
the detection packs carry as tests (SigmaHQ's regression data and Splunk's attack
recordings, about 1.6 KB each on average), each with the agent's name and the time now,
tagged `win.events` as the agent's Windows event log input tags them. So the servers parse,
map and store events of real size and shape, and the detections search them.

`attack_share` (default 0.001) is the share sent as recorded, which the detections match.
The rest are the same events with the letters of their values rotated (ROT13): the same
fields, sizes and parsing, but no program, path or command line a detection looks for, as
most of a real fleet's events are. A few rules that look only at an event ID or a number
still match them. Replayed events carry no sequence numbers, so a replay run does not
verify stored events one by one; the counters `agent_bytes_sent` and
`agent_attack_events_sent` give the bytes and the attacks sent.

```yaml
agents: {n: 200, rate: 7200, replay: {attack_share: 0.001}}
```

## Running a scenario

```
signalith-loadgen run -f loadtest/s1-small.yaml -json s1-small.json
```

`-target` and `-ca` replace the file's addresses and CA files (comma separated), and
`-admin-file`, `-token-file`, `-opensearch` and the other flags replace its other
settings. The commands `agents`, `syslog`, `users`, `brute` and `churn` run one kind of
load from flags alone, for example:

```
signalith-loadgen agents -target https://siem-a:8443 -ca ca.pem -token-file token.txt -n 100 -rate 2000 -for 5m
```

The secret files hold one line: `admin.txt` is `admin:<password>`, `token.txt` an agent
token from Add data (or the quick start's `ingest-token`). Secrets are never taken from
flags and never written in reports.

### Reading the report

Each phase lists its counters (requests, events sent and stored, status codes) and
response times (p50, p95, p99, max). Then each criterion is one line:

```
PASS   ingest_p99_ms (load)            measured 812        limit <= 2000
FAIL   events_lost                     measured 12         limit <= 0
SKIP   takeover_seconds                measured -          limit <= 45  (not a cluster)
RECORD write_conflicts                 measured 3
```

`SKIP` means the check does not apply here (one server, no OpenSearch to read), never
that it failed. `RECORD` is measured without a limit. The exit code is 0 for a pass
(or a scenario skipped because the servers lack something it needs), 1 when a
criterion failed and 2 when the run could not be made.

When a criterion fails:

- `events_lost`: the report's Verify line lists a few events by agent and sequence
  number. Search for them with `loadgen_run=<run> loadgen_agent=<n>`, and look in the
  server logs for errors at that time (the phase that held them is in the counters).
- `events_duplicated`: the same event stored twice; look for a fault or a server
  restart at that time.
- `takeover_seconds` and `leaders_at_once`: the Servers page and the servers' logs
  show who held the background jobs and when.
- `unexpected_signouts`: a signed-in user got 401 from a server; see whether that
  server could reach OpenSearch then.
- `generator_lag_ms`: the load generator could not keep up with its own schedule, so
  the other numbers are not trustworthy. Use a bigger machine or less load.
- `ingest_scaling`: the events per second stored, divided by the baseline run's
  (`-baseline <report.json>`, the same scenario against one server). Its limit depends
  on how many servers took part (`min_by_servers`); against one server it is recorded.
  Below the limit, see whether OpenSearch was the limit (its CPU and disk) before
  blaming the servers.
- `ingest_share_min`: one server took much less than its share of the agents' events.
  The counters `agent_events_stored_target_<n>` show each target's; look at that
  server's log and the Servers page.
- `opensearch_red_samples`, `opensearch_unreachable_samples`: Signalith's own indices
  lost every copy of a shard, or no OpenSearch node answered. Check each index's
  replicas (`GET _cat/indices/<prefix>_*?v`) and the cluster's health.
- `check_failures`: the report prints each failed check's output.
- `servers_not_upgraded`: the report's upgrade fault lists each server's step (from
  and to which version, how long, any error). The upgrade stops at the first server
  that fails, which stays drained so you can look at it; the reason is the install
  command's output, or what the server showed when the wait ran out.
- `jobs_moves`: how often the background jobs went to another server. In a rolling
  upgrade they should move once, to the first upgraded server; more means a server
  that ran them was upgraded before the check said so, or a takeover happened.
- `page_reloads_per_user`: an open page reloads when a server of another version
  answers, as the web pages do, and only once; a second mismatch soon after only
  warns.

`-pids siem-a=1234,siem-b=5678` gives the servers' process IDs when they run on the
load generator's machine (Linux), for `server_cpu_cores` and `server_memory_mb`. For the
laptop cluster, `docker inspect -f '{{.State.Pid}}' <container>` prints them.

`signalith-loadgen verify -run <id> -opensearch ...` counts a past run's events again,
and `signalith-loadgen cleanup -run <id> -target ... -admin-file ...` removes the
accounts and closes the case a run left behind (with `-keep`, or after a crash). The
events themselves go with the retention policy.

## Laptop cluster

Three servers on the Docker quick start's OpenSearch, with toxiproxy between them and
OpenSearch and HAProxy in front, from the folder you cloned Signalith into:

```
docker compose -p loadtest -f deploy/docker/docker-compose.yml -f loadtest/compose/docker-compose.loadtest.yml up -d
```

Then copy out the files the scenarios read (into `loadtest/compose/out`, which git
ignores):

```
C="docker compose -p loadtest -f deploy/docker/docker-compose.yml -f loadtest/compose/docker-compose.loadtest.yml"
O=loadtest/compose/out
mkdir -p $O/secrets
for s in siem-a siem-b siem-c; do $C cp $s:/var/lib/signalith/tls/ca.pem $O/$s-ca.pem; done
$C cp siem-a:/run/signalith-secrets/. $O/secrets/
cp $O/secrets/opensearch-ca.pem $O/secrets/opensearch-client.pem $O/secrets/opensearch-client-key.pem $O/
cp $O/secrets/ingest-token $O/token.txt
```

The first admin password Signalith made allows only choosing a new one, so choose
one, on every server that still has the first (until the servers share their users,
each keeps its own), and give the scenarios that one:

```
FIRST=$(cat $O/secrets/initial-admin-password)
PW=$(openssl rand -hex 16)
for p in 8441 8442 8443; do
  curl -sk -u "signalithadmin:$FIRST" -H 'Content-Type: application/json' \
    -d "{\"current_password\":\"$FIRST\",\"new_password\":\"$PW\"}" https://localhost:$p/api/me/password; echo
done
echo "signalithadmin:$PW" > $O/admin.txt
```

The CI-size scenarios (`s1-small`, `s2-browsers-small`, `s3-idle`, `s4-small`,
`s6-brute`) then run as they are, against siem-a and siem-b. To go through HAProxy
instead, use `-target https://localhost:8440` with every server's CA in `-ca`. HAProxy
passes HTTPS straight through, so the servers see HAProxy's address as the client's
until they accept the PROXY protocol; then add `send-proxy-v2` to the server lines in
`loadtest/compose/haproxy.cfg`.

`docker compose -p loadtest ... down -v` removes it all.

## The lab

For the full-size scenarios (the `lab/...` files in them are on the load generator's
machine; replace the `.lab` names with yours):

- **Signalith:** 3 Linux VMs, 4 vCPU and 8 GB each, `siem-1.lab` to `siem-3.lab`,
  installed from packages, with one cluster key. Optionally a Windows Server 2022 VM.
- **OpenSearch:** 3 nodes, 8 vCPU, 32 GB (16 GB heap) and SSD each, `os-1.lab` to
  `os-3.lab`, secured.
- **Toxiproxy** between the servers and OpenSearch (`toxiproxy.lab`, proxy
  `opensearch`), so `cut_opensearch` can cut the leader off. Point each server's
  `opensearch.url` at it.
- **HAProxy** in front (`lb.lab:8443` for HTTPS and `lb.lab:6514` for syslog over TLS),
  TCP mode, with `send-proxy-v2` once the servers accept it.
- **Time:** NTP on every machine. The clock fault turns it off on one server for a few
  minutes and moves the clock.
- **The load generator** on its own machine (8 vCPU or more), with SSH keys for the
  servers: the faults in `s4-chaos.yaml` are commands it runs, such as
  `ssh {server} sudo systemctl kill -s KILL signalith`. `{server}` is the server's name
  as the Servers page shows it, so name each VM after its server.

`s4-chaos.yaml` expects two small scripts on the machines it names:

- `/usr/local/sbin/loadtest-clock <seconds>` on the servers: with a number other than
  0, `timedatectl set-ntp false` and `date -s "+<seconds> seconds"`; with 0,
  `timedatectl set-ntp true`.
- `/usr/local/sbin/loadtest-fill-disk <percent>` on `os-1.lab`: with a percentage,
  `fallocate` a file in OpenSearch's data folder until the disk is that full; with 0,
  remove the file.

Run S1 three times, against one, two and three servers behind HAProxy (take servers
out of HAProxy's backend between runs). Save the first report and pass it to the others:

```
signalith-loadgen run -f loadtest/s1-ingest.yaml -json s1-one.json
signalith-loadgen run -f loadtest/s1-ingest.yaml -baseline s1-one.json -json s1-two.json
```

`ingest_scaling` then checks two servers store at least 1.7 times, and three at least
2.4 times, what one did at the top phase. Keep each run's JSON report with the date and
the version (`signalith version`); the lab rows of the sizing table in
docs/performance.md come from them.

### S8: a Windows server

`s8-windows-member.yaml` needs one Linux server (`siem-1.lab`) and the Windows Server
2022 VM (`win-1.lab`) in one domain-joined lab, with OpenSSH Server on the Windows VM.

1. Add the Windows server from the Servers page (Add a server, Windows), pasting the
   line in an administrator PowerShell on `win-1.lab`. That join is the first thing S8
   checks: the run is skipped if no Windows server is ready.
2. Make an SMB share for archives (for example `\\files.lab\signalith-archive`) and
   give the computer accounts `LAB\SIEM-1$` and `LAB\WIN-1$` Modify on it. On
   Linux, mount it at the archive folder with the machine's Kerberos ticket; on Windows,
   set the archive folder to the UNC path. The Windows service runs as LocalSystem, so
   it reaches the share as the computer account, with no password stored anywhere.
3. Put `C:\loadtest\check-archive-share.ps1` on `win-1.lab`. The check runs it over
   SSH; it writes a file on the share from a task running as SYSTEM, which is how the
   service reaches the share, and checks the computer account owns it:

   ```
   $probe = "\\files.lab\signalith-archive\loadtest-$env:COMPUTERNAME.txt"
   $write = New-ScheduledTaskAction -Execute powershell.exe -Argument "-NoProfile -Command Set-Content '$probe' ok"
   Register-ScheduledTask loadtest-share -Action $write -User SYSTEM -Force | Out-Null
   Start-ScheduledTask loadtest-share; Start-Sleep 10
   Unregister-ScheduledTask loadtest-share -Confirm:$false
   if (-not (Test-Path $probe)) { "the computer account could not write"; exit 1 }
   $owner = (Get-Acl $probe).Owner
   Remove-Item $probe
   if ($owner -notlike "*\$env:COMPUTERNAME$") { "owned by $owner"; exit 1 }
   ```

The faults stop whichever server runs the background jobs twice, three minutes
apart, so each server takes over once; for a Windows target the scenario uses
`windows_cmd` (`taskkill /F`) instead of `cmd`. It passes when both servers are ready
at the end, each took at least half its even share of events, every takeover took
under 45 s, the Windows server ran the jobs for at least 30 s, and the share check
succeeded.

### S7: a rolling upgrade

`s7-rolling-upgrade.yaml` upgrades the three servers from the previous release while
agents send and analysts work. Install the previous release on every server first, and
put the new one in the apt repository the servers use (and the new MSI at
`C:\loadtest\signalith-<version>.msi` on a Windows server). Then run it with the new
version:

```
TO_VERSION=0.3.0 signalith-loadgen run -f loadtest/s7-rolling-upgrade.yaml -json s7.json
```

Before each server, the upgrade fault waits until the upgrade check
(`GET /api/cluster/upgrade`, as `signalith cluster upgrade-check` says it) is safe,
drains the server it names, runs `cmd` over SSH (`windows_cmd` on Windows), waits until
the Servers page shows it on `TO_VERSION`, resumes it and goes on with the next. The
server that runs the jobs goes last. Each server is a target of its own, so agents and
analysts on a server that is being upgraded move to another one (agents) or see errors
until it is back (analysts); a load balancer in front hides that from people. It is
skipped on versions without the upgrade check. On the laptop cluster, `s7-small.yaml`
does the same with `docker compose ... up -d --no-deps {server}` once
`SIGNALITH_VERSION` names the new image.

### S9: an OpenSearch node lost

`s9-opensearch-node-loss.yaml` stops `os-2.lab` for four minutes under load. It needs
servers with `opensearch.urls` listing all three nodes (it is skipped on versions
without it) and replicas on Signalith's own indices (`<prefix>_*`): with no replica,
losing a node loses their only copy and the run fails on `opensearch_red_samples`. The
load generator reads OpenSearch through `opensearch.url` and `opensearch.urls` in the
scenario, so it also carries on with one node gone. It passes when those indices never
go red, fewer than 1% of batches are refused (and those are resent), none is lost, and
people stay signed in. If the stopped node was the cluster manager, the other two
take a few seconds to choose a new one, so a few health samples may go unanswered.

`s9-small.yaml` does the same at CI size with the Docker quick start and
`deploy/docker/docker-compose.opensearch3.yml`: it stops the `opensearch-2` container
for 90 s with `docker stop`. Publish each node's port (9200, 9201 and 9202 here) so
the load generator reaches them.

## Nightly job

`.github/workflows/nightly-load.yml` runs the CI-size scenarios every night (and on
demand from the Actions tab) on two servers that share the Docker quick start's
OpenSearch, through the integration test in `cmd/signalith-loadgen`. Each report is
kept as the run's `load-reports` artifact. Its `sizing` job runs `sizing-small.yaml`
against one server and then two, reads each server's CPU and memory, and keeps the
reports and the table it makes (`sizing.md`) as `sizing-reports`; set
`LOADGEN_SIZING=1` to run it yourself. Its `rolling-upgrade` job runs `s7-small.yaml`:
two servers built as version 9.9.0 are upgraded to a 9.9.1 build one at a time, by a
script that stops each and starts the newer build on the same files. Its
`opensearch-node-loss` job starts the quick start with
`docker-compose.opensearch3.yml` (three OpenSearch nodes) and runs `s9-small.yaml`;
the test takes the other nodes from `SIGNALITH_TEST_OPENSEARCH_URLS` and is skipped
without it. To run the same on Linux with Go:

```
go test -tags integration -run '^TestLoadgen' -v ./cmd/signalith-loadgen/
```

Without `SIGNALITH_TEST_OPENSEARCH` it uses an in-memory OpenSearch, which keeps no
operation counts, and `LOADGEN_SHORT=1` cuts each phase of the scenarios without faults
to a few seconds.
