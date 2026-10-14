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
| `s7-rolling-upgrade.yaml` | Rolling upgrade under load (skipped until supported) | Lab |

A scenario file names the targets, the files with secrets, the phases of load, the
faults and the pass criteria. `${NAME}` in it is replaced by that environment variable.
`signalith-loadgen check loadtest/*.yaml` checks the files without running anything.

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
echo "admin:$(cat $O/secrets/initial-admin-password)" > $O/admin.txt
cp $O/secrets/ingest-token $O/token.txt
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
out of HAProxy's backend between runs), and compare the highest phase each keeps
within its latency limit. Keep each run's JSON report with the date and the version
(`signalith version`); they are what the sizing table in docs/performance.md comes
from.

## Nightly job

`.github/workflows/nightly-load.yml` runs the CI-size scenarios every night (and on
demand from the Actions tab) on two servers that share the Docker quick start's
OpenSearch, through the integration test in `cmd/signalith-loadgen`. Each report is
kept as the run's `load-reports` artifact. To run the same on Linux with Go:

```
go test -tags integration -run '^TestLoadgen' -v ./cmd/signalith-loadgen/
```

Without `SIGNALITH_TEST_OPENSEARCH` it uses an in-memory OpenSearch, which keeps no
operation counts, and `LOADGEN_SHORT=1` cuts each phase of the scenarios without faults
to a few seconds.
