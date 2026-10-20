# Performance and sizing

How much one Signalith server handles, what a second and third add, and what servers
that share one OpenSearch cost it, are measured with `signalith-loadgen`, a separate
program in the repository that plays many agents, syslog devices, people and attackers
at once. It is built and tested with Signalith but not shipped in the packages or the
image. The [lab runbook](https://github.com/jrsamsanchez/Signalith/blob/main/loadtest/README.md)
says how to run it, on a laptop or in a lab.

## How it measures

`signalith-loadgen run -f <scenario>` reads a scenario file from
[loadtest/](https://github.com/jrsamsanchez/Signalith/tree/main/loadtest), drives the
load it describes against one server, several servers, or a load balancer, breaks
things on a timeline where the scenario says so, and checks each pass criterion. It
prints a report and, with `-json`, saves it.

- **Agents** send JSON batches to `/api/ingest` the way Fluent Bit does, and resend a
  batch unchanged when the server says to try again. Every event carries the run, the
  agent and a sequence number, so afterwards the tool counts in OpenSearch exactly which
  events the servers had accepted and are missing, and which were stored twice.
- **Load is open loop:** requests go out on a fixed schedule, not when the last one
  returns, so a slow server shows up as longer response times rather than fewer
  requests. When the load generator itself falls behind, the report says so.
- **It only uses what anyone can:** the web API, the syslog ports, and read-only
  searches in OpenSearch to count what was stored.
- **Against one server**, checks that only mean something for several servers (such
  as how fast another server takes over the background jobs) are skipped, not failed.
  One server is the baseline the other results are compared with.

A nightly GitHub job runs the short scenarios (S1, S2, S3, S4, S6, S7 and S9 at CI size) on two
servers sharing the Docker quick start's OpenSearch (three nodes of it for S9) and keeps each report. A second job
in it measures the sizing table below.

## Scenarios

| | Scenario | Passes when |
| --- | --- | --- |
| S1 | Agents (and, in the lab, syslog devices) sending steadily, then more | No accepted event is lost or stored twice; 99% of batches answered within 2 s below the limit; two servers store at least 1.7 times, and three at least 2.4 times, what one server does |
| S2 | People using the pages on every server at once, all triaging the same findings and writing in the same case, while agents send | Nobody is sent back to sign in; no note or comment refused; 95% of searches within 3 s |
| S3 | Servers doing nothing, then a flood of made-up session cookies | Few OpenSearch operations per idle server; the cookies cost OpenSearch nothing |
| S4 | The server that runs the background jobs is stalled, then killed (in the lab also cut off from OpenSearch, its clock moved and OpenSearch's disk filled) | Another server takes over within 45 s; never two at once; nothing lost |
| S5 | A large configuration: thousands of users, detections and indicators | Pages within 2 s and searches within 3 s for 95% of requests, agents answered within 2 s, as without it; how long each part took to make is recorded |
| S6 | Wrong passwords against many accounts from many addresses, spread over every server | Each account gets only a few real password checks in total, whichever server is asked, and the guessing is refused |
| S7 | Every server upgraded in turn under load, as [Rolling upgrade](servers.md#rolling-upgrade-one-server-at-a-time) says: wait for the upgrade check, drain, install, resume | Every server reaches the new version; the jobs move once, to an upgraded server, and never run on two at once; nothing lost; nobody signed out; each open page reloads at most once |
| S8 | A Windows server joined to a Linux one (lab) | It takes at least half its even share of agents' events, runs the background jobs after a takeover within 45 s, and writes to the archive share as its computer account |
| S9 | One of three OpenSearch nodes stopped under load, as in [OpenSearch failover](opensearch-failover.md) | Signalith's own indices never lose their last copy (yellow, not red); fewer than 1% of batches refused and none lost; nobody signed out. Skipped on versions without `opensearch.urls` |

## Sizing

### Measured on a CI runner

These numbers come from the nightly job's sizing run
([loadtest/sizing-small.yaml](https://github.com/jrsamsanchez/Signalith/blob/main/loadtest/sizing-small.yaml))
on one standard GitHub-hosted Linux runner (4 vCPU, 16 GB). **They are not a lab
measurement.** One machine runs everything: the Signalith servers, a single OpenSearch
node (the Docker quick start's, with its default 1 GB heap), and the load generator.
Agents send events of about 500 bytes, and the load goes up every 45 seconds. Measured
on 2026-10-15.

| Servers | Agents asked to send (events/s) | Stored (events/s) | p99 answer to agents | Busiest server CPU (cores) | Most memory of one server |
| --- | --- | --- | --- | --- | --- |
| 1 | 1,000 | 1,000 | 618 ms | 0.1 | 72 MB |
| 1 | 4,000 | 4,000 | 472 ms | 0.3 | 78 MB |
| 1 | 16,000 | 16,000 | 966 ms | 0.7 | 116 MB |
| 1 | 32,000 | 17,000 | 2.4 s | 0.7 | 172 MB |
| 2 | 1,000 | 1,000 | 222 ms | 0.1 | 70 MB |
| 2 | 4,000 | 4,000 | 175 ms | 0.1 | 72 MB |
| 2 | 16,000 | 16,000 | 808 ms | 0.4 | 98 MB |
| 2 | 32,000 | 18,000 | 2.5 s | 0.4 | 135 MB |

What this shows:

- **The single OpenSearch node is the limit, not Signalith.** Both runs level off at
  about 17,000 to 18,000 events a second. At that point the busiest Signalith server
  uses less than one core and under 200 MB. A second server adds little here (1.06
  times one server) because both servers write to that one node. Extra servers help when
  OpenSearch has room to spare, and for staying up when one server stops.
- **Past the limit, nothing is lost.** Agents are told to wait and send again, so
  answers slow down (2.4 s at the 99th percentile) but no events are dropped. The
  nightly S1 run counts every event to check this.
- **A small setup has plenty of room.** One server and one OpenSearch node sharing a
  4-vCPU machine stored 16,000 events a second, which is well over a billion a day.
  Disk space and how long you keep data usually set the size first (see
  [Retention](retention.md)).

The latest numbers are in each night's `sizing-reports` artifact, as `sizing.md`.

### Lab sizes

Measured in a cloud lab on separate machines with
[loadtest/tb-day.yaml](https://github.com/jrsamsanchez/Signalith/blob/main/loadtest/tb-day.yaml):
200 agents sending 25,000 events a second of about 500 bytes for 4 hours, 5 analysts
searching, and the built-in detections on. It ran for 4 hours on each of two days in a row (October 2026),
each day into a new daily index, with OpenSearch 3.9.0 and automatic shards.

| Events/s stored | Per day | Signalith servers | OpenSearch nodes | Result |
| --- | --- | --- | --- | --- |
| about 21,500 (median), 24,000 (p95) | about 1.86 billion events, about 1 TB | 1, with 2 vCPU and 4 GB | 2, with 8 vCPU and 16 GB each, on network volumes | Steady in both runs; 99% of batches answered within 1.8 s; searches under 0.8 s (p95); no detection ran late |
| all 25,000 offered (672 million in 4 hours, none dropped) | about 2.16 billion events, about 1 TB | 3, with 2 vCPU each | 2, with 4 vCPU each, on network volumes | 1,520 detections spread over the servers, none late; events searchable 2 s after sending (median), 9 s (p95); searches under 1.7 s (p95) |

The one Signalith server's 2 cores were the limit (about 70% busy on average), so it
stored about 21,500 of the 25,000 events a second offered. To reach 25,000, give the server more cores or add a
[second server](multi-server.md). OpenSearch was about 27% busy and refused no writes.
With three Signalith servers (one 4-hour run, October 2026), all 25,000 events a second
were stored with 1,520 detections turned on and
[spread over the servers](servers.md#the-background-jobs) (25, 21 and 18 of 64 groups).
The Signalith servers averaged under 50% CPU. This time OpenSearch was the limit: both
4-core nodes peaked at 99-100% CPU and their data volumes were 95-99% busy, so for more
headroom give OpenSearch more cores, faster local disks or a third node. In an earlier
three-server run, spread detections stayed evenly shared with no late runs through a
restart and a crash.

## Known limits

- **A batch may be stored twice after a failover.** If a server stores a batch but stops
  before it answers, the agent sends the batch again to whichever server it reaches. A
  batch resent unchanged to any server is recognised and not stored again; the load test
  counts any duplicate that still gets through.
- **The cases list can lag a note by a second.** A note, pinned event or saved search
  is saved without waiting for OpenSearch to make it searchable, so many people can
  write in one case at once (10 analysts on two servers: notes save in well under a
  second). The case itself shows the note at once; only the list's order by last update
  can be a second behind.
- **Agents do not move by themselves.** An agent sends to one address. With several
  servers, put a load balancer in front of them; DNS round robin alone leaves an agent
  sending to a server that is down until its DNS answer changes.
