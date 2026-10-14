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

A nightly GitHub job runs the short scenarios (S1, S2, S3, S4 and S6 at CI size) on two
servers sharing the Docker quick start's OpenSearch and keeps each report.

## Scenarios

| | Scenario | Passes when |
| --- | --- | --- |
| S1 | Agents (and, in the lab, syslog devices) sending steadily, then more | No accepted event is lost or stored twice; 99% of batches answered within 2 s |
| S2 | People using the pages on every server at once, all triaging the same findings and writing in the same case, while agents send | Nobody is sent back to sign in; 95% of searches within 3 s |
| S3 | Servers doing nothing, then a flood of made-up session cookies | Few OpenSearch operations per idle server; the cookies cost OpenSearch nothing |
| S4 | The server that runs the background jobs is stalled, then killed (in the lab also cut off from OpenSearch, its clock moved and OpenSearch's disk filled) | Another server takes over within 45 s; never two at once; nothing lost |
| S5 | A large configuration: thousands of users, detections and indicators | Recorded: how long each takes to make, and how the pages respond afterwards |
| S6 | Wrong passwords against many accounts from many addresses, spread over every server | Each account gets only a few real password checks in total, whichever server is asked |
| S7 | A rolling upgrade under load | Skipped until rolling upgrades are supported |

## Sizing

Measured numbers from the lab will fill this table. Until then, a single server is set up
as in [Getting started](getting-started.md).

| Events/s | Servers | OpenSearch nodes | CPU per server | Memory per server |
| --- | --- | --- | --- | --- |
| | | | | |

## Known limits

- **A batch may be stored twice after a failover.** If a server stores a batch but stops
  before it answers, the agent sends the batch again to whichever server it reaches. A
  batch resent unchanged to any server is recognised and not stored again; the load test
  counts any duplicate that still gets through.
- **Agents do not move by themselves.** An agent sends to one address. With several
  servers, put a load balancer in front of them; DNS round robin alone leaves an agent
  sending to a server that is down until its DNS answer changes.
