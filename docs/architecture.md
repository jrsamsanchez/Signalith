---
description: How Signalith is built, at a high level, covering the server, agents, OpenSearch, detections and the cluster, and how data flows between them.
---

# Architecture

This page gives the high-level design: the programs that make up Signalith, what each
part of the server does, and how an event travels from a computer to a finding. For the
security view of the same parts (trust boundaries, threats and defenses), see the
[threat model](threat-model.md).

## The programs

| Program | Where it runs | What it does |
| --- | --- | --- |
| **Signalith server** (`signalith`) | One or more servers | Web pages and API, data intake, search, detections, findings, cases, playbooks, settings. One Go binary with the web interface built in |
| **OpenSearch** | Next to the server, or a separate cluster | Stores events, findings and Signalith's own state. Signalith talks to it over HTTPS with a client certificate |
| **Signalith Agent** (`signalith-agent`) | Each monitored computer | Installs, configures and supervises Fluent Bit and osquery, and reports their health. See [Signalith Agent](signalith-agent.md) |
| **Fluent Bit** and **osquery** | Each monitored computer | Fluent Bit reads and sends logs; osquery reports inventory and file changes and answers live queries. Both come from their own publishers |

Other senders need no agent: syslog devices, OpenTelemetry collectors, HEC-compatible
senders and cloud services that Signalith pulls from (see [Sending data](sending-data.md)).

```text
 Computers                    Signalith server                       OpenSearch
 ─────────                    ────────────────                       ──────────
 Agent ─ Fluent Bit ─HTTPS:7779─►┐
 Agent ─ osquery ────HTTPS:7779─►│  intake ─► parse ─► normalize ─────► daily event
 Syslog devices ───UDP/TCP 514──►│  (limits,   (per     (data model     indices
 OTLP / HEC senders ──HTTPS─────►┘  tokens)    source)   fields)
                                                                 ┌──── findings, cases,
 Browsers, API, MCP ─HTTPS:9000─► web pages + API ─► search ─────┤     settings, users,
                                     │                           │     audit log
                                     └─ detections (scheduled) ──┘
                                        ─► findings ─► risk, notifications, playbooks
```

## Inside the server

The server is one process made of packages under `internal/`. The main groups:

| Area | Packages | Role |
| --- | --- | --- |
| Web and API | `api`, `httpserver`, `auth`, `users`, `oidc`, `saml`, `scim`, `mcp` | Serves the web interface (`web/`) and the JSON API, signs people in, checks each request against the user's role and tenant |
| Intake | `ingest`, `syslog`, `agents`, `agenttokens`, `agentproto`, `m365`, `okta`, cloud pulls | Accepts events, enforces size and rate limits, checks agent tokens |
| Parsing and data models | `datamodel`, `clusterparsers`, `redact` | Turns raw events into common fields grouped by data model (Authentication, Endpoint, Network Traffic and others) so one search covers many sources |
| Storage | `store`, `retention`, `clusterarchive`, `archivecrypt`, `summary` | Writes to OpenSearch in daily indices (`<prefix>-<datamodel>-YYYY.MM.DD`, split into parts on busy days), applies retention, moves old days to encrypted cold storage, keeps summary indexes |
| Search | `query`, `search`, `nlq`, `lookuptables` | Parses the pipe-style [query language](query-language.md), runs what it can inside OpenSearch and the rest in the server, with time and size limits. `nlq` turns plain-English questions into queries |
| Detections | `detect`, `sigmacheck`, `splcheck`, `content`, `ruledraft` | Runs detections on a schedule, converts Sigma and other rule formats into Signalith queries, loads signed content updates |
| Findings and response | `findings`, `risk`, `cases`, `storyline`, `investigate`, `respond`, `playbooks`, `notify`, `ticketing`, `chatops` | Groups detection hits into findings with risk scores, tracks cases, runs response playbooks (with approval), and sends notifications and tickets |
| Context | `assets`, `intel` | Asset and identity lists (CSV parsing, matching, priority), and threat intel indicators: feed parsing (lines, CSV, STIX, format detection), the feed catalog, TAXII 2.1, guarded downloads and feeds managed on the page |
| Dashboards | `dashboards` | Security posture metrics, custom dashboard files, and a runner that runs panels in parallel |
| AI | `assistant`, `investigate`, `mcp` | Optional AI features using a model you choose; the MCP server is read-only |
| Settings and secrets | `config`, `secrets`, `securefile`, `safelog`, `audit` | Settings with validation, secrets encrypted at rest with the master key, whole-or-nothing writes of files with secrets, length limits for log values and the rotating log file, and a signed, chained audit log |
| Cluster | `cluster`, `clusterauth`, `clusterjoin`, `clusterpki`, `clustertls`, `clustercfg`, `ospki`, `tlsauto` | Lets several servers share one OpenSearch: membership, the cluster key, the certificate authority, shared settings and the choice of which server runs background jobs |
| Tenants | `tenants` | Keeps each tenant's data, users and settings apart in multi-tenant mode |

Outside `internal/`:

| Path | What it holds |
| --- | --- |
| `cmd/signalith` | The command line and the server's entry point, and the Windows service |
| `web/static` | The web interface: plain JavaScript, no build step |
| `deploy/` | Install files, among them Docker Compose, the systemd unit and the Windows installer script |

To build and test Signalith, see
[Contributing](https://github.com/jrsamsanchez/Signalith/blob/main/CONTRIBUTING.md).

## How an event becomes a finding

1. A sender delivers events to the agent port (7779), a syslog port or an intake API.
   The server checks the sender's token and the size limits, and refuses what does not
   fit.
2. A parser for that source pulls out fields, and the event gets its data model and
   common field names. Unknown fields are kept.
3. The event is written to that day's index for its data model.
4. Each detection is a saved query with a schedule and a look-back window. When it is
   due, the server runs the query over that window. Each row it returns is a hit.
5. Hits become findings, grouped by entity and scored for risk. A finding can raise a
   notification, open a ticket, start a playbook or be added to a case.

## Several servers

Any number of Signalith servers can share one OpenSearch. Every server serves the web
pages, takes in data and searches. They find each other through OpenSearch and share
settings signed with the cluster key. One server at a time runs the background jobs,
detections can be spread across all of them, and if a server stops, another takes over
its work. See
[Servers](servers.md) and [Multi-server setup](multi-server.md).

## Where state lives

- **OpenSearch**: events, findings, cases, users, shared settings, detection state and
  the audit log. Records Signalith depends on are signed with keys OpenSearch never holds.
- **The state folder** on each server: the master key, the cluster key, certificates and
  the server's own settings file. Anyone who can write it controls that server; back up
  the master key (see [Backing up the key](encryption.md#backing-up-the-key)).

## Built with

Go (standard library crypto, no cgo of its own), OpenSearch 2.17 or newer (3.x included), Fluent Bit,
osquery, and plain HTML, CSS and JavaScript for the web interface with no build step.
