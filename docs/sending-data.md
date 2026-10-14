---
description: Send events to Signalith with Fluent Bit agents and syslog, what each source becomes, and the limits on ingest.
---

# Agents and syslog

Signalith takes events from three kinds of senders:

- **Fluent Bit agents** on Windows and Linux, set up from the **Add data** page;
- **syslog** (RFC 5424, RFC 3164 and CEF) from firewalls, switches, appliances and
  servers without an agent;
- **OpenTelemetry** Collectors and SDKs over OTLP/HTTP (see [OpenTelemetry](opentelemetry.md)).

## Agents

Open **Add data**, pick **Linux** or **Windows**, and follow the steps: install Fluent
Bit, save Signalith's CA certificate and the generated configuration, and restart it.
The configuration already contains the server address and ingest token, and sends over
HTTPS, checking the server's certificate with that CA.

Agents on other machines must send to an address they can reach, such as
`https://192.168.1.20:8080`, not `localhost`. Enter it under **Agents send to** on that
page (or set `server.public_url` or `SIGNALITH_PUBLIC_URL`), and allow the port, 8080 by
default, through this computer's firewall.

## What each source becomes

Events are sorted into data models with common (CIM-style) field names, so one search
or detection covers every source of the same kind.

| Source | Data model |
| --- | --- |
| Windows Security log: 4624, 4625 logons | Authentication |
| Windows Security log: 4688 process creation | Endpoint |
| Windows Security log: 4720, 4726 accounts; 4728, 4732, 4756 group changes | Change |
| Sysmon: 1 process create, 8 remote thread, 10 process access; 3 network connection; 6 driver and 7 DLL load; 11 file create, 23 and 26 file delete; 12, 13, 14 registry; 22 DNS query | Endpoint, Network_Traffic, Image_Load, Filesystem, Registry, Network_Resolution |
| PowerShell script block logging: 4104 (Microsoft-Windows-PowerShell/Operational; see [Detections](detections.md#powershell-script-blocks)) | Script |
| Linux sshd, sudo, su (auth.log, secure, or journald) | Authentication |
| Linux useradd, userdel, usermod, gpasswd | Change |
| Syslog from any device (see below), including CEF | Authentication, Change, Network_Traffic or Other |
| OpenTelemetry Collector or SDK logs over OTLP/HTTP ([OpenTelemetry](opentelemetry.md)) | the same models for Windows, Linux and syslog records; Other for app logs |
| Anything else | Other (searchable by text and fields) |

sshd prints the user name a client sends, and on a failed key sign-in the key ID of the
certificate it offers, as they were sent. When either copies sshd's own "from <address>
port <n>" so that the real address cannot be told, the event is stored without `src` and
with `src_ambiguous=true`. Search `src_ambiguous=true` to find these sign-in attempts;
`host` says which server they were made against.

## Ingest limits

Agents send batches to `/api/ingest`, and OpenTelemetry Collectors to `/api/otlp/v1/logs`. One request can be up to 16 MB, with up to 200,000
records of at most 1 MB each, nested at most 32 levels deep; Fluent Bit's requests are
far smaller. A request over a limit is refused with 413 (400 for broken JSON) and a
message saying what to change, and nothing from it is stored. When many agents send at
once, the extra requests wait their turn and then get 503, so Fluent Bit sends them again.

A batch is read in full before it waits for its turn, so a slow sender never holds up
other agents. Batches still arriving may hold 256 MB of memory in all, and one sender (an
IPv4 address or an IPv6 /64) a quarter of that; past it, the sender gets 503 and sends
again shortly. Senders behind one proxy or NAT can be listed in `server.shared_addresses`.
A batch has 2 minutes to arrive; one still arriving at least 16 KB every 30 seconds gets
more time, up to 10 minutes, so slow links work. A batch that stalls or takes longer is
refused with 408 and a message saying to send smaller batches (a lower `Flush` in Fluent
Bit's `[SERVICE]` section), and the server log notes it.

Each event keeps its own time unless that is older than `ingest.max_event_age` (a week
by default, or the shortest retention period if shorter) or more than an hour ahead. Then it is filed
under the time it arrived and its own time is kept in `device_time`, so a wrong clock or
a forged date cannot create indices for other days. Search `device_time=*` to find these
events.

Field names that senders choose (JSON keys, syslog structured data, CEF extensions) are
limited so they cannot fill OpenSearch's mapping: at most 200 fields per event, names of
up to 128 letters, digits and `_ - @ : /` in at most 5 dot-separated parts, and at most
1,000 new names per daily index each time Signalith starts. Fields Signalith itself
produces are always kept, so an event is never lost to extra fields. Fields left out are
counted in the event's `dropped_fields` (search `dropped_fields>0`), their values stay in
`_raw`, and the Health page and `/api/health` show the totals under `ingest`
(`retimed`, `fields_dropped`).

A few field names belong to Signalith, which sets them itself: `@timestamp`, `datamodel`,
`device_time`, `dropped_fields` and the sample-data marker `signalith_sample`. When a
sender's event has one of them, it is left out and counted in `dropped_fields` the same
way; the event is stored without it. The one exception is the time of a JSON record:
its `date` (Fluent Bit sends one) is the event's time, or its `@timestamp` when it has
no `date`. These two are read as the time, not stored as fields and not counted. When
a record has both, its `@timestamp` is not used.

## Syslog

Firewalls, switches, routers, appliances and servers without an agent can send syslog.
Point them at this server's address on **UDP or TCP port 514**, or over **TLS on port
6514**. `signalith init` turns all three on; the Docker quick start publishes port 514.
Syslog over TLS uses the web UI's certificate (see [HTTPS](https.md#agents-and-syslog)).

Open **Add data** and pick **Syslog** for copy-ready setup for rsyslog, syslog-ng, Cisco IOS
and ASA, Palo Alto, FortiGate, pfSense and OPNsense, UniFi and Windows, with this server's
address filled in; rsyslog and syslog-ng send over TLS when it is on, with the CA certificate
to save. Send the test message it shows and watch it arrive on the same page.
When syslog is off, the page gives the steps to turn it on for this system: the
UDP and TCP address on the **Settings** page, then **Restart now**, plus the port
permission for a Linux service or the Windows Firewall rules.
By hand, forwarding a Linux server's logs with rsyslog is one line in
`/etc/rsyslog.d/90-signalith.conf`, then a restart of rsyslog:

```
*.* @@siem.example.com:514
```

`@@` sends over TCP; a single `@` sends over UDP. Signalith reads RFC 5424 and RFC 3164
syslog (including the usual variations, such as Cisco IOS, IOS XR, NX-OS and ASA), and
**CEF** (Common Event Format) from security products, mapped to CIM fields like `src`,
`dest`, `dest_port`, `user` and `action`. Forwarded sshd, sudo, su and user-management messages
land in Authentication and Change like agent data, so the built-in detections apply.
Events have `sourcetype=syslog` (or `cef`), `host` from the message, `dvc` set to the
sender's address, and `facility` and `severity`. The event time is the one in the message,
unless it is older than `ingest.max_event_age` (a week by default, or the shortest time any
event category is kept when that is shorter) or more than an hour
ahead; then it is the time Signalith received the message, and the device's own time is
kept in `device_time`, as for agent data (see [Ingest limits](#ingest-limits)).

To accept syslog only from known senders, list them in **Allowed senders** on the
Settings page, or under `syslog.allow`:

```yaml
syslog:
  udp: 0.0.0.0:514
  tcp: 0.0.0.0:514
  allow: [10.0.0.0/8, 192.0.2.10]
```

Over UDP the sender address can be forged, so for trusted senders use TCP or TLS, and
restrict the port with a firewall as well. The Windows installer limits its firewall
rules to the `syslog.allow` senders.

Ports below 1024 need extra permission on Linux. The systemd unit grants it; when
running Signalith another way, use a port such as `0.0.0.0:1514`. When devices send to a
different port than Signalith listens on, because Docker or a firewall forwards it, set
`syslog.public_port` so Add data shows the right one (the Docker quick start listens on
5514 and sets it to 514). The **Health** page (and `/api/health`, under `syslog`) shows the
listeners, how many messages were received, dropped, not written and rejected, and the
most recent senders.
