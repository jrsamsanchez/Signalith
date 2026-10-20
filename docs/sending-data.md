---
description: Send events to Signalith with Fluent Bit agents and syslog, what each source becomes, and the limits on ingest.
---

# Agents and syslog

Signalith takes events from these kinds of senders:

- the **[Signalith Agent](signalith-agent.md)**, installed with one line per computer: it
  runs Fluent Bit for you, with nothing to configure by hand;
- **Fluent Bit agents** on Windows and Linux, set up from the **Add data** page;
- **syslog** (RFC 5424, RFC 3164 and CEF) from firewalls, switches, appliances and
  servers without an agent;
- **OpenTelemetry** Collectors and SDKs over OTLP/HTTP (see [OpenTelemetry](opentelemetry.md));
- tools built for Splunk's HTTP Event Collector, once turned on (see [Splunk HEC senders](hec.md)).

## Agents

Open **Add data**, pick **Linux** or **Windows**, and follow the steps: install Fluent
Bit, save Signalith's CA certificate and the generated configuration, and restart it.
The configuration already contains the server address and ingest token, and sends over
HTTPS, checking the server's certificate with that CA.

The configuration also sends two short headers with every batch: the computer's name
(`X-Signalith-Agent`, which Fluent Bit fills in itself) and which Signalith version made
the configuration and which certificate authority it trusts (`X-Signalith-Config`). With
them, the [Endpoints page](endpoints.md#log-agents) lists each agent once, even when it
sends to several servers, and says when one needs a new configuration. They are labels
only: the agent token is what lets an agent in. OpenTelemetry Collector configurations
send the second header only; Signalith takes a Collector's computer name from its events.

Agents on other machines must send to an address they can reach, such as
`https://192.168.1.20:7779`, not `localhost`. Enter it under **Agents send to** on that
page (or set `server.public_url` or `SIGNALITH_PUBLIC_URL`; agents use its host on the
agent port), and allow the agent port, 7779 by default, through this computer's firewall,
besides the web port, 9000 by default.

### The agent port

Agents send to a port of their own, apart from the web page and API: Fluent Bit, the
OpenTelemetry Collector (OTLP), osquery and network sensors. The web page is on port 9000
and agents send to port 7779, by default. Both use the same HTTPS certificate.

The agent port takes only what agents need: events (`/api/ingest`, and OTLP's
`/api/otlp/v1/logs`, and [HEC](hec.md)'s `/services/collector/...` when turned on), osquery (`/api/osquery/...`), the network sensor's own requests, the CA certificate
(`/api/tls/ca.pem`), the sensor install script (`/api/sensor/install.sh`), and `/livez`
and `/readyz` for load balancer health checks. It serves no web page and no API. Once
`server.agent_listen` is set, the web port turns agents away with 503 and a message
naming the agent port.

Set it with `server.agent_listen` (or `SIGNALITH_AGENT_LISTEN`), on the **Settings** page
as **Agent address**:

```yaml
server:
  listen: 0.0.0.0:9000        # web page and API
  agent_listen: 0.0.0.0:7779  # agents
```

`server.agent_listen: off` sends agents to the web port, as before 0.3. When you change
the agent port, set each agent up again from **Add data**: agents that send to the old
port stop sending.

**Add data** writes the agent port into each configuration: **Agents send to** takes the
host of the server's address and port 7779. With several servers, each server's choice
uses that server's own agent port. A firewall must let in both ports, and a load balancer
in front of several servers must forward both (see [Load balancers](load-balancers.md)).

### Upgrading to 0.3

New installs (`signalith init`, the installers and the Docker compose files) set
`server.agent_listen`, so their web port never takes agent traffic. A server installed
before 0.3 has no `server.agent_listen` in its `signalith.yaml`. It keeps its web port
(such as 8080), listens for agents on that address's host at port 7779, and still takes
agents on the web port, with a warning in the log for each one, so nothing stops sending.
To move over:

1. Allow port 7779 through the firewall, and through any load balancer.
2. Set up each agent again from **Add data**; the new configuration sends to port 7779.
3. Set `server.agent_listen`, such as `0.0.0.0:7779`, so the web port stops taking
   agents. The next release stops taking agents on the web port anyway.

The Docker quick start is different: its updated files publish 9000 and 7779 and set
`server.agent_listen`, so after the update open `https://localhost:9000` and set up each
agent again from **Add data** (see
[Upgrading to 0.3](https://github.com/jrsamsanchez/Signalith/blob/main/README.md#upgrading-to-03-the-agent-port)).

## What each source becomes

Events are sorted into data models with common (CIM-style) field names, so one search
or detection covers every source of the same kind.

| Source | Data model |
| --- | --- |
| Windows Security log: 4624, 4625 logons; 4648 explicit credentials; 4768, 4769, 4771 Kerberos; 4776 NTLM credential checks | Authentication |
| Windows Security log: 4688 process creation | Endpoint |
| Windows Security log: 4720, 4726, 4738, 4781 accounts; 4722, 4725 accounts enabled and disabled; 4723, 4724 password changes and resets; 4741, 4742 computer accounts; 4727, 4728, 4729, 4730, 4731, 4732, 4737, 4744, 4749, 4754, 4756, 4759, 4783, 4790 group changes; 4798, 4799 group listings; 4698, 4699, 4701, 4702 scheduled tasks; 4886, 4887 certificates; 4662 directory object operations; 1102 log cleared | Change |
| Windows Security log: 5140, 5145 network share access | Filesystem |
| Sysmon: 1 process create, 5 process terminated, 8 remote thread, 9 raw disk read, 10 process access; 3 network connection; 6 driver and 7 DLL load; 11 file create, 23 and 26 file delete; 12, 13, 14 registry; 22 DNS query | Endpoint, Network_Traffic, Image_Load, Filesystem, Registry, Network_Resolution |
| PowerShell script block logging: 4104 (Microsoft-Windows-PowerShell/Operational; see [Detections](detections.md#powershell-script-blocks)) | Script |
| PowerShell module logging: 4103 (same channel), and the Windows PowerShell log: 400, 403, 600, 800 (see [Detections](detections.md#powershell-module-logging-and-the-windows-powershell-log)) | Script; Other |
| Linux sshd, sudo, su (auth.log, secure, or journald) | Authentication |
| Linux audit log (auditd: audit.log, or its syslog plugin; each program start also joined into one process launch, see [Detections](detections.md#linux-audit-log-auditd)) | Other, sourcetype `linux:audit`; program starts in Endpoint |
| Apache and Nginx access logs (/var/log/nginx, /var/log/apache2, /var/log/httpd; see [Detections](detections.md#web-server-access-logs)) | Web |
| Linux useradd, userdel, usermod, gpasswd | Change |
| Syslog from any device (see below), including CEF | Authentication, Change, Network_Traffic or Other |
| OpenTelemetry Collector or SDK logs over OTLP/HTTP ([OpenTelemetry](opentelemetry.md)) | the same models for Windows, Linux and syslog records; Other for app logs |
| Splunk HEC senders ([Splunk HEC senders](hec.md)) | by sourcetype: Authentication, Web and the cloud sources' models; Other for the rest |
| Zeek on a network sensor: conn, dns, http, ssl and x509, files, notice ([Network sensor](network-sensor.md)) | Network_Traffic, Network_Resolution, Web, Certificates, File_Transfers, Intrusion_Detection; Modbus, DNP3 and the ICSNPP industrial protocol logs in Industrial; other Zeek logs in Other |
| Suricata EVE from a network sensor, or over syslog from pfSense and OPNsense: alert, flow, dns, http, tls, fileinfo ([Network sensor](network-sensor.md)) | Intrusion_Detection, Network_Traffic, Network_Resolution, Web, Certificates, File_Transfers; modbus, dnp3 and enip in Industrial; other event types in Other |
| Status of a sensor built with the sensor install script, every 5 minutes ([Network sensor](network-sensor.md#status)) | Other, sourcetype `sensor:status` |
| A log you saved a parser for on **Add data → Any other log** ([Any other log](custom-logs.md)) | The data model you chose, with the parser's sourcetype |
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
A server writes 32 batches at once (`ingest.max_concurrent`, under Settings > Web; lower it
on a server with little memory). While others wait, one agent token gets at most a quarter
of them, so one busy agent cannot hold up the rest. In [multi-tenant mode](multi-tenant.md)
these slots, and the memory for batches arriving described below, are shared by all tenants,
and no one tenant takes more than half of either while others wait.

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
1,000 new names per daily index each time Signalith starts. With several servers, those
1,000 are shared among the servers that stored events in the last 10 minutes (at least
100 each), and no server adds new names to a day whose index already has 2,100 fields
(see [Servers](servers.md#field-names-when-several-servers-receive-events)). Fields Signalith itself
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
Point them at this server's address over **TLS on port 6514**, or, once it is turned on,
as plain syslog on **UDP or TCP port 514**. Syslog over TLS uses the web UI's certificate
(see [HTTPS](https.md#agents-and-syslog)).

A new install takes **syslog over TLS only**. Plain syslog over UDP and TCP is
unencrypted, and anyone who can reach the port can send fake events, so it is off by
default: `signalith init`, the packages, the Windows installer, the Docker quick start
and the Helm chart all leave it off. Many network devices can only send plain syslog;
for them, turn it on as below, and limit who may send with
**Allowed senders** (below).

**Upgrading:** an existing install keeps plain syslog as it was. Package, Windows and
hand-made installs keep their `signalith.yaml`, which an upgrade never changes, and
settings saved on the Settings page stay saved. A Docker quick start set up before keeps
UDP and TCP on 5514 (514 on the host) although the new `signalith.yaml` has them off:
its first start with this version sees Signalith's own files in the `signalith-data`
volume, notes the answer in `plain-syslog.json` there, and never decides again; a new
install's empty volume stays on TLS only. A Helm upgrade keeps plain syslog when the
release's syslog Service takes port 514, unless `server.syslog.plain` says otherwise.
Turn plain syslog off on the Settings page once every device sends over TLS.

Open **Add data** and pick **Syslog** for copy-ready setup for rsyslog, syslog-ng, Cisco IOS
and ASA, Palo Alto, FortiGate, pfSense and OPNsense, UniFi and Windows, with this server's
address filled in; rsyslog and syslog-ng send over TLS, with the CA certificate
to save. Send the test message it shows (over TLS while plain syslog is off) and watch it
arrive on the same page.

### Turning on plain syslog

On **Add data** > **Syslog**, an admin chooses **Turn on plain syslog (UDP and TCP)**.
The page warns first that plain syslog is unencrypted and can be forged. The button saves
**UDP address** and **TCP address** (`syslog.udp` and `syslog.tcp`) the way the
**Settings** page does: `0.0.0.0:514`, or `0.0.0.0:5514` in a container, which the Docker
quick start publishes as port 514. Plain syslog starts with the next restart: **Restart
now** opens the Settings page at its restart banner. Where the system needs more, the page
says so after the click: on Linux, the command that lets a service open port 514 (it
restarts Signalith too), and on Windows the firewall rules for UDP and TCP 514.

When the server's environment sets these settings (`SIGNALITH_SYSLOG_UDP` and
`SIGNALITH_SYSLOG_TCP`), the page says so instead of offering the button. The Helm chart
sets them from `server.syslog.plain` (see [Kubernetes](kubernetes.md)). To turn plain
syslog on in signalith.yaml instead:

```yaml
syslog:
  udp: 0.0.0.0:514
  tcp: 0.0.0.0:514
  tls: 0.0.0.0:6514
```

or give `signalith init` `-syslog-udp 0.0.0.0:514 -syslog-tcp 0.0.0.0:514` on a new
install (`install.ps1 -SyslogUdp 0.0.0.0:514 -SyslogTcp 0.0.0.0:514` on Windows).

By hand, forwarding a Linux server's logs with rsyslog over plain TCP is one line in
`/etc/rsyslog.d/90-signalith.conf`, then a restart of rsyslog (Add data gives the TLS
setup, which needs a few more):

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
`syslog.public_port` so Add data shows the right one (the Docker quick start's plain syslog
listens on 5514 and sets it to 514). The **Health** page (and `/api/health`, under `syslog`) shows the
listeners, how many messages were received, dropped, not written and rejected, and the
most recent senders.
