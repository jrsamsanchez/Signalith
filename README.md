# Signalith

An open-source SIEM for Windows and Linux, inspired by Splunk Enterprise Security.
Signalith stores events in [OpenSearch](https://opensearch.org), collects them with
[Fluent Bit](https://fluentbit.io), and adds the security layer on top: a pipe-based
query language that reads like SPL, plain-English questions that become queries, a
visual query builder, CIM-style data models, scheduled detections with a findings
queue for triage, Sigma rule import, a MITRE ATT&CK coverage map, risk-based
alerting with asset and identity context, threat intel feeds matched against your
events, a security posture dashboard plus dashboards you build from queries, and
investigation cases that collect findings, notes, searches and evidence in one place,
and response actions (block an IP, disable an account, isolate a host) run from a
finding or a case. Playbooks come next.

Website: **https://signalith.io** (its source is in [`site/`](site/)). Documentation:
**https://signalith.io/docs/** (built from [`docs/`](docs/)).

The server is a single Go binary with the web UI embedded. It runs as a Windows
service or a systemd unit.

> Status: Phase 3 (ES depth) is complete; Phase 4 has started with investigation cases. See the [roadmap](#roadmap).

## Quick start

### Docker (evaluation)

It needs Docker Compose 2.20 or newer (Docker Desktop has it). Check with
`docker compose version`; on Linux, update the `docker-compose-plugin` package if it is
older. Then, from the folder you cloned Signalith into:

```sh
docker compose -f deploy/docker/docker-compose.yml up -d
docker compose -f deploy/docker/docker-compose.yml exec signalith signalith initial-password
```

The first command downloads Signalith's ready-made image from GitHub
(`ghcr.io/jrsamsanchez/signalith`) and starts OpenSearch and Signalith. On first start a setup step makes the
admin password, a shared agent token and the certificates OpenSearch and Signalith use
with each other, and keeps them in Docker volumes; no password is written in the compose
files. Once OpenSearch is up, a second step loads OpenSearch's security settings (who may
sign in, and what each may do), and Signalith starts after it. If the first command ends
with `service "opensearch-security" didn't complete successfully`, see
[If OpenSearch's security settings aren't loaded](docs/opensearch-security.md#if-opensearchs-security-settings-arent-loaded).
The second command shows the admin password. Open https://localhost:8080 and sign
in as `admin` with it. Signalith serves HTTPS with a certificate it makes for itself, so
the browser warns until you trust it; the sign-in page has a **Download the server
certificate** link, and [docs/https.md](docs/https.md) says how to trust it.

Agents get their configuration from the **Add data** page: they send over HTTPS, and each
group of agents gets its own token when you copy or download its configuration. A new
install refuses events sent over plain `http://`, and refuses `change-this-ingest-token`,
the example token older versions gave every agent.

The token the setup step made (`ingest-token` in the `signalith-secrets` volume, passed in
as `SIGNALITH_INGEST_TOKEN_FILE`) is a **legacy shared token**: every agent set up with it
uses the same secret. It is kept so agents set up before per-agent tokens keep working.
To switch, give those agents a new configuration from **Add data**, then, under **Agent
tokens**, choose **Stop accepting** on the shared token. That's all: you don't need to
edit `docker-compose.yml`, and the Security page counts the token as retired. On a new
install no agent has it, so you can choose **Stop accepting** straight away. See
[Replace a shared token](docs/agent-tokens.md#replace-a-shared-token).
Coming from an older version? See
[Upgrading the Docker quick start](#upgrading-the-docker-quick-start).

Port 8080 is open on every network this computer is on. To take agents and browsers from
one network only, put this computer's address on that network in front of it in
`docker-compose.yml`, for example `- "192.168.1.20:8080:8080"`, then run the first command
again.

OpenSearch runs with its security plugin on: it answers only over HTTPS, publishes no
port, and lets in only Signalith's certificate, which may use only Signalith's own
indices. See [docs/opensearch-security.md](docs/opensearch-security.md).

To change the admin password (the first one then stops working):

```sh
docker compose -f deploy/docker/docker-compose.yml exec signalith signalith passwd
docker compose -f deploy/docker/docker-compose.yml restart signalith
```

Settings changed on the **Settings** page are kept in the `signalith-data` volume
(`/var/lib/signalith/lookups/settings.yaml` in the container), with Signalith's own
certificate authority, so they survive updates; settings given in `docker-compose.yml`'s
`environment:` show there locked.

To update, run `git pull` and then the first command again. It downloads the Signalith
image built from the newest code each time. If `git pull` says your local changes to
`deploy/docker/signalith.yaml` would be overwritten, run `git stash` and `git pull` again.
If the change you had made there was `plaintext_ingest: deny`, add that line back under
`mode: auto`, indented the same, before you run the first command; otherwise agents on
plain `http://` and the old example token may be accepted again. After a reboot
everything starts again by itself once Docker is running; in Docker Desktop turn on
Settings > General > "Start Docker Desktop when you sign in". If the computer restarted
while the first command was still waiting for the step that loads OpenSearch's security
settings, Signalith had not started yet and does not start by itself: https://localhost:8080
doesn't answer. Run `docker compose -f deploy/docker/docker-compose.yml up -d` again then.

#### Running a release, or building the image yourself

The quick start runs the image GitHub builds from `main`, which matches the code `git pull`
gives you. To run a release instead, check out its tag and set `SIGNALITH_VERSION` to the
same version before the first command, for example in PowerShell:

```powershell
git checkout v0.1.0
$env:SIGNALITH_VERSION = "0.1.0"
docker compose -f deploy/docker/docker-compose.yml up -d
```

(in a Linux or macOS terminal: `export SIGNALITH_VERSION=0.1.0`). To build the image
from the code you checked out, for example to try a change of your own, add
`-f deploy/docker/docker-compose.build.yml` after the first `-f` in every command:

```sh
docker compose -f deploy/docker/docker-compose.yml -f deploy/docker/docker-compose.build.yml up -d
```

#### Upgrading the Docker quick start

Earlier versions of the quick start served plain HTTP, ran OpenSearch without security,
and took the admin password and ingest token from `docker-compose.yml`
(`change-me-please` and `change-this-ingest-token` unless you changed them). To upgrade,
in the folder you cloned Signalith into (PowerShell or a terminal, the commands are the
same):

1. Put your own edits aside and update:
   ```sh
   git stash
   git pull
   ```
   `git stash` keeps what you changed (such as the admin password in
   `docker-compose.yml`, which is no longer needed); `git stash show -p` shows it later.
2. Start it as usual:
   ```sh
   docker compose -f deploy/docker/docker-compose.yml up -d
   ```
   This downloads the new Signalith image, runs the setup step once, restarts OpenSearch with its
   security plugin on, and then runs the step that loads OpenSearch's security settings;
   Signalith starts after that. The first start takes a minute or two longer, and up to
   about 10 minutes on a slow computer, where that step keeps trying while OpenSearch is
   slow. Events, findings, investigations, users, detections and dashboards are kept: they
   are in the `opensearch-data` and `signalith-data` volumes, which stay. If the command
   ends with `service "opensearch-security" didn't complete successfully`, or the
   **Servers** page later says OpenSearch's security settings aren't loaded, follow
   [If OpenSearch's security settings aren't loaded](docs/opensearch-security.md#if-opensearchs-security-settings-arent-loaded).
3. Show the new admin password:
   ```sh
   docker compose -f deploy/docker/docker-compose.yml exec signalith signalith initial-password
   ```
   The old one no longer works. People you added on the **Users** page keep theirs.
4. Open **https**://localhost:8080 (old `http://` bookmarks are redirected) and sign in as
   `admin`. Trust the certificate as described in [docs/https.md](docs/https.md).
5. Update the agents. Agents you set up before keep sending for now: on its first start
   Signalith sees that OpenSearch already holds events from before the upgrade, so it
   still accepts agents over plain `http://`, with the old example token. (A new install
   refuses both. Signalith decides this once and keeps the answer, so events stored later,
   such as sample data, never change it.) The **Health** page lists each agent still
   sending over plain `http://` (behind Docker Desktop they share one address, so it names
   them by the computer names in their events). On each of them, install the configuration
   from the **Add data** page again; it gives the agent a token of its own and moves it to
   HTTPS. Syslog devices need no change. If you had set a token of your own in
   `SIGNALITH_INGEST_TOKEN`, add that line back under `environment:` of the `signalith`
   service in `docker-compose.yml` and run step 2 again; new agents still get their own
   token.
6. If you had changed other things, such as ports or `SIGNALITH_PUBLIC_URL`, make the same
   changes in the new files (`SIGNALITH_PUBLIC_URL` now starts with `https://`).
7. Once the **Health** page lists no agent still sending over plain `http://`, set
   **Agents on plain HTTP** to **Refuse them** on the **Settings** page (the **HTTPS**
   card; it applies at once). That also ends the old token for good: it stays refused even
   if you accept agents on plain HTTP again later. An agent you missed is turned away until
   it gets a new configuration; it keeps its events and sends them then, and Health names
   it. Until then the **Security** page shows the old token as a risk.

This version encrypts the passwords and keys it keeps in the `signalith-data` volume
(`directory.json`, `intel_feeds.yaml` and `settings.yaml`), which older versions cannot
read. Before going back to one, run `secrets decrypt` in a container of its own (see
[docs/encryption.md](docs/encryption.md#going-back-to-an-older-version), which has the
Docker commands).

### Try it with sample data

No logs to hand? On the **Add data** page (under Data, admins only), **Load
sample data** fills Signalith with a week of made-up activity for a fictional company,
with a handful of attacks hidden in it, so detections fire, the triage queue fills,
risk builds up, threat intel matches and the dashboards light up. Everything is
fictional and kept apart from your own data, and one click removes all of it. See
[docs/sample-data.md](docs/sample-data.md). From the shell or in Docker:

```sh
docker compose -f deploy/docker/docker-compose.yml exec signalith signalith sample-data load
```

### Packages (.deb, .rpm, .msi)

Each [release](https://github.com/jrsamsanchez/Signalith/releases) has signed packages
that install Signalith as a service in one step, and a container image on GHCR:

```sh
sudo apt install ./signalith_0.1.0-1_amd64.deb      # Debian, Ubuntu
sudo dnf install ./signalith-0.1.0-1.x86_64.rpm     # Red Hat, Rocky, Alma, Fedora
sudo signalith initial-password                     # the first admin password
```

On Windows, double-click `signalith-0.1.0-x64.msi`. On Linux you can instead add
Signalith's signed apt or dnf repository, so `apt upgrade` and `dnf upgrade` bring new
releases. See [docs/install-packages.md](docs/install-packages.md) for the repositories,
what the packages set up, upgrades, and how to check a download's signature and SBOM. The steps below install by hand.

### Linux

1. Install OpenSearch 2.x ([instructions](https://opensearch.org/docs/latest/install-and-configure/install-opensearch/index/)).
2. Install Signalith:
   ```sh
   sudo install -m 0755 signalith-linux-amd64 /usr/local/bin/signalith
   sudo useradd --system --no-create-home signalith
   sudo signalith init -c /etc/signalith/signalith.yaml -opensearch http://127.0.0.1:9200
   sudo chown -R signalith /etc/signalith /var/lib/signalith
   sudo cp deploy/systemd/signalith.service /etc/systemd/system/
   sudo systemctl enable --now signalith
   ```
   `init` prints the admin password once, and where it put the master key that
   encrypts the passwords and keys Signalith stores (`/var/lib/signalith/keys/master.key`).
   Back that file up, apart from the config; see [Encryption](#encryption). Open
   `https://<server>:8080`: Signalith serves HTTPS with a certificate it makes for itself
   (see [HTTPS](#https)).
3. Replace OpenSearch's demo security setup, whose passwords and certificates are public,
   and have Signalith sign in with a certificate of its own:
   [docs/opensearch-security.md](docs/opensearch-security.md).

To upgrade, stop the service, replace the program and the unit, encrypt passwords an older
version kept as plain text in `signalith.yaml`, and start it again:

```sh
sudo systemctl stop signalith
sudo install -m 0755 signalith-linux-amd64 /usr/local/bin/signalith
sudo cp deploy/systemd/signalith.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo signalith secrets encrypt
sudo systemctl start signalith
sudo signalith secrets status
```

The server encrypts the passwords and keys in its own files when it starts. Its master key is
`/var/lib/signalith/keys/master.key`; `secrets status` shows where it is. Older versions cannot
read encrypted values: before going back to one, run `sudo signalith secrets decrypt` (see
[docs/encryption.md](docs/encryption.md#going-back-to-an-older-version)).

### Windows

1. Install OpenSearch 2.x for Windows ([instructions](https://opensearch.org/docs/latest/install-and-configure/install-opensearch/windows/)).
2. In an elevated PowerShell, from the folder holding `signalith.exe` and `deploy\windows\install.ps1`:
   ```powershell
   .\install.ps1 -OpenSearchUrl http://127.0.0.1:9200
   ```
   This writes `C:\ProgramData\Signalith\signalith.yaml`, installs the **Signalith** service and starts it.
   Open https://localhost:8080 (see [HTTPS](#https) to stop the certificate warning).
   The service runs as its own account, `NT SERVICE\Signalith`, and only SYSTEM, Administrators and
   that account can read `C:\ProgramData\Signalith`. To upgrade, put the new `signalith.exe` next to
   the script and run it again: it stops the service, replaces the program, encrypts passwords an
   older version kept as plain text, moves the service off LocalSystem and starts it again. An
   archive folder outside `C:\ProgramData\Signalith` (`retention.archive_dir`) is given to the new
   account too, and certificate and key files named in `signalith.yaml` or on the **Settings** page
   (`server.tls_cert`, `opensearch.ca_file` and the like) can be read by it; the script says which.
   After naming one outside `C:\ProgramData\Signalith` on the page later, run `signalith service install`
   again, as Administrator, so the service may read it. Before going back
   to an older version, run `signalith secrets decrypt` (see
   [docs/encryption.md](docs/encryption.md#going-back-to-an-older-version)).
3. Secure OpenSearch and have Signalith sign in with a certificate:
   [docs/opensearch-security.md](docs/opensearch-security.md).

### Send data

Open **Add data** in the UI, pick Linux or Windows, and follow the steps: install
Fluent Bit, save Signalith's CA certificate and the generated configuration, restart it.
The configuration already contains the server address and a token of its own for this group
of agents (made when you copy or download it; see [docs/agent-tokens.md](docs/agent-tokens.md)), and sends over
HTTPS, checking the server's certificate with that CA. For firewalls, switches and other network
devices, pick **Syslog** (see [Syslog](#syslog)). Hosts that run an OpenTelemetry Collector, and
apps with an OpenTelemetry SDK, can send logs over OTLP instead: pick **OpenTelemetry** (see
[docs/opentelemetry.md](docs/opentelemetry.md)). To watch files, take inventory and check
configuration on Windows, Linux and macOS hosts, pick **osquery**: Signalith becomes
osquery's management server and the hosts appear on the **Endpoints** page (see
[docs/endpoints.md](docs/endpoints.md)).
If you run Wazuh, pick **Wazuh** to send the alerts your Wazuh manager raises, through
Fluent Bit on the manager or its own syslog output (see [docs/wazuh.md](docs/wazuh.md)).

Agents on other machines must send to an address they can reach, such as
`https://192.168.1.20:8080`, not `localhost`. Enter it under **Agents send to** on that page
(or set `server.public_url` or `SIGNALITH_PUBLIC_URL`), and allow the port, 8080 by default,
through this computer's firewall.

Supported sources in Phase 1:

| Source | Data model |
| --- | --- |
| Windows Security log: 4624, 4625 logons | Authentication |
| Windows Security log: 4688 process creation | Endpoint |
| Windows Security log: 4720, 4726 accounts; 4728, 4732, 4756 group changes | Change |
| Sysmon: 1 process create, 8 remote thread, 10 process access; 3 network connection; 6 driver and 7 DLL load; 11 file create, 23 and 26 file delete; 12, 13, 14 registry; 22 DNS query | Endpoint, Network_Traffic, Image_Load, Filesystem, Registry, Network_Resolution |
| PowerShell script block logging: 4104 (Microsoft-Windows-PowerShell/Operational; see [Detections](docs/detections.md#powershell-script-blocks)) | Script |
| Linux sshd, sudo, su (auth.log, secure, or journald) | Authentication |
| Linux useradd, userdel, usermod, gpasswd | Change |
| Syslog from any device (see below), including CEF and LEEF | Authentication, Change, Network_Traffic or Other |
| Microsoft Defender Antivirus (Windows agent, collected automatically) | Malware |
| ClamAV (Linux agent: /var/log/clamav or the journal) | Malware |
| Antivirus consoles via syslog (CEF, LEEF, Symantec, Trellix ePO): Trend Micro, Sophos, ESET, CrowdStrike, SentinelOne, Kaspersky, Bitdefender and others | Malware |
| OpenTelemetry Collector or SDK logs over OTLP/HTTP ([docs/opentelemetry.md](docs/opentelemetry.md)) | the same models for Windows, Linux and syslog records; Other for app logs |
| osquery ([docs/endpoints.md](docs/endpoints.md)): file changes, software, accounts, ports, services, startup items, configuration checks | Filesystem, Inventory, Configuration_Check |
| Wazuh alerts from a Wazuh manager ([docs/wazuh.md](docs/wazuh.md)) | Authentication, Filesystem, Registry, Configuration_Check, Endpoint, Change or Alerts |
| Anything else | Other (searchable by text and fields) |

Antivirus: see [docs/antivirus.md](docs/antivirus.md).

sshd prints the user name a client sends, and on a failed key sign-in the key ID of the
certificate it offers, as they were sent. When either copies sshd's own "from <address>
port <n>" so that the real address cannot be told, the event is stored without `src` and
with `src_ambiguous=true`. Search `src_ambiguous=true` to find these sign-in attempts;
`host` says which server they were made against.

#### Ingest limits

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

#### Syslog

Firewalls, switches, routers, appliances and servers without an agent can send syslog.
Point them at this server's address on **UDP or TCP port 514**, or over **TLS on port
6514**. `signalith init` turns all three on; the Docker quick start publishes port 514.
Syslog over TLS uses the web UI's certificate (see [docs/https.md](docs/https.md#agents-and-syslog)).

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

### Sign in and users

The web UI has its own sign-in page. Sessions end after `auth.session_timeout` without
activity (12 hours by default) or when you sign out; tick **Keep me signed in** to stay
signed in for up to 7 days. Ten wrong passwords for one account from one address within
15 minutes lock that account out for that address for 15 minutes (with wider limits per
address and per account; see [docs/users.md](docs/users.md#signing-in)). Scripts and API
clients can keep using HTTP Basic auth with the same username and password, over HTTPS.

Admins add people on the **Users** page and give each one a role: **Viewer** (look,
search, change nothing), **Analyst** (also triage findings, work investigations, build
dashboards) or **Admin** (also detections, feeds, lists, data collection and users).
New users get a temporary password they replace at their first sign-in. People can
also sign in with their **Active Directory or LDAP** account, with their role coming
from their groups; set it up and test it on the same page. The `admin` account from
`signalith.yaml` stays as a break-glass account that always works. See
[docs/users.md](docs/users.md).

### HTTPS

The web UI, API and agent ingest use HTTPS by default, on the same port as before (8080).
On first start Signalith makes a small certificate authority of its own and a server
certificate signed by it, and renews the certificate by itself; nothing has to be set up.
Browsers warn until the CA is trusted: download it from the sign-in page (**Download the
server certificate**) and trust it once per computer. Agent setups on **Add data** carry the
CA and check the server with it. Plain `http://` still reaches the port: browsers are
redirected, and passwords and sessions are refused.

To use your own certificate, set `server.tls.mode: files` with `server.tls_cert` and
`tls_key`; behind a reverse proxy that adds HTTPS, `server.tls.mode: off` with
`server.trusted_proxies`. All of these are also on the **Settings** page, in the
**HTTPS** card. Configs from earlier versions keep working: agents set up for
`http://` keep sending until they get a new configuration, and the **Health** page lists
them. All of this, with the commands to trust the CA on Windows, macOS and Linux, is in
[docs/https.md](docs/https.md).

### Hardening built in

- **Security check**: the Security page (**Settings > Security**) and `signalith security`
  check how this server is set up and what to fix first. See
  [docs/security.md](docs/security.md).
- **Encryption in transit**: HTTPS by default, TLS 1.2 or newer, for the UI, API and
  agents, which check the server's certificate; passwords, Basic credentials and session
  cookies are refused over plain HTTP, and the session cookie is HTTPS-only
  (`__Host-signalith_session`). `X-Forwarded-Proto` is believed only from
  `server.trusted_proxies`. See [docs/https.md](docs/https.md).
- **Connections**: clients get 10 seconds to send request headers and a minute to send a
  request body (after their token or sign-in is checked, agent batches get 2 minutes, more
  while they keep arriving, and signed-in uploads 10 minutes); idle kept-alive connections
  close after 2 minutes, and headers are limited to 64 KB. Open connections are capped
  (`server.max_connections`), and one client may hold a tenth of them; a client is one IPv4
  address or one IPv6 /64 network, since an IPv6 host can pick any address in its /64. Over
  HTTPS (HTTP/2) each request in progress counts too, at most 32 per connection, so one
  connection cannot carry hundreds. Agent batches are also limited in size, in the memory one
  sender's batches may hold while they arrive, and in how many are written at once (see
  [Ingest limits](#ingest-limits)).
- **Browser**: every response carries a strict Content-Security-Policy (no framing, no
  plugins, no forms or base URLs pointing elsewhere) and, over HTTPS, HSTS. API replies are
  never stored in the browser cache, and signing out clears this site's cache and the last
  query; display preferences such as the theme stay.
- **Disguised text**: invisible and text-reordering Unicode characters in event data are
  shown as a marked `⟨U+202E⟩`. U+202E, for example, would otherwise make `invoice`,
  U+202E, `fdp.exe` look like `invoiceexe.pdf`. The stored events are unchanged; finding
  titles, which copy values from events and become the titles of new cases, are stored with
  the marker.
- **Logs**: values in log lines are cut to a sensible length, and the Windows service log
  (`C:\ProgramData\Signalith\signalith.log`) rotates at 10 MB, keeping 5 old files. The Docker
  quick start caps container logs the same way; under systemd, journald limits the log.
- **OpenSearch**: Signalith can sign in to OpenSearch with a client certificate over
  HTTPS, with a role limited to its own indices. The Docker quick start sets this up by
  itself, with no default passwords anywhere; `signalith opensearch-certs` makes the same
  files for OpenSearch on Linux or Windows. See
  [docs/opensearch-security.md](docs/opensearch-security.md).
- **Secrets**: every password and API key in Signalith's settings files is encrypted with a
  master key (`signalith secrets`; see [Encryption](#encryption)); files that hold a key on
  their own, such as the HTTPS CA key and the Docker quick start's generated secrets, are
  protected by their permissions instead. A password written into
  `opensearch.url` is moved out of the address and encrypted by `signalith secrets encrypt`; one
  in `opensearch.proxy` or a key in a feed's address cannot be, and is reported. Passwords and
  keys in configured URLs are hidden (`***`) everywhere a URL is shown or logged, and agents get a
  generic error rather than OpenSearch details.
- **Agent tokens**: each agent group sends with its own token (`sgl_` and 52 more
  characters), shown once and kept only as a SHA-256 hash in OpenSearch. Revoking one on
  **Add data** or with `signalith tokens revoke` turns its agents away within seconds on every
  server. Every event records the token's name and the sender's address
  (`signalith_token`, `signalith_sender`), and senders can't set those fields. To have a
  secret scanner find leaked tokens, give it `\bsgl_[a-z2-7]{52}\b`. See
  [docs/agent-tokens.md](docs/agent-tokens.md).
- **Memory**: on Linux the server turns off core dumps and keeps other programs from reading its
  memory; the systemd unit also turns off swap for it, hides other processes and limits it to the
  files and system calls it needs. On Windows the service runs as its own account rather than
  LocalSystem.

## Configuration

Everything lives in one YAML file (`/etc/signalith/signalith.yaml` or
`C:\ProgramData\Signalith\signalith.yaml`). `signalith init` writes a working one, and
`signalith validate` checks it and lists every problem with the setting to fix.
Unknown keys are rejected, so typos do not silently do nothing.

### Settings page

Admins can change most of these settings on the **Settings** page instead: the public
and web addresses, HTTPS (the mode, extra certificate names, your own certificate
files, agents on plain HTTP and trusted reverse proxies), the OpenSearch connection,
search limits, syslog, the detection scheduler and the AI assistant. Each one shows where its value comes
from; an environment variable wins over the page, which wins over `signalith.yaml`.
Some apply at once; for the rest, the page restarts Signalith inside the same process,
after checking that the new web address can be listened on and that OpenSearch
answers, and people stay signed in. A move of the web address goes back by itself
when nobody reaches the new one within 2 minutes, which makes a lockout unlikely,
though a firewall or proxy in between can still cause one. Changes are kept in
`settings.yaml` in the lookups folder (`SIGNALITH_SETTINGS_FILE` moves it), never in
`signalith.yaml`. Passwords and keys saved there are encrypted with the master key (see
[Encryption](#encryption)), are never shown, and are only sent to the address they
were entered for. If a change goes wrong, `signalith settings list` shows what was
changed on the page and `signalith settings reset [setting...]` undoes it; then
restart the service. The Linux service keeps the file in `/var/lib/signalith/lookups`,
which these commands read from its unit; where they cannot, give it with
`-file /var/lib/signalith/lookups/settings.yaml`. See [docs/settings.md](docs/settings.md).

Behind a reverse proxy that serves HTTPS, have it send `X-Forwarded-Proto: https` and
list it under `server.trusted_proxies` (**Trusted reverse proxies** on the Settings
page), so the sign-in cookie is marked for HTTPS only; the header is ignored from
anyone else. If the proxy also sets `X-Forwarded-For` itself, set
`server.client_header: x-forwarded-for` (**Client address header**) so failed sign-ins
are counted for each person's own address, not the proxy's. See
[docs/https.md](docs/https.md#behind-a-reverse-proxy).

| Setting | Default | Meaning |
| --- | --- | --- |
| `server.listen` | `127.0.0.1:8080` | Address the UI and API bind to |
| `server.public_url` | `https://` and the `listen` host and port | URL agents use (scheme, host and port); goes into generated agent configs. With HTTPS on it must be `https://` |
| `server.tls.mode` | `auto` | `auto`: HTTPS with a certificate Signalith makes and renews itself; `files`: `server.tls_cert` and `tls_key`; `off`: plain HTTP behind a reverse proxy that adds HTTPS. See [docs/https.md](docs/https.md) |
| `server.tls.names` | none | Extra host names or IP addresses for the `auto` certificate (this machine's names and addresses, `public_url` and addresses entered on Add data are always in it) |
| `server.tls.ca_scope` | `standard` | How far a certificate authority Signalith makes may vouch: `standard` (this server and private network names) or `strict` (only this server's own names and addresses). Used on the first start and when you make a new one on the Security page. See [docs/https.md](docs/https.md#how-far-the-certificate-authority-reaches) |
| `server.tls.plaintext_ingest` | `deny` (`allow` for configs from before HTTPS was the default, and on a Docker quick start upgraded from one that served plain HTTP, until agents on plain HTTP are first refused) | Whether agents may still send events over plain `http://`; the Health page lists any that do |
| `server.tls_cert`, `server.tls_key` | none | Your certificate (with its chain) and key, for `server.tls.mode: files`; reloaded when they change. TLS 1.2 or newer; browsers are told to use HTTPS only |
| `server.trusted_proxies` | none | IPs or CIDRs of reverse proxies whose `X-Forwarded-Proto: https` is believed (HSTS, HTTPS-only cookie, no redirect) |
| `server.client_header` | none | `x-forwarded-for` or `forwarded`: the header the trusted proxies set to each person's address, for the failed sign-in limits and the log. Only for a proxy that sets it itself; empty counts everyone behind a trusted proxy as one shared address |
| `server.max_connections` | `10000` | Open connections (and, over HTTPS, requests in progress) allowed at once; one client, an IPv4 address or an IPv6 /64, may hold a tenth of them. Connections from this machine, such as a local reverse proxy, are not limited that way |
| `server.node_url` | from `listen` and this computer's name | The address other Signalith servers that share this OpenSearch reach this one at, shown in the list of servers. Set in signalith.yaml or `SIGNALITH_NODE_URL` only; in Docker set it, since a container cannot know it |
| `server.shared_addresses` | none | IPs or CIDRs that many clients reach Signalith through: a reverse proxy, load balancer or NAT on another machine, or Docker Desktop's port forwarding, where every client seems to come from one address. These are not held to one client's share of connections, requests and ingest memory, only to the totals, and wrong passwords from them count per account, never pausing sign-ins from the whole address. The log names the address when one reaches its share |
| `opensearch.url` | `http://127.0.0.1:9200` | Event store, `http(s)://host:port` (no query string). A `user:password@` in it is moved to `username` and `password` when loaded and never shown; `signalith secrets encrypt` moves it there in the file, encrypted |
| `opensearch.username`, `opensearch.password` | none | OpenSearch credentials. Sent only over https, or plain http to this machine, unless `allow_insecure_http` is on |
| `opensearch.ca_file` | none | PEM file with the CA that signed OpenSearch's certificate (for a private CA); system CAs are trusted too. Relative to the config file |
| `opensearch.cert_file`, `opensearch.key_file` | none | Client certificate and key for certificate sign-in to OpenSearch; reloaded when they change |
| `opensearch.tls_skip_verify` | `false` | Skip OpenSearch certificate checks. Lab use only: anyone on the path can read and change traffic; Signalith warns while it is on |
| `opensearch.proxy` | none | Proxy for OpenSearch traffic (`http://`, `https://` or `socks5://`; or `SIGNALITH_OPENSEARCH_PROXY`). `HTTP_PROXY` and `HTTPS_PROXY` are never used for OpenSearch; when one is set and OpenSearch cannot be reached, the error says so |
| `opensearch.allow_insecure_http` | `false` | Allow `username`/`password` over plain http to another machine. Off, such a config is refused with an explanation |
| `opensearch.index_prefix` | `signalith` | Indices are `<prefix>-<datamodel>-YYYY.MM.DD` |
| `opensearch.replicas` | `auto` | Extra copies of each new day's events on other OpenSearch nodes: `auto` (one copy once OpenSearch has more than one node, none on one node) or a whole number such as `0`. Days already stored keep theirs; applies after a restart |
| `search.default_earliest` | `-24h` | Time range when a query sets none |
| `retention.days` | `90` | Days of events to keep (`0` keeps everything) until a default policy is saved on the Data retention page |
| `retention.interval` | `1h` | How often retention policies are enforced |
| `retention.archive_dir` | `archive` next to `lookups.dir` | Folder for archived days |
| `retention.default`, `retention.policies.<category>` | none | Policies that override the page; see [Data retention](#data-retention) |
| `retention.guard` | on, 85%, 7 days | Disk guard: `enabled`, `max_disk_percent`, `min_days` |
| `auth.admin_user`, `auth.admin_password_hash` | `admin` | The built-in admin, a break-glass account; change its password with `signalith passwd` (it asks twice without showing the password, or reads one line from a pipe or `SIGNALITH_NEW_PASSWORD`, and changes only this line of the file) |
| `auth.session_timeout` | `12h` | Sign the web UI out after this long without activity ("Keep me signed in" lasts up to 7 days) |
| `auth.users_file` | `users.json` in `lookups.dir` | Where users added on the Users page are kept; directory settings go in `directory.json` next to it |
| `auth.ldap` | none | Active Directory or LDAP sign-in, when you would rather not set it up on the Users page; see [docs/users.md](docs/users.md#setting-it-in-signalithyaml) |
| `ingest.tokens` | none | Shared tokens (legacy) agents send as `Authorization: Bearer`; still accepted. New agents get their own token on **Add data** (see [docs/agent-tokens.md](docs/agent-tokens.md)) |
| `ingest.max_event_age` | `7d` (or the shortest retention period if shorter) | Events older than this, or more than an hour ahead, are filed under the time they arrived, with their own time in `device_time`. See [Ingest limits](#ingest-limits) |
| `syslog.udp`, `syslog.tcp` | off (`init` sets `0.0.0.0:514`) | Addresses to receive syslog on; empty turns a listener off. See [Syslog](#syslog) |
| `syslog.tls` | off (`init` sets `0.0.0.0:6514`) | Address for syslog over TLS, such as `0.0.0.0:6514`; uses the web UI's certificate |
| `syslog.allow` | any sender | Sender IPs or CIDRs allowed to send syslog; others are dropped and counted |
| `syslog.public_port` | the listen port | Port devices send UDP and TCP syslog to, when it is forwarded to the listen port; shown on Add data |
| `detections.dir` | `detections` | Folder for custom and edited detections, relative to the config file |
| `detections.scheduler` | `true` | Lets this server run detections, threat intel downloads, notifications and retention. Servers that share one OpenSearch take turns automatically; turn it off only on a server that should never run them. See [More than one server](#more-than-one-server) |
| `detections.max_findings_per_run` | `100` | Cap on findings one run can raise |
| `detections.catch_up` | `6h` | When detections could not run, for example while every server was stopped, how far back the missed runs are made up once they run again (at most `7d`). Older ones are skipped and shown on the Detections page. `0` turns this off |
| `lookups.dir` | `lookups` | Folder for `assets.csv` and `identities.csv`, relative to the config file |
| `intel.feeds` | none | Threat intel feeds kept in this file (read-only on the page); most people add feeds on the **Threat intel** page instead. See [Threat intel](#threat-intel). Nothing is fetched until a feed is added |
| `intel.feeds[].name`, `.url` | required | Feed name (shown as the indicator source) and its http(s) address |
| `intel.feeds[].kind`, `.collection` | `url` | `taxii` reads a TAXII 2.1 collection: `url` is the API root and `collection` the collection ID |
| `intel.feeds[].format` | `lines` | `lines` (one per line, `#` comments), `csv` (with `column:`, a header name or number), `stix` (STIX 2.1 bundle) or `auto` to detect |
| `intel.feeds[].type` | `auto` | `auto` detects each value, or `ip`, `cidr`, `domain`, `url`, `hash`, `md5`, `sha1`, `sha256`, `email` |
| `intel.feeds[].interval`, `.max_age` | `1h`, `7d` | How often to download; how long indicators last when downloads keep failing |
| `intel.feeds[].weight` | `1` | Multiplies the risk a match adds (0 to 10) |
| `intel.feeds[].headers`, `.username`, `.password` | none | Request headers and HTTP basic sign-in for feeds that need a key; values may use `${ENV_VAR}` |
| `intel.feeds[].tags`, `.description`, `.enabled` | none, `true` | Labels added to every indicator, and on/off |
| `intel.feeds_file` | `<lookups.dir>/intel_feeds.yaml` | Where feeds added on the page are saved, with their API keys encrypted (file mode 0600) |
| `notify.file` | `<lookups.dir>/notifications.yaml` | Where notification channels and rules set on the **Notifications** page are saved, with their webhook URLs, header values and passwords encrypted (file mode 0600). See [docs/notifications.md](docs/notifications.md) |
| `playbooks.file` | `<lookups.dir>/playbooks.yaml` | Where playbooks set on the **Playbooks** page are saved (file mode 0600; they hold no secrets). See [docs/playbooks.md](docs/playbooks.md) |
| `intel.allow_loopback_feeds` | `false` | Allow feed downloads from this machine (`127.0.0.1`, `::1`), for a feed server on the same host |
| `cluster.node_name` | the name kept in the state folder, else this computer's name | This server's name in the list of servers and on every log line (`node=`). 1 to 63 letters, digits, dots, dashes or underscores. In Docker, set it (or `SIGNALITH_NODE_NAME`), since a container's name is random. Set in signalith.yaml or the environment only |
| `dashboards.dir` | `dashboards` | Folder for custom dashboards, one YAML file each, relative to the config file |
| `dashboards.stale_after` | `2h` | How long a host and source type can be quiet before the posture dashboard lists it as stopped |
| `assistant.provider` | off | Optional AI model for **Ask**: `anthropic`, or `openai` for any OpenAI-compatible API (OpenAI, Ollama, LM Studio, vLLM) |
| `assistant.url`, `assistant.model`, `assistant.api_key` | per provider | Endpoint, model name and key; `anthropic` defaults to `claude-sonnet-5-5` |
| `assistant.investigate` | `false` | Lets analysts use **Investigate with AI** on a finding, which sends the finding's events to the model. See [docs/investigate.md](docs/investigate.md) |
| `assistant.mask_fields` | none | Fields whose values are replaced with stand-ins before Investigate with AI sends anything; `_raw` leaves out the event text. Passwords, tokens, keys and cookies are always masked |

Secrets can come from the environment instead: `SIGNALITH_OPENSEARCH_PASSWORD`,
`SIGNALITH_ADMIN_PASSWORD`, `SIGNALITH_INGEST_TOKEN`, `SIGNALITH_LDAP_BIND_PASSWORD` (for
`auth.ldap` in this file only; directory sign-in set up on the Users page keeps its own) (also
`SIGNALITH_OPENSEARCH_URL`, `SIGNALITH_OPENSEARCH_USERNAME`, `SIGNALITH_OPENSEARCH_PROXY`, `SIGNALITH_LISTEN`,
`SIGNALITH_PUBLIC_URL`, `SIGNALITH_DETECTIONS_DIR`, `SIGNALITH_LOOKUPS_DIR`, `SIGNALITH_DASHBOARDS_DIR`,
`SIGNALITH_USERS_FILE`, `SIGNALITH_INTEL_FEEDS_FILE`, `SIGNALITH_NOTIFY_FILE`, `SIGNALITH_PLAYBOOKS_FILE`, `SIGNALITH_ARCHIVE_DIR`, `SIGNALITH_ASSISTANT_API_KEY`, and
`SIGNALITH_SYSLOG_UDP` and `SIGNALITH_SYSLOG_TCP`, where `off` turns the listener off, `SIGNALITH_NODE_NAME` and
`SIGNALITH_NODE_URL`). Secrets can also be read
from a file, as Docker and Kubernetes secrets are: set `SIGNALITH_OPENSEARCH_PASSWORD_FILE`,
`SIGNALITH_ADMIN_PASSWORD_FILE`, `SIGNALITH_INGEST_TOKEN_FILE`, `SIGNALITH_LDAP_BIND_PASSWORD_FILE` or
`SIGNALITH_ASSISTANT_API_KEY_FILE` to the file's path. Setting both forms of one is an error, except for the
ingest token, where both are accepted as shared tokens (agents set up on Add data get a token of their own). A setting set by an
environment variable, or by a file one names, is shown locked on the Settings page. When the admin password
comes from `SIGNALITH_ADMIN_PASSWORD_FILE`, or from `SIGNALITH_ADMIN_PASSWORD` given to the systemd or Windows
service, `signalith passwd` keeps the new one in `admin-password-hash` in the state folder, where it replaces
that password. `SIGNALITH_STATE_DIR` is the state folder,
where Signalith keeps files it makes for itself: its master key (in `keys`), its HTTPS
certificate (in `tls`), `admin-password-hash`, and this server's identity (`node.id`, and
`cluster/lock` while it runs). It defaults to the folder that holds `lookups.dir`, and the
systemd unit and Docker image set it to `/var/lib/signalith`; see
[More than one server](#more-than-one-server) for when Signalith uses another folder. `SIGNALITH_MASTER_KEY_FILE` or
`SIGNALITH_MASTER_KEY` supply the master key (see [Encryption](#encryption)). `SIGNALITH_SETTINGS_FILE` sets where the Settings page keeps its changes
(default `settings.yaml` in `lookups.dir`).

### More than one server

Several Signalith servers can share one OpenSearch, for example behind a load
balancer. They find each other through OpenSearch: each writes a heartbeat to the
`<prefix>_runtime` index every 10 seconds, so the OpenSearch user needs the right to
create, read and write that index (or `<prefix>_*`). The **Servers** page (under
Health, for admins) lists them, which one runs the background jobs, and what to fix
when something is wrong; `GET /api/cluster` returns the same list. When something
stops for everyone, such as no server running detections, every signed-in person
sees a red banner at the top of the page. One of
them runs the background jobs (detections, threat intel downloads, retention and
index upgrades); the others take over within about 40 seconds if it stops, or within
seconds when it is stopped on purpose. Two servers never run them at once: the one
that runs them stops by itself when it cannot confirm, within 20 seconds, that it
still may. Only servers with `detections.scheduler: true` take part. A server whose
clock is more than 30 seconds off leaves the jobs to one whose clock is right; keep
clocks in sync with NTP. A server that takes the jobs over makes up the
detection runs missed in between, up to `detections.catch_up` back, without raising
any finding twice, and every server shows the same detection run state (see
[Schedules and missed runs](docs/detections.md#schedules-and-missed-runs)).

The servers share the threat intel feeds and the retention policies through
OpenSearch, in the `<prefix>_config` index (give the OpenSearch user the right to
create, read and write it too): a change on any server's Threat intel or Data
retention page applies to all of them at once. The shared settings are signed with a
**cluster key** that the server running the jobs makes the first time; every other
server needs it, with `signalith cluster export-key` and `import-key` or a file named
in `SIGNALITH_CLUSTER_KEY_FILE`, and until it has it, it keeps using its own files
and never takes the jobs over (see
[Shared settings and the cluster key](docs/servers.md#shared-settings-and-the-cluster-key)
and [signalith cluster](docs/cluster-cli.md)). Custom detections are still kept in
files on each server: a server whose detection files differ from those of the server
that runs the jobs does not take them over by itself, and the list of servers says
why. When a retention policy archives, every server must set `retention.archive_dir`
to the same shared folder (Signalith names it with a `.signalith-archive-id` file;
leave it there).

Each server keeps its identity in its state folder (`node.id`, and `cluster/lock`
while it runs), next to its master key (`keys`) and its HTTPS certificate (`tls`).
The folder must be on a local disk that the service's user can write. When the folder
that holds `lookups.dir` is on a network share or cannot be written, and holds none
of those files yet, Signalith uses `/var/lib/signalith` (Linux) or
`C:\ProgramData\Signalith` (Windows) instead, unless another Signalith install already
keeps its files there, says so in its log, and keeps using it from then on (commands
such as `signalith secrets` find it too). A folder that
already holds a master key, a certificate or `admin-password-hash` is always kept, so
an upgrade never leaves them behind; if it is on a network share, the log says so,
and you can move its files to a local folder and set `SIGNALITH_STATE_DIR` to it.
Servers that share `lookups.dir` must each set their own `SIGNALITH_STATE_DIR`. Never
copy the folder to another server: two servers with one identity are found out, at
start or within seconds while running, and one of them stops running jobs and says
why. To give a server a new identity, stop it, delete `node.id` and start it again.

Load balancers and container platforms can ask `GET /readyz` (200
`{"ready":true}`, or 503 with a one-word `reason`: `starting`, `restarting`, `down`,
`opensearch`, `identity`, `degraded`, `gone`, `key_missing` or `stopping`) and `GET /livez` (200 while the process
runs). Both answer without signing in and say nothing else, over HTTPS and also over
plain `http://` on the same port, where everything else is sent to HTTPS, so a
health check works either way.

The servers also share their users, the built-in admin's password, the directory
sign-in settings and the sign-in sessions, once every server runs this version: a user
added on any server's Users page can sign in on all of them, a session made on one
server works on every server, so the load balancer needs no sticky sessions, and
`signalith passwd` on any server changes the built-in admin's password everywhere with
no restart (see [Users on several servers](docs/users.md#users-on-several-servers)).
Everyone signs in once more when the servers start sharing their users. Until then,
a web sign-in is kept by the server it was made on: set the load balancer to keep each
person on one server (sticky sessions). The pages
still see their own changes when a request reaches another server, and keep working
while servers of two versions share one address during an upgrade (see
[Several servers behind one address](docs/servers.md#several-servers-behind-one-address)).

**Upgrading servers that share one OpenSearch:** older versions ignore the shared
job lease, so upgrade them all together, or first set `detections.scheduler: false`
on every server but one and turn it back on once all of them run this version. Give
every server the cluster key once the first one has made it, and upgrade them all:
an older version keeps using its own feed and retention files, and the users are
shared only once no server of an older version has run for 24 hours (see
[Upgrading servers you set up by hand](docs/servers.md#upgrading-servers-you-set-up-by-hand)).

See [docs/servers.md](docs/servers.md) for the Servers page, how the jobs move,
adding a server by hand, and load balancer examples.

## Encryption

Passwords and API keys are encrypted in the files where Signalith keeps its settings: in `signalith.yaml`
(`opensearch.password`, `assistant.api_key`, `auth.ldap.bind_password`, `ingest.tokens`, feed
passwords and headers), in `settings.yaml` (the OpenSearch password and the AI model's API key
saved on the **Settings** page), in `directory.json` (the directory service account password),
in `intel_feeds.yaml` (keys of feeds added on the page) and in `notifications.yaml` (webhook URLs,
headers, signing secrets and mail passwords of notification channels). They look like `enc:v1:9096cd23:...`. A
plain value pasted into `signalith.yaml` still works, and `signalith validate` and the **Health**
page say to encrypt it; the server encrypts plain values in the files it writes itself
(`settings.yaml`, `directory.json`, `intel_feeds.yaml`) when it starts. The master key is made by
`signalith init` (or the first time a password is stored): `/var/lib/signalith/keys/master.key`
on Linux, `C:\ProgramData\Signalith\keys\master.key.dpapi` on Windows (also protected with DPAPI
for that computer), `/var/lib/signalith/keys/master.key` in the Docker volume. Back it up, apart
from the config. Losing it loses only the stored passwords and keys, never events: the server
keeps running, and the **Health** page lists what to enter again (for the Settings page, the
field itself says so).

```sh
sudo signalith secrets status                       # where the key is; how each value is stored
sudo signalith secrets encrypt                      # encrypt plain values, keeping comments and layout
sudo signalith secrets set opensearch.password      # asks twice without showing it, or reads a pipe
sudo signalith secrets set ingest.tokens            # adds a shared agent token (per-agent ones: signalith tokens create)
sudo signalith secrets rotate-master                # new master key; everything encrypted again
sudo signalith secrets rotate-master -prune         # remove the previous key once nothing needs it
sudo signalith secrets decrypt                      # plain text again, before going back to an older version
```

When the key is lost, `encrypt` and `set` stop rather than make a new one; add `-new-key` to the
first of them.

[docs/encryption.md](docs/encryption.md) covers backing up and changing the key, keeping it in a
systemd credential or a Docker secret, the commands in Docker, going back to an older version,
the key files the master key does not encrypt (such as the HTTPS CA key), disk encryption
(BitLocker, LUKS, Docker Desktop, cloud disks), what protects passwords in memory, and
confidential VMs. HTTPS is in [docs/https.md](docs/https.md).

## Detections and findings

A detection is a query that runs on a schedule. Each row it returns becomes a
**finding** in the queue, like a notable event in Splunk ES. Signalith ships 21
detections mapped to MITRE ATT&CK (brute force, password spray, encoded PowerShell,
Office spawning shells, shadow copy deletion, credential dumping, privileged group
changes and more, plus two risk incident rules); 19 are on by default.

- **Findings** is the triage queue: filter by status, severity, owner or entity;
  assign, change status and disposition, comment, and update many at once. Each
  finding shows the result that fired, its entities, triage guidance, its full
  history, and a **View contributing events** link that opens the exact search.
- **Detections** lists every rule with its last run. Edit one in the form, **Test**
  it to see which findings it would raise, or **Run now**. Editing a built-in saves
  your version and keeps the original to revert to. Any search can become a detection
  with **Save as detection** on the Search page.
- **Import Sigma rule** converts a [Sigma](https://github.com/SigmaHQ/sigma) rule to a
  Signalith query and lists anything it had to approximate. Imported rules start
  disabled so you can test them first.
- **Content packs** add community rules, off until you turn them on: 2,035 tested
  [SigmaHQ](https://github.com/SigmaHQ/sigma) Windows and Linux rules and 903 Windows and Linux detections
  from Splunk's open source
  [security_content](https://github.com/splunk/security_content) (Apache 2.0). With
  both packs on, detections cover 148 ATT&CK techniques. Newer tested rules arrive as
  signed content updates, without a new Signalith release (from the internet or as an
  upload). See [docs/detections.md](docs/detections.md#content-packs).
- **ATT&CK coverage** shows the Enterprise matrix with techniques covered by enabled
  detections, by disabled ones, and gaps.

Detections are YAML files, so they can live in Git. See
[docs/detections.md](docs/detections.md) for the format.

## Investigations

A **case** groups the findings that belong to one incident with the work done on it,
like an investigation in Splunk ES. Open the **Investigations** tab to see open cases.

- Start a case with **New case**, or select findings on the Findings page and choose
  **Add to case**. A finding belongs to one case; adding it to another moves it. The
  case takes the highest urgency of its findings and collects their users, hosts and
  IPs as **entities**, each a click away from a search.
- The **timeline** holds notes, searches and events. **Add a search** (or **Add to
  case** on the Search page) runs the query and keeps a snapshot of its first 50 rows,
  so the case still shows what you saw after the events age out. In search results,
  click a cell and choose **Pin this event to a case** to keep the full event.
- Set status, severity and owner as you work. When you resolve or close a case, write
  a resolution and optionally close all of its open findings with one disposition.

Cases are stored in OpenSearch in the `<prefix>_cases` index, and every change is
recorded with who made it.

### Investigate with AI

**Investigate with AI** on a finding gathers its events, where its users, hosts and
addresses show up, threat intel matches and related findings, lets the AI model run a
few more read-only searches, and writes a short verdict (likely real, likely benign or
unsure) with a timeline, the evidence behind it and suggested response actions, which a
person still reviews and runs. **Save to case** keeps the write-up as a case note.

It sends event data to the model, so it is off until an admin turns it on in **Settings
→ AI assistant**. Analysts see exactly what will be sent before it goes, admins can mask
fields (replaced with stand-ins such as `masked-user-1`), and a model on your own
hardware, such as Ollama, keeps everything on site. See
[docs/investigate.md](docs/investigate.md).

## Notifications

Signalith can tell you about new findings in Slack, Microsoft Teams, email or a webhook (a
SOAR, ticketing system or your own script). On the **Notifications** page (admins), add a
**channel** for each place messages go and test it with **Send test**. Then add a **rule**
that says which findings go there, such as "High and critical findings from any detection go
to Slack #soc and Email SOC team". Rules can also pick detections and a least risk score.
Sample-data findings are skipped unless a rule includes them.

Each finding goes to each channel once. Failed sends are retried for about 80 minutes,
and the Health page warns about a failing channel. Only the server running the background jobs
sends, so a cluster sends each message once. Webhook bodies are versioned JSON and can be
signed with HMAC-SHA256.

See [docs/notifications.md](docs/notifications.md) for setting up each kind of channel
(Teams uses a Workflows webhook), the webhook body, checking its signature, and the API.

## Risk and context

Signalith does risk-based alerting the way Splunk ES does. Most detections add
**risk** to the users and systems in their results instead of (or as well as)
raising a finding. Risk adds up per object, and two risk incident detections raise
one finding when an object crosses a total of 100 in 24 hours, or trips three ATT&CK
tactics from three detections in a week. Many weak signals about one user become
one alert, and noisy rules (new services, scheduled tasks, discovery commands) stop
flooding the queue.

- **Risk** lists the users and systems with the most risk, with a bar per score, the
  number of detections and tactics, and the asset or identity context. Click one to
  see every detection that added risk, oldest first.
- **Assets & identities** takes two CSV files, like the ES asset and identity
  lookups. Upload them on that page, or put them in `lookups.dir` (they reload within
  a minute). Every bad line is reported and nothing is saved until the file is clean.
  Download the current file from the same page to edit it.

```csv
host,ip,cidr,owner,priority,category,bunit,location
web1|web1.corp.local,10.0.1.10,,web team,critical,web|pci,ecommerce,dc1
,,10.20.0.0/16,it,low,workstation,,office
```

```csv
identity,name,email,manager,priority,category,bunit,watchlist
alice|CORP\alice|alice@corp.local,Alice Ng,alice@corp.local,bob,high,admin,it,true
```

Use `|` between several values in one cell. Hosts match by short name or FQDN,
IPs exactly or by the most specific CIDR, and users with or without `DOMAIN\` or
`@domain`. Priority is `low`, `medium`, `high` or `critical`.

Context changes three things:

- **Risk scores** are multiplied by the object's priority: critical ×2, high ×1.5,
  medium ×1, low ×0.5. A watchlisted user counts at least ×1.5.
- **Urgency** on each finding starts at its severity, goes up one level when a
  critical asset or watchlisted user is involved, and down one level when every
  known entity is low priority. The queue shows and filters by urgency.
- **`| enrich`** in any search adds `<field>_priority`, `_owner`, `_category` and more
  next to each user, host and IP field.

Risk events are stored under the Risk data model (`datamodel=Risk`) in
`<prefix>-risk-YYYY.MM.DD` indices, which ordinary searches leave out.

## Vulnerability scanning

The **Vulnerabilities** page scans the networks you list with [Nmap](https://nmap.org),
on a schedule or with **Scan now**, and matches the software it finds to known CVEs from
the U.S. National Vulnerability Database, marking the ones in CISA's Known Exploited
Vulnerabilities catalog. Before the first scan, **Scanner setup** checks the server and
says what is needed, why, and how to fix anything missing. Only product names are sent
for CVE lookups. Results go to the Vulnerabilities data model and three built-in
detections, and the hosts join the asset list. The Docker image includes Nmap; on
Windows and Linux installs, install Nmap from your package manager or nmap.org. See
[docs/vulnerabilities.md](docs/vulnerabilities.md).

## Threat intel

Like the ES threat intelligence framework, Signalith matches events against
**indicators**: IP addresses and IPv4 networks, domains, URLs, MD5/SHA-1/SHA-256
file hashes and email addresses.

- **Feeds** are added on the **Threat intel** page with **Add feed**: pick free
  feeds from the built-in catalog (abuse.ch, Spamhaus, Emerging Threats and more),
  paste the address of any list, CSV or STIX file, or connect a TAXII 2.1 server
  such as MISP or OpenCTI and pick a collection. **Test** downloads the feed and
  shows what it holds (format, indicator types, samples) before you save, and a new
  feed downloads at once. Feeds can also be listed under `intel.feeds` in
  signalith.yaml; those show on the page as read-only. Nothing is fetched until you
  add one.
- **Downloads** run on the server that runs the background jobs, every feed on its
  own interval. The server needs outbound HTTPS to each feed; proxy settings come
  from `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY` (OpenSearch traffic never uses
  them; see `opensearch.proxy`). An indicator that disappears from
  a feed is removed at the next download; if a feed keeps failing, its indicators
  expire after `max_age`. Turning a feed off removes its indicators; deleting one
  removes them, or keeps them until they age out if you choose.
- **Manual indicators**: add one on the **Threat intel** page or upload a CSV
  (`value,type,description,weight,expires,tags`) or plain list. Every bad line is
  reported and nothing is saved until the file is clean.
- **Matching**: the built-in **Threat intel match** detection (`threat-activity`)
  runs every 5 minutes, raises one finding per indicator and system a day, and adds
  60 risk times the indicator's weight to the system and user involved. In Search,
  `| threatmatch` keeps only matching events and `| intel` adds
  `<field>_intel_source`, `_intel_type`, `_intel_weight` and `_intel_description`
  columns to any result.

Feeds added on the page are saved in `lookups/intel_feeds.yaml` (set
`intel.feeds_file` to move it). To keep feeds in signalith.yaml instead, for example
when it is managed by configuration tools (check each provider's terms; values may
use `${ENV_VAR}` so keys stay out of the file):

```yaml
intel:
  feeds:
    - name: feodo-tracker          # botnet C2 servers, abuse.ch
      url: https://feodotracker.abuse.ch/downloads/ipblocklist.txt
      weight: 1.5
    - name: urlhaus                # malware download URLs, abuse.ch
      url: https://urlhaus.abuse.ch/downloads/text_recent/
      type: url
    - name: our-cti                # a collection on your own TAXII 2.1 server
      kind: taxii
      url: https://cti.example.com/taxii2/api1/
      collection: 91a7b528-80eb-42ed-a74d-c6fbd5a26116
      username: signalith
      password: ${CTI_PASSWORD}
```

See [docs/threat-intel.md](docs/threat-intel.md) for the catalog, formats, TAXII,
download safety rules, matching details and the API.

## Response actions

Analysts can act on what they find without leaving Signalith: **Respond** on a
finding or a case runs a **response action** on one of its users, hosts or IPs, such
as blocking an IP on the firewall, disabling the user in Active Directory, isolating
the host with a script, or starting a Shuffle workflow. The target is checked strictly
for its kind, a disruptive action needs a reason, and a confirm step says exactly
what will happen before anything runs. Every run is kept in the `<prefix>_actions`
index with who ran it, why and what came back, and noted on the case or finding.

Admins set actions up on the **Response actions** page from templates (OPNsense or
pfSense alias, generic webhook, Shuffle, isolate-host script, disable or enable an AD
user), with **Test** to check one without changing anything. Scripts run only from
the server's scripts folder (`response.scripts_dir`), which no page can change.

See [docs/response-actions.md](docs/response-actions.md) for each kind of action,
the AD delegation, example isolate scripts and the API.

## Playbooks

A **playbook** does the first steps when a detection fires: notify a channel, run a
response action, open a case (or add to the one it opened), set the finding's status
and owner. Admins build them on the **Playbooks** page, step by step, and the page says
in one sentence what each does. Disruptive actions (block, disable, isolate) always wait
for an analyst: they show on the **Approvals** page with exactly what will happen, and run
only once someone approves, within 24 hours. A rejected, expired or failed step stops the
playbook. Each playbook runs once per finding, only on the server running the background
jobs, and everything it does is noted on the finding and the case.

See [docs/playbooks.md](docs/playbooks.md) for the steps, the approval flow, an example
and the API.

## Dashboards

The **Dashboards** tab opens on the built-in **Security posture** dashboard, like the
Splunk ES Security Posture and executive summary views. Pick a time range (last hour
to 30 days) and, if you like, auto-refresh. It shows:

- **Key indicators** compared with the previous period of the same length: open
  findings by urgency, new findings, findings closed, mean time to triage, mean time
  to resolve, and events ingested.
- **Findings over time by urgency**, **top detections firing** (findings and risk
  events), **top risk objects** and **ATT&CK tactics seen**.
- **Events by data model** and **by source type** over time.
- **Detection health**: how many detections are enabled, which ones failed on their
  last run, which enabled ones matched nothing in 30 days, and which hosts stopped
  sending (quiet for `dashboards.stale_after`).

**Custom dashboards** are panels of queries shown as a single value (optionally with
the change from the previous period), a table, bars, or a line or area chart. Build
one with **New dashboard**, then **Add panel**: ask a question in plain English and
the query is written for you, or write it, and preview before saving. On the Search
page, **Add to dashboard** turns the current search into a panel. Panels can be
edited, reordered and removed in the UI; they run in parallel and a failing panel
shows its error without breaking the others.

Each custom dashboard is a YAML file in `dashboards.dir`, so dashboards can be
reviewed and shared in Git. Files dropped into the folder show up without a restart.

```yaml
id: auth-watch
title: Authentication watch
time_range: 24h
panels:
  - title: Failed logons
    query: datamodel=Authentication action=failure | stats count
    viz: single
    compare: true
  - title: Logons over time
    query: datamodel=Authentication | timechart count by action
    viz: area
```

See [docs/dashboards.md](docs/dashboards.md) for every option and the API.

## Data retention

Admins set how long data is kept on the **Data retention** page. It lists every
category with its size on disk, the days it holds and its policy:

- each data model (Authentication, Endpoint, Network traffic, Change),
- Other events,
- Risk events,
- Findings,
- Investigations,
- Threat intel, which is managed by its feeds.

Each event category can have its own policy, or use the default policy:

- **Keep**: how many days stay searchable (0 keeps them forever).
- **Size cap**: the most disk the category may use. Its oldest days are deleted
  first.
- **Compact after**: makes old days read-only and merges them into one segment, so
  they take less space and memory.
- **Archive before deleting**: writes each day to a compressed, checksummed file
  first. You can restore it later from the page or with `signalith archive restore`.

Findings and investigations can be set to delete resolved and closed ones after a
number of days. Open ones are never deleted, and neither are findings that belong to
an investigation that is kept. Before you save, the dialog shows exactly which days
the change deletes, archives or compacts, including days already due, and asks
before deleting anything. Saving applies the change at once, with no restart.
Restoring archived days shows how full the disk will be first.

The **disk guard**, on by default, deletes the oldest event days when OpenSearch's
disk passes 85% and spares the last 7 days. This keeps OpenSearch from reaching 95%,
where it makes every index read-only and ingest stops. It deletes only when that
helps: if other files fill the disk, it keeps your history and the page says to add
space. A server upgraded while its OpenSearch disk is already above 85% trims old
days at its first run. To avoid that, set `retention.guard` in signalith.yaml first.

Retention runs every hour on the server that runs the background jobs (see
[More than one server](#more-than-one-server)); with several servers, the policies are shared and can be changed on any of them. It never deletes today's data or indices that are not
Signalith daily indices. The page keeps the last 200 actions with the reason for each.

Page settings are saved in `retention.yaml` in `lookups.dir`. Anything set under
`retention` in signalith.yaml is read-only on the page, except `retention.days`,
which is the default only until you save a default on the page:

```yaml
retention:
  days: 90
  policies:
    authentication: {keep_days: 365, compact_after_days: 14}
    endpoint: {keep_days: 30, max_size_gb: 500, archive: true}
    cases: {keep_days: 1095}
  guard: {enabled: true, max_disk_percent: 85, min_days: 7}
```

See [docs/retention.md](docs/retention.md) for more:

- how each rule works,
- the archive format and restores,
- compliance examples such as keeping 90 days searchable and a year archived,
- running more than one server,
- the API.

## Writing queries

```
datamodel=Authentication action=failure earliest=-24h
| stats count, dc(user) as users by src
| where count > 20
| sort -count
```

Ways to build one without memorizing syntax:

- **Ask in plain English.** Type a question above the query box, such as
  *top 10 users with failed logins today*, *users who logged in to more than 3 hosts*
  or *powershell spawned by winword on dc01*. Signalith writes the query, runs it, and
  lists how it read each phrase, so you can see why the query looks the way it does
  and edit it. The built-in translator works offline and knows the data models, CIM
  field names, common Windows and Linux tools, time ranges, counting, top and rare
  values, thresholds and charts, and recognizes names from your asset and identity
  lists. Words it does not understand are listed rather than guessed at.
- **Query builder.** Pick the data, add conditions, choose events, a table or a chart. The query text is written as you click, and typing in the text updates the builder when it can represent the query.
- **Fields sidebar.** Click a field for its top values; click a value to filter on it.
- **Click any result cell** to filter to it, exclude it, count by that field, or chart it over time.
- **Autocomplete** for fields, commands and functions as you type.
- **Explain** turns any query into plain-English steps and shows the OpenSearch request it runs.
- **AI model (optional).** For questions the translator only partly understands, set
  `assistant.provider` and Signalith asks the model instead, or always when you tick
  **Use AI**. Only the question and the field list are sent, never your events, and
  the model's query is checked by the parser before you see it. Point
  `assistant.url` at a local Ollama or LM Studio server to keep everything on site:

  ```yaml
  assistant:
    provider: openai
    url: http://localhost:11434/v1
    model: llama3.1
  ```
- **Starter hunts** on the empty search page cover brute force, new accounts, encoded PowerShell and more.

From the shell: `signalith query "datamodel=Authentication | top user"` or add
`-explain` to see the compiled request, and `signalith ask "failed logins from
203.0.113.9 today"` prints the query for a question. The full reference is in
[docs/query-language.md](docs/query-language.md).

## Architecture

```
Fluent Bit agents ──HTTPS──▶ signalith (Go) ──REST──▶ OpenSearch
 (Windows, Linux)            ingest, parse,          events by data model and day
syslog devices ─UDP/TCP/TLS▶ query compiler,
                             web UI and API ◀── analyst browser
```

| Path | What it holds |
| --- | --- |
| `cmd/signalith` | CLI and server entry point, Windows service |
| `internal/query` | Query language lexer, parser, canonical printer, builder model |
| `internal/search` | Compiles queries to OpenSearch DSL and runs remaining commands in memory |
| `internal/ingest` | Fluent Bit and OTLP record parsing for Windows and Linux, index template |
| `internal/syslog` | Syslog receiver (UDP, TCP, TLS), RFC 5424, RFC 3164 and CEF parsing |
| `internal/datamodel` | Authentication, Endpoint, Network_Traffic, Change, Malware, Filesystem, Registry, Network_Resolution, Image_Load, Script, Inventory, Configuration_Check, Alerts, Risk, Other |
| `internal/agents` | Fluent Bit and OpenTelemetry Collector configuration generator |
| `internal/detect` | Detection format, built-in content, scheduler, Sigma converter, ATT&CK catalog |
| `internal/findings` | Findings model and its OpenSearch store |
| `internal/assets` | Asset and identity lists: CSV parsing, matching, priority |
| `internal/risk` | Risk event store |
| `internal/intel` | Threat intel indicators, feed parsing (lines, CSV, STIX, format detection), the feed catalog, TAXII 2.1, guarded downloads and feeds managed on the page |
| `internal/retention` | Retention policies, planner, disk guard, archives and restores |
| `internal/cluster` | Servers that share one OpenSearch: identity, heartbeats and the job lease |
| `internal/dashboards` | Security posture metrics, custom dashboard files, parallel panel runner |
| `internal/nlq` | Plain-English question to query translator |
| `internal/assistant` | Optional AI model client (Anthropic, OpenAI-compatible) |
| `internal/config` | YAML config, validation, password hashing, encrypted values in `signalith.yaml`, the Settings page's registry and settings file |
| `internal/secrets` | Master key, encryption of stored passwords and keys, key rotation |
| `internal/securefile` | Whole-or-nothing writes of files with secrets, private permissions on Linux and Windows |
| `internal/httpserver` | Web server timeouts, connection limits, HTTPS and plain HTTP on one port |
| `internal/ospki` | Certificates and security settings for a secured OpenSearch (`bootstrap-docker`, `opensearch-certs`) |
| `internal/tlsauto` | Signalith's own certificate authority and HTTPS certificate: issue, renew, reload |
| `internal/safelog` | Length limits for log values, rotating log file |
| `internal/redact` | Hides secrets in URLs before they are shown or logged |
| `internal/auth` | Web UI sign-in sessions and the failed sign-in limit |
| `internal/users` | Roles, local users, Active Directory and LDAP sign-in and its tests |
| `internal/api` | REST API, the role of every route, query explanations |
| `web/static` | Browser UI (plain JavaScript, no build step) |
| `deploy/` | Docker Compose, systemd unit, Windows installer script |

## Building

See [CONTRIBUTING.md](CONTRIBUTING.md) for tests, code style and how to send changes.

Requires the Go version in `go.mod` (1.26.9) or newer.

```sh
go test ./...
go build -o signalith ./cmd/signalith                         # Linux
GOOS=windows GOARCH=amd64 go build -o signalith.exe ./cmd/signalith  # Windows
```

The end-to-end tests need an OpenSearch without security, such as the one in CI:

```sh
SIGNALITH_TEST_OPENSEARCH=http://localhost:9200 go test -tags integration ./internal/integration/
```

The `TestCluster` tests among them start several `signalith serve` processes that
share one OpenSearch, and stop them with kill -9 and SIGSTOP (Linux only). Without
`SIGNALITH_TEST_OPENSEARCH` they run against a built-in stand-in for OpenSearch.

## Roadmap

1. **Search foundation**: agents, parsing, data models, query language, builder, installers.
2. **Detect and triage**: scheduled detections in Sigma or Signalith queries, throttling, a findings queue, ATT&CK coverage.
3. **ES depth**: risk-based alerting, asset and identity context, threat intel feeds, posture dashboards, and plain-English to query.
4. **Respond and scale**: investigation cases, response actions, playbooks, multi-node deployments.

What is being built now and what comes next, from detection content and osquery endpoint
visibility to alerts, response actions and signed packages, is on the
[public roadmap](https://signalith.io/docs/roadmap/) ([source](docs/roadmap.md)).

## License

[Apache 2.0](LICENSE). See [NOTICE](NOTICE) for third-party data.

## Trademarks

Signalith is an independent open-source project. It is not affiliated with,
endorsed by or sponsored by Splunk or Cisco, and contains no Splunk software code.
Its optional Splunk Security Content pack ships detection rules from Splunk's open
source security_content project under the Apache License 2.0 (see NOTICE).
Splunk, Splunk Enterprise Security and SPL are trademarks of Splunk LLC; they are
named here only to describe what Signalith works like. OpenSearch, Fluent Bit,
Sigma and MITRE ATT&CK are trademarks of their respective owners.
