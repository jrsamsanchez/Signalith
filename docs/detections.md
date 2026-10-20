# Detections

A detection is a Signalith query that runs on a schedule. Every row the query
returns becomes a finding, unless the throttle says the same thing was already
raised recently.

Signalith ships 59 built-in detections mapped to MITRE ATT&CK: brute force, password
spray, encoded PowerShell, Office spawning shells, shadow copy deletion, credential
dumping, privileged group changes, malware and more, plus two risk incident rules. 54
are on by default. With both [content packs](#content-packs) on, rules are tagged with
181 ATT&CK techniques.

## The pages

- **Findings** is the triage queue. Filter by status, severity, owner or entity;
  assign, change status and disposition, comment, and update many at once. Each
  finding shows the result that fired, its entities, triage guidance, its full
  history, and a **View contributing events** link that opens the exact search (see
  [What a finding contains](#what-a-finding-contains)). Findings that belong to one
  incident can be grouped in a [case](cases.md).
- **Detections** lists every rule with its last run. Edit one in the form, **Test**
  it to see which findings it would raise, or **Run now**. Editing a built-in saves
  your version and keeps the original to revert to. Any search can become a
  detection with **Save as detection** on the Search page.
- **Import Sigma rule** converts a [Sigma](https://github.com/SigmaHQ/sigma) rule to
  a Signalith query and lists anything it had to approximate (see
  [Sigma rules](#sigma-rules)).
- **ATT&CK coverage** shows the Enterprise matrix with the techniques covered by
  enabled detections, those covered only by disabled ones, and the gaps.

## Where detections live

- **Built-in detections** ship inside the binary (`internal/detect/builtin`).
- **Content pack detections** ship inside the binary too, off until you turn them
  on (see [Content packs](#content-packs)).
- **Custom and edited detections** are YAML files in `detections.dir`
  (default: a `detections` folder next to the config file; `/var/lib/signalith/detections`
  for the systemd unit and Docker image). One file per detection, named `<id>.yaml`.
- A file whose `id` matches a built-in or pack detection **overrides** it. Delete
  the file, or click **Revert to built-in**, to go back.
- Turning a built-in or pack detection on or off, or giving it
  [exceptions](#exceptions), without other changes only writes a small file to
  `detections/state/<id>.yaml`, so the rule itself keeps coming from the binary and
  gets fixes on upgrade.

You can edit detections in the UI or drop YAML files into the folder and restart.
`signalith validate` checks every file and reports problems with the field to fix;
a broken file is skipped at startup and logged, so it never stops the server.

### On several servers

The servers of a cluster share their detections: custom ones, overrides, and the choices
made for built-in and pack ones. Each server's detections folder is then an inbox: a
file added or changed there is shared, and a change made on any server is written back
into every server's folder. Removing a file changes nothing unless
`detections.sync` is `mirror`. See
[Shared detections, dashboards and asset lists](servers.md#shared-detections-dashboards-and-asset-lists).

Saving a detection sends the version the page read (`If-Match` with the `etag` from
`GET /api/detections/{id}`); if someone else saved it meanwhile, the save is refused
with `412`, naming who changed it, on which server and when.

## Format

```yaml
id: auth-brute-force                    # 3-64 lowercase letters, digits, - or _
title: Brute force against $dest$ from $src$   # $field$ is filled from the result row
name: Brute force     # optional: the name without $field$ tokens, for counts across hosts
description: One source failed to log on to a system many times.
query: |
  datamodel=Authentication action=failure
  | stats count, dc(user) as users by src, dest
  | where count >= 10
schedule: 5m          # how often it runs: s, m, h, d or w
lookback: 15m         # how far back each run searches
severity: medium      # informational, low, medium, high, critical
mitre: [T1110]        # ATT&CK technique or sub-technique IDs
throttle:
  fields: [src, dest] # one finding per distinct src and dest...
  window: 1h          # ...per hour
risk:                 # optional; see "Risk" below
  score: 30
  objects:
    - {field: src, type: system}
enabled: true
tags: [authentication]
guidance: Check whether the source is internal and whether any attempt succeeded.
```

Rules of thumb:

- Do not put `earliest=` or `latest=` in the query; `lookback` sets the window.
- Make `lookback` at least as long as `schedule`, or events between runs are missed.
  A little overlap is fine; throttling keeps overlapping runs from raising duplicates.
- Without `throttle.fields`, the whole result row is the throttle key.
- Views that count a detection across many findings, such as **Top detections firing**
  on the posture dashboard, show `name`. Without one, they show `title` with each
  `$field$` and the word that leads to it left out ("Brute force against $dest$ from
  $src$" reads "Brute force"). Set `name` when that reads badly, as for a title that
  starts with a `$field$`.
- Use `stats ... by` to raise one finding per entity instead of one per event.
- Up to four detections run at once. A run is stopped when it takes longer than its
  schedule (at least 1 minute, at most 5); the Detections page then shows **Timed out**.
  Narrow the query or shorten `lookback` so it finishes in time.

## Schedules and missed runs

- **Fixed times.** Each detection runs at fixed times: every `schedule`, at a moment
  Signalith picks for that rule, so that rules with the same schedule do not all
  start together. Every server works these times out the same way, from
  OpenSearch's clock.
- **What a run searches.** Each run searches the `lookback` that ends at its scheduled
  time, even when it starts a little late.
- **Missed runs are made up.** When runs are missed, because every worker was busy or
  no server was running detections, they are run later, oldest first, so nothing in
  between goes unsearched. They are made up as far back as `detections.catch_up`
  (default `6h`, at most `7d`; `0` turns this off and runs only the latest time).
  Older missed runs are skipped: the Detections page marks the detection
  **Skipped**, and its details and the posture dashboard say for which times, for
  example "Signalith was not running detections from 02:10 to 09:40; 90 runs of this
  detection were skipped." Search that time by hand if it matters. Set
  `detections.catch_up` on the Settings page, or see the
  [configuration table](configuration.md#all-settings).
- **Failed runs.** A run that failed because OpenSearch did not answer, or was too
  busy, is tried again: the detection waits until it works. A run whose query has an
  error is not tried again; fix the query and the next run uses it. A run that times
  out is tried up to three times, then the next one goes on.
- **New, turned on again, or rescheduled.** A new detection, one turned back on, and
  one whose `schedule` changed start at their next scheduled time; they do not make up
  the time before it. Changing only the query or `lookback` keeps the place in the
  schedule.
- **After upgrading.** The first time this version starts, each detection that is on
  runs once straight away, over the `lookback` up to its latest scheduled time, as
  every start did before. From then on it keeps to its schedule.
- **Times on findings.** A finding's **Detected** time is the scheduled time of the run
  that raised it, so a run made up later still sorts where it belongs. A finding raised
  more than a few minutes after that time also says how much later it was raised (hold
  the pointer over it for the exact time).
- **No duplicates.** A run that is repeated, for example after a restart or when
  another server takes the detections over, finds what it raised before and does not
  raise it again. Throttling also holds across servers and restarts.
- **Run now** searches the `lookback` up to this moment, on the server you are using,
  whichever server runs the schedule. It respects throttling and its findings throttle
  the scheduled runs in turn, but it does not change the schedule. The detection's
  details show it as **Last run now**, with who ran it and where.
- The Detections page shows late runs and skipped runs under **Behind schedule**, and
  the Health page warns while a detection waits longer than its schedule, and for a day
  after runs were skipped.

## Risk

A `risk` section makes the detection add risk to the users and systems in each
result row:

| Key | Meaning |
| --- | --- |
| `score` | Base risk, 1 to 1000. Multiplied by the object's priority from the asset and identity lists (critical ×2, high ×1.5, medium ×1, low ×0.5; a watchlisted user at least ×1.5) |
| `objects` | Result fields that hold a risk object, each with `type` `user`, `system` or `other`. Empty or missing values are skipped |
| `only` | `true` records risk without raising a finding. Throttling still applies, per risk object row |
| `weight_field` | A result column with a number from 0 to 10 that multiplies `score`, such as `threat_weight` from `threatmatch` |

Each object gets one risk event in the Risk data model with `risk_object`,
`risk_object_type`, `risk_score`, `risk_base_score`, `risk_priority`,
`risk_message` (the rendered title), `detection_id`, `mitre` and `mitre_tactic`,
plus the row's entity fields. Search them with `datamodel=Risk`.

Fourteen built-in detections are risk-only. Two **risk incident** detections (tagged
`risk-incident`) read the Risk data model and raise findings:

- `risk-threshold-exceeded`: total risk of 100 or more for one object in 24 hours.
- `risk-multiple-tactics`: three or more ATT&CK tactics from three or more
  detections on one object in 7 days.

The **threat intel match** detection (`threat-activity`, tagged `threat-intel`)
runs `* | threatmatch` every 5 minutes over the last 10, raises one finding per
indicator and target system per day, and adds 60 risk times the indicator's weight
to `threat_target` and `user`. See [threat-intel.md](threat-intel.md).

[Behavior baselines](baselines.md) add risk the same way for first-seen and rare
activity, such as a sign-in from a new country.

Write your own the same way, for example
`datamodel=Risk risk_object_type=user | stats sum(risk_score) as risk_score by risk_object | where risk_score >= 200`.

The **Risk** page lists the users and systems with the most risk. Open one to see
what added its risk: each entry opens the detection that added it, with a link to
the finding raised with it (or, for a risk-only detection, to the risk event in
Search). Click an ATT&CK tactic to show only the entries for that tactic. Each user
or system in the list has a bar for its score, the number of detections and tactics,
and its asset or identity context.

Risk events are stored under the Risk data model (`datamodel=Risk`) in
`<prefix>-risk-YYYY.MM.DD` indices, which ordinary searches leave out.

## Assets and identities

The **Assets & identities** page takes two CSV files, one for assets and one for
identities. Upload them on that page, or put them in `lookups.dir` as `assets.csv` and
`identities.csv`; they reload within a minute. Every bad line is reported, and nothing
is saved until the file is clean. Download the current file from the same page to
edit it.

```csv
host,ip,cidr,owner,priority,category,bunit,location
web1|web1.corp.local,10.0.1.10,,web team,critical,web|pci,ecommerce,dc1
,,10.20.0.0/16,it,low,workstation,,office
```

```csv
identity,name,email,manager,priority,category,bunit,watchlist
alice|CORP\alice|alice@corp.local,Alice Ng,alice@corp.local,bob,high,admin,it,true
```

Use `|` between several values in one cell. Hosts match by short name or FQDN, IPs
exactly or by the most specific CIDR, and users with or without `DOMAIN\` or
`@domain`. Priority is `low`, `medium`, `high` or `critical`.

This context changes three things:

- **Risk scores** are multiplied by the object's priority: critical ×2, high ×1.5,
  medium ×1, low ×0.5. A watchlisted user counts at least ×1.5.
- **Urgency** on each finding starts at its severity. It goes up one level when a
  critical asset or watchlisted user is involved, and down one level when every
  known entity is low priority. The Findings queue shows and filters by urgency.
- **`| enrich`** in any search adds `<field>_priority`, `_owner`, `_category` and more
  next to each user, host and IP field (see [enrich](query-language.md#commands)).

## Exceptions

An exception tunes a detection without editing its query, so that
results that match it raise no finding and add no risk,
and every other result still alerts. Use one for a vulnerability scanner that trips
a brute force rule, an admin script that looks like an attack, or a maintenance
window.

- **From a finding**: admins open the finding, choose **More actions** (⋯) >
  **Don't alert on this again**, tick the values to match (the finding's host, user
  and so on), pick how long (24 hours, 7 days, 30 days or until removed), and add a
  comment. The finding can be closed in the same step, as a false positive by
  default, and its activity records what was suppressed.
- **On the detection**: the **Exceptions** section of a detection lists each
  exception with who added it, when and why, and how long it lasts. Admins remove
  one with its bin icon, or add one by hand with **Add**: one `field=value` per line,
  where `*` and `?` are wildcards and case is ignored. Leave the values empty, with a
  start time and how long, to silence every result for a maintenance window.

Each run counts the results exceptions matched; **Last run** on the Detections page
shows them. An exception that has ended stays listed, greyed out, until it is
removed. A detection can have up to 500 exceptions, each matching up to 8 fields.

In YAML (a custom detection keeps them in its own file; a built-in or pack detection
in `detections/state/<id>.yaml`):

```yaml
exceptions:
  - id: ex-3f9a1c2b7d10
    match: {src: 203.0.113.9}           # every field must match; * and ? are wildcards
    until: 2026-11-01T00:00:00Z          # optional: without it, until removed
    comment: Quarterly vulnerability scan
    by: admin
    added: 2026-10-13T21:00:00Z
  - id: ex-maintenance
    from: 2026-10-18T02:00:00Z           # no match: every result, so until is required
    until: 2026-10-18T06:00:00Z
    comment: Patch window
```

Exceptions are checked against the fields of each result row, so match on fields the
query returns: after `stats ... by src, dest`, only `src`, `dest` and the
aggregates exist.

## Antivirus detections

Ten built-in detections read the Malware data model (see
[antivirus.md](antivirus.md#detections) for what each means and what to do). All
are on by default and raise findings:

| ID | Severity | Fires when |
| --- | --- | --- |
| `malware-not-removed` | high | A threat was allowed, failed to clean or was restored from quarantine |
| `malware-left-clamav` | high | ClamAV found malware and only reported it, so the file is still there |
| `malware-detected` | low | A named threat was found (ransomware has its own finding) |
| `malware-outbreak` | high | The same threat was found on three or more hosts in a day (not test files, adware or unwanted apps) |
| `malware-ransomware` | critical | A threat in the ransomware category was found |
| `av-protection-disabled` | high | Protection or tamper protection was turned off |
| `av-tamper-blocked` | medium | Tamper protection blocked a change to the antivirus |
| `av-exclusion-added` | medium | An antivirus exclusion was added |
| `av-definitions-failing` | low | Definitions failed to update twice in a day, or are a week old |
| `av-rule-block` | medium | An attack surface reduction or controlled folder access rule blocked something unusual |

## Vulnerability detections

Five built-in detections read the Vulnerabilities data model, which Signalith's
own network scans fill (see the **Vulnerabilities** page). All are on by default,
raise findings and add risk to the scanned host. Each raises one finding per host
and CVE (or per host, for Telnet) a week: a nightly scan that finds the same
vulnerability again raises it again only after seven days.

| ID | Severity | Fires when |
| --- | --- | --- |
| `vuln-known-exploited` | high | A scan found a vulnerability in CISA's Known Exploited Vulnerabilities catalog (`known_exploited=true`): attackers are using it |
| `vuln-known-exploited-priority-asset` | critical | The same, on an asset whose priority in the asset list is critical or high |
| `vuln-likely-exploited` | medium | A scan found a vulnerability not yet known exploited with an EPSS score of 10% or more (`epss>=0.1`) |
| `vuln-critical` | medium | A scan found a critical vulnerability (CVSS 9 or higher) that is not known to be exploited yet |
| `vuln-cleartext-remote-login` | low | A scan found Telnet open, which sends passwords in clear text |

To see everything a scan found on a host, search
`datamodel=Vulnerabilities dest=<host>`.

## Network detections

Network data from a [network sensor](network-sensor.md) (Zeek, Suricata) lights up
these built-in detections. Those marked *risk only* add risk to the host and raise no
finding by themselves: they are signals that are
common on their own and matter when they add up (see [Risk](#risk)).

| ID | Severity | Fires when | Default |
| --- | --- | --- | --- |
| `ids-alert-high` | high | A network IDS such as Suricata raised a high or critical alert (Zeek notices are medium, so they do not count). One finding per signature, source and destination an hour, with risk on both hosts | on |
| `threat-activity` | high | An address, domain, URL or file hash the sensor saw is in your threat intel | on |
| `network-dns-tunneling` | medium | One host looked up 10 or more different names with a label of 40 characters or more in 30 minutes (DNS tunnelling, DNS command and control); your DNS servers are left out (see below) | on |
| `network-dns-nxdomain-burst` | medium | One host asked for 25 or more different names that do not exist in 15 minutes (a domain generation algorithm); your DNS servers are left out (see below) | on |
| `network-internal-scan` | medium | An internal host's TCP connections to 20 or more internal hosts, or 50 or more ports, failed in 15 minutes (connections the sensor saw only one side of do not count) | on |
| `network-zeek-scan-notice` | medium | Zeek's scan detection reported one of your own hosts in an address, port or random scan (`Scan::*` notices); scans from the internet are left out | on |
| `network-http-executable-download` | medium | A host that is not on the internet side downloaded a program or script over plain HTTP, whole or in ranges (status 200 or 206), from outside (Windows Update's and Google's updater addresses are left out) | on |
| `network-cleartext-credentials` | low | A password crossed the network in clear text: HTTP basic authentication, an FTP sign-in (not anonymous) or an answered Telnet connection that did not come from the internet | on |
| `network-sensor-packet-loss` | low | Zeek missed more than 5% of the traffic, or Suricata dropped more than 5% of packets (counted once it has received a million) | on |
| `network-sensor-unhealthy` | medium | A network sensor reported Zeek or Suricata stopped, its capture port down or idle, rules or rule tuning failing or old, or a full disk, or Signalith found it silent. One finding per sensor and problem a day; fix it from **Settings > Network sensors** | on |
| `network-beaconing` | low | Twelve or more short (a minute or less), small (5 KB or less out) connections from one host to one outside address and port in two hours | off, risk only |
| `network-tls-untrusted-cert` | low | A TLS session from a host not on the internet side to an outside server with a self-signed or expired certificate | on, risk only |
| `network-large-outbound-transfer` | medium | One host sent more than 1 GB to one outside address, in connections that started within six hours | on, risk only |
| `network-sensor-shell-port` | medium | The sensor saw an answered connection from your network to the internet on a reverse shell port (4444, 1337, 31337, ...); the network side of `network-shell-port` | on, risk only |
| `network-new-inbound-service` | medium | A host inside answered connections from the internet on a port it had not answered on in 30 days | off |

Choices worth knowing:

- **Beaconing** is approximated: the search language has no standard deviation, so
  regular timing is not measured. Many separate small, short connections to one address
  in two hours is the signal; update checks, telemetry, chat clients, CDNs and
  certificate status checks look the same, and an ordinary workstation talks to several
  of them all day. So it is off by default: run its search over a day, add exceptions on
  `dest` for the destinations many of your hosts talk to, then turn it on (risk only,
  10 points per destination).
- **DNS servers are left out** of the two DNS detections. With the sensor on the
  internet link, it sees your DNS servers (in an Active Directory network, the domain
  controllers) ask upstream on behalf of every client, so their lookups add up the
  whole organisation's mistyped names and browser probes, and hide which client asked.
  A source whose asset category contains `dns` or `domain-controller` in your
  asset list (**Assets & identities**) is not counted (the rules run `enrich src` and check
  `src_category`), so give your resolvers one of those categories. To see which client
  is behind a resolver's lookups, mirror the traffic between clients and the resolver
  too, or collect the resolver's own query log.
- **Large outbound transfers** are counted by when each connection started: Zeek writes
  a connection only when it ends, stamped with its start time, so the rule looks back
  six hours to catch a long upload. A single upload of more than about five and a half
  hours is missed.
- **New inbound service** uses its 30-day throttle as its memory of what was seen. The
  first runs after you turn it on list every service already reachable from the
  internet, which is why it is off by default; turn it on when you want that inventory.
- **Direction** comes from the sensor (`direction=outbound` means from your network to
  the internet; see [Data models](network-sensor.md#data-models)). Zeek says which ends
  are local only in `conn.log`; for web requests, TLS sessions and DNS lookups the
  direction comes from the addresses (private ranges count as local), so a client with
  a public IPv6 or IPv4 address is `external`. The web and TLS detections therefore
  count every direction except `inbound` and `internal`. If your internal addresses are
  public addresses, tell Zeek about them in `Site::local_nets`, or the connection
  detections see your traffic as `external`.
- **Expired certificates** are known only from Zeek's `ssl/validate-certs` script (on by
  default). In TLS 1.3 the certificate is encrypted, so a sensor sees it only in TLS 1.2
  and older sessions.

Every network detection is tagged with the compliance controls it is evidence for:
`pci-dss:10.4.1` (security events reviewed), `pci-dss:11.5.1` (intrusions detected and
alerted, PCI DSS 3.2.1's 11.4), `nist-800-53:SI-4` (system monitoring) and
`cis-v8:13.3` (network intrusion detection); the packet loss and sensor health detections have
`pci-dss:10.7.2` (failures of security controls) and `cis-v8:13.6` instead of 13.3.

`network-shell-port` and `network-remote-admin-port` are about the process that made
a connection, which only host data (Sysmon) has, so they leave sensor data alone;
`network-sensor-shell-port` covers the sensor's side. If one IDS rule is noisy on your
network, add an exception on its `signature_id`.

## Industrial detections

Industrial protocol traffic seen by a [network sensor](network-sensor.md#industrial-protocols)
(the **Industrial** data model) lights up these built-in detections. They are mapped to
[MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/), so their techniques
(T0xxx) appear on **Detections > Coverage** under **ICS**, a second matrix shown once any
detection uses one. They stay quiet on a network with no industrial devices.

| ID | Severity | Fires when | Default |
| --- | --- | --- | --- |
| `ot-controller-stop-start` | high | A host told a controller to stop, start, restart, reset or stop talking (S7 PLC stop, DNP3 cold or warm restart, CIP stop or reset, BACnet device control, ...) | on |
| `ot-program-transfer` | medium | A program or logic was downloaded to, or uploaded from, a controller | on |
| `ot-command-from-outside` | high | An address outside your network sent a write, control or program command to an industrial device | on |
| `ot-modbus-listen-only` | high | A Modbus device was forced into listen-only mode (needs CISA's ICSNPP Modbus analyzer) | on |
| `ot-device-discovery` | medium | One host sent identification or discovery requests to 10 or more industrial devices in 15 minutes | on |
| `ot-exception-burst` | low | Industrial devices answered 25 or more requests from one host with an error in 15 minutes | on |
| `ot-new-command-source` | medium | A host sent write, control or program commands to a device it had not commanded in 30 days | off |

Engineering workstations stop controllers and transfer programs during maintenance, and
asset inventory tools ask devices who they are: add an exception on `src` for the hosts
that do this routinely. Like `network-new-inbound-service`, `ot-new-command-source` uses
its 30-day throttle as its memory, so its first runs list every host that commands each
device today; turn it on when you want that inventory.

## What a finding contains

The result row, the entities found in it (`user`, `src_user`, `src`, `src_host`,
`dest`, `dest_host`, `host`, `process_name`, `object`, `member`), the detection's
severity and ATT&CK techniques, a drilldown search, the asset and identity context
of each entity, and an **urgency** that combines severity with that context. For `stats` and `top`
detections the drilldown is the detection's filter plus the row's group-by values,
so **View contributing events** shows exactly the events behind that row.

Findings move through `new`, `in_progress`, `pending`, `resolved` and `closed`, with
an owner, a disposition (`true_positive`, `benign_true_positive`, `false_positive`,
`undetermined`), comments, and a history of every change. They are stored in the
OpenSearch index `<index_prefix>_findings`, which event searches never include.

## Content packs

Content packs are rule sets from other open source projects, shipped unchanged
inside Signalith and converted when it starts. Every pack detection is **off** until
an admin turns it on.

**SigmaHQ community rules** (`internal/detect/packs/sigmahq`) holds 2,638 rules from
[SigmaHQ](https://github.com/SigmaHQ/sigma), pinned to one commit: 2,138 Windows rules
for these Sysmon, Security, PowerShell, System, Application, Code Integrity, Windows Firewall, BITS, AppX deployment, WMI activity, Remote Desktop session, shell, SMB client, exploit protection, DNS client, Task Scheduler, NTLM, LSA, CryptoAPI, device driver, packaged app, certificate, OpenSSH, DNS Server, IIS configuration and Defender log sources, 154 Linux rules (see
[Linux endpoints](#linux-endpoints-sysmon-for-linux) and
[the Linux audit log](#linux-audit-log-auditd)), 56 macOS rules (see
[macOS program starts](#macos-program-starts-osquery)), 13 web server rules (see
[Web server access logs](#web-server-access-logs)), 45 network rules (see
[Network rules](#network-rules-zeek-dns-proxy-and-firewall)), 38 AWS CloudTrail rules (see
[AWS CloudTrail](#aws-cloudtrail)), 108 Microsoft Entra ID and Azure rules (see
[Entra ID and Azure](#entra-id-and-azure)), 17 Microsoft 365 rules (see
[Microsoft 365](#microsoft-365)), 16 Google Cloud rules and 7 Google Workspace rules (see
[Google Cloud](#google-cloud)), 19 Okta rules (see [Okta](#okta)), 15 Kubernetes rules (see
[Kubernetes](#kubernetes)), and 12 GitHub rules (see [GitHub](#github)):

| Sigma log source | Windows events | Data model |
| --- | --- | --- |
| `process_creation` | Sysmon 1, Security 4688; on Linux, Sysmon for Linux 1 or a program start auditd recorded; on macOS, a program start osquery reported | Endpoint |
| `network_connection` | Sysmon 3 | Network_Traffic |
| `process_access`, `create_remote_thread` | Sysmon 10, 8 | Endpoint |
| `image_load`, `driver_load` | Sysmon 7, 6 | Image_Load |
| `file_event`, `file_delete` | Sysmon 11; 23 and 26 | Filesystem |
| `registry_add`, `registry_delete`, `registry_set`, `registry_event` | Sysmon 12; 12; 13; 12, 13 and 14 | Registry |
| `dns_query` | Sysmon 22 | Network_Resolution |
| `pipe_created` | Sysmon 17 and 18 (named pipe created or connected to) | Endpoint |
| `create_stream_hash` | Sysmon 15 (alternate data stream written, such as a download's `Zone.Identifier`) | Filesystem |
| `raw_access_thread` | Sysmon 9 (a drive read directly; `Device` is `device`) | Endpoint |
| `ps_script` | PowerShell 4104 | Script |
| `ps_module` | PowerShell 4103 (see [PowerShell module logging](#powershell-module-logging-and-the-windows-powershell-log)) | Script |
| `ps_classic_start`, `ps_classic_provider_start`, `service: powershell-classic` | Windows PowerShell log 400; 600; any event | Other |
| `webserver` | Apache and Nginx access log lines (see [Web server access logs](#web-server-access-logs)) | Web |
| `product: aws`, `service: cloudtrail` | AWS CloudTrail records (see [AWS CloudTrail](#aws-cloudtrail)) | Authentication, Change or Other |
| `product: azure`, `service: signinlogs` | Entra ID sign-ins (see [Entra ID and Azure](#entra-id-and-azure)) | Authentication |
| `product: azure`, `service: auditlogs` | Entra ID audit records | Change |
| `product: azure`, `service: riskdetection`, `pim` | Entra ID Protection risk detections | Alerts |
| `product: azure`, `service: activitylogs` | Azure activity log records | Change |
| `product: m365`, any service | Microsoft 365 audit records (see [Microsoft 365](#microsoft-365)) | Authentication, Change, Alerts or Other |
| `product: gcp`, `service: gcp.audit` | Google Cloud audit log entries (see [Google Cloud](#google-cloud)) | Change, Authentication or Other |
| `product: gcp`, `service: google_workspace.admin`, `google_workspace.login` | Google Workspace audit log entries, shared with Google Cloud | Change or Authentication |
| `product: okta`, `service: okta` | Okta System Log events (see [Okta](#okta)) | Authentication, Change, Alerts or Other |
| `product: kubernetes`, `service: audit` | Kubernetes audit events (see [Kubernetes](#kubernetes)) | Change, Authentication or Other |
| `product: github`, `service: audit` | GitHub audit log events (see [GitHub](#github)) | Change, Authentication or Other |
| `service: system` | System 7045 (service installed) | Change |
| `service: system` | Other System events, by provider and event ID (see below) | Other |
| `service: application` | Application events, by provider and event ID (see below) | Other |
| `service: codeintegrity-operational` | Code Integrity events (unsigned, revoked and blocked drivers and images), by event ID | Other |
| `service: firewall-as` | Windows Firewall events (rules added and deleted, settings changed, reset), by event ID and data (see below) | Other |
| `service: bits-client` | BITS events (jobs created, transfers started), by event ID and data (see below) | Other |
| `service: appxdeployment-server` | App package (MSIX, AppX) events (deployed, downloaded, blocked), by event ID and data (see below) | Other |
| `service: wmi` | WMI activity events (operations failed, event subscriptions registered), by event ID and data (see below) | Other |
| `service: sysmon` | Sysmon's own events: files blocked (27, 28) and executables detected (29) in Filesystem with `action` blocked or created, a configuration change (16) in Other | Filesystem, Other |
| `service: terminalservices-localsessionmanager` | Remote Desktop session events (logon, logoff, disconnect, reconnect), by event ID and data (see below) | Other |
| `service: shell-core` | Shell events (app shortcuts added to the app resolver cache), by event ID and data (see below) | Other |
| `service: smbclient-security` | SMB client security events (insecure guest logons refused), by event ID and data (see below) | Other |
| `service: security-mitigations` | Exploit protection blocks in kernel mode (images not signed by Microsoft), by event ID and data (see below) | Other |
| `service: dns-client` | DNS client queries (3008), by event ID and data (see below) | Other |
| `service: taskscheduler` | Task Scheduler events (a task started a process, a task deleted or disabled), by event ID and data (see below) | Other |
| `service: ntlm` | NTLM authentications audited (outgoing, incoming, to a domain controller), by event ID and data (see below) | Other |
| `service: lsa-server` | The groups of a user logging on (LSA 300), by event ID and data (see below) | Other |
| `service: capi2` | CryptoAPI events (a certificate's private key acquired), by event ID | Other |
| `service: driver-framework` | Devices plugged in (user-mode drivers loaded, Plug and Play operations), by event ID | Other |
| `service: appmodel-runtime` | Packaged app processes created, by event ID and data (see below) | Other |
| `service: appxpackaging-om` | App package signing certificates read, by event ID and data (see below) | Other |
| `service: certificateservicesclient-lifecycle-system` | Computer certificates exported, by event ID | Other |
| `service: openssh` | OpenSSH server messages, by event ID and data (see below) | Other |
| `service: dns-server` | DNS Server plug-in DLLs loaded and zone transfers refused, by event ID | Other |
| `service: iis-configuration` | IIS configuration changes, by event ID and data (see below) | Other |
| `service: windefend` | Microsoft Defender Antivirus events (threats, attack surface reduction blocks, protection turned off, settings changed; `Path` is `file_path`, `ProcessName` `process_path`, `NewValue` `new_value`, `SourceName` `detection_source`, a 5013's `Value` `setting`) | Malware |
| `service: security` | The Security log events in the next table | See the next table |

A Security log rule names its event's own fields (`TargetUserName`, `LogonType`,
`ServiceFileName`, `ObjectName`), so each one converts for the one Security event it
is about, or for events that carry the same data: a handle request and the access made
with it (4656 and 4663), or a scheduled task deleted or disabled (4699 and 4701). Rules
about other Security events, or other sets of events, are left out. Event IDs of Windows
2000 and XP (below 1000, such as 517 for the log cleared) that a rule names beside
current ones are ignored, since those systems' events never reach Signalith. Windows
logs each event only with its audit policy setting on:

| Security events | Data model | Audit policy setting |
| --- | --- | --- |
| 4624, 4625 (logon, failed logon), 4648 (logon with explicit credentials) | Authentication | Audit Logon |
| 4768, 4769 (Kerberos tickets, on domain controllers) | Authentication | Audit Kerberos Authentication Service, Audit Kerberos Service Ticket Operations |
| 4697 (service installed) | Change | Audit Security System Extension |
| 4698, 4699, 4701, 4702 (scheduled task created, deleted, disabled, updated) | Change | Audit Other Object Access Events |
| 4720, 4738 (user account created or changed), 4732 (member added to a local group), 4728, 4729 (member added to or removed from a global group), 4730 (global group deleted), 4727, 4731, 4744, 4749, 4754, 4759 (group created), 4756 (member added to a universal group) | Change | Audit User Account Management, Audit Security Group Management |
| 4783, 4790 (basic application and LDAP query group created) | Change | Audit Application Group Management |
| 1102 (Security log cleared) | Change | Always logged |
| 4719 (audit policy changed) | Change | Audit Audit Policy Change |
| 4706 (domain trust created), 4794 (DSRM password set) | Change | Audit Authentication Policy Change, Audit User Account Management |
| 4656 (handle requested), 4663 (object access) | Filesystem for a file, Registry for a key | Audit Handle Manipulation, Audit File System or Audit Registry |
| 4661 (handle to a SAM or directory object) | none (searched in every model) | Audit SAM |
| 4657 (registry value modified) | Registry | Audit Registry |
| 5145 (network share access) | Filesystem | Audit Detailed File Share |
| 5140 (network share accessed, once per session) | Filesystem | Audit File Share |
| 5136 (directory object changed), 4662 (operation on a directory object) | Change | Audit Directory Service Changes, Audit Directory Service Access (domain controllers) |
| 5156, 5157 (connection allowed or blocked) | Network_Traffic | Audit Filtering Platform Connection |
| 4611 (logon process registered), 4616 (time changed), 4649 (Kerberos replay), 4673, 4674 (privileged service called, privileged object operation), 4692 (DPAPI master key backup), 4704 (user right assigned), 4765, 4766 (SID History added or refused), 4825 (Remote Desktop denied), 4898, 4899 (certificate template loaded or changed), 5379 (Credential Manager credentials read), 5441, 5447, 5449 (filtering platform filters and provider contexts), 6416, 6423 (device recognized or blocked) | Other, by name: each value is `security_` and its name in snake case (`FilterName` is `security_filter_name`), and the account that acted is `user` | Audit Security System Extension, Audit System Integrity, Audit Sensitive Privilege Use, Audit Other Policy Change Events, Audit Authorization Policy Change, Audit User Account Management, Audit Other Logon/Logoff Events, Audit Certification Services, Audit Filtering Platform Policy Change, Audit PNP Activity |

Handle requests, object accesses and registry value changes are logged only for
objects whose auditing (SACL) asks for them. Directory object
types and properties are kept as Windows records them (`%{19195a5b-...}`), so a rule
that compares one to a bare GUID matches only events that already carry the name. An access list
(`AccessList`) is searched by its codes (`%%4417`) and by their names (`WriteData`),
since rules use both.

Each pack rule only searches its own log source's event IDs, since several kinds of
event share a data model (a process creation and a process access are both Endpoint).
Sysmon only records the events its configuration asks for, so a rule fires only when
your Sysmon configuration logs that kind of event.

### Linux endpoints (Sysmon for Linux)

[Sysmon for Linux](https://github.com/Sysinternals/SysmonForLinux) (open source, MIT)
records process creations, network connections and file creation and deletion with
the same event IDs and fields as Sysmon on Windows, and writes them to syslog. Signalith
reads them into the same data models, with sourcetype `sysmon:linux`:

| Sigma log source (Linux) | Sysmon for Linux events | Data model |
| --- | --- | --- |
| `process_creation` | 1 | Endpoint |
| `network_connection` | 3 | Network_Traffic |
| `file_event` | 11 | Filesystem |

The SigmaHQ pack's Linux rules and the Splunk pack's Linux rules read these events.
Sigma Linux rules search every Linux event of their data model; Splunk's search only
Sysmon for Linux events. To collect them, install Sysmon for Linux with a
configuration, then on **Add data** choose Linux, turn on **Include Sysmon for Linux**
and use the new agent configuration: the agent reads Sysmon's events from the
systemd journal.

### Linux audit log (auditd)

The Linux audit system (auditd, open source) records what its audit rules ask for:
programs run, files opened, services stopped, accounts added. The Linux agent reads
its log, `/var/log/audit/audit.log`, and the syslog receiver reads audit records
forwarded by auditd's syslog plugin. Each record is one event in the Other data model,
with sourcetype `linux:audit`. Every field is kept by auditd's own name with
`auditd_` in front (`exe` is `auditd_exe`, `a0` is `auditd_a0`, the record type is
`auditd_type`). The names an ENRICHED record gives numbers, which rules write in
capitals (`UID`, `SYSCALL`), get `_name` at the end (`auditd_uid_name`,
`auditd_syscall_name`). Text auditd writes in hex, such as a command line, is
decoded. A program's arguments are also joined as `auditd_execve_command`, and the
program, its process ID and the logged-in user are in the usual `process`,
`process_path`, `process_name`, `process_id` and `user` fields. Records that
`ausearch -i` printed are read too.

auditd writes each program start as several records with one serial number
(`auditd_id`): SYSCALL (the program, its process and parent process IDs, and its
user), EXECVE (its arguments), CWD (its working folder) and PROCTITLE. Signalith
also joins them into one process launch in the Endpoint data model, as Splunk's
add-on for Linux does, so `datamodel=Endpoint` and the process rules see Linux hosts
that run auditd without Sysmon for Linux:

| Field | From |
| --- | --- |
| `process` | the arguments, joined (the command line) |
| `process_path`, `process_name` | SYSCALL's `exe`, and its file name |
| `process_id`, `parent_process_id` | SYSCALL's `pid` and `ppid` |
| `user` | the account the program runs as (`uid`, by name when the record has it) |
| `logon_id` | the login session's user ID (`auid`), as Sysmon for Linux gives it |
| `process_current_directory` | CWD's `cwd` |
| `parent_process`, `parent_process_path`, `parent_process_name`, `parent_user` | the parent's own start, when the same server recorded it |
| `action` | `allowed`, or `blocked` when the call failed |

The launch has sourcetype `linux:audit` and `signature_id` `EXECVE`; the records
stay in Other as well, for the auditd rules. The 103 SigmaHQ Linux process rules
(`product: linux`, `category: process_creation`) and Splunk's Linux process rules
fire on these launches as they do on Sysmon for Linux events: CI checks each of
their test events both ways.

40 SigmaHQ rules (`service: auditd`) and 52 Splunk rules (the `linux_auditd` macro)
read these records, for example capabilities discovery, clipboard and screen capture,
hidden files run, kernel modules loaded, firewalls turned off, `LD_PRELOAD` and
`/etc/ld.so.preload` changes, SUID binaries made, and audit or Sysmon stopped. Each
Splunk rule also fires on Splunk's own recording of its attack.

Most of these rules need auditd to record each program run, which it does not do by
default. Install auditd and add a rule such as:

```sh
sudo auditctl -a always,exit -F arch=b64 -S execve -k exec
echo '-a always,exit -F arch=b64 -S execve -k exec' | sudo tee /etc/audit/rules.d/signalith.rules
```

The OpenTelemetry Collector runs as its own user and cannot read the audit log, so
collect it with the Fluent Bit agent, or forward it with auditd's syslog plugin.

### macOS program starts (osquery)

On a Mac enrolled with Signalith's [osquery management](endpoints.md), osquery reads
every program start from Apple's EndpointSecurity framework (`es_process_events`) and
sends it within about a minute. Each one is an Endpoint event with sourcetype
`osquery:process_start`:

| Field | From osquery | Sigma field |
| --- | --- | --- |
| `process_path`, `process_name` | the program (`path`) | `Image` |
| `process` | its arguments (`cmdline`), the first of which is the program | `CommandLine` |
| `parent_process_path`, `parent_process_name`, `parent_process` | the parent's program and arguments, from the running processes | `ParentImage`, `ParentCommandLine` |
| `user`, `user_id` | the account osquery names for the process's user ID (`username`, `uid`) | `User` |
| `process_current_directory` | `cwd` | `CurrentDirectory` |
| `process_id`, `parent_process_id` | `pid`, `parent` | `ProcessId`, `ParentProcessId` |

The account is always the one the user ID belongs to, never a name read from the
command line. The parent comes from the processes running when osquery sends the
batch: a parent that has already quit is left out, and so is a process that started
after the program (its process ID was used again), so rules about the parent fire only
when osquery can still see it. The code signing identity, team ID and whether Apple
signed the program are kept in the event's raw text.

56 SigmaHQ rules (`product: macos`, `category: process_creation`) and 13 Splunk
detections (data source Osquery Results, over `Endpoint.Processes`) read
these events only, for example AppleScript and JavaScript for Automation run from the
command line, keychain dumps, Gatekeeper and System Integrity Protection turned off,
Time Machine backups deleted, accounts added to the admin group, and discovery with
`system_profiler`, `sw_vers` and `ioreg`. Sigma's Linux rules leave these events out.

To collect them, enroll the Mac with the setup script from **Add data** (osquery,
macOS) and give osqueryd Full Disk Access, which EndpointSecurity needs. The script's
flags turn EndpointSecurity on (`--disable_endpointsecurity=false`); a Mac enrolled
before this release needs the script run again. A busy Mac starts hundreds of
programs a minute, each of them an event.

### Web server access logs

Apache and Nginx write each request to an access log. The Linux agent reads them
(`/var/log/nginx/*access*.log`, `/var/log/apache2/*access*.log` and
`/var/log/httpd/*access_log`), in the combined format both use by default, the common
format, or Apache's `vhost_combined`. Each request is an event in the Web data model,
with Splunk's Web field names:

| Field | What it is |
| --- | --- |
| `url` | The request's target as logged: path and query (`/index.php?id=1`) |
| `uri_path`, `uri_query` | Its path, and its query without the `?` |
| `http_method`, `status`, `http_version` | The method, the response status (`404`) and HTTP version |
| `src`, `user` | The client's address, and the account it logged in as, when it did |
| `http_user_agent`, `http_referrer` | The User-Agent and Referer headers |
| `bytes_out`, `url_length`, `http_user_agent_length` | Response size, and the lengths of `url` and `http_user_agent` |
| `dest`, `dest_port` | The web server: the virtual host and port when the log names them, else the host |

The sourcetype is `nginx:access` or `apache:access`. A line that is not a request
(an error Apache wrote to the wrong file) stays in Other.

Query strings can carry tokens and passwords. **Settings > General > Query strings in web
addresses** (`ingest.url_query`) can hide their values or remove them as events are stored,
in the fields and the raw line alike; rules that look at query values then see less (see
[Query strings in web addresses](network-sensor.md#query-strings-in-web-addresses)).

The 13 SigmaHQ `webserver` rules name the W3C fields: `cs-method` is
`http_method`, `cs-uri-query` (which the rules use for the whole target) and `c-uri` are
`url`, `cs-uri-stem` is `uri_path`, `sc-status` is `status`, `cs-user-agent` is
`http_user_agent`, `cs-referer` is `http_referrer` and `c-ip` is `src`. Their keywords
(`'${jndi:'`, `'=whoami'`) are searched in what the client sent: the target, the user
agent and the referrer. 43 Splunk rules search the Web data model, for example
exploitation attempts against SharePoint, Citrix, Ivanti, Confluence, Fortinet, F5 and
TeamCity, and Spring4Shell.

The OpenTelemetry Collector reads the same files once its user is in the `adm` group,
as its setup steps say. On Red Hat-family systems `/var/log/httpd` is readable only by
root, so collect it with the Fluent Bit agent there.

### Network rules (Zeek, DNS, proxy and firewall)

The SigmaHQ pack also holds rules for network data, which a
[network sensor](network-sensor.md) fills with Zeek's logs:

| Sigma log source | Events | Data model | Shipped |
| --- | --- | --- | ---: |
| `product: zeek`, `service: dns`, `http`, `x509` | Zeek's dns.log, http.log and x509.log, by Zeek's own field names (`query`, `qtype_name`, `certificate.serial`; `uri`, the path and query the client asked for, is `uri_path`) | Network_Resolution, Web, Certificates | 5 |
| `product: zeek`, `service: smb_files`, `dce_rpc`, `kerberos`, `rdp` | Zeek logs whose own fields are kept as `zeek_<name>` (`name` is `zeek_name`), as for every Zeek log without a full mapping; the connection is `src`, `src_port`, `dest`, `dest_port` | Authentication (`kerberos`, `rdp`), Filesystem (`smb_files`), Other (`dce_rpc`) | 11 |
| `category: dns` (`rules/network/dns`) | A DNS lookup that names who asked (`src`): Zeek's dns.log (`record_type` is `query_type`). A host's own lookups (Sysmon 22) are searched by the `dns_query` rules | Network_Resolution | 7 |
| `category: proxy` (`rules/web/proxy_generic`) | A web request a client made: Zeek's http.log, not a web server's access log (`c-uri` is the whole address, `url`; `cs-host`, the site asked for, is `url_domain`; `c-useragent` is `http_user_agent`) | Web | 22 |
| `category: firewall` (`rules/network/firewall`) | Any connection (`dst_port` is `dest_port`) | Network_Traffic | 0 |

A Zeek rule searches only its own log (`sourcetype=zeek:dns`). A firewall rule
searches every connection, from a sensor or a firewall, as Sigma means. A dns rule
searches the lookups that name who asked (`src=*`), so its findings and risk are
about that address. A proxy rule leaves out web servers' access logs
(`NOT sourcetype IN (apache:access, nginx:access)`): those requests come in from the
internet, and their `url` is only the path; the `webserver` rules cover them, and in
those `cs-host` is the web server (`dest`). Their test events are Zeek log lines read by the real Zeek
parser, so a rule ships only when it agrees with Sigma on events as a sensor logs
them. 13 of the 58 network rules are left out: three are experimental; eight name
a field Signalith does not keep (`c-uri-extension`, `cs-uri`, `cs-cookie`, a
firewall's `action` of `accept` or `forward`, Zeek's DNS `Z` flag); one Zeek HTTP
rule uses proxy field names; one searches free text. Network pack rules are titled by the
address that sent the traffic (`from $src$`), find once a day per source and what it
reached, and add risk to the source; a certificate rule (x509) is about the sensor
that saw the certificate (`$host$`), which gets the risk.

A few rules are converted faithfully but are unlikely to match real Zeek data, because
Sigma's rule expects values Zeek writes differently: `zeek_smb_converted_win_atsvc_task`
names the share as the literal `\\*\IPC$` (Zeek logs the server's name), and
`zeek_smb_converted_win_transferring_files_with_credential_data` names whole file
names such as `\sam`, where Zeek logs the file's path in the share. Like every pack
rule they are off until you turn them on; test them on your own data first.

### PowerShell script blocks

The `ps_script` rules read event 4104, which Windows PowerShell writes for each script
it runs once **script block logging** is on (it is off by default). Turn it on with
Group Policy (Administrative Templates > Windows Components > Windows PowerShell >
Turn on PowerShell Script Block Logging) or, in an elevated PowerShell:

```powershell
$k = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
New-Item -Path $k -Force | Out-Null
Set-ItemProperty -Path $k -Name EnableScriptBlockLogging -Value 1
```

Then collect the `Microsoft-Windows-PowerShell/Operational` channel: **Include
PowerShell** on the Add data page adds it to the Windows agent and the OpenTelemetry
Collector. PowerShell 7 logs to its own `PowerShellCore/Operational` channel, which
Signalith does not read yet.

Script blocks are long (up to about 20,000 characters, and a longer script arrives in
parts with `script_part` and `script_parts`), so `script_block_text` is a wildcard
field, which finds text anywhere in a value of any length. That field type needs
OpenSearch 2.15 or later. On older versions Signalith maps it as a keyword instead,
and then the text of a script block longer than 8,191 characters cannot be searched.
The type applies to indices created after an upgrade, so from the next day's index
on. Rules that would list more script snippets than OpenSearch allows in one search
(1,024 clauses by default) are left out of the pack.

### PowerShell module logging and the Windows PowerShell log

The `ps_module` rules read event 4103, which PowerShell writes to the same
`Microsoft-Windows-PowerShell/Operational` channel for each command a pipeline runs
once **module logging** is on (also off by default, and much noisier than script
block logging). Turn it on for all modules with Group Policy (Administrative
Templates > Windows Components > Windows PowerShell > Turn on Module Logging, with
`*` as the module name) or, in an elevated PowerShell:

```powershell
$k = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
New-Item -Path "$k\ModuleNames" -Force | Out-Null
Set-ItemProperty -Path $k -Name EnableModuleLogging -Value 1
Set-ItemProperty -Path "$k\ModuleNames" -Name '*' -Value '*'
```

A 4103 event is stored in Script: its `Payload` (the command and the values bound to
its parameters) in `script_block_text`, and its `ContextInfo` (host program, command,
account) in `event_data`, both wildcard fields searched for words inside. From an
English context Signalith also takes `user` (User), `process` (Host Application,
its first line) and `script_path` (Script Name); a context in another language is
kept as it is, without them.

Module logging records the values passed to every command, so secrets typed or
scripted in plain text (a `-Password`, `ConvertTo-SecureString -AsPlainText`, an API
key) land in `script_block_text`. Name only the modules you need under
`ModuleNames` rather than `*`, and give search access only to people who may see
such values.

The `ps_classic_start`, `ps_classic_provider_start` and `service: powershell-classic`
rules read the classic **Windows PowerShell** log, which every Windows PowerShell 5.1
(and 2.0) engine writes without any setting: an engine starting (400) or stopping
(403), a provider starting (600), and, with module logging, each pipeline (800). The
event's data values are stored one per line in `event_data` (Sigma's `Data`), in
Other with sourcetype `WinEventLog:Windows PowerShell`; `process` is the
`HostApplication=` line (the command line that started the engine, which is how
the downgrade rule sees `-version 2`), `script_path` the `ScriptName=` line and,
for 800, `user` the `UserId=` line. These are read from the event's context value
only; since the command lines in it are written by whoever ran PowerShell,
`script_path` is left empty when the context names more than one script. **Include PowerShell** on the Add data page
collects this log too. Rules that use a case-sensitive regular expression on these
fields, which are searched ignoring case, are left out of the pack.

A rule is only shipped when:

- its status is `stable` or `test` (not `experimental` or `deprecated`), and its
  level is not `informational`;
- it converts exactly: every field maps to a Signalith field and every modifier is
  supported (strict mode, below);
- it fires on its test events and stays quiet on its near misses. Test events are
  made from the rule itself (every way the rule can match, plus events with each
  field removed or changed and events hitting each exclusion), and SigmaHQ's own
  recorded events are added where they exist. Each event goes through the real
  Windows parser, and two independent readings must agree: a Sigma evaluator on the
  raw event, and the converted query on the stored event.

`internal/detect/packs/sigmahq/REPORT.md` lists every rule left out and why.
CI runs the same checks on every change (`TestPackRulesFireOnTheirTests`) and
repeats them against a real OpenSearch (`TestPackRulesAgainstOpenSearch`), so a
change to the parser, the field mappings or the query compiler that breaks a
shipped rule fails the build.

Pack detections get these defaults: the title names the host, at most one finding
per host, user and command line a day (per host, program, destination and port for
network rules), and risk on the user and the host by Sigma level (low 10, medium 25,
high 50, critical 80). Low level rules only add risk and raise no finding, so they
feed [risk-based alerting](#risk) without flooding the queue. Each is tagged
`sigma`, the pack name, the product and the log source.

On the **Detections** page, the pack card shows how many rules are on.
**Turn on N high and critical rules** is the suggested start; **Browse rules** lists
the pack so you can filter, read a rule's source and turn rules on or off one at a
time or all shown at once (with Undo). Pack rules cannot be deleted, only turned
off; editing one saves an override that keeps the credit.

Licence: the SigmaHQ rules are under the [Detection Rule License 1.1](https://github.com/SigmaHQ/Detection-Rule-License)
(full text in the pack folder). As it requires, every finding from a pack rule
carries a credit line naming the rule's author, the pack and the licence, shown on
the finding and stored as its `credit` field.

To refresh the pack from a newer SigmaHQ commit:

```sh
git clone https://github.com/SigmaHQ/sigma /tmp/sigma
go run ./internal/detect/packgen -sigma /tmp/sigma
go test ./internal/detect/
```

The generator keeps each rule's Signalith ID across runs, rewrites `rules/`,
`tests/`, `pack.yaml` and `REPORT.md`, and only lists rules whose checks pass.

### AWS CloudTrail

The 38 CloudTrail rules read CloudTrail's own field names (`eventName`, `eventSource`,
`userIdentity.type`, `requestParameters.*`), which Signalith keeps as CloudTrail writes
them, and each searches `sourcetype=aws:cloudtrail`. Rules that compare one field with
another, or that match text inside the call's parameters in a way no test record
exercises, are left out. The Splunk pack adds 33 CloudTrail detections (see
[Splunk Security Content](#splunk-security-content)). To send CloudTrail records, see [AWS CloudTrail](aws-cloudtrail.md).

### Entra ID and Azure

SigmaHQ's Azure rules name fields as Microsoft Sentinel does (`ResultType`,
`AuthenticationRequirement`, `DeviceDetail.trusttype`), while Signalith keeps each record's
own names (`resultType`, `properties.authenticationRequirement`,
`properties.deviceDetail.trustType`). The converter maps one to the other, by the rule's
service, and a sign-in's `Status` reads `signin_status` (`Success`, or `Failure` with why).
Older rules that name an audit record's operation `properties.message` read
`operationName`. Rules that name a field no record has, or that search free text, are left
out. Sign-in and audit rules search `sourcetype=azure:monitor:aad`, and activity log rules
`sourcetype=azure:monitor:activity`.

The Splunk pack adds 31 Entra ID detections (see
[Splunk Security Content](#splunk-security-content)): admin roles assigned, MFA turned
off, new federated domains, guest invitations, single-factor and device code sign-ins,
password spraying and MFA fatigue. They name fields as Splunk's add-on does, which
Signalith keeps too: a list's values by Splunk's name for them
(`properties.targetResources{}.modifiedProperties{}.newValue`), any of which a search
matches. After `rename properties.* as *`, a later `search` or `stats` reads the fields by
their old names. Most rules that use `eval`, `spath` or `rex`, and the
Intune rules, are left out; a lookup of privileged roles reads the table the pack ships. To send Entra ID and Azure logs, see
[Entra ID and Azure](azure.md).

### Microsoft 365

SigmaHQ's 17 tested Microsoft 365 rules ship. Newer ones name a record's own fields
(`Operation`, `Workload`, `ApplicationId`), which Signalith keeps by the same names. Older
ones name `eventSource` (the workload), `eventName` (the operation, or for the Security &
Compliance Center an alert's name) and `status` (success or failure), which read
`Workload`, `signature` and `status`. A sign-in's `RequestType` is one of its
`ExtendedProperties`, so it reads `ExtendedProperties{}.Value`. Every rule searches
`sourcetype=o365:management:activity`.

The Splunk pack adds 54 Microsoft 365 detections (see
[Splunk Security Content](#splunk-security-content)): MFA turned off, service principals
added or given new credentials, mail security settings changed, content searches
exported, mailboxes read through EWS or Microsoft Graph, malware in SharePoint, and
counts that catch password spraying and MFA fatigue. They name a record's own fields and
the fields Splunk's add-on for Microsoft 365 gives it (`src_ip` is `src`, a sign-in's
`UserAgent` is `user_agent`, and its `OS`, the `DeviceProperties` item of that name, is `os`).
A field must be one Microsoft's audit record schema has: an Exchange cmdlet's parameters
are only in `Parameters{}.Name` and `Parameters{}.Value`, so rules that name one as a
field (`Role=ApplicationImpersonation`) are left out, with rules whose later stages
Signalith would read differently from Splunk. To read
the audit log, see [Microsoft 365](microsoft-365.md).

### Okta

SigmaHQ's 19 tested Okta rules ship. They name a System Log event's own fields
(`eventType`, `actor.alternateId`, `securityContext.isProxy`,
`debugContext.debugData.behaviors`), which Signalith keeps by the same names; a field of
an event's targets (`target.displayName`) reads each target's value
(`target{}.displayName`), as Splunk's add-on for Okta names them. Every rule searches
`sourcetype=OktaIM2:log`. `okta_user_created` is informational, and
`okta_password_in_alternateid_field` uses `^` inside a regular expression's
alternatives, so they are left out.

The Splunk pack adds 13 Okta detections (see
[Splunk Security Content](#splunk-security-content)). Five search the `okta` macro by
Okta's field names (`eventType`, `outcome.result`) and the CIM fields Splunk's add-on
gives an event (`user`, `src`, `signature`). Eight are `tstats` searches of the
Authentication or Change data model whose only data source is Okta: they read the same
CIM fields of Okta's events (`Authentication.action`, `All_Changes.command`), limited to
`sourcetype=OktaIM2:log`. One of them, `okta_user_logins_from_multiple_cities`, counts
the cities an account signs in from with `iplocation`, and needs a GeoIP database (see
[GeoIP and iplocation](#geoip-and-iplocation)). Experimental, hunting and correlation
rules and one that reads every field after `iplocation` and uses a syntax Signalith
doesn't run (`okta_mismatch_between_source_and_response_for_verify_push_request`) are
left out. To read the System Log, see [Okta](okta.md).

### Kubernetes

SigmaHQ's 15 tested Kubernetes audit rules ship. They name an audit Event's own fields
(`verb`, `objectRef.resource`, `objectRef.subresource`, `responseStatus.code`), which
Signalith keeps by the same names; `user.username` and `user.groups` read
`kube_user.username` and each value of `kube_user.groups{}`, as the Event's `user`
object is kept under that name. Three rules name a field the Event doesn't have at the
top: `apiGroup` reads `objectRef.apiGroup`, the only API group an Event names, and
`hostPath: '*'` and `capabilities: '*'` (which their authors note stand for "the field
exists") read a pod's hostPath volumes (`requestObject.spec.volumes{}.hostPath.path`) and
its containers' added capabilities
(`requestObject.spec.containers{}.securityContext.capabilities.add{}`), so those two
fire only when the audit policy records request bodies. Every rule searches
`sourcetype=_json source=kubernetes`. `kubernetes_audit_potential_enumeration_activity`
is experimental, and is left out.

The Splunk pack adds 13 Kubernetes detections (see
[Splunk Security Content](#splunk-security-content)), the production rules that search
the `kube_audit` macro: by the Event's fields as Splunk reads its JSON (`verb`,
`objectRef.resource`, `requestObject.spec.type`, `user.username`, which reads
`kube_user.username`, and `sourceIPs{}`), and a pod's
`requestObject.metadata.annotations.kubectl.kubernetes.io/last-applied-configuration`,
searched for `"privileged":true` and `"hostNetwork":true`. Four read an allowed list
macro (`kube_allowed_user_agents`, `kube_allowed_images` and the like), shipped with
Splunk's sample values. Two count refused anonymous requests by the country and city
`iplocation` names, and need a GeoIP database (see
[GeoIP and iplocation](#geoip-and-iplocation)). One that compares the country after a
`fillnull` of every field (`kubernetes_abuse_of_secret_by_unusual_location`), the Falco rule, the metrics and Splunk Connect for
Kubernetes object rules, and experimental and hunting rules are left out. To send the
audit log, see [Kubernetes audit logs](kubernetes-audit.md).

### GitHub

SigmaHQ's 12 tested GitHub audit log rules ship. They name the event's own `action`
(`repo.destroy`, `org.disable_two_factor_requirement`), which Signalith keeps as
`vendor_action`, as Splunk's add-on for GitHub does, since `action` is the CIM field.
Every rule searches `sourcetype=github:cloud:audit`. `github_new_org_member` is
informational, and `github_pages_site_changed_to_public` and
`github_repository_archive_status_changed` are experimental, so they are left out.

The Splunk pack adds 18 GitHub detections (see
[Splunk Security Content](#splunk-security-content)): the 12 `github_enterprise` searches,
which name GitHub's own fields (`action`, `actor`, `reason`) as audit log streaming sends
them, and the 6 `github_organizations` searches, which name GitHub's action
`vendor_action` as Splunk's add-on for GitHub does. GitHub's `actor`, `user`, `reason`,
`name` and `user_agent` are kept as `github_actor`, `github_user` and so on, and
`action` as `vendor_action`, so both macros' searches read the same events, limited to
`sourcetype=github:cloud:audit`. To send the audit log, see
[GitHub audit log](github-audit-log.md).

### Google Cloud

SigmaHQ's 16 tested Google Cloud audit log rules ship. Most name a call's method as
Elastic does (`gcp.audit.method_name`), which reads `protoPayload.methodName`; the others
name the entry's fields as Splunk's add-on keeps them, under `data.`
(`data.protoPayload.serviceName`), which read the same names without it. An entry's list
of permissions checked reads Splunk's names for its values
(`protoPayload.authorizationInfo{}.permission`), and a rule's log (`logName`) reads
`log_id`, the end of the entry's `logName`. A rule's keywords are searched in the call's
request (`request_parameters`), where a Kubernetes object's annotations are. Every rule
searches `sourcetype=google:gcp:pubsub:message`. Splunk's Google Cloud detections are left
out, as they are all experimental.

SigmaHQ's 7 tested Google Workspace admin rules ship too: an application's access level
changed, an application removed, an API client given domain-wide access, 2-step
verification turned off, a role changed or deleted, a privilege removed from a role, and
admin rights granted. They read Workspace's audit logs as Google Cloud has them when an
organization shares them, the same entries in the same sourcetype. They name the event as
Workspace's Reports API does (`eventName`, such as `GRANT_ADMIN_PRIVILEGE`), which reads
`event_name`, the event's name in the entry's metadata, and its parameters by their names
in lower case (`new_value`, `setting_name`), which read `event_parameters.new_value` and
the like. `eventService` reads `protoPayload.serviceName`. The 3 sign-in rules (a
government-backed attack warning, mail forwarded out of the domain, and sign-ins Google
calls suspicious) convert as well, but are experimental, so they don't ship. Splunk's
Google Workspace detections read the Reports API's own records, as Splunk's add-on for
Google Workspace stores them (`sourcetype=gws:reports:login`), with fields the add-on
derives, so they are left out. To send the audit logs, see
[Google Cloud](google-cloud.md).

### Splunk Security Content

**Splunk Security Content** (`internal/detect/packs/splunk`) holds 1,330 Windows,
Linux, macOS, web, network, AWS CloudTrail, Entra ID, Microsoft 365, Okta, Kubernetes and GitHub detections from Splunk's Threat Research Team
([security_content](https://github.com/splunk/security_content)), pinned to one
commit. They are the production TTP and anomaly rules that search the CIM
`Endpoint.Processes`, `Endpoint.Filesystem`, `Endpoint.Registry` and `Web` nodes with
`tstats`, plus the PowerShell script block rules, and 9 of the 102 network detections
(`detections/network`), the `tstats` searches that read any source of their data
model, a [network sensor](network-sensor.md) among them: Cisco Smart Install port
4786, ngrok tunnels, protocol on an unusual port, Tor, Kerberos coercion through DNS,
unusually long DNS queries and the 3CX supply chain attack's domains over
`Network_Traffic` or `Network_Resolution`, and the F5 iControl REST exploit and
remote management tools' user agents over `Web`. The other network
detections use lookups, `eval` or Cisco firewall searches, are experimental or hunting
rules, or search Sysmon's DNS and network events, which is endpoint content
(`REPORT.md`). Signalith uses the same CIM field
names, so each rule's `where` clause becomes a Signalith filter field for field:

| Splunk node | Windows events | Data model |
| --- | --- | --- |
| `Endpoint.Processes` | Sysmon 1, Security 4688; on Linux, Sysmon for Linux 1 or a program start auditd recorded; for a macOS rule (data source Osquery Results), a program start osquery reported | Endpoint |
| `Endpoint.Filesystem` | Sysmon 11, 23 and 26 | Filesystem |
| `Endpoint.Registry` | Sysmon 12, 13 and 14 | Registry |
| `Network_Traffic.All_Traffic` | Sysmon 3 (`app` is the program's path, `dest_ip` and `src_ip` are `dest` and `src`) | Network_Traffic |
| `` `powershell` EventCode=4104 `` (raw search) | PowerShell 4104 | Script |
| `` `sysmon` EventCode=1 `` (raw search) | Sysmon 1 | Endpoint |
| `` `sysmon` EventCode=3 `` (raw search) | Sysmon 3 | Network_Traffic |
| `` `sysmon` EventCode=7 `` (raw search) | Sysmon 7 | Image_Load |
| `` `sysmon` EventCode=22 `` (raw search) | Sysmon 22 | Network_Resolution |
| `` `sysmon` EventCode=11 ``, `23` or `26` (raw search) | Sysmon 11, 23 and 26 | Filesystem |
| `` `sysmon` EventCode=12 ``, `13` or `14` (raw search) | Sysmon 12, 13 and 14 | Registry |
| `` `sysmon` EventCode=8 `` or `10` (raw search) | Sysmon 8 and 10 | Endpoint |
| `` `sysmon` EventCode=17 `` or `18` (raw search) | Sysmon 17 and 18 (named pipe created or connected to; `PipeName` is `pipe_name`) | Endpoint |
| `` `sysmon` EventCode=15 `` (raw search) | Sysmon 15 (alternate data stream written; `Contents` is `file_contents`) | Filesystem |
| `` `sysmon` EventCode=5 `` or `9` (raw search) | Sysmon 5 (process terminated) and 9 (a drive read directly; `Device` is `device`) | Endpoint |
| `` `wineventlog_security` EventCode=4624 `` or `4625` (raw search) | Security 4624 (successful logon) and 4625 (failed logon) | Authentication |
| `` `wineventlog_security` EventCode=4698 `` (raw search) | Security 4698 (scheduled task created) | Change |
| `` `wineventlog_security` EventCode=4663 `` (raw search) | Security 4663 (object access) | Filesystem for a file, Registry for a key |
| `` `wineventlog_system` EventCode=7045 `` (raw search) | System 7045 (service installed) | Change |
| `` `wineventlog_security` EventCode=5136 `` (raw search) | Security 5136 (directory object changed) | Change |
| `` `wineventlog_security` EventCode=5145 `` or `5140` (raw search) | Security 5145 (network share access) and 5140 (share accessed, once per session) | Filesystem |
| `` `wineventlog_security` EventCode=4768 `` or `4769` (raw search) | Security 4768 and 4769 (Kerberos tickets) | Authentication |
| `` `wineventlog_security` EventCode=4738 `` or `4732` (raw search) | Security 4738 (user account changed) and 4732 (member added to a local group) | Change |
| `` `wineventlog_security` EventCode=4648 ``, `4776` or `4771` (raw search) | Security 4648 (logon with explicit credentials), 4776 (NTLM credential check) and 4771 (Kerberos pre-authentication failed) | Authentication |
| `` `wineventlog_security` EventCode=4741 ``, `4742`, `4781`, `4727`, `4730` or `4737` (raw search) | Security 4741 and 4742 (computer account created or changed), 4781 (account renamed), 4727, 4730 and 4737 (global group created, deleted or changed) | Change |
| `` `wineventlog_security` EventCode=4731 ``, `4744`, `4749`, `4754`, `4759`, `4783`, `4790` or `4756` (raw search) | Security 4731, 4744, 4749, 4754 and 4759 (local, global and universal group created), 4783 and 4790 (application and LDAP query group created), 4756 (member added to a universal group) | Change |
| `` `wineventlog_security` EventCode=4798 ``, `4799`, `4886` or `4887` (raw search) | Security 4798 and 4799 (local group membership listed), 4886 and 4887 (certificate requested and issued) | Change |
| `` `wineventlog_security` EventCode=4662 ``, `4728`, `4722`, `4723`, `4724` or `4725` (raw search) | Security 4662 (operation on a directory object), 4728 (member added to a global group), 4722 and 4725 (account enabled or disabled), 4723 and 4724 (password changed or reset) | Change |
| `` `wineventlog_security` EventCode=5447 `` (raw search) | Security 5447 (Windows Filtering Platform filter changed; each value by its name, `FilterName` is `security_filter_name`) | Other |
| `` `wineventlog_system` EventCode=7036 `` or `7040` (raw search) | System 7036 (service started or stopped) and 7040 (service start type changed), each value by its name (`param1` is `system_param1`); the service's binary data, which `` `normalized_service_binary_field` `` reads, is `system_binary` | Other |
| `` `wmi` EventCode=5861 `` (raw search) | WMI-Activity 5861 (permanent event subscription; `spath` of its user data, such as `PossibleCause`, reads `wmi_possible_cause`) | Other |
| `` `wineventlog_appxdeploymentserver` EventCode=603 `` or `854` (raw search) | AppXDeployment-Server 603 (package deployment started; `Flags` is `appx_flags`) and 854 (package file downloaded) | Other |
| `` `ntlm_audit` EventCode=8004 `` (raw search) | NTLM 8004 (NTLM authentication to a domain controller audited; `WorkstationName` is `ntlm_workstation_name`) | Other |
| `` `wineventlog_application` EventCode=15457 `` or `17135` (raw search) | Application 15457 (SQL Server configuration option changed) and 17135 (SQL Server startup procedure run); a `rex` of the event's first `<Data>` values reads the first lines of `event_data` | Other |
| `Endpoint.Processes` (Sysmon for Linux rules) | Sysmon for Linux 1 | Endpoint |
| `Endpoint.Filesystem` (Sysmon for Linux rules) | Sysmon for Linux 11 and 23 | Filesystem |
| `` `linux_auditd` `` (raw search) | Linux audit records, each field by auditd's name (see [the Linux audit log](#linux-audit-log-auditd)) | Other |
| `Web` (`datamodel=Web` or `Web.Web`) | Apache and Nginx access log lines (see [Web server access logs](#web-server-access-logs)), and a network sensor's web requests (Zeek's http.log) | Web |
| `` `cloudtrail` `` (raw search) | AWS CloudTrail records, by CloudTrail's field names and the CIM fields Splunk's AWS add-on gives them (`errorCode=success` reads a record with no error code; see [AWS CloudTrail](#aws-cloudtrail)) | Authentication, Change or Other |
| `` `azure_monitor_aad` `` (raw search) | Entra ID sign-in, audit and risk records, by the record's own field names and the CIM fields Splunk's add-on for Microsoft cloud services gives them (see [Entra ID and Azure](#entra-id-and-azure)) | Authentication, Change or Alerts |
| `` `o365_management_activity` `` (raw search) | Microsoft 365 audit records, by the record's own field names and the CIM fields Splunk's add-on for Microsoft 365 gives them (see [Microsoft 365](#microsoft-365)) | Authentication, Change, Alerts or Other |
| `` `okta` `` (raw search) | Okta System Log events, by Okta's own field names and the CIM fields Splunk's add-on for Okta Identity Cloud gives them (see [Okta](#okta)) | Authentication, Change, Alerts or Other |
| `Authentication.Authentication`, `Change.All_Changes` (rules whose only data source is Okta) | Okta System Log events of that data model (see [Okta](#okta)) | Authentication or Change |
| `` `kube_audit` `` (raw search) | Kubernetes audit events, by the Event's own field names (`user.` is `kube_user.`) and the CIM fields Signalith gives them (see [Kubernetes](#kubernetes)) | Change, Authentication or Other |
| `` `github_enterprise` ``, `` `github_organizations` `` (raw search) | GitHub audit log events, by GitHub's own field names (GitHub's action, `action` in `github_enterprise`'s searches and `vendor_action` in `github_organizations`', is `vendor_action`; `actor` is `github_actor`) and the CIM fields Signalith gives them (see [GitHub](#github)) | Change, Authentication or Other |
| `Network_Traffic` (network detections) | Any connection: Zeek's conn.log, a firewall, Sysmon 3 (`app` is the protocol, Zeek's `service`) | Network_Traffic |
| `Network_Resolution` (network detections) | A DNS lookup that names who asked (`src`), as Zeek's dns.log does (`record_type` is `query_type`); a host's own lookups (Sysmon 22) name only the host and are left to the endpoint rules | Network_Resolution |

The rule files and the macros they use ship unchanged; Signalith converts them when
it starts, reading the search the way Splunk does: `*` is the only wildcard (`?` is
literal, so rules with one are left out), case is ignored, `!=` only matches
when the field is present, `OR` binds tighter than `AND` (`a b OR c` is
`a AND (b OR c)`), and `\\` is one backslash, quoted or not, as in Splunk's search
syntax. Sysmon's user (`NT AUTHORITY\SYSTEM`) compares as the name alone
(`SYSTEM`), the way Splunk's Sysmon add-on reads it. TTP rules raise findings and add risk; anomaly rules only
add risk, as their authors intend. Severity follows the rule's risk score
(TTP: 80 and up critical, 64 high, 30 medium; anomalies low). Each is tagged
`splunk`, the pack name, `ttp` or `anomaly`, and the node, and keeps the rule's
known false positives as triage guidance.

Some rules look values up in a table Splunk publishes with them (`| lookup
pua_named_pipes pua_pipe_name AS pipe_name OUTPUT tool | where isnotnull(tool)`):
named pipes, user agents and services of known tools, PowerShell attack strings,
vulnerable drivers, LOLBAS paths, DLLs open to hijacking and privileged Entra ID
roles. The pack ships the 15 tables its rules read (about 250 KB, in
`internal/detect/packs/splunk/lookups`), unchanged, each with its yml, and the rule
looks up the pack's copy, `splunk-pua_named_pipes`, so a table of your own with the
same name is never used or replaced (see
[Tables that come with content packs](lookups.md#tables-that-come-with-content-packs)).
The lookup matches as the yml says (wildcard columns, case, `max_matches`,
`default_match`), and the rule's test events hold a value of one of the table's
rows. A rule is left out when Signalith's lookup could give it a different answer
than Splunk's: a table row with a pattern before a row it also matches under
`max_matches: 1`, values with spaces around them, an output that several rows may
give compared with a value or counted by, more matching rows than Signalith's
lookup takes (100), more than 2,000 rows with patterns, or a table security_content
does not ship as a CSV file (KV store lookups such as `identity_lookup_expanded`).

#### GeoIP and iplocation

Three rules group or count by where an address is, with `iplocation`:
`kubernetes_access_scanning` and `kubernetes_scanning_by_unauthenticated_ip_address`
(more than 5 refused anonymous requests from one address, by its `Country` and
`City`) and `okta_user_logins_from_multiple_cities` (one account signing in from more
than one `City`). **They need a GeoIP database, which an admin adds**: Splunk ships
one (DB-IP's IP to City Lite), Signalith doesn't. Put a City database (`.mmdb`, such
as DB-IP's IP to City Lite or MaxMind's GeoLite2 City) in the `geoip` folder next to
the lookup tables on each server (see
[GeoIP database for iplocation](lookups.md#geoip-database-for-iplocation)) before
turning them on. Without one, each run fails with "iplocation needs a GeoIP database",
which the detection shows as its last error, and finds nothing, rather than running
without locations; their triage guidance says so, and they are tagged `geoip`. Runs
that start while the server is still reading the database wait and are tried again.

The rules read the database as Splunk's `iplocation` does. An address the database
locates gets `City`, `Region`, `Country`, `lat` and `lon`, each empty when the
database has no value for it (an address located only to its country has an empty
`City`, so `stats ... by Country City` keeps it as it does in Splunk, and `dc(City)`
counts the empty city as one); a private address, one the database does not list, or
text that is not an address gets none of them (so `stats ... by City` drops it), and a
field the event already had keeps its value. Signalith's own `iplocation` adds only
the fields that have a value, so each rule's conversion adds the empty ones. A list of
addresses (Kubernetes' `sourceIPs`) is located by its first, the client's. What a
rule finds still depends on the database: two versions, or DB-IP's and MaxMind's,
place some addresses in different cities, which is true of Splunk too. Where an
address has no country of its own, Signalith names its registered country (MaxMind's
`registered_country`); Splunk's documentation doesn't say whether its `iplocation`
does. An `iplocation` that no later stage reads (it only adds columns
to the finding, as in several Okta and Entra ID rules) is left out, so those rules
need no database. Rules whose stages after `iplocation` read every field of a row
(`fillnull` with no fields, `values(*)`) are left out: Signalith's rows would have the
location fields when Splunk's don't.

PowerShell rules, and Sysmon image load, remote thread and process access rules,
search the events themselves rather than a data model: their event fields become
Signalith's (`ScriptBlockText` is `script_block_text`, `ImageLoaded` is
`loaded_file_path`, `TargetImage` is `target_process_path`, and so on), and their
`fillnull` and `stats` stages only count the events. (Without `fillnull`, Splunk's
`stats` also drops events that miss one of its `by` fields; Signalith keeps them.) PowerShell rules need script block logging
turned on (**Include PowerShell** on Add data). A PowerShell search that needs
`ScriptBlockText` in every event it finds may leave out its event code: of the events
of the channels the `powershell` macro reads, only a script block (4104) has it.

Scheduled task rules search the task's name (`TaskName` is `task_name`) and its
XML definition (`TaskContent` is `task_content`); after `xmlkv`, the command and
arguments of its first action are `task_command` and `task_arguments`. Splunk keeps that XML escaped
(`&lt;Hidden&gt;`); Signalith stores it as it is, so the rule's values are unescaped
to match. Security 4698 is logged when **Audit Other Object Access Events** is on.

Object access rules (Security 4663) search the object's path whatever its type
(`ObjectName` and `object_file_path` are `object_path`, `object_file_name` is
`object_name`), the program (`ProcessName` is `process_path`), `ObjectType`,
`AccessList` and `AccessMask`. Files are stored in Filesystem and registry keys in
Registry (action `read`, `modified` or `deleted`), and a rule searches both, as in
Splunk. Windows logs 4663 only for objects whose auditing (SACL) asks for it, with
**Audit File System** or **Audit Registry** on.

Directory change rules (Security 5136) search the object's DN (`ObjectDN` is
`object`), `ObjectClass` (`ad_object_class`), the attribute (`AttributeLDAPDisplayName`
is `ad_attribute`), its value (`AttributeValue` is `ad_value`) and `OperationType`
(`ad_operation`, `%%14674` for a value added), and who made the change
(`SubjectUserName` is `user`, `SubjectUserSid` `user_sid`, `SubjectDomainName`
`user_domain`). Share access rules (Security 5145)
search `ShareName` (`share_name`), the path inside the share (`RelativeTargetName` is
`share_target`), the client (`IpAddress` is `src`), `AccessMask` and `AccessList`.

A raw search may name only its event code: it reads every event of that code, and
its later stages, run as written, keep what they keep (a `stats` with no `by` fields
is refused: Splunk counts every event into one row). A search may name codes of
events that are read differently when one node reads them all, with the fields
stored the same in each: Sysmon 11 and 15 (a file created and a stream written),
Security 4738 and 4742 (a user and a computer account changed), and a group created
(4727 and the like) with a member added (4728, 4732, 4756). In Sysmon 5, Splunk's
`ProcessID` is the Sysmon process that logged the event, which Signalith does not
keep, so a rule that counts by it is left out.

Kerberos rules (Security 4768 for a ticket-granting ticket, 4769 for a service
ticket) search the account (`TargetUserName` is `user`), the service
(`ServiceName` is `kerberos_service`), `TicketOptions` (`ticket_options`),
`TicketEncryptionType` (`ticket_encryption_type`, `0x17` for RC4), `Status`
(`kerberos_status`, `0x0` when granted) and the client (`src_ip` is `src`, stored
without the `::ffff:` Windows puts before an IPv4 address). They are stored in
Authentication with `app` `win:kerberos`, action `success` or `failure`.

Account rules (Security 4738 for a user account changed, 4732 for a member added to
a local group) search the account or group (`TargetUserName` is `object`), who made
the change (`SubjectUserName` is `user`), the account's `UserAccountControl` flags
(`user_account_control`, such as `%%2096` for Kerberos pre-authentication turned
off), and the member added (`MemberSid` is `member_sid`). They are stored in Change
with `object_category` `user` or `group`.

Sign-in rules search the account (`TargetUserName` is `user`); a logon or failed
logon (4624, 4625) also by the account that asked for it (`SubjectUserName` is
`src_user`, `SubjectUserSid` `src_user_sid`); a logon with explicit
credentials (4648) by who used them (`SubjectUserName`, or the add-on's
`Caller_User_Name`, is `src_user`), an NTLM credential check (4776) by the computer it
came from (`Workstation` is `src_host`) and its result (`Status` is `ntlm_status`,
`0xc0000064` for an account that does not exist), and a failed Kerberos
pre-authentication (4771) by the client (`IpAddress` is `src`) and `Status`
(`kerberos_status`, `0x18` for a wrong password).

Computer account rules (4741, 4742) search the account (`TargetUserName` is `object`),
its `UserAccountControl`, `NewUacValue` and service principal names
(`ServicePrincipalNames` is `service_principal_names`, one space between names). A
renamed account (4781) has its new name as `object` and its old one as `old_object`.
Local group listing rules (4798, 4799) search the program that asked
(`CallerProcessName` is `process_path`), and certificate rules (4886, 4887) the
requester (`Requester` is `cert_requester`) and the request's `Attributes`
(`cert_attributes`, such as its template and any subject alternative name).
Directory object rules (4662) search the object (`ObjectName` is `object`, as
recorded: often a `%{GUID}`), its class (`ObjectType` is `object_type`),
`AccessMask`, `AccessList` and `Properties` (`object_properties`, one space between
values), and who acted (`SubjectUserName` is `user`). Password rules (4723 changed by
the account, 4724 reset by another) and account enabled or disabled (4722, 4725)
search the account (`TargetUserName` is `object`, `TargetSid` is `object_sid`) and
who acted (`SubjectUserName` is `user`, `SubjectUserSid` is `user_sid`).

Service install rules (System 7045, from the Sigma `service: system` log source or
Splunk's `wineventlog_system`) search the service's name (`ServiceName` is
`service_name`), what it runs (`ImagePath` is `service_path`, a path or a whole
command line), `ServiceType` (`service_type`), `StartType` (`service_start_type`) and
`AccountName` (`service_account`). They are stored in Change with `object_category`
`service` and action `created`. The Service Control Manager logs 7045 on every
Windows version without any audit setting, and the Windows agent collects the System
log.

Rules about other System log events find them in Other by provider (`Provider_Name`
is `provider`) and event ID. Signalith also keeps the data of these events, each value
as `system_` and its name in snake case:

| Provider and event | Data |
|---|---|
| Service Control Manager 7036 (service changed state), 7034 (terminated unexpectedly), 7023 (terminated with an error) | `param1` (the service's display name) and `param2` (its state, crash count or error) |
| Service Control Manager 7040 (start type changed) | `param1` to `param4` |
| Microsoft-Windows-Eventlog 104 (a log cleared) | `SubjectUserName`, `SubjectDomainName`, `Channel` (the log cleared) and `BackupPath`; the account is also `user` and `user_domain` |
| Microsoft-Windows-Kernel-General 16 (a hive's access history cleared) | `HiveName` and the counts with it |
| Application Popup 26 | `Caption` and `Message` |
| Microsoft-Windows-DistributedCOM 10001 (a DCOM server could not start) | `param1` to `param3` |

An event's binary data (`Binary`, a service's name in UTF-16 hex for service events)
is `system_binary` when the OpenTelemetry Collector sends it; Fluent Bit does not. Rules
about other data of System events (NTFS volume names, for example) are left out of the
packs, and importing one says so.

Application log rules (SQL Server, Windows Installer, ESENT, Windows Backup,
ScreenConnect, application crashes) find their events in Other by provider and event ID
and search the event's data values (`Data` is `event_data`, the values one per line).
The Windows agent collects the Application log. A rule about the rendered message
(`Message`) is left out of the pack.

Code Integrity rules (`Microsoft-Windows-CodeIntegrity/Operational`, which the Windows
agent collects) find their events the same way, with the event's data values as
`event_data`; a rule about a named value (`FileNameBuffer`) is left out of the pack.

Windows Firewall rules (`Microsoft-Windows-Windows Firewall With Advanced Security/Firewall`),
BITS rules (`Microsoft-Windows-Bits-Client/Operational`), app package rules
(`Microsoft-Windows-AppXDeploymentServer/Operational`) and WMI activity rules
(`Microsoft-Windows-WMI-Activity/Operational`), and Remote Desktop session
(`Microsoft-Windows-TerminalServices-LocalSessionManager/Operational`), shell
(`Microsoft-Windows-Shell-Core/Operational`), SMB client security
(`Microsoft-Windows-SmbClient/Security`) and exploit protection
(`Microsoft-Windows-Security-Mitigations/KernelMode`) rules, and the rules for the logs in the
table below, find their events in Other by
event ID, and name their data the way Windows does: each value is the log's prefix
(`firewall_`, `bits_`, `appx_`, `wmi_`, `rdp_`, `shell_`, `smbclient_`, `mitigation_`, or the one
in the table) and
its name in snake case (`ApplicationPath` is `firewall_application_path`,
`RemoteName` `bits_remote_name`, `PackageFullName` `appx_package_full_name`, `Operation`
`wmi_operation`). The Windows agent collects these logs, which Windows keeps by default.

| Log (channel) | Prefix | Kept by default |
|---|---|---|
| DNS client (`Microsoft-Windows-DNS-Client/Operational`) | `dnsclient_` | No: `wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:true` |
| Task Scheduler (`Microsoft-Windows-TaskScheduler/Operational`) | `taskscheduler_` | Servers yes; on clients turn on the task history (`wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true`) |
| NTLM (`Microsoft-Windows-NTLM/Operational`) | `ntlm_` | Only with the "Network security: Restrict NTLM" audit policies set |
| LSA (`Microsoft-Windows-LSA/Operational`) | `lsa_` | Yes |
| CryptoAPI (`Microsoft-Windows-CAPI2/Operational`) | `capi2_` | No: `wevtutil sl Microsoft-Windows-CAPI2/Operational /e:true` |
| Device drivers (`Microsoft-Windows-DriverFrameworks-UserMode/Operational`) | `driver_` | No: `wevtutil sl Microsoft-Windows-DriverFrameworks-UserMode/Operational /e:true` |
| Packaged apps (`Microsoft-Windows-AppModel-Runtime/Admin`) | `appmodel_` | Yes |
| App packages (`Microsoft-Windows-AppxPackaging/Operational`) | `appxpackaging_` | Yes |
| Certificates (`Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational`) | `certlifecycle_` | Yes |
| OpenSSH server (`OpenSSH/Operational`) | `openssh_` | When OpenSSH Server is installed |
| DNS Server (`DNS Server`) | `dnsserver_` | On DNS servers |
| IIS configuration (`Microsoft-IIS-Configuration/Operational`) | `iisconfig_` | On web servers, after `wevtutil sl Microsoft-IIS-Configuration/Operational /e:true` |

Fluent Bit skips the logs a computer doesn't have. The OpenTelemetry Collector stops on a log
it can't open, so its configuration leaves out the OpenSSH, DNS Server and IIS logs; add a
`windowseventlog` receiver for each one a server has.
A rule that searches an event's free text (the WMI persistence rule) is left out of the
pack.

Registry values that Sysmon writes as `DWORD (0x00000001)` compare as `0x00000001`,
the way Splunk's Sysmon add-on reads them.

A rule is shipped only when its search converts exactly (a `tstats` search
whose later stages only rename fields, format times, keep rows that have a field
(`where isnotnull(...)`), keep rows a regular expression matches (`regex field="..."`,
or `where match(field, "...")` joined by AND or OR) or apply the rule's empty `_filter`
macro) and, on test events made from its `where` clause and passed through
the real Windows parser, the converted detection agrees with Splunk's reading of the
clause on every event. A regular expression converts when it is also valid in Go's
syntax (no lookarounds) and OpenSearch can search it exactly. One that OpenSearch
cannot search only because of its word boundaries (`\b`, `\B`), and that every event
must match (not one of several joined by OR, and not negated), runs as a `regex`
stage right after the search instead, which reads word boundaries as Splunk does.
A value with a `?`, which Splunk reads literally, is searched as a regular expression
too. An address range (`dest_ip IN ("10.0.0.0/8", ...)`) matches the addresses in it, as in Splunk. Raw searches that test an access mask bit by bit (`eval m = tonumber(GrantedAccess, 16)`,
`bit_and(m, 16)` and a `where` on the result being the mask, 0 or not 0) convert to a regular
expression over the mask's hex digits.

Rules that count events convert too: a `tstats` count `by` some fields and
`_time span=1m` (or a raw search's `bucket span=5m _time` and `stats ... by`), then a
`where` limit on the count (`where count >= 10`, `where unique_accounts > 30`, several
joined by AND; the count may have a name, `count as failures`). The detection runs
`| stats count, dc(field) as name by fields` and the same limit. A `bucket` before a
`stats` that is not `by _time` only rounds each event's time, so that count is over
the rule's whole search, as one without a span. Each run counts the rule's span plus the time since the last run
(every minute for spans under 5 minutes, every 5 minutes otherwise; a count without
a span covers an hour, as Splunk's default schedule does), so a burst Splunk finds
in one of its fixed buckets is counted even when its events arrive a little late,
and each group is found once a day. Fields of Splunk's add-ons that only restate
which event it is (`signature`, `vendor_product`, `dvc`, `app`, `user_id`,
`authentication_method`) are left out of the grouping; an event's `Computer` is
`host`. A rule ships only when its test events carry every field it groups by and
counts.

Counts compared with each other (a later `eventstats avg(n), stdev(n)` after a `stats`,
keeping a group above the average by some standard deviations) run as later stages
(below). Splunk compares the groups of its whole search window (by default the hour that
ended 10 minutes before each hourly run), so a rule that compares counts over the whole
search, or across time buckets (`eventstats ... by src` after `stats ... by _time, src`),
depends on that window and is left out. So is any other later stage that reads the
search's other rows (`eventstats` over the events or a `tstats` search's rows,
`streamstats`, `anomalydetection`, `outlier`, `predict`, `trendline`, `delta`, `accum`,
`autoregress`): its answer depends on how long a window it sees. One that compares the groups of each time bucket
(`bucket span=10m _time`, `stats ... by _time, src`, `eventstats ... by _time`) ships when
the span divides 10 minutes, so Splunk's window holds each bucket whole: each run searches
the span plus the time since the last run (every 5 minutes), and the detection keeps a
bucket's rows only from a run whose window holds the whole bucket (`addinfo` and
`where _time >= info_min_time AND _time + 600 <= info_max_time` at the end, for a 10-minute
span), since a part of a bucket may stand out where the whole does not. A bucket is
compared at the first run after it ends; events that arrive later are not counted in it
(Splunk's default waits 10 minutes). The standard deviation of a single value is 0, as in
Splunk, so a source alone in its bucket stands out by its count alone. Its test events are the repeated event among other
groups' events at the same time, one each (`"baseline"` in the test file): the rule must
find the repeat among enough others to stand out, and not find it when another group is as
high, or among fewer others (with the sample standard deviation, one group stands out
from the others by at most (n-1)/√n standard deviations, so three need ten others).

A `tstats` search grouped by time (`by _time span=1h dest`) whose other later stages
run as written (below) puts each event's time in its bucket first (`bin _time span=3600s
as time_bucket`), groups by the bucket and names it `_time`, so `min(_time)` and
`max(_time)` still read the events' own times. The span may be at most 24 hours, which
bounds how far back each run searches; a rule with a longer span is left out. Buckets are aligned to UTC (an hour
bucket starts on the hour in UTC). Splunk aligns them to the searching user's time
zone, which is the same for zones a whole number of hours from UTC, and for spans in
minutes that divide an hour, in any zone a whole number of those minutes off; in a
zone such as India's (UTC+5:30), hour buckets start half an hour apart. As for a
count, each run searches the span plus the time since the last run (every minute for
spans under 5 minutes, every 5 minutes otherwise), so each bucket is whole in some
run, and the buckets at the edges of a run are parts of buckets. So such a rule ships
only when a part of a bucket cannot keep a row the whole bucket would not: its later
filters may only test that a value is at least or more than a number (`where count > 10`).
A rule with a `<`, `!=`, `=`, `NOT`, `IN` or `isnull` in a later `where` or `search`, or a
`<`, `!=`, `NOT`, `IN` or `isnull` in a later `eval`, is left out, and so is one whose
later `stats` takes a smallest value, an average or a percentile of its rows (other than
`min(firstTime)`), whose later `eval` or `where` reads `_time`, or with a stage that compares
or regroups the buckets (`eventstats`, `streamstats`, `bin`, `sort`, `head`, `dedup`), since
its answer depends on Splunk's search window (by default the hour that ended 10 minutes
before each hourly run). A bucket Splunk finds is found too, once it is whole (Splunk's
own hourly window sees a bucket in parts, so this can also find a bucket whose parts
each fall short).

A test that only leaves out the other platform's events (`NOT Processes.os="Linux"` in
a Windows rule) is always true for the rule's own events, whether Splunk's add-on sets
`os` or not, so it is dropped; other tests of `os` or `vendor_product` are left out.
A `\/` in a value is left out too, since Splunk's documented escapes do not say how
it reads it.

Other later stages (`eval`, `rex`, `stats`, `eventstats`, `dedup`, `fillnull`, a later
`search`) run as written, in Signalith's [query language](query-language.md), after the
converted filter. Before them, each field they name by Splunk's name is copied from the
field Signalith keeps it as (`eval TargetUserName=user`), and a `tstats` search's own
grouping comes first, with the data model's missing fields as `unknown`, as in the CIM.
A test event is one the rule finds when the filter matches it and the later stages keep a
row for it; a rule ships only when some test event comes through. A rule that counts
(`stats count`, `dc`) keeps no row for one event, so its test is the same event
repeated within 30 seconds, as often as the count needs (`"repeat"` in the test file),
with a field it counts distinct values of different each time (`"vary"`), next to a
smaller repeat that the rule must not find. When none of the events made from the
`where` clause comes through, the tests the later stages make of fields the clause
leaves open (`search process IN (...)` after a `tstats`, `like()` and `match()`, a
`rex` a later stage reads, a `regex` stage, a length a later `where` needs, as in `eval n=len(x) | where n > 512`) are added to the clause to make more
events, and failing that, the program runs from a folder other than System32 (for a
rule that leaves System32 out), a library loads from its program's own folder, or a
share access writes; whether the rule finds each is still what its search, run as
written, says of the event as Signalith stores it. Where the two
languages read a stage differently, the rule is left out: text with a `*` compared with `!=` or under `NOT`,
since Signalith's `where` reads a plain condition as a filter. Without `NOT`, Splunk's
`where action = "*"` compares the text exactly, so it runs as `where in('action', "*")`;
a field in an `IN` list (`where NOT new_ace IN (old_values)`)
is left out, since Splunk's documentation does not say how `IN` reads a field of several
values or none. A later `search` runs as Signalith's `search`, so its terms side by side
are joined by AND, with OR before AND, as in Splunk; a bare term in it is left out. A later
`search field IN (...)` of a field an earlier stage made multivalue (`makemv`) keeps the row
when one of its values is in the list, ignoring case, as in Splunk, and runs as
`where in(mvmap(field, lower(field)), ...)`. So does a later `search` of a list's field
(`search "{}.ResourceAppId"="..."` after `spath`, or `targetResources{}.type`), which
Signalith's `search` would compare as one value: each `field=value` is `in()` over its
values in lower case, with the terms' AND and OR kept. Such a field compared with a `*`,
a number or under `NOT`, two quoted terms with no space between them, and a `stats` that
groups by a field `spath` takes from a JSON list (Splunk groups by each value and does not say how it counts one
that comes twice) are left out. A number a later `where` compares a `rex` group with
(`where tonumber(target_rid) IN (512, 513)`) makes test events whose field ends in it. A macro in an `IN` list
(`` process_name IN (`uacbypass_process_name`) ``) stands for its values, as Splunk expands
macros as text; a list with two values and no comma between them is left out. A
comma right after `(` or right before `)` adds no value (`IN (,"*auth *","*req *",)`). A `where`
that compares two
fields (`where process_name != service_process`) has both quoted, so Signalith compares
the fields' values as Splunk does. A dotted field (`userIdentity.userName`)
is quoted, as Splunk reads it as one field. When the stages end in groups
(`stats ... by`), each group is found once a day. A later `transaction` runs as
Signalith's when Splunk's search window cannot change what it finds: it needs
`startswith=` and `endswith=` (so a transaction is the events from a start to its end,
wherever the window begins) and `maxspan=`, or a later test that keeps only a short
transaction (`where duration<300`, or `eval x=case(duration<300,"TRUE")` then
`search x=TRUE`). Each run then searches that span plus the time since the last run, so
every transaction Splunk finds is whole in some run (one that straddles the edge of
Splunk's hourly window is found too). A later `stats` grouped by a field the transaction
makes multivalue counts the transaction under each value, as Splunk's does; a later
`eval`, `where` or `search` of such a field is left out. Its test events are runs of
events: a start and its end, which it finds, and the end too late, before the start,
alone or of another object, which it does not. A `map` search is left out: it reads
each row's other events (a logon by its `TargetLogonId`) from Splunk's whole window,
however long before. `spath` and the functions Signalith lacks are left out for now;
`internal/detect/packs/splunk/REPORT.md` lists every rule left out and why. The same
CI checks as the SigmaHQ pack run on it.

Rules that pair two events (a program start and the file it writes, the connection it
makes or the program it starts) convert when they `join` a `tstats` subsearch over
another Endpoint node or Sysmon's connections: the detection runs Signalith's `join`,
its subsearch the other node's converted filter followed by its own grouping and later
stages. A `dest` the join reads is the computer that logged the event (`host`), as
security_content's data sources map Sysmon's events. A join is left out when it matches
on a field Signalith keeps differently or Splunk's add-on does not document (a user, a
registry value's data, a connection's `src` or `dest`, a row's `_time`), and so is a
subsearch grouped by time (`_time span=1h`). Sysmon's network connections keep their
process ID for this. Each test of such a rule is an event with the events the
subsearch reads (`"with"` in the test file), on the same host: the pair the rule
finds, and the same event alone, with its partner sharing another value, or with a
partner the subsearch leaves out, which it must not.

Each rule is also checked on the real attack it was written for: Splunk records one
for most rules (`tests.attack_data`, from [attack_data](https://github.com/splunk/attack_data)).
Every recorded Windows event goes through Signalith's parser, and the detection must
read it as the rule does and find the attack (a rule's later stages run over the
recording's matching events together, as they count across events). 715 of the 717 shipped rules with a
Windows recording do, and up to two recorded events each rule finds are kept with
its test events, so CI checks real events too:

```sh
go run ./internal/detect/attackgen -write   # downloads the recordings, about 2 GB
```

On the pack card, **Turn on N TTP rules** is the suggested start.

Licence: the rules are © Splunk Inc. under the
[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) (the licence text
is in the pack folder and the attribution in `NOTICE`). Findings credit the rule's
authors and link to the rule at the pinned commit. Signalith is not affiliated with
or endorsed by Splunk; see [Trademarks](index.md#trademarks).

To refresh the pack from a newer commit:

```sh
git clone https://github.com/splunk/security_content /tmp/security_content
go run ./internal/detect/splunkgen -splunk /tmp/security_content
go test ./internal/detect/ ./internal/splcheck/
```

### Content updates

Pack rules can be updated without a new Signalith release. Every week the Signalith
project rebuilds both packs from the newest SigmaHQ and Splunk rules, runs every check
above on them (in memory and against a real OpenSearch), and publishes the ones that
pass as one signed bundle. A server only installs a bundle that:

- is signed by a key built into Signalith (Ed25519; the keys are in
  `internal/content/trusted.keys`), so a copy from anywhere else is as good as the
  original, and a changed byte is refused;
- is newer than the rules it uses, so an old bundle cannot roll rules back;
- this version of Signalith can read. A rule for something it does not know yet, such as
  a new log source, is left out and counted on the Detections page.

Under the pack cards on the **Detections** page, the line says how new the rules are.
Admins can:

- **Check for updates**: download and install the newest bundle.
- **Upload update…**: for a server without internet access. Download
  `signalith-content.tar.gz` and `signalith-content.tar.gz.sig` from the
  [content release](https://github.com/jrsamsanchez/Signalith/releases/tag/content)
  on another computer, then choose both files together.
- **Use built-in rules**: go back to the rules that came with this version of Signalith.

Rules you turned on stay on, exceptions stay, and new rules start off. A rule that an
update drops stops running; your choices for it come back if it returns.

The **Content pack updates** setting (`detections.content_updates`) can be **Daily**:
the server then checks once a day and installs what it finds. **Content update address**
(`detections.content_url`) points servers at a copy on your own web server; the bundle's
signature is read from the same address plus `.sig`. Each server keeps its update in
`content/` in its detections folder. Upgrading Signalith to a version with newer rules
built in uses those instead of an older update.

From the command line (as the service, with `-c` for the config file):

```sh
signalith content status
signalith content install signalith-content.tar.gz   # reads signalith-content.tar.gz.sig too
signalith content remove
```

Restart Signalith after `install` or `remove` so a running server uses the change, or
upload on the Detections page instead.

## Describe a detection in plain English

On the Detections page, **Describe a detection** turns a sentence such as
"more than 10 failed logins from the same source in 5 minutes" into a whole
rule: the search, how often it runs and how far back it looks, severity,
ATT&CK techniques, risk and how repeats are grouped. The draft opens in the
editor turned off, with a note on how each part was chosen, and is
backtested straight away.

- **Offline by default.** The draft uses the same translator as the Ask
  box, a table of common attack behaviours (brute force, encoded
  PowerShell, log clearing, admin group changes and so on) for severity and
  ATT&CK, and a time window in the sentence ("in 5 minutes", "within an
  hour") for the lookback. Say "high severity" or "priority: low" to set
  the severity yourself.
- **Similar detections.** The draft lists detections already in the
  library that look like the description, so you can turn one of those on
  instead. When the translator understands little and the library has a
  close match, the draft starts as a copy of it.
- **With an AI model.** When an AI model is set up (Settings, AI
  assistant), it writes the draft instead, and the offline draft is used if
  the model fails. The model sees only the description, never your events.
  Every model draft is checked like any detection, and ATT&CK IDs that are
  not in the matrix are dropped.

### Backtest

**Backtest** in the editor runs the detection over the past 7, 30 or 90
days the way its scheduled runs would have, and shows how many findings it
would have raised, a bar per search, the users and systems that raised the
most, and the newest titles. Exceptions and the repeat grouping apply.
Nothing is written: no findings, risk or throttle records.

A backtest runs at most 60 searches, each bounded by the usual search
limits. Each search covers the lookback, or more when the window needs
more than 60 of them; a stats detection is then marked approximate, since
counting over a longer span can cross a threshold that live runs would
not. Each person runs one backtest at a time, the server at most two, and
a backtest stops after 3 minutes with what it has so far.

## Sigma rules

**Import Sigma rule** on the Detections page (or `POST /api/detections/sigma`)
converts a rule and shows the result for review. Supported:

- Log sources `process_creation` (Endpoint), `network_connection` and `firewall`
  (Network_Traffic), `authentication` and Linux `auth` (Authentication), and
  `antivirus` (Malware, where `Signature` maps to `signature` and `Filename` to
  `file_path`), plus the Sysmon and PowerShell log sources in the table above. Other log sources
  search all data and say so. `product: windows` limits the search to Windows event
  logs (and, for the log sources in the table, to their event IDs), and `linux` or
  `macos` leave them out.
- For `ps_script`, `ScriptBlockText` maps to `script_block_text`, `ScriptBlockId` to
  `script_block_id` and `Path` to `script_path`. For `ps_module`, `Payload` maps to
  `script_block_text` and `ContextInfo` to `event_data`; for `ps_classic_start`,
  `ps_classic_provider_start` and `service: powershell-classic`, `Data` maps to
  `event_data`.
- For the Sysmon log sources other than process creation, fields map by log source:
  `TargetFilename` to `file_path`; `TargetObject` to `registry_path`, `Details` to
  `registry_value_data` and `EventType` (`SetValue`, `CreateKey`...) to
  `registry_event_type`; `QueryName` to `query` and `QueryResults` to `answer`;
  `ImageLoaded` to `loaded_file_path` with `Signed`, `Signature` and
  `SignatureStatus`, and the loaded file's `Hashes` to `loaded_file_hash` (for DLLs,
  also `OriginalFileName`, `Description`, `Product` and `Company` to
  `loaded_original_file_name`, `loaded_file_description`, `loaded_file_product` and
  `loaded_file_company`); `SourceImage`, `TargetImage`, `GrantedAccess`, `CallTrace`,
  `StartAddress`, `StartModule` and `StartFunction` for process access and remote
  threads. A field not listed for its log source (such as `CommandLine` in
  `image_load`, which Sysmon does not record there) has no mapping.
- Sysmon and Windows Security field names, mapped to Signalith fields (`Image` to
  `process_path`, or `process_name` for `endswith` a file name; `CommandLine` to
  `process`; `OriginalFileName` to `original_file_name`; `ParentUser`,
  `IntegrityLevel`, `CurrentDirectory`, `Description`, `Product`, `Company`,
  `FileVersion`, `LogonId`, `ProcessGuid`, `SourceHostname`, `Initiated` and more;
  `TargetUserName` to `user`; `IpAddress` to `src`; `SourceIsIpv6` to `src_is_ipv6`;
  `Provider_Name` to `provider`; and so on). In a successful logon (4624) the
  requesting account's `SubjectUserSid` and `SubjectUserName` map to `src_user_sid`
  and `src_user`, and `KeyLength`, `ImpersonationLevel`, `ElevatedToken` and
  `TargetOutboundUserName` to `key_length`, `impersonation_level`, `elevated_token`
  and `target_outbound_user`; a Security service install's (4697) `ClientProcessId`
  and `ParentProcessId` to `client_process_id` and `parent_process_id`. Unmapped
  fields are searched as-is and listed as warnings.
- Modifiers `contains`, `startswith`, `endswith`, `all`, `windash`, `exists`,
  `base64`, `base64offset`, `utf16le`, `utf16be`, `utf16`, `wide`, `cidr` (IPv4 and IPv6) and
  `re` (with `i`, `m` and `s`), searched as a regular expression (`field=~"..."`);
  escaped wildcards (`\*`, a literal asterisk) also become a regular expression;
  lists, `null` and empty values, keyword lists; conditions with `and`, `or`, `not`,
  parentheses, `1 of`, `all of`, `them` and `selection_*` patterns.

Not supported, and reported as an error: other modifiers, regular
expressions with word boundaries (`\b`) or line anchors, and aggregation conditions
(`| count() > 10`).

Strict mode, used for content packs, also refuses anything that would only be
approximated: unmapped fields, keyword (free text) searches, rules with no data
model, and `cased`.

Imported rules start disabled with a 5 minute schedule and 10 minute lookback.

## API

| Method and path | Purpose |
| --- | --- |
| `GET /api/detections` | All detections with their run state: last run, next run, errors, skipped runs and the last Run now. Every server returns the same state |
| `POST /api/detections` | Create (400 lists every problem) |
| `GET`, `PUT`, `DELETE /api/detections/{id}` | Read, save, delete or revert |
| `GET /api/detections/{id}/yaml` | Export as YAML |
| `POST /api/detections/test` | Run an unsaved detection; returns rows and titles, raises nothing |
| `POST /api/detections/draft` | `{"description": "...", "mode": "auto"}`: draft a detection from plain English (admin). `mode` is `auto` (the AI model when one is set up), `rules` (offline) or `ai`. Returns the draft with its steps, warnings and similar detections; nothing is saved |
| `POST /api/detections/backtest` | `{"detection": {...}, "window": "30d"}`: what an unsaved detection would have raised over a past window of 1h to 90d (admin; 429 while one of yours runs). Raises nothing |
| `POST /api/detections/{id}/run` | Run now on this server and raise findings (admin). Searches the lookback up to now, does not change the schedule, and is recorded as the detection's last Run now with who ran it |
| `POST /api/detections/sigma` | Convert a Sigma rule (YAML body, or JSON `{"rule": "..."}`) |
| `GET /api/detections/packs` | Content packs with their rule IDs, how many are on, and counts by severity |
| `GET /api/detections/content` | Content update status: the version in use, whether it is an update, the last check and the `content_updates` mode |
| `POST /api/detections/content/check` | Download and install a newer content update (admin; 502 with the reason when it fails) |
| `POST /api/detections/content/upload` | Install an update from a form with the files `bundle` and `signature` (admin; 409 when it is not newer) |
| `DELETE /api/detections/content` | Remove the update and use the rules built into Signalith (admin) |
| `POST /api/detections/{id}/exceptions` | Add an exception: `{"match": {"host": "web*"}, "for": "7d", "from", "until", "comment"}` (admin) |
| `DELETE /api/detections/{id}/exceptions/{exception}` | Remove an exception (admin) |
| `POST /api/findings/{id}/suppress` | Don't alert on this again: `{"fields": ["host", "user"], "for": "30d", "comment", "update": {"status": "closed", "disposition": "false_positive"}}` adds an exception for the finding's values of those fields and can update the finding (admin) |
| `POST /api/detections/enable` | `{"ids": [...], "enabled": true}`: turn up to 5,000 detections on or off at once (404 and no change if any ID is unknown) |
| `GET /api/coverage` | ATT&CK matrix with coverage; `ics` holds the ATT&CK for ICS matrix when a detection uses an ICS technique |
| `GET /api/findings?status=&severity=&urgency=&owner=&detection=&q=&since=7d&limit=` | Queue |
| `GET`, `PATCH /api/findings/{id}` | Read; update status, owner, severity, disposition, comment |
| `POST /api/findings/bulk` | `{"ids": [...], "update": {...}}` |
| `POST /api/findings` | Raise a finding by hand |
| `GET /api/findings/summary` | Open counts by status, severity and urgency |
| `GET /api/cases?status=&owner=&q=&finding=&limit=` | Cases, most recently updated first, without timelines |
| `POST /api/cases` | `{"title", "description", "severity", "owner", "findings": [...]}`; the title defaults to the first finding's |
| `GET`, `PATCH /api/cases/{id}` | Read with linked findings; update title, description, status, severity, owner, resolution, `comment`, and `close_findings` with `disposition` |
| `POST /api/cases/{id}/findings` | `{"ids": [...]}`: add findings, moving them from another case |
| `DELETE /api/cases/{id}/findings/{finding}` | Remove a finding |
| `POST /api/cases/{id}/entries` | Add `{"kind": "note", "text"}`, `{"kind": "search", "query", "earliest", "latest"}` (runs it and keeps 50 rows) or `{"kind": "event", "event": {...}}` |
| `DELETE /api/cases/{id}/entries/{entry}` | Remove a timeline entry |
| `POST /api/cases/{id}/entities` | `{"field", "value"}` |
| `GET /api/cases/summary` | Open cases, and open cases you own |
| `GET /api/risk?since=24h&type=` | Risk objects by total score, with context |
| `GET /api/risk/object?object=&type=&since=7d` | Risk events for one object |
| `GET`, `PUT /api/lookups/assets`, `/api/lookups/identities` | List or replace a list (CSV body of up to 16 MB and 1,000,000 rows; 400 lists every bad line). On several servers the list is shared, and `PUT` honours `If-Match` (see [Servers](servers.md#shared-detections-dashboards-and-asset-lists)) |
| `GET /api/lookups/assets.csv`, `/api/lookups/identities.csv` | Download the current CSV |
| `GET /api/lookups/context?field=&value=` | Context for one value |

Changes to findings and cases are saved only over the version they were made on, and
made again on a newer one when someone changed the item meanwhile (on any server), so
nothing is lost. When other changes keep getting in first, `PATCH /api/findings/{id}`
and the case changes answer 409 with "Someone else changed this ... at the same moment.
Try again."; nothing was changed. In `POST /api/findings/bulk` such a finding is listed
under `failed` and the others are still updated.
