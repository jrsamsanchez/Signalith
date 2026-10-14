# Detections

A detection is a Signalith query that runs on a schedule. Every row the query
returns becomes a finding, unless the throttle says the same thing was already
raised recently.

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
  [configuration table](https://github.com/jrsamsanchez/Signalith/blob/main/README.md#configuration).
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

Ten built-in detections are risk-only. Two **risk incident** detections (tagged
`risk-incident`) read the Risk data model and raise findings:

- `risk-threshold-exceeded`: total risk of 100 or more for one object in 24 hours.
- `risk-multiple-tactics`: three or more ATT&CK tactics from three or more
  detections on one object in 7 days.

The **threat intel match** detection (`threat-activity`, tagged `threat-intel`)
runs `* | threatmatch` every 5 minutes over the last 10, raises one finding per
indicator and target system per day, and adds 60 risk times the indicator's weight
to `threat_target` and `user`. See [threat-intel.md](threat-intel.md).

Write your own the same way, for example
`datamodel=Risk risk_object_type=user | stats sum(risk_score) as risk_score by risk_object | where risk_score >= 200`.

## Exceptions

An exception tunes a detection without editing its query, like a suppression in
Splunk Enterprise Security: results that match it raise no finding and add no risk,
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

Eight built-in detections read the Malware data model (see
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

Three built-in detections read the Vulnerabilities data model, which Signalith's
own network scans fill (see the **Vulnerabilities** page). All are on by default,
raise findings and add risk to the scanned host. Each raises one finding per host
and CVE (or per host, for Telnet) a week: a nightly scan that finds the same
vulnerability again raises it again only after seven days.

| ID | Severity | Fires when |
| --- | --- | --- |
| `vuln-known-exploited` | high | A scan found a vulnerability in CISA's Known Exploited Vulnerabilities catalog (`known_exploited=true`): attackers are using it |
| `vuln-critical` | medium | A scan found a critical vulnerability (CVSS 9 or higher) that is not known to be exploited yet |
| `vuln-cleartext-remote-login` | low | A scan found Telnet open, which sends passwords in clear text |

To see everything a scan found on a host, search
`datamodel=Vulnerabilities dest=<host>`.

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

**SigmaHQ community rules** (`internal/detect/packs/sigmahq`) holds 1,909 rules from
[SigmaHQ](https://github.com/SigmaHQ/sigma), pinned to one commit: 1,799 Windows rules
for these Sysmon, Security, PowerShell and System log sources, and 110 Linux rules (see
[Linux endpoints](#linux-endpoints-sysmon-for-linux)):

| Sigma log source | Windows events | Data model |
| --- | --- | --- |
| `process_creation` | Sysmon 1, Security 4688 | Endpoint |
| `network_connection` | Sysmon 3 | Network_Traffic |
| `process_access`, `create_remote_thread` | Sysmon 10, 8 | Endpoint |
| `image_load`, `driver_load` | Sysmon 7, 6 | Image_Load |
| `file_event`, `file_delete` | Sysmon 11; 23 and 26 | Filesystem |
| `registry_add`, `registry_delete`, `registry_set`, `registry_event` | Sysmon 12; 12; 13; 12, 13 and 14 | Registry |
| `dns_query` | Sysmon 22 | Network_Resolution |
| `ps_script` | PowerShell 4104 | Script |
| `service: system` | System 7045 (service installed) | Change |
| `service: security` | Security 4624 and 4625 (logons); 4648 (logon with explicit credentials); 4768 and 4769 (Kerberos tickets); 5156 and 5157 (connection allowed or blocked); 4697 (service installed); 4698 (scheduled task created); 4656 and 4661 (handle to an object requested); 4663 (object access); 4657 (registry value modified); 5145 (network share access); 5136 (directory object changed); 4662 (operation on a directory object) | Authentication; Authentication; Authentication; Network_Traffic; Change; Change; Filesystem, Registry or none; Filesystem or Registry; Registry; Filesystem; Change; Change |

A Security log rule names its event's own fields (`TargetUserName`, `LogonType`,
`ServiceFileName`, `ObjectName`), so each one converts for the one Security event it
is about, or for a handle request and the access made with it (4656 and 4663), which
carry the same data; rules about other Security events, or other sets of events, are
left out. Windows
logs these events with **Audit Logon** (4624, 4625, 4648), **Audit Filtering
Platform Connection** (5156, 5157), **Audit Kerberos Authentication
Service** and **Audit Kerberos Service Ticket Operations** (4768, 4769, on domain
controllers), **Audit Security System Extension** (4697), **Audit Other Object Access
Events** (4698), **Audit Handle Manipulation** (4656), **Audit SAM** (4661), **Audit
File System** or **Audit Registry** (4656, 4657, 4663), **Audit Detailed File Share**
(5145), **Audit Directory Service Changes** (5136) and **Audit Directory Service
Access** (4662, on domain controllers) on. Handle requests and registry value changes
are logged only for objects whose auditing (SACL) asks for them. Directory object
types and properties are kept as Windows records them (`%{19195a5b-...}`), so a rule
that compares one to a bare GUID matches only events that already carry the name. An access list
(`AccessList`) is searched by its codes (`%%4417`) and by their names (`WriteData`),
since rules use both. Rules that match a share name with a literal `*`
(`\\*\IPC$`) are left out: Signalith patterns cannot yet say "a literal asterisk".

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

### Splunk Security Content

**Splunk Security Content** (`internal/detect/packs/splunk`) holds 836 Windows and
Linux detections from Splunk's Threat Research Team
([security_content](https://github.com/splunk/security_content)), pinned to one
commit. They are the production TTP and anomaly rules that search the CIM
`Endpoint.Processes`, `Endpoint.Filesystem` and `Endpoint.Registry` nodes with
`tstats`, plus the PowerShell script block rules. Signalith uses the same CIM field
names, so each rule's `where` clause becomes a Signalith filter field for field:

| Splunk node | Windows events | Data model |
| --- | --- | --- |
| `Endpoint.Processes` | Sysmon 1, Security 4688 | Endpoint |
| `Endpoint.Filesystem` | Sysmon 11, 23 and 26 | Filesystem |
| `Endpoint.Registry` | Sysmon 12, 13 and 14 | Registry |
| `` `powershell` EventCode=4104 `` (raw search) | PowerShell 4104 | Script |
| `` `sysmon` EventCode=7 `` (raw search) | Sysmon 7 | Image_Load |
| `` `sysmon` EventCode=8 `` or `10` (raw search) | Sysmon 8 and 10 | Endpoint |
| `` `wineventlog_security` EventCode=4698 `` (raw search) | Security 4698 (scheduled task created) | Change |
| `` `wineventlog_security` EventCode=4663 `` (raw search) | Security 4663 (object access) | Filesystem for a file, Registry for a key |
| `` `wineventlog_system` EventCode=7045 `` (raw search) | System 7045 (service installed) | Change |
| `` `wineventlog_security` EventCode=5136 `` (raw search) | Security 5136 (directory object changed) | Change |
| `` `wineventlog_security` EventCode=5145 `` (raw search) | Security 5145 (network share access) | Filesystem |
| `` `wineventlog_security` EventCode=4768 `` or `4769` (raw search) | Security 4768 and 4769 (Kerberos tickets) | Authentication |
| `Endpoint.Processes` (Sysmon for Linux rules) | Sysmon for Linux 1 | Endpoint |
| `Endpoint.Filesystem` (Sysmon for Linux rules) | Sysmon for Linux 11 and 23 | Filesystem |

The rule files and the macros they use ship unchanged; Signalith converts them when
it starts, reading the search the way Splunk does: `*` is the only wildcard (`?` is
literal, so rules with one are left out), case is ignored, `!=` only matches
when the field is present, `OR` binds tighter than `AND` (`a b OR c` is
`a AND (b OR c)`), and `\\` is one backslash, quoted or not, as in Splunk's search
syntax. Sysmon's user (`NT AUTHORITY\SYSTEM`) compares as the name alone
(`SYSTEM`), the way Splunk's Sysmon add-on reads it. TTP rules raise findings and add risk; anomaly rules only
add risk, as in Splunk ES risk-based alerting. Severity follows the rule's risk score
(TTP: 80 and up critical, 64 high, 30 medium; anomalies low). Each is tagged
`splunk`, the pack name, `ttp` or `anomaly`, and the node, and keeps the rule's
known false positives as triage guidance.

PowerShell rules, and Sysmon image load, remote thread and process access rules,
search the events themselves rather than a data model: their event fields become
Signalith's (`ScriptBlockText` is `script_block_text`, `ImageLoaded` is
`loaded_file_path`, `TargetImage` is `target_process_path`, and so on), and their
`fillnull` and `stats` stages only count the events. (Without `fillnull`, Splunk's
`stats` also drops events that miss one of its `by` fields; Signalith keeps them.) PowerShell rules need script block logging
turned on (**Include PowerShell** on Add data).

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
(`ad_operation`, `%%14674` for a value added). Share access rules (Security 5145)
search `ShareName` (`share_name`), the path inside the share (`RelativeTargetName` is
`share_target`), the client (`IpAddress` is `src`), `AccessMask` and `AccessList`.

Kerberos rules (Security 4768 for a ticket-granting ticket, 4769 for a service
ticket) search the account (`TargetUserName` is `user`), the service
(`ServiceName` is `kerberos_service`), `TicketOptions` (`ticket_options`),
`TicketEncryptionType` (`ticket_encryption_type`, `0x17` for RC4), `Status`
(`kerberos_status`, `0x0` when granted) and the client (`src_ip` is `src`, stored
without the `::ffff:` Windows puts before an IPv4 address). They are stored in
Authentication with `app` `win:kerberos`, action `success` or `failure`.

Service install rules (System 7045, from the Sigma `service: system` log source or
Splunk's `wineventlog_system`) search the service's name (`ServiceName` is
`service_name`), what it runs (`ImagePath` is `service_path`, a path or a whole
command line), `ServiceType` (`service_type`), `StartType` (`service_start_type`) and
`AccountName` (`service_account`). They are stored in Change with `object_category`
`service` and action `created`. The Service Control Manager logs 7045 on every
Windows version without any audit setting, and the Windows agent collects the System
log. Of the System log's events, Signalith reads only service installs; other System
rules (services stopping, for example) are left out of the packs, and importing one
says so.

Registry values that Sysmon writes as `DWORD (0x00000001)` compare as `0x00000001`,
the way Splunk's Sysmon add-on reads them.

A rule is shipped only when its whole search converts exactly (a `tstats` search
whose later stages only rename fields, format times, keep rows that have a field
(`where isnotnull(...)`) or apply the rule's empty `_filter` macro) and, on test events made from its `where` clause and passed through
the real Windows parser, the converted detection agrees with Splunk's reading of the
clause on every event. Searches with `eval`, `rex`, `regex`, `lookup`, and other raw searches
are left out for now; `internal/detect/packs/splunk/REPORT.md` lists
every rule left out and why. The same CI checks as the SigmaHQ pack run on it.

Each rule is also checked on the real attack it was written for: Splunk records one
for most rules (`tests.attack_data`, from [attack_data](https://github.com/splunk/attack_data)).
Every recorded Windows event goes through Signalith's parser, and the detection must
read it as the rule does and find the attack. 715 of the 717 shipped rules with a
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
or endorsed by Splunk.

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
  `script_block_id` and `Path` to `script_path`.
- For the Sysmon log sources other than process creation, fields map by log source:
  `TargetFilename` to `file_path`; `TargetObject` to `registry_path` and `Details` to
  `registry_value_data`; `QueryName` to `query` and `QueryResults` to `answer`;
  `ImageLoaded` to `loaded_file_path` with `Signed`, `Signature` and
  `SignatureStatus`; `SourceImage`, `TargetImage`, `GrantedAccess`, `CallTrace`,
  `StartAddress`, `StartModule` and `StartFunction` for process access and remote
  threads. A field not listed for its log source (such as `Description` in
  `image_load`, which describes the DLL there, not the process) has no mapping.
- Sysmon and Windows Security field names, mapped to Signalith fields (`Image` to
  `process_path`, or `process_name` for `endswith` a file name; `CommandLine` to
  `process`; `OriginalFileName` to `original_file_name`; `ParentUser`,
  `IntegrityLevel`, `CurrentDirectory`, `Description`, `Product`, `Company`,
  `FileVersion`, `LogonId`, `ProcessGuid`, `SourceHostname`, `Initiated` and more;
  `TargetUserName` to `user`; `IpAddress` to `src`; and so on). Unmapped fields are
  searched as-is and listed as warnings.
- Modifiers `contains`, `startswith`, `endswith`, `all`, `windash`, `exists`,
  `base64`, `base64offset`, `utf16le`, `utf16be`, `utf16`, `wide` and `cidr` (IPv4);
  lists, `null` and empty values, keyword lists; conditions with `and`, `or`, `not`,
  parentheses, `1 of`, `all of`, `them` and `selection_*` patterns.

Not supported, and reported as an error: `re`, IPv6 `cidr` and other modifiers,
aggregation conditions (`| count() > 10`), and escaped wildcards.

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
| `GET /api/coverage` | ATT&CK matrix with coverage |
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
| `GET`, `PUT /api/lookups/assets`, `/api/lookups/identities` | List or replace a list (CSV body of up to 16 MB and 1,000,000 rows; 400 lists every bad line) |
| `GET /api/lookups/assets.csv`, `/api/lookups/identities.csv` | Download the current CSV |
| `GET /api/lookups/context?field=&value=` | Context for one value |

Changes to findings and cases are saved only over the version they were made on, and
made again on a newer one when someone changed the item meanwhile (on any server), so
nothing is lost. When other changes keep getting in first, `PATCH /api/findings/{id}`
and the case changes answer 409 with "Someone else changed this ... at the same moment.
Try again."; nothing was changed. In `POST /api/findings/bulk` such a finding is listed
under `failed` and the others are still updated.
