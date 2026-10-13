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
  schedule (at least 1 minute, at most 5); the Detections page then shows **Timed out**,
  and the next run starts on schedule. Narrow the query or shorten `lookback` so it
  finishes in time.
- When every worker is busy, a due detection waits. Its next run then searches on from
  where its last successful run stopped, not just its `lookback`, so the events in
  between are still searched; failed and timed-out runs are made up the same way. It
  catches up at most ten lookbacks back (at least 1 hour, at most 24 hours); anything
  older is counted as not searched. The Detections page shows late runs, timeouts and
  time not searched under **Behind schedule**, and the Health page warns while a
  detection waits longer than its schedule. Where a detection stopped is kept in
  memory, so after a restart, or once it is turned back on, it searches its `lookback`.

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

**SigmaHQ community rules** (`internal/detect/packs/sigmahq`) holds 1,695 Windows
rules from [SigmaHQ](https://github.com/SigmaHQ/sigma), pinned to one commit, for
these Sysmon, Security and PowerShell log sources:

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

Each pack rule only searches its own log source's event IDs, since several kinds of
event share a data model (a process creation and a process access are both Endpoint).
Sysmon only records the events its configuration asks for, so a rule fires only when
your Sysmon configuration logs that kind of event.

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
| `GET /api/detections` | All detections with last-run state |
| `POST /api/detections` | Create (400 lists every problem) |
| `GET`, `PUT`, `DELETE /api/detections/{id}` | Read, save, delete or revert |
| `GET /api/detections/{id}/yaml` | Export as YAML |
| `POST /api/detections/test` | Run an unsaved detection; returns rows and titles, raises nothing |
| `POST /api/detections/{id}/run` | Run now and raise findings |
| `POST /api/detections/sigma` | Convert a Sigma rule (YAML body, or JSON `{"rule": "..."}`) |
| `GET /api/detections/packs` | Content packs with their rule IDs, how many are on, and counts by severity |
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
