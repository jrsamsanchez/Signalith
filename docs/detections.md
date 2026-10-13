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
- Turning a built-in or pack detection on or off without other changes only writes
  a small file to `detections/state/<id>.yaml` (`enabled: true` or `false`), so the
  rule itself keeps coming from the binary and gets fixes on upgrade.

You can edit detections in the UI or drop YAML files into the folder and restart.
`signalith validate` checks every file and reports problems with the field to fix;
a broken file is skipped at startup and logged, so it never stops the server.

## Format

```yaml
id: auth-brute-force                    # 3-64 lowercase letters, digits, - or _
title: Brute force against $dest$ from $src$   # $field$ is filled from the result row
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

**SigmaHQ community rules** (`internal/detect/packs/sigmahq`) holds 1,055 Windows
process creation and network connection rules from [SigmaHQ](https://github.com/SigmaHQ/sigma),
pinned to one commit. A rule is only shipped when:

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
  `file_path`). Other log sources search all data and say so. `product: windows`
  limits the search to Windows event logs, and `linux` or `macos` leave them out.
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
