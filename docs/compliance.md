# Compliance

The **Compliance** page (under **Detect & respond**) shows where Signalith gives
evidence for the controls of common security frameworks, what is still missing and how
to fix it, and exports a report you can hand an auditor.

It covers six frameworks:

| Framework | Version | Controls mapped |
| --- | --- | --- |
| NIST SP 800-53 | Rev. 5 | 30 |
| CIS Controls | v8 | 20 |
| PCI DSS | v4.0 | 27 |
| ISO/IEC 27001 | 2022 (Annex A) | 13 |
| HIPAA Security Rule | 45 CFR 164 Subpart C | 8 |
| SOC 2 | Trust Services Criteria 2017 (revised 2022) | 6 |

Only controls a SIEM can give evidence for are listed: logging, monitoring and
detection, incident handling, configuration and vulnerability checks, and protecting the
logs themselves. Controls about, say, physical security or HR are outside what Signalith
can see, so they are left out rather than shown as gaps.

Every signed-in user can open the page and export reports, so an auditor can work with a
**Viewer** account. Only admins can add notes to controls.

## How a control gets its status

Each control is backed by one or more **evidence sources**: things Signalith can check
on its own, right now. For example:

- **Data arriving**: authentication, process, network, DNS, account change, antivirus,
  file integrity and inventory events in the last 7 days. Sample data never counts.
- **Detections**: enabled detections that match the control (sign-in attacks, privilege
  misuse, malware, network intrusions, persistence), with the data they read arriving
  and scheduled detections turned on.
- **Configuration checks**: the [osquery checks](endpoints.md) whose NIST SP 800-53
  references match the control, and how many pass and fail across your hosts.
- **Vulnerability scanning**: a [scan](vulnerabilities.md) finished in the last month
  (in the last three months counts as partial).
- **Findings reviewed**: no new finding has waited more than 7 days.
- **Settings**: [data retention](retention.md) (90 days searchable, a year kept, the
  disk guard), [notifications](notifications.md), [response actions](response-actions.md),
  [threat intel feeds](threat-intel.md), named [user accounts](users.md) and HTTPS.
- **Built in**: things Signalith always does, such as storing event times in UTC with
  the original text.

A control shows:

- **Evidence** when every source behind it is in place,
- **Partial** when some are, or when configuration checks fail on some hosts,
- **Gap** when none are.

Open a control to see each source, what Signalith found, and what to do about anything
missing, with a link to the page where you fix it. The **Evidence sources** tab lists
every source once, missing ones first, ordered by how many controls each one affects, so
the top of that list is where a fix raises coverage most.

The **coverage score** on each framework counts controls with evidence as 1 and partial
ones as ½, out of the controls that apply.

The page reads the system again when you open it and caches the result for a minute.
Click the refresh button to check again at once.

### Tag your own detections

A detection you write can name the controls it supports with a tag of the form
`<framework>:<control>`, for example:

```yaml
tags:
  - pci-dss:10.2.1.4
  - nist-800-53:AC-7
```

Framework IDs are `nist-800-53`, `cis-v8`, `pci-dss`, `iso-27001`, `hipaa` and `soc2`.
Tagged detections are listed on the control, and count as its detection evidence.

## Controls handled elsewhere

Some controls are met by something Signalith cannot see: clock synchronization checked
by another tool, an incident response plan kept in a wiki. An admin can open the control
and choose:

- **Handled outside Signalith**: the control counts as covered.
- **Not applicable**: the control does not apply to you and is left out of the score.

Either one needs a note saying how the control is handled or why it does not apply. The
note, who wrote it and when appear on the page and in every report, next to what
Signalith's own evidence would say. Remove the note to go back to the evidence alone.

Notes are kept in `compliance-notes.json` in the server's state folder.

## Evidence reports

Each framework has two exports:

- **CSV**: one row per control and piece of evidence, with the status, the details, the
  NIST SP 800-53 controls it lines up with, any note, the server and the time. Cells
  that start with `=`, `+`, `-` or `@` are prefixed with `'` so spreadsheet programs do
  not run them as formulas.
- **Report (PDF)**: a report page that opens in a new tab. Use your browser's
  **Print** command and choose **Save as PDF**. It has the score, a summary and every
  control grouped as in the framework, with the evidence, failing checks, detections and
  notes.

Over the API (any role):

```
GET /api/compliance
GET /api/compliance/export?framework=pci-dss&format=csv
GET /api/compliance/export?framework=pci-dss&format=html
```

Admins add, change or remove a note with:

```
PUT /api/compliance/notes
{"framework": "pci-dss", "control": "10.6.1", "status": "external", "note": "..."}
```

`status` is `external`, `na`, or empty to remove the note.

## Where the mapping comes from

The mapping is Signalith's own work, under the project's Apache 2.0 licence, in
[`internal/compliance/frameworks.yaml`](https://github.com/jrsamsanchez/Signalith/blob/main/internal/compliance/frameworks.yaml).
Each control lists the evidence sources that support it and the NIST SP 800-53 controls
it lines up with.

- NIST SP 800-53 and the HIPAA Security Rule are US government works; their official
  control titles are used.
- For CIS Controls, PCI DSS, ISO/IEC 27001 and SOC 2, only the control and requirement
  numbers are used. The titles are Signalith's own short summaries; read the standard
  for its text.
- The configuration checks follow the [SCAP Security Guide](https://github.com/ComplianceAsCode/content)
  (BSD-3-Clause) and carry the NIST SP 800-53 references of the rules they are based
  on. No CIS Benchmark text is used.

The mapping shows where Signalith gives evidence. It does not by itself make a system
compliant, and your assessor decides what evidence is enough.

## Limits

- Compliance reads this server's settings. With [several servers](servers.md), the
  notes on controls are kept on the server where they were written.
- Event counts cover the last 7 days. A source that sends rarely can show as missing.
- The HIPAA and SOC 2 lists are short on purpose: most of their requirements are about
  policies and people, which no SIEM can show.
