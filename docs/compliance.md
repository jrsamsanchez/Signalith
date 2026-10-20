# Compliance

The **Compliance** page (under **Detect & respond**) shows where Signalith gives
evidence for the controls of common security frameworks, what is still missing and how
to fix it, and exports a report you can hand an auditor.

It covers eight frameworks:

| Framework | Version | Controls mapped |
| --- | --- | --- |
| NIST SP 800-53 | Rev. 5 | 30 |
| CIS Controls | v8 | 20 |
| PCI DSS | v4.0 | 27 |
| ISO/IEC 27001 | 2022 (Annex A) | 13 |
| HIPAA Security Rule | 45 CFR 164 Subpart C | 8 |
| SOC 2 | Trust Services Criteria 2017 (revised 2022) | 6 |
| NIS2 Directive | (EU) 2022/2555 | 14 |
| GDPR | (EU) 2016/679 | 11 |

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
  references match the control, and how many pass and fail across your hosts. Each
  failing check names the hosts it fails on (up to 25, then a count); analysts and
  admins can click a host to open it as on the Endpoints page.
- **Vulnerability scanning**: a [scan](vulnerabilities.md) finished in the last month
  (in the last three months counts as partial).
- **Findings reviewed**: no new finding has waited more than 7 days.
- **Settings**: [data retention](retention.md) (90 days searchable, a year kept, the
  disk guard), [notifications](notifications.md), [response actions](response-actions.md),
  [threat intel feeds](threat-intel.md), named [user accounts](users.md) and HTTPS.
- **Settings**: also [two-step sign-in](users.md) required for everyone, and event data
  deleted after a set time instead of kept forever.
- **Built in**: things Signalith always does, such as storing event times in UTC with
  the original text, and its own [audit trail](audit.md).

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

Framework IDs are `nist-800-53`, `cis-v8`, `pci-dss`, `iso-27001`, `hipaa`, `soc2`, `nis2`
and `gdpr`, for example `nis2:23(4)(a)` or `gdpr:33(1)`.
Tagged detections are listed on the control, and count as its detection evidence.

## NIS2 and the GDPR

Both are EU law, and most of what they ask is about governance: management
responsibility, policies, training, contracts, and the reports and notices themselves.
Signalith cannot do those for you, and a good score here does not mean you comply. What
it gives is evidence for the technical parts, and the records you need to act on time.

**NIS2** (Directive (EU) 2022/2555) covers:

- the **Article 21** risk-management measures a SIEM can show: incident handling,
  vulnerability handling, assessing whether measures work, basic cyber hygiene,
  encryption, access control and asset management, and multi-factor authentication;
- the **Article 23** reporting deadlines: an early warning within 24 hours of becoming
  aware of a significant incident, an incident notification within 72 hours, and a final
  report within one month. Detections and notifications make you aware quickly, and an
  [investigation](investigate.md) keeps the timeline, findings, notes and evidence to write the
  reports from;
- for digital providers covered by Commission Implementing Regulation (EU) 2024/2690,
  **monitoring and logging** (section 3.2 of its Annex) and **incident response**
  (section 3.5).

Business continuity, supply chain security and training (Article 21(2)(c), (d) and (g)
in part) are left out. National laws that transpose NIS2 can add to it; check yours.

**The GDPR** (Regulation (EU) 2016/679) is in two parts:

- **Personal data in your logs.** Logs hold personal data: user names, IP addresses, host
  names, sometimes email addresses. These controls check how Signalith itself treats
  them: access limited to named accounts with roles (Article 5(1)(f)), two-step sign-in
  and limited access by default (Article 25), encryption in transit and of the secrets
  it keeps, its own audit trail of who did what (Article 5(2)), and event data deleted
  after a set time rather than kept forever (Article 5(1)(e)). Set the retention to what
  your purposes and legal duties need: NIS2, PCI DSS and your own incident handling may
  call for a year, while data protection asks for no longer than needed.
- **Security of processing and breaches** for your other systems: Article 32 (encryption,
  monitoring, regular testing) and Articles 33 and 34 (noticing a personal data breach in
  time to tell the supervisory authority within 72 hours, describing it, documenting every
  breach, and finding the people affected).

Lawful basis, records of processing activities (Article 30), data subject requests and the
notifications themselves are outside what Signalith can see, so they are not listed. Your
data protection officer decides what is enough. Signalith does not pseudonymize events,
and its audit trail records changes and sign-ins, not every search.

## Controls handled elsewhere

Some controls are met by something Signalith cannot see: clock synchronization checked
by another tool, an incident response plan kept in a wiki. An admin can open the control
and choose:

- **Handled outside Signalith**: the control counts as covered.
- **Not applicable**: the control does not apply to you and is left out of the score.

Either one needs a note saying how the control is handled or why it does not apply. The
note, who wrote it and when appear on the page and in every report, next to what
Signalith's own evidence would say. Remove the note to go back to the evidence alone.

Notes are kept in `compliance-notes.json` in the server's state folder. With
[several servers](servers.md#shared-detections-dashboards-and-asset-lists), they are kept
in the shared settings instead, so every server shows the same notes.

## Evidence reports

Each framework has two exports:

- **CSV**: one row per control and piece of evidence, with the status, the details, the
  NIST SP 800-53 controls it lines up with, any note, the server and the time. Cells
  that start with `=`, `+`, `-` or `@` are prefixed with `'` so spreadsheet programs do
  not run them as formulas.
- **Report (PDF)**: a report page that opens in a new tab. Use your browser's
  **Print** command and choose **Save as PDF**. It has the score, a summary and every
  control grouped as in the framework, with the evidence, failing checks and their hosts, detections and
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
  numbers are used. For NIS2 and the GDPR, article numbers are used, with Signalith's
  own short titles; the official texts are on [EUR-Lex](https://eur-lex.europa.eu/). The titles are Signalith's own short summaries; read the standard
  for its text.
- The configuration checks follow the [SCAP Security Guide](https://github.com/ComplianceAsCode/content)
  (BSD-3-Clause) and carry the NIST SP 800-53 references of the rules they are based
  on. No CIS Benchmark text is used.

The mapping shows where Signalith gives evidence. It does not by itself make a system
compliant, and your assessor decides what evidence is enough.

## Limits

- Compliance reads this server's settings. With [several servers](servers.md), give
  every server the same settings (most of them are [shared](settings.md#settings-on-several-servers)).
- Event counts cover the last 7 days. A source that sends rarely can show as missing.
- The HIPAA, SOC 2, NIS2 and GDPR lists are short on purpose: most of their requirements are about
  policies and people, which no SIEM can show.
