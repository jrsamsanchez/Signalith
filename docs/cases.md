---
description: Group the findings of one incident in a case, with its entities, a timeline of notes, searches and events, and a resolution.
---

# Investigations

A **case** groups the findings that belong to one incident with the work done on it.
Open the **Investigations** tab to see open cases.

## Starting a case

- Start a case with **New case**, or select findings on the **Findings** page and
  choose **Add to case**.
- A finding belongs to one case. Adding it to another moves it.
- The case takes the highest urgency of its findings. It collects their users, hosts
  and IPs as **entities**, each a click away from a search.
- **Open an investigation** on the [attack storyline](storyline.md) opens a case
  holding every finding in the story, and a [playbook](playbooks.md) can open one
  when a detection fires.

## The timeline

The **timeline** holds notes, searches and events.

- **Add a search** on the case (or **Add to case** on the Search page) runs the query
  and keeps a snapshot of its first 50 rows. The case still shows what you saw after
  the events age out.
- In search results, click a cell and choose **Pin this event to a case** to keep the
  full event.
- [Investigate with AI](investigate.md) can save its write-up to the case as a note
  (**Save to case**).
- A [hunting notebook](hunting-notebooks.md#from-a-hunt-to-a-detection-or-a-case) can
  be linked to the case, with its results.
- [Response actions](response-actions.md) run from the case with **Respond** are
  noted on its timeline.

Each pinned event and search snapshot records a **SHA-256** of its content when it is
added, shown under it. If the stored copy is ever changed outside Signalith, the case
says so in red, so the evidence can be trusted in a report.

A case holds at most 1,000 timeline entries and 500 findings.

## Templates and tasks

**New case** can start from a template: it sets the severity, fills the
description, and adds the tasks most investigations of that kind need, such as
"Disable the account or end its sessions" for an account compromise. Signalith comes
with Phishing, Account compromise, Malware on a host, Ransomware, and Insider or data
loss. Admins add their own with **Templates** on the Investigations page.

**Tasks** are the case's checklist. Tick one off when it is done; the case records
who did it and when. Give a task an owner to split the work, add your own with
**Add task**, or add a template's tasks to a case that already exists. A case holds at
most 100 tasks.

## Working a case

Set status, severity and owner as you work. Cases use the same statuses as findings:
`new`, `in_progress`, `pending`, `resolved` and `closed`.

When you resolve or close a case, write a resolution. You can also close all of its
open findings with one disposition.

A case can have a ticket in Jira or ServiceNow that stays in step with it; see
[Ticketing](ticketing.md).

## Exporting a report

**Export** on a case (analysts and admins) downloads its report, to attach to a
ticket, hand to an auditor or keep with legal records:

- **Report page** (`.html`) is one file that opens in any browser and prints
  cleanly. It holds the case's details, entities, tasks, linked findings, timeline,
  changes, and a table of every piece of evidence with its SHA-256 and whether it still
  matches. The page loads nothing from anywhere and runs no scripts.
- **Report data** (`.json`) is the same report for tools.

Linked findings are listed without their raw event; pin an event to the timeline to
include it. Findings that retention has already removed are listed by ID.

The API is `GET /api/cases/{id}/report?format=html` or `format=json`.

Each report carries its own **SHA-256**, taken over its data, and is **signed** with
the server's report key (Ed25519): the page shows "Signed with report key" and the
key's ID. The signature covers the exact report data, so a report changed after it was
exported, even with its hashes worked out again, no longer verifies.

## Checking a report

On the **Investigations** page, **Check a report** (analysts and admins) takes a
report page or data file and says whether it verifies:

- **Verified**: the signature matches one of this server's report keys, and the
  report, its evidence and the page are as exported. It also names the key and its
  status.
- **Signed with a key that may have leaked**: the signature matches, but an admin
  revoked that key (below). Someone who had the key could have made or backdated the
  report, so confirm it another way, such as the export in the [audit log](audit.md).
- **Changed**: the signature does not match, the key is not one this server used, or
  the report, a piece of evidence or the page was edited.

On any computer with Signalith installed (no server needed), download the key list
with **Download keys** in the same window, then:

```
signalith report verify -keys signalith-report-keys.json signalith-case-20261020-3fa9c1d27b40e865.html
```

On the server itself, `signalith report verify <file>` uses the server's own keys.
It prints `Verified` and exits 0, or says what changed and exits 2. Without a key
list it checks only that the report is intact (`Intact`), which does not prove who
made it, since anyone who edits a report can work its hashes out again. A report from
a server whose signing was not set up says **Not signed**, and is only ever called
intact. Every export and every check is in the [audit log](audit.md), with the
report's SHA-256 and the key, so you can match a report to the export that made it.

## Report keys

The report key is never stored: it is made again from the cluster key (a cluster) or
the master key (a server on its own; see [Encryption](encryption.md#the-master-key)).
What is kept is the public half of each report key, when it was first used, and
whether it was retired or revoked, so older reports still verify:

- **Current** signs new reports.
- **Retired**: a newer key took over, after the master key or cluster key was
  changed. Its reports still verify.
- **Revoked**: it may have leaked. Its reports still check, with a warning.

A server on its own keeps the list in `report-keys.json` in its state folder, which
[backups](backup.md) include; a cluster keeps it in its shared settings. When a
server joins a cluster, its own keys are added to the cluster's list as retired.

When a master key or cluster key may have leaked, change it (`signalith secrets
rotate-master`, or `signalith cluster rotate-key`) and then revoke the report key it
made, since changing a key does not revoke anything by itself. An admin does that on
the **Investigations** page (**Check a report**, then **Revoke…** on the key), or on
a server on its own with:

```
signalith report keys
signalith report revoke-key -reason "the master key was in a leaked backup" 3fa9c1d27b40
```

The APIs are `POST /api/cases/reports/verify` (the file as the request body),
`GET /api/cases/reports/keys`, and `POST /api/cases/reports/keys/{id}/revoke`
(admins, with `{"reason": "..."}`).

## Where cases are kept

Cases are stored in OpenSearch in the `<prefix>_cases` index, and every change is
recorded with who made it. The **Investigations** policy on the
[Data retention](retention.md) page can delete resolved and closed cases after a
number of days. Open cases are never deleted, and the findings of a case are kept as
long as the case is.

The cases API is listed with the detections and findings API; see
[API](detections.md#api).
