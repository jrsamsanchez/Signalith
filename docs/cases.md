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

Each report carries its own **SHA-256**, taken over its data. To check that a report
you were sent is intact, on any computer with Signalith installed (no server needed):

```
signalith report verify signalith-case-20261020-3fa9c1d27b40e865.html
```

It prints `Intact` and exits 0, or says what changed (the report's data, a piece of
evidence, or the page itself) and exits 2. This catches accidental or careless edits;
it does not prove who made the report, since anyone who edits one can work its hashes
out again. Every export is in the [audit log](audit.md) with the report's SHA-256, so
you can match a report to the export that made it.

The API is `GET /api/cases/{id}/report?format=html` or `format=json`.

## Where cases are kept

Cases are stored in OpenSearch in the `<prefix>_cases` index, and every change is
recorded with who made it. The **Investigations** policy on the
[Data retention](retention.md) page can delete resolved and closed cases after a
number of days. Open cases are never deleted, and the findings of a case are kept as
long as the case is.

The cases API is listed with the detections and findings API; see
[API](detections.md#api).
