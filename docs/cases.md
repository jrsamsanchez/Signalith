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

## Where cases are kept

Cases are stored in OpenSearch in the `<prefix>_cases` index, and every change is
recorded with who made it. The **Investigations** policy on the
[Data retention](retention.md) page can delete resolved and closed cases after a
number of days. Open cases are never deleted, and the findings of a case are kept as
long as the case is.

The cases API is listed with the detections and findings API; see
[API](detections.md#api).
