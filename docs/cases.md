---
description: Group the findings of one incident in a case, with its entities, a timeline of notes, searches and events, and a resolution.
---

# Investigations

A **case** groups the findings that belong to one incident with the work done on it.
Open the **Investigations** tab to see open cases.

!!! note "Arriving with the next release"
    [Attaching files](#attaching-files), [templates and tasks](#templates-and-tasks),
    [exporting a report](#exporting-a-report) and [report keys](#report-keys) are on
    `main` and come with the release after 0.3.2.

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

The **timeline** holds notes, searches, events and [files](#attaching-files).

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

Each pinned event, search snapshot and attached file records a **SHA-256** of its content when it is
added, shown under it. If the stored copy is ever changed outside Signalith, the case
says so in red, so the evidence can be trusted in a report.

A case holds at most 1,000 timeline entries and 500 findings.

## Attaching files

**File** on the timeline (analysts and admins) attaches a file to the case, such as a
screenshot, a suspicious email with its headers or a tool's output, with an optional
note. Signalith records the file's **SHA-256** when it is added and shows it on the
timeline; the case's [report](#exporting-a-report) lists each file's name and SHA-256
(not the file itself), so whoever has a copy of the file can check it is the same one.

- A file is at most 10 MiB, and a case holds at most 25 files and 100 MiB of them.
- Files are only ever downloaded, never opened in the browser by Signalith, whatever
  they hold. Treat a file someone attached as you would an email attachment: it may be
  the malware you are investigating.
- Every upload and download is in the [audit log](audit.md), with the file's SHA-256.
- Like notes and pinned events, analysts remove only the files they attached; admins
  can remove any. Removing a file from the timeline deletes it.
- A few files at a time are sent or received: a download or upload past that is
  refused for a moment (`429`) and can be tried again.
- Files are kept in OpenSearch in the `<prefix>_case_files` index. Every
  [Data retention](retention.md) run deletes the files no case names any more: those of
  deleted cases, and any whose timeline entry is gone, once they are a day old. A report lists whether each
  file is still stored as it was attached; a download checks its bytes, and says so in
  an `X-Signalith-Evidence: changed` header if they changed.
- OpenSearch must accept requests of about 14 MiB to store a 10 MiB file
  (`http.max_content_length`, 100 MB by default; some hosted services allow only
  10 MiB on their smallest instances).

The APIs are `POST /api/cases/{id}/files` (a `multipart/form-data` form with the file
in `file` and an optional note in `text`) and `GET /api/cases/{id}/files/{file}`.

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
- **Signed with a revoked key**: the signature matches, but that key was revoked
  because it may have leaked (below). The report does not verify: someone who had the
  key could have made or backdated it, so confirm it another way, such as the export
  in the [audit log](audit.md).
- **Did not verify**: the report is not signed, the signature does not match, the key
  is not one this server used, the report is another tenant's, or the report, a piece
  of evidence or the page was edited.

On any computer with Signalith installed (no server needed), download the key list
with **Download** next to **Report keys** in the same window, then:

```
signalith report verify -keys signalith-report-keys.json signalith-case-20261020-3fa9c1d27b40e865.html
```

On a server on its own, `signalith report verify <file>` uses the server's own keys;
on a server of a cluster, pass `-keys`, since the cluster's list is in its shared
settings. `-tenant <prefix>` also requires the report to be that tenant's; the
command prints the tenant either way. It exits:

| Code | Meaning |
| --- | --- |
| 0 | `Verified`: signed with one of the keys, and nothing changed |
| 2 | `CHANGED`: edited, not signed, or signed with a key not in the list |
| 3 | `REVOKED`: signed with a revoked key |
| 4 | Intact, but its signature was not checked (no key list) or it is not signed |
| 1 | The file cannot be read |

Without a key list it can only check that the report is intact, which does not prove
who made it, since anyone who edits a report can work its hashes out again; it then
says the report "carries a signature claiming" a key, and exits 4 (0 with
`-allow-unsigned`). A server exports reports unsigned when it has no report key, or
its key was revoked; they are only ever called intact. Every export and every check is in the [audit log](audit.md), with the
report's SHA-256 and the key, so you can match a report to the export that made it.

## Report keys

The report key is never stored: it is made again from the cluster key (a cluster) or
the master key (a server on its own; see [Encryption](encryption.md#the-master-key)).
What is kept is the public half of each report key, when it was first used, and
whether it was retired or revoked, so older reports still verify:

- **Current** signs new reports.
- **Retired**: a newer key took over, after the master key or cluster key was
  changed. Its reports still verify.
- **Revoked**: it may have leaked. Its reports no longer verify, and it signs no
  more: the server exports reports unsigned until the master key or cluster key is
  changed.

A server on its own keeps the list in `report-keys.json` in its state folder, which
[backups](backup.md) include; a cluster keeps it in its shared settings. When a
server joins a cluster, its own keys are added to the cluster's list as retired.

When a master key or cluster key may have leaked, change it (`signalith secrets
rotate-master`, or `signalith cluster rotate-key`) and then revoke the report key it
made, since changing a key does not revoke anything by itself. An admin does that on
the **Investigations** page (**Check a report**, then **Revoke…** on the key; on a
cluster with tenants, only the provider's admins, since every tenant shares the key),
or on a server on its own with:

```
signalith report keys
signalith report revoke-key -reason "the master key was in a leaked backup" 3fa9c1d27b40
```

The APIs are `POST /api/cases/reports/verify` (the file as the request body),
`GET /api/cases/reports/keys` (a tenant's users see the keys, not who revoked one or
why), and `POST /api/cases/reports/keys/{id}/revoke` (admins, with
`{"reason": "..."}`).

## Where cases are kept

Cases are stored in OpenSearch in the `<prefix>_cases` index, and every change is
recorded with who made it. The **Investigations** policy on the
[Data retention](retention.md) page can delete resolved and closed cases after a
number of days. Open cases are never deleted, and the findings of a case are kept as
long as the case is.

The cases API is listed with the detections and findings API; see
[API](detections.md#api).
