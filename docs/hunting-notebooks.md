# Hunting notebooks

A hunting notebook is a saved hunt: notes and searches in order, each search
with what it found the last time it ran, tagged with the ATT&CK techniques the
hunt looks for. Open **Hunting notebooks** under **Hunt** in the sidebar.

Use one to write down a hypothesis, test it with a few searches, keep what you
found, and hand the whole thing to a teammate or an investigation.

## Starter hunts

Seven hunts come built in, made from the same data models and techniques as the
built-in detections:

| Hunt | ATT&CK techniques |
| --- | --- |
| Password spraying and brute force | T1110.001, T1110.003, T1078 |
| Living off the land | T1218, T1105, T1059, T1566.001 |
| Suspicious PowerShell | T1059.001, T1027, T1105 |
| New persistence | T1053.005, T1543.003, T1136, T1098 |
| Command-and-control beaconing | T1071, T1573, T1571 |
| DNS tunneling and odd lookups | T1071.004, T1048.003, T1568.002 |
| Discovery after a break-in | T1033, T1087, T1082, T1016, T1069 |

Anyone who can sign in can open and run a starter hunt. Starter hunts are
read-only and their results are not saved; analysts choose **Make a copy** to get
a notebook of their own that they can change and that keeps its results.

## Building a notebook

1. Choose **New notebook** (analysts and admins), or copy a starter hunt.
2. **Add note** writes a Markdown note: headings, lists, quotes, code,
   **bold**, _italic_, `code` and links. Use **Preview** to check it.
3. **Add search** adds a titled search in the [query language](query-language.md).
   **Save and run** runs it at once.
4. **Edit details** in the **More** menu sets the title, description and ATT&CK
   technique IDs. The IDs are checked against the ATT&CK catalog.
5. From **Search**, **Add to notebook** puts the current query at the end of a
   notebook you can change, or starts a new one.

Each cell has a menu to edit it, move it up or down, or delete it. Double-click a
note or a query to edit it. Ctrl+Enter (⌘+Enter on a Mac) saves (and runs a search).

## Running

**Run all** runs every search in order; **Run** on a search runs only that one. The
time range at the top applies to all searches (last 24 hours, 7, 30 or 90 days).

Runs use the same limits as the **Search** page: the per-user search slots and the
per-search memory and size limits. A run of a whole notebook stops after 5
minutes, and each search after 2 minutes. A search that fails shows why under it;
the others still run.

What each search found is kept with the notebook: up to 100 rows, with long values
cut and at most 256 KB per search. A result stays only while its query is
unchanged, so an edited search shows "Not run yet" until it runs again. Results are
saved only for people who may change the notebook; anyone else sees their run
without changing what the notebook keeps.

## Sharing

New notebooks are private. The owner or an admin chooses **Share**:

| Sharing | Who can see and run it | Who can change it |
| --- | --- | --- |
| Private | The owner and admins | The owner and admins |
| Team can view | Everyone who can sign in | The owner and admins |
| Team can edit | Everyone who can sign in | Every analyst and admin |

Only the owner and admins can change the sharing or delete a notebook. A notebook
someone cannot see does not appear in their list, and its link answers "not
found". **Copy link** in the **More** menu copies a link to the notebook.

Two people saving the same notebook at once cannot overwrite each other: the
second save is refused with the name of the person who changed it, and **Reload**
picks up their change.

Creating, copying, deleting, sharing and linking notebooks are written to the
[audit log](audit.md).

## From a hunt to a detection or a case

- **Turn into detection** (admins, in a search's menu) opens the detection editor
  with the search's query and the notebook's ATT&CK techniques. The new detection
  starts off, so you can check it before turning it on.
- **Link to case** adds the notebook to an investigation's timeline, with a copy of
  each search's last result. The case links back to the notebook, and the notebook
  lists its cases. **Unlink** takes the notebook off the case's timeline; search
  results already copied there stay.
- **Open in Search** opens a search on the **Search** page with the notebook's
  time range.
- **Download as Markdown** saves the notebook, with its results as tables, as a
  Markdown file. Values from events are escaped so they cannot add HTML or break
  the tables.

## Safety

Notes are shown as plain text with Markdown formatting only: HTML in a note is
shown as text, never run, and links work only for `http`, `https`, `mailto` and
pages of Signalith. Links to other sites open in a new tab with no referrer.

**Download as Markdown** writes notes and titles exactly as their authors wrote them.
Values from events are escaped, so an event cannot add a link, an image or HTML to the
file.

When a user is deleted (on the Users page or through SCIM), their notebooks lose their
owner, so a new account with the same name does not get them. Shared ones stay
shared; private ones are seen only by admins, who can share, copy or delete them.
Unlinking a case and changes made by someone other than the owner are also written
to the audit log.

## API

| Method and path | Role | What it does |
| --- | --- | --- |
| `GET /api/notebooks` | viewer | Notebooks you can see and the starter hunts (`q`, `technique`, `case` filter) |
| `GET /api/notebooks/{id}` | viewer | One notebook, its version and what you may do with it |
| `GET /api/notebooks/{id}/markdown` | viewer | The notebook as Markdown |
| `POST /api/notebooks/{id}/run` | viewer | Run every search, or one (`cell`), with an optional `range` |
| `POST /api/notebooks` | analyst | Create a notebook, or copy one (`from`) |
| `PUT /api/notebooks/{id}` | analyst | Save a notebook; send `If-Match` with the version you read |
| `DELETE /api/notebooks/{id}` | analyst | Delete a notebook (owner or admin) |
| `POST /api/notebooks/{id}/cells` | analyst | Add a note or search at the end |
| `POST /api/notebooks/{id}/cases` | analyst | Link a case (`case_id`, `with_results`) |
| `DELETE /api/notebooks/{id}/cases/{case}` | analyst | Unlink a case |
