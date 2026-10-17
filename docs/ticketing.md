# Ticketing: Jira and ServiceNow

Signalith can open a ticket for a case in Jira (Cloud or Data Center) or ServiceNow, and
keep the two in step after that. A case's status, title, severity and notes go to the
ticket. The ticket's comments and status come back to the case. Admins set up the
connections on the **Ticketing** tab of **Settings**. Analysts open tickets from a case.

Signalith polls the systems' REST APIs every minute. It does not wait for their webhooks,
so it works when Jira Cloud or ServiceNow cannot reach Signalith, and it opens no way in.

## Add a connection

On **Ticketing**, choose **Add connection** and pick **Jira** or **ServiceNow**. When there
are no connections yet, the page offers both itself. Use a dedicated account for each
connection: tickets and comments show up as written by it, and its permissions bound
what Signalith can do.

Each connection has **Test**. It signs in with the settings in the dialog, before you save
them, checks the project or table, and says what it found or what is wrong, in plain
words: the token was refused, the project does not exist, the certificate is not trusted,
and so on.

### Jira Cloud

1. Sign in to Atlassian as the account tickets should come from. Create an API token at
   **id.atlassian.com**, **Security**, **API tokens**.
2. In Signalith, choose **Add connection**, then **Jira**, then **Cloud: email and API
   token**.
3. Enter the site address (`https://example.atlassian.net`), the account's email address,
   the API token, and the **project key** (such as `SEC`). The issue type is `Task` unless you
   enter another.
4. Choose **Test**, then **Add connection**.

The account needs the project permissions **Browse projects**, **Create issues**,
**Edit issues**, **Transition issues** and **Add comments**. Signalith uses REST API version
3 and writes descriptions and comments in Atlassian Document Format.

### Jira Data Center or Server

1. In Jira, open your profile, then **Personal Access Tokens**, and create a token for the
   account tickets should come from.
2. In Signalith, choose **Jira**, then **Data Center: access token**. Enter the address you
   open Jira at, with its context path if it has one (`https://jira.example.com/jira`), the
   token and the project key.

Signalith uses REST API version 2 and writes descriptions and comments as plain text.

### ServiceNow

1. Create an integration user, such as `signalith.integration`, with the `itil` role.
   For comments to come back to cases, it also needs read access to the
   `sys_journal_field` table. **Test** checks both.
2. In Signalith, choose **ServiceNow**. Enter the instance address
   (`https://example.service-now.com`) and either:
   - **User name and password** of the integration user, or
   - **OAuth client**: the client ID and secret of an application registered in
     **System OAuth**, **Application Registry**, with the client credentials grant allowed
     (`glide.oauth.inbound.client.credential.grant_type.enabled`). Signalith asks
     `/oauth_token.do` for a token and keeps it until a minute before it expires.
3. The table is `incident` unless you enter another. Case notes go to **Work notes**,
   which only the people working the ticket see, or to **Additional comments**, which the
   caller sees too.

Under **Mapping and advanced** you can set the **close code** that resolving or closing
a case sets (default `Solution provided`; it must be one your instance offers), and an
optional **caller** and **assignment group** for new tickets, as `sys_id`s.

## Open a ticket from a case

On a case, the **Tickets** card lists its tickets and offers **Open ticket** to analysts and
admins. Pick the connection when there are several. The ticket opens at once, with a link
to it. A case has at most one ticket in each connection. If a ticket could not be opened,
the card says why and offers **Try again**.

A new ticket gets:

| Field | From the case |
| --- | --- |
| Summary (Jira), short description (ServiceNow) | The case's title (cut to 250 or 160 characters) |
| Description | "Opened from Signalith case …", the severity and status, a link to the case, and the case's description |
| Priority (Jira) | The case's severity, mapped: Critical to Highest, High to High, Medium to Medium, Low to Low, Informational to Lowest. You can change the names under **Mapping and advanced**, or turn it off. When the project's screens have no Priority field, Signalith leaves it out by itself. |
| Impact and urgency (ServiceNow) | Critical 1 and 1, High 1 and 2, Medium 2 and 2, Low 2 and 3, Informational 3 and 3, which make priorities 1 to 5 |
| Label (Jira), correlation ID (ServiceNow) | `signalith-<case id>` or `signalith:<case id>`, so a ticket opened by a server that stopped before recording it is found rather than opened twice (see [Which server syncs](#which-server-syncs)) |

That is all a ticket ever gets: the title, severity, status, description, notes and a link
to the case. It never gets events, search results or findings, so data stays in Signalith.

The link is `<server.public_url>/#cases?id=<case>`. Set `server.public_url` on the
**Settings** page, or tickets have no link back.

### Open tickets by themselves

Tick **Open a ticket for every new case** on a connection, and pick the least severity
(High and above by default). Only cases opened from when you turn it on get one, so turning
it on does not open tickets for old cases. Cases made by the sample data never get one. If
opening one fails, Signalith tries again twice, 5 and then 10 minutes later.

## What stays in step

Every minute, the server that runs the background jobs asks each system which of its
tickets changed, finds the cases with tickets that changed, and brings each pair in step.

| On the case | On the ticket |
| --- | --- |
| A new note | A new comment (Jira) or work note (ServiceNow) that starts with `[Signalith] <author>:` |
| A new status | The ticket moves to the mapped status (below) |
| Resolved or closed with a resolution | ServiceNow gets the close code and the resolution as close notes. Jira gets the resolution as a comment. |
| A new title or severity | The summary and priority, or short description, impact and urgency |
| A new note by `jira:Dana Scully` or `servicenow:beth.anglin` | A comment on the ticket by someone other than Signalith's account |
| A new status | The ticket's new status, mapped back |

A note that came from a ticket shows on the case's timeline with the system's name. Turn
off **Status** or **Notes and comments** on a connection to keep only one of them in step.

Comments come back within limits, so a ticket flooded with them cannot fill the case: each
is cut to 4 KB, a pass adds at most 50 of a ticket's comments (the rest come on the next
passes), and at most 200 of a ticket's comments are ever added to its case. After that, and
when the case's timeline is within 100 entries of its limit of 1,000, new comments are left
out, and the case's Tickets card says so; those 100 entries are kept for analysts' notes.

### Statuses

| Case status | Jira (by default) | ServiceNow state (by default) |
| --- | --- | --- |
| New | A status in the **To Do** category | 1 New |
| In progress, Pending | A status in the **In Progress** category | 2 In Progress, 3 On Hold |
| Resolved, Closed | A status in the **Done** category | 6 Resolved, 7 Closed |

For Jira, you can map each case status to status names instead, separated by commas in
order of preference, such as `Waiting for customer` for Pending. Signalith moves an issue
through the transitions its workflow offers from where it is; when the workflow has none to
the mapped status, the case's ticket shows why until the case's status changes. For
ServiceNow, you can enter other state numbers. Canceled (8) closes the case.

When the case's status and the ticket's both changed since the last minute, the case
wins: the ticket is moved back to match it.

With **Status** on, whoever can move the ticket can move the case: a move to a status mapped
to Resolved or Closed (or Canceled in ServiceNow) resolves or closes the case. Turn **Status**
off on a connection whose tickets people outside the security team can change, if that should
not happen.

### Nothing echoes back

Signalith never sends back what it took, or takes back what it sent:

- Comments it writes start with `[Signalith]`, and it never takes back such a comment written
  by its own account. Anyone can start a comment with `[Signalith]`, so one by another account
  comes back like any other. (A ServiceNow connection signed in with OAuth cannot tell its own
  account, so there such a comment is skipped only when it is one of the case's notes as sent.)
- Notes it took from a ticket are by `jira:<name>` or `servicenow:<user>`, and it never sends
  those to any ticket.
- Each ticket's record (below) remembers the IDs of the notes sent and comments taken, and
  the status last sent and last seen, so a pass only acts on what is new.

Notes written on the case before its ticket was opened are not sent; the description and
the link to the case cover them.

### Deleted tickets and cases

When a ticket is deleted in its system, or the account can no longer see it, the case's
Tickets card says so and offers **Open a new one**. When a case is deleted, its ticket is no
longer kept in step and stays as it is. A closed case whose ticket agrees stops being
checked 30 days after the case last changed, until the case changes again.

## Problems and retries

A case's Tickets card shows the last problem of each of its tickets, and the **Tickets that
need attention** list on the Ticketing page shows the latest problems of the tickets being
kept in step. Each is tried again by itself:

- A problem that may pass (a timeout, HTTP 5xx, a refused connection) is tried again on the
  next pass that has something new, and at least every 5 minutes.
- HTTP 429 or 503 with `Retry-After`: Signalith waits that long. Up to 5 seconds it waits and
  tries again at once; longer, it leaves the connection alone until then (at most 15
  minutes). Connections that keep failing are tried after 1, 2, 4 and up to 30 minutes.
- HTTP 401 says to check the token or password. With OAuth, Signalith first asks for a new
  token once.
- A move the workflow or a data policy refuses is not tried again until the case's status
  changes.

Every hour, and when a server takes the background jobs over, a pass looks at every linked
ticket, so a change missed while a system was down is still brought in step.

## Security

- Signalith connects only over HTTPS. `http://` is allowed only to this machine, with
  **Allow this server's own addresses**, for a test system.
- Every address is checked after DNS: a connection never reaches cloud metadata services,
  Signalith's own OpenSearch, or this machine unless allowed. Redirects are not followed.
- Certificates are always checked, against the system's trusted authorities and, when
  set, the connection's own **Certificate authority** (PEM).
- Each request has a 20-second limit, and answers over 4 MB are refused. A pass spends at most
  2 minutes on one connection; what is left waits for the next pass. Paging stops at what the
  system's total needs, and at a fixed number of pages whatever it says.
- When a proxy is set with `HTTPS_PROXY`, the proxy looks up and connects to the address, so
  Signalith's checks of addresses after DNS cannot apply: the proxy must do its own egress
  filtering (no cloud metadata services, no internal services Signalith must not reach).
- API tokens, passwords and client secrets are encrypted in the file and never sent to the
  page, which only shows whether each is set. A saved secret is only sent to the server it was
  entered for: change a connection's address or way of signing in, and it must be entered
  again. Errors never show a secret, in any form it takes on the wire.
- Setting connections up is for admins, and saving them asks for your password again.
  Opening a ticket is for analysts and admins. The audit log records connection changes and
  tests (with the admin's address, the hosts the connections reach, and whether a secret was
  replaced), every ticket opened, and every change made on either side (`audit=true`).

## Which server syncs

When several servers share one OpenSearch, only the server that holds the **background
jobs** talks to Jira and ServiceNow (see [servers.md](servers.md)). It runs the `ticketing`
job every minute.

- Connections live in that server's ticketing file. On other servers the page shows them
  but cannot change them, and it names the server to use. If the jobs move to a server
  whose ticketing file differs, the Servers page says so, as it does for the other settings
  files. Copy the file to every server that may run the jobs.
- On another server, **Open ticket** asks the job server to open it: the card shows the
  ticket as being opened, and it opens within a minute.
- Each ticket has a record in OpenSearch (the `<prefix>_ticket_sync` index), with an ID made
  from the connection and the case. Only one server can create it, so a case never gets two
  tickets in one connection, even when two analysts click at once.
- Every ticket carries a marker of its case: the Jira label `signalith-<case id>`, or the
  ServiceNow `correlation_id` `signalith:<case id>` (with `correlation_display` `Signalith`).
  A case ID with characters these do not take is replaced by a short hash of it.
- If a server stops between opening a ticket and recording it, or a try fails in a way that
  does not say whether the ticket was made (such as a timeout), the case's card shows it as
  being opened or failed. When it is tried again (after 10 minutes for one left being
  opened), Signalith first looks for a ticket with the case's marker, in the connection's
  project or table, and records that one instead of opening a second. Since anyone who can
  open tickets can put the marker on one, it only takes a ticket created by the connection's
  own account (the Jira creator, the ServiceNow `sys_created_by`) no earlier than 5 minutes
  before the case's first try, the newest when there are several; otherwise it opens a new
  one. A ServiceNow connection signed in with OAuth cannot tell its own account, so it never
  takes one and opens a new ticket. If the project's create screen has no **Labels** field,
  Jira issues are opened without the label, and this check cannot find them.
- A ticket the connection was opening by itself (**Open a ticket for every new case**) is
  tried again by the background sync once it has been left being opened for 10 minutes,
  looking first in the same way. Together with failed tries, it gets three in all; after
  that the card shows it as failed, and **Retry** on the case still looks before opening.

## Where the settings live

Connections are kept in `tickets.yaml` in the lookups folder (setting `ticketing.file`,
environment `SIGNALITH_TICKETING_FILE`; a relative path is relative to the config file). The
server writes the file with mode 0600. Every token, password and client secret in it is
encrypted with the master key (`enc:v1:...`), for its connection and setting.
`signalith secrets status`, `encrypt`, `rotate-master` and the **Security** page cover it,
like the other settings files. Edit it on the page rather than by hand.

If the file cannot be read, nothing syncs and the page shows the error. If a secret cannot
be decrypted, for example after the master key is lost, that connection does nothing until
it is entered again; its card says which.

## Multi-tenant installs

On a [multi-tenant](multi-tenant.md) install each tenant has its own connections, tickets
and sync:

- A tenant's connections are kept in `tenants/<id>/lookups/tickets.yaml` in the state
  folder; `ticketing.file` names the default tenant's file only. What each of its tickets
  last sent and saw is in its own index, such as `signalith.t.acme_ticket_sync`.
- The `ticketing` job runs once per tenant, with that tenant's connections, cases and
  tickets only. A tenant's connection never opens or updates a ticket for another tenant's
  case, and the Tickets panel of a case offers its own tenant's connections only.
- Connections send case details to the addresses they name, so only provider users change
  or test them (`PUT /api/ticketing` and `POST /api/ticketing/test`), while in the tenant.
  A tenant's admins see its connections and tickets on the page; its analysts open tickets
  from its cases as usual.
- Changes are in the audit log with `tenant=<id>`.

An install without tenants keeps its file and `<prefix>_ticket_sync` index as they were.

## API

| Route | Role | What it does |
| --- | --- | --- |
| `GET /api/ticketing` | admin | The connections without their secrets (`token_set`, `password_set`, `client_secret_set`), with how many tickets each keeps in step and how many are failing; `problems` (the latest tickets that need attention), `revision`, `file`, `manage` and `file_error` |
| `PUT /api/ticketing` | admin, asks for the password again | Replaces the connections with the body (`revision`, `connections`). A secret left empty keeps its saved value. A body with problems is refused with 400 and `problems` (`where`, `field`, `message`); a stale `revision`, or another server running the jobs, gives 409. |
| `POST /api/ticketing/test` | admin | Tests `{"id": "<connection id>"}` or `{"connection": {...}}` being edited. Answers `{ok, message, error, duration_ms}`. |
| `GET /api/cases/{id}/tickets` | viewer | The case's tickets, how each is kept in step (`state`: `pending`, `creating`, `linked`, `failed` or `gone`; `remote_status`, `error`, `synced_at`), and the connections a ticket can be opened in |
| `POST /api/cases/{id}/tickets` | analyst | Opens a ticket: `{"connection": "<id>"}`. 201 with the ticket, or 202 with `queued` on a server that does not run the jobs; 409 when the case already has one there. |
