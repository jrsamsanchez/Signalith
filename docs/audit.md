# Audit

Signalith logs every change an admin or the server makes as an **audit line**: sign-ins
and failed sign-ins, users and roles, settings, agent tokens, response actions and playbooks, retention policies and
what retention deleted, archived or restored. On a server of its own these lines are in
the server's log, marked `audit=true`.

When servers share one OpenSearch as a cluster (see
[Audit and archives across servers](servers.md#audit-and-archives-across-servers)), each
server also writes its audit lines to OpenSearch, and the **Audit** tab of **Settings**
(admins only) searches the lines of every server in one place.

## The Audit page

Filter by time range, server, user, words, and named actions (data retention, shared
settings, lost audit records); the newest lines come first, and **Show older** pages back. Each line
shows when it happened, on which server, who did it, what it did and to what, and from
which address. The **Audit** buttons on the Users and Settings pages open the page searching
for their kind of change.

## How the lines are kept

- Lines are written to monthly indices, `<prefix>_audit-YYYY.MM`.
- A server never waits for OpenSearch to log. Lines wait in a spool on disk
  (`audit-spool` in the server's state folder, at most 50 MB, oldest dropped first)
  and are written every few seconds; while OpenSearch is away they wait there.
- A line written twice (after a restart, or a retry) is stored once.
- They are kept 400 days by default. Change that, or archive them before they are
  deleted, with the **Audit records** policy on the [Data retention](retention.md)
  page. The current month is never deleted.

## API

Both routes need an admin.

| Method and path | Response |
| --- | --- |
| `GET /api/audit` | `{"enabled":true,"events":[...],"total":N,"next":"..."}`, newest first. Query parameters: `from` and `to` (RFC 3339 times), `server`, `user`, `action` (exact, or ending in `.` for every action it starts, such as `users.`), `q` (text in the message, user or target), `size` (1 to 500, 50 by default) and `after` (the `next` of the page before). On a server that does not share OpenSearch: `{"enabled":false,"note":...}` |
| `GET /api/audit/servers` | `{"servers":[...]}`: the servers with audit lines |

Each event has `@timestamp`, `server`, `node_id`, `user`, `action`, `target`,
`message`, `source_ip`, `level` and `fields` (the line's other attributes).
