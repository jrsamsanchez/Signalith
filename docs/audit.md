# Audit

Signalith logs every change an admin or the server makes as an **audit line**: sign-ins
and failed sign-ins, users and roles, settings, agent tokens, response actions and playbooks, retention policies and
what retention deleted, archived or restored. It also logs every [search](#searches) someone runs. On a server of its own these lines are in
the server's log, marked `audit=true`.

When servers share one OpenSearch as a cluster (see
[Audit and archives across servers](servers.md#audit-and-archives-across-servers)), each
server also writes its audit lines to OpenSearch, and the **Audit** tab of **Settings**
(admins only) searches the lines of every server in one place.

## The Audit page

Filter by time range, server, user, words, and named actions (data retention, shared
settings, lost audit records, audit checkpoints); the newest lines come first, and **Show older** pages back. Each line
shows when it happened, on which server, who did it, what it did and to what, and from
which address. The **Audit** buttons on the Users and Settings pages open the page searching
for their kind of change. **Check integrity** checks that no line in the time range (of the
server picked, if one is) was changed or removed; see [Tamper evidence](#tamper-evidence).

## Searches

Events hold personal data such as user names and addresses, so reading them is audited
like changing a setting. Each search run from the Search page, the API, an API token or
the MCP server, each dashboard run, each panel preview, each notebook search, each search
added to an investigation and each look at a field's top values writes a line with:

- who ran it (`by`), their tenant, how they signed in (`method`: session, basic or token,
  and `token_id`) and from which address (`client`);
- the query text (up to 2,000 characters), its time range (`earliest`, `latest`) and the
  indices it read (`index`);
- how it ended (`outcome` ok or failed, with the error), how many events matched and how
  long it took.

A dashboard run is one line naming the dashboard, since its queries are saved with it.
Searches Signalith runs on its own (scheduled detections, summaries, the Compliance page)
are not logged as a person's search. Pick **Searches** under actions on the Audit page to
see only these lines.

The query text can itself hold personal data or a secret someone typed, such as a user
name or a password they searched for, so these lines are kept like every other audit line:
only the provider's admins see them (tenant admins do not), they are chained and signed,
and the **Audit records** retention policy decides how long they are kept.

## How the lines are kept

- Lines are written to monthly indices, `<prefix>_audit-YYYY.MM`.
- A server never waits for OpenSearch to log. Lines wait in a spool on disk
  (`audit-spool` in the server's state folder, at most 50 MB, oldest dropped first)
  and are written every few seconds; while OpenSearch is away they wait there.
- A line written twice (after a restart, or a retry) is stored once.
- They are kept 400 days by default. Change that, or archive them before they are
  deleted, with the **Audit records** policy on the [Data retention](retention.md)
  page. The current month is never deleted.

## Tamper evidence

Whoever can write to OpenSearch could change or delete audit lines there. So each server
chains the lines it writes and signs each one, and a check shows a line changed or removed
since:

- Each line has a sequence number in its server's **chain** (`chain`, `seq`), the hash of the
  line before it (`prev`), and an HMAC-SHA256 of all its fields (`mac`) made with a key
  derived from the cluster key (`kid` names which cluster key). Only the cluster's servers
  hold the cluster key, sealed under their master key; it is never in OpenSearch.
- Where the chain is (the last sequence number and hash) is kept in `audit-spool/chain.json`,
  so a restart continues the chain. A server that lost its spool folder starts a new chain,
  its first line marked `chain_start`; the check counts that as a chain started, not as
  lines removed.
- When the spool is full and drops its oldest lines, or OpenSearch refuses a line for good,
  the server writes an `audit.lost` line naming the sequence numbers lost, so the check tells
  that gap from a removal.
- Every hour the server that runs the background jobs writes an `audit.checkpoint` line naming
  the latest line of every server. Removing the last lines of a server leaves no gap that a
  later line of its own would show; the checkpoint, chained and signed in its own server's
  lines, still names them.

Check with **Check integrity** on this page, `GET /api/audit/verify`, or from the shell:

```
signalith audit verify [-c file] [-from 2026-10-01] [-to 2026-10-15] [-server name] [-json]
```

It reads the lines in the range in each chain's order and reports how many check out, and
those **changed** (the MAC does not match, or a checkpoint saw them otherwise), **signature
removed** (not signed with a key the server holds, though their server signed its lines before
them: a server that signs keeps signing, so the MAC was removed or replaced, or the line was
put in), **not linked** (the line before was changed, or one was put in), **removed** (missing from a
chain, and no signed `audit.lost` line names them), and **removed at the end** (a checkpoint saw
later lines of a server than there are). It exits 2 when it finds any. Only signed `audit.lost` and
`audit.checkpoint` lines count, as anyone who can write to OpenSearch could write unsigned
ones; a gap where nothing is signed and only an unsigned `audit.lost` line names it is
counted as **unverifiable**. It also counts the lines dropped and recorded, the unsigned ones, those signed with a cluster key this server
does not hold, and the chains started. The command and the page check the lines with every
cluster key this server holds, so lines signed before a [key
rotation](servers.md#draining-and-removing-a-server) keep checking out as long as the old key's
file stays in `keys/` of the state folder, as it does after a rotation. One check reads at
most 500,000 lines on the page and 2,000,000 from the shell; pick a shorter range for more.

What it cannot show:

- Someone who holds the cluster key (an admin of a member server, or anyone who can read its
  state folder and master key) can write lines that check out. Keep those as safe as the
  master key; see [encryption.md](encryption.md). A removed server keeps the cluster key it
  had, so rotate the key when you remove one (the default); lines signed with an old key
  after its rotation still check out.
- Lines removed at the end of a server's chain after the last checkpoint, such as in the last
  hour, show only once a later line of that server or a later checkpoint exists. Lines
  removed at the start of the oldest chain look like lines retention deleted.
- A line put in without a chain place and dated before its server first signed a line, or
  within a minute after, counts only as unsigned. When a server first signs its lines, it notes
  the time in the cluster's shared settings, which are signed with the cluster key, so a check
  of any range knows its later lines must be signed even if every line it reads was stripped.
  Lines of a server that never signed (an older version) are only counted as unsigned.
- Lines written before this version, imported lines (the founder's retention history), and
  lines a server wrote while it had no cluster key yet are chained (when written by a server
  of this version) but not signed: changing one shows only through the line after it.
- A server's lines still in its spool are not in OpenSearch yet; a check right after an
  outage can show a gap that closes once the server has written them. Check again before
  calling it a removal.
- Monthly indices made before this version keep the new fields in each line but do not map
  them; the check reads them all the same.

## API

All three routes need an admin.

| Method and path | Response |
| --- | --- |
| `GET /api/audit` | `{"enabled":true,"events":[...],"total":N,"next":"..."}`, newest first. Query parameters: `from` and `to` (RFC 3339 times), `server`, `user`, `action` (exact, or ending in `.` for every action it starts, such as `users.`), `q` (text in the message, user or target), `size` (1 to 500, 50 by default) and `after` (the `next` of the page before). On a server that does not share OpenSearch: `{"enabled":false,"note":...}` |
| `GET /api/audit/servers` | `{"servers":[...]}`: the servers with audit lines |
| `GET /api/audit/verify` | `{"enabled":true,"tampered":false,"report":{...}}`: the [integrity check](#tamper-evidence) of the lines from `from` to `to` (RFC 3339 times; all when left out), of `server` alone when set. The report has the counts `records`, `ok`, `edited`, `stripped`, `broken`, `missing`, `truncated`, `dropped`, `unverifiable`, `unsigned`, `unknown_key`, `restarts`, `continued` and `checkpoints`, `limited` when there were more lines than one check reads, `servers` (counts for each) and `problems` (the first 100, each with `kind`, `time`, `server`, `node_id`, `seq`, `id` and `detail`). One check runs at a time: another asked meanwhile gets 429 |

Each event has `@timestamp`, `server`, `node_id`, `user`, `action`, `target`,
`message`, `source_ip`, `level` and `fields` (the line's other attributes), and
`epoch`, `seq`, `chain`, `chain_start`, `prev`, `kid` and `mac` (its place in its server's
chain, and its signature).
