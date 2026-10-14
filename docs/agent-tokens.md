# Agent tokens

Agents (Fluent Bit, the OpenTelemetry Collector and osquery) prove who they are with an
agent token, sent as `Authorization: Bearer <token>`. Each agent, or each group of agents
that do the same job, gets its own token. You can see which token every event came with,
and you can revoke one group without touching the others.

Tokens are listed on the **Add data** page, under **Agent tokens**. Admins can create,
rename and revoke them there or with `signalith tokens`. Analysts can list their names
through the API; nobody can see a token again after it is created.

## How tokens work

- **Shape.** A token is `sgl_` followed by 52 lowercase letters and digits (`a` to `z`,
  `2` to `7`), 56 characters in all, for example `sgl_7f2kq…`. The 52 characters hold 32
  random bytes. The `sgl_` prefix lets secret scanners (GitHub secret scanning, gitleaks,
  trufflehog and the like) find a token that leaked into a file or a chat. The pattern to
  give them is:

  ```
  \bsgl_[a-z2-7]{52}\b
  ```

- **Shown once.** Signalith shows a new token only when it creates it. It keeps the
  SHA-256 hash of the token, a 12-character ID (the start of that hash) and the last 4
  characters (shown as `sgl_…x7q2`, so you can match a configuration file to a row).
  A plain SHA-256 is enough here: a token holds 256 random bits, so nobody can work it
  out from its hash. Lost a token? Create a new one and revoke the old one.
- **Shared by every server.** Tokens are kept in OpenSearch, in the `<prefix>_runtime`
  index (`signalith_runtime` by default) that the [servers](servers.md) of one Signalith
  share, so a token made on one server works on all of them. Only hashes are stored there.
- **Revocation takes seconds.** Each server keeps the list in memory and checks
  OpenSearch every 2 seconds for a change. A revoked token is refused at once on the
  server where you revoked it, and within a few seconds on the others. No restart is
  needed.
- **When OpenSearch is down.** Servers keep using the list they already have. Nothing
  can be revoked or created until OpenSearch is back, and no events can be stored either,
  so the list being a little old changes nothing. A server that starts while OpenSearch
  is down can't read the list yet: agents with an `sgl_` token are asked to try again
  later (`503`, `Retry-After: 30`). Fluent Bit and the Collector keep their events and
  send them again. Agents with a shared token are asked the same, since you may have
  chosen **Stop accepting** on it: a token you turned away is never let back in.
- **Shared token IDs.** A shared token (see [below](#replace-a-shared-token)) is often
  one a person typed, so its ID is not made from a plain hash of it, which anyone who can
  search events could use to test guesses. It is an HMAC-SHA256 of the token under a
  random key kept in the `<prefix>_runtime` index, made the first time a server with a
  shared token reads the tokens.
- **Not a password.** An agent token can't be used to sign in to the web UI or the API,
  and a user's password or session can't be used to send events.

## Create a token

**On the Add data page (the usual way).** Pick the source (Linux, Windows,
OpenTelemetry or osquery) and type a name under **Token for these agents**, such as
`Linux web servers`. The name is recorded on every event those agents send. The setup
shows where the token goes. When you choose **Copy** or **Download** for the
configuration, or copy a command that holds the token, Signalith creates the token, puts
it in the configuration and the steps, and shows **Created token "Linux web servers"**.
Copy or download the configuration before you leave the page: the token is not shown
again. Copying again reuses the same token; changing the name or the source makes a new
one on the next copy.

Already have a token for these agents? Choose **Use a token I already have** and paste it.

**Without a configuration.** Under **Agent tokens**, choose **New token**, type a name and
choose **Create token**. Copy the token from the next screen into the agent's
configuration. When you choose **Done**, it is gone from the page.

**From the command line:** `sudo signalith tokens create "Linux web servers"`
(see [Commands](#commands)).

Names are 1 to 64 letters, digits, spaces or `. _ - ( ) / : # @`, and no two active tokens
can have the same name (capitals don't count). There can be up to 1,000 active tokens.

## Revoke a token

On **Add data**, under **Agent tokens**, open the token's **⋯** menu and choose
**Revoke**, or run `sudo signalith tokens revoke <id or name>`.

- Agents that send with it are refused within a few seconds on every server, with
  `401` and `this agent token was revoked; give the agent a new configuration from the
  Add data page`. The **Health** page names them.
- osquery hosts enrolled with it are removed (see [osquery hosts](#osquery-hosts)).
- Events already stored stay, and keep the token's name.
- It can't be undone. To bring those agents back, give them a new configuration from
  **Add data**.

Revoked tokens stay in the list under **Show revoked**, so old events still explain
themselves. **Rename** in the same menu changes the name on new events only; events
already stored keep the old name.

## What each event records

Signalith adds four fields to every event agents send:

| Field | Holds |
|---|---|
| `signalith_intake` | How it came in: `agent` (Fluent Bit, `POST /api/ingest`), `otlp` (OpenTelemetry), `osquery` or `syslog` |
| `signalith_token` | The token's name when the event arrived, such as `Linux web servers` (never the token itself). A shared token shows as `Shared token 3f9c0a` |
| `signalith_token_id` | The token's 12-character ID, which stays the same when the token is renamed |
| `signalith_sender` | The address that sent it, without the port. Behind a [trusted proxy](https.md), the real client's address |

Syslog has no token, so syslog events record only `signalith_intake` and
`signalith_sender`.

For example, to see which agents sent with a token in the last day:

```
signalith_token="Linux web servers" | stats count by signalith_sender, host
```

**Names a sender can't set.** These fields are Signalith's own. Whatever a sender puts
in an event, Signalith drops (and counts in `dropped_fields`, with a warning in the
server log). The event itself is kept:

- `@timestamp`, `datamodel`, `device_time` and `dropped_fields`;
- `signalith`, and every name that starts with `signalith_` or `signalith.`;
- any name whose part before the first `.` is one of those, such as `datamodel.x`.

Capitals don't count (`Signalith_Sample` is dropped too). This covers OpenTelemetry
attributes named `signalith.*` and `signalith_sample`, which marks
[sample data](sample-data.md).

## Replace a shared token

Before per-agent tokens, every agent used the same token, from `ingest.tokens` in
signalith.yaml or from `SIGNALITH_INGEST_TOKEN` or `SIGNALITH_INGEST_TOKEN_FILE`. The
Docker quick start makes one too (`ingest-token`, made by its setup step). These **shared
tokens** still work, so nothing breaks when you update. They are shown under **Agent
tokens** as **Shared tokens**, with a warning: a copy taken from any one agent works for
all of them, and you can't turn one agent away without turning all of them away. The
[Security page](security.md#agent-tokens) flags them too.

To replace a shared token:

1. Open **Add data** and, for each group of agents, copy or download a new configuration.
   Each group gets its own token. Put the configuration on the agents and restart them.
2. Under **Agent tokens**, watch the shared token's **Last used**. It covers every server.
   Once it is older than the last agent you updated, nothing uses it any more.
3. Choose **Stop accepting** on the shared token. Every server refuses it within a few
   seconds, with no restart. Fluent Bit and the Collector drop the batches refused this
   way, so update the agents first. Changed your mind? **Accept again** undoes it.
That's all. A token that is no longer accepted can't be used, and the Security page
counts it as retired. It stays listed as **No longer accepted**.

- **Docker quick start:** stop here. Leave `docker-compose.yml` as it is, so `git pull`
  keeps updating it cleanly. On a new install no agent has the shared token, so you can
  choose **Stop accepting** on it straight away.
- **signalith.yaml (optional):** to tidy up, delete its line under `ingest.tokens`, then
  restart Signalith.
- **Environment (optional):** remove `SIGNALITH_INGEST_TOKEN` (or `_FILE`) from the
  service's environment and restart it.

The example token `change-this-ingest-token` from older Docker quick starts is handled
on its own; see
[The Docker quick start's old example token](https.md#the-docker-quick-starts-old-example-token).

## Commands

Run these on a Signalith server, as the user that can read signalith.yaml (usually with
`sudo`). They use the OpenSearch in the configuration, so they work from any server of a
cluster. Add `-c <file>` for another configuration file. In Docker, run them in the container:
`docker compose -f deploy/docker/docker-compose.yml exec signalith signalith tokens list`.

```sh
signalith tokens list                      # active tokens and shared tokens; -all adds revoked ones, -json for scripts
signalith tokens create "Linux web servers"            # prints the token once, on its own line
signalith tokens create -purpose windows "Domain controllers"
signalith tokens rename 3f9c0a1b2c4d "Web servers (Leeds)"
signalith tokens revoke 3f9c0a1b2c4d       # or the exact name; asks first, -yes skips the question
signalith tokens legacy refuse a1b2c3d4e5f6   # stop accepting a shared token
signalith tokens legacy accept a1b2c3d4e5f6   # accept it again
```

`create` prints only the token on standard output, so `TOKEN=$(signalith tokens create
"Build agents")` works; what it did goes to standard error. Changes made here are logged
as audit lines (`audit=true`, `by=cli:<your user>`), as the same changes on the page are.

`signalith secrets set ingest.tokens` still adds a shared token, for setups that need one
fixed token in the configuration. New agents should get their own token instead.

### API

| Route | Role | Does |
|---|---|---|
| `GET /api/agent-tokens` | Analyst | Lists tokens and shared tokens: name, status, created, last used, events in the last hour. Never a token |
| `POST /api/agent-tokens` | Admin | `{"name": "Linux servers", "purpose": "linux"}` creates a token. `purpose` is `linux`, `windows`, `otel`, `osquery` or empty. The `201` answer is the only one that holds the token, in `secret` |
| `PATCH /api/agent-tokens/{id}` | Admin | `{"name": "New name"}` renames it |
| `POST /api/agent-tokens/{id}/revoke` | Admin | Revokes it; answers `hosts_removed`, the osquery hosts removed with it |
| `POST /api/agent-tokens/legacy/{id}/refuse` | Admin | Stops accepting a shared token |
| `POST /api/agent-tokens/legacy/{id}/accept` | Admin | Accepts it again |

Errors carry `error` (a sentence), `code` and, for the name, `field: "name"`:
`name_invalid`, `name_taken`, `purpose_invalid`, `not_found`, `revoked`, `too_many`,
`rate_limited` (more than 10 tokens a minute; wait for `Retry-After`),
`store_unavailable` (OpenSearch can't be reached) and `tokens_loading`. Create, rename,
revoke, stop accepting and accept again are written to the audit log, never with the token.

## osquery hosts

Hosts running osquery (see [endpoints.md](endpoints.md)) enroll with an agent token as their
enroll secret, and each host remembers which token it enrolled with. The setup script Add
data makes for osquery holds a token of its own, named `osquery hosts` unless you choose
another name.

- Revoking that token, or choosing **Stop accepting** on a shared token, removes every
  host enrolled with it, on every server. Their next request is refused, and they must
  enroll again with an active token. The revoke answer and the message after it say how
  many hosts were removed.
- A host enrolled with a shared token that was later deleted from signalith.yaml or the
  environment is refused too, since the token it enrolled with no longer exists.
- Events from osquery record the token and the host's address as above, with
  `signalith_intake=osquery`.
