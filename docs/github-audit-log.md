# GitHub audit log

GitHub keeps an **audit log** for every enterprise and organization: repositories
created, archived, transferred and deleted, members invited and removed, branch
protections and rulesets changed, secret scanning, Dependabot, push protection and the
two-factor requirement turned off, secrets added, self-hosted runners registered, and
audit log streams changed or paused. Signalith makes each event searchable and runs the
SigmaHQ and Splunk GitHub rules on it.

It reads the audit log of **GitHub Enterprise Cloud** (an enterprise, or an organization
on the Enterprise plan) and **GitHub Enterprise Server** 3.x, the same events GitHub
shows under **Settings > Audit log**.

## How it works

Signalith doesn't sign in to GitHub. GitHub's events reach it one of three ways; pick
the first that fits:

| Way | What you need | How soon events arrive |
| --- | --- | --- |
| [Audit log streaming to an Azure event hub](#stream-to-an-azure-event-hub) | GitHub Enterprise Cloud or Server, an Azure Event Hubs namespace, the OpenTelemetry Collector | Within a minute |
| [A script that reads the REST API](#read-the-rest-api-with-a-script) | An owner's token, a machine that runs a job every few minutes | As often as the script runs |
| [Files that streaming writes to Amazon S3, Azure Blob Storage or Google Cloud Storage](#send-files-from-a-storage-bucket) | A storage bucket GitHub already streams to | As often as you send them |

GitHub can also stream to Splunk's HTTP Event Collector. Signalith has no HTTP Event
Collector endpoint, so use one of the ways above instead.

Every way sends GitHub's own JSON for each event, unchanged. Under the `github` tag,
Signalith reads any event with an `action` such as `repo.destroy`, a time, and who or
where. Under another tag (except one that names another source, such as `linux.` or
`windows.`) it recognizes an event by GitHub's `_document_id`, or an `actor_id` with an
organization, enterprise or repository, so other applications' audit logs are never read
as GitHub's. It stores an event sent twice once, so a script that reads a little of the
last round again doesn't make copies.

## What you need

- For streaming: an **enterprise owner** (or, on GitHub Enterprise Server, a site admin).
- For the REST API: an **organization owner** or **enterprise owner**, and a personal
  access token (classic) with the `read:audit_log` scope. The organization API needs the
  Enterprise plan.
- An [agent token](agent-tokens.md#create-a-token) to send events to Signalith, made on
  **Add data** under **Agent tokens**, or with `signalith tokens create`.

## Stream to an Azure event hub

This is the same path as [Entra ID and Azure](azure.md): GitHub writes each event to an
event hub, and the OpenTelemetry Collector reads it and sends it to Signalith. If you
already send Entra ID's logs that way, GitHub can use the same event hub.

1. **Make an event hub.** In the Azure portal, create an Event Hubs namespace (Standard
   tier) and, in it, an event hub named `signalith`, or use the one you made for Entra ID.
2. **Make a key GitHub can write with.** In the event hub's **Shared access policies**,
   add a policy named `github` with **Send** only, and copy its **Connection
   string-primary key**.
3. **Make a key the Collector can read with.** Add another policy with **Listen** only,
   and copy its connection string too. (Skip this if the Collector already reads this
   event hub for Entra ID.)
4. **Turn on streaming in GitHub.** As an enterprise owner, open your enterprise's
   **Settings**, then **Audit log**, then **Log streaming**. Choose **Configure stream**,
   then **Azure Event Hubs**. Enter the event hub's name (`signalith`) as **Azure Event
   Hubs Instance**, and the `github` policy's connection string. Choose **Check
   endpoint**, then **Save**. On GitHub Enterprise Server, the same page is under the
   enterprise's **Settings > Audit log > Log streaming** in the site admin's account.
5. **Run the Collector.** On the **Add data** page, choose **Entra ID and Azure** and
   follow its steps with the Listen connection string: it installs the Collector and
   writes its configuration. The receiver passes each message on whole (`format: raw`),
   which is what Signalith reads.

Events usually arrive within a minute. GitHub keeps trying for a while when the event
hub can't be reached, and the event hub keeps messages for its retention time, so a
Collector that was off catches up.

## Read the REST API with a script

GitHub's REST API serves the audit log a page at a time: `GET /orgs/{org}/audit-log` for
an organization and `GET /enterprises/{enterprise}/audit-log` for an enterprise (on GitHub
Enterprise Server, under `https://<your server>/api/v3`). This script, run every five
minutes by cron or a scheduled task, reads the last 15 minutes of an organization's audit
log with the [GitHub CLI](https://cli.github.com/) and sends it to Signalith:

```sh
#!/bin/sh
# Read the last 15 minutes of an organization's audit log and send it to Signalith.
# GH_TOKEN: a token (classic) with read:audit_log. SIGNALITH_TOKEN: an agent token.
set -eu
ORG=example-org
SIGNALITH=https://signalith.example.com:7779
SINCE=$(date -u -d '15 minutes ago' +%Y-%m-%dT%H:%M:%SZ)   # macOS: date -u -v-15M ...

gh api --paginate "/orgs/$ORG/audit-log?include=all&per_page=100&phrase=created:>=$SINCE" \
  --jq '.[] | tojson' > /tmp/github-audit.ndjson

if [ -s /tmp/github-audit.ndjson ]; then
  curl --fail --silent --show-error \
    -H "Authorization: Bearer $SIGNALITH_TOKEN" -H "X-Signalith-Tag: github" \
    --data-binary @/tmp/github-audit.ndjson "$SIGNALITH/api/ingest"
fi
```

For an enterprise, use `/enterprises/<enterprise>/audit-log` instead. With GitHub
Enterprise Server, set `GH_HOST` to your server's name. `include=all` adds git events
(clones and pushes) on GitHub Enterprise Cloud; leave it out to send only the web and API
events. The script reads 15 minutes each time it runs every 5, so a late run misses
nothing, and the events it reads again are stored once.

Send events to the [agent port](sending-data.md#the-agent-port) (7779), with the agent
token. One request can hold up to 200,000 events and 16 MB; a script that reads more at a
time should send them in parts (`split -l 50000`). Signalith takes one JSON event per
line, as here, or a JSON array of events as each page comes from the API.

## Send files from a storage bucket

When GitHub already streams to **Amazon S3**, **Azure Blob Storage** or **Google Cloud
Storage**, it writes the events in files of one JSON event per line, compressed with
gzip. Send a file the same way as the script does:

```sh
gunzip -c 2026-10-11T09-12-31Z.json.gz | curl --fail --silent --show-error \
  -H "Authorization: Bearer $SIGNALITH_TOKEN" -H "X-Signalith-Tag: github" \
  --data-binary @- https://signalith.example.com:7779/api/ingest
```

A job that downloads new files (`aws s3 sync`, `azcopy sync` or `gcloud storage rsync`)
and sends each one keeps Signalith up to date. An **export** from the audit log page
(**Export > JSON**) is a JSON array of events, and can be sent as it is.

The [OpenTelemetry Collector](opentelemetry.md) works too: any log record whose body is
GitHub's JSON for one event, events one per line, or an array of them, is read as GitHub's.

## What you get

Each event becomes one event with `sourcetype=github:cloud:audit`, the sourcetype of
Splunk's add-on for GitHub. Its fields keep GitHub's own names, with nested objects
flattened into dotted names and each value in a list by Splunk's name for it
(`events{}`). A few of GitHub's names are Signalith's own fields with another meaning,
so those are kept under another name:

| Field | Example |
| --- | --- |
| `vendor_action` | GitHub's `action`: `repo.destroy`, `org.disable_two_factor_requirement` |
| `github_actor`, `actor_id`, `actor_ip`, `actor_is_bot` | GitHub's `actor`: who did it, from where |
| `actor_location.country_code` | `US` |
| `business`, `org`, `repo`, `team` | the enterprise, organization, repository and team |
| `github_user`, `github_user_id` | GitHub's `user`: the account the action was about, such as the member added |
| `visibility`, `operation_type` | `private`, `create`, `modify`, `remove` |
| `github_document_id`, `created_at` | GitHub's `_document_id`, and its time in milliseconds |
| `github_name`, `github_reason`, `github_user_agent` | GitHub's `name`, `reason` and `user_agent` |

Any other name GitHub gives an action's own fields (`ruleset_name`, `runner_name`,
`hashed_token`, `config.url`) is kept as GitHub writes it, unless Signalith uses it for
something else, when it is kept as `github_<name>`. Every value is kept as text. A
webhook address's user name, password and query values (`https://user:pass@ci.example.com/hook?token=...`)
are replaced with `[redacted]` before the event is stored. Each
event also gets the data model fields of what it is:

- A **change** (almost every action) is a **Change** event, with `action` (created,
  modified or deleted, by the action's words: `repo.create`, `org.add_member`,
  `repo.destroy`, `org.remove_outside_collaborator`, `repo.archived`), `change_type` (the
  action's category, such as `repo` or `org`), and `object` and `object_category` (the
  repository, team, user, organization or enterprise it changed).
- A **sign-in** to GitHub Enterprise Server (`user.login`, `user.failed_login`,
  two-factor challenges) is an **Authentication** event, with `action` success or failure.
- **Git operations, API requests and workflow runs** (`git.*`, `api.*`, `workflows.*`) are
  **Other** events.

All of them have `user` and `src_user` (the actor), `src` (the actor's address),
`signature` (the action), `dest` (the organization, or the enterprise), `vendor_account`
(the enterprise, or the organization), `app` (`GitHub`), `status` and `id` (the event's
`_document_id`). Some searches to start with:

```
sourcetype=github:cloud:audit vendor_action=repo.destroy | stats count by user, repo
datamodel=Change sourcetype=github:cloud:audit action=deleted | stats count by signature, user
sourcetype=github:cloud:audit vendor_action=*disable* | stats count by vendor_action, org
```

## Detections

The SigmaHQ pack has 12 GitHub rules (see [Detections](detections.md#github)): delete
actions (codespaces, environments, projects, repositories), high-risk settings turned off
(advanced security, OAuth app restrictions, the two-factor requirement), Dependabot and
vulnerability alerts turned off, forking of private repositories allowed or cleared, new
secrets, outside collaborators, push protection bypassed or turned off, repositories and
organizations transferred, secret scanning turned off, self-hosted runner changes and SSH
certificate settings changed. Three SigmaHQ GitHub rules are left out:
`github_new_org_member` is informational, and `github_pages_site_changed_to_public` and
`github_repository_archive_status_changed` are experimental.

The Splunk Security Content pack has 18 GitHub rules, from its
`github_enterprise` searches (by GitHub's own names, `action=repo.destroy`) and its
`github_organizations` searches (Splunk's add-on's, `vendor_action=repo.destroy`): branch
rulesets and classic branch protection deleted, the two-factor requirement turned off,
Dependabot turned off, audit log streams deleted, changed or paused, the IP allow list
turned off, self-hosted runners registered, organizations removed from the enterprise,
and repositories archived and deleted: every production rule of both macros. Splunk's
other rules with GitHub in their name are hunting searches of endpoint and MCP server
data. Turn them on from each pack's
page like any other rules.

## When nothing arrives

- **Search for the events.** `sourcetype=github:cloud:audit` over the last day. If
  nothing is there, search for an action you expect as text (`"repo.create"`): events
  that arrived but weren't recognized, such as a file that wraps each event in another
  object, are stored as plain events.
- **Streaming.** On GitHub's **Log streaming** page, a stream that can't deliver shows
  an error; **Check endpoint** tests the connection string again. Check the Collector's
  log for `azure_event_hub`.
- **The script.** `gh api` names what's wrong with the token: a token without
  `read:audit_log`, an account that isn't an owner, or an organization not on the
  Enterprise plan. `curl --fail` prints Signalith's answer when it refuses a request, such
  as an agent token it doesn't know.
