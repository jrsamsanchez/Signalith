# Signalith query language

A query is a **search** followed by zero or more **commands**, each after a `|`.
The search selects events; commands reshape the results. It reads like Splunk's SPL,
but it is Signalith's own language and does not claim SPL compatibility.

```
datamodel=Authentication action=failure earliest=-24h
| stats count, dc(user) as users by src
| where count > 20
| sort -count
| head 10
```

## Search

| Syntax | Meaning |
| --- | --- |
| `datamodel=Authentication` | Events of one data model: Authentication, Endpoint, Network_Traffic, Change, Malware (antivirus; see [antivirus.md](antivirus.md)), Filesystem, Registry, Network_Resolution, Image_Load, Script, Inventory, Configuration_Check, Alerts, Other. `datamodel=Risk` searches risk events, which are left out otherwise |
| `index=signalith-authentication-2026.10.*` | One pattern of Signalith's daily indices, `<prefix>-<datamodel>-YYYY.MM.DD`. It must start with the configured `opensearch.index_prefix` and `-`; `index=*` means all events, as when `index=` is left out. Lists (`a,b`), exclusions (`-x`), other indices and system indices, other clusters (`remote:x`) and date math are refused |
| `field=value` | Exact match, case-insensitive |
| `field=val*` | Wildcard match with `*` and `?` |
| `field=*` | The field has any value |
| `src=10.0.0.0/8`, `src=fe80::/10` | An IPv4 or IPv6 address range (CIDR) |
| `field!=value` | Does not match |
| `field=~"pattern"` | Regular expression ([RE2 syntax](https://github.com/google/re2/wiki/Syntax)), found anywhere in the value unless `^` or `$` anchor it, and case-sensitive unless it starts with `(?i)`. Also works in `where`. Word boundaries (`\b`), `(?m)` and `^`/`$` other than at the ends are refused, since the search runs in OpenSearch |
| `field>10`, `>=`, `<`, `<=` | Numeric (or text) comparison |
| `field IN (a, b, c)` | Any of several values |
| `word` or `"a phrase"` | Text anywhere in the raw event (`_raw`) |
| `NOT term`, `( ... )` | Negation and grouping |
| `a OR b` | Either. As in SPL, OR binds tighter than the implicit AND, so `x a OR b` means `x AND (a OR b)` |
| `earliest=-7d@d latest=now` | Time range; overrides the UI time picker |

Relative times: `-30s`, `-15m`, `-4h`, `-7d`, `-2w`, `-1mon`, `-1y`, optionally snapped
with `@d`, `@h`, `@w`. Absolute times are ISO 8601 (`2026-10-01T00:00:00Z`).

Quote values that contain spaces or symbols: `process_path="C:\Windows\System32\cmd.exe"`.
Inside quotes, `\"` is a quote and `\\` is one backslash; any other backslash is
kept as typed, so Windows paths work without doubling.
In a regular expression that means `\.` stays `\.`, and a literal backslash is
`\\\\` (two backslashes after quoting, which the expression reads as one).

## Commands

| Command | Example | Notes |
| --- | --- | --- |
| `stats` | `stats count, dc(user) as users, avg(bytes) by src, dest` | Functions: `count`, `count(f)`, `dc(f)`, `sum(f)`, `avg(f)`, `min(f)`, `max(f)` |
| `timechart` | `timechart span=1h count by action` | One aggregation when splitting by a field; span picked automatically if omitted |
| `top` | `top limit=10 process_name by host` | Adds `count` and `percent` |
| `where` | `where count > 20 AND users >= 2` | AND binds tighter than OR here, as in most languages |
| `sort` | `sort -count, src` | `-` for descending |
| `head` | `head 20` | Also `limit` |
| `table` | `table _time, user, src` | Also `fields`; wildcards allowed |
| `rename` | `rename src as source_ip` | |
| `enrich` | `enrich` or `enrich user, dest` | Adds asset and identity context: `<field>_priority`, `_category`, `_bunit`, plus `_owner`, `_location` for assets and `_name`, `_email`, `_manager`, `_watchlist` for users. With no fields it enriches `user`, `src_user`, `src`, `dest`, `host`, `src_host`, `dest_host` and `risk_object` |
| `threatmatch` | `threatmatch` or `threatmatch src, dest` | Keeps only events where a field equals a threat intel indicator. Runs inside OpenSearch, so it must come right after the search (before `stats` and other commands). Adds `threat_match_field`, `threat_match_value`, `threat_indicator`, `threat_type`, `threat_source`, `threat_weight`, `threat_description` and `threat_target` (the system on your side) to each event |
| `intel` | `intel` or `intel src, url` | Adds `<field>_intel_source`, `_intel_type`, `_intel_weight` and `_intel_description` where a value is a known indicator. Works on any result, including after `stats` |

With no fields, `threatmatch` and `intel` check `src`, `dest`, `src_ip`, `dest_ip`,
`dest_host`, `domain`, `query`, `url_domain`, `url`, the hash fields
(`process_sha256`, `process_sha1`, `process_md5`, `process_hash`, `file_hash`,
`file_sha256`, `file_sha1`, `file_md5`, `hash`, `md5`, `sha1`, `sha256`) and the email fields (`sender`, `recipient`, `src_user`,
`user`). The `threat_*` columns are added after OpenSearch returns events, so
aggregate on event fields and add intel afterwards:
`* | threatmatch src | stats count by src, dest | intel src`.

Columns produced by `stats` are referenced by name in later commands, for example
`sort -dc(user)` or `where avg(bytes) > 1000`.

## Asking in plain English

The box above the query editor (and `signalith ask "..."`) turns a question into a
query. It understands:

| You write | It adds |
| --- | --- |
| logins, processes, connections, account changes, risk | `datamodel=...` |
| failed, successful, blocked, allowed, created, deleted | `action=...` |
| from 10.0.0.5, to web1, on dc01, by alice, port 22, user bob | field filters; `not`/`except` negates |
| powershell, cmd, certutil, mimikatz.exe, spawned by winword | `process_name`, `parent_process_name` |
| containing mimikatz, "quoted text" | `process=*...*` for processes, text search otherwise |
| last 4 hours, past 7 days, today, yesterday, this week | `earliest=` and `latest=` |
| how many, distinct users, total bytes, average bytes | `stats count`, `dc()`, `sum()`, `avg()` |
| per user, by source ip, for each host | `by ...` |
| top 10 users, most common processes, rare processes | `top` or `stats ... \| sort \| head` |
| more than 5, at least 3 hosts | `where count>5`; `stats dc(dest) as distinct_dest ... \| where distinct_dest>=3` |
| per hour, over time, daily | `timechart` |
| show user, src and dest | `table _time, user, src, dest` |

Names from the asset and identity lists are recognized as users or hosts. When an AI
model is configured, questions with unknown words go to it; see
[Writing queries](https://github.com/jrsamsanchez/Signalith/blob/main/README.md#writing-queries) in the README.

## How queries run

- The search and any `where` commands that come before the first `stats`, `timechart`
  or `top` run inside OpenSearch, so they scale with the cluster.
- `stats` and `top` use composite aggregations and page through every group (up to
  50,000 groups, then results are marked truncated).
- `threatmatch` becomes `terms` filters of indicator values (10,000 per clause) and
  prefix filters for networks, so matching runs inside OpenSearch too.
- Commands after that run in the Signalith server on the aggregated rows.
- An event search without `stats` returns the newest 100 events, or up to
  `search.max_events` (at most 100,000) when later commands need to sort or filter
  them all.
- Wildcard values (`*`, `?`) can be up to 1,000 characters long, and the wildcard values
  in `where` commands up to 4,096 characters together (`where` runs over every row in the
  server, so put long filters in the search before the first `|`). An `IN` list holds at
  most 1,000 values.
- At most 8 searches run at once (detections are counted separately), and one user's
  searches take at most 4 of those turns. Others wait their turn for up to 15 seconds,
  then fail with "Signalith is busy running other searches" (or "You already have several
  searches running"); try again shortly.

Use **Explain** in the UI, or `signalith query -explain "<query>"`, to see the plain-English
steps and the exact OpenSearch request.
