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
| `datamodel=Authentication` | Events of one data model: Authentication, Endpoint, Network_Traffic, Change, Malware (antivirus; see [antivirus.md](antivirus.md)), Filesystem, Registry, Network_Resolution, Intrusion_Detection, Web, Certificates, File_Transfers (the last four from a [network sensor](network-sensor.md)), Image_Load, Script, Inventory, Configuration_Check, Alerts, Other. `datamodel=Risk` searches risk events, which are left out otherwise |
| `index=signalith-authentication-2026.10.*` | One pattern of Signalith's daily indices, `<prefix>-<datamodel>-YYYY.MM.DD`. It must start with the configured `opensearch.index_prefix` and `-`; `index=*` means all events, as when `index=` is left out. Lists (`a,b`), exclusions (`-x`), other indices and system indices, other clusters (`remote:x`) and date math are refused |
| `index` as a field | Every event has the daily index it is stored in as the field `index`, as in Splunk: `stats count by index`, `table _time index host`, `where index="signalith-web-2026.10.15"`, `(index=signalith-web-* OR index=signalith-authentication-*)`. It takes `=` and `!=` with `*` wildcards (not `=~` or `<`), and in `stats` it works with `count`, `dc`, `values` and `mode` and as a `by` field |
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
| `stats` | `stats count, dc(user) as users, perc95(bytes) by src, dest` | Functions are listed [below](#stats-functions) |
| `eventstats` | `eventstats avg(bytes) as avg_bytes by src` | Same [functions](#stats-functions) as `stats`, but adds the results to every row instead of replacing the rows, so later commands can compare each event with its group: `\| where bytes > avg_bytes * 10` |
| `timechart` | `timechart span=1h count by action` | One aggregation when splitting by a field; span picked automatically if omitted |
| `top` | `top limit=10 process_name by host` | Adds `count` and `percent` |
| `rare` | `rare limit=10 process_name by host` | Like `top`, least common values first |
| `where` | `where count > 20 AND users >= 2` | AND binds tighter than OR here, as in most languages. Also takes [expressions](#expressions-eval-and-where): `where len(process) > 1000`, `where bytes_out > bytes_in * 10` |
| `eval` | `eval kb=round(bytes / 1024, 1), who=lower(user)` | Sets fields from [expressions](#expressions-eval-and-where). Separate several with commas; each sees the ones before it. A result that is null removes the field |
| `rex` | `rex field=process "-enc(?:odedcommand)? (?<encoded>\S+)"` | Extracts a field for each named group (`(?<name>...)` or `(?P<name>...)`) of an [RE2](https://github.com/google/re2/wiki/Syntax) regular expression. Reads `_raw` unless `field=` names another. `max_match=N` keeps up to N matches as a multivalue field (`0` for all) |
| `dedup` | `dedup user, host` | Keeps the first row for each combination of values; `dedup 3 user` keeps three. Events come newest first, so this keeps the latest. Rows missing a field are dropped unless `keepempty=true`; `consecutive=true` only drops repeats that follow each other. Sort before `dedup` to choose which row stays |
| `fillnull` | `fillnull value=0 bytes, packets` | Sets missing values (default `0`). With no fields it fills every column |
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

### Stats functions

`stats`, `eventstats` and `timechart` take these, each optionally followed by `as name`:

| Function | Result |
| --- | --- |
| `count`, `count(f)` | Events, or events where `f` has a value |
| `dc(f)` | Distinct values of `f` (approximate above a few thousand, as OpenSearch counts them) |
| `sum(f)`, `avg(f)`, `min(f)`, `max(f)`, `range(f)` | Totals, average, smallest, largest, and largest minus smallest |
| `median(f)`, `perc95(f)` | The median and any percentile from `perc1` to `perc99` (`p95` works too). OpenSearch estimates these on large data |
| `stdev(f)`, `var(f)` | Sample standard deviation and variance |
| `mode(f)` | The most common value |
| `values(f)` | The distinct values, sorted, up to 100 |
| `list(f)` | The values, newest first, up to 100 |
| `first(f)`, `latest(f)` | The newest value; `last(f)` and `earliest(f)` give the oldest |

## Expressions (eval and where)

`eval` computes values with expressions, and `where` accepts the same expressions
whenever its condition is more than a field compared with a value:

```
datamodel=Network_Traffic bytes_out>1000000
| eval ratio=round(bytes_out / bytes_in, 1), direction=if(cidrmatch("10.0.0.0/8", dest), "internal", "external")
| where ratio > 10 AND direction="external"
```

| Syntax | Meaning |
| --- | --- |
| `bytes`, `'dc(user)'` | A field's value. Put names with characters other than letters, digits, `_` and `@` in single quotes (`'event.code'`) |
| `"text"`, `42`, `1.5e3` | A string (double quotes) or a number |
| `+ - * / %` | Arithmetic. `+` also joins two strings. Dividing by zero gives null |
| `.` | Joins values as text: `user . "@" . domain` |
| `= != < <= > >=` | Compare numbers as numbers, everything else as case-sensitive text. A multivalue field equals a value when any of its values does |
| `LIKE` | `user LIKE "adm%"`: `%` is any run of characters, `_` any one character, case-sensitive |
| `AND`, `OR`, `XOR`, `NOT`, `( )` | Combine conditions |

A comparison with a missing field is null, which `where` treats as false. Use `isnull()`,
`isnotnull()` or `coalesce()` to handle missing values.

`where` keeps its plain filter reading for conditions such as `count > 20`,
`user=adm*` or `src IN (a, b)`: there the right side is a value, matching ignores case and
`*` is a wildcard. As soon as the condition uses a function, arithmetic or a quoted field
name it is read as an expression, so `where bytes_out > bytes_in` compares the text
`bytes_in`, while `where bytes_out > bytes_in * 1` compares the two fields.

| Functions | |
| --- | --- |
| Conditions | `if(cond, then, else)`, `case(cond1, value1, cond2, value2, ...)` (null when none is true), `coalesce(a, b, ...)` (first non-null), `nullif(a, b)`, `null()`, `true()`, `false()` |
| Tests | `isnull(x)`, `isnotnull(x)`, `isnum(x)`, `isstr(x)`, `typeof(x)`, `in(x, v1, v2, ...)`, `like(x, "a%")`, `match(x, "regex")`, `cidrmatch("10.0.0.0/8", ip)` |
| Text | `lower(s)`, `upper(s)`, `len(s)`, `substr(s, start[, length])` (start at 1; negative counts from the end), `replace(s, "regex", "with \1")`, `trim(s[, chars])`, `ltrim`, `rtrim`, `urldecode(s)`, `md5(s)`, `sha1(s)`, `sha256(s)` |
| Numbers | `round(x[, digits])`, `floor(x)`, `ceil(x)`, `abs(x)`, `sqrt(x)`, `pow(x, y)`, `exp(x)`, `ln(x)`, `log(x[, base])`, `min(...)`, `max(...)` |
| Conversion | `tonumber(s[, base])`, `tostring(x[, "hex" \| "commas" \| "duration"])` |
| Multivalue | `split(s, ",")`, `mvcount(mv)`, `mvindex(mv, start[, end])` (from 0; negative counts from the end), `mvjoin(mv, ",")`, `mvappend(a, b, ...)`, `mvdedup(mv)`, `mvsort(mv)` |
| Time | `now()` and `time()` (epoch seconds), `strftime(_time, "%Y-%m-%d %H:%M:%S")`, `strptime("2026-10-15", "%Y-%m-%d")` (to epoch seconds). Times are UTC; `strftime` takes epoch seconds or an event's `_time` |

Regular expressions use RE2 syntax and are case-sensitive unless they start with `(?i)`.
To keep one search from exhausting the server, a value `eval` builds can be up to 1 MB
(a multivalue field counts all its values), expressions build at most 256 MB across all
rows and commands of one search, a multivalue field holds up to 10,000 values, and one
expression has at most 10,000 terms.

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
| median bytes, 95th percentile of duration, standard deviation of bytes | `median()`, `perc95()`, `stdev()` |
| per user, by source ip, for each host | `by ...` |
| top 10 users, most common processes, rare processes | `top`, `rare`, or `stats ... \| sort \| head` |
| latest login per user, most recent process for each host | `dedup user` (events come newest first) |
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
- Commands after that run in the Signalith server on the aggregated rows. So do `eval`,
  `rex`, `dedup`, `eventstats`, and a `where` written as an expression, wherever they are.
- An event search without `stats` returns the newest 100 events, or up to
  `search.max_events` (at most 100,000) when later commands need to sort, filter,
  de-duplicate or aggregate them all. To work on more events, filter in the search or
  aggregate with `stats` first.
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
