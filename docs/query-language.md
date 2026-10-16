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
| `sourcetype`, `source` | Every event has its format as `sourcetype` (`WinEventLog:Security`, `linux:auth`, `aws:cloudtrail`) and where it was read from as `source`, as in Splunk: the log file (`/var/log/auth.log`), the Windows event log (`WinEventLog:Security`), `journald`, or how it arrived (`syslog`, `otlp`, `osquery`, `agent`). A sender's own `source` is kept. `stats count by sourcetype, source` shows what is coming in. Events stored before Signalith 0.3.0 have no `source`, and Linux agents installed before it give auth and audit lines the source `agent` until they are installed again from **Add data** |
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
| `streamstats` | `streamstats current=f window=5 avg(bytes) as prev_avg by src` | Adds running results to each row, over the rows before it in result order (events come newest first; `sort` first for oldest first). Takes `count`, `dc`, `sum`, `avg`, `min`, `max`, `range`, `first` and `last`. `current=f` leaves the row itself out; `window=N` (up to 10,000) looks back over the last N rows of each group |
| `timechart` | `timechart span=1h count by action` | One aggregation when splitting by a field; span picked automatically if omitted |
| `chart` | `chart count over host by action` | One row per `over` value and, with `by`, one column per `by` value: the 10 with the largest totals unless `limit=N` says (`0` for all, up to 1,000). Without a split field it is `stats ... by` the over field; `chart count by host, action` is the same as `over host by action`. Runs in OpenSearch like `stats` when it comes first |
| `xyseries` | `xyseries host action count` | Turns rows into one row per first field and one column per second field's value, holding the third; with several value fields the columns are named `count: allow` |
| `untable` | `untable host action count` | The reverse of `xyseries`: one row per cell, with the row field, the column's name and its value |
| `top` | `top limit=10 process_name by host` | Adds `count` and `percent`. `countfield=` and `percentfield=` rename them, `showcount=f` and `showperc=f` leave them out, and `useother=t` adds a row per group counting the values past the limit, with `OTHER` (or `otherstr=`) as the value. `top 5 user` is `limit=5` |
| `rare` | `rare limit=10 process_name by host` | Like `top`, least common values first |
| `search` | `search count>20 user=adm*` | After the first `\|`, filters the rows with the [search syntax](#search) (wildcards, bare words, `OR` binding tighter than the implicit AND). Right after the search it runs in OpenSearch. A query may also start with the word `search`, as copied from Splunk |
| `where` | `where count > 20 AND users >= 2` | AND binds tighter than OR here, as in most languages. Also takes [expressions](#expressions-eval-and-where): `where len(process) > 1000`, `where bytes_out > bytes_in * 10` |
| `eval` | `eval kb=round(bytes / 1024, 1), who=lower(user)` | Sets fields from [expressions](#expressions-eval-and-where). Separate several with commas; each sees the ones before it. A result that is null removes the field |
| `rex` | `rex field=process "-enc(?:odedcommand)? (?<encoded>\S+)"` | Extracts a field for each named group (`(?<name>...)` or `(?P<name>...)`) of an [RE2](https://github.com/google/re2/wiki/Syntax) regular expression. Reads `_raw` unless `field=` names another. `max_match=N` keeps up to N matches as a multivalue field (`0` for all). `mode=sed` changes the field's text with a sed expression instead: `rex field=user mode=sed "s/^CORP\\\\//"` replaces the first match (`g` for all, a number for that match only; `\1` and `&` in the replacement refer to the match), and `y/abc/xyz/` replaces characters one for one |
| `dedup` | `dedup user, host` | Keeps the first row for each combination of values; `dedup 3 user` keeps three. Events come newest first, so this keeps the latest. Rows missing a field are dropped unless `keepempty=true`; `consecutive=true` only drops repeats that follow each other. Sort before `dedup` to choose which row stays |
| `transaction` | `transaction host, user maxspan=30m startswith="Accepted" endswith=(action=logoff)` | Groups events that share the fields' values into one row each, oldest event first: `_time` is the first event's, `duration` the seconds to the last, `eventcount` how many, `_raw` their raw text one per line, and other fields the distinct values. A transaction ends where the next event would pass `maxspan=` (first to last) or `maxpause=` (between events) or `maxevents=` (default 1,000), or matches `startswith=`. With `startswith=`, events before a start are left out; with `endswith=`, transactions that never end are left out. Both take text found in `_raw` or a search in parentheses. Events missing a field are left out |
| `join` | `join type=left user [search datamodel=Change \| stats count as changes by user]` | Adds the fields of a subsearch's rows to the rows that share the join fields' values; the subsearch's values win. `type=inner` (the default) drops rows with no match, `type=left` keeps them. Each row takes the first match, `max=N` up to N, `max=0` all (up to 100). The subsearch searches the same time range unless it sets its own, may start with `search`, and counts toward the same limits; a query runs at most 10 subsearches, nested at most 3 deep |
| `append` | `append [search datamodel=Change \| stats count by user]` | Adds a subsearch's rows after the results. The subsearch works as in `join` and counts toward the same limits |
| `appendpipe` | `appendpipe [stats sum(count) as count \| eval user="TOTAL"]` | Runs the commands in `[ ]` over a copy of the results so far and adds the rows they give after them, for totals and summary rows. `inputlookup`, `makeresults`, `timechart` and `threatmatch` cannot run inside |
| `bin` | `bin span=1h _time` | Rounds values down into buckets so `stats ... by _time` groups them: a time span (`30s`, `15m`, `1h`, `1d`, `1w`; weeks start on Monday, all in UTC) on times, or a number span (`span=100`) that turns numbers into ranges like `200-300`. `AS name` writes the bucket to another field. Also `bucket` |
| `regex` | `regex process="(?i)-enc(odedcommand)?\s"` | Keeps rows where the field matches an [RE2](https://github.com/google/re2/wiki/Syntax) regular expression (any value of a multivalue field); `field!="..."` keeps those that do not. `regex "..."` looks at `_raw`. Rows without the field never match |
| `spath` | `spath output=user path=actor.user.name` | Extracts values from JSON in `_raw` (or `input=field`): the value at `path=` (`items{}.id` takes `id` from every item of the `items` array, as a multivalue field), written to `output=` or the path's name. Without a path it extracts every value (up to 500 per event), each named by its path. Objects and arrays come out as JSON text |
| `fromjson` | `fromjson body prefix=b_` | Extracts each top-level key of the JSON object in a field as a field of the same name, or `prefix=` and the name. Arrays of plain values come out as multivalue fields; objects and other arrays as JSON text. Up to 500 keys per event |
| `mvexpand` | `mvexpand user limit=100` | Makes one row for each value of a multivalue field, each a copy of the row with that one value (up to `limit=` values per row, and 100,000 rows). Rows without the field are dropped |
| `makemv` | `makemv delim="," recipients` | Splits a field's text into a multivalue field at `delim=` (a space by default), or takes each match of `tokenizer="<regex>"` (its first group if it has one). Empty values are dropped unless `allowempty=t` |
| `mvcombine` | `mvcombine host` | Merges rows that hold the same values in every field but one into a single row whose field holds all their distinct values, in the order the rows came. `delim=` is accepted for Splunk searches; the values stay a multivalue field |
| `nomv` | `nomv recipients` | Turns a multivalue field into one value, its values on separate lines |
| `strcat` | `strcat src ":" port addr` | Joins fields and quoted text into the last field named. A missing field adds nothing, unless `allrequired=t`, which leaves the row without the new field |
| `rangemap` | `rangemap field=count low=0-10 elevated=11-100 default=severe` | Sets `range` to the name of each inclusive range the field's number falls in (a multivalue field when it falls in several), or to `default=` (`None` unless set) |
| `fieldformat` | `fieldformat firstTime=strftime(firstTime, "%F %T")` | Accepted for Splunk searches and run as `eval`, so it changes the value itself, not only how it is shown. Put it last |
| `foreach` | `foreach bytes_* [eval <<FIELD>>=round(<<FIELD>>/1024, 1)]` | Runs the `eval` commands in `[ ]` once for each field whose name matches (`*` matches any text, once per name), with `<<FIELD>>` standing for the field's name and `<<MATCHSTR>>` for the text the `*` matched. Fields run in name order, up to 1,000; names other than letters, digits, `_` and dots between them are skipped |
| `reverse` | `reverse` | Turns the rows' order around, so events come oldest first |
| `tail` | `tail 20` | Keeps the last 20 rows (default 10), last first. On events, that is the oldest of those the search reads |
| `uniq` | `uniq` | Drops rows that repeat the row just before them exactly |
| `convert` | `convert timeformat="%Y-%m-%d %H:%M" ctime(firstTime) AS first, dur2sec(duration)` | Changes values in place, or into the `AS` field: `ctime` writes a time with `timeformat=` (default `%m/%d/%Y %H:%M:%S`), `mktime` reads one back into seconds, `dur2sec` reads `[D+]HH:MM:SS`, `mstime` reads `[MM:]SS.SSS`, `memk` reads sizes like `10m` as kilobytes, `rmcomma` and `rmunit` read numbers written with commas or units, `num` keeps only numbers and `auto` turns what it can into numbers. A field with `*` converts every matching field; `none(f)` leaves f out of them |
| `addtotals` | `addtotals fieldname=total bytes_*` | Adds each row's numeric fields (or the listed ones, `*` matching any text) into `Total` (or `fieldname=`). Fields starting with `_` are left out. `col=t` also adds a last row with each column's total, labelled with `label=` (default `Total`) in `labelfield=`; `row=f` leaves out the row totals. `addcoltotals [labelfield=f] [label=x]` adds only the column totals |
| `fillnull` | `fillnull value=0 bytes, packets` | Sets missing values (default `0`). With no fields it fills every column |
| `sort` | `sort -count, src` | `-` for descending |
| `head` | `head 20` | Also `limit` |
| `table` | `table _time, user, src` | Also `fields`; wildcards allowed. `fields - _raw, tmp_*` removes fields instead |
| `rename` | `rename src as source_ip, dest as target` | Pairs may be separated by commas or spaces. A `*` in the old name matches any text, which the new name's `*` takes: `rename *_ip as *` renames `src_ip` to `src`, `rename Processes.* as *` drops a `tstats` prefix. A renamed field replaces one that already had its new name |
| `lookup` | `lookup owners host OUTPUT owner, team` | Adds columns from a lookup table (Settings > Lookups) to rows whose field matches a key column; `host AS dest` matches another field, `OUTPUTNEW` fills only missing fields, no `OUTPUT` adds every column. See [Lookup tables](https://github.com/jrsamsanchez/signalith/blob/main/docs/lookups.md) |
| `makeresults` | `\| makeresults count=3 \| eval user="test"` | Starts a search with rows that hold only `_time` (now), for trying out `eval` and other commands; `count=N` makes up to 10,000. It must come first, with nothing before the `\|` |
| `tstats` | `\| tstats count from datamodel=Endpoint.Processes where Processes.process_name=cmd.exe by Processes.dest` | Splunk's `tstats`, read as the data model search and `stats` it stands for, so it runs in OpenSearch. CIM nodes map to Signalith's data models (`Endpoint.Processes` is `Endpoint`, `Endpoint.Filesystem` is `Filesystem`, `Network_Traffic.All_Traffic` is `Network_Traffic`), fields drop the node prefix (`Processes.dest` is `dest`) and result columns keep it, as in Splunk. `\| tstats count where index=* by index, sourcetype` counts events of any kind. `by _time span=1h` buckets times, which runs in the server over the newest events. `summariesonly=` and similar options are accepted and do nothing; `prestats=t` is not supported. It must come first |
| `inputlookup` | `\| inputlookup owners \| stats count by team` | Starts a search with a lookup table's rows instead of events; `max=N` reads at most N rows. It must come first, with nothing before the `\|` |
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

Any function can take an expression instead of a field, as in Splunk: `stats count(eval(action="failure")) as failures, values(eval(if(bytes>1000, dest, null()))) as big_dests by user`. Each needs `as name`. `count(eval(x))` counts the events where `x` is true. A search that uses one runs `stats` in the Signalith server over at most `search.max_events` events instead of in OpenSearch. `stats`, `eventstats`, `streamstats` and `chart` take these.

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
| `bytes`, `userIdentity.userName`, `'dc(user)'` | A field's value. Dots between name characters are part of the name, as in Splunk. Before Signalith 0.3.0, `a.b` joined the values of `a` and `b`; a saved search or custom detection written that way now reads the field `a.b`, so write `a . b` to join. Put names with other characters in single quotes (`'event code'`) |
| `"text"`, `42`, `1.5e3` | A string (double quotes) or a number |
| `+ - * / %` | Arithmetic. `+` also joins two strings. Dividing by zero gives null |
| `.` | Joins values as text, with spaces around it: `user . "@" . domain` |
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
| Multivalue | `split(s, ",")`, `mvcount(mv)`, `mvindex(mv, start[, end])` (from 0; negative counts from the end), `mvjoin(mv, ",")`, `mvappend(a, b, ...)`, `mvdedup(mv)`, `mvsort(mv)`, `mvfind(mv, "regex")` (the first matching value's index), `mvzip(a, b[, ","])` (pairs of values joined), `mvfilter(match(email, "@corp$"))` (the values for which the expression is true; it must use one field), `mvmap(sizes, sizes * 2)` (the expression for each value). `mvfilter` and `mvmap` go through at most 10 million values in one search, counting the values of nested calls |
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
  `rex`, `dedup`, `eventstats`, `streamstats`, `bin`, `regex`, `append`, `appendpipe`,
  `xyseries`, `untable`, `spath`, `fromjson`, `mvexpand`, `mvcombine`, `nomv`, `strcat`, `rangemap`, `foreach`, `makemv`, `reverse`, `tail`, `uniq`, `convert`, `addtotals`, and a
  `where` written as an expression, wherever they are.
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
