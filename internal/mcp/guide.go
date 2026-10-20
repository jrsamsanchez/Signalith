// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package mcp

// languageGuide is a short guide to the query language for the model. The
// full reference is docs/query-language.md.
const languageGuide = `A query is a search, then commands after |. It reads like Splunk SPL but is Signalith's own language.

Search:
  datamodel=Authentication      events of one data model (see datamodels); datamodel=Risk for risk events
  field=value                   exact match, case-insensitive; field=val* wildcard; field=* has a value
  src=10.0.0.0/8                IP range
  field!=value, NOT term, ( )   negation and grouping
  field=~"regex"                RE2 regular expression
  field>10 (also >= < <=)       comparison
  field IN (a, b, c)            any of several values
  word or "a phrase"            text anywhere in the raw event
  a OR b                        OR binds tighter than the implicit AND
  earliest=-7d@d latest=now     time range: -30s -15m -4h -7d -2w -1mon, snap with @d @h @w, or ISO 8601

Commands:
  stats count, dc(user) as users, avg(bytes) by src, dest   (count, count(f), dc, sum, avg, min, max)
  timechart span=1h count by action
  top limit=10 process_name by host
  where count > 20 AND users >= 2
  sort -count, src       head 20       table _time, user, src       rename src as source_ip (rename *_ip as *)
  search count>20 user=adm*   filter rows with search syntax after the first |
  top limit=5 useother=t showperc=f user   also countfield=, percentfield=, showcount=, otherstr=
  mvexpand f             one row per value of a multivalue field; makemv delim="," f splits text into one
  reverse                turn the row order around; tail 20 keeps the last 20; uniq drops exact repeats
  convert ctime(firstTime) AS first   format times (timeformat=), dur2sec, num, rmcomma, rmunit
  rex field=user mode=sed "s/^CORP\\\\//"   change text with a sed expression
  addtotals col=t        add each row's numbers into Total, and a totals row; addcoltotals for only that row
  lookup <table> <col> [OUTPUT cols]  add columns from an uploaded lookup table (admins add them on Settings > Lookups)
  | inputlookup [max=N] <table>  start a search with a lookup table's rows instead of events
  transaction f1, f2 [maxspan=10m] [maxpause=1m] [startswith="text"] [endswith=(search)]  group events into one row each, with duration and eventcount
  join [type=left] f1 [search <query>]  add the fields of a subsearch's rows that share f1
  append [search <query>]  add a subsearch's rows after the results
  appendpipe [stats sum(count) as count]  add summary rows made from the results so far
  streamstats [window=N] count, sum(bytes) by src  running totals in result order
  bin span=1h _time      round times (or numbers, span=100) into buckets
  regex field="<regex>"  keep rows that match; field!= keeps those that do not
  fields - f1, f2        remove fields
  | tstats count from datamodel=Authentication where Authentication.action=failure by Authentication.user  as in Splunk
  chart count over host by action   one column per action; xyseries and untable pivot and unpivot
  spath [path=a.b{}.c]   extract JSON values from _raw
  fromjson f [prefix=p]  extract the top-level keys of the JSON in f
  strcat, rangemap, mvcombine, nomv, foreach f_* [eval <<FIELD>>=...]  as in Splunk
  | makeresults [count=N]  start with N rows holding only _time
  | eventcount [index=pattern] [summarize=false]  start with the number of stored events, or a row per index
  enrich [fields]        add asset and identity context (priority, owner, watchlist)
  threatmatch [fields]   keep events whose fields match threat intel; must come right after the search
  intel [fields]         add threat intel context to any result

Quote values with spaces or symbols: process_path="C:\Windows\System32\cmd.exe".

Examples:
  datamodel=Authentication action=failure | stats count, dc(user) as users by src | where count > 20 | sort -count
  datamodel=Endpoint process_name=powershell.exe | table _time, host, user, process
  datamodel=Network_Traffic | threatmatch dest | stats count by src, dest, threat_source`
