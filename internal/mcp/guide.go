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
  sort -count, src       head 20       table _time, user, src       rename src as source_ip
  enrich [fields]        add asset and identity context (priority, owner, watchlist)
  threatmatch [fields]   keep events whose fields match threat intel; must come right after the search
  intel [fields]         add threat intel context to any result

Quote values with spaces or symbols: process_path="C:\Windows\System32\cmd.exe".

Examples:
  datamodel=Authentication action=failure | stats count, dc(user) as users by src | where count > 20 | sort -count
  datamodel=Endpoint process_name=powershell.exe | table _time, host, user, process
  datamodel=Network_Traffic | threatmatch dest | stats count by src, dest, threat_source`
