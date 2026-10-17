# Summary indexes

Signalith keeps summaries of your events so that dashboards and long
searches stay fast as data grows. Splunk Enterprise Security users know the
idea as data model acceleration. You don't need to set anything up: it is on
by default and searches use it on their own.

## What gets summarized

For each data model (Authentication, Network Traffic, Web and the rest), the
server that runs the background jobs counts events in 5-minute slots, once per
combination of the model's main fields. For Authentication those are fields
such as `action`, `user`, `src`, `dest` and `app`. For Network Traffic they
include `src`, `dest`, `dest_port` and `transport`. Every model also has
`host`, `sourcetype`, `source`, `vendor_product`, `signature_id` and
`signature`. A few models also keep sums: `bytes`, `bytes_in`, `bytes_out`,
`packets_in` and `packets_out` for Network Traffic, `bytes_in` and `bytes_out`
for Web, `file_size` for File Transfers, and `risk_score` for Risk.

The summaries go back `search.summary_days`, 30 days unless you change it on
the **Settings** page (**Search** card, **Summaries go back**). The most is
400 days and 0 turns summaries off. A data model whose retention policy keeps
events for less time gets summaries for that long only, so summaries never
outlive the events retention deletes. When a day's events go before that (a
size cap or the low disk guard deleted them early), its summaries go within a
minute too.

## Which searches use them

A search reads summaries when all of these are true:

- its first command is `stats`, `chart`, `timechart` or `tstats`,
- that command only counts (`count`) or adds up a summed field
  (`sum(bytes)`),
- it groups only by the model's main fields,
- the search only filters on the model's main fields, with no free text,
  `_raw` or `index=`,
- `timechart` buckets are whole 5-minute slots: `span=5m`, `10m`, `1h`,
  `1d`, a week, a month and so on.

For example, these searches read summaries:

```
datamodel=Authentication action=failure | stats count by src, user
datamodel=Network_Traffic | stats sum(bytes) as bytes by dest_port
datamodel=Authentication | timechart span=1h count by action
| tstats count from datamodel=Authentication by Authentication.src
* | stats count by sourcetype
```

These read the events as before:

```
datamodel=Authentication "failed password" | stats count
datamodel=Authentication | stats dc(user) by src
datamodel=Authentication | timechart span=1m count
```

When a search used summaries, the results show a **Summarized** badge next to
the time it took.

Detections, behavior baselines and the data source watch never read
summaries: they always search the events, so an event that arrives late
counts at their next run.

## Results are the same

A summarized search reads summaries only for whole 5-minute slots that the
summaries already cover. It reads the events themselves for everything else:
the newest few minutes, the partial slots at the start and end of the time
range, and any hours that were too varied to summarize. You get the same
counts as a search of the events, just faster.

The summaries are checked against the events every 10 minutes for the last two
days, and every 6 hours for the whole range. A slot whose count changed gets
summarized again. That covers events that arrived late, sample data added or
removed, and days restored from the archive.

## Good to know

- Summaries are stored in OpenSearch in monthly indices named
  `<prefix>_summary-YYYY.MM`, next to your events. They take a small fraction
  of the space of the events they count.
- Only the server that runs the background jobs builds summaries. When it
  hands the jobs to another server, that server carries on where it left off.
- The first time, summaries are built for the whole range in the background,
  about a day per data model per minute. Searches read the events until a
  range is summarized.
- An hour with more than 100,000 different combinations of a model's main
  fields, or with very long values, is not summarized. Neither is an hour
  that keeps failing to summarize. Searches read those hours' events instead.
- Summaries hold the same field values as the events they count, such as user
  names and addresses. They are kept in the same OpenSearch, with the same
  protection, and anyone who can search events can search them.
