# Dashboards

The **Dashboards** tab has two built-in dashboards, **Security posture** and
**Malware**, and any custom dashboards you build. Pick one from the list at the top left, choose a time
range, and optionally turn on auto-refresh (every minute, 5 or 15 minutes; it pauses
while the browser tab is hidden).

## Security posture

The built-in dashboard, like the Splunk ES Security Posture and executive summary
dashboards. Every key number is compared with the previous period of the same
length, so "Last 24 hours" compares today with the 24 hours before.

| Panel | What it shows |
| --- | --- |
| Open findings | Findings not yet resolved or closed, with a count per urgency |
| New findings | Findings raised in the period |
| Findings closed | Findings moved to resolved or closed in the period |
| Mean time to triage | From a finding being raised to its first status change or owner assignment, for findings triaged in the period |
| Mean time to resolve | From a finding being raised to it being resolved or closed, for findings closed in the period |
| Events ingested | Events stored in the period, all data models except Risk |
| Findings over time by urgency | New findings per hour (or per 15 minutes, 6 hours or day, depending on the range) |
| Top detections firing | Findings plus risk events per detection; click one to open it |
| Top risk objects | Users and systems with the most risk; click one to open it on the Risk page |
| ATT&CK tactics seen | Findings and risk events per ATT&CK tactic, in matrix order |
| Detection health | Enabled detections, detections whose last run failed, enabled detections with no findings and no risk events in 30 days, and data sources that stopped sending |
| Events by data model, by source type | Event volume over time |

A data source is a host and source type pair. It counts as stopped when it sent
events in the last 7 days but nothing for `dashboards.stale_after` (default `2h`).
Raise the setting for hosts that send in bursts:

```yaml
dashboards:
  stale_after: 6h
```

Each section loads on its own: if one part fails (for example, OpenSearch rejects a
query), that card shows the error and the rest of the dashboard still works. Cards
with an **Open in Search** link show the exact query behind them.

## Malware

A built-in panel dashboard for antivirus data: hosts with malware, malware not
removed, protection turned off, the top threats and hosts, protection rule blocks
and antivirus health problems, across Microsoft Defender, ClamAV and antivirus
consoles. It opens on the last 7 days. Until antivirus events arrive it shows a
**Set up antivirus logs** button (for admins) that opens Add data. See
[antivirus.md](antivirus.md#the-malware-dashboard) for each panel.

## Built-in dashboards are read-only

Built-in dashboards are part of Signalith and change only with it, so they have
no Settings, Add panel or panel editing, and the panel menu has only **Open in
Search**. **Download YAML** saves the Malware dashboard's definition, and works
without `dashboards.dir`.

To change one, choose **Make a copy** (analysts and admins, when custom dashboards
are on). It saves *Malware (copy)* as a custom dashboard with the same panels and
opens it, ready to edit. **Add to dashboard** on the Search page lists custom
dashboards only.

The ids `posture` and `malware` belong to the built-in dashboards. A file
`malware.yaml` in `dashboards.dir` is ignored and listed as a problem: rename the
file and change its `id` to keep it.

## Custom dashboards

A custom dashboard is a list of **panels**. Each panel is a Signalith query and a
way to show its result.

| Visualization | `viz` | Best for |
| --- | --- | --- |
| Single value | `single` | `| stats count` or any query whose first row has a number; can show the change from the previous period |
| Table | `table` | Any result |
| Bar chart | `bar` | `| stats count by field`, `| top field`; one bar per row |
| Line chart | `line` | `| timechart ...` |
| Stacked columns | `area` | `| timechart ...`; one column per time bucket, series stacked |

Ways to add a panel:

- **From Search.** Run a search, then click **Add to dashboard**. Pick a dashboard
  (or create one), check the preview and save. If the query came from the plain-English
  Ask box, the question becomes the panel title.
- **Ask in plain English.** In **Add panel**, type a question such as *failed logins
  by source ip* and click **Write query**. The query is written for you (and by the AI
  model if one is configured and the question needs it), and a preview runs.
- **Write the query** yourself; the visualization is picked from its shape
  (`timechart` is a line, `stats` with no `by` a single value, other `stats` and
  `top` bars, anything else a table). You can change it.

Click **Edit dashboard** to rename it, set its default time range and auto-refresh,
move panels up and down, remove panels, or delete the dashboard. **Edit** on a panel
changes its query, title, visualization or width. **Search** on a panel opens its
query on the Search page.

Panels run in parallel, four at a time, through the same engine as the Search page.
A panel whose query fails shows the error in its own card; the others are not
affected. A panel returns at most 500 rows.

## Where dashboards live

Each custom dashboard is one YAML file, `<id>.yaml`, in `dashboards.dir` (default: a
`dashboards` folder next to the config file; `/var/lib/signalith/dashboards` for the
systemd unit and Docker image; `SIGNALITH_DASHBOARDS_DIR` overrides it). Saving in
the UI writes the file. Files are read every time the list or a dashboard is opened,
so dashboards you copy in or `git pull` show up without a restart. A file with
mistakes is listed at the top of the Dashboards page with every problem, and
`signalith validate` checks every file.

## Format

```yaml
id: auth-watch              # 3-64 lowercase letters, digits, - or _; must match the file name
title: Authentication watch
description: Failed logons and where they come from    # optional
time_range: 24h             # default range: m, h, d or w; the page's picker overrides it
refresh: 5m                 # optional auto-refresh, at least 30s; empty is off
panels:
  - title: Failed logons
    query: datamodel=Authentication action=failure | stats count
    viz: single
    compare: true           # show the change from the previous period
    width: third            # third, half or full
  - title: Distinct users targeted
    query: datamodel=Authentication action=failure | stats count, dc(user) as users
    viz: single
    field: users            # which column a single value shows (default: the first number)
  - title: Logons over time
    query: |
      datamodel=Authentication
      | timechart count by action
    viz: area
    width: full
  - title: Failures by source
    query: |
      datamodel=Authentication action=failure
      | stats count by src
      | sort -count
      | head 10
    viz: bar
  - title: Accounts created this week
    query: datamodel=Change action=created earliest=-7d | table _time, host, user, object
    viz: table
```

| Key | Default | Meaning |
| --- | --- | --- |
| `id` | from the title | File name without `.yaml`. `posture` and `malware` are reserved for the built-in dashboards |
| `title` | required | Shown in the dashboard list |
| `description` | none | Shown under the title |
| `time_range` | `24h` | Default time range for panels |
| `refresh` | off | Auto-refresh interval |
| `panels[].title` | required | Panel heading |
| `panels[].query` | required | Any Signalith query; see [query-language.md](query-language.md) |
| `panels[].viz` | from the query | `single`, `table`, `bar`, `line` or `area` |
| `panels[].width` | `third` for single values, `full` for line and area, else `half` | Panel width on wide screens; every panel is full width on a phone |
| `panels[].field` | first number | Column a single value shows |
| `panels[].compare` | `false` | Single values only: also run the query over the previous period and show the change |

A query that sets its own `earliest=` keeps it whatever the time picker says.
`compare` needs a relative range such as `24h` or `earliest=-7d`; a query with
`latest=` is not compared. Unknown keys are rejected so typos are caught.

## API

Every endpoint needs the admin sign-in, like the rest of the API.

| Endpoint | Purpose |
| --- | --- |
| `GET /api/posture?range=24h` | The security posture report (range 1m to 90d) |
| `GET /api/dashboards` | List: the built-in dashboards (posture, then malware, each with `"builtin": true`, even when custom dashboards are off), every custom one, and files with problems |
| `POST /api/dashboards` | Create; without `id`, one is made from the title. 409 if the id exists or belongs to a built-in dashboard |
| `GET /api/dashboards/{id}` | One dashboard as JSON |
| `GET /api/dashboards/{id}/yaml` | Download its YAML file |
| `PUT /api/dashboards/{id}` | Replace a dashboard (save edits, reorder panels) |
| `DELETE /api/dashboards/{id}` | Delete its file |
| `POST /api/dashboards/{id}/panels` | Append one panel (`{"title", "query", "viz", ...}`) |
| `POST /api/dashboards/{id}/run` | Run every panel; body `{"range": "7d"}` is optional. Returns one result per panel, each with `result`, `value` and `previous` for single values, or `error` |
| `POST /api/panels/run` | Run an unsaved panel: `{"range": "24h", "panel": {...}}` |

Validation errors return 400 with a `problems` list naming each field to fix.

`GET`, `/yaml` and `/run` also work for the built-in `malware` dashboard, without
`dashboards.dir`. `PUT`, `DELETE` and adding a panel to it return 400: *The Malware
dashboard is built in and can’t be changed. Make a copy to change it.*
