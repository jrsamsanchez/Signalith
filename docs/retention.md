# Data retention

Signalith keeps events in daily OpenSearch indices, one per data category and day
(`<prefix>-endpoint-2026.10.12`). Retention policies decide, for each category:

- how many days it stays searchable,
- how large it may grow,
- when old days are compacted to save space,
- whether days are archived to files before they are deleted.

Findings and investigations have their own policy. A **disk guard** keeps
OpenSearch from filling its disk.

Set everything on the **Data retention** tab of **Settings** (admins only): select a
category to change its policy, or edit the default policy and the disk guard under
**Defaults**. The dialog shows what saving would delete, archive or compact before you
save, including days that are already due and go in the same run, and asks again
before anything is deleted. Changes apply at once: saving starts a retention run, with
no restart. If a run or restore is going, the new run starts as soon as it ends, and
the run in progress already skips anything the new settings keep. The same settings can be written in
`signalith.yaml` instead (see [Settings in signalith.yaml](#settings-in-signalithyaml)).

## Categories

| Category | ID | Stored in | Policy |
| --- | --- | --- | --- |
| Authentication | `authentication` | `<prefix>-authentication-YYYY.MM.DD` | Event policy |
| Endpoint | `endpoint` | `<prefix>-endpoint-YYYY.MM.DD` | Event policy |
| Network traffic | `network_traffic` | `<prefix>-network_traffic-YYYY.MM.DD` | Event policy |
| Change | `change` | `<prefix>-change-YYYY.MM.DD` | Event policy |
| Filesystem | `filesystem` | `<prefix>-filesystem-YYYY.MM.DD` | Event policy |
| Registry | `registry` | `<prefix>-registry-YYYY.MM.DD` | Event policy |
| Network resolution | `network_resolution` | `<prefix>-network_resolution-YYYY.MM.DD` | Event policy |
| Image load | `image_load` | `<prefix>-image_load-YYYY.MM.DD` | Event policy |
| Script | `script` | `<prefix>-script-YYYY.MM.DD` | Event policy |
| Inventory | `inventory` | `<prefix>-inventory-YYYY.MM.DD` | Event policy |
| Configuration check | `configuration_check` | `<prefix>-configuration_check-YYYY.MM.DD` | Event policy |
| Alerts | `alerts` | `<prefix>-alerts-YYYY.MM.DD` | Event policy |
| Other events | `other` | `<prefix>-other-YYYY.MM.DD` | Event policy; listed once it has data or a policy |
| Risk events | `risk` | `<prefix>-risk-YYYY.MM.DD` | Event policy |
| Findings | `findings` | `<prefix>_findings` | Delete closed findings after N days |
| Investigations | `cases` | `<prefix>_cases` | Delete closed cases after N days |
| Threat intel | `intel` | `<prefix>_intel` | Managed by feeds: indicators expire through each feed's `max_age` |

Days are UTC days, the same days the index names use.

## Event policies

| Setting | Meaning |
| --- | --- |
| **Keep** (`keep_days`) | Days a category stays searchable. `0` keeps it forever. A day is deleted once it is more than `keep_days` days old, so `90` keeps today and the 90 days before it |
| **Size cap** (`max_size_gb`) | Largest the category may be, in GB (1 GB = 2^30 bytes) of disk, replicas included. Over the cap, its oldest days are deleted until it fits. `0` means no cap |
| **Compact after** (`compact_after_days`) | Days after which a day is made read-only and force-merged to one segment. `0` never compacts. Must be less than `keep_days` |
| **Archive before deleting** (`archive`) | Write each day to a compressed file before deleting it, so it can be restored later |

A category without its own policy uses the **default policy**. Until you save a
default on the page, the default is `retention.days` from signalith.yaml (90 days,
nothing else), which is exactly how retention worked before policies existed. A
default saved on the page replaces `retention.days`. To make the default a fixed
limit that the page cannot change, set `retention.default` in signalith.yaml.

**Compaction** makes old days smaller and cheaper to search: fewer segments,
deleted documents purged, and less memory for OpenSearch. Today and yesterday are
never compacted. A compacted day is read-only. If an agent sends events for that
day later, OpenSearch refuses them and they are lost; the server logs "some events
were rejected". So set **Compact after** above the longest time your agents can be
offline. For laptops that may be away for a week, use 14 or more.

**Size caps** are checked after `keep_days`. They never delete today's data or a
restored day, and restored days do not count toward the cap, so restoring days for
an investigation never pushes live days out. If only today's or restored data is
left and the category is still over its cap, the page says so.

A day that OpenSearch cannot read, because a primary shard is missing (a red index,
for example while its node is down), is left alone: it is not deleted, archived or
compacted until OpenSearch recovers, and the page lists it.

## Findings and investigations

The policy for **Findings** and **Investigations** has one setting, `keep_days`. It
is off by default, which keeps them forever. When it is set, retention deletes only
the ones that are **resolved or closed** and have not changed for more than
`keep_days` days. New, in-progress and pending items are never deleted, whatever
their age.

Findings that belong to an investigation are kept as long as the investigation is,
open or closed: a case stores only the IDs of its findings, so deleting them would
leave the case with gaps. Once the investigation itself is deleted, its findings
follow the findings policy. A case keeps its own notes, search snapshots and pinned
events, so it outlives the event days it came from. If the investigations cannot be
listed, or there are more than 60,000 of them, no findings are deleted in that run.

## The disk guard

OpenSearch protects itself when a data disk fills up. At 85% (the low watermark) it
stops placing new replica shards on the node. At 90% (the high watermark) it moves
shards away from the node. At 95% (the flood stage) it makes every index with a
shard on that node read-only, and ingest stops until space is freed. The page counts
the indices OpenSearch has blocked this way.

The disk guard acts first. When the fullest OpenSearch data disk is above
**Max disk use** (default 85%), it deletes the oldest event days, in any category,
until the disk is back under the limit:

- It counts what the policies already delete before deleting more.
- It never deletes the last **Min days** days (default 7), today, restored days, or
  days OpenSearch cannot read.
- It never touches findings, cases or threat intel.
- A category set to archive is archived first, as usual. If a day cannot be archived
  or deleted, the guard keeps it and picks the next oldest day instead.
- It deletes only when that helps. When even every day it may delete cannot get the
  disk under the limit, usually because other files fill the disk, it deletes only
  the oldest days needed to keep the disk below 95%, where OpenSearch stops taking
  events. If that is out of reach too, it deletes nothing. Either way the page says
  so, and the server logs an error.

Disk use is `(total - available) / total`, the same formula OpenSearch's watermarks
use. So space used by other files on the same disk counts too. On a cluster with
several data nodes, the guard follows the fullest node's disk and counts only the
shards each day has on that node.

If OpenSearch has already reached the flood stage, the guard still frees space.
Blocked indices can still be read and deleted, so they are archived (when the policy
says so) and deleted as usual. Compaction waits until OpenSearch lifts the block,
which it does by itself once disk use falls below the high watermark.

The guard is **on by default**, including on servers upgraded from an earlier
version. A server whose OpenSearch disk is already above 85% deletes its oldest days
(older than 7 days) at the first run after the upgrade, as far as that gets the disk
under the limit. To prevent this, turn the guard off or raise its limit (up to 94%)
before upgrading, by setting `retention.guard` in signalith.yaml.

The guard runs with every retention run. Between runs it also checks the disk every
5 minutes and starts a run when the disk passes the limit. If it cannot get the disk
under the limit, or days it chose could not be deleted, the page says so and the
guard waits for the next scheduled run instead of checking every 5 minutes. Add disk
space, lower **Min days** or the policies' **Keep**, or look for other data on the
same disk. While `retention.yaml` has errors, the guard is paused like every other
part of retention, and the page says so.

## Archives

With **Archive before deleting** on, each day is archived and checked before its
index is deleted:

1. The index is made read-only and refreshed, so the copy holds every event,
   including those written in the last seconds before.
2. Every event is written to `<index>.ndjson.gz`, one `{"_id": ..., "_source": ...}`
   per line, then flushed to disk with fsync.
3. A manifest `<index>.json` is written beside it, with the event count, file size,
   SHA-256 and creation time.
4. The file is read back and checked against the manifest. Its event count must also
   match the index's count.
5. Only then is the index deleted.

If anything fails (a full archive disk, a count that does not match, an OpenSearch
error), the index is kept, made writable again, and the error is listed in the run's
history. The next run tries again. Before writing, retention checks that the archive
folder's disk has room for about half the day's size in OpenSearch, and keeps the
day if it does not.

Put the archive folder on a different disk from OpenSearch's data. By default it is
on the same disk (next to the lookups folder), and then archiving the days the guard
picks takes space on the very disk the guard is trying to free. The page warns when
both look like the same disk.

On Linux, files are written with mode 0600 in a folder with mode 0700. On Windows,
the server gives the archive folder an access list of its own, not inherited from
the drive: full control for SYSTEM, Administrators and the server's account, nobody
else. To set it up by hand for a folder you create yourself:

```powershell
icacls D:\SignalithArchive /inheritance:r /grant:r "Administrators:(OI)(CI)F" "SYSTEM:(OI)(CI)F"
```

Each archive records the ID (UUID) of the exact index it came from. If late events
recreate a day after it was archived and deleted, the new index has a new UUID, so
it is archived again before it is deleted. The new copy gets its own ID, such as
`signalith-endpoint-2026.07.01.2`. A restored day is not archived a second time: the
index notes the archives it was restored from.

The archive folder is `retention.archive_dir`, `SIGNALITH_ARCHIVE_DIR`, or an
`archive` folder next to `lookups.dir`. Docker images and the systemd unit use
`/var/lib/signalith/archive`; in Docker, mount a volume there to keep archives
outside the container. Archives are plain gzip and JSON, so `zcat file.ndjson.gz | head` works
and any tool can read them. Move older files to cheaper storage as you like:
retention never deletes archive files.

Example manifest:

```json
{
  "format": "signalith-archive/1",
  "id": "signalith-endpoint-2026.07.01",
  "index": "signalith-endpoint-2026.07.01",
  "category": "endpoint",
  "day": "2026-07-01",
  "docs": 1840221,
  "file": "signalith-endpoint-2026.07.01.ndjson.gz",
  "bytes": 211630580,
  "index_bytes": 1073741824,
  "sha256": "ace69f8245...",
  "created": "2026-10-04T03:00:12Z"
}
```

### Restoring

On the page, open **Archive**, select days and choose **Restore**. Before anything is
restored, the dialog shows how much space the days take in OpenSearch and how full
the disk will be. Restored days are spared by size caps and the guard, so if the
restore takes the disk over the guard's limit, the guard makes room by deleting the
oldest live days of other categories. The dialog then names how many days that
would be, and whether they are archived, and asks you to confirm. A restore that
would fill the disk to 95% needs confirmation too.

You can also use the CLI on the server:

```sh
signalith archive list
signalith archive verify signalith-endpoint-2026.07.01
signalith archive restore -keep-days 30 signalith-endpoint-2026.07.01
```

The CLI reads `retention.archive_dir` from signalith.yaml, or `SIGNALITH_ARCHIVE_DIR`.
The systemd unit sets that variable only for the service, so on those installs give
the folder with `-dir`:

```sh
sudo -u signalith signalith archive list -c /etc/signalith/signalith.yaml -dir /var/lib/signalith/archive
```

The CLI installs Signalith's index template before it restores, so restored days get
the same field types as live ones, even on a new OpenSearch that the server has not
started against yet. It does not check the disk first; use the page for that.

A restore works like this:

- It checks the whole file against its manifest first, so a damaged file restores
  nothing.
- It writes the events back into their original index, so ordinary searches over
  that day find them again.
- Each event keeps its original ID, so restoring the same day twice does not
  duplicate anything. An interrupted restore can be run again to finish.
- A restored day stays searchable for the days you choose (14 by default, up to
  365). Retention, the size cap and the disk guard leave it alone until then. After
  that, the category's policy applies again and the day is deleted without being
  archived a second time.

Restores from the page run in the background, one at a time, and never during a
retention run.

## Compliance examples

**Keep 90 days searchable and 1 year archived.** Set the default policy to keep 90
days and turn **Archive before deleting** on. Each day is archived when it turns 91
days old. Signalith never deletes archive files. To keep a year in all, delete each
day's files once the day is a year old. That is about 275 days after the file was
written:

```sh
find /var/lib/signalith/archive -type f -mtime +275 -delete
```

Each manifest records the day it holds (`day`). Use it instead of file times if
your policy must be exact to the day.

**Keep authentication events for a year, everything else for 30 days.** Set the
default to 30 days and give **Authentication** its own policy of 365 days.

**Keep endpoint data under 500 GB.** Give **Endpoint** a 500 GB size cap. Add
`keep_days` as well if you also need a time limit.

**Keep closed investigations for 3 years.** Give **Investigations** a policy of 1095
days. Open cases are never deleted.

## Runs and history

Retention runs every hour (`retention.interval`) on the server that runs the
background jobs. It also runs when settings are saved, when **Run now** is pressed,
and when the disk guard trips. The first scheduled run is 2 minutes after the server
starts running the jobs. A server with `detections.scheduler: false` logs a warning
at startup that it never runs retention.

Each run plans first and then acts. The preview in the page's dialogs uses the same
planner, so what it shows is what the next run does. Deletions run oldest day first,
then compactions. Before each step, the run reads the settings again and skips any
step that settings saved meanwhile no longer call for, so a correction saved during
a long run takes effect at once.

Retention only touches indices named `<prefix>-<category>-YYYY.MM.DD` with a known
category and a valid date, plus the findings and cases indices. Anything else under
the prefix is listed as unmanaged and left alone. Today's and future-dated days are
never deleted, and today and yesterday are never compacted. Only one run or restore
happens at a time.

The page keeps the last 200 actions (what was deleted, archived or compacted, why,
how much space it freed, and who made the change behind it), plus the last run's
totals and errors. Every action is also logged by the server.

## Settings in signalith.yaml

The page saves its settings in `retention.yaml` in the `lookups.dir` folder (mode
0600). Run history goes in `retention_history.json` beside it. You can edit
`retention.yaml` by hand. The server notices the change at the next run. If the
file has a mistake, runs pause and the page shows the error until it is fixed.

Anything set under `retention` in signalith.yaml wins over the page and is shown
there as "From signalith.yaml", read-only, except `retention.days`, which a default
saved on the page replaces. Use this for settings that must not be changed from the
UI:

```yaml
retention:
  days: 90                 # default keep_days until a default is saved on the page (0 = forever)
  interval: 1h             # how often to enforce, 5m to 24h
  archive_dir: /srv/signalith-archive
  default:                 # replaces days; the page can no longer change the default
    keep_days: 90
    archive: true
  policies:
    authentication:
      keep_days: 365
      compact_after_days: 14
    endpoint:
      keep_days: 30
      max_size_gb: 500
    findings:
      keep_days: 365       # resolved or closed findings
    cases:
      keep_days: 1095      # resolved or closed investigations
  guard:
    enabled: true
    max_disk_percent: 85   # 50 to 94
    min_days: 7
```

| Key | Default | Meaning |
| --- | --- | --- |
| `retention.days` | `90` | Default `keep_days` for event categories without a policy, until a default is saved on the page |
| `retention.interval` | `1h` | How often policies are enforced (5m to 24h) |
| `retention.archive_dir` | `archive` next to `lookups.dir` | Archive folder; relative paths are relative to signalith.yaml. `SIGNALITH_ARCHIVE_DIR` overrides it |
| `retention.default` | none | Default event policy: `keep_days`, `max_size_gb`, `compact_after_days`, `archive` |
| `retention.policies.<id>` | none | Policy for one category (IDs above). Findings and cases accept only `keep_days` |
| `retention.guard.enabled` | `true` | Disk guard on or off |
| `retention.guard.max_disk_percent` | `85` | Disk use the guard keeps OpenSearch under (50 to 94) |
| `retention.guard.min_days` | `7` | Days before today the guard never deletes |

`signalith validate` checks all of these and names each problem.

## More than one server

When several Signalith servers share one OpenSearch, one of them runs the background
jobs, retention among them, with the settings saved on that server (page settings
live in its own `lookups.dir`). Only servers with `detections.scheduler: true` take
part, and another one takes over if that server stops. The other servers show the
page read-only, say which server runs retention, and refuse changes, **Run now** and
restores. Make retention changes on the server that runs it.

A server whose retention settings differ from those of the server that runs
retention does not take retention over by itself, so it can never delete what the
other keeps: the list of servers (`GET /api/cluster`) says why. While any policy
archives, the same goes for a server that uses a different archive folder: set
`retention.archive_dir` to the same shared folder on every server. Signalith names
that folder with a small file in it, `.signalith-archive-id`; leave it there. Copy
`retention.yaml` across to let it take over.

Before every step that deletes or changes data, retention checks with OpenSearch
that its server still runs the background jobs, and stops if not. When OpenSearch's
disk is full, it refuses every write, so no server can confirm that in the usual way.
The server that runs the jobs then keeps them, as long as it can read that nothing
changed, and runs only retention, so the disk guard can delete the oldest days and
free space. Detections and feed downloads wait until OpenSearch accepts writes again.

Archives are written on the server that runs retention, in its archive folder.
Restore from that server, or with the CLI after copying the files to where you run
it.

### Upgrading

- Retention used to run on every server, then on every server with
  `detections.scheduler: true`. It now runs on one of those at a time. Upgrade every
  server that shares an OpenSearch together: an older version ignores which server
  runs the jobs. Or first set `detections.scheduler: false` on the servers you
  upgrade last.
- The disk guard is on by default; see [The disk guard](#the-disk-guard).

## API

All routes need an admin. Request bodies reject unknown fields, so a typo is an
error rather than a setting that does nothing.

| Method and path | Body | Response |
| --- | --- | --- |
| `GET /api/retention` | | Categories with sizes, days and policies; the default; the guard and disk; the archive; the schedule; pending actions; the last run and recent actions |
| `PUT /api/retention/policies/{id}` | `{"keep_days":30,"max_size_gb":0,"compact_after_days":14,"archive":true}` | `{"category","policy","source":"ui","run_started","run_queued"}` |
| `DELETE /api/retention/policies/{id}` | | Back to the default: `{"category","policy","source","run_started","run_queued"}` |
| `PUT /api/retention/default` | A policy | `{"policy","source":"ui","run_started","run_queued"}` |
| `PUT /api/retention/guard` | `{"enabled":true,"max_disk_percent":85,"min_days":7}` | The guard plus `source`, `run_started` and `run_queued` |
| `POST /api/retention/preview` | `{"category":"endpoint","policy":{...}}`, `{"category":"endpoint","policy":null}`, `{"default":{...}}` or `{"guard":{...}}` | What the run that saving starts would do: `summary` and `steps` for the change, `due`, `due_steps` and `due_records` for what is already due, `records`, `deletes_data`, `guard`, `notes` |
| `POST /api/retention/run` | | `202 {"started":true}`; `409` while a run or restore is going |
| `GET /api/retention/archive` | | Archived days, with whether each is searchable and its latest restore |
| `POST /api/retention/archive/preview` | `{"ids":[...],"keep_days":14}` | What the restore does to the disk: `bytes`, `percent_after`, `over_limit`, `flood`, the live days the guard would delete (`steps`, `deletes`, `unarchived`), `needs_confirm` and `message` |
| `POST /api/retention/archive/restore` | `{"ids":["signalith-endpoint-2026.07.01"],"keep_days":14,"confirm":false}` | `202 {"restores":[...]}` with each restore's state; `409 {"error","check"}` when the restore needs `"confirm":true` |

`run_started` is true when saving started a run; `run_queued` when a run or restore
was going and a new run starts as soon as it ends.

Errors:

- An invalid setting returns `400` with `error`, `problems` and `fields` (the
  settings at fault).
- A setting that comes from signalith.yaml returns `409`.
- On a server that does not run the background jobs (with `detections.scheduler:
  false`, or while another server runs them), every change, **Run now** and restore
  returns `409` with an `error` that says which server runs retention; `GET
  /api/retention` has `schedule.read_only` and `schedule.read_only_why`.
- An unknown category or archive ID returns `404`.
- When OpenSearch cannot be reached, previews and restore checks return `503`.
