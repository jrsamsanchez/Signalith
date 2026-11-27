# Sizing and scaling out

One Signalith server with one OpenSearch node is a complete install: it stores every
data model, runs every detection and keeps 90 days without any tuning. This page says
what that one machine holds, what to watch as it fills, and what to add, in order, when
it is not enough. The measured rates behind it are in
[Performance and sizing](performance.md).

## What one server holds

Three things run out on a single machine, usually in this order:

| What | Where you see it | What it depends on |
| --- | --- | --- |
| **Disk** | The OpenSearch card on the **Servers** page, and the disk guard on the [Data retention](retention.md) page | Events a day, their size, and the days kept |
| **CPU** for storing events | The server's CPU, and agents told to send again later | Events a second. One 2-core server stored about 21,500 small events a second in the lab |
| **OpenSearch's disk speed and memory** | Events searchable later than usual, slow searches | How many data models are written at once, and how much of a day fits in memory |

Shards used to be a fourth: OpenSearch refuses new indices once a node holds 1,000
shards (`cluster.max_shards_per_node`), and every data model added an index a day.
Twelve data models kept 90 days needed 1,092 shards, more than one node allows. Now a
quiet data model kept more than 30 days stores a month in one index (see
[Months stored as one index](retention.md#months-stored-as-one-index)), so the same
twelve need about 60, and all 18 of Signalith's data models about 90:

| One OpenSearch node, kept 90 days | Stored by day | Stored by month (quiet models) |
| --- | --- | --- |
| 8 data models | 728 shards | about 40 |
| 12 data models (Windows and Sysmon) | 1,092: over the limit | about 60 |
| 18 data models (everything) | 1,638: over the limit | about 90 |

A month stored as one index is deleted once its last day is older than its retention,
so shortening a category's **Keep** later can leave data already stored by month up to
a month past the new setting (see [Months stored as one index](retention.md#months-stored-as-one-index)).

A busy data model, one whose month would hold more than the rollover size (40 GB per
primary shard unless set), is stored by day once its month's index is full, as before;
it adds 91 shards kept 90 days. Each tenant in [multi-tenant mode](multi-tenant.md) has
its own indices, so multiply by the tenants.

The OpenSearch card on the **Servers** page counts the shards in use against the limit,
and warns when OpenSearch holds 80% of them, or will once each data model written today
has been kept as long as its retention says. It counts monthly data models as months.

## Signs it is time to grow

- **The disk guard deletes days** before their policy would, or the OpenSearch card
  says a disk is past its low watermark: add disk, keep fewer days, or move old days to
  [cold storage](cold-storage.md).
- **Agents are told to send again later** and the server's CPU stays high: give the
  server more cores, or add a second server.
- **Events take longer to become searchable**, or searches slow down, while the
  Signalith server is not busy: OpenSearch is the limit. Give it faster local disks
  (SSD or NVMe), more memory, or more nodes.
- **The shard warning** on the Servers page: see [What adds room for shards](#what-adds-room-for-shards).
- **You need it to keep running when one machine stops**: that takes three OpenSearch
  nodes and two or more Signalith servers, whatever the load.

## Growing, step by step

Each step stands on its own; take only the ones the signs above point to.

1. **Give the machine more.** More cores for the Signalith server, more memory and
   faster disks for OpenSearch. Signalith's own OpenSearch takes a quarter of the
   computer's memory as its heap, 1 to 8 GB; choose another with
   `signalith opensearch install -heap 8g`. This is the cheapest step and needs no
   change to how anything is set up.
2. **Keep less, or keep it elsewhere.** On the [Data retention](retention.md) page,
   keep fewer days of the categories you search least, compact old days, or move them to
   [cold storage](cold-storage.md), where they stay searchable but leave OpenSearch's
   disks.
3. **Add OpenSearch nodes.** Three nodes keep working when any one stops, and each data
   node adds room for 1,000 more shards and its own disk and CPU. Signalith notices new
   data nodes within minutes: with **Shards** and **Replicas** left automatic, each new
   day's index gets one primary shard per data node (up to 8) and one copy on another
   node. See [OpenSearch with several nodes](opensearch-failover.md).
4. **Add Signalith servers.** Servers that share one OpenSearch share the work:
   agents' events through a load balancer, detections spread over the servers, and the
   background jobs on one of them, taken over by another within a minute if it stops.
   See [Adding servers](multi-server.md) and [Load balancers](load-balancers.md).

Upgrade servers one at a time as [Rolling upgrade](servers.md#rolling-upgrade-one-server-at-a-time)
says. A feature that changes what is stored, like monthly indices, starts only once
every server runs a version that reads it.

## What adds room for shards

In order of preference:

1. **Leave Store quiet data models by month on** (the default). It is the largest
   saving, and costs nothing to run.
2. **Keep fewer days** of the categories you need least.
3. **Add an OpenSearch data node.** The limit is per data node.
4. **Raise `cluster.max_shards_per_node`.** It is a soft limit, meant to stop runaway
   index creation. Each open index costs OpenSearch heap for its mapping, and Signalith
   maps about 1,000 fields up front in each, so raise it only on nodes with heap to
   spare, and not past what retention will ever keep:

   ```
   PUT _cluster/settings
   { "persistent": { "cluster.max_shards_per_node": 2000 } }
   ```

Fewer primary shards per index does not help on one node: it already has one. Leave
**Shards** automatic.
