# Cold storage

Cold storage keeps old event days in a snapshot repository, such as an S3 bucket,
instead of on OpenSearch's disks, and they stay searchable. It is for installs that keep
a lot of history: months of terabytes cost far less in a bucket than on fast disks, and
a search over them still works, more slowly.

Each event category's policy on the **Data retention** page gets one more setting,
**Move to cold storage after**. A day older than that:

1. is made read-only and merged into one segment,
2. is snapshotted on its own into the repository `signalith-cold`,
3. is checked: the snapshot must have succeeded with every shard of that day,
4. is deleted from OpenSearch's disks, and
5. is mounted back from the snapshot under the same name, as a *searchable snapshot*.

Searches, detections, dashboards and investigations then read it from the repository,
with a cache on the node. When **Keep** runs out, the day is archived first if the
policy archives, then deleted, and so is its snapshot.

## What you need

- **OpenSearch 3**, with at least one node that has the `warm` role. That node mounts
  the cold days and keeps a cache of what searches read (`node.search.cache.size`).
  OpenSearch 2 is not supported: there, searches of a mounted day fail on the
  wildcard fields every Signalith index has.
- **A snapshot repository named `signalith-cold`** (`<prefix>-cold` with another
  `opensearch.index_prefix`), registered in OpenSearch. Signalith never sees the
  bucket's credentials: they stay in OpenSearch's keystore. Nothing on Signalith's
  pages can point cold storage at another bucket.
- **The `signalith_cold_storage` role mapped to Signalith** in OpenSearch's security
  settings. Signalith's own role has no snapshot permissions, because OpenSearch's are
  not limited to one repository; this role is mapped only where cold storage is used.

The page says what is missing. Until everything is in place, days that are due stay
on OpenSearch's disks and are compacted as the policy says.

## The Docker quick start, with a folder

`deploy/docker/docker-compose.cold.yml` turns cold storage on for the quick start,
keeping it in a folder you choose, such as a NAS share. Pick a folder on another disk
than Docker's: cold storage on the same disk saves nothing. OpenSearch's user (uid
1000) must be able to write it.

```
SIGNALITH_COLD_DIR=/mnt/nas/signalith-cold docker compose -f deploy/docker/docker-compose.yml -f deploy/docker/docker-compose.cold.yml up -d
```

On Windows, in PowerShell:

```powershell
$env:SIGNALITH_COLD_DIR = "D:\SignalithCold"
docker compose -f deploy/docker/docker-compose.yml -f deploy/docker/docker-compose.cold.yml up -d
```

Add the file to every later `docker compose` command too. To avoid typing the folder
each time, put `SIGNALITH_COLD_DIR=...` in a `.env` file next to `docker-compose.yml`.

The file gives OpenSearch the `warm` role with a 10 GB cache (`SIGNALITH_COLD_CACHE`
changes it), maps the `signalith_cold_storage` role to Signalith, and registers the
folder as `signalith-cold`. Then set **Move to cold storage after** on the Data
retention page.

## Your own OpenSearch cluster, with S3

On every OpenSearch node:

1. Install the S3 plugin, which OpenSearch 3 no longer bundles:

    ```
    sudo /usr/share/opensearch/bin/opensearch-plugin install --batch repository-s3
    ```

2. Store the bucket's access key in OpenSearch's keystore (skip this on AWS when the
   node has an IAM role):

    ```
    sudo /usr/share/opensearch/bin/opensearch-keystore add s3.client.default.access_key
    sudo /usr/share/opensearch/bin/opensearch-keystore add s3.client.default.secret_key
    ```

3. In `opensearch.yml`, set the bucket's region and, on the nodes that should hold cold
   days, add the `warm` role and a cache:

    ```yaml
    s3.client.default.region: us-east-1
    node.roles: [cluster_manager, data, ingest, warm]
    node.search.cache.size: 50gb
    ```

    A node may have only the `warm` role. Dedicated warm nodes keep cold-day searches
    from slowing ingest.

4. Restart the node.

Then, once, with the admin certificate:

```
curl --cacert root-ca.pem --cert admin.pem --key admin-key.pem -X PUT -H 'Content-Type: application/json' \
  https://opensearch:9200/_snapshot/signalith-cold \
  -d '{"type": "s3", "settings": {"bucket": "my-signalith-cold", "base_path": "signalith"}}'

curl --cacert root-ca.pem --cert admin.pem --key admin-key.pem -X PUT -H 'Content-Type: application/json' \
  https://opensearch:9200/_plugins/_security/api/rolesmapping/signalith_cold_storage \
  -d '{"users": ["signalith", "signalith-server-*"]}'
```

The role is in Signalith's `roles.yml` (`deploy/docker/opensearch/security/`). If you
load your security settings from files with `securityadmin.sh`, add the mapping to your
`roles_mapping.yml` as well, or the next load removes it.

S3-compatible storage (MinIO and others) works the same way, with
`s3.client.default.endpoint` set in `opensearch.yml`. Azure Blob Storage and Google Cloud
Storage work with their repository plugins.

## Keeping the bucket safe

- **Turn on the bucket's default encryption** (SSE-S3 or SSE-KMS). Signalith encrypts
  its own [archives](retention.md#archives); snapshots are encrypted by the bucket.
- **Give the access key only this bucket**: list, read, write and delete objects in
  it, nothing else.
- **Keep backups somewhere else.** Signalith deletes cold days' snapshots when Keep
  runs out, so its role may delete snapshots, and OpenSearch does not limit that to one
  repository. Keep backup snapshots in another bucket with object lock, or in another
  cluster, so nothing Signalith can do reaches them.
- Signalith only ever touches snapshots named `signalith-*` in `signalith-cold`.

## Good to know

- **Late events for a cold day are refused and lost**, as for a compacted day. Set
  **Move to cold storage after** above how long your agents can be offline.
- **Searches of cold days are slower** the first time, while the node fetches what they
  read; repeated searches hit the cache.
- **Size caps and the disk guard leave cold days alone.** They take no space on
  OpenSearch's disks, so deleting them would free none. The page counts them apart:
  "+ 120 GB in cold storage" under a category's size.
- **A move that stops halfway is finished by the next run.** If the snapshot is made
  but the day could not be mounted again, the next run mounts it; nothing is lost,
  because the day is deleted from disk only after its snapshot is checked.
- **Removing cold storage:** set **Move to cold storage after** back to empty. Days
  already in cold storage stay there, searchable, until Keep runs out.
- The Helm chart does not set cold storage up yet; follow the steps for your own
  cluster.
