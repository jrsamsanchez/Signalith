# OpenSearch with several nodes

Signalith keeps everything in OpenSearch: events, findings, investigations and, once
servers share them, their settings and users. With one OpenSearch node, losing that node
stops every Signalith server. This page shows how to run OpenSearch so that any one node
can stop, and how Signalith keeps working when one does.

## What you need

- **Three cluster-manager-eligible nodes.** OpenSearch only works while a majority of
  these nodes can reach each other, so the cluster's state cannot split in two. With
  three, any one can stop. Two is no better than one: losing either stops the cluster.
- **Data on at least two nodes**, and **one replica** of each index, so every shard has a
  copy on another node. Set **Replicas** on the Settings page to `auto` (the default):
  each new day's indices then get one copy on another node once OpenSearch has more
  than one node. Days already stored keep the copies they have.
- **A certificate for each node**, from the same CA (see below).
- Enough disk on each node for its share plus a node's worth more: when a node stops,
  OpenSearch makes new copies of its shards on the others.

## The Docker quick start with three nodes

`deploy/docker/docker-compose.opensearch3.yml` adds two nodes to the quick start. Add it
after `docker-compose.yml` in every command, from the Signalith folder:

```
docker compose -f deploy/docker/docker-compose.yml -f deploy/docker/docker-compose.opensearch3.yml up -d
```

The setup service makes a certificate for each node (`bootstrap-docker -nodes 3`), the
nodes find each other by name, and Signalith spreads its requests over all three. Give
Docker at least 8 GB of memory. Three nodes on one computer protect against a node that
stops, not against losing the computer; for that, run them on three machines as below.

An existing single-node quick start keeps its events: its node becomes the first of the
three. Take a [snapshot](#snapshots) first.

## Per-node certificates

Every node presents its own certificate to the others, and OpenSearch only lets a node
join when its certificate's name is in `plugins.security.nodes_dn`. All of them must come
from the same CA as Signalith's client certificate.

- Docker quick start: `bootstrap-docker -nodes 3` makes `node.pem`, `node-2.pem` and
  `node-3.pem` (names `opensearch`, `opensearch-2`, `opensearch-3`) in the
  `opensearch-certs` volume.
- OpenSearch installed by hand: make the first node's certificates with
  `signalith opensearch-certs -node os-1 -out <dir>`, then each other node's from the
  same CA with `signalith opensearch-certs -ca-dir <dir> -node os-2 -out <dir2>`, and
  list every node's name in `nodes_dn` on every node. See
  [Securing OpenSearch](opensearch-security.md).

## Telling Signalith every node

Set **More addresses** on the Settings page (`opensearch.urls` in signalith.yaml, or
`SIGNALITH_OPENSEARCH_URLS`, comma-separated) to the other nodes' addresses:

```yaml
opensearch:
  url: https://os-1.example.com:9200
  urls:
    - https://os-2.example.com:9200
    - https://os-3.example.com:9200
```

Signalith then:

- spreads its requests over every address in turn;
- skips an address for 30 seconds after it fails to answer, and tries it again after
  that;
- tries a request on the next address when it could not be sent at all, and, when it
  may have arrived, only when sending it twice is harmless: searches and reads, and
  batches of events that each carry their own ID (a second copy is refused as already
  stored). A write that may have gone through is never sent twice; for a change to a
  finding, a case or a setting, Signalith reads it back on another node to learn whether
  the change landed.

Every address must use the same scheme as **Address**, and none may carry a user name or
password. The OpenSearch password is sent to every address, so adding one on the
Settings page asks for the password again. Each server keeps its own list; it takes
effect after a restart.

The alternative is one address in front of OpenSearch: a load balancer, or a
coordinating-only OpenSearch node. That works too, but the load balancer or that node is
then the one thing that must not stop. A list of addresses needs nothing in between.

## The OpenSearch card on the Servers page

The Servers page shows OpenSearch's health, its nodes, how many may be cluster manager,
shards on no node, each node's disk against OpenSearch's watermarks, Signalith indices
with no copy on another node, and this server's addresses, with the ones being skipped.
Its warnings mean:

| Warning | What to do |
| --- | --- |
| One OpenSearch node | Add two more nodes, as above |
| Only 1 or 2 cluster-manager-eligible nodes | Make three nodes eligible (`node.roles` with `cluster_manager`) |
| Shards on no node | OpenSearch could not place them, often for lack of disk or of nodes. `GET _cluster/allocation/explain` says why |
| A disk past the low watermark | OpenSearch puts no new shards on that node. Free or add disk |
| Signalith indices with no copy on another node | Set Replicas to `auto`. New days get a copy; to give an old day one too, set `index.number_of_replicas: 1` on it in OpenSearch |

When OpenSearch has more than one data node and **Replicas** is `0`, the card offers
**Use automatic replicas**, which sets it to `auto` for every server.

## Snapshots

Replicas protect against losing a node, not against deleting the wrong index or losing
every node. Take snapshots to a repository outside the cluster:

1. Give every node the same shared folder (or an S3 bucket with the `repository-s3`
   plugin) and list it in `path.repo` in each node's `opensearch.yml`.
2. Register it: `PUT _snapshot/signalith` with
   `{"type": "fs", "settings": {"location": "/mnt/opensearch-snapshots"}}`.
3. Schedule snapshots with OpenSearch's snapshot management, for example nightly with 14
   kept: `POST _plugins/_sm/policies/signalith-nightly` with a `creation` schedule
   (`"cron": {"expression": "0 2 * * *", "timezone": "UTC"}`), `"indices": "signalith*"`,
   and a `deletion` condition `"max_count": 14`.

## Restoring a snapshot on purpose

Each Signalith server remembers how far the shared settings had got, and refuses older
ones as changed outside Signalith. After restoring a snapshot on purpose (`POST
_snapshot/signalith/<name>/_restore`), run on one server:

```
signalith cluster accept-restore
```

Every server then accepts the shared settings now in OpenSearch within seconds. See
[signalith cluster](cluster-cli.md#accept-restore).

Snapshots hold the shared settings too (the `<prefix>_config` index), but they are
sealed with the cluster key, which is not in OpenSearch: keep a copy of it with
[`signalith cluster export-key`](cluster-cli.md#export-key-and-import-key).
