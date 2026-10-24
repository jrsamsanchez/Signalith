# Metrics for Prometheus

Each Signalith server can answer `GET /metrics` on its web port with its own
numbers, in the Prometheus text format or, for a scraper that asks for it,
OpenMetrics 1.0: how many events it stored and lost, how long writes to
OpenSearch take and why OpenSearch refused them, syslog's queue and spool,
retention and the disk guard, and whether it runs the background jobs.

The endpoint is **off** until an admin turns it on, and then answers only a
scraper that sends the scrape token. It never holds event data, user names,
host names or the addresses of agents and senders: every label comes from a
short fixed list, so the number of series stays the same however much data
arrives.

## Turning it on

1. Open **Settings > Metrics** (admins).
2. Select **Create token**. Copy the token: it is shown only this once.
   Signalith keeps only its SHA-256 fingerprint (`metrics.token_sha256`).
3. Turn on **Answer scrapes**, list the scrapers' addresses if you like, and
   select **Save**. Saving asks for your password or code again, as other
   security settings do.

The settings are shared by every server of a cluster, so one token scrapes
them all. In `signalith.yaml`:

```yaml
metrics:
  enabled: true
  # The SHA-256, in hex, of the token. Make one on the Metrics tab, or:
  #   t="sgl_metrics_$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')"
  #   printf %s "$t" | sha256sum
  token_sha256: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
  # Optional: only these addresses and ranges may scrape.
  allow: [10.0.5.20, 10.0.6.0/24]
```

Replace the token by making a new one and saving it: the old one stops
working as soon as each server has the new setting (within seconds on servers
that share their settings). Turn the endpoint off to stop all
scrapes; it then answers `404`, as for a page that does not exist.

## What a scrape must bring

- **The token**, as `Authorization: Bearer <token>`. It is compared by its
  SHA-256 in constant time. A wrong or missing token gets `401`.
- **HTTPS.** A scrape over plain HTTP from another computer is refused with
  `403` before the token is looked at, so the token never crosses the
  network in the clear. Behind a [trusted reverse proxy](https.md) that
  ends HTTPS, the proxy's word counts. A scrape from the server itself
  (127.0.0.1 or ::1) may use plain HTTP.
- **An allowed address**, when `metrics.allow` lists any. Behind a trusted
  reverse proxy this is the scraper's own address, as the proxy forwards it.
  A reverse proxy on the same computer must be listed in
  `server.trusted_proxies`: otherwise every scrape looks like it comes from
  the server itself, all scrapers share one rate limit, and an allowlist of
  outside addresses refuses them.
- **Patience**: each address may scrape 30 times a minute, and all of them
  together 3,600 times an hour; more get `429` with `Retry-After`. Wrong
  tokens count too. Refused scrapes are logged (as audit records) at most
  once a minute per address.

On a [public demo](demo.md) the endpoint is always off.

## Prometheus

```yaml
scrape_configs:
  - job_name: signalith
    scheme: https
    authorization:
      credentials_file: /etc/prometheus/signalith-scrape-token
    tls_config:
      # Signalith's own CA, from https://<server>:9000/api/tls/ca.pem; leave
      # it out when the servers have a certificate Prometheus trusts.
      ca_file: /etc/prometheus/signalith-ca.pem
    static_configs:
      - targets: ['siem-1.example.com:9000', 'siem-2.example.com:9000']
```

Scrape every server, not a load balancer in front of them: each answers with
its own counters.

## The metrics

Counters count from the server's start.

| Metric | Type | What it is |
|---|---|---|
| `signalith_build_info{version,goversion}` | gauge (info) | Always 1; the version the server runs. |
| `signalith_start_time_seconds` | gauge | When the server started (Unix seconds). |
| `signalith_jobs_holder` | gauge | 1 on the server that runs the background jobs (detections, retention, feeds), 0 on the others. Exactly one server of a cluster should say 1. |
| `signalith_ingest_events_total{intake,result}` | counter | Events written to OpenSearch, by how they arrived (`agent`, `otlp`, `hec`, `osquery`, `syslog`, `scanner`, `signalith`, `other`) and the outcome (`indexed`, `rejected` by OpenSearch, `failed` with the whole write). Every tenant's events count. |
| `signalith_ingest_events_received_total` | counter | Events received, before they are written. |
| `signalith_ingest_events_retimed_total` | counter | Events filed under their arrival time, as their own time was too old or ahead. |
| `signalith_ingest_fields_dropped_total` | counter | Fields left out of events (invalid names, too many fields). |
| `signalith_ingest_last_indexed_timestamp_seconds` | gauge | When the server last stored an event. |
| `signalith_opensearch_rejected_events_total{reason}` | counter | Events OpenSearch turned away: `too_many_requests` (429, full write queues, a tripped circuit breaker), `shard_limit` (the cluster holds the most shards it allows), `read_only` (a block, as at the flood-stage disk watermark), `mapping`, `unavailable`, `other`. Agents send `too_many_requests`, `shard_limit` and `read_only` events again later; syslog keeps them in its spool. |
| `signalith_opensearch_bulk_failures_total{reason}` | counter | Writes that failed as a whole: `busy`, `blocked`, `auth`, `forbidden`, `not_initialized`, `unavailable`, `other`, `timeout`, `unreachable`. |
| `signalith_opensearch_bulk_duration_seconds` | histogram | How long each write of a batch of events to OpenSearch took. |
| `signalith_ingest_slots`, `signalith_ingest_slots_in_use`, `signalith_ingest_slots_waiting` | gauge | The ingest slots (`ingest.max_concurrent`), those held, and batches waiting for one. |
| `signalith_ingest_slot_wait_seconds` | histogram | How long batches waited for an ingest slot (0 when one was free). |
| `signalith_ingest_slot_timeouts_total` | counter | Batches that waited too long; their senders were told to try again. |
| `signalith_syslog_enabled` | gauge | 1 when the server receives syslog. The syslog metrics below are there only then. |
| `signalith_syslog_messages_received_total` | counter | Messages accepted from allowed senders. |
| `signalith_syslog_messages_dropped_total` | counter | Messages lost because the queue was full or the server was stopping. |
| `signalith_syslog_messages_write_failed_total` | counter | Messages OpenSearch did not store and the spool did not keep. |
| `signalith_syslog_messages_rejected_total{reason}` | counter | Messages and connections turned away: `not_allowed`, `too_large`, `bad_framing`, `too_many_connections`, `too_many_from_sender`, `proxy_untrusted`. |
| `signalith_syslog_queue_depth`, `signalith_syslog_connections` | gauge | Messages waiting to be written; open TCP and TLS connections. |
| `signalith_syslog_spooled_total`, `signalith_syslog_replayed_total`, `signalith_syslog_spool_dropped_total` | counter | Messages kept in the spool on disk while OpenSearch refused them, written from it since, and dropped because it was full. |
| `signalith_syslog_spool_events`, `signalith_syslog_spool_bytes`, `signalith_syslog_spool_max_bytes` | gauge | What the spool holds now, and its cap. |
| `signalith_opensearch_status{status}` | gauge | 1 for OpenSearch's cluster health as this server sees it: `green`, `yellow`, `red`, `unreachable`, `unknown`. |
| `signalith_opensearch_write_blocked` | gauge | 1 while OpenSearch refuses writes because of a block, as when its disk is full. |
| `signalith_opensearch_shards`, `signalith_opensearch_shards_limit` | gauge | Shards the cluster holds, and the most it allows (`cluster.max_shards_per_node` times the data nodes). |
| `signalith_opensearch_disk_used_percent` | gauge | How full the fullest OpenSearch data disk is. |
| `signalith_retention_running` | gauge | 1 while a retention run or restore is in progress on this server. |
| `signalith_retention_last_run_timestamp_seconds`, `signalith_retention_last_run_age_seconds`, `signalith_retention_last_run_errors` | gauge | When the last retention run ended, how long ago, and its errors. |
| `signalith_retention_disk_guard_state{state}` | gauge | 1 for the [disk guard](retention.md)'s state: `off`, `ok`, `over` its limit, `unknown` (the disk can't be read), `paused` (the retention settings have errors). |
| `signalith_retention_disk_guard_waiting` | gauge | 1 while the guard waits for the next scheduled run, after one that could not get the disk under its limit. |
| `signalith_retention_disk_guard_limit_percent` | gauge | The guard's limit. |

What the server asks OpenSearch for (status, blocks, shards, disk, the
retention history) is read at most every 30 seconds, however many scrapers
there are.

## Alerts to start with

```yaml
groups:
  - name: signalith
    rules:
      - alert: SignalithEventsRejected
        expr: sum by (instance, reason) (rate(signalith_opensearch_rejected_events_total[10m])) > 0
        for: 15m
      - alert: SignalithWritesBlocked
        expr: signalith_opensearch_write_blocked == 1
      - alert: SignalithNearShardLimit
        expr: signalith_opensearch_shards / signalith_opensearch_shards_limit > 0.8
      - alert: SignalithSyslogDropping
        expr: rate(signalith_syslog_messages_dropped_total[10m]) > 0 or rate(signalith_syslog_spool_dropped_total[10m]) > 0
      - alert: SignalithNoJobHolder
        expr: sum(signalith_jobs_holder) == 0
        for: 5m
      - alert: SignalithRetentionStale
        expr: signalith_retention_last_run_age_seconds > 3 * 3600 and signalith_jobs_holder == 1
      - alert: SignalithIngestSlow
        expr: histogram_quantile(0.95, sum by (instance, le) (rate(signalith_opensearch_bulk_duration_seconds_bucket[10m]))) > 5
        for: 15m
```

## API

`GET /api/metrics` (admins) says whether the endpoint is on, the address to
scrape and the settings, never the token. `POST /api/metrics/token` (admins)
makes a new token and returns it with its SHA-256; nothing changes until the
SHA-256 is saved as `metrics.token_sha256` with `PUT /api/settings`. Both are
the provider's only on a [multi-tenant](multi-tenant.md) install.
