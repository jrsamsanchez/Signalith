---
description: Every setting in signalith.yaml, the environment variables that set or override them, and the state folder.
---

# Configuration file

Everything lives in one YAML file: `/etc/signalith/signalith.yaml` on Linux,
`C:\ProgramData\Signalith\signalith.yaml` on Windows. `signalith init` writes a
working one. `signalith validate` checks it and lists every problem with the setting
to fix. Unknown keys are rejected, so typos do not silently do nothing.

Admins can change most of these settings on the **Settings** page instead. An
environment variable wins over the page, which wins over `signalith.yaml`. See
[Server settings](settings.md).

## All settings

| Setting | Default | Meaning |
| --- | --- | --- |
| `server.listen` | `127.0.0.1:9000` | Address the UI and API bind to |
| `server.agent_listen` | `listen`'s host on port 7779 | Address agents send to (Fluent Bit, OTLP, osquery, network sensors), with the same certificate as the web page; or `SIGNALITH_AGENT_LISTEN`. `off` sends agents to the web port, as before 0.3. See [The agent port](sending-data.md#the-agent-port) |
| `server.public_url` | `https://` and the `listen` host and port | This server's address (scheme, host and port). Generated agent configs use its scheme and host on the agent port. With HTTPS on it must be `https://` |
| `server.tls.mode` | `auto` | `auto`: HTTPS with a certificate Signalith makes and renews itself; `files`: `server.tls_cert` and `tls_key`; `off`: plain HTTP behind a reverse proxy that adds HTTPS. See [docs/https.md](https.md) |
| `server.tls.names` | none | Extra host names or IP addresses for the `auto` certificate (this machine's names and addresses, `public_url` and addresses entered on Add data are always in it) |
| `server.tls.ca_scope` | `standard` | How far a certificate authority Signalith makes may vouch: `standard` (this server and private network names) or `strict` (only this server's own names and addresses). Used on the first start and when you make a new one on the Security page. See [docs/https.md](https.md#how-far-the-certificate-authority-reaches) |
| `server.tls.plaintext_ingest` | `deny` (`allow` for configs from before HTTPS was the default, and on a Docker quick start upgraded from one that served plain HTTP, until agents on plain HTTP are first refused) | Whether agents may still send events over plain `http://`; the Health page lists any that do |
| `server.tls_cert`, `server.tls_key` | none | Your certificate (with its chain) and key, for `server.tls.mode: files`; reloaded when they change. TLS 1.2 or newer; browsers are told to use HTTPS only |
| `server.trusted_proxies` | none | IPs or CIDRs of reverse proxies whose `X-Forwarded-Proto: https` is believed (HSTS, HTTPS-only cookie, no redirect) |
| `server.client_header` | none | `x-forwarded-for` or `forwarded`: the header the trusted proxies set to each person's address, for the failed sign-in limits and the log. Only for a proxy that sets it itself; empty counts everyone behind a trusted proxy as one shared address |
| `server.max_connections` | `10000` | Open connections (and, over HTTPS, requests in progress) allowed at once; one client, an IPv4 address or an IPv6 /64, may hold a tenth of them. Connections from this machine, such as a local reverse proxy, are not limited that way |
| `server.node_url` | from `listen` and this computer's name | The address other Signalith servers that share this OpenSearch reach this one at, shown in the list of servers. Set in signalith.yaml or `SIGNALITH_NODE_URL`, or, once the servers share their settings, on the Settings page (**Address for other servers**); in Docker set it, since a container cannot know it |
| `server.shared_addresses` | none | IPs or CIDRs that many clients reach Signalith through: a reverse proxy, load balancer or NAT on another machine, or Docker Desktop's port forwarding, where every client seems to come from one address. These are not held to one client's share of connections, requests and ingest memory, only to the totals, and wrong passwords from them count per account, never pausing sign-ins from the whole address. The log names the address when one reaches its share |
| `opensearch.url` | `http://127.0.0.1:9200` | Event store, `http(s)://host:port` (no query string). A `user:password@` in it is moved to `username` and `password` when loaded and never shown; `signalith secrets encrypt` moves it there in the file, encrypted |
| `opensearch.urls` | none | Other nodes of the same OpenSearch cluster (same scheme, no password in them; or `SIGNALITH_OPENSEARCH_URLS`, comma-separated). Requests are spread over every address and one that is down is skipped for 30 seconds; see [OpenSearch with several nodes](opensearch-failover.md) |
| `opensearch.username`, `opensearch.password` | none | OpenSearch credentials. Sent only over https, or plain http to this machine, unless `allow_insecure_http` is on |
| `opensearch.ca_file` | none | PEM file with the CA that signed OpenSearch's certificate (for a private CA); system CAs are trusted too. Relative to the config file |
| `opensearch.cert_file`, `opensearch.key_file` | none | Client certificate and key for certificate sign-in to OpenSearch; reloaded when they change |
| `opensearch.crl_file` | none | The revocation list OpenSearch checks client certificates against. When the cluster keeps OpenSearch's certificate authority, Signalith writes it, so a removed server's certificate stops working at once ([docs/servers.md](servers.md#ending-a-servers-opensearch-access-at-once)); or `SIGNALITH_OPENSEARCH_CRL_FILE` |
| `opensearch.tls_skip_verify` | `false` | Skip OpenSearch certificate checks. Lab use only: anyone on the path can read and change traffic; Signalith warns while it is on |
| `opensearch.proxy` | none | Proxy for OpenSearch traffic (`http://`, `https://` or `socks5://`; or `SIGNALITH_OPENSEARCH_PROXY`). `HTTP_PROXY` and `HTTPS_PROXY` are never used for OpenSearch; when one is set and OpenSearch cannot be reached, the error says so |
| `opensearch.allow_insecure_http` | `false` | Allow `username`/`password` over plain http to another machine. Off, such a config is refused with an explanation |
| `opensearch.index_prefix` | `signalith` | Indices are `<prefix>-<datamodel>-YYYY.MM.DD`, with `-2` and so on after the day for the parts of a busy day |
| `opensearch.replicas` | `auto` | Extra copies of each new day's events on other OpenSearch nodes: `auto` (one copy once OpenSearch has more than one node, none on one node) or a whole number such as `0`. Days already stored keep theirs; applies after a restart |
| `opensearch.shards` | automatic | Primary shards for each new day's events, per data model. Automatic (`0` or unset) is one per OpenSearch data node, up to 8, and one while OpenSearch holds more than half the shards it allows. A number fixes it, up to 64 and at most one per data node. Days already stored keep theirs; applies after a restart |
| `opensearch.rollover_gb` | `40` | GB per primary shard after which a day's index of a data model continues in a new one (`<prefix>-<datamodel>-YYYY.MM.DD-2`, and so on), from 10 to 200. Applies after a restart |
| `search.default_earliest` | `-24h` | Time range when a query sets none |
| `retention.days` | `90` | Days of events to keep (`0` keeps everything) until a default policy is saved on the Data retention page |
| `retention.interval` | `1h` | How often retention policies are enforced |
| `retention.archive_dir` | `archive` next to `lookups.dir` | Folder for archived days |
| `retention.default`, `retention.policies.<category>` | none | Policies that override the page; see [Data retention](retention.md) |
| `retention.guard` | on, 85%, 7 days | Disk guard: `enabled`, `max_disk_percent`, `min_days` |
| `auth.admin_user`, `auth.admin_password_hash` | `signalithadmin` on a new install (`admin` on one made before 0.3.1, which keeps it) | The built-in admin, a break-glass account; change its password with `signalith passwd` (it asks twice without showing the password, or reads one line from a pipe or `SIGNALITH_NEW_PASSWORD`, and changes only this line of the file) |
| `auth.session_timeout` | `1h` | Sign the web UI out after this long without activity; `auth.session_max_age` (`24h`) ends every session, "Keep me signed in" too |
| `auth.users_file` | `users.json` in `lookups.dir` | Where users added on the Users page are kept; directory settings go in `directory.json` next to it |
| `auth.ldap` | none | Active Directory or LDAP sign-in, when you would rather not set it up on the Users page; see [docs/users.md](users.md#setting-it-in-signalithyaml) |
| `auth.oidc` | off | Single sign-on with an OpenID Connect provider, usually set up under **Settings > Single sign-on**; see [docs/sso.md](sso.md#setting-it-in-signalithyaml) |
| `ingest.tokens` | none | Shared tokens (legacy) agents send as `Authorization: Bearer`; still accepted. New agents get their own token on **Add data** (see [docs/agent-tokens.md](agent-tokens.md)) |
| `ingest.max_event_age` | `7d` (or the shortest retention period if shorter) | Events older than this, or more than an hour ahead, are filed under the time they arrived, with their own time in `device_time`. See [Ingest limits](sending-data.md#ingest-limits) |
| `syslog.udp`, `syslog.tcp` | off, also on a new install (plain syslog is unencrypted; **Add data** > **Syslog** turns them on) | Addresses to receive plain syslog on; empty turns a listener off. See [Syslog](sending-data.md#syslog) |
| `syslog.tls` | off (`init` sets `0.0.0.0:6514`) | Address for syslog over TLS, such as `0.0.0.0:6514`; uses the web UI's certificate |
| `syslog.allow` | any sender | Sender IPs or CIDRs allowed to send syslog; others are dropped and counted |
| `syslog.public_port` | the listen port | Port devices send UDP and TCP syslog to, when it is forwarded to the listen port; shown on Add data |
| `syslog.spool_mb` | `1024` | Most disk space, in MB, for syslog events kept while OpenSearch refuses them for now; when full, the oldest are dropped. See [When OpenSearch is down](sending-data.md#when-opensearch-is-down) |
| `detections.dir` | `detections` | Folder for custom and edited detections, relative to the config file |
| `detections.scheduler` | `true` | The older name of `cluster.leader_eligible`, which wins when both are set |
| `cluster.leader_eligible` | `true` | Lets this server run detections, threat intel downloads, notifications and retention. Servers that share one OpenSearch take turns automatically; turn it off only on a server that should never run them (**May run background jobs** on the Settings page, or `SIGNALITH_LEADER_ELIGIBLE`). See [More than one server](servers.md) |
| `cluster.name` | `Signalith` | The name of the servers that share one OpenSearch, shown on the Servers page; changed on the Settings page once they share their settings |
| `cluster.opensearch_url` | none | The OpenSearch address a new server of the cluster is given, when it differs from the one the servers use |
| `detections.max_findings_per_run` | `100` | Cap on findings one run can raise |
| `detections.catch_up` | `6h` | When detections could not run, for example while every server was stopped, how far back the missed runs are made up once they run again (at most `7d`). Older ones are skipped and shown on the Detections page. `0` turns this off |
| `lookups.dir` | `lookups` | Folder for `assets.csv` and `identities.csv`, relative to the config file |
| `intel.feeds` | none | Threat intel feeds kept in this file (read-only on the page); most people add feeds on the **Threat intel** page instead. See [Threat intel](threat-intel.md). Nothing is fetched until a feed is added |
| `intel.feeds[].name`, `.url` | required | Feed name (shown as the indicator source) and its http(s) address |
| `intel.feeds[].kind`, `.collection` | `url` | `taxii` reads a TAXII 2.1 collection: `url` is the API root and `collection` the collection ID |
| `intel.feeds[].format` | `lines` | `lines` (one per line, `#` comments), `csv` (with `column:`, a header name or number), `stix` (STIX 2.1 bundle) or `auto` to detect |
| `intel.feeds[].type` | `auto` | `auto` detects each value, or `ip`, `cidr`, `domain`, `url`, `hash`, `md5`, `sha1`, `sha256`, `email` |
| `intel.feeds[].interval`, `.max_age` | `1h`, `7d` | How often to download; how long indicators last when downloads keep failing |
| `intel.feeds[].weight` | `1` | Multiplies the risk a match adds (0 to 10) |
| `intel.feeds[].headers`, `.username`, `.password` | none | Request headers and HTTP basic sign-in for feeds that need a key; values may use `${ENV_VAR}` |
| `intel.feeds[].tags`, `.description`, `.enabled` | none, `true` | Labels added to every indicator, and on/off |
| `intel.feeds_file` | `<lookups.dir>/intel_feeds.yaml` | Where feeds added on the page are saved, with their API keys encrypted (file mode 0600) |
| `notify.file` | `<lookups.dir>/notifications.yaml` | Where notification channels and rules set on the **Notifications** page are saved, with their webhook URLs, header values and passwords encrypted (file mode 0600). See [docs/notifications.md](notifications.md) |
| `ticketing.file` | `<lookups.dir>/tickets.yaml` | Where Jira and ServiceNow connections set on the **Ticketing** page are saved, with their API tokens, passwords and client secrets encrypted (file mode 0600). See [docs/ticketing.md](ticketing.md) |
| `playbooks.file` | `<lookups.dir>/playbooks.yaml` | Where playbooks set on the **Playbooks** page are saved (file mode 0600; they hold no secrets). See [docs/playbooks.md](playbooks.md) |
| `intel.allow_loopback_feeds` | `false` | Allow feed downloads from this machine (`127.0.0.1`, `::1`), for a feed server on the same host |
| `cluster.node_name` | the name kept in the state folder, else this computer's name | This server's name in the list of servers and on every log line (`node=`). 1 to 63 letters, digits, dots, dashes or underscores. In Docker, set it (or `SIGNALITH_NODE_NAME`), since a container's name is random. Set in signalith.yaml or the environment only |
| `demo.enabled`, `demo.admin_networks` | `false`, none | Runs a public, read-only demo with the sample data: visitors sign in with one click as a read-only analyst, password sign-in works only from `admin_networks`, and event intake, the AI assistant and everything that reaches other systems are off. Set in signalith.yaml or `SIGNALITH_DEMO` and `SIGNALITH_DEMO_ADMIN_NETWORKS` only. See [docs/demo.md](demo.md) |
| `dashboards.dir` | `dashboards` | Folder for custom dashboards, one YAML file each, relative to the config file |
| `dashboards.stale_after` | `2h` | How long a host and source type can be quiet before the posture dashboard lists it as stopped |
| `assistant.provider` | off | Optional AI model for **Ask**: `anthropic`, or `openai` for any OpenAI-compatible API (OpenAI, Ollama, LM Studio, vLLM) |
| `assistant.url`, `assistant.model`, `assistant.api_key` | per provider | Endpoint, model name and key; `anthropic` defaults to `claude-sonnet-5-5` |
| `assistant.investigate` | `false` | Lets analysts use **Investigate with AI** on a finding, which sends the finding's events to the model. See [docs/investigate.md](investigate.md) |
| `assistant.mask_fields` | none | Fields whose values are replaced with stand-ins before Investigate with AI sends anything; `_raw` leaves out the event text. Passwords, tokens, keys and cookies are always masked |
| `assistant.request_timeout` | `3m` | How long one answer from the model may take (Test and each Investigate with AI turn), from 30s to 1h. A local model on a CPU without a GPU may need `15m` or more |
| `assistant.investigate_timeout` | `6m` | How long one Investigate with AI may take in all, from 30s to 2h. With a slow local model, allow about 3 times the answer limit, such as `45m` |

## Environment variables

Secrets can come from the environment instead of the file:

| Variable | Setting |
| --- | --- |
| `SIGNALITH_OPENSEARCH_PASSWORD` | `opensearch.password` |
| `SIGNALITH_ADMIN_PASSWORD` | The built-in admin's password |
| `SIGNALITH_INGEST_TOKEN` | A shared agent token (`ingest.tokens`) |
| `SIGNALITH_LDAP_BIND_PASSWORD` | The bind password of `auth.ldap` in `signalith.yaml` only. Directory sign-in set up on the Users page keeps its own |
| `SIGNALITH_OIDC_CLIENT_SECRET` | The client secret of `auth.oidc` |
| `SIGNALITH_ASSISTANT_API_KEY` | `assistant.api_key` |

So can these settings:

| Variable | Setting |
| --- | --- |
| `SIGNALITH_OPENSEARCH_URL` | `opensearch.url` |
| `SIGNALITH_OPENSEARCH_URLS` | `opensearch.urls`, comma-separated |
| `SIGNALITH_OPENSEARCH_USERNAME` | `opensearch.username` |
| `SIGNALITH_OPENSEARCH_PROXY` | `opensearch.proxy` |
| `SIGNALITH_OPENSEARCH_CRL_FILE` | `opensearch.crl_file` |
| `SIGNALITH_LISTEN` | `server.listen` |
| `SIGNALITH_AGENT_LISTEN` | `server.agent_listen` |
| `SIGNALITH_PUBLIC_URL` | `server.public_url` |
| `SIGNALITH_DETECTIONS_DIR` | `detections.dir` |
| `SIGNALITH_LOOKUPS_DIR` | `lookups.dir` |
| `SIGNALITH_DASHBOARDS_DIR` | `dashboards.dir` |
| `SIGNALITH_USERS_FILE` | `auth.users_file` |
| `SIGNALITH_INTEL_FEEDS_FILE` | `intel.feeds_file` |
| `SIGNALITH_NOTIFY_FILE` | `notify.file` |
| `SIGNALITH_TICKETING_FILE` | `ticketing.file` |
| `SIGNALITH_PLAYBOOKS_FILE` | `playbooks.file` |
| `SIGNALITH_ARCHIVE_DIR` | `retention.archive_dir` |
| `SIGNALITH_SYSLOG_UDP`, `SIGNALITH_SYSLOG_TCP` | `syslog.udp`, `syslog.tcp`; `off` turns the listener off |
| `SIGNALITH_NODE_NAME` | `cluster.node_name` |
| `SIGNALITH_NODE_URL` | `server.node_url` |
| `SIGNALITH_LEADER_ELIGIBLE` | `cluster.leader_eligible`, `true` or `false` |
| `SIGNALITH_DEMO`, `SIGNALITH_DEMO_ADMIN_NETWORKS` | `demo.enabled`, `demo.admin_networks` |

Secrets can also be read from a file, as Docker and Kubernetes secrets are. Set
`SIGNALITH_OPENSEARCH_PASSWORD_FILE`, `SIGNALITH_ADMIN_PASSWORD_FILE`,
`SIGNALITH_INGEST_TOKEN_FILE`, `SIGNALITH_LDAP_BIND_PASSWORD_FILE`,
`SIGNALITH_OIDC_CLIENT_SECRET_FILE` or `SIGNALITH_ASSISTANT_API_KEY_FILE` to the
file's path. Setting both forms of one is an error, except for the ingest token: both
are accepted as shared tokens (agents set up on **Add data** get a token of their own).

A setting set by an environment variable, or by a file one names, is shown locked on
the Settings page.

When the admin password comes from `SIGNALITH_ADMIN_PASSWORD_FILE`, or from
`SIGNALITH_ADMIN_PASSWORD` given to the systemd or Windows service, `signalith passwd`
keeps the new one in `admin-password-hash` in the state folder, where it replaces that
password.

These set where Signalith keeps files of its own:

| Variable | What it sets |
| --- | --- |
| `SIGNALITH_STATE_DIR` | The state folder (see below) |
| `SIGNALITH_MASTER_KEY_FILE`, `SIGNALITH_MASTER_KEY` | The master key (see [Encryption](encryption.md)) |
| `SIGNALITH_SETTINGS_FILE` | Where the Settings page keeps its changes (default `settings.yaml` in `lookups.dir`) |
| `SIGNALITH_CLUSTER_KEY_FILE` | The cluster key, for servers that share one OpenSearch (see [Shared settings and the cluster key](servers.md#shared-settings-and-the-cluster-key)) |

## The state folder

The state folder is where Signalith keeps files it makes for itself:

- its master key, in `keys`,
- its HTTPS certificate, in `tls`,
- `admin-password-hash`,
- this server's identity: `node.id`, and `cluster/lock` while it runs.

It defaults to the folder that holds `lookups.dir`. The systemd unit and the Docker
image set it to `/var/lib/signalith`. `SIGNALITH_STATE_DIR` sets another one. For when
Signalith uses another folder by itself, see [Identity](servers.md#identity).
