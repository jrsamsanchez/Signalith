# Threat intel

Signalith matches events against threat intel **indicators**, like the Splunk ES
threat intelligence framework. Indicators come from feeds that the server downloads,
from indicators you add by hand, and from uploaded lists.

## Indicators

| Type | Example | Matched against |
| --- | --- | --- |
| `ip` | `203.0.113.9` | `src`, `dest`, `src_ip`, `dest_ip` |
| `cidr` | `198.51.100.0/24` | The same fields, for any address in the network |
| `domain` | `evil.example` | `dest`, `dest_host`, `domain`, `query`, `url_domain`, and the host of `url` (with `| intel`) |
| `url` | `http://evil.example/a.exe` | `url` |
| `md5`, `sha1`, `sha256` | `d41d8cd9...` | `process_md5`, `process_sha1`, `process_sha256`, `process_hash`, `file_hash`, `file_md5`, `file_sha1`, `file_sha256`, `hash`, `md5`, `sha1`, `sha256` |
| `email` | `ceo@spoofed.example` | `sender`, `recipient`, `src_user`, `user` |

Each indicator has a source (the feed name, or `manual`), description, weight,
tags, first and last seen times, and an optional expiry. The same value from two
feeds is two indicators, and a match lists every source.

Values are normalized: IPs and hashes are lower-cased and canonical, domains and
email addresses lower-cased, URL schemes and hosts lower-cased. Defanged values
such as `hxxp://evil[.]example` are accepted. Domain matches are exact, so
`evil.example` does not match `www.evil.example`; list both if you need both.

Sysmon process events get `process_md5`, `process_sha1` and `process_sha256` (lower
case) split out of `Hashes` at ingest, so hashes match exactly. Events ingested
before this version have only `process_hash`; `| intel` still reads it.

**Weight** multiplies the risk a match adds: 1 is normal, 2 doubles it, 0.5 halves
it, up to 10.

## Feeds

A feed is a list of indicators on the internet, or on a server of your own, that
Signalith downloads on a schedule. Nothing is downloaded until you add a feed.

### Adding a feed on the page

On the **Threat intel** page, **Add feed** offers three ways:

- **From the catalog**: free public feeds that Signalith already knows how to read,
  with suggested settings. Add the recommended set in one go, or pick feeds one by
  one.
- **From a URL**: paste the address of a list, CSV file or STIX 2.1 bundle. The
  format is detected (`auto`), and **Test** shows what Signalith found before you
  save: the format and CSV column it picked, the indicator types and counts, a few
  samples, lines it skipped, or why the download failed.
- **From a TAXII 2.1 server** such as MISP, OpenCTI or a commercial provider: enter
  the server's address and its user name and password (or API key header), list its
  collections and pick one. See [TAXII 2.1](#taxii-21).

A new or changed feed downloads at once; after that, every `interval`. Feeds from
signalith.yaml show on the page as read-only and are changed in the file.
Only admins add, change, test and refresh feeds. Viewers and analysts see the feeds and
their status, with the address cut at `?` (a query can hold an API key) and no TAXII
user name.

Feed settings are the same wherever a feed is defined:

| Setting | Default | Meaning |
| --- | --- | --- |
| `name` | required | 2-64 lowercase letters, digits, `-`, `_` or `.`; shown as the indicators' source. `manual` is reserved. It cannot be changed after the feed is added |
| `kind` | `url` | `url` downloads a file; `taxii` reads a TAXII 2.1 collection |
| `url` | required | http(s) address. For `taxii`, the API root, such as `https://cti.example.com/api1/`. A user name or password in the URL is refused; use `username` and `password` |
| `collection` | none | For `taxii`: the collection ID |
| `format` | `lines` in signalith.yaml, `auto` on the page | `lines`, `csv`, `stix` or `auto` (detected at each download). `taxii` feeds are always `stix` |
| `type` | `auto` | `auto`, `ip`, `cidr`, `domain`, `url`, `hash`, `md5`, `sha1`, `sha256` or `email`. Values of other types are skipped and counted |
| `column` | none | For `csv` (or `auto` that turns out to be CSV): a header name or a column number starting at 1. With `auto` and no column, the column with the most indicators is used |
| `interval` | `1h` | How often to download, at least `5m`. Units: `m`, `h`, `d`, `w` |
| `max_age` | `7d` | How long indicators last if downloads keep failing; at least the interval |
| `weight` | `1` | Risk multiplier for matches, 0 to 10 |
| `description`, `tags` | none | Added to every indicator from the feed (a STIX indicator keeps its own description; tags are combined) |
| `headers` | none | Sent with each request, for feeds that need an API key |
| `username`, `password` | none | HTTP basic sign-in, as TAXII servers usually use. A password needs a user name |
| `enabled` | `true` | `false` stops the feed and removes its indicators |

### The catalog

Only long-standing, publicly documented feeds are listed, with intervals that
respect each provider's update rate. Check each provider's terms of use, especially
for commercial use.

| ID | Provider | Contents | Type | Interval | Weight | Key | Recommended |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `feodo-tracker` | abuse.ch | Botnet command-and-control servers | ip | 1h | 1.5 | optional | yes |
| `urlhaus` | abuse.ch | URLs that served malware in the last 30 days | url | 1h | 1 | optional | yes |
| `malwarebazaar` | abuse.ch | SHA-256 hashes of malware shared in the last 48 hours | sha256 | 1h | 1 | optional | yes |
| `et-compromised` | Proofpoint Emerging Threats | Compromised hosts attacking others | ip | 12h | 1 | no | yes |
| `spamhaus-drop` | Spamhaus | Hijacked and criminal networks (DROP) | cidr | 12h | 1.5 | no | yes |
| `openphish` | OpenPhish | Active phishing URLs (community feed) | url | 12h | 1 | no | |
| `cins-army` | Sentinel IPS | Addresses with a poor reputation from scanning and brute force | ip | 6h | 0.5 | no | |
| `blocklist-de` | blocklist.de | Addresses reported for brute force in the last 48 hours | ip | 6h | 0.5 | no | |
| `firehol-level1` | FireHOL | Combined blocklist of attack sources and criminal networks | ip | 12h | 1 | no | |
| `tor-exits` | The Tor Project | Tor exit relays; Tor use is not malicious by itself | ip | 3h | 0.25 | no | |

abuse.ch bulk downloads work without a key today. A free key (sign in at
<https://auth.abuse.ch/>) can be sent in the `Auth-Key` header; it lifts rate limits
and keeps the feed working if abuse.ch starts to require one. Lists of noisy
sources (scanners, brute force, Tor) have a weight below 1, so a match adds less
risk.

Feeds that were considered and left out: AlienVault OTX (its API needs a key and
returns only the pulses you subscribe to, through its own paginated format),
ThreatFox (its exports list `ip:port` pairs and change format often), the abuse.ch
SSL blacklist (deprecated), and DShield's block list (start and end addresses
rather than indicators). Any of them can still be added from a URL if the format
suits you.

### Testing a feed

**Test** downloads the feed without saving it, with a 1-minute time limit and at
most 4 MB (a larger feed is checked from its first 4 MB, and the result says so; a
STIX bundle larger than that cannot be checked in part, but can still be added);
for TAXII, only the first page of the collection is read. It reports what a
download would store, or why it failed, in plain words, for example:

- *The server answered 403 Forbidden. This feed may need an API key.*
- *The server sent a web page, not a feed. Check the URL: a feed's address is
  usually a download link on that page.*
- *None of the 120 values were valid indicators (the first was "lorem"). Check the
  feed's format, type and column.*
- *Signalith does not download feeds from 169.254.169.254, a link-local address,
  such as a cloud metadata service.*

When testing a saved feed, its saved API key and password are used, unless you
enter new ones. A test shows counts and up to 10 examples, and keeps only those in
memory. A server runs at most two tests (or TAXII collection lookups) at a time; a
third is refused with *try again in a moment*.

Test, like a feed, can reach servers on your local network (MISP and OpenCTI often
live there), and shows a few values from what it reads. Only the admin can use it.
It never reaches Signalith's own OpenSearch (`opensearch.url`), loopback addresses
or the other addresses listed under [Network access and safety](#network-access-and-safety).

### TAXII 2.1

A `taxii` feed reads one collection of a TAXII 2.1 server.

1. Enter the server's address. It can be the API root
   (`https://cti.example.com/api1/`), the discovery address
   (`https://cti.example.com/taxii2/`) or just `https://cti.example.com`; Signalith
   asks the API root for its collections, and otherwise uses discovery to find the
   API roots (at most 10).
2. Enter the credentials: a user name and password (basic sign-in), or a header
   such as `Authorization: Token …` for servers that use API keys.
3. Pick a collection you can read. The feed stores the collection's API root as its
   URL and the collection ID.

Each download is a **full pull**: Signalith requests
`<api root>/collections/<id>/objects/?match[type]=indicator&limit=1000` with
`Accept: application/taxii+json;version=2.1`, follows the `next` value page by page
(or `X-TAXII-Date-Added-Last` with `added_after`, for servers that page by date),
and replaces the feed's indicators with what it read. A full pull is used rather
than an incremental one (`added_after` from the last run) because an incremental
pull never learns that the server revoked or deleted an indicator, which would then
keep matching until `max_age`. A pull stops after 1,000 pages, 500,000 objects or
256 MB in all, and the feed's status then says that only part of the collection was
read; the feed then holds those indicators.

A pull has 30 minutes in all, and 2 minutes for each page. If a slow server runs out
of time after the first page, the pages read so far are stored, nothing is removed
(the rest of the collection was not seen, so indicators from earlier pulls stay until
`max_age`), and the status says how much was read. If the first page does not come
in time, the download fails and the previous indicators are kept. **Refresh now**
waits at most 5 minutes, so a large collection may be read in part that way.
Only `indicator` objects with STIX patterns are used, as described under
[Formats](#formats).

In signalith.yaml:

```yaml
intel:
  feeds:
    - name: our-cti
      kind: taxii
      url: https://cti.example.com/taxii2/api1/
      collection: 91a7b528-80eb-42ed-a74d-c6fbd5a26116
      username: signalith
      password: ${CTI_PASSWORD}
```

### Formats

- **auto** (the default on the page): a STIX bundle or TAXII envelope is read as
  `stix`; a CSV file with a header row is read as `csv`, from the column that holds
  the most indicators of the feed's type (or `column` if the header has it);
  anything else is read as `lines`. The detected format and column are shown by
  **Test**, and in the feed's details after each download (for example *CSV, column
  dst_ip (detected)*). Dotted column names such as `source.ip` or `url.domain`
  (Elastic ECS, OpenCTI exports) are recognized as a header.
- **lines**: one indicator per line. Lines starting with `#`, `;` or `//` are
  comments. The first word is the indicator, so `1.2.3.0/24 ; SBL123` and
  `1.2.3.4 # note` work, and hosts files (`0.0.0.0 evil.example`) use the second word.
- **csv**: `column` picks the value, by number or header name. The header can be the
  first row, or the last `#` comment line before the data, which is how abuse.ch
  publishes its CSV files.
- **stix**: a STIX 2.1 bundle (`{"type": "bundle", "objects": [...]}`), a TAXII 2.1
  envelope (`{"objects": [...]}`) or an array of objects. Each `indicator` with a STIX
  pattern contributes every comparison it contains, such as
  `[ipv4-addr:value = '203.0.113.9']`, `[domain-name:value = '...']`,
  `[url:value = '...']`, `[file:hashes.'SHA-256' = '...']` and
  `[email-addr:value = '...']`. The indicator's name and description become the
  description, `indicator_types` and `labels` become tags, and `valid_until` becomes
  the expiry. Revoked and expired indicators and other pattern languages are skipped.

Addresses and networks in private, loopback, link-local, multicast and other
reserved ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10`,
`127.0.0.0/8`, `169.254.0.0/16`, `0.0.0.0/8`, `224.0.0.0/4`, `240.0.0.0/4`, `fc00::/7`,
`fe80::/10`, `ff00::/8`), and networks broader than /8 (IPv4) or /16 (IPv6), are
skipped in feeds and counted as reserved, so a feed such as FireHOL level 1, which
lists the bogon ranges for firewalls, never matches your own network. Add an
internal address by hand if you need to.

### Schedule and aging

The server that runs the background jobs downloads each enabled feed when it
starts running them (unless it downloaded it within the interval, which survives
restarts in `lookups.dir/intel_feeds.json`) and then every `interval`. Each download replaces the
feed's indicators: new ones are added, existing ones get a new last-seen time, and
ones no longer listed are removed. A failed download, or one with no valid
indicators, keeps the previous indicators and is retried within 15 minutes; if it
keeps failing, indicators expire `max_age` after the last good download. Expired
indicators stop matching at once and are deleted hourly.

The Threat intel page lists each feed with its status, indicator count and last
download. Open a row for its settings, the last download's changes, skipped and
reserved values, notes and last error. The row's menu has **Refresh now** and, for
feeds added on the page, **Edit**, **Turn off** and **Delete**.

### Turning off and deleting feeds

Turning a feed off stops its downloads and removes its indicators. Deleting a feed
added on the page asks what to do with its indicators:

- **Remove them** (the default): they stop matching at once.
- **Keep them**: they stay until they age out, `max_age` after the feed's last
  download, and can be deleted one by one before that. Adding a feed with the same
  name again takes them over.

Feeds from signalith.yaml are removed by editing the file and restarting.

### Where feeds are stored

When several servers share one OpenSearch and form a cluster, the feeds are stored in
OpenSearch and shared by every server; see [Several servers](#several-servers). The
rest of this section is about a server on its own.

Feeds added on the page are saved in `intel_feeds.yaml` in `lookups.dir`, or in
`intel.feeds_file` (environment: `SIGNALITH_INTEL_FEEDS_FILE`); a relative path is
relative to the folder of signalith.yaml. Signalith writes the file atomically
(a new file renamed over the old one) with mode 0600. It holds API keys and
passwords in plain text, so keep it and its backups private. Feeds from signalith.yaml
are never written to it.

API keys and passwords are write-only: the page and the API show only whether each
is set, never its value. Leaving a secret empty when changing a feed keeps the saved
value; clear it to remove it. A saved key or password is only sent to the server it
was entered for: when a change or test points the feed at another server (scheme,
host or port), each saved secret must be entered again or cleared. `${ENV_VAR}`
references are expanded only in signalith.yaml; on the page, `${...}` is sent as
typed.

If `intel_feeds.yaml` cannot be read (for example after a bad hand edit), the page
shows the error, changes on the page are refused until it is fixed or deleted, and
the feeds in it are not downloaded; indicators already stored are kept and age out
normally. Signalith reads the file again each time the page loads, so after fixing
or deleting it, reload the page; no restart is needed. `signalith validate` reports
problems in both files.

A name used in both files belongs to the signalith.yaml feed; the page's feed is
shown with the problem and not downloaded.

### Several servers

When several servers share one OpenSearch, they form a cluster and share the feeds
(see [Shared feeds and retention policies](servers.md#shared-feeds-and-retention-policies)):
every server's Threat intel page lists the same feeds, and a feed added, changed or
deleted on any of them changes for all of them at once. API keys and passwords are
stored in OpenSearch encrypted with the cluster key, which OpenSearch never holds.

- **Downloads.** The server that runs the background jobs (one with
  `detections.scheduler: true`; another takes over if it stops) downloads every feed,
  and the page says which server that is. **Refresh now** on another server asks it
  to: the page shows "Queued on siem-a", then "Downloading…", then what the download
  found. Each feed's status (last download, error, indicators) is shared too, and
  reaches the other servers within a few seconds.
- **Where a feed came from.** When the cluster is made, the feeds of the server that
  founds it, from its `intel_feeds.yaml` and from `intel.feeds` in signalith.yaml,
  become the shared feeds. Feeds from signalith.yaml then work like feeds added on the
  page: they can be changed and deleted on the page, and show a badge and a line
  saying where they came from, such as "Applied from signalith.yaml on siem-b". A
  feed in a server's signalith.yaml applies again only when it changes there (see
  [Shared feeds and retention policies](servers.md#shared-feeds-and-retention-policies)).
  The other servers' own `intel_feeds.yaml` files are no longer used.
- **Changes at the same moment.** If someone changed a feed since you opened the
  page, your change to it is refused, and the page says so and shows theirs.
- While a server cannot use the shared settings (it cannot reach OpenSearch, or
  misses the cluster key), changes there are refused and the page says why.

Indicators are stored in OpenSearch, so matching works on every server.

**Servers that are not part of the cluster** (an older version, or a server without
the cluster key) use their own `intel_feeds.yaml` and download nothing while another
server runs the jobs: their page lists the feeds read-only and says which server
downloads them, and **Refresh now** works only for feeds from signalith.yaml. Give
them the cluster key (see [signalith cluster](cluster-cli.md#export-key-and-import-key)).

### Network access and safety

Every server that may run the background jobs needs outbound HTTP(S) to each feed: for the catalog, port 443
(and port 80 for `cins-army`) to the hosts in the catalog URLs. Downloads use the
proxy in `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY`, like the rest of Signalith; set
them in the service's environment if your network requires a proxy.

Because anyone who can add a feed chooses where the server connects, downloads
follow these rules:

- Only `http` and `https` URLs, without a user name or password in the URL.
- Addresses are checked when connecting, after DNS, on every redirect and for
  every address a name resolves to. Never allowed: loopback (`127.0.0.0/8`, `::1`),
  unspecified (`0.0.0.0/8`, `::`), link-local (`169.254.0.0/16`, `fe80::/10`, which
  includes the `169.254.169.254` cloud metadata service), multicast and broadcast,
  and the metadata addresses `fd00:ec2::254` and `100.100.100.200`. IPv4 addresses
  written as IPv6 (`::ffff:127.0.0.1`, `64:ff9b::7f00:1`) are checked as IPv4.
  Private ranges (`10.0.0.0/8`, `192.168.0.0/16` and so on) are allowed, since
  MISP and OpenCTI servers often live there.
- `intel.allow_loopback_feeds: true` allows loopback, for a feed server on the same
  machine. It never allows link-local or metadata addresses. A proxy from the
  environment may be on this machine either way.
- Signalith's own OpenSearch (the host and port of `opensearch.url`) is never
  allowed, by name or by any address the name resolves to, even with
  `allow_loopback_feeds`. An OpenSearch without its security plugin answers anyone
  who reaches it, so this keeps a feed URL from reading it.
- Through a proxy, the proxy looks up host names and connects, so only addresses
  written in the URL are checked; limit what the proxy may reach if that matters.
  Only the connection to the proxy itself skips the check: a feed URL that names
  the proxy's own address (such as `http://localhost:3128/`, which Go never sends
  through a proxy) is checked like any other.
- At most 5 redirects, each checked by the same rules. No `Referer` is sent, since
  the feed URL's query may hold a key. API key headers and the password are only
  sent on a redirect that stays on the same host and port (or only moves from http
  to https).
- Downloads stop at 256 MB and 2 million indicators and time out after 5 minutes
  (TAXII: 30 minutes, 2 minutes a page); a test stops at 4 MB and 1 minute, and at
  most two run at once; listing TAXII collections times out after 30 seconds.
- Logs and error messages never show API keys, passwords or the query part of a
  URL (which often holds a key); URLs are logged as `https://host/path?…`, and a
  server's error text is shown with any secret replaced by `[hidden]`.

### Feeds in signalith.yaml

Feeds can also be listed in signalith.yaml, for example when the file is managed by
configuration tools. They use the settings above, and header and password values
may use `${ENV_VAR}` so keys stay out of the file:

```yaml
intel:
  feeds:
    # Botnet command-and-control servers
    - name: feodo-tracker
      url: https://feodotracker.abuse.ch/downloads/ipblocklist.txt
      weight: 1.5
    # Malware download URLs from the last 30 days
    - name: urlhaus
      url: https://urlhaus.abuse.ch/downloads/text_recent/
      type: url
    # Recent malware file hashes
    - name: malwarebazaar
      url: https://bazaar.abuse.ch/export/txt/sha256/recent/
      type: sha256
    # Your own platform exporting STIX 2.1 over HTTPS
    - name: our-export
      url: https://cti.example.com/export/signalith.json
      format: stix
      headers: {Authorization: "Bearer ${CTI_API_KEY}"}
  # feeds_file: lookups/intel_feeds.yaml
  # allow_loopback_feeds: false
```

## Manual indicators and uploads

Add one indicator on the Threat intel page, or upload a file:

```csv
value,type,description,weight,expires,tags
203.0.113.9,,Scanner seen in incident 42,2,30d,scanner|ssh
login-bank.example,domain,Phishing site,,2026-12-31,phishing
```

Only `value` is required; `type` is detected when empty. `expires` is a date, an
RFC 3339 time or a duration such as `30d`. A plain list with one value per line also
works. Every bad line is reported and nothing is saved unless the whole file is
valid. Uploads add to the manual indicators (a value already present is updated).
One file can be up to 16 MB and 2,000,000 indicators; split a larger one. Delete
manual indicators on the page; feed indicators come back with the next download,
so turn the feed off instead. Indicators kept from a deleted feed can be deleted
one by one.

## Matching

### The threat intel match detection

`threat-activity` is built in and enabled. Every 5 minutes it runs

```
* | threatmatch
| head 1000
```

over the last 10 minutes and raises one finding per indicator and target system per
24 hours, titled for example *Threat intel match on src 203.0.113.9 (feodo-tracker)*.
The finding's result has the matched field and value, the indicator, its sources,
weight and description. Risk is 60 times the indicator's weight, added to
`threat_target` (system) and `user`. It does nothing until there are indicators.
Matching is forward-looking; to check older events, search with a longer time range.

### threatmatch

`| threatmatch [fields]` keeps only events where a field equals an active indicator.
It runs inside OpenSearch: the server sends the indicator values as `terms` filters
(10,000 values per clause, upper- and lower-case for hashes) and IPv4 networks as
prefix filters, so events are never streamed through Signalith. It must come right
after the search. Up to about 800 network clauses are used (a /24 or /16 is one;
a /20 is 16); networks beyond that are matched only by `| intel`. IPv6 networks
match only with `| intel`.

Each event gets:

| Column | Meaning |
| --- | --- |
| `threat_match_field`, `threat_match_value` | The event field and value that matched (the highest-weight match if several did) |
| `threat_indicator`, `threat_type` | The indicator, such as the network the address is in |
| `threat_source` | Every source listing it |
| `threat_weight`, `threat_description` | From the strongest indicator |
| `threat_target` | The system on your side: the destination when the source matched, otherwise the source or reporting host |

### intel

`| intel [fields]` checks any result in the Signalith server and adds
`<field>_intel_source`, `<field>_intel_type`, `<field>_intel_weight` and
`<field>_intel_description` where a value is an indicator. It also matches URLs by
host against domain indicators and Sysmon `process_hash` lists. Use it after `stats`:

```
datamodel=Network_Traffic | stats count, sum(bytes) as bytes by dest | intel dest | where dest_intel_source=*
```

## Storage and scale

Indicators are stored in the `<prefix>_intel` OpenSearch index, which event searches
never read, and every server keeps the active ones in memory (about 200 bytes each),
reloading within a minute when another server changes them. A few hundred thousand
indicators are fine; the threatmatch filter for 200,000 IP indicators is a few
megabytes per search.

## API

Every change needs a signed-in session (or basic sign-in) and is refused from other
sites, like the rest of the API. Secret values are never returned: headers come back
as `{"name": "X-Api-Key", "set": true}` and the password as `{"set": true}`.

| Method and path | Purpose |
| --- | --- |
| `GET /api/intel` | Counts by type and source, and every feed with its status |
| `GET /api/intel/feeds` | Every feed with its settings and status, plus `downloads` (whether this server downloads feeds), `manage` (whether feeds can be changed here), `shared` (whether the feeds are shared), `feeds_file` (empty when shared), `formats`, `types`, `file_error` when the feeds file cannot be read, and for admins `etags`, each feed's version by name. A shared feed that was not added on the page has `from`, such as `"applied from signalith.yaml on siem-b"` |
| `POST /api/intel/feeds` | Add a feed (body below); it downloads at once |
| `PUT /api/intel/feeds/{name}` | Change a feed added on the page. Settings left out stay as they are; an empty secret keeps the saved one. 409 for a feed from signalith.yaml, unless the feeds are shared. With `If-Match` and the feed's etag, 412 when it changed meanwhile; the answer's `ETag` is its new version |
| `DELETE /api/intel/feeds/{name}?indicators=remove\|keep` | Delete a feed added on the page; `remove` (default) deletes its indicators, `keep` lets them age out. Takes `If-Match` like `PUT` |
| `POST /api/intel/feeds/{name}/refresh` | Download a feed now. With shared feeds, on a server that does not download them: `202 {"feed","request_id","queued_on"}`, followed with `GET /api/requests/{id}` (see [the retention API](retention.md#api)), whose `result` is the feed's status, or `{"already_running":true}` when it was downloading already |
| `POST /api/intel/feeds/test` | Download without saving; the body is a feed, or `{"feed": "<name>"}` plus any settings to try on a saved feed with its saved secrets |
| `GET /api/intel/catalog` | The catalog, each entry with `added` and the `feed` made from it |
| `POST /api/intel/catalog` | Add catalog feeds: `{"ids": ["feodo-tracker", "spamhaus-drop"]}` returns `{"added": [feeds], "skipped": [{"id", "reason"}]}` |
| `POST /api/intel/taxii/collections` | A TAXII server's collections: `{"url", "username", "password", "headers"}` or `{"feed": "<name>"}` |
| `GET /api/intel/indicators?q=&type=&source=&limit=&offset=` | List indicators, newest first |
| `POST /api/intel/indicators` | Add one: `{"value": "...", "type": "auto", "description": "...", "weight": "1", "expires": "30d", "tags": []}` |
| `DELETE /api/intel/indicators/{id}` | Delete a manual indicator, or one kept from a deleted feed |
| `POST /api/intel/upload` | Add manual indicators from CSV or a list; returns `{"lines": [{"line", "msg"}]}` on errors |
| `GET /api/intel/lookup?value=` | Check one value against every indicator |

Adding a feed:

```json
POST /api/intel/feeds
{
  "name": "partner",
  "url": "https://feeds.partner.example/ips.txt",
  "format": "auto",
  "type": "auto",
  "interval": "30m",
  "max_age": "7d",
  "weight": 1.5,
  "description": "Partner list",
  "tags": ["partner"],
  "enabled": true,
  "headers": [{"name": "X-Api-Key", "value": "the key"}]
}
```

Only `name` and `url` are required (`kind`, `collection`, `column`, `username`,
`password` and `catalog` are optional; `catalog` fills empty settings from that
catalog entry). On a change, a header `{"name": "X-Api-Key"}` without a value keeps
the saved value, `{"name": "X-Api-Key", "clear": true}` removes it, and
`"clear_password": true` removes the password. The answer is the feed:

```json
{
  "name": "partner", "source": "ui", "kind": "url",
  "url": "https://feeds.partner.example/ips.txt",
  "format": "auto", "type": "auto", "interval": "30m", "max_age": "7d", "weight": 1.5,
  "description": "Partner list", "tags": ["partner"], "enabled": true,
  "headers": [{"name": "X-Api-Key", "set": true}], "password": {"set": false},
  "has_headers": true, "indicators": 0, "status": {"count": 0, "added": 0, "removed": 0}
}
```

`source` is `ui` for feeds added on the page and `config` for feeds from
signalith.yaml; `problem` explains why a feed is not downloaded. Invalid settings
answer 400 with every problem and the setting it belongs to:

```json
{
  "error": "Please fix these settings: interval must be at least 5m; feeds update far less often",
  "problems": ["interval must be at least 5m; feeds update far less often"],
  "fields": {"interval": "interval must be at least 5m; feeds update far less often"}
}
```

A test answers 200 whether or not the download worked:

```json
{
  "ok": true, "format": "csv", "column": "dst_ip", "type": "ip",
  "total": 2, "by_type": {"ip": 2}, "skipped": 0,
  "samples": [{"type": "ip", "value": "203.0.113.9"}, {"type": "ip", "value": "198.51.100.4"}],
  "bytes": 187, "duration_ms": 412
}
```

```json
{
  "ok": false, "http_status": 403,
  "error": "The server answered 403 Forbidden. This feed may need an API key. It said: \"missing or wrong API key\"",
  "total": 0, "by_type": {}, "skipped": 0, "samples": [], "bytes": 0, "duration_ms": 95
}
```

Other fields: `skipped_example` (the first value that was not an indicator),
`reserved` (private and reserved addresses skipped), `truncated` and `note` (only
part of the feed was read). Listing TAXII collections answers
`{"ok": true, "title": "...", "collections": [{"api_root", "id", "title", "description", "can_read", "media_types"}]}`,
or `{"ok": false, "error": "...", "collections": []}`.
