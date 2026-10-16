# Behavior baselines

Behavior baselines learn what each user and host usually does, and add risk when
one of them does something new or rare. They find what no single rule can: a
sign-in from a country the user never signed in from, a program almost no host
has run, an hour of uploads far above a host's normal. This is often called user
and entity behavior analytics (UEBA).

The baselines don't raise findings of their own. Each one adds **risk events** to
the user or host, in the Risk data model, with the detections' risk. Risk-based
alerting then raises a finding when enough adds up: the built-in
`risk-threshold-exceeded` detection fires at 100 risk on one user or host in 24
hours. A new country alone (40) doesn't raise a finding. A new country, a new kind
of change and a detection hit on the same user does. See
[Detections: Risk](detections.md#risk).

Open them at **Settings > Behavior baselines** (admins). They are on by default.

## The checks

| Check | Learns per | From | Adds risk when | Risk |
| --- | --- | --- | --- | --- |
| Sign-in from a new country | user | Authentication | a successful sign-in comes from a country none of the user's sign-ins came from before | 40 |
| Sign-in from a new network | user | Authentication | it comes from an AS (internet provider or cloud network) the user never signed in from, in a country they did sign in from | 15 |
| Sign-in at an unusual hour | user | Authentication | it comes at an hour of the day (UTC) with under 2% of the user's activity, once they have been seen in at least 40 different hours | 10 |
| Rare process on a host | host | Endpoint | a host runs a program it never ran before, which at most 3 hosts ever ran | 20 |
| New kind of change by a user | user | Change | a user makes a kind of change they never made before, such as a cloud API call (`CreateAccessKey`) or deleting a group | 15 |
| Unusual data volume from a host | host | Network_Traffic | a host on your network sends at least 100 MB in an hour, five times its usual hour and four standard deviations above it | 30 |

Each risk event has `detection_id` `baseline-<check>` (for example
`baseline-new-country`), the field `baseline` (the check), `baseline_value` (the
new value, such as `BR`, `AS15169`, `03:00 UTC` or `teamviewer.exe`), the fields
of the activity (`user`, `src`, `src_country`, `src_asn`, `dest`, `process_name`,
`bytes_out` and so on) and a message such as *First sign-in from Brazil (BR) for
alice, from 203.0.113.7*. Find them with:

```
datamodel=Risk detection_id=baseline-*
```

The risk is multiplied by the user's or host's priority in your
[asset and identity lists](detections.md#risk), as for every detection. The sign-in
checks are tagged ATT&CK T1078 (Valid Accounts) and the data volume check T1048
(Exfiltration Over Alternative Protocol); the rare process check counts as the
Execution tactic. Each check counts as one tactic, so three checks seeing one odd
sign-in don't add up to three tactics.

What the checks leave out:

- Computer accounts (names ending in `$`), failed sign-ins and failed changes.
- Sample data.
- For the data volume check, hosts outside your network: only private and other
  non-public addresses are learned.
- For the country and network checks, private addresses: they belong to no
  country.

## How they learn

- **Every hour.** The server that runs the background jobs reads each finished hour
  (five minutes after it ends) with ordinary searches, and updates what it learned.
  With several servers, only that server learns; when another takes over the jobs,
  it carries on from the last hour learned. Every server shows the same page.
- **The first run learns from the past.** It reads up to 30 days of the data you
  already have (or the learning period, if longer), oldest first, a day of data per
  round. Users and hosts with a history are judged from the start.
- **The learning period.** A user or host first seen less than 14 days ago is only
  learned from, so a new employee's first week adds no risk.
- **Catching up.** If the baselines fall more than 7 days behind (OpenSearch was
  down for a week), they skip to 7 days ago rather than replay every hour.
- **Each hour adds risk once.** A risk event's ID comes from the check, the user or
  host, the value and the hour, so an hour read twice (after a server takeover)
  writes nothing twice.

## Tuning

On the **Checks** card, each check has its own risk score (1 to 1000) and switch.
Its menu opens its risk in Search, or **forgets what it learned**: the check
deletes its profiles at its next round, then learns again from that hour, so it
adds no risk for the learning period. Risk it already added stays.

On the **Learning** card:

| Setting | Default | Meaning |
| --- | --- | --- |
| Behavior baselines | On | Off stops all learning and risk. What was learned is kept |
| Learning period | 14 days | 1 to 90 days |
| Forget after | 90 days | 7 to 365 days. A value not seen again for this long is forgotten, and so is a user or host |
| Rare program | 3 hosts | 1 to 10 |
| Least unusual volume | 100 MB | 1 MB to 1 TB |
| IP database | iptoasn.com | See below |

Every server shares these settings. They are kept in OpenSearch, and saving
them is recorded in the [audit log](audit.md).

## Exceptions

An exception holds back the risk of what it matches. The behavior is still
learned, so it stays normal after the exception ends. Add one on the
**Exceptions** card, or from a baseline's risk event on the Risk page with **Mark
as normal**. An exception matches:

- **Check**: one check, or any.
- **User or host**: as the risk event names it, such as `alice` or `svc-*`.
- **Value**: the `baseline_value`, such as `BR` or `AS15169`.

`*` matches anything. Empty means any. An exception can end on a date. Common uses:
a sales team that travels (`new-country`, `sales-*`, `BR`), a company VPN's
network (`new-network`, any user, `AS64500`), and build servers that run new tools
all day (`rare-process`, `build-*`).

## The IP database

The country and network checks need to know which network an address belongs to.
Signalith downloads the free
[IP to ASN database of iptoasn.com](https://iptoasn.com/), which is in the public
domain, at the first sign-in from an internet address and then once a week. It stores a copy in OpenSearch, so every server uses the same
one and a failed download keeps the last copy. The server that runs the background
jobs downloads it from `https://iptoasn.com/data/ip2asn-combined.tsv.gz`, a few
MB. Allow that address in your firewall, or set **IP database** to:

- the https address of a mirror (`https://mirror.example.com/ip2asn-combined.tsv.gz`);
- for servers without internet access, `file:` and the name of a file in the
  `ipdb` folder of the lookups folder on the server that runs the background jobs,
  such as `file:ip2asn-combined.tsv.gz` for
  `/var/lib/signalith/lookups/ipdb/ip2asn-combined.tsv.gz`. Only a file name is
  taken, never a path, so the setting can't read other files of the server. With
  several servers, put the file on each one that can run the background jobs, and
  replace it now and then;
- `off`, and the country and network checks wait.

Downloads follow the [threat intel feed rules](threat-intel.md): they don't
reach loopback, link-local or cloud metadata addresses, or OpenSearch, and only
https addresses are taken. The file is
read as tab-separated lines of start address, end address, AS number, country
code and AS name, up to 64 MB compressed.

The country is where the network is **registered**, which is usually where its
users are, but not always. A VPN, a cloud provider or a roaming mobile network can
be registered elsewhere. That is why a new country adds a moderate 40, not a
finding on its own.

## Limits

To keep memory and storage bounded:

- Each check keeps at most 200 values per user or host (countries, networks,
  programs, changes). When it is full, the value seen longest ago is dropped.
- Each check learns at most 100,000 users or hosts. Past that, new ones are learned
  once old ones are forgotten, and the page says so.
- Each check adds risk to at most 50 users or hosts per hour of data, so a change
  seen everywhere at once (new software rolled out, a VPN moved) can't flood the
  risk index. The page shows how many were held back.
- One hour's search returns at most 50,000 combinations. The page says when an hour
  had more.
- The learned profiles are kept in the `signalith_baselines` index (one shard, one
  replica when there are two OpenSearch nodes), apart from your events, so data
  retention doesn't delete them. A profile is forgotten after the **Forget after**
  period.

## API

Admins only:

- `GET /api/baselines`: the settings, each check's state and what it learned.
- `PUT /api/baselines` with `{"settings": {...}, "version": "..."}`: saves the
  settings and exceptions. The version is the one read; another admin's newer save
  is refused with 409.
- `POST /api/baselines/{check}/reset`: forgets what a check learned.
