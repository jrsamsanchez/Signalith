# Splunk HEC senders

Many tools can already send events to Splunk's HTTP Event Collector (HEC): logging
libraries, the OpenTelemetry Collector's `splunk_hec` exporter, Fluent Bit's `splunk`
output, Vector, cloud services and appliances. Signalith answers HEC's requests, so those
tools can send to Signalith by changing only the address and the token.

Signalith is not affiliated with or endorsed by Splunk. Splunk and HTTP Event Collector
are Splunk Inc.'s names, used here only to say which senders work.

## Turn it on

The HEC intake is off until an admin turns it on:

1. Open **Settings > General** and turn on **Splunk HEC senders**, then **Save**. It
   applies at once, on every server.
2. Open **Add data**, make an [agent token](agent-tokens.md) for the senders (any
   purpose; a token per group of senders makes them easy to tell apart and revoke), and
   copy it.
3. Point the sender at this server's **agent port** over HTTPS, with the token:
   - URL: `https://<server>:7779/services/collector/event` (or `/services/collector/raw`)
   - Header: `Authorization: Splunk <token>` (`Bearer <token>` works too)

If the sender checks certificates (it should), give it Signalith's CA certificate from
`https://<server>:7779/api/tls/ca.pem`, or use your own certificate (see
[HTTPS](https.md)).

For example, with curl:

```bash
curl https://siem.example.com:7779/services/collector/event \
  --cacert signalith-ca.pem -H "Authorization: Splunk $TOKEN" \
  -d '{"event": "user amy signed in", "sourcetype": "myapp", "host": "app1"}'
```

## What it accepts

| Route | What it takes |
|---|---|
| `POST /services/collector/event` (also `/services/collector` and `/event/1.0`) | JSON objects one after another, each with `event` (text or an object) and optionally `time` (epoch seconds), `host`, `source`, `sourcetype`, `index` and `fields` |
| `POST /services/collector/raw` | lines of text, one event per line; `host`, `source`, `sourcetype` and `index` in the query string |
| `GET /services/collector/health` | `{"text":"HEC is healthy","code":17}` while the intake is on |

Requests may be gzip-compressed (`Content-Encoding: gzip`). Answers are HEC's:
`{"text":"Success","code":0}`, or the HEC status code of what went wrong, with
`invalid-event-number` for a bad event. A request with a bad event is refused as a whole,
so nothing of it is stored. Indexer acknowledgment is not supported: a sender with
`useACK` on gets code 14, so turn it off.

The usual [ingest limits](sending-data.md#ingest-limits) apply: up to 16 MB per request
(after unpacking gzip), 200,000 events, and 1 MB per event. Senders share the server
fairly with every other agent, by token. When the server is busy or OpenSearch is down,
the answer is 503 with `Retry-After`, and senders send again; a request sent again is not
stored twice.

## What the events become

Each event is filed under a data model (see [What each source becomes](sending-data.md#what-each-source-becomes)), as events from agents are:

- `sourcetype` `linux_secure` or `syslog`: parsed as Linux authentication or syslog lines.
- `access_combined`, `access_common`, `apache:access`, `nginx:access`: Web.
- JSON events (an object, or text with sourcetype `_json`): read like the same record
  from an agent, so Windows events, AWS CloudTrail (`aws:cloudtrail`), Microsoft 365,
  Okta, Google Cloud, Azure and GitHub audit records get their usual fields and
  detections.
- Anything else: an Other event with the text in `message` and the sender's
  `sourcetype`.

`host` and `source` fill the event's own when it has none, and `time` sets its time.
When a parser gives an event its own sourcetype (`linux:auth` for `linux_secure`), the
sender's is kept in `orig_sourcetype`. The sender's `index` is kept in `orig_index`:
Signalith keeps events in one index per data model, so search them with `index=` or
`datamodel=` as usual (`datamodel=Other orig_index=main`). Indexed `fields` become
fields of the event; they cannot replace its own fields or set the fields Signalith
sets itself.

Every event records that it came over HEC (`signalith_intake=hec`) and the name of the
token it came with. The sender appears on the **Endpoints** page, named after the host
in its events.

## Security

- HEC is off by default, and takes only [agent tokens](agent-tokens.md): revoke a token
  and its senders are refused at once.
- Only HTTPS: while Signalith serves HTTPS, a plain-HTTP request is refused, whatever
  the setting for older agents on plain HTTP says. (With HTTPS off behind a reverse
  proxy, the proxy serves HTTPS.) A token in the query string (`?token=`) is refused, since addresses end
  up in logs.
- On a [multi-tenant](multi-tenant.md) server, a tenant's token files its events in that
  tenant's data.
