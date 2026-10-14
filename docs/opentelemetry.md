# OpenTelemetry

Signalith takes logs over OTLP/HTTP, so an
[OpenTelemetry Collector](https://opentelemetry.io/docs/collector/) or an app's
OpenTelemetry SDK can send to it. Fluent Bit stays the default agent; use the Collector
when your hosts already run one, or when you would rather have one agent for logs,
metrics and traces. Signalith keeps only the logs.

## Set up a Collector

Open **Add data**, pick **OpenTelemetry**, and choose where the Collector runs:

- **Linux**: reads `/var/log/auth.log` or `/var/log/secure`, or the systemd journal,
  like the Fluent Bit agent.
- **Windows**: reads the Security event log, Sysmon when **Include Sysmon** is on, and
  PowerShell script blocks when **Include PowerShell** is on.

Either way the Collector also listens on `127.0.0.1:4317` (gRPC) and `127.0.0.1:4318`
(HTTP) for apps on that host that export OTLP logs, and passes those on too.

The page gives the steps and a complete `config.yaml` for the
[Collector Contrib](https://github.com/open-telemetry/opentelemetry-collector-releases/releases)
distribution (`otelcol-contrib`, 0.100 or later): it already holds this server's
address, an [agent token](agent-tokens.md) of its own (made when you copy or download
the configuration) and, over HTTPS, Signalith's CA certificate to check the
server with. It keeps unsent logs and its place in each log on disk, so a restart or
an outage of Signalith neither loses nor repeats events.

If the Collector already sends elsewhere, keep your config and add Signalith's parts
to it: the `otlphttp/signalith` exporter (and `file_storage/signalith`, which it uses),
plus a pipeline, or add the exporter to an existing logs pipeline.

## Send from your own Collector or SDK

Any OTLP/HTTP sender works. Point it at:

| Setting | Value |
| --- | --- |
| Logs endpoint | `https://<server>:8080/api/otlp/v1/logs` (or endpoint `https://<server>:8080/api/otlp`, to which the exporter adds `/v1/logs`) |
| Header | `Authorization: Bearer <agent token>`; make one on **Add data** under **Agent tokens**, or with `signalith tokens create` (see [agent-tokens.md](agent-tokens.md#create-a-token)) |
| Encoding | protobuf (`application/x-protobuf`, the Collector's default) or JSON (`application/json`) |
| Compression | gzip (the Collector's default) or none |
| CA | Signalith's CA certificate (`/api/tls/ca.pem`), unless the server has a certificate your systems trust |

For example, with curl:

```sh
curl --cacert signalith-ca.pem https://siem.example.com:8080/api/otlp/v1/logs \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"resourceLogs":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"shop"}}]},
       "scopeLogs":[{"logRecords":[{"severityText":"ERROR","body":{"stringValue":"payment failed"}}]}]}]}'
```

Only logs are taken: gRPC, metrics and traces are not. Over plain HTTP to the HTTPS
port, OTLP follows `server.tls.plaintext_ingest`, as the agents do.

## How records are mapped

Records from the Collector's own receivers for sources Signalith already parses are
mapped as the Fluent Bit agent's records are, so the built-in detections fire whichever
agent collects them:

| Receiver | Becomes |
| --- | --- |
| `windowseventlog` (Security log 4624, 4625, 4648, 4656, 4657, 4661, 4662, 4663, 4688, 4697, 4698, 4706, 4719, 4720, 4726, 4728, 4732, 4738, 4756, 4768, 4769, 4794, 5136, 5145, 5156, 5157; System 7045; Sysmon 1, 3, 6, 7, 8, 10, 11, 12, 13, 14, 22, 23, 26; PowerShell 4104) | Authentication, Endpoint, Change, Network_Traffic, Image_Load, Filesystem, Registry, Network_Resolution, Script |
| `filelog` on `auth.log` or `secure` (or any syslog-format file) | Authentication and Change for sshd, sudo, su and account changes |
| `journald` | as the agent's journal input |
| `syslog` | as Signalith's own syslog receiver |

Both of the `windowseventlog` receiver's `event_data_format` settings work (`map`, the
default in recent versions, and `array`).

Any other record is an **Other** event with `sourcetype=otel`:

- `message` is the body (a structured body as JSON, with its top-level keys also as
  fields).
- Attributes, then resource attributes, become fields, with dots turned into
  underscores (`http.route` becomes `http_route`). Common semantic-convention names map
  onto Signalith's own: `user.name` and `enduser.id` to `user`, `client.address` and
  `source.address` to `src`, `server.address` and `destination.address` to `dest` (and
  their ports to `src_port` and `dest_port`), `http.request.method` to `http_method`,
  `http.response.status_code` to `status`, `url.full` to `url`,
  `user_agent.original` to `http_user_agent`, `process.pid`, `process.executable.path`
  and `process.command_line` to `process_id`, `process_path` and `process`, and
  `file.path` and `file.name` to `file_path` and `file_name`.
- The resource's `host.name` is `host`, and `service.name` is `service`.
- `severity` is the severity text (or the name of the severity number), and
  `severity_id` the number; `trace_id`, `span_id` and `otel_scope` (the instrumentation
  scope) are kept, so a search can follow one request.

Every record also gets `host`, `service`, `trace_id` and `span_id` when it has them.

The event's time is the record's own time, else the time in its log line, else when the
Collector saw it. As for every source, a time older than `ingest.max_event_age` or more
than an hour ahead is filed under the time it arrived (see [Ingest limits](sending-data.md#ingest-limits)).

## Limits and errors

The same limits as agent batches apply: up to 16 MB per request (also after gzip is
undone), 200,000 records of at most 1 MB each, values nested at most 32 levels. A
request over a limit or that does not decode is refused with 4xx and a message saying
why, and nothing from it is stored; the Collector logs the message and drops the batch,
so keep batches small (the generated config's batch processor sends at most 5,000
records). When Signalith is busy or OpenSearch is down the answer is 503 with
`Retry-After`, and the Collector keeps the batch and sends it again. Records OpenSearch
turns away are counted in the answer's partial success.
