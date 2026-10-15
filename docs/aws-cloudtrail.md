# AWS CloudTrail

AWS CloudTrail records every sign-in to the AWS console and every call made to your AWS
accounts' APIs: who did it, from where, with which tool, and what they asked for. Signalith
reads CloudTrail's records, makes them searchable and runs the SigmaHQ CloudTrail rules on
them. Those rules cover sign-ins without MFA, logging switched off, new access keys,
public snapshots and more.

## How it works

CloudTrail writes a file of records to an S3 bucket every few minutes. S3 tells an SQS
queue about each new file. An **OpenTelemetry Collector** reads the queue, fetches each
file and sends its records to Signalith over HTTPS, the same way it sends any other logs.

```
  your AWS accounts
        │ every API call and sign-in
        ▼
  CloudTrail ──▶ S3 bucket ──▶ SQS queue
                    │              │ "a new file"
                    │ the file     ▼
                    └──────▶ OpenTelemetry Collector ──HTTPS──▶ Signalith
```

The Collector can run on any Linux or Windows machine that can reach both AWS and
Signalith. A small EC2 instance is the easiest: it gets AWS access from its role, with no
keys to keep.

## What you need

- A CloudTrail **trail** that writes to an S3 bucket. An organization trail covers every
  account in your AWS Organization with one bucket.
- The **OpenTelemetry Collector Contrib**, version 0.153 or later (`otelcol-contrib`).
- An AWS identity for the Collector: an EC2 instance role, or an IAM user's access key.

CloudTrail's management events (the default for a new trail) are what the rules read. Data
events (every S3 object read, every Lambda call) work too, but they can add up to a lot of
events and AWS charges for them.

## Set it up

On the **Add data** page, choose **AWS CloudTrail**. Enter your trail's bucket and the URL
of the queue you'll make (you can fill them in as you go), and pick where the Collector
runs. The page then lists every step with your own names filled in, and writes the
Collector's configuration. Here are the same steps:

1. **Have a trail write to S3.** In the AWS console, open CloudTrail, then Trails, then
   Create trail, and keep management events on. Note the bucket's name.
2. **Make a queue.** In SQS, create a **standard** queue in the bucket's region. Give it an
   access policy that lets the bucket send to it. The Add data page writes this policy for
   you:

    ```json
    {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
      "Principal": {"Service": "s3.amazonaws.com"}, "Action": "sqs:SendMessage",
      "Resource": "arn:aws:sqs:us-east-1:123456789012:signalith-cloudtrail",
      "Condition": {"ArnLike": {"aws:SourceArn": "arn:aws:s3:::my-cloudtrail-bucket"}}}]}
    ```

3. **Tell the queue about new files.** In the bucket's Properties, add an event
   notification for **all object create events**, with the prefix `AWSLogs/` and the queue
   as its destination.
4. **Let the Collector read them.** Attach this IAM policy to the EC2 instance's role, or
   to an IAM user whose access key the Collector gets:

    ```json
    {"Version": "2012-10-17", "Statement": [
      {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::my-cloudtrail-bucket/*"},
      {"Effect": "Allow", "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
       "Resource": "arn:aws:sqs:us-east-1:123456789012:signalith-cloudtrail"}]}
    ```

5. **Install the Collector and its configuration.** Follow the page's steps. With an access
   key instead of a role, put `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` in the
   Collector's environment: in `/etc/otelcol-contrib/otelcol-contrib.conf` on Linux, or in
   the service's `Environment` value in the registry on Windows. The page shows both.

The configuration it writes looks like this:

```yaml
extensions:
  aws_logs_encoding/cloudtrail:
    format: cloudtrail

receivers:
  aws_s3/cloudtrail:
    s3downloader:
      region: us-east-1
      s3_bucket: my-cloudtrail-bucket
    sqs:
      queue_url: https://sqs.us-east-1.amazonaws.com/123456789012/signalith-cloudtrail
      region: us-east-1
    encodings:
      - extension: aws_logs_encoding/cloudtrail
        suffix: .json
```

It also has the exporter that sends to Signalith with your agent token, as every Collector
configuration from the Add data page does (see [OpenTelemetry](opentelemetry.md)).

Already run a Collector? Add the receiver, the extension and the pipeline to your own
configuration instead. Signalith also reads CloudTrail records that arrive another way: as
JSON in an OTLP log record's body (as from CloudWatch Logs), or as JSON records sent with
the tag `aws.cloudtrail`.

## What you get

Each record becomes one event with `sourcetype=aws:cloudtrail`. Its fields keep
CloudTrail's own names, as Splunk's AWS add-on does, so searches written for CloudTrail
work as they are:

| Field | Example |
| --- | --- |
| `eventName`, `eventSource` | `CreateAccessKey`, `iam.amazonaws.com` |
| `userIdentity.type`, `userIdentity.arn` | `AssumedRole`, `arn:aws:sts::123456789012:assumed-role/Admin/alice` |
| `userIdentity.sessionContext.sessionIssuer.userName` | `Admin` |
| `sourceIPAddress`, `userAgent` | `203.0.113.7`, `aws-cli/2.15.0` |
| `errorCode`, `errorMessage` | `AccessDenied` |
| `awsRegion`, `recipientAccountId` | `us-east-1`, `123456789012` |
| `requestParameters.*`, `responseElements.*` | `requestParameters.userName=backdoor` |

The call's parameters and response are also kept whole, as JSON text, in
`request_parameters` and `response_elements`, for searching words anywhere inside them.
Each event also gets the data model fields of what it is:

- A sign-in to the console (`signin.amazonaws.com`) is an **Authentication** event, with
  `action` success or failure, `user`, `src` and `reason`.
- A call that changes something is a **Change** event, with `action` (created, deleted,
  modified, ...), `command` (the call), `status`, `user`, `src`, `vendor_account` and
  `vendor_region`.
- A call that only reads (`readOnly=true`, such as `ListBuckets`) is an **Other** event.

Some searches to start with:

```
sourcetype=aws:cloudtrail errorCode=AccessDenied | stats count by user, eventName
datamodel=Authentication app=aws:console action=failure | stats count by user, src
datamodel=Change vendor_product="AWS CloudTrail" | stats count by command
```

## Detections

The SigmaHQ pack has 38 CloudTrail rules (see [Detections](detections.md)). Each searches
`sourcetype=aws:cloudtrail`. Turn them on from the pack's page like any other rules.

## When nothing arrives

- **Wait 15 minutes.** CloudTrail writes a file every five minutes or so, and the queue
  hears about it only then.
- **Check the queue.** In SQS, Messages available should go up as files arrive and down as
  the Collector reads them. Never up: the event notification or the queue's access policy
  is missing. Never down: the Collector can't reach the queue, or its AWS identity lacks
  the IAM policy.
- **Read the Collector's log**, with `journalctl -u otelcol-contrib` on Linux or in Event
  Viewer's Application log on Windows. `AccessDenied` there means the IAM policy;
  `no EC2 IMDS role found` means it has no AWS identity at all.
- **Check the Health page** in Signalith, which says whether OTLP batches arrive and why any were refused.
