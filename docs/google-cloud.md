# Google Cloud

Google Cloud keeps **audit logs** of what is done in each project, folder and
organization. The **Admin Activity** log records every change: who created, changed or
deleted which resource, from where, and whether it went through. The **Data Access** log
records reads, the **System Event** log the changes Google makes itself, and the **Policy
Denied** log requests that a security policy refused. Signalith reads them, makes them
searchable and runs the SigmaHQ Google Cloud rules on them. Those rules cover firewall
rules, VPN tunnels, DNS zones, SQL databases and storage buckets changed or deleted,
service accounts changed or disabled, access policies deleted, Kubernetes secrets, role
bindings, cron jobs and admission webhooks, and break-glass deployments. **Google
Workspace** can share its own audit logs with Google Cloud, and Signalith reads them the
same way (see [Google Workspace](#google-workspace)).

## How it works

A **log sink** in Cloud Logging sends the audit log entries to a **Pub/Sub topic**. An
**OpenTelemetry Collector** pulls the topic's subscription and sends each entry to
Signalith over HTTPS, the same way it sends any other logs.

```
  Google Cloud project or organization (audit logs)
            │ log sink, filter logName:"cloudaudit.googleapis.com"
            ▼
     Pub/Sub topic ──▶ subscription (pull)
                                │
                                ▼
                    OpenTelemetry Collector ──HTTPS──▶ Signalith
```

The Collector can run on any Linux or Windows machine that can reach both Google Cloud
and Signalith, such as a small Compute Engine VM or a server in your own network.

## What you need

- A Google Cloud project to hold the Pub/Sub topic and subscription. The sink can send
  that project's audit logs, or a whole organization's.
- Rights to create a log sink, a topic, a subscription and a service account: Owner on the
  project, or Logging Admin, Pub/Sub Admin and Service Account Admin. An organization's
  sink needs Logging Admin on the organization.
- The **OpenTelemetry Collector Contrib**, version 0.132 or later (`otelcol-contrib`).

Admin Activity and System Event logs are always on and free. Data Access logs are off for
most services (BigQuery is the exception) and can be large; turn on the ones you want in
**IAM & Admin**, then **Audit Logs**.

## Set it up

On the **Add data** page, choose **Google Cloud**, enter your project ID and the name you
want for the subscription, and pick where the Collector runs. The page lists every step,
with your names in each command, and writes the Collector's configuration. Here are the
same steps, with `my-project` as the project and `signalith-audit` as the topic, sink and
subscription. Each is a `gcloud` command, which Cloud Shell runs as it is:

1. **Make a topic.**
   `gcloud pubsub topics create signalith-audit --project=my-project`
2. **Make a log sink that sends the audit logs to it.**
   `gcloud logging sinks create signalith-audit pubsub.googleapis.com/projects/my-project/topics/signalith-audit --project=my-project --log-filter='logName:"cloudaudit.googleapis.com"'`.
   For a whole organization, use `--organization=ORGANIZATION_ID --include-children` in
   place of `--project=my-project`, so the sink sends every project's entries.
3. **Let the sink publish to the topic.** The sink has its own identity, its writer
   identity, which needs Pub/Sub Publisher on the topic:
   `gcloud pubsub topics add-iam-policy-binding signalith-audit --project=my-project --role=roles/pubsub.publisher --member=$(gcloud logging sinks describe signalith-audit --project=my-project --format='value(writerIdentity)')`
4. **Make a pull subscription.** It keeps entries for 7 days while the Collector is away:
   `gcloud pubsub subscriptions create signalith-audit --topic=signalith-audit --project=my-project --ack-deadline=60 --message-retention-duration=7d`
5. **Make a service account that can only pull it.**
   `gcloud iam service-accounts create signalith-collector --project=my-project`, then
   `gcloud pubsub subscriptions add-iam-policy-binding signalith-audit --project=my-project --member=serviceAccount:signalith-collector@my-project.iam.gserviceaccount.com --role=roles/pubsub.subscriber`.
6. **Give the Collector the service account.** On a Compute Engine VM, attach the service
   account to the VM, with the Cloud Platform access scope, and the Collector uses it with
   no key. Elsewhere, make a key file:
   `gcloud iam service-accounts keys create signalith-gcp-key.json --iam-account=signalith-collector@my-project.iam.gserviceaccount.com`.
   Keep it private: it lets anyone who has it read your audit logs.
7. **Install the Collector and its configuration.** Follow the page's steps. With a key
   file, the Collector finds it through the `GOOGLE_APPLICATION_CREDENTIALS` environment
   variable, so the configuration never holds it. On Linux, put the key in
   `/etc/otelcol-contrib/signalith-gcp-key.json` and add
   `GOOGLE_APPLICATION_CREDENTIALS=/etc/otelcol-contrib/signalith-gcp-key.json` to
   `/etc/otelcol-contrib/otelcol-contrib.conf`. On Windows, put it next to the
   configuration and set the variable in the service's `Environment` value in the
   registry. The page shows both.

The receiver it writes looks like this:

```yaml
extensions:
  text_encoding/signalith:
    encoding: utf8

receivers:
  googlecloudpubsub/signalith:
    project: my-project
    subscription: projects/my-project/subscriptions/signalith-audit
    encoding: text_encoding/signalith
```

The text encoding passes each message's data, one log entry as JSON, on as it is, so no
field is renamed or lost on the way. Pub/Sub keeps each entry until the Collector
acknowledges it, so a restart neither loses nor repeats entries, and an entry Pub/Sub
delivers twice is stored once. The configuration also has the exporter that sends to
Signalith with your agent token, as every Collector configuration from the Add data page
does (see [OpenTelemetry](opentelemetry.md)).

Already run a Collector? Add the extension, the receiver and the pipeline to your own
configuration instead. Signalith also reads log entries that arrive another way: a
`LogEntry` as text or as a map in an OTLP log record's body, or sent as JSON with the tag
`gcp`, either as the entry itself or as a Pub/Sub push or pull message
(`{"message": {"data": "<base64>"}}`).

## What you get

Each log entry becomes one event with `sourcetype=google:gcp:pubsub:message`, Splunk's.
Its fields keep the entry's own names, flattened into dotted names. Splunk's add-on for
Google Cloud Platform keeps the same names under `data.` (`data.protoPayload.methodName`);
Signalith leaves that prefix off, and the rules are converted to match.

| Field | Example |
| --- | --- |
| `logName`, `log_id` | `projects/prod-1/logs/cloudaudit.googleapis.com%2Factivity`, `cloudaudit.googleapis.com/activity` |
| `protoPayload.serviceName`, `protoPayload.methodName` | `compute.googleapis.com`, `v1.compute.firewalls.delete` |
| `protoPayload.resourceName` | `projects/prod-1/global/firewalls/allow-ssh` |
| `protoPayload.authenticationInfo.principalEmail` | `alice@example.com` |
| `protoPayload.requestMetadata.callerIp`, `protoPayload.requestMetadata.callerSuppliedUserAgent` | `203.0.113.7`, `google-cloud-sdk gcloud/500.0.0` |
| `protoPayload.status.code`, `protoPayload.status.message` | `7`, `PERMISSION_DENIED` |
| `protoPayload.authorizationInfo{}.permission`, `protoPayload.authorizationInfo{}.granted` | each value in a list, as Splunk's add-on names it: `compute.firewalls.delete`, `true` |
| `resource.type`, `resource.labels.project_id` | `gce_firewall_rule`, `prod-1` |
| `insertId`, `severity`, `timestamp` | `-abc123e1`, `NOTICE` |
| `request_parameters`, `response_elements` | the call's whole request and response, as JSON text |

`log_id` is the log the entry is in, the end of its `logName` with the `%2F` read as a
slash. A search for a list's value (`protoPayload.authorizationInfo{}.permission=storage.buckets.delete`)
matches an entry when any value in the list does, as in Splunk. Labels, whose names the
sender chooses, are kept as one field of JSON text (`labels`), so they can't use up the
index's field names. Each event also gets the data model fields of what it is:

- An **Admin Activity** or **System Event** entry is a **Change** event, with `action`
  (created, deleted, modified, enabled, disabled, started or stopped, from the method's
  verb), `command` (the method), `status` (success, or failure with `reason`), `user` and
  `src_user` (who made the call), `src` (their address), `object` (the resource),
  `object_path` (its full name), `object_category` (its type, such as `gcs_bucket`),
  `dest` (the service) and `vendor_account` (the project).
- A sign-in to a Google account (`login.googleapis.com`, when your organization shares its
  Google Workspace data with Google Cloud) is an **Authentication** event, with `action`
  success or failure (see [Google Workspace](#google-workspace)).
- The rest (Data Access and Policy Denied entries) are **Other** events, with the same
  `user`, `src`, `status` and `vendor_account`.

Some searches to start with:

```
datamodel=Change sourcetype=google:gcp:pubsub:message | stats count by user, command
sourcetype=google:gcp:pubsub:message status=failure | stats count by user, src, reason
sourcetype=google:gcp:pubsub:message protoPayload.methodName=SetIamPolicy | table _time, user, object_path
```

## Google Workspace

Google Workspace keeps audit logs of what its admins and users do. When you share them
with Google Cloud, Cloud Logging keeps them in your organization's audit logs, as log
entries like Google Cloud's own, and the same sink, topic and Collector bring them to
Signalith. The Admin log (`admin.googleapis.com`: users, roles, settings and apps
changed) is in the organization's Admin Activity log, and the Login log
(`login.googleapis.com`: sign-ins, failed sign-ins and Google's warnings about them) in
its Data Access log.

To share them:

1. In the Google Admin console, as a super admin, go to **Account**, then **Account
   settings**, then **Legal and compliance**.
2. Open **Sharing options**, choose **Enabled** under **Share data with Google Cloud
   services**, and save. Your Workspace needs a Google Cloud organization to share with,
   which Google makes the first time someone in it uses Google Cloud.
3. Make the log sink at the organization, as the second step of
   [Set it up](#set-it-up) says: Workspace's entries are in the organization's own logs,
   not in any project's, so a project's sink never sees them.
   `gcloud logging sinks create signalith-audit pubsub.googleapis.com/projects/my-project/topics/signalith-audit --organization=ORGANIZATION_ID --include-children --log-filter='logName:"cloudaudit.googleapis.com"'`.
   The same filter matches Google Cloud's logs and Workspace's. `gcloud organizations list`
   shows the organization's ID. When you let the sink publish to the topic, describe it
   with `--organization=ORGANIZATION_ID` too.

After you share them, entries can take an hour or more to start arriving, and Google can
take longer to publish a Workspace event than a Google Cloud one. Each Workspace entry is
an event like any other Google Cloud one, with `vendor_product="Google Workspace"`, and a
little more:

| Field | Example |
| --- | --- |
| `event_name` | the event as Workspace's Reports API names it: `GRANT_ADMIN_PRIVILEGE`, `login_failure` |
| `event_parameters.<name>` | each of the event's parameters, by its name in lower case: `event_parameters.user_email`, `event_parameters.new_value`; a list's values are each in the list |
| `protoPayload.methodName` | the event in the entry's own form: `google.admin.AdminService.grantAdminPrivilege` |

An admin's change is a **Change** event: `command` and `signature` are the event's name,
`user` is the admin, `src` their address, `object` what the change is about (the user,
group, role, app or setting the event's parameters name), `object_category` the
event's type (`USER_SETTINGS`) and `vendor_account` the organization's ID. A sign-in is an
**Authentication** event: `action` is success or failure, `user` who signed in,
`authentication_method` how (`google_password`, `saml`), and `reason` why it failed
(`login_failure_invalid_password`). Some searches to start with:

```
datamodel=Change sourcetype=google:gcp:pubsub:message vendor_product="Google Workspace" | stats count by user, command
sourcetype=google:gcp:pubsub:message event_name=login_failure | stats count by user, src, reason
```

## Detections

The SigmaHQ pack has 16 Google Cloud rules (see [Detections](detections.md#google-cloud)):
firewall rules, VPN tunnels, DNS zones, SQL databases and storage buckets changed or
deleted, buckets listed, data re-identified with Sensitive Data Protection, packet
mirroring, service accounts changed, disabled or deleted, access policies deleted, and
Kubernetes secrets, role bindings, cron jobs, admission webhooks and break-glass
deployments. Each searches `sourcetype=google:gcp:pubsub:message`. Turn them on from the
pack's page like any other rules.

It also has 7 Google Workspace rules, for Workspace's audit logs shared with Google Cloud:
an application's access level changed, an application removed, an API client given
domain-wide access, 2-step verification turned off, a role changed or deleted, a privilege
removed from a role, and admin rights granted. SigmaHQ's 3 Workspace sign-in rules are
experimental, so they don't ship.

Splunk Security Content's Google Cloud detections are all experimental, and the Splunk
pack ships only production ones, so none ship yet. Its Google Workspace detections read
the records of Workspace's Reports API, as Splunk's add-on for Google Workspace stores
them, rather than these log entries, so they don't ship either.

## When nothing arrives

- **Wait 5 minutes.** Google Cloud publishes audit log entries within a minute or two.
  Google Workspace's can take an hour or more after you share them, and only an
  organization's sink sends them.
- **Check the subscription.** Its page in the Google Cloud console charts unacknowledged
  messages. None published to the topic: the sink is missing, its filter matches nothing,
  or its writer identity lacks Pub/Sub Publisher (Cloud Logging's **Log Router** page
  shows the sink's errors). Messages piling up: the Collector can't reach Pub/Sub, or its
  service account can't pull.
- **Read the Collector's log**, with `journalctl -u otelcol-contrib` on Linux or in Event
  Viewer's Application log on Windows. `PermissionDenied` there means the service account
  lacks Pub/Sub Subscriber on the subscription, or the Collector found other credentials;
  `could not find default credentials` means `GOOGLE_APPLICATION_CREDENTIALS` is not set
  or the key file is not readable by the Collector.
- **Check the Health page** in Signalith, which says whether OTLP batches arrive and why
  any were refused.
