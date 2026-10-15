# Microsoft Entra ID and Azure

Microsoft Entra ID (formerly Azure AD) records every sign-in to your Microsoft tenant,
every change to its users, groups, roles and apps, and every risk Entra ID Protection
detects. Azure records every change made to each subscription's resources in its
**activity log**: who created, changed or deleted what, and from where. Signalith reads
both, makes them searchable and runs the SigmaHQ Azure rules on them. Those rules cover
sign-ins without MFA, MFA denied, users added to admin roles, new app credentials,
conditional access policies changed, key vaults deleted and more.

## How it works

Entra ID and Azure send their logs through **diagnostic settings** to an **Azure Event
Hub**. An **OpenTelemetry Collector** reads the event hub and sends each message to
Signalith over HTTPS, the same way it sends any other logs. Signalith splits each message
into its records.

```
  Entra ID (sign-ins, audit log, risk)     Azure subscriptions (activity log)
            │ diagnostic setting                    │ diagnostic setting
            └──────────────▶ Event Hub ◀────────────┘
                                │
                                ▼
                    OpenTelemetry Collector ──HTTPS──▶ Signalith
```

The Collector can run on any Linux or Windows machine that can reach both Azure and
Signalith, such as a small Azure VM or a server in your own network.

## What you need

- An **Event Hubs namespace** (Standard tier) with one event hub for these logs.
- **Microsoft Entra ID P1 or P2** for the sign-in logs. The audit log works on every tier.
- Rights to add diagnostic settings: Security Administrator in Entra ID, and Monitoring
  Contributor (or Owner) on each subscription.
- The **OpenTelemetry Collector Contrib**, version 0.145 or later (`otelcol-contrib`).

## Set it up

On the **Add data** page, choose **Entra ID and Azure** and pick where the Collector runs.
The page lists every step and writes the Collector's configuration. Here are the same
steps:

1. **Make an event hub.** In the Azure portal, create an Event Hubs namespace (Standard
   tier) and, in it, an event hub named `signalith`. One day of retention is enough: the
   Collector reads it as messages arrive.
2. **Make a key that can only read it.** In the `signalith` event hub's **Shared access
   policies**, add a policy with **Listen** only, and copy its **Connection string-primary
   key**. Keep it private: it lets anyone who has it read your logs.
3. **Send Entra ID's logs.** In the Microsoft Entra admin center, open **Monitoring &
   health**, then **Diagnostic settings**, then **Add diagnostic setting**. Tick
   `AuditLogs`, `SignInLogs`, `NonInteractiveUserSignInLogs`,
   `ServicePrincipalSignInLogs`, `ManagedIdentitySignInLogs`, `RiskyUsers` and
   `UserRiskEvents`, choose **Stream to an event hub**, and pick the namespace and the
   `signalith` event hub.
4. **Send each subscription's activity log.** In the Azure portal, open **Monitor**, then
   **Activity log**, then **Export Activity Logs**. Pick the subscription, add a diagnostic
   setting with `Administrative`, `Security`, `Policy` and `Alert` ticked, and stream it to
   the same event hub. Do this for each subscription you want to watch.
5. **Install the Collector and its configuration.** Follow the page's steps. The
   configuration reads the connection string from the `SIGNALITH_EVENT_HUB` environment
   variable, so the file never holds it. On Linux, add it to
   `/etc/otelcol-contrib/otelcol-contrib.conf` as one line,
   `SIGNALITH_EVENT_HUB=Endpoint=sb://...`. On Windows, put it in the service's
   `Environment` value in the registry. The page shows both.

The receiver it writes looks like this:

```yaml
receivers:
  azure_event_hub/signalith:
    connection: ${env:SIGNALITH_EVENT_HUB}
    format: raw
    storage: file_storage/signalith
```

`format: raw` passes each message on whole, so no field is renamed or lost on the way. The
`storage` keeps the Collector's place in the event hub, so a restart neither loses nor
repeats records. The configuration also has the exporter that sends to Signalith with your
agent token, as every Collector configuration from the Add data page does (see
[OpenTelemetry](opentelemetry.md)).

Already run a Collector? Add the receiver and the pipeline to your own configuration
instead. Signalith also reads Azure records that arrive another way: an Event Hub
message (`{"records": [...]}`) as text in an OTLP log record's body, or single records sent
as JSON with the tag `azure`.

## What you get

Each record becomes one event. Its fields keep the record's own names, as Splunk's add-on
for Microsoft cloud services does, with everything under `properties` flattened into dotted
names:

| Field | Example |
| --- | --- |
| `category` | `SignInLogs`, `AuditLogs`, `Administrative` |
| `operationName` | `Sign-in activity`, `Add member to role`, `MICROSOFT.KEYVAULT/VAULTS/DELETE` |
| `resultType`, `resultDescription` | `50126`, `Invalid username or password` |
| `callerIpAddress`, `tenantId`, `resourceId` | `203.0.113.7` |
| `properties.userPrincipalName`, `properties.appDisplayName` | `alice@example.com`, `Azure Portal` |
| `properties.status.errorCode`, `properties.authenticationRequirement` | `0`, `singleFactorAuthentication` |
| `properties.initiatedBy.user.userPrincipalName` | `admin@example.com` |
| `properties.targetResources` | the changed objects, as JSON text |

Entra ID's logs have `sourcetype=azure:monitor:aad` and the activity log
`sourcetype=azure:monitor:activity`. A sign-in also gets `signin_status`, `Success` or
`Failure` with why (`Failure: MFA denied; user declined the authentication`), as Microsoft
Sentinel shows it. Each event also gets the data model fields of what it is:

- A **sign-in** is an **Authentication** event, with `action` success or failure, `user`,
  `app`, `src`, `dest` (the resource signed in to) and `reason`.
- An **audit record** is a **Change** event, with `action` (created, deleted, modified),
  `command` (the operation), `status`, `user` (who made the change), `object` (what they
  changed) and `object_category`.
- An **activity log** change (category `Administrative`) is a **Change** event too, with
  `object` (the resource), `object_category` (its type, such as
  `microsoft.keyvault/vaults`), `user`, `src`, `status` and `vendor_account` (the
  subscription). The activity log's other categories (service health, alerts, autoscale,
  policy) are **Other** events.
- A **risk detection** is an **Alerts** event, with `type` (the risk, such as
  `unfamiliarFeatures`), `severity`, `user` and `src`.

Some searches to start with:

```
sourcetype=azure:monitor:aad category=SignInLogs action=failure | stats count by user, src, reason
datamodel=Change sourcetype=azure:monitor:aad | stats count by command, user
sourcetype=azure:monitor:activity action=deleted | stats count by user, object_category
```

## Detections

The SigmaHQ pack has 108 Azure rules (see [Detections](detections.md)): sign-ins,
directory changes, Privileged Identity Management, Identity Protection risk detections and
activity log changes to firewalls, key vaults, Kubernetes clusters and virtual networks.
Each searches the sourcetype its log has. Turn them on from the pack's page like any other
rules.

## When nothing arrives

- **Wait 10 minutes.** Entra ID and Azure send their logs every few minutes.
- **Check the event hub.** Its Overview page charts incoming and outgoing messages.
  Nothing incoming: a diagnostic setting is missing or points at another event hub.
  Incoming but nothing outgoing: the Collector can't reach it, or its connection string is
  wrong.
- **Read the Collector's log**, with `journalctl -u otelcol-contrib` on Linux or in Event
  Viewer's Application log on Windows. `unauthorized` there means the connection string's
  policy lacks Listen, or is for another event hub.
- **Check the Health page** in Signalith, which says whether OTLP batches arrive and why
  any were refused.
