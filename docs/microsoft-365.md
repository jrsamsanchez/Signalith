# Microsoft 365

Microsoft 365 keeps an **audit log** of what happens in the tenant: sign-ins, mailbox
rules and permissions in Exchange, files viewed, shared and deleted in SharePoint and
OneDrive, Teams activity, admin changes and the alerts Microsoft Defender and Purview
raise. Signalith reads it straight from Microsoft, makes each record searchable and runs
the SigmaHQ Microsoft 365 rules on it. Nothing needs to be installed.

## How it works

Signalith signs in to Microsoft as an app you register in Entra ID, with a client secret,
and reads the audit log from the **Office 365 Management Activity API**. It subscribes to
four audit logs, then every five minutes reads what each made available since it last
looked:

| Audit log | What is in it |
| --- | --- |
| `Audit.AzureActiveDirectory` | Sign-ins and Entra ID changes |
| `Audit.Exchange` | Mailbox and Exchange admin activity |
| `Audit.SharePoint` | SharePoint and OneDrive file and sharing activity |
| `Audit.General` | Teams, Power Platform, Defender and Purview alerts, and the rest |

The server that runs the background jobs does the reading, and keeps its place in each
log in OpenSearch, so a restart or another server taking over carries on where it left
off. A record read twice is stored once. Records usually arrive 30 minutes to a few hours
after they happen: that is Microsoft's delay, not Signalith's. Microsoft keeps them for 7
days, so Signalith catches up after being off for less than that.

## What you need

- Auditing turned on. It is on by default; in **Microsoft Purview**, open **Audit**: if
  there is a **Start recording user and admin activity** button, choose it.
- Rights to register an app and grant admin consent: Application Administrator, Cloud
  Application Administrator or Global Administrator in Entra ID.
- The Signalith server must reach `login.microsoftonline.com` and `manage.office.com`
  over HTTPS (or your cloud's addresses, below). Set `HTTPS_PROXY` if it goes through a
  proxy.

## Set it up

On the **Add data** page, choose **Microsoft 365** for the same steps:

1. **Register an app.** In the Microsoft Entra admin center, open **App registrations**
   and choose **New registration**. Name it `Signalith`, keep **Accounts in this
   organizational directory only**, and register it.
2. **Let it read the audit log.** On the app's **API permissions** page, choose **Add a
   permission**, then **Office 365 Management APIs**, then **Application permissions**,
   and tick `ActivityFeed.Read`. Then choose **Grant admin consent**. Signalith needs
   nothing else: it can't read mail or files, only the audit log.
3. **Make a client secret.** On **Certificates & secrets**, choose **New client secret**
   and copy its **Value** (not its Secret ID). Microsoft shows it once.
4. **Enter it in Signalith.** In **Settings**, under **Microsoft 365**, enter the
   **Directory (tenant) ID** and the **Application (client) ID** from the app's Overview
   page, and the secret. Choose **Test**: it signs in and checks the app may read the
   audit log. Then save.

Reading starts within five minutes. The first time, Signalith reads the last 24 hours. A
tenant that never had these subscriptions may take up to 12 hours to make its first
records available.

The secret is kept encrypted with Signalith's other secrets, and only ever sent to
Microsoft's sign-in service for the tenant and app it was entered for. To keep it out of
the settings entirely, set the `SIGNALITH_M365_CLIENT_SECRET` environment variable
instead. In `signalith.yaml` the settings are:

```yaml
m365:
  tenant_id: 11111111-2222-3333-4444-555555555555
  client_id: 66666666-7777-8888-9999-000000000000
  client_secret: ...   # or SIGNALITH_M365_CLIENT_SECRET
  cloud: commercial    # gcc, gcc_high or dod for US government tenants
```

When the secret expires, make a new one and enter it the same way.

### US government clouds

Set **Microsoft cloud** to the tenant's cloud. GCC uses the commercial sign-in service
and `manage-gcc.office.com`; GCC High uses `login.microsoftonline.us` and
`manage.office365.us`; DoD uses `login.microsoftonline.us` and
`manage.protection.apps.mil`.

## What you get

Each record becomes one event with `sourcetype=o365:management:activity`. Its fields keep
the record's own names, as Splunk's add-on for Microsoft 365 does, with nested objects
flattened into dotted names:

| Field | Example |
| --- | --- |
| `Operation` | `UserLoggedIn`, `New-InboxRule`, `FileDownloaded`, `AlertTriggered` |
| `Workload` | `AzureActiveDirectory`, `Exchange`, `SharePoint`, `OneDrive` |
| `UserId`, `ClientIP`, `ObjectId` | `jo@example.com`, `203.0.113.7`, the file or mailbox |
| `ResultStatus`, `LogonError` | `Succeeded`, `Failed`, `IdsLocked` |
| `record_type` | the record type's name: `ExchangeAdmin`, `SharePointFileOperation` |
| `Parameters`, `ExtendedProperties` | lists, as JSON text |
| `Parameters{}.Name`, `Parameters{}.Value` | each value in a list, as Splunk's add-on names it |

Every value is kept as text, because the same field holds a number in one workload's
records and text in another's. Each event also gets the data model fields of what it is:

- A **sign-in** (`UserLoggedIn`, `UserLoginFailed`) is an **Authentication** event, with
  `action` success or failure, `user`, `src`, `user_agent`, `reason` and
  `authentication_method`.
- A **change** (an operation such as `New-`, `Set-`, `Add-`, `Remove-`, `Update`,
  `Delete`) is a **Change** event, with `action` (created, modified, deleted), `command`,
  `user`, `object` and `change_type` (the workload).
- An **alert** from Defender or Purview is an **Alerts** event, with `signature` (the
  alert's name), `severity` and `id`.
- Everything else, such as files viewed or mail read, is an **Other** event.

All of them have `user`, `src`, `signature` (the operation), `app` (the workload),
`status` and `vendor_account` (the tenant). Some searches to start with:

```
sourcetype=o365:management:activity Operation=New-InboxRule | stats count by user, src
datamodel=Authentication sourcetype=o365:management:activity action=failure | stats count by user, reason
sourcetype=o365:management:activity Operation=FileDownloaded | stats count by user | sort -count
```

## Detections

The SigmaHQ pack has 17 Microsoft 365 rules (see [Detections](detections.md)): MFA turned
off, new federated domains, PST exports, and the Defender for Cloud Apps and Purview
alerts for impossible travel, activity from anonymous or suspicious addresses,
suspicious inbox forwarding, ransomware activity, mass file deletion and users restricted
from sending mail. Turn them on from the pack's page like any other rules.

## When nothing arrives

- **Wait.** Microsoft makes records available 30 minutes to a few hours after they
  happen, and a new subscription's first ones may take 12 hours.
- **Look at the Add data page.** Choose **Microsoft 365**: below the steps it says how far
  each audit log has been read, and the last error Microsoft gave.
- **Test the settings.** **Test** in Settings names what is wrong: a wrong or expired
  secret, an app ID or tenant ID Microsoft doesn't know, or an app without
  `ActivityFeed.Read` and admin consent.
- **Check auditing is on** in Microsoft Purview (above).
- **Read Signalith's log** for `could not read the Microsoft 365 audit log`, which carries
  Microsoft's own error code.
