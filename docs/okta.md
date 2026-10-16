# Okta

Okta keeps a **System Log** of what happens in your Okta organization: sign-ins and
MFA prompts, sessions, accounts created, locked and deleted, groups and apps changed,
admin roles granted, policies and network zones edited, API tokens made, and the threats
Okta ThreatInsight sees. Signalith reads it straight from Okta, makes each event
searchable and runs the SigmaHQ and Splunk Okta rules on it. Nothing needs to be
installed.

## How it works

Signalith signs in to Okta as an **API service app** you add in the Okta Admin Console,
with a private key only Signalith holds, and reads the System Log from Okta's **System
Log API** (`GET /api/v1/logs`). Every minute it reads the events published since it last
looked, oldest first, in pages of up to 1,000.

The server that runs the background jobs does the reading, and keeps its place in the
log in OpenSearch, so a restart or another server taking over carries on where it left
off. An event read twice is stored once. Events usually arrive within a minute or two of
happening. Okta keeps them for 90 days, so Signalith catches up after being off for less
than that; one round reads at most 20 pages, so a long gap is read over a few minutes,
leaving room in your organization's rate limit for its other apps.

The app can only read the System Log: it is granted the `okta.logs.read` scope and
nothing else, and it signs in with a signed token (`private_key_jwt`), never a shared
secret. When the app requires DPoP, as new Okta apps do, Signalith also proves each
token is its own with a key it makes for itself and never stores.

## What you need

- An Okta admin who can add apps and assign admin roles: a Super Administrator, or an
  Application Administrator together with someone who can assign roles.
- The Signalith server must reach your Okta domain (such as `example.okta.com`) over
  HTTPS. Set `HTTPS_PROXY` if it goes through a proxy. Signalith only connects to
  internet addresses for Okta, so a domain that leads to this machine or the local
  network is refused.

## Set it up

On the **Add data** page, choose **Okta** for the same steps:

1. **Add the app.** In the Okta Admin Console, open **Applications > Applications** and
   choose **Create App Integration**. Pick **API Services**, name it `Signalith`, and
   save.
2. **Give it a key.** On the app's **General** tab, edit **Client Credentials** and
   choose **Public key / Private key**. Choose **Add key**, then **Generate new key**.
   Okta shows the private key once: copy it, as **PEM** or as the JSON it shows, before
   you close the box. Save the app. If Okta asks, keep **Require Demonstrating Proof of
   Possession (DPoP) header in token requests** on: Signalith supports it.
3. **Let it read the System Log.** On the **Okta API Scopes** tab, choose **Grant** next
   to `okta.logs.read`. On the **Admin roles** tab, choose **Edit assignments** and give
   the app **Read-only Administrator**, which may read the System Log and change nothing.
4. **Enter it in Signalith.** In **Settings**, under **Okta**, enter your **Okta domain**
   (the address of your Okta sign-in page, without `https://`), the app's **Client ID**
   from its General tab, and the private key. Choose **Test**: it signs in and reads the
   last hour of the System Log. Then save.

Reading starts within a minute. The first time, Signalith reads the last 24 hours.

The key is kept encrypted with Signalith's other secrets, and only ever sent to your
Okta domain. It is only used to sign Signalith's sign-in, so Okta never sees it either.
A browser drops the line breaks of a PEM key pasted into the Settings page; Signalith
reads it all the same. If the app has more than one key, also enter the **Key ID** (the
`kid` Okta shows next to the key). To keep the key out of the settings entirely, put it
in a file only Signalith can read and set `SIGNALITH_OKTA_PRIVATE_KEY_FILE` to that
file's path, or store it encrypted in `signalith.yaml` with
`signalith secrets set okta.private_key < key.pem`. In `signalith.yaml` the settings are:

```yaml
okta:
  domain: example.okta.com
  client_id: 0oa1b2c3d4e5f6g7h8i9
  private_key: ...   # or SIGNALITH_OKTA_PRIVATE_KEY_FILE
  key_id: ""         # only when the app has more than one key
```

To change the key, add a new one to the app, enter it in Signalith, then deactivate the
old one in Okta.

### With an API token instead

An admin's API token works too, in place of the app: create one in **Security > API >
Tokens** while signed in as an admin with at least **Read-only Administrator**, and enter
it as **API token** with the Okta domain (or set `SIGNALITH_OKTA_API_TOKEN`). A token has
all of that admin's rights and expires after 30 days without use, so the app is the
better way. When both are set, Signalith uses the app.

### Sending events another way

Events that come some other way are read the same: send Okta's LogEvent JSON (one event,
or a JSON array of them as the API returns a page) to `/api/ingest?tag=okta` with an
agent token, or through the [OpenTelemetry Collector](opentelemetry.md) as a log record
whose body is one event. Don't do this as well as Signalith's own reading, which needs
nothing else.

## What you get

Each event becomes one event with `sourcetype=OktaIM2:log`, the sourcetype of Splunk's
add-on for Okta Identity Cloud. Its fields keep Okta's own names, with nested objects
flattened into dotted names:

| Field | Example |
| --- | --- |
| `eventType` | `user.session.start`, `user.mfa.factor.deactivate`, `system.api_token.create` |
| `displayMessage`, `severity` | `User login to Okta`, `INFO`, `WARN` |
| `actor.alternateId`, `actor.displayName` | `jo@example.com`, `Jo Doe` |
| `client.ipAddress`, `client.userAgent.rawUserAgent` | `203.0.113.7`, the browser |
| `outcome.result`, `outcome.reason` | `SUCCESS`, `FAILURE`, `INVALID_CREDENTIALS` |
| `authenticationContext.externalSessionId` | the session an event belongs to |
| `securityContext.isProxy`, `securityContext.asOrg` | `true` for an anonymizing proxy, the network's owner |
| `debugContext.debugData.behaviors`, `.risk`, `.threatSuspected` | what Okta's risk engine saw |
| `target{}.type`, `target{}.alternateId`, `target{}.displayName` | each thing the event acted on, as Splunk's add-on names them |
| `okta_device.name`, `okta_device.os_platform`, `okta_device.managed` | the device an Okta Verify or FastPass sign-in came from (Okta's `device` object, renamed because Signalith's `device` field holds text) |

Every value is kept as text, because Okta's debug data uses names of its own whose values
differ from one event type to the next. Each event also gets the data model fields of
what it is:

- A **sign-in** (`user.session.start`, `user.authentication.*`, opening the Admin
  Console, a denied app) is an **Authentication** event, with `action` success, failure
  or pending, `user`, `src`, `app`, `reason` and `authentication_method`.
- A **change** (users, accounts, MFA factors, groups, apps, policies, network zones, API
  tokens, identity providers, devices, admin roles) is a **Change** event, with `action`
  (created, modified, deleted or lockout), `command`, `object` and `object_category` (the
  first target), and `change_type` `AAA`.
- A **threat** Okta detected (`security.*`, `user.risk.*`) or **suspicious activity** a
  user reported is an **Alerts** event, with `signature`, `severity` and `type`.
- Everything else, such as MFA pushes sent and policies evaluated, is an **Other** event.

All of them have `user` and `src_user` (the actor), `src` (the client's address),
`signature` (the event type), `description`, `id` (the event's ID), `app` and `dest`
(the app it was about, or `Okta`), `result` and `status` (success or failure). Some
searches to start with:

```
sourcetype=OktaIM2:log eventType=user.session.start outcome.result=FAILURE | stats count by user, src
datamodel=Change sourcetype=OktaIM2:log | stats count by signature, user
sourcetype=OktaIM2:log securityContext.isProxy=true | stats count by user, src
```

## Detections

The SigmaHQ pack has 19 Okta rules (see [Detections](detections.md#okta)): admin roles
assigned, API tokens created or revoked, apps, sign-on policies, policies and policy
rules changed or deleted, identity providers created, MFA reset or deactivated, network
zones deactivated or deleted, accounts locked out, admin functions used through a proxy,
new Admin Console behaviors, sessions started through an anonymizing proxy, FastPass
phishing detections, ThreatInsight threats, unauthorized access to apps and suspicious
activity users reported. Two SigmaHQ Okta rules are left out: `okta_user_created` is
informational, and `okta_password_in_alternateid_field` uses a regular expression
Signalith can't read exactly.

The Splunk Security Content pack has 12 Okta rules: failed MFA challenges, MFA turned
off, identity provider changes, many accounts locked out, many failed MFA requests for
one user, many users failing to sign in from one address, new API tokens, new devices
enrolled, sign-ins with only one factor, suspicious activity reported, ThreatInsight
threats and unauthorized access to apps. Of the 21 Splunk rules for Okta, 9 are left out:
4 are experimental, one is a hunting search and one a correlation search, two need
`iplocation` to name a city (Signalith has no city database), and one uses a command
Signalith doesn't run (`REPORT.md` in the pack lists each). Turn them on from each pack's
page like any other rules.

## When nothing arrives

- **Look at the Add data page.** Choose **Okta**: below the steps it says how far the
  System Log has been read, and the last error Okta gave.
- **Test the settings.** **Test** in Settings names what is wrong: a client ID Okta
  doesn't know, a key that isn't the app's (or the app not set to **Public key / Private
  key**), the `okta.logs.read` scope not granted, or no admin role that can read the
  System Log.
- **Rate limits.** When the organization's rate limit for the System Log is used up,
  Signalith waits until Okta says it resets, then carries on.
- **Read Signalith's log** for `could not read the Okta System Log`, which carries Okta's
  own error code (such as `E0000011` for a token Okta refused).
