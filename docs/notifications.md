# Notifications

Signalith can send a message when a finding is raised. It can send to a Slack channel, a
Microsoft Teams channel or chat, email, or a webhook such as a SOAR or ticketing system.
Set this up on the **Notifications** page, under Configure. Only admins see the page.

There are two parts:

- A **channel** is a place messages go, such as Slack #soc or the SOC mailbox.
- A **rule** says which findings go to which channels. For example: "High and critical
  findings from any detection go to Slack #soc and Email SOC team."

Nothing is sent until a rule sends findings to a channel.

## Add a channel

On **Notifications**, choose **Add channel** and pick a kind. When there are no channels
yet, the page offers the four kinds itself. Each kind asks for a **Name**. The name is shown
on the page, in rule summaries and in emails, so name the place it posts to, such as `#soc`.

Each kind of channel has **Send test**. It sends a test message through the settings in the
dialog, before you save them, and says whether it worked. If a test fails, the dialog shows
why, in plain words: the address could not be found, the certificate is not trusted, the
receiver answered 404, and so on.

### Slack

1. In Slack, add the **Incoming Webhooks** app to your workspace. Pick the channel and copy
   its **Webhook URL** (`https://hooks.slack.com/services/...`).
2. In Signalith, choose **Add channel**, then **Slack**. Paste the URL and name the channel
   after the Slack channel, such as `#soc`.
3. Choose **Send test**, then **Add channel**.

Messages use Slack Block Kit: the finding's title, its urgency, detection, ATT&CK
techniques and entities, and a link to the Findings page.

### Microsoft Teams

Teams messages go through a **Workflows** webhook. Microsoft retired the old Office 365
connectors ("Incoming Webhook"), and their URLs no longer work.

1. In Teams, open the channel's **...** menu, then **Workflows**. Choose **Post to a
   channel when a webhook request is received**. The template may also be called "Send
   webhook alerts to a channel".
2. Pick the team and channel, then finish the workflow. Copy the URL it shows. The URL
   usually starts with `https://prod-...logic.azure.com/workflows/...` or `https://...
   .environment.api.powerplatform.com/...`.
3. In Signalith, choose **Add channel**, then **Teams**. Paste the URL, then **Send test**
   and **Add channel**.

Messages are Adaptive Cards (version 1.4) inside the `{"type": "message", "attachments":
[...]}` envelope that the Workflows template expects. A workflow you build yourself in
Power Automate works too, as long as it posts the card it receives.

### Email

Signalith sends mail through your own mail server over SMTP.

| Setting | What to enter |
| --- | --- |
| **Mail server**, **Port** | Your mail server's name, such as `smtp.office365.com`, and its port |
| **Connection** | **STARTTLS** on port 587 (the default), **TLS** on port 465, or **None**. None is only allowed for a mail relay on this server (`localhost`), and sends no password. |
| **User name**, **Password** | The account to sign in with. Leave both empty for a server that does not need a sign-in. Passwords are only sent over an encrypted connection. Signalith uses PLAIN sign-in, or LOGIN when the server only offers that. |
| **From** | The address messages come from. Your mail server must allow the account to send as this address. |
| **To** | One or more addresses, separated by commas (at most 50) |

Signalith refuses to send when the server does not offer STARTTLS. It does not fall back to
sending in plain text. Each email has a plain-text body with the finding's details and a link.
The subject line is the urgency and title, such as `[Signalith] High: Brute force against admin`.

### Webhook

A webhook channel POSTs a JSON body to any URL, such as a SOAR, a ticketing system or your
own script.

- **URL**: where to send. A URL often holds a token, so Signalith encrypts it like a password.
- **Signing secret** (optional): signs each body so the receiver can check that it came from
  Signalith. See [Checking the signature](#checking-the-signature).
- **Headers** (optional): headers the receiver asks for, such as `Authorization: Bearer ...`
  or an API key. Header values are encrypted. Signalith sets `Content-Type`, `User-Agent`
  and `X-Signalith-Signature` itself, and these cannot be changed.

The receiver should answer with any 2xx status. The rest of the answer is not used. Signalith
reads at most 64 KB of it, to quote in an error.

### Advanced: private networks, this server, and private certificates

- **Private addresses** (10.x, 192.168.x, internal names) are allowed, since SOAR and
  firewalls live there.
- **This server's own addresses** (`localhost`, `127.0.0.1`, `::1`) and cloud metadata
  addresses (such as `169.254.169.254`) are refused. This stops a channel from being used to
  reach services that only this machine can reach. To send to a receiver on the same machine,
  open **Advanced** and tick **Allow this server's own addresses**. Signalith's own
  OpenSearch address is always refused.
- Signalith checks addresses after it looks up the name, so a name that resolves to a refused
  address is refused too.
- **Certificate authority**: certificates are always verified. If the receiver's certificate
  comes from a private certificate authority, paste that authority's certificate (PEM, one
  or more `-----BEGIN CERTIFICATE-----` blocks) under **Advanced**. The system's trusted
  authorities still count.
- Signalith does not follow a redirect to another server, and waits at most 10 seconds for
  an answer (30 seconds for email).

## Add a rule

Choose **Add rule**. A rule has:

| Setting | Meaning |
| --- | --- |
| **Name** | Shown on the page and in deliveries |
| **Send to** | One or more channels |
| **How urgent** | The least urgency to send: Critical, High (the default), Medium, Low, or Any. Urgency is the finding's own (its severity, or the urgency set on it). |
| **From** | **Any detection**, or **Only some**: pick detections from the list |
| **Least risk score** (More options) | Only applies to findings that carry a risk score: the risk incident detections put one in `result.risk_score`. Other findings are sent whatever this says. Empty or 0 means any score. |
| **Include sample data** (More options) | Findings from the one-click sample data are skipped unless this is on. Turn it on to try a channel with sample data. |
| **On** | A rule that is off sends nothing |

The dialog shows a plain-English summary of the rule as you change it.

What gets sent:

- Only **new** findings are sent. A rule sends findings raised after it was added or last
  turned on, so a new rule does not send old findings. The job looks back over the last 30
  minutes.
- Each finding goes to each channel **once**, even when several rules match it.
- The channels in one rule all get the finding.
- **Flood guard**: if one pass would send more than 10 messages to a channel, Signalith sends
  the 9 most urgent and then one summary, such as "And 23 more new findings", with a link to
  the Findings page.
- Messages link to `server.public_url` + `/#findings`. When `server.public_url` is not set,
  messages have no link, and the page says so. Set it on the **Settings** page.

When you delete a channel, it is taken out of its rules. A rule left with no channel is
turned off.

## Send a test

Each channel card has **Send test**, and so does the channel dialog. A test message is
marked as a test, as in the webhook example below (`"type": "test"`). Tests are listed under
**Recent deliveries** like other messages. The card then shows "Test delivered 2m ago", or
the error.

Tests are sent from the server that runs the background jobs. On any other server the
button is not shown (see below).

## Recent deliveries and failures

**Recent deliveries** lists the latest messages: the finding, the channel, the status and
when it was sent. Deliveries are kept for 30 days.

- **Sent**: the receiver accepted it. "on try 3" means earlier tries failed.
- **Retrying**: the send failed in a way that may pass, such as a timeout, a 5xx or 429
  answer, or a temporary 4xx mail error. Signalith tries again after 1, 5, 15 and 60 minutes,
  so there are 5 tries in all.
- **Failed**: Signalith gave up. Some failures are not retried, because sending again would
  fail the same way: a refused address, a redirect to another server, a 4xx answer other than
  408 and 429, or a permanent 5xx mail error.

Each channel card shows its last delivery. When a channel's last message failed, the
**Health** page warns: "Notifications to Slack #soc are failing."

Errors never show a channel's secrets. The URL's token, header values, the signing secret
and the password are replaced with `***`.

## Which server sends

When several servers share one OpenSearch, only the server that holds the **background
jobs** sends notifications. This is the same server that runs detections (see
[servers.md](servers.md)). It runs the `notifications` job every 15 seconds.

- Channels and rules live in that server's notifications file. On other servers the page
  shows them but cannot change them, and it names the server to use. If the jobs move to a
  server whose notifications file differs, the Servers page says so, as it does for the
  other settings files. Copy the file to every server that may run the jobs.
- Before it sends, the job **claims** each message by creating a record in OpenSearch (the
  `<prefix>_notifications` index). The record's ID is made from the finding and the channel,
  so it is the same on every server. Only one server can create it, so only one server sends,
  even right after the jobs move.
- If a server stops while sending, its message may or may not have arrived. Signalith does
  not send it again, since it would rather miss one than send it twice. After 5 minutes the
  delivery is marked failed: "The server stopped while sending this message; it may not
  have arrived."
- The job checks that this server still holds the jobs before each send.
- With `detections.scheduler: false` on every server, nothing is sent.

## Where the settings live

Channels and rules are kept in `notifications.yaml` in the lookups folder (setting
`notify.file`, environment `SIGNALITH_NOTIFY_FILE`; a relative path is relative to the
config file). The server writes the file with mode 0600. Every secret in it is encrypted
with the master key (`enc:v1:...`): webhook URLs, header values, signing secrets and email
passwords. `signalith secrets status`, `encrypt`, `rotate-master` and the **Security** page
cover it, like the other settings files. Edit it on the page rather than by hand. A plain value
typed into the file still works, and it is encrypted the next time the page saves the file
or `signalith secrets encrypt` runs.

If the file cannot be read, nothing is sent, and the page shows the error. If a secret cannot
be decrypted, for example after the master key is lost, that channel sends nothing. Its card
says which secret to enter again.

## The webhook body

Every webhook POST has `Content-Type: application/json`, `User-Agent: Signalith` and, when
the channel has a signing secret, `X-Signalith-Signature`. The body is version 1.

A finding:

```json
{
  "version": 1,
  "type": "finding",
  "sent": "2026-10-13T09:15:02Z",
  "finding": {
    "id": "f7c1e0a2b9d84d1c",
    "title": "Brute force against admin from 203.0.113.9",
    "urgency": "high",
    "severity": "medium",
    "detection": "brute_force",
    "mitre": ["T1110"],
    "entities": {"user": "admin", "host": "web-01", "src": "203.0.113.9"},
    "risk_score": null,
    "created": "2026-10-13T09:14:51Z",
    "link": "https://siem.example.com/#findings",
    "sample": false
  }
}
```

| Field | Meaning |
| --- | --- |
| `version` | The body's version. It stays `1` while fields are only added; a change that breaks receivers would be `2`. |
| `type` | `finding`, `summary` (flood guard) or `test` |
| `sent` | When this message was sent (UTC). A receiver can refuse old ones. |
| `finding.id` | The finding's ID in Signalith |
| `finding.urgency` | `critical`, `high`, `medium`, `low` or `informational`: the urgency the rule matched on. `severity` is the detection's own. |
| `finding.detection` | The detection's ID |
| `finding.mitre` | ATT&CK technique IDs; may be empty (`[]`) |
| `finding.entities` | Any of `user`, `host`, `src` and `dest`; may be empty (`{}`) |
| `finding.risk_score` | A number for findings of risk detections, else `null` |
| `finding.link` | `server.public_url` + `/#findings`, or empty when that is not set |
| `finding.sample` | `true` for a finding from sample data |

A flood guard summary:

```json
{
  "version": 1,
  "type": "summary",
  "sent": "2026-10-13T09:15:02Z",
  "summary": {"count": 23, "text": "And 23 more new findings", "link": "https://siem.example.com/#findings"}
}
```

A test has `"type": "test"` and a finding with the ID `test`, the title "Test message from
Signalith", and made-up entities.

Receivers should ignore fields they do not know, so new fields can be added to version 1.

### Checking the signature

With a signing secret, each POST has:

```
X-Signalith-Signature: sha256=<hex HMAC-SHA256 of the raw body, keyed with the secret>
```

Compute the HMAC over the raw bytes of the body as received, before parsing the JSON.
Compare the values in constant time. Also check `sent`, so an old message cannot be
replayed; allowing five minutes is plenty.

Python:

```python
import hashlib, hmac, json, time
from datetime import datetime

def verify(secret: str, body: bytes, header: str) -> dict:
    want = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(want, header or ""):
        raise ValueError("bad signature")
    msg = json.loads(body)
    sent = datetime.fromisoformat(msg["sent"].replace("Z", "+00:00")).timestamp()
    if abs(time.time() - sent) > 300:
        raise ValueError("too old")
    return msg
```

Go:

```go
func verify(secret string, body []byte, header string) bool {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(want), []byte(header))
}
```

Node.js:

```js
const crypto = require('crypto');
function verify(secret, rawBody, header) {
  const want = 'sha256=' + crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
  return header && want.length === header.length && crypto.timingSafeEqual(Buffer.from(want), Buffer.from(header));
}
```

## API

Every route is for admins.

| Route | What it does |
| --- | --- |
| `GET /api/notify` | Channels, rules and the page's details: each channel without its secrets (`url_set`, `password_set`, `signing_secret_set`, header names only), its last delivery and the rules that use it; each rule with its `summary`; `revision`, `file`, `manage` (whether this server can change them) and `file_error` |
| `PUT /api/notify` | Replaces channels and rules with the body (`revision`, `channels`, `rules`). A secret left empty keeps its saved value; `clear_password`, `clear_signing_secret` and a header with `clear` remove one. A secret must be typed again when a channel's URL or mail server moves to another server. A body with problems is refused with 400 and `problems` (`where`, `field`, `message`). A stale `revision`, or another server running the jobs, gives 409. |
| `POST /api/notify/test` | Sends a test message: `{"id": "<channel id>"}` for a saved channel, or `{"channel": {...}}` for a channel being edited. Its empty secrets are the saved ones. Answers `{ok, duration_ms, error}`. |
| `GET /api/notify/deliveries?limit=50` | The latest deliveries, newest first (at most 500) |
