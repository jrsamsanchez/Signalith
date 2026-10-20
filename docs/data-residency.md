# Where your data goes

Signalith stores your events in the OpenSearch you run, and nowhere else. Its own
settings, keys and files are on its servers (`/var/lib/signalith` and `/etc/signalith` on
Linux, `C:\ProgramData\Signalith` on Windows) and in that OpenSearch. Nothing is sent to
the Signalith project: there is no telemetry ([Outbound connections](outbound.md#no-telemetry)).

Some features send event data, or facts about it, to a system outside the server. Each
one is off until an admin sets it up. This table lists all of them.

| Feature | What leaves the server | Where it goes | Masking | How to turn it off |
| --- | --- | --- | --- | --- |
| [Investigate with AI](investigate.md) | The finding; the events behind it; where its users, hosts and addresses show up from 7 days before to 1 day after; threat intel matches; related findings; asset and identity context; analyst notes. Then the results of up to 8 searches the model asks for, 10 rows each | The AI model set up under **Settings > AI assistant** (**Address**) | Values of **Fields never sent** (`assistant.mask_fields`) are replaced with stand-ins everywhere they appear. Fields whose names contain password, passwd, secret, token, api_key, apikey, cookie, authorization, session_id or private_key are always masked. The analyst sees exactly what will be sent and must click to send it ([Keeping data private](investigate.md#keeping-data-private)) | Off by default. Leave **Investigate with AI** (`assistant.investigate`) off |
| Ask, the plain-English box above the query editor | The question, and the query Signalith's offline translator made from it. Sent only in AI mode, or in auto mode when the translator understood too little | The AI model | None: only what the person typed | Leave **Provider** (`assistant.provider`) off. The offline translator still works ([Asking in plain English](query-language.md#asking-in-plain-english)) |
| Describe a detection in plain English | The description, and the offline draft made from it. Never events | The AI model | None: only what the admin typed | Leave **Provider** off. The offline draft still works ([Describe a detection](detections.md#describe-a-detection-in-plain-english)) |
| Improve with AI, for a custom log parser | The first 20 lines of the sample (at most 8 KB), the current parser, and the list of data models and formats | The AI model | Credentials in the lines are replaced with `[masked]`: values after names such as password, token, key and secret, cookie and Authorization headers, passwords in URLs, private keys, and common access key and token shapes ([Improve it with AI](custom-logs.md#improve-it-with-ai)) | Leave **Provider** off, or don't click it. The offline rules still work |
| AI tools through MCP (`signalith mcp`) | Whatever the AI tool reads: search results (up to 500 rows a search), findings, cases, detections, assets and risk | The provider of the model the AI tool uses, such as the company behind Claude Desktop or Cursor | **None** ([Security](ai-tools.md#security)) | There is no server switch. Don't make API tokens for AI tools, and revoke them on **Settings > API tokens**. A user can still run it with their own user name and password |
| [Notifications](notifications.md) (Slack, Teams, email, webhook) | A finding's title, urgency, severity, detection, ATT&CK techniques, user, host, source and destination, risk score, time and a link. An approval request says what waits, such as the address to block. Never the event or the finding's result row | The channels you add | None. Titles can name a host (the content pack titles end in "on" and the host) | Don't add channels, or rules that send to them |
| [Ticketing](ticketing.md) (Jira, ServiceNow) | A case's title, severity, status, description, notes and a link. Never events, search results or findings | The Jira or ServiceNow you connect | None | Don't add a connection |
| [Response actions](response-actions.md) and [playbooks](playbooks.md) | The target (an IP, domain, user or host), and what the action's template adds: the finding and case IDs, who ran it and why | The firewall, SOAR, directory or script the action names | None | Don't set up actions. Playbooks only run actions and notifications that exist |
| CVE lookups for [vulnerability scans](vulnerabilities.md) | The vendor and product names of the software a scan finds, such as `openbsd openssh`. No versions, addresses or host names | `services.nvd.nist.gov`, or your NVD mirror | Not needed | Turn off **Look up CVEs in the National Vulnerability Database** in **Scanner setup** |
| [Directory sign-in](users.md#sign-in-with-active-directory-or-ldap) and [single sign-on](sso.md) | The user name of the person signing in, and directory lookups about them | Your LDAP or Active Directory, or your identity provider | Not needed | Use Signalith's own accounts |
| [Archives](retention.md#archives) | Whole days of events, before retention deletes them | The archive folder you set, which can be a network share | Archives can be encrypted ([Archived days](security.md#archived-days)) | Leave **Archive before deleting** off |
| [Cold storage](cold-storage.md) | Whole days of events, as OpenSearch snapshots. OpenSearch sends them, not Signalith | The snapshot repository you register in OpenSearch, such as an S3 bucket | As the repository stores them | Leave **Move to cold storage after** empty |

These features send nothing of yours: they only download public data.

| Feature | What it downloads |
| --- | --- |
| [Threat intel](threat-intel.md) feeds | Whole feeds, with the API key you gave a feed. Matching against indicators happens in Signalith |
| [Behavior baselines](baselines.md#the-ip-database) | The iptoasn.com IP database |
| [Content updates](detections.md#content-updates) | The signed content bundle |
| KEV and EPSS, for [vulnerability scans](vulnerabilities.md#which-vulnerabilities-to-fix-first-kev-and-epss) | The whole KEV catalog and the whole EPSS score list |
| [Microsoft 365](microsoft-365.md) and [Okta](okta.md) | Their audit logs, into Signalith, with the app credentials you set up |

## Keeping AI on your own network

Every AI feature uses the one model set up under **Settings > AI assistant**. With
Ollama, LM Studio or vLLM on your own network, nothing the AI features send leaves it,
and the Investigate dialog says whether the model is on your network or outside it.
Each request is written to the [audit log](audit.md) with who sent it, which model and
address, and how much was sent.

The MCP server is the exception: it runs on the person's own computer, and what the AI
tool reads goes to whatever model that tool uses.

## Related

- [Outbound connections](outbound.md): every host Signalith and its installers reach.
- [Threat model: AI features](threat-model.md#ai-features)
