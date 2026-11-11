# Threat model

This page says what Signalith protects, who might attack it, where the trust
boundaries are, and what stands in the way of each threat. It also says what Signalith
trusts and what it leaves to you. Use it to judge whether Signalith fits your
environment, and to decide what to check before putting it on a network that matters.

!!! warning "No independent audit yet"
    Signalith has not had an independent security audit. It has one maintainer, and its
    code is reviewed with AI assistance before each change is merged (see
    [How it is reviewed](#how-it-is-reviewed)), but no second person approves changes and
    no outside firm has looked at it yet. An outside review is planned. Until then, treat
    Signalith as you would any young security tool: run it on a network you control, keep
    it up to date, and report anything you find (see [SECURITY.md](https://github.com/jrsamsanchez/Signalith/blob/main/SECURITY.md)).

- [What Signalith protects](#what-signalith-protects)
- [Who might attack it](#who-might-attack-it)
- [Trust boundaries](#trust-boundaries)
- [Threats and defenses](#threats-and-defenses)
- [What Signalith trusts](#what-signalith-trusts)
- [Out of scope and known limits](#out-of-scope-and-known-limits)
- [How it is reviewed](#how-it-is-reviewed)

## What Signalith protects

| Asset | Why it matters |
| --- | --- |
| **Events** in OpenSearch and in archives | They hold user names, addresses, command lines and sometimes secrets. Reading them helps an attacker; changing or deleting them hides what they did. |
| **Findings, cases and the audit log** | They are the record of an investigation. Changing them misleads defenders. |
| **Control of agents** | The server decides what agents read and where they send, and agents run as root or SYSTEM. Control of the server is a foothold on every computer with an agent. |
| **Response actions and playbooks** | They block addresses, disable accounts and isolate hosts. Triggering them on the wrong target is a denial of service on your own network. |
| **Keys and secrets** | The master key, the cluster key, the certificate authority's key, agent and API tokens, passwords for OpenSearch, directories, feeds, AI providers and scanners. |
| **Accounts** | Users, roles, MFA factors and sessions. |
| **Detection content** | A changed or turned-off detection is a blind spot. |

## Who might attack it

| Actor | Can | Wants |
| --- | --- | --- |
| **Someone on the network** with no account | Reach the web port (9000), the agent port (7779), syslog ports and, if exposed, OpenSearch (9200) | Sign in, read events, send forged events, crash the server |
| **Someone who writes log text** (any user of a monitored computer, a web visitor whose request is logged) | Put any text in an event | Hide from detections, inject into searches or the AI features, attack the browser of whoever views the event |
| **A stolen agent token, or a compromised computer with an agent** | Send events as that agent group; a Signalith Agent's computer can't report as another computer that has its [own key](agent-tokens.md#computer-keys) | Flood or poison the data, hide its own activity |
| **A signed-in user with a low role** (Viewer, Analyst) | Use the UI and API within their role | Gain a higher role, read what their role or tenant doesn't allow, run actions |
| **A tenant user** in multi-tenant mode | Work within their tenant | Read or change another tenant's data, reach server settings |
| **Someone who can write to OpenSearch** but has no Signalith key | Change documents in Signalith's indices | Change shared settings, users or detections, forge audit records |
| **A rogue or compromised server** that tries to join a cluster | Talk to OpenSearch and to other servers | Get the cluster key, the CA's key, or users' sessions |
| **A compromised outside service** (threat intel feed, identity provider, AI model, content or update download) | Answer Signalith's requests | Reach internal addresses through Signalith, hand it bad data or code |

## Trust boundaries

```text
 Browsers ──HTTPS:9000──┐                       ┌── Threat intel feeds, NVD/KEV/EPSS,
 AI tools (MCP) ────────┤                       │   identity providers, AI models,
                        │    Signalith server   │   webhooks, content updates
 Agents ──HTTPS:7779────┼──►  (state folder,  ──┼──►
 Syslog devices ─UDP/TCP┘    master key)        │
                                 │              └── Other Signalith servers (cluster)
                                 ▼
                            OpenSearch (HTTPS, client certificate)
```

Each arrow is a boundary where data from the other side is not trusted:

1. **Browsers and API clients** to the web port: everything is checked against the
   signed-in user's role and tenant on every request.
2. **Agents and syslog devices** to the agent and syslog ports: events are untrusted
   input, and an agent token only lets its holder send events.
3. **Signalith and OpenSearch**: Signalith treats what it reads back from OpenSearch as
   possibly changed, so shared settings, users and audit records are signed with keys
   OpenSearch never holds.
4. **Servers in a cluster**: a new server gets the cluster key only with a join token or
   an admin's approval after comparing fingerprints.
5. **Outside services**: answers are parsed with limits, and downloads that run code
   (content updates, agent updates) must carry a signature from a key built into
   Signalith.
6. **The server's own files**: the state folder is trusted. Anyone who can write it, or
   who is root or Administrator on the server, controls Signalith.

## Threats and defenses

### Sign-in and accounts

| Threat | What stands in the way |
| --- | --- |
| Guessing or stuffing passwords | Common-password blocklist and length rules ([Password rules](users.md#password-rules)); wrong passwords slow the next tries for that account from strangers, without locking the account for its owner ([Signing in](users.md#signing-in)) |
| Stolen password | Two-step sign-in with an app code or a passkey ([Two-step sign-in](users.md#two-step-sign-in), [Passkeys](users.md#passkeys)); single sign-on with your identity provider's MFA ([Single sign-on](sso.md)) |
| Stolen or left-open session | `__Host-` HTTPS-only cookie; sessions end after 1 hour idle and 24 hours at most; sensitive actions ask for the password or a passkey again ([Confirming it's you](users.md#confirming-its-you)) |
| The generated first password | The built-in admin must change it at first sign-in |
| Cross-site requests and framing | Same-origin check on every request that changes something; strict Content-Security-Policy, no framing ([Always on](security.md#always-on)) |
| Role or tenant escape | Role looked up on every request, not kept in the session; every API route has a declared role, checked by a test; tenant data in indices whose names can't overlap ([Roles](users.md#roles), [Multi-tenant mode](multi-tenant.md)) |
| Forged SSO answers | OIDC with PKCE and state checks; SAML signatures checked against the configured certificate only, with signature-wrapping variants refused, single-use requests and signed state ([Single sign-on](sso.md)) |
| Long-lived API tokens | API tokens are read-only for AI tools, expire after 90 days by default and can be revoked ([API tokens](ai-tools.md#api-tokens)) |

### Agent and ingest surface

| Threat | What stands in the way |
| --- | --- |
| Forged events from anyone on the network | Each agent group sends with its own token, kept only as a hash; revoking it turns its agents away within seconds; every event records the token and sender, which senders can't set ([Agent tokens](agent-tokens.md)) |
| Agents and admins sharing one port | Agents send to their own port (7779), so the web page needn't be reachable from every monitored computer ([Agent port](security.md#agent-port)) |
| Floods and oversized batches | Limits on connections per client, request time, batch size and memory per sender ([Ingest limits](sending-data.md#ingest-limits)) |
| Malformed input crashing a parser | Parsers have fuzz targets run in CI and for longer every night; a parser that panics on one request fails only that request |
| Log text attacking the viewer | Events are shown as text, never as HTML; invisible and reordering Unicode characters are shown marked |
| Sniffing events in transit | HTTPS by default; plain HTTP for agents can be refused ([Agents on plain HTTP](security.md#agents-on-plain-http)). Syslog over UDP is plain text by nature; prefer TLS syslog ([Syslog](security.md#syslog)) |

### Agents on monitored computers

| Threat | What stands in the way |
| --- | --- |
| A fake server collecting tokens | The install line pins the server's CA by SHA-256 before any token is sent ([How it stays safe](signalith-agent.md#how-it-stays-safe)) |
| A broken-into server pushing code to agents | Agents update only to a newer program listed in a manifest signed with the release key built into them; package sources and their keys are fixed in the install script, not sent by the server ([Updates](signalith-agent.md#updates)) |
| A broken-into server reading more of the computer | On Linux the agent's service may only read files and writes only its own folders; osquery gets only checked settings with extensions off, and Fluent Bit only a configuration that reads logs and sends them to that server: no programs, plugins, secret files or other destinations ([How it stays safe](signalith-agent.md#how-it-stays-safe)). The server still decides which logs are read, as root: guard admin accounts as you would any tool that manages your computers |

### Several servers, the cluster key and the certificate authority

| Threat | What stands in the way |
| --- | --- |
| A rogue server joining | A server gets the cluster key only with a single-use join token or after an admin compares its fingerprint and approves it ([Approving a server](multi-server.md#approving-a-server)) |
| Changing shared settings, users or detections through OpenSearch | Shared settings are signed with the cluster key, which is kept only in each server's state folder, encrypted with its master key ([Shared settings and the cluster key](servers.md#shared-settings-and-the-cluster-key)) |
| Stealing the CA's key | It is stored in OpenSearch only encrypted with the cluster key, and deleted from disk once shared ([One certificate authority](servers.md#one-certificate-authority)) |
| A stolen CA key signing anything | The CA is name-constrained to private names or to the server's own names, and limited to TLS server certificates ([Certificate authority](security.md#certificate-authority)) |
| A removed server keeping access | Each server has its own OpenSearch certificate, which can be revoked at once, and the cluster key can be rotated ([Ending a server's OpenSearch access at once](servers.md#ending-a-servers-opensearch-access-at-once)). A removed server, or a backup of any server's state folder, may still hold the cluster's HTTPS CA key. HTTPS certificates have no revocation, so it can make certificates agents trust until the cluster's CA is replaced: replace it after removing a server you no longer trust ([Replacing the cluster's CA](servers.md#replacing-the-clusters-ca)) |

### OpenSearch

| Threat | What stands in the way |
| --- | --- |
| Reading events without signing in | The Docker quick start runs OpenSearch with its security plugin, client certificates and no default passwords; the Security page checks that OpenSearch refuses anonymous searches ([Who can read OpenSearch](security.md#who-can-read-opensearch)) |
| Signalith's account doing too much | Its OpenSearch role is limited to Signalith's own indices ([Securing OpenSearch](opensearch-security.md)) |

### Search language

| Threat | What stands in the way |
| --- | --- |
| Reading data a role or tenant may not see | Searches run with the user's role and tenant; index patterns of one tenant can't match another's |
| Injection between commands (for example a value carried by `map`) | Values substituted into searches are quoted so they can never become commands or conditions; structural fuzzing in CI |
| One search exhausting the server | Limits on value size (1 MB), memory per search (256 MB), expression size, evaluation steps and subsearches; a search that fails stops only itself ([Writing queries](query-language.md)) |
| Lookup and data files reading the server's files | Only file names are taken, never paths |

### Secrets at rest and the audit trail

| Threat | What stands in the way |
| --- | --- |
| A copied disk or backup revealing passwords | Every stored password and key is encrypted with the master key, which can be kept apart from backups ([Encryption](encryption.md)) |
| Archives read outside Signalith | Archived days can be encrypted, and the Security page flags plain ones ([Archived days](security.md#archived-days)) |
| Hiding activity by changing or removing audit lines | Audit records are chained and signed with a key derived from the cluster key, with signed checkpoints; **Check integrity** and `signalith audit verify` show changed, removed or unsigned records ([Tamper evidence](audit.md#tamper-evidence)) |

### Response actions and playbooks

| Threat | What stands in the way |
| --- | --- |
| A page admin running any program | Scripts run only from a folder set on the server's disk, with no shell and a small environment without Signalith's secrets ([Run a script](response-actions.md#run-a-script)) |
| Target values injecting into webhooks | Each value is escaped for where it stands and the template is read once; values can't change the scheme, host or port ([Send a webhook](response-actions.md#send-a-webhook)) |
| Actions run without a person | Analyst role and a per-user rate limit; playbook steps can wait for approval ([Approvals](playbooks.md#approvals)) |

### AI features

| Threat | What stands in the way |
| --- | --- |
| Prompt injection in log text | Log text is fenced with a per-investigation random marker; the model has no tools of its own, only limited read-only searches; it may only suggest containment actions, which a person confirms ([Prompt injection](investigate.md#prompt-injection)) |
| Sensitive data sent to an AI provider | Use a model on your own network; mask fields, with secret-like fields always masked ([Keeping data private](investigate.md#keeping-data-private)). The MCP server masks nothing: use a model you may send that data to ([AI tools](ai-tools.md#security)) |
| An AI tool changing things | The MCP server sends only reads, and its token's role is checked like a person's |

### Outbound requests and supply chain

[Outbound connections](outbound.md) lists every host Signalith and its installers reach, and
[Where your data goes](data-residency.md) what each feature sends.

| Threat | What stands in the way |
| --- | --- |
| Feeds or downloads reaching internal addresses | Threat intel feed downloads are checked after DNS and on every redirect, and never reach link-local or cloud metadata addresses, or this machine unless allowed ([Threat intel](threat-intel.md)). The CVE, KEV and EPSS addresses are admin settings and are downloaded under the same checks; the NVD API key never follows a redirect to another server |
| A tampered detection content update | Bundles must be signed by a key built into Signalith and newer than the rules in use ([Content packs](detections.md#content-packs)). Only pack changes merged after review are signed |
| A bad or hostile upstream rule | Upstream SigmaHQ and Splunk rules arrive as a pull request pinned to an upstream commit, with the rule diff and the report of what was left out, and are signed only after it merges |
| A tampered release | Release files and images are signed with Sigstore and come with build provenance and an SBOM ([Check a download](install-packages.md#check-a-download)) |
| Vulnerable dependencies | govulncheck, Dependabot, CodeQL and Trivy image scans in CI |

## What Signalith trusts

- **Admins.** An admin can change detections, settings, users and what agents collect.
  Treat Signalith admin accounts like domain admin accounts: few, with MFA.
- **The server's operating system and its administrators.** Root or Administrator on a
  Signalith server, or anyone who can write its state folder, controls Signalith and can
  read its keys.
- **OpenSearch's administrators** can read and delete events. They can't forge shared
  settings, users or audit records unnoticed, but they can delete them.
- **Your identity provider and directory**, when you use single sign-on or directory
  sign-in, decide who is who.
- **The release key, the content key and the offline root key** built into Signalith.
  A leaked release or content key is revoked with a list signed by the root key
  ([Key management](key-management.md)).
- **SigmaHQ and Splunk security_content**, the upstream projects the content packs come
  from. Their rules reach a content update only through a reviewed pull request that pins
  the upstream commit and shows the changed rules; the Content workflow signs only what
  is merged ([Content updates](detections.md#content-updates)).

## Out of scope and known limits

- **Denial of service by signed-in users with high roles.** Limits make it harder, but an
  admin can always make the server busy.
- **Weaknesses in OpenSearch, Fluent Bit, osquery or the operating system.** Report them
  to those projects, and to us if Signalith's defaults make them worse.
- **Firewalls, backups and the computers agents run on.** Signalith can't see them; see
  [Not checked here](security.md#not-checked-here).
- **The Windows installer is not code-signed yet**, so Windows SmartScreen warns about it.
  Check the download's signature and provenance instead ([Check a download](install-packages.md#check-a-download)).
- **Syslog over UDP** can't be authenticated or encrypted.
- **No independent audit yet** (see the note at the top of this page).

## How it is reviewed

- Every change that touches sign-in, sessions, tokens, agents, ingest, the cluster, keys,
  uploads or the search language gets a security review before it is merged. Most of
  Signalith's code is written with an AI coding assistant, and these reviews are
  AI-assisted too, so they are not a substitute for an independent audit. Signalith has
  one maintainer, so no second person approves a change before it is merged. Findings
  and their fixes are in the public pull request history.
- The baselines are OWASP ASVS, NIST SP 800-63B for authentication, CIS and NIST SSDF.
- CI runs CodeQL, OpenSSF Scorecard, govulncheck, Trivy image scans, 70+ fuzz targets
  (longer every night), race tests and a two-server cluster test.

Report a weakness privately: see [SECURITY.md](https://github.com/jrsamsanchez/Signalith/blob/main/SECURITY.md).
