---
hide:
  - navigation
description: Where Signalith stands, what 1.0 means, what is not being added before then, and what it does today.
---

# Roadmap

Signalith aims to be a complete, general-purpose open-source SIEM: collect events from
the systems you run, find the attacks in them, and help you respond. It is a personal
project built in the open, so this page has no dates.

**Where we are.** Signalith already does a lot (see [Done](#done)), but it is young: no
install outside the maintainer's lab has run it for long, and one person reviews every
change. Until 1.0, the work goes into making what exists correct, easy to keep running
and proven, not into adding more. Version 1.0 comes when every line of the
[1.0 checklist](#next) is ticked.

Ideas and requests are welcome as
[feature requests](https://github.com/jrsamsanchez/Signalith/issues/new/choose) on GitHub.

## Now <span class="sg-pill sg-pill--now">In progress</span> { #now data-toc-label="Now" }

**The next release**
:   Finished and waiting for the next release: [case](cases.md) templates and tasks,
    files attached to a case, and case reports signed with SHA-256 fingerprints;
    `signalith opensearch install`, which sets up OpenSearch on Linux in one command;
    scheduled OpenSearch [snapshots](backup.md) with a Backups card; a
    [Prometheus metrics](metrics.md) endpoint; signed monthly
    [compliance](compliance.md) evidence records; for the
    [Signalith Agent](signalith-agent.md), Windows 11 on ARM, staged updates, an alert
    when an agent goes silent and a check of Fluent Bit configuration;
    [vulnerability](vulnerabilities.md) matching of installed Linux packages against
    distribution advisories; and an Ingress and an agent Service in the
    [Helm chart](kubernetes.md).

**Correct answers**
:   Fixes for the remaining findings of an internal review, and searches checked against
    Splunk's answers where the two should agree.

**Easy to keep running**
:   OpenSearch shard limits checked before they bite, syslog that
    keeps events through an OpenSearch restart.

**Proof**
:   A seven-day lab run with real Windows and Sysmon events, with the bytes, cores and
    shards it took published on the [performance](performance.md) page.

## Next: the 1.0 checklist <span class="sg-pill sg-pill--next">Planned</span> { #next data-toc-label="Next: 1.0" }

Version 1.0 means every line below is ticked. Each one can be checked by a link or a
command.

**Trust**

- [ ] An outside security review of the main attack surface, its report published, and
  every high and critical finding fixed and retested.
- [x] The [OpenSSF Best Practices](https://www.bestpractices.dev/projects/15694) silver
  badge.
- [ ] A code-signed Windows installer and agent (see the
  [code signing policy](code-signing.md)).
- [ ] A second person who reviews and merges changes, at least to detection content.

**Proof**

- [ ] A seven-day lab run, at small-team size and with three servers, that loses no
  accepted event, raises no late detection, and keeps disk and memory flat.
- [ ] Five installs outside the lab running for 30 days, two of them with real Windows
  computers, listed by name with their permission.
- [ ] A published false-positive rate for the starter rule set on one real network, low
  enough for one analyst to work through.

**Easy to keep running**

- [ ] Backup and restore for Docker, Linux and Windows, with a wipe-and-restore test in CI.
- [ ] Upgrades from every release of the past 90 days tested in CI.
- [ ] A written promise of what settings, API and query language keep working after 1.0.

**Easy to use**

- [ ] Five people other than the maintainer get their first finding from their own
  Windows computer within 30 minutes of opening [Getting started](getting-started.md).
- [ ] A README that fits on two screens, with upgrade notes in these docs.

**Releases**

- [ ] Two releases in a row on a fixed two-week schedule, with no emergency patch.

## Not being added before 1.0 { #freeze }

To keep the work on the checklist, these stay as they are until 1.0. Bug fixes still
land, and community contributions in these areas are welcome.

- **New compliance frameworks.** The eight already mapped stay; the evidence behind them
  gets fixed first.
- **New cloud log sources.** Anything else can still come in through
  [OpenTelemetry](opentelemetry.md), [syslog](sending-data.md#syslog) or a
  [custom parser](custom-logs.md).
- **New query commands**, beyond what tested detection content needs.

## Later <span class="sg-pill sg-pill--later">Exploring</span> { #later data-toc-label="Later" }

**After 1.0**
:   Mutual TLS for senders, per-tenant quotas and tenant removal, permissions on saved
    objects, an allow-list for outbound connections, OCSF export, and filtering events
    before they are stored.

**Managed service providers**
:   A console for running Signalith for several customers, once several single-team
    installs are running well.

## Not planned { #not-planned }

These are outside what Signalith is for:

- **An EDR.** Signalith collects and analyses endpoint events; it does not block or
  quarantine on its own.
- **Packet capture.** The [network sensor](network-sensor.md) keeps Zeek and Suricata
  logs, not packets.
- **Its own storage engine.** Events stay in OpenSearch.
- **Matching every SPL command.** The query language reads like SPL so it feels
  familiar, and grows where detections need it, not toward full parity.
- **Paid features.** Everything is in the open-source release under Apache 2.0.

## Done <span class="sg-pill sg-pill--done">Available</span> { #done data-toc-label="Done" }

Everything below is in Signalith now. Items named under **The next release** in [Now](#now) arrive with the release after 0.3.2.

**Search foundation**

- The [Signalith Agent](signalith-agent.md): one line installs it on Linux, Windows
  (with optional Sysmon) or macOS, it runs Fluent Bit and osquery, and what each group
  of computers collects is chosen on the Endpoints page, so nobody edits a configuration.
  Its buffer on disk is capped, it stops sending when the server refuses its token, and an
  update is kept only once the new agent has reached the server.
- Fluent Bit agents for Windows and Linux, set up from the **Add data** page, plus
  [syslog and CEF](sending-data.md#syslog) from network devices and
  [OpenTelemetry](opentelemetry.md) logs over OTLP, each agent with its own
  [token](agent-tokens.md).
- Parsing into CIM-style data models (Authentication, Endpoint, Network traffic, Web,
  Change, Malware and more).
- A pipe-based [query language](query-language.md) that reads like SPL, plain-English
  questions that become queries, a visual query builder, and an optional AI model.
- A Docker quick start, [packages](install-packages.md) for Linux and Windows, signed
  apt and dnf repositories, and a [Helm chart](kubernetes.md) for Kubernetes.
- A first-use [setup guide](getting-started.md#the-setup-guide) that opens the page for
  each step and ticks it off once it is done.

**Detect and triage**

- Scheduled [detections](detections.md) mapped to MITRE ATT&CK, with throttling, a
  findings queue for triage, and an ATT&CK coverage map.
- Content packs of tested community rules: 2,641 from
  [SigmaHQ](https://github.com/SigmaHQ/sigma) and 1,332 from Splunk Security Content,
  each with test events that prove it fires, and signed content updates.
- [Sigma](https://github.com/SigmaHQ/sigma) rule import.
- A [starter set](detections.md#the-starter-set) of about 140 high and critical rules
  that read only what hosts send as installed, and a Windows install line that turns on
  the process auditing and the logs those rules need.
- [Describe a detection](detections.md#describe-a-detection-in-plain-english) in plain
  English, then backtest it over the past 7, 30 or 90 days before turning it on.

**Security depth**

- Risk-based alerting with asset and identity context, and
  [behavior baselines](baselines.md) that add risk for first-seen and rare activity.
- [Threat intel](threat-intel.md) feeds (lists, CSV, STIX, TAXII 2.1) matched against
  your events.
- A security posture dashboard and [dashboards](dashboards.md) of your own, where any
  number or row opens the events behind it.
- [Sample data](sample-data.md) with attacks hidden in it, to try everything out.
- A [public demo](https://demo.signalith.io) that runs read-only with the sample data,
  and the [demo mode](demo.md) behind it for running your own.

**Respond and scale**

- Investigation cases that collect findings, notes, searches and evidence, and
  [Investigate with AI](investigate.md) for a first verdict on a finding.
- An [attack storyline](storyline.md) that shows one intrusion as a single story: the
  ATT&CK tactics it reached, a timeline and the entities that tie it together.
- [Hunting notebooks](hunting-notebooks.md): saved, shareable hunts of notes and searches
  tagged to ATT&CK, with seven starter hunts.
- [Notifications](notifications.md) to email, webhooks, Slack and Microsoft Teams, with
  [buttons](notifications.md#buttons-in-slack-and-teams) to acknowledge findings and approve
  playbook steps from chat, and
  [response actions](response-actions.md) and [playbooks](playbooks.md) with an approval
  step.
- [Jira and ServiceNow tickets](ticketing.md) for cases, kept in step both ways.
- [Several teams or customers](multi-tenant.md) on one install, each with its own data,
  users, detections and behavior baselines, managed on **Settings > Tenants** with a
  tenant picker in the top bar.
- [Several servers](servers.md) sharing one OpenSearch (a preview until 1.0): [add a server](multi-server.md)
  with one line on Linux, Windows or Docker, shared settings, users and detections,
  each server's detection health on the Servers page,
  [detections spread over the servers](servers.md#the-background-jobs) (on by default
  from 0.3.1), one certificate authority, rolling upgrades,
  draining and removing a server, and
  [OpenSearch with several nodes](opensearch-failover.md).
- [Load balancers](load-balancers.md) in front of several servers, with PROXY protocol so
  the real sender of each connection is kept, and sample HAProxy, nginx and keepalived
  setups.
- A load test with [sizing numbers](performance.md), including a
  [lab run](performance.md#lab-sizes) of about 21,500 events a second (about 1 TB a day)
  on one 2-core Signalith server and two OpenSearch nodes, in two 4-hour runs on
  consecutive days with no late detections; a 4-hour run on three Signalith servers that
  stored all 25,000 events a second (about 1 TB a day) with 1,520 detections and none
  late; and a three-server run in which detections stayed evenly shared through a
  restart and a crash.

**More data**

- [Endpoints with osquery](endpoints.md): file integrity monitoring, inventory and
  configuration checks, plus [Wazuh](wazuh.md) alerts.
- [Antivirus](antivirus.md) logs from Defender, ClamAV and consoles that send CEF or LEEF.
- Apache and Nginx access logs, with web rules from SigmaHQ and Splunk.
- [AWS CloudTrail](aws-cloudtrail.md) through the OpenTelemetry Collector, with 38 SigmaHQ
  and 32 Splunk CloudTrail rules.
- [Microsoft Entra ID and Azure](azure.md) sign-ins, audit log, risk detections and
  activity log through an Event Hub and the OpenTelemetry Collector, with 108 SigmaHQ and
  30 Splunk Entra ID rules.
- [Microsoft 365](microsoft-365.md) audit log, read from Microsoft with no agent, with 17
  SigmaHQ and 54 Splunk Microsoft 365 rules.
- [Okta](okta.md) System Log, read from Okta with no agent, with 19 SigmaHQ and 13 Splunk
  Okta rules.
- [Kubernetes audit logs](kubernetes-audit.md), posted by the API server's audit webhook or
  tailed from its log file, with 15 SigmaHQ and 13 Splunk Kubernetes rules.
- [GitHub audit log](github-audit-log.md) of GitHub Enterprise Cloud and Server, streamed
  through an Azure event hub or sent by a script, with 12 SigmaHQ and 18 Splunk GitHub rules.
- [Google Cloud](google-cloud.md) audit logs through a log sink, Pub/Sub and the
  OpenTelemetry Collector, with 16 SigmaHQ Google Cloud rules, and Google Workspace's
  admin and sign-in audit logs the same way, with 7 SigmaHQ Google Workspace rules.
- A [network sensor](network-sensor.md) with Zeek and Suricata, installed with one line,
  network detections for sensor, firewall, DNS and proxy data, a Network dashboard, and
  [Settings > Network sensors](network-sensor.md#settings-network-sensors) to check every
  sensor's health, tune rules on all sensors at once or revoke one.
- [Any other log](custom-logs.md): a guided page that builds a parser from a sample, with
  optional help from AI.
- [Vulnerability scanning](vulnerabilities.md) with Nmap and CVE matching, ranked with
  CISA KEV and EPSS, a scanner for each network zone, and OpenVAS for deeper scans, with
  [encrypted SSH, Windows, VMware ESXi and SNMP logins](vulnerabilities.md#credentialed-openvas-scans).
- A read-only [MCP server](ai-tools.md) for AI tools, with API tokens.

**Built in from the start**

- HTTPS by default, a secured OpenSearch, and [encrypted](encryption.md) passwords, keys
  and archives.
- [Users and roles](users.md), with Active Directory and LDAP sign-in,
  [single sign-on](sso.md) with OpenID Connect or SAML 2.0 and SCIM provisioning, and two-step sign-in
  with [passkeys](users.md#passkeys) or an authenticator app.
- A separate [agent port](sending-data.md#the-agent-port), so agents never need the web
  page.
- [Data retention](retention.md) policies with archives you can restore, and a disk guard.
- [Backup and restore](backup.md) of a server's files and OpenSearch data.
- A [security check](security.md) of how each server is set up, a
  [tamper-evident audit log](audit.md#tamper-evidence), and API tokens that expire.
- [Compliance](compliance.md) coverage for NIST SP 800-53, CIS Controls v8, PCI DSS 4.0.1,
  ISO/IEC 27001, HIPAA, SOC 2, NIS2 and the GDPR, with evidence reports for auditors.
- Fuzz tests for every parser that reads data from the network, run in CI and nightly.
