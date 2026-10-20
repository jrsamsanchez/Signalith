---
hide:
  - navigation
description: What Signalith does today, what is being built now, and what comes next.
---

# Roadmap

Signalith aims to be a complete, general-purpose open-source SIEM: collect events from
the systems you run, find the attacks in them, and help you respond. This page says
where it stands. It has no dates: Signalith is a personal project built in the open,
and things ship when they are ready and tested. **Next** and **Later** together cover
what is planned for the coming year.

Ideas and requests are welcome as
[feature requests](https://github.com/jrsamsanchez/Signalith/issues/new/choose) on GitHub.

## Done <span class="sg-pill sg-pill--done">Available</span> { #done data-toc-label="Done" }

The first four phases are complete, and work on hardening for 1.0 has started.

**Search foundation**

- The [Signalith Agent](signalith-agent.md): one line installs it on Linux, Windows
  (with optional Sysmon) or macOS, it runs Fluent Bit and osquery, and what each group
  of computers collects is chosen on the Endpoints page, so nobody edits a configuration.
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
- Content packs of tested community rules: 2,638 from
  [SigmaHQ](https://github.com/SigmaHQ/sigma) and 1,330 from Splunk Security Content,
  each with test events that prove it fires, and signed content updates.
- [Sigma](https://github.com/SigmaHQ/sigma) rule import.
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
- [Several servers](servers.md) sharing one OpenSearch: [add a server](multi-server.md)
  with one line on Linux, Windows or Docker, shared settings, users and detections,
  each server's detection health on the Servers page,
  [detections spread over the servers](servers.md#the-background-jobs) (on by default
  from the next release), one certificate authority, rolling upgrades,
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
- A [security check](security.md) of how each server is set up, a
  [tamper-evident audit log](audit.md#tamper-evidence), and API tokens that expire.
- [Compliance](compliance.md) coverage for NIST SP 800-53, CIS Controls v8, PCI DSS 4.0,
  ISO/IEC 27001, HIPAA and SOC 2, with evidence reports for auditors.
- Fuzz tests for every parser that reads data from the network, run in CI and nightly.

## Being built now <span class="sg-pill sg-pill--now">In progress</span> { #now data-toc-label="Being built now" }

**A public demo**
:   [demo.signalith.io](https://demo.signalith.io) runs Signalith read-only with the
    sample data, so anyone can try it in a browser. You can [run one too](demo.md).

**In the next release**
:   These are finished and arrive with the next release. The Windows installer sets up
    [OpenSearch on the same computer](install-packages.md#opensearch-on-windows), so
    Windows needs no separate install step. Signalith Agents update themselves from
    signed releases and roll back if an update fails. With several servers,
    [detections are spread over them](servers.md#the-background-jobs) by default. New
    installs take syslog over TLS on port 6514 only, and
    [plain syslog on 514](sending-data.md#turning-on-plain-syslog) is one click away.

## Next <span class="sg-pill sg-pill--next">Planned</span> { #next data-toc-label="Next" }

**A signed Windows installer**
:   A code-signed `.msi` (see the [code signing policy](code-signing.md)).

## Later <span class="sg-pill sg-pill--later">Exploring</span> { #later data-toc-label="Later" }

**Hardening and 1.0**
:   An outside security review, and then version 1.0.
