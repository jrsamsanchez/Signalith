---
hide:
  - navigation
description: What Signalith does today, what is being built now, and what comes next.
---

# Roadmap

Signalith aims to be a complete, general-purpose open-source SIEM: collect events from
the systems you run, find the attacks in them, and help you respond. This page says
where it stands. It has no dates: Signalith is a personal project built in the open,
and things ship when they are ready and tested.

Ideas and requests are welcome as
[feature requests](https://github.com/jrsamsanchez/Signalith/issues/new/choose) on GitHub.

## Done <span class="sg-pill sg-pill--done">Available</span> { #done data-toc-label="Done" }

The first four phases are complete, and work on hardening for 1.0 has started.

**Search foundation**

- Fluent Bit agents for Windows and Linux, set up from the **Add data** page, plus
  [syslog and CEF](sending-data.md#syslog) from network devices and
  [OpenTelemetry](opentelemetry.md) logs over OTLP, each agent with its own
  [token](agent-tokens.md).
- Parsing into CIM-style data models (Authentication, Endpoint, Network traffic, Web,
  Change, Malware and more).
- A pipe-based [query language](query-language.md) that reads like SPL, plain-English
  questions that become queries, a visual query builder, and an optional AI model.
- A Docker quick start, [packages](install-packages.md) for Linux and Windows, and signed
  apt and dnf repositories.

**Detect and triage**

- Scheduled [detections](detections.md) mapped to MITRE ATT&CK, with throttling, a
  findings queue for triage, and an ATT&CK coverage map.
- Content packs of tested community rules: 2,471 from
  [SigmaHQ](https://github.com/SigmaHQ/sigma) and 1,131 from Splunk Security Content,
  each with test events that prove it fires, and signed content updates.
- [Sigma](https://github.com/SigmaHQ/sigma) rule import.

**Security depth**

- Risk-based alerting with asset and identity context.
- [Threat intel](threat-intel.md) feeds (lists, CSV, STIX, TAXII 2.1) matched against
  your events.
- A security posture dashboard and [dashboards](dashboards.md) of your own.
- [Sample data](sample-data.md) with attacks hidden in it, to try everything out.

**Respond and scale**

- Investigation cases that collect findings, notes, searches and evidence, and
  [Investigate with AI](investigate.md) for a first verdict on a finding.
- [Notifications](notifications.md) to email, webhooks, Slack and Microsoft Teams, and
  [response actions](response-actions.md) and [playbooks](playbooks.md) with an approval
  step.
- [Several servers](servers.md) sharing one OpenSearch: [add a server](multi-server.md)
  with one line on Linux, Windows or Docker, shared settings, users and detections, one
  certificate authority, rolling upgrades, draining and removing a server, and
  [OpenSearch with several nodes](opensearch-failover.md).
- [Load balancers](load-balancers.md) in front of several servers, with PROXY protocol so
  the real sender of each connection is kept, and sample HAProxy, nginx and keepalived
  setups.
- A load test with [sizing numbers](performance.md).

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
  SigmaHQ and 19 Splunk Microsoft 365 rules.
- [Google Cloud](google-cloud.md) audit logs through a log sink, Pub/Sub and the
  OpenTelemetry Collector, with 16 SigmaHQ Google Cloud rules.
- A [network sensor](network-sensor.md) with Zeek and Suricata, installed with one line,
  network detections for sensor, firewall, DNS and proxy data, and a Network dashboard.
- [Vulnerability scanning](vulnerabilities.md) with Nmap and CVE matching, a scanner for
  each network zone, and OpenVAS for deeper scans.
- A read-only [MCP server](ai-tools.md) for AI tools, with API tokens.

**Built in from the start**

- HTTPS by default, a secured OpenSearch, and [encrypted](encryption.md) passwords, keys
  and archives.
- [Users and roles](users.md), with Active Directory and LDAP sign-in and two-step sign-in
  with an authenticator app.
- [Data retention](retention.md) policies with archives you can restore, and a disk guard.
- A [security check](security.md) of how each server is set up.
- [Compliance](compliance.md) coverage for NIST SP 800-53, CIS Controls v8, PCI DSS 4.0,
  ISO/IEC 27001, HIPAA and SOC 2, with evidence reports for auditors.
- Fuzz tests for every parser that reads data from the network, run in CI and nightly.

## Being built now <span class="sg-pill sg-pill--now">In progress</span> { #now data-toc-label="Being built now" }

**Network sensors in Settings**
:   One page listing every network sensor with its health, where an admin can turn off a
    noisy rule on all sensors or revoke a sensor.

**More cloud logs**
:   Microsoft 365 audit logs.

## Next <span class="sg-pill sg-pill--next">Planned</span> { #next data-toc-label="Next" }

**A signed Windows installer**
:   A code-signed `.msi` (see the [code signing policy](code-signing.md)).

**Lab load numbers**
:   The [sizing](performance.md#lab-sizes) table filled in from separate lab machines and an
    OpenSearch cluster, not only a CI runner.

## Later <span class="sg-pill sg-pill--later">Exploring</span> { #later data-toc-label="Later" }

**Hardening and 1.0**
:   An outside security review, a public demo, and then version 1.0.
